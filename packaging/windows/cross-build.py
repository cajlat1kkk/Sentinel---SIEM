#!/usr/bin/env python3
"""Fetch a pinned MinGW Qt SDK or stage Windows runtimes. Does not install host packages."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import urllib.request
import time

SOURCE = Path(__file__).resolve().parents[2]
LOCK = json.loads((SOURCE / "packaging/windows/msys2-packages.lock.json").read_text())
SDK = Path(os.environ.get("SIEM_WINDOWS_SDK", "/tmp/siem-windows-sdk")).resolve()
MINGW = SDK / "sysroot/mingw64"


def fetch():
    cache = SDK / "packages"
    cache.mkdir(parents=True, exist_ok=True)
    (SDK / "sysroot").mkdir(parents=True, exist_ok=True)
    mirror = os.environ.get("SIEM_MSYS2_MIRROR", LOCK["mirror"]).rstrip("/") + "/"

    def download(item):
        name, meta = item
        target = cache / meta["file"]
        if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest() != meta["sha256"]:
            for attempt in range(3):
                try:
                    print(f"Downloading {name} (attempt {attempt + 1})", flush=True)
                    with urllib.request.urlopen(mirror + meta["file"], timeout=90) as response:
                        content = response.read()
                    break
                except (OSError, TimeoutError):
                    if attempt == 2:
                        raise
                    time.sleep(2)
            if hashlib.sha256(content).hexdigest() != meta["sha256"]:
                raise RuntimeError("SHA-256 mismatch: " + name)
            target.write_bytes(content)
        print("Verified " + name, flush=True)
        return target

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        packages = list(pool.map(download, LOCK["packages"].items()))
    for package in packages:
        listing = subprocess.check_output(["tar", "--zstd", "-tf", str(package)], text=True).splitlines()
        if any(x.startswith("/") or ".." in PurePosixPath(x).parts for x in listing):
            raise RuntimeError("Unsafe archive path")
        subprocess.run(["tar", "--zstd", "-xf", str(package), "-C", str(SDK / "sysroot")], check=True)


def stage():
    bundle = SOURCE / "dist/windows/portable"
    # This directory is build output only. Avoid mixing obsolete DLLs with the new bundle.
    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.mkdir(parents=True)
    binaries = []
    for name in ["sentinel-siem.exe", "siem-firewall-helper.exe", "siem-agent.exe", "siem-server.exe", "siem-fleetctl.exe", "siem-update-verify.exe"]:
        target = bundle / name
        shutil.copy2(SDK / "build" / name, target)
        binaries.append(target)
    plugin_root = MINGW / "share/qt6/plugins"
    for group, names in {
        "platforms": ["qwindows.dll", "qoffscreen.dll"],
        "sqldrivers": ["qsqlpsql.dll", "qsqlite.dll"],
        "iconengines": ["qsvgicon.dll"],
        "imageformats": ["qsvg.dll", "qjpeg.dll", "qgif.dll"],
        "tls": ["qschannelbackend.dll", "qopensslbackend.dll", "qcertonlybackend.dll"],
    }.items():
        (bundle / group).mkdir()
        for name in names:
            source = plugin_root / group / name
            if source.exists():
                target = bundle / group / name
                shutil.copy2(source, target)
                binaries.append(target)
    available = {p.name.lower(): p for p in (MINGW / "bin").glob("*.dll")}
    visited = set()
    system_imports = set()
    while binaries:
        binary = binaries.pop()
        key = binary.name.lower()
        if key in visited:
            continue
        visited.add(key)
        imports = re.findall(r"DLL Name:\s*(\S+)", subprocess.check_output(
            ["x86_64-w64-mingw32-objdump", "-p", str(binary)], text=True))
        for name in imports:
            if name.lower() in available:
                source = available[name.lower()]
                target = bundle / source.name
                if not target.exists():
                    shutil.copy2(source, target)
                binaries.append(target)
            else:
                system_imports.add(name)
    (bundle / "qt.conf").write_text("[Paths]\nPrefix=.\nPlugins=.\n")
    shutil.copytree(MINGW / "share/licenses", bundle / "licenses", dirs_exist_ok=True)
    shutil.copy2(SOURCE / "README.md", bundle / "README.md")
    shutil.copytree(SOURCE / "docs", bundle / "docs", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "samples", bundle / "samples", dirs_exist_ok=True)
    manifest = dict(LOCK)
    manifest["system_dll_imports"] = sorted(system_imports)
    manifest["bundled_files"] = {str(p.relative_to(bundle)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in sorted(bundle.rglob("*")) if p.is_file()}
    (bundle / "runtime-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    (bundle / "THIRD_PARTY.txt").write_text(
        "Sentinel SIEM Windows runtime bundle\n\n"
        "This application dynamically links to Qt and other third-party libraries.\n"
        "Their notices and license texts are in licenses/. Package versions, upstream\n"
        "source URLs, MSYS2 build recipes, binary archive checksums and bundled-file\n"
        "checksums are recorded in runtime-manifest.json.\n\n"
        "Qt Core/Gui/Widgets/Network/Sql/Concurrent/Svg are dynamically linked.\n"
        "Users may replace the Qt DLLs with ABI-compatible builds and exercise the\n"
        "rights granted by the applicable LGPL license, including debugging changes.\n"
        "Qt source: https://download.qt.io/archive/qt/6.12/6.12.0/submodules/\n"
        "MSYS2 source recipes: https://github.com/msys2/MINGW-packages\n"
        "Qt license texts: licenses/qt6-base and licenses/qt6-svg.\n\n"
        "The application was cross-compiled on Linux. Wine smoke tests do not replace\n"
        "testing installation, UAC and firewall enforcement on a native Windows host.\n",
        encoding="utf-8")
    # Delete only installed files. Keep unrelated files the user may put in this directory.
    uninstall = []
    for path in sorted(bundle.rglob("*")):
        if path.is_file():
            relative = str(path.relative_to(bundle)).replace("/", "\\")
            uninstall.append('  Delete "$INSTDIR\\' + relative + '"')
    for path in sorted((p for p in bundle.rglob("*") if p.is_dir()),
                       key=lambda p: len(p.parts), reverse=True):
        relative = str(path.relative_to(bundle)).replace("/", "\\")
        uninstall.append('  RMDir "$INSTDIR\\' + relative + '"')
    (SDK / "uninstall-files.nsh").write_text("\n".join(uninstall) + "\n", encoding="utf-8")
    print(f"Staged {len(visited)} PE binaries in {bundle}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"fetch", "stage"}:
        raise SystemExit("Usage: cross-build.py fetch|stage")
    {"fetch": fetch, "stage": stage}[sys.argv[1]]()

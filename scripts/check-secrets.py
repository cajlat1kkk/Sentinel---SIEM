#!/usr/bin/env python3
"""Reject private/runtime files and scan with a checksum-pinned Gitleaks binary.

Findings are always redacted. No secrets or reports are uploaded.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "8.30.1"
ARCHIVES = {
    ("Linux", "x86_64"): ("linux_x64.tar.gz", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"),
    ("Windows", "AMD64"): ("windows_x64.zip", "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"),
    ("Darwin", "arm64"): ("darwin_arm64.tar.gz", "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"),
}


def private_path(name):
    p = PurePosixPath(name)
    if any(part in {".dev", "dist", ".venv", "secrets", "pki", "config.local", "node_modules"} or part.startswith("build-") for part in p.parts[:-1]):
        return True
    if p.parts[0] == "build":
        return True
    if p.name.startswith(".env") and not p.name.endswith(".example"):
        return True
    if re.search(r"\.(pem|key|p12|pfx|crt|cer|csr|jks|keystore|kdbx|sqlite.*|db|dump|backup|exe|dll|deb|pkg\.tar\.zst)$", name, re.I):
        return True
    if re.search(r"\.local\.(json|ya?ml)$", name):
        return True
    return p.name in {"postgres-password", "agent.json", "server.json", "console.json", "enrollment.token"}


def scanner():
    suffix, checksum = ARCHIVES[(platform.system(), platform.machine())]
    cache = ROOT / ".dev" / "tools" / "gitleaks-pinned"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / ("gitleaks_" + VERSION + "_" + suffix)
    if not archive.exists():
        url = "https://github.com/gitleaks/gitleaks/releases/download/v" + VERSION + "/" + archive.name
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(64 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != checksum:
            raise RuntimeError("Gitleaks download checksum mismatch")
        archive.write_bytes(data)
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != checksum:
        raise RuntimeError("Gitleaks cached archive checksum mismatch")
    executable = cache / ("gitleaks.exe" if os.name == "nt" else "gitleaks")
    if suffix.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            executable.write_bytes(package.read(executable.name))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as package:
            executable.write_bytes(package.extractfile("gitleaks").read())
    executable.chmod(0o755)
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--paths-only", action="store_true")
    args = parser.parse_args()
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    bad = [name for name in names if name and private_path(name)]
    if bad:
        print("Private/runtime files must be removed from the Git index:")
        print("\n".join(bad))
        return 1
    if args.paths_only:
        print("Tracked paths: no private or generated artifacts")
        return 0
    command = [str(scanner()), "git", "--redact", "--no-banner", "--ignore-gitleaks-allow", "--timeout", "120"]
    command += ["--pre-commit", "--staged"] if args.staged else ["--log-opts=--all"]
    return subprocess.call(command, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--build", default="build")
parser.add_argument("--wine", action="store_true", help="Verify the actual Windows executable under Wine")
args = parser.parse_args()
windows = os.name == "nt" or args.wine
def argument(path):
    return subprocess.check_output(["winepath", "-w", str(path)], text=True).strip() if args.wine else str(path)
with tempfile.TemporaryDirectory(prefix="sentinel-update-test-") as temp:
    work = Path(temp)
    private, public = work / "release.key", work / "release.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
    package = work / "test-package.bin"
    package.write_bytes(b"Harmless signed update fixture")
    subprocess.run([os.sys.executable, str(ROOT / "scripts/sign-release.py"), str(package), "--private-key", str(private), "--version", "0.3.0", "--sequence", "2", "--platform", "windows-x64" if windows else "linux-x64"], check=True, capture_output=True)
    manifest = package.with_name(package.name + ".manifest.json")
    command = (["wine"] if args.wine else []) + [str(ROOT / args.build / ("siem-update-verify.exe" if windows else "siem-update-verify")), "--public-key", argument(public), "--manifest", argument(manifest), "--signature", argument(Path(str(manifest) + ".sig")), "--package", argument(package)]
    report = work / "verification.json"
    command += ["--report", argument(report)]
    verified = subprocess.run(command, capture_output=True)
    assert verified.returncode == 0, (verified.returncode, verified.stderr.decode(errors="replace"), report.read_text() if report.exists() else "no report")
    assert subprocess.run(command + ["--minimum-sequence", "2"], capture_output=True).returncode != 0
    original = package.read_bytes()
    package.write_bytes(b"X" + original[1:])
    assert subprocess.run(command, capture_output=True).returncode != 0
    package.write_bytes(original)
    value = json.loads(manifest.read_text())
    value["sequence"] = 999
    manifest.write_text(json.dumps(value))
    assert subprocess.run(command, capture_output=True).returncode != 0
print("PASS: valid release, anti-replay, modified package and modified manifest")

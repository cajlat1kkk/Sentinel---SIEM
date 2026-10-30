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
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="sentinel-update-test-") as temp:
    work = Path(temp)
    private, public = work / "release.key", work / "release.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
    package = work / "test-package.bin"
    package.write_bytes(b"Harmless signed update fixture")
    subprocess.run([os.sys.executable, str(ROOT / "scripts/sign-release.py"), str(package), "--private-key", str(private), "--version", "0.3.0", "--sequence", "2", "--platform", "windows-x64" if os.name == "nt" else "linux-x64"], check=True, capture_output=True)
    manifest = package.with_name(package.name + ".manifest.json")
    command = [str(ROOT / args.build / ("siem-update-verify.exe" if os.name == "nt" else "siem-update-verify")), "--public-key", str(public), "--manifest", str(manifest), "--signature", str(manifest) + ".sig", "--package", str(package)]
    assert subprocess.run(command, capture_output=True).returncode == 0
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

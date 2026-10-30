#!/usr/bin/env python3
"""Sign a release manifest with an offline RSA key. Never generates or uploads signing keys."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("package", type=Path)
parser.add_argument("--private-key", required=True, type=Path)
parser.add_argument("--version", required=True)
parser.add_argument("--sequence", required=True, type=int)
parser.add_argument("--platform", choices=["linux-x64", "windows-x64"], required=True)
args = parser.parse_args()
if args.sequence < 1:
    raise SystemExit("Sequence must be positive and strictly increase between releases")
manifest = args.package.with_name(args.package.name + ".manifest.json")
sha = hashlib.sha256()
with args.package.open("rb") as package:
    while data := package.read(1024 * 1024):
        sha.update(data)
manifest.write_text(json.dumps({"version": args.version, "sequence": args.sequence, "platform": args.platform,
    "sha256": sha.hexdigest(), "size": args.package.stat().st_size, "package": args.package.name,
    "expires": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec="seconds")}, separators=(",", ":")) + "\n")
signature = manifest.with_suffix(manifest.suffix + ".sig")
subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(args.private_key), "-out", str(signature), str(manifest)], check=True)
print("Signed manifest:", manifest)

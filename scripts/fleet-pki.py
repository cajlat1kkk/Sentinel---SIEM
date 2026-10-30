#!/usr/bin/env python3
"""Create an offline deployment CA or issue a unique server/operator/agent identity.

Store output outside Git. The CA private key must never be installed on endpoints.
"""
import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile


def run(arguments):
    subprocess.run(["openssl", *map(str, arguments)], check=True, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init-ca", "issue"])
    parser.add_argument("--ca-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--name", default="Sentinel Deployment")
    parser.add_argument("--server-name", help="Server DNS name or IP; omit for agent/operator certificates")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9 _.-]{1,100}", args.name):
        raise SystemExit("Use a simple certificate name: letters, digits, spaces, _, . or -")
    os.umask(0o077)
    args.ca_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key, cert = args.ca_dir / "ca.key", args.ca_dir / "ca.crt"
    if args.action == "init-ca":
        if key.exists() or cert.exists():
            raise SystemExit("Refusing to overwrite an existing CA")
        run(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", key, "-out", cert,
             "-subj", "/CN=" + args.name, "-days", "3650", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        print("CA created. Keep ca.key offline; distribute only ca.crt.")
        return
    if not args.output or not key.is_file() or not cert.is_file():
        raise SystemExit("Existing CA and --output are required")
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_key, output_cert = args.output / "identity.key", args.output / "identity.crt"
    if output_key.exists() or output_cert.exists():
        raise SystemExit("Refusing to overwrite an existing identity")
    extension = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
    if args.server_name:
        try:
            ipaddress.ip_address(args.server_name)
            san = "IP:" + args.server_name
        except ValueError:
            if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", args.server_name):
                raise SystemExit("Invalid server DNS name")
            san = "DNS:" + args.server_name
        extension += "extendedKeyUsage=serverAuth\nsubjectAltName=" + san + "\n"
    else:
        extension += "extendedKeyUsage=clientAuth\n"
    with tempfile.TemporaryDirectory(dir=args.output) as temporary:
        csr, ext = Path(temporary) / "request.csr", Path(temporary) / "extensions.txt"
        ext.write_text(extension)
        run(["req", "-newkey", "rsa:3072", "-nodes", "-keyout", output_key, "-out", csr, "-subj", "/CN=" + args.name])
        run(["x509", "-req", "-in", csr, "-CA", cert, "-CAkey", key, "-set_serial", "0x" + secrets.token_hex(16),
             "-out", output_cert, "-days", "365", "-extfile", ext])
    (args.output / "ca.crt").write_bytes(cert.read_bytes())
    der = ssl.PEM_cert_to_DER_cert(output_cert.read_text())
    print("Certificate SHA-256:", hashlib.sha256(der).hexdigest())


if __name__ == "__main__":
    main()

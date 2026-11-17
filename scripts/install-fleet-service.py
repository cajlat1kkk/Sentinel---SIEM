#!/usr/bin/env python3
"""Install an explicitly configured agent/server service on Linux. Requires root.

Copies identity material into a protected directory; never enables an unconfigured service.
Does not change firewall policies, routes, NIC ownership or PostgreSQL authentication.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=["agent", "server"])
    parser.add_argument("config", type=Path)
    parser.add_argument("--operator-certificate", type=Path,
                        help="server only: provision this operator certificate after validation")
    parser.add_argument("--operator-name", default="Administrator")
    parser.add_argument("--operator-role", choices=["admin", "analyst"], default="admin")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run this installer as root after reviewing your configuration")
    os.umask(0o077)
    if args.operator_certificate and args.role != "server":
        raise SystemExit("--operator-certificate is valid only for the server role")
    executable = Path("/usr/bin/siem-" + args.role)
    if not executable.is_file() or executable.stat().st_uid != 0 or executable.stat().st_mode & 0o022:
        raise SystemExit("Install the package first; service binary must be root-owned and not group/world-writable")
    config = json.loads(args.config.read_text())
    directory = Path("/etc/sentinel-" + args.role)
    user = "root"
    if args.role == "server":
        user = "sentinel-server"
        try:
            pwd.getpwnam(user)
        except KeyError:
            subprocess.run(["useradd", "--system", "--home-dir", "/var/lib/sentinel-server", "--shell", "/usr/bin/nologin", user], check=True)
    account = pwd.getpwnam(user)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(directory, account.pw_uid, account.pw_gid)
    directory.chmod(0o700)
    # Unique identity filenames preserve the previous configuration if validation fails.
    with tempfile.TemporaryDirectory(prefix="identity-", dir=directory) as staging:
        stage = Path(staging)
        stage.chmod(0o700)
        os.chown(stage, account.pw_uid, account.pw_gid)
        identity = config["server"] if args.role == "agent" else config
        for field in ("ca", "certificate", "private_key"):
            target = stage / (field + ".pem")
            shutil.copyfile(identity[field], target)
            target.chmod(0o600)
            os.chown(target, account.pw_uid, account.pw_gid)
            identity[field] = str(target)
        if args.role == "agent":
            config["state_dir"] = "/var/lib/sentinel-agent"
            token = stage / "enrollment.token"
            shutil.copyfile(config["enrollment_token_file"], token)
            token.chmod(0o600)
            config["enrollment_token_file"] = str(token)
        else:
            password = config.get("database", {}).get("password_file")
            if password:
                target = stage / "postgres-password"
                shutil.copyfile(password, target)
                target.chmod(0o600)
                os.chown(target, account.pw_uid, account.pw_gid)
                config["database"]["password_file"] = str(target)
        candidate = stage / (args.role + ".json")
        candidate.write_text(json.dumps(config, indent=2))
        candidate.chmod(0o600)
        os.chown(candidate, account.pw_uid, account.pw_gid)
        prefix = ["runuser", "-u", user, "--"] if user != "root" else []
        subprocess.run(prefix + [str(executable), "--config", str(candidate), "--check-config"], check=True)
        if args.operator_certificate:
            certificate = args.operator_certificate.resolve(strict=True)
            staged_certificate = stage / "operator-bootstrap.crt"
            shutil.copyfile(certificate, staged_certificate)
            staged_certificate.chmod(0o600)
            os.chown(staged_certificate, account.pw_uid, account.pw_gid)
            subprocess.run(prefix + [str(executable), "--config", str(candidate),
                                      "--add-operator", str(staged_certificate),
                                      "--name", args.operator_name,
                                      "--role", args.operator_role], check=True)
            staged_certificate.unlink()
        # Move the entire validated identity into a permanent private directory atomically.
        persistent = directory / (stage.name + "-active")
        config_text = candidate.read_text().replace(str(stage), str(persistent))
        stage.rename(persistent)
        new_config = directory / (args.role + ".json.new")
        new_config.write_text(config_text)
        new_config.chmod(0o600)
        os.chown(new_config, account.pw_uid, account.pw_gid)
        destination = directory / (args.role + ".json")
        if destination.exists():
            shutil.copyfile(destination, directory / (args.role + ".json.previous"))
        new_config.replace(destination)
    unit = "sentinel-" + args.role + ".service"
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", unit], check=True)
    try:
        subprocess.run(["systemctl", "restart", unit], check=True)
        subprocess.run(["systemctl", "is-active", unit], check=True)
    except subprocess.CalledProcessError:
        previous = directory / (args.role + ".json.previous")
        if previous.is_file():
            shutil.copyfile(previous, destination)
            destination.chmod(0o600)
            os.chown(destination, account.pw_uid, account.pw_gid)
            subprocess.run(["systemctl", "restart", unit], check=False)
        raise
    print("Configured service:", args.role)


if __name__ == "__main__":
    main()

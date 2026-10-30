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
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run this installer as root after reviewing your configuration")
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
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "sentinel-" + args.role + ".service"], check=True)
    subprocess.run(["systemctl", "restart", "sentinel-" + args.role + ".service"], check=True)
    subprocess.run(["systemctl", "is-active", "sentinel-" + args.role + ".service"], check=True)
    print("Configured service:", args.role)


if __name__ == "__main__":
    main()

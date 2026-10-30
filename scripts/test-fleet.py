#!/usr/bin/env python3
"""Real PostgreSQL + mutual TLS + background agent integration, without host firewall changes."""
import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    try:
        return subprocess.run([str(a) for a in args], check=True, capture_output=True, text=True, **kwargs)
    except subprocess.CalledProcessError as error:
        print(error.stderr[-6000:])
        raise


def wait_for(check, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(.2)
    raise AssertionError("Timed out waiting for integration condition")


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", default="build")
    args = parser.parse_args()
    build = (ROOT / args.build).resolve()
    processes = []
    logs = []
    with tempfile.TemporaryDirectory(prefix="sentinel-fleet-") as temp:
        work = Path(temp)
        work.chmod(0o755)
        prefix = []
        user = getpass.getuser()
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            import pwd
            account = pwd.getpwnam("postgres")
            user = "postgres"
            prefix = ["runuser", "-u", user, "--"]
            pgwork = work / "postgres"
            pgwork.mkdir()
            os.chown(pgwork, account.pw_uid, account.pw_gid)
        else:
            pgwork = work / "postgres"
            pgwork.mkdir()
        pgbin = Path(run(["pg_config", "--bindir"]).stdout.strip())
        pgport = port()
        pgstarted = False
        try:
            run(prefix + [pgbin / "initdb", "-D", pgwork / "data", "--auth=trust", "--no-locale", "--encoding=UTF8"])
            run(prefix + [pgbin / "pg_ctl", "-D", pgwork / "data", "-l", pgwork / "server.log", "-o", f"-h 127.0.0.1 -p {pgport} -k {pgwork}", "-w", "start"])
            pgstarted = True
            run([pgbin / "createdb", "-h", "127.0.0.1", "-p", pgport, "-U", user, "sentinel_fleet_test"])
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", work / "ca.key", "-out", work / "ca.crt", "-subj", "/CN=Sentinel isolated test CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
            for name in ("server", "admin", "analyst", "agent", "unknown"):
                run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", work / f"{name}.key", "-out", work / f"{name}.csr", "-subj", f"/CN={name}"])
                ext = work / "extensions.txt"
                ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + ("serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n" if name == "server" else "clientAuth\n"))
                run(["openssl", "x509", "-req", "-in", work / f"{name}.csr", "-CA", work / "ca.crt", "-CAkey", work / "ca.key", "-CAcreateserial", "-out", work / f"{name}.crt", "-days", "1", "-extfile", ext])
            server_port, udp_port = port(), port()

            def identity(name):
                return {"ca": str(work / "ca.crt"), "certificate": str(work / f"{name}.crt"), "private_key": str(work / f"{name}.key")}

            def write(name, value):
                path = work / name
                path.write_text(json.dumps(value))
                path.chmod(0o600)
                return path

            server_config = write("server.json", dict(identity("server"), listen="127.0.0.1", port=server_port,
                database={"host": "127.0.0.1", "port": pgport, "name": "sentinel_fleet_test", "user": user}))
            for name, role in (("admin", "admin"), ("analyst", "analyst")):
                run([build / "siem-server", "--config", server_config, "--add-operator", work / f"{name}.crt", "--name", name, "--role", role])

            def start(binary, *arguments):
                log = open(work / f"{binary}-{len(logs)}.log", "w+")
                logs.append(log)
                process = subprocess.Popen([str(build / binary), *map(str, arguments)], stdout=log, stderr=log)
                processes.append(process)
                return process

            def stop(process):
                process.terminate()
                try:
                    process.wait(15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

            ready = work / "ready"
            server = start("siem-server", "--config", server_config, "--ready-file", ready)
            wait_for(ready.exists)

            def rpc(method, params=None, name="admin", expected=True):
                context = ssl.create_default_context(cafile=str(work / "ca.crt"))
                context.load_cert_chain(str(work / f"{name}.crt"), str(work / f"{name}.key"))
                with socket.create_connection(("127.0.0.1", server_port), timeout=5) as tcp:
                    with context.wrap_socket(tcp, server_hostname="localhost") as connection:
                        connection.sendall(json.dumps({"method": method, "params": params or {}}).encode() + b"\n")
                        data = b""
                        while b"\n" not in data:
                            chunk = connection.recv(65536)
                            assert chunk, "Server disconnected without response"
                            data += chunk
                        response = json.loads(data)
                assert response["ok"] == expected, response.get("error")
                return response.get("result", {})

            assert rpc("session")["role"] == "admin"
            rpc("devices.list", name="unknown", expected=False)
            agent_der = ssl.PEM_cert_to_DER_cert((work / "agent.crt").read_text())
            fingerprint = hashlib.sha256(agent_der).hexdigest()
            rpc("enrollment.create", {"identity": fingerprint}, name="analyst", expected=False)
            ticket = rpc("enrollment.create", {"identity": fingerprint})
            token_file = work / "enrollment.token"
            token_file.write_text(ticket["token"])
            token_file.chmod(0o600)
            config = write("agent.json", {"server": dict(identity("agent"), host="localhost", port=server_port),
                "enrollment_token_file": str(token_file), "state_dir": str(work / "agent-state"),
                "manage_firewall": False, "collect_system": False, "syslog_port": udp_port, "scan_roots": [str(work / "scan")], "queue_max_events": 1000})
            (work / "scan").mkdir()
            agent = start("siem-agent", "--config", config)
            wait_for(lambda: len(rpc("devices.list")["rows"]) == 1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.sendto(json.dumps({"message": "fleet-delivery-online", "severity": "info"}).encode(), ("127.0.0.1", udp_port))
            wait_for(lambda: rpc("events.list", {"search": "fleet-delivery-online"})["rows"])
            print("PASS: mutual TLS, certificate-bound enrollment, role checks and PostgreSQL delivery", flush=True)
            stop(server)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                for n in range(12):
                    udp.sendto(json.dumps({"message": f"fleet-offline-{n}"}).encode(), ("127.0.0.1", udp_port))
            time.sleep(1)
            stop(agent)
            ready.unlink()
            server = start("siem-server", "--config", server_config, "--ready-file", ready)
            wait_for(ready.exists)
            agent = start("siem-agent", "--config", config)
            wait_for(lambda: len(rpc("events.list", {"search": "fleet-offline-"})["rows"]) == 12)
            print("PASS: queued events survive server outage and agent restart", flush=True)
            old = rpc("policies.get", {"group": "default"})
            policy = old["policy"]
            policy["antivirus"] = {"enabled": True, "paths": [str(work / "scan")], "exclusions": [], "interval_minutes": 5}
            target = rpc("policies.set", {"group": "default", "expected_revision": old["revision"], "policy": policy})
            rpc("policies.set", {"group": "default", "expected_revision": old["revision"], "policy": policy}, expected=False)
            wait_for(lambda: json.loads(rpc("devices.list")["rows"][0]["health"]).get("policy_token") == target["token"])
            # Harmless scanner fixture, never a real malicious executable.
            (work / "scan" / "test.txt").write_bytes(base64.b64decode("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="))
            command = rpc("commands.scan", {"identity": fingerprint})["id"]
            wait_for(lambda: any(r["id"] == command and r["state"] == "complete" for r in rpc("commands.list")["rows"]), 60)
            assert rpc("events.list", {"search": "EICAR"})["rows"]
            print("PASS: versioned policy and remote background antivirus task", flush=True)
            console = write("console.json", dict(identity("admin"), host="localhost", port=server_port))
            env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
            run([build / "sentinel-siem", "--fleet", console, "--smoke-test", "--theme", "night"], env=env, timeout=20)
            print("PASS: native fleet console authenticates without database credentials", flush=True)
            rpc("devices.revoke", {"identity": fingerprint})
            rpc("agent.poll", {}, name="agent", expected=False)
            print("PASS: revoked endpoint cannot ingest or receive policies", flush=True)
        except Exception:
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.read()[-6000:])
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            for log in logs:
                log.close()
            if pgstarted:
                run(prefix + [pgbin / "pg_ctl", "-D", pgwork / "data", "-m", "immediate", "-w", "stop"])


if __name__ == "__main__":
    main()

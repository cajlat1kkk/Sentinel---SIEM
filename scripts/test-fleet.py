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
import sys
import struct
import tempfile
import time
import urllib.request

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
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", work / "ca.key", "-out", work / "ca.crt", "-subj", "/CN=Sentinel isolated test CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always"])
            for name in ("server", "admin", "analyst", "agent", "unknown"):
                run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", work / f"{name}.key", "-out", work / f"{name}.csr", "-subj", f"/CN={name}"])
                ext = work / "extensions.txt"
                ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nextendedKeyUsage=" + ("serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n" if name == "server" else "clientAuth\n"))
                run(["openssl", "x509", "-req", "-in", work / f"{name}.csr", "-CA", work / "ca.crt", "-CAkey", work / "ca.key", "-CAcreateserial", "-out", work / f"{name}.crt", "-days", "1", "-extfile", ext])
            server_port, udp_port, metrics_port, radar_port = port(), port(), port(), port()

            def identity(name):
                return {"ca": str(work / "ca.crt"), "certificate": str(work / f"{name}.crt"), "private_key": str(work / f"{name}.key")}

            def write(name, value):
                path = work / name
                path.write_text(json.dumps(value))
                path.chmod(0o600)
                return path

            server_config = write("server.json", dict(identity("server"), listen="127.0.0.1", port=server_port,
                metrics={"enabled": True, "listen": "127.0.0.1", "port": metrics_port},
                radar={"enabled": True, "port": radar_port, "scan_ports": 3, "scan_hosts": 10, "burst_bytes": 8192},
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

            def metrics_ready():
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{metrics_port}/metrics", timeout=2) as response:
                        value = response.read().decode()
                    return value if "sentinel_database_up 1\n" in value else None
                except OSError:
                    return None

            metrics = wait_for(metrics_ready)
            assert "sentinel_rpc_requests_total" in metrics
            assert "secret" not in metrics
            print("PASS: loopback Prometheus endpoint reports aggregate database and server health", flush=True)

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
            # VPP 25.10 L2/L3/L4 template layout, sent through the real loopback collector.
            fields = [(10, 4), (14, 4), (61, 1), (2, 8), (156, 8), (157, 8), (56, 6), (80, 6),
                      (256, 2), (8, 4), (12, 4), (4, 1), (1, 8), (7, 2), (11, 2), (6, 2)]
            def ipfix(set_id, payload, sequence=0):
                return struct.pack("!HHIIIHH", 10, 20 + len(payload), int(time.time()), sequence, 1, set_id, len(payload) + 4) + payload
            template = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", *f) for f in fields)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as exporter:
                exporter.sendto(ipfix(2, template), ("127.0.0.1", radar_port))
                records = b""
                for n in range(10):
                    values = {10: 1, 2: 4, 8: int.from_bytes(socket.inet_aton("192.0.2.77")),
                              12: int.from_bytes(socket.inet_aton("192.0.2.2")), 4: 6, 1: 4096, 7: 12345, 11: 80 + n}
                    records += b"".join(values.get(ie, 0).to_bytes(width, "big") for ie, width in fields)
                datagram = ipfix(256, records, 1)
                exporter.sendto(datagram, ("127.0.0.1", radar_port))
                exporter.sendto(datagram, ("127.0.0.1", radar_port))
                exporter.sendto(b"malformed", ("127.0.0.1", radar_port))
            wait_for(lambda: len(rpc("radar.flows")["rows"]) == 10)
            radar_status = rpc("radar.flows")["status"]
            assert radar_status["records"] == 10 and radar_status["duplicate_datagrams"] == 1
            assert radar_status["decode_errors"] == 1 and radar_status["storage_errors"] == 0
            assert rpc("radar.top", name="analyst")["rows"][0]["bytes"] == 40960
            rpc("radar.flows", name="agent", expected=False)
            wait_for(lambda: len(rpc("events.list", {"search": "Network radar:"})["rows"]) == 2)
            assert any("Network radar:" in r["title"] for r in rpc("incidents.list")["rows"])
            def radar_metrics_ready():
                with urllib.request.urlopen(f"http://127.0.0.1:{metrics_port}/metrics", timeout=3) as response:
                    body = response.read().decode()
                assert "192.0.2.77" not in body
                return "sentinel_radar_records_total 10\n" in body and "sentinel_radar_scan_alerts_total 1\n" in body
            wait_for(radar_metrics_ready)
            print("PASS: real UDP IPFIX → PostgreSQL flows/top sources → scan incident, volume alert, mTLS RBAC and radar Prometheus metrics", flush=True)
            maintenance = [sys.executable, ROOT / "scripts/sentinel-maintenance.py"]
            for profile in (server_config, console, config):
                report = json.loads(run([*maintenance, "diagnose", "--config", profile], timeout=60).stdout)
                assert report["ok"], report
            # TLS succeeds but an unregistered operator must fail the diagnostic.
            unknown = write("unknown-console.json", dict(identity("unknown"), host="localhost", port=server_port))
            denied = subprocess.run(list(map(str, [*maintenance, "diagnose", "--config", unknown])), capture_output=True, text=True, timeout=60)
            assert denied.returncode == 1 and not json.loads(denied.stdout)["ok"]
            print("PASS: diagnostics validate server DB, operator authorization and agent mTLS", flush=True)

            # Exercise pgpass against SCRAM authentication, while the running fleet keeps its original role.
            psql = [pgbin / "psql", "-X", "-h", "127.0.0.1", "-p", pgport, "-U", user,
                    "-d", "sentinel_fleet_test", "-v", "ON_ERROR_STOP=1", "-Atc"]
            backup_password = work / "backup.password"
            backup_password.write_text("test:backup\\password")
            backup_password.chmod(0o600)
            run([*psql, "CREATE ROLE sentinel_backup_test LOGIN PASSWORD 'test:backup\\password'; "
                 "GRANT CONNECT ON DATABASE sentinel_fleet_test TO sentinel_backup_test; "
                 "GRANT USAGE ON SCHEMA public TO sentinel_backup_test; "
                 "GRANT SELECT ON ALL TABLES IN SCHEMA public TO sentinel_backup_test; "
                 "GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_backup_test;"])
            hba = pgwork / "data/pg_hba.conf"
            # Support the existing run-as-postgres test mode without changing ownership.
            run(prefix + [sys.executable, "-c",
                "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text('host all sentinel_backup_test 127.0.0.1/32 scram-sha-256\\n'+p.read_text())", hba])
            run(prefix + [pgbin / "pg_ctl", "-D", pgwork / "data", "reload"])
            backup_configuration = json.loads(server_config.read_text())
            backup_configuration["database"].update(user="sentinel_backup_test", password_file=str(backup_password))
            backup_config = write("backup-server.json", backup_configuration)
            backup_result = json.loads(run([*maintenance, "backup", "--config", backup_config,
                                           "--output", work / "backups"], timeout=60).stdout)
            backup_dir = Path(backup_result["backup_directory"])
            run([*maintenance, "verify-backup", "--output", backup_dir], timeout=60)
            run([pgbin / "createdb", "-h", "127.0.0.1", "-p", pgport, "-U", user, "sentinel_restore_test"])
            run([pgbin / "pg_restore", "--exit-on-error", "--no-owner", "--no-acl", "-h", "127.0.0.1",
                 "-p", pgport, "-U", user, "-d", "sentinel_restore_test", backup_dir / "database.dump"], timeout=60)
            restored = [pgbin / "psql", "-X", "-h", "127.0.0.1", "-p", pgport, "-U", user,
                        "-d", "sentinel_restore_test", "-Atc"]
            assert run([*restored, "SELECT count(*) FROM events WHERE message LIKE 'fleet-offline-%'"]).stdout.strip() == "12"
            assert run([*restored, "SELECT count(*) FROM fleet_operators WHERE revoked=0"]).stdout.strip() == "2"
            assert run([*restored, "SELECT count(*) FROM fleet_devices"]).stdout.strip() == "1"
            assert run([*restored, "SELECT count(*) FROM radar_flows"]).stdout.strip() == "10"
            # Corruption must be detected before any restore is attempted.
            with (backup_dir / "database.dump").open("ab") as archive:
                archive.write(b"corruption")
            corrupt = subprocess.run(list(map(str, [*maintenance, "verify-backup", "--output", backup_dir])),
                                     capture_output=True, text=True, timeout=30)
            assert corrupt.returncode == 1 and "SHA-256" in json.loads(corrupt.stdout)["error"]
            print("PASS: private SCRAM backup, archive verification, isolated restore of events/devices/operators, corruption rejection", flush=True)
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

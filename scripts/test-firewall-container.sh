#!/usr/bin/env bash
# Exercise the real helper/nftables only inside an isolated Docker network namespace.
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=${SIEM_FIREWALL_TEST_IMAGE:-sentinel-siem-deb:local}
docker_args=(--rm -i --network none --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW)
helper=/work/build/siem-firewall-helper

if [[ ${1:-} == --host-runtime ]]; then
    # Offline fallback for this Linux development host. /usr and build are read-only;
    # the host network namespace and host /etc are never mounted or reused.
    image=${SIEM_FIREWALL_TEST_IMAGE:-python:3.12-slim}
    [[ -x "$project_root/build/siem-firewall-helper" ]] || { echo 'Build the helper first' >&2; exit 2; }
    docker_args+=(--mount type=bind,src=/usr,dst=/usr,readonly
        --mount "type=bind,src=$project_root/build,dst=/sentinel-build,readonly")
    helper=/sentinel-build/siem-firewall-helper
elif [[ $# -gt 0 ]]; then
    echo "Usage: $0 [--host-runtime]" >&2
    exit 2
fi

docker run "${docker_args[@]}" --env "SIEM_HELPER=$helper" --entrypoint /usr/bin/python3 "$image" - <<'PY'
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import struct
import time

nft_executable = shutil.which("nft")
assert nft_executable, "nftables is required in the test image"

def nft(*args):
    return subprocess.check_output([nft_executable, *args], text=True)

def snapshot(table):
    return json.loads(nft("-j", "list", "table", "inet", table))

with tempfile.TemporaryDirectory(prefix="sentinel-nft-") as directory:
    root = Path(directory)
    helper = os.environ["SIEM_HELPER"]
    nft("add", "table", "inet", "unrelated_lab_table")
    untouched = snapshot("unrelated_lab_table")
    policy = [{"name": "Lab UDP block", "direction": "output", "source": "any",
               "destination": "127.0.0.1", "protocol": "udp", "port": 49827,
               "action": "drop", "enabled": True}]
    path = root / "policy.json"
    def apply(value, expected=0):
        path.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run([helper, "--apply", str(path)], capture_output=True, text=True, timeout=20)
        assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)

    apply(policy)
    assert snapshot("unrelated_lab_table") == untouched, "Unrelated table was modified"
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 49827))
    listener.settimeout(0.3)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(b"blocked test packet", ("127.0.0.1", 49827))
    except PermissionError:
        # Local OUTPUT drops may report EPERM synchronously to sendto().
        pass
    try:
        listener.recvfrom(512)
        raise AssertionError("The supposedly blocked packet reached its receiver")
    except TimeoutError:
        pass
    blocked = snapshot("sentinel_siem")
    counters = [expression["counter"] for row in blocked["nftables"] if "rule" in row
                for expression in row["rule"].get("expr", []) if "counter" in expression]
    assert any(counter["packets"] >= 1 for counter in counters), blocked
    print("PASS: helper applies actual nftables rule and UDP delivery is blocked")

    policy[0]["source"] = "any; flush ruleset"
    apply(policy, expected=2)
    assert snapshot("sentinel_siem") == blocked, "Invalid policy changed the active rules"
    assert snapshot("unrelated_lab_table") == untouched
    print("PASS: malformed policy rejected without modifying active or unrelated rules")

    apply([])
    sender.sendto(b"allowed after rollback", ("127.0.0.1", 49827))
    assert listener.recvfrom(512)[0] == b"allowed after rollback"
    assert snapshot("unrelated_lab_table") == untouched
    print("PASS: applying the empty policy restores delivery, unrelated rules preserved")
    # v2 profiles must affect real traffic, including port ranges and source ports.
    sender2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender2.bind(("127.0.0.1",0))
    source_port = sender2.getsockname()[1]
    v2 = {"version":2,"stateful":False,"rules":[{"name":"Range", "direction":"output", "source":"any", "destination":"any", "protocol":"udp", "action":"drop", "source_ports":str(source_port), "destination_ports":"49826-49828"}]}
    apply(v2)
    try: sender2.sendto(b"range-block",("127.0.0.1",49827))
    except PermissionError: pass
    try:
        listener.recvfrom(512)
        raise AssertionError("Port-range rule did not block")
    except TimeoutError: pass
    sender.sendto(b"other source allowed",("127.0.0.1",49827))
    assert listener.recvfrom(512)[0] == b"other source allowed"
    print("PASS: v2 source port and destination port range enforce actual UDP filtering")

    v2["rules"] = [{"name":"Rate", "direction":"output", "source":"any", "destination":"any", "protocol":"udp", "port":49827, "action":"accept", "rate_limit":1,"log":True}]
    apply(v2)
    for _ in range(4):
        try: sender.sendto(b"rate",("127.0.0.1",49827))
        except PermissionError: pass
    received = 0
    while True:
        try: listener.recvfrom(512); received += 1
        except TimeoutError: break
    assert received == 1, received
    print("PASS: rate limit permits one UDP packet and drops excess packets")

    apply({"stateful":True})
    server = socket.socket(); server.bind(("127.0.0.1",0)); server.listen(2)
    server_port = server.getsockname()[1]
    client = socket.create_connection(("127.0.0.1",server_port)); accepted,_ = server.accept()
    accepted.settimeout(1)
    apply({"version":2,"stateful":True,"defaults":{"input":"drop"}})
    client.sendall(b"established stays alive")
    assert accepted.recv(128) == b"established stays alive"
    fresh = socket.socket(); fresh.settimeout(.3)
    try:
        fresh.connect(("127.0.0.1",server_port))
        raise AssertionError("New connection bypassed default-drop")
    except TimeoutError: pass
    finally: fresh.close()
    apply([]); client.close(); accepted.close(); server.close()
    print("PASS: established TCP survives stateful default-drop; new connections are blocked")

    # SNAT changes a real receiver's observed source address.
    apply({"stateful":False,"nat":[{"name":"SNAT lab", "type":"snat", "source":"127.0.0.1", "destination":"127.0.0.1", "protocol":"udp", "port":49827, "to_address":"127.0.0.2"}]})
    snat_sender = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    snat_sender.sendto(b"snat",("127.0.0.1",49827))
    data,peer = listener.recvfrom(512)
    assert data == b"snat" and peer[0] == "127.0.0.2", (data,peer)
    print("PASS: SNAT rewrites the actual received source address")

    # DNAT ingress test: veth pair wholly inside this disposable namespace.
    ip = shutil.which("ip")
    assert ip, "iproute2 is required for the NAT lab"
    def ipcmd(*args): subprocess.run([ip,*args],check=True,capture_output=True)
    ipcmd("link","add","sentinel-a","type","veth","peer","name","sentinel-b")
    ipcmd("link","set","sentinel-a","up"); ipcmd("link","set","sentinel-b","up")
    ipcmd("addr","add","10.77.0.1/24","dev","sentinel-b")
    mac = bytes.fromhex(Path("/sys/class/net/sentinel-b/address").read_text().strip().replace(":",""))
    receive_nat = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    receive_nat.bind(("10.77.0.1",49829)); receive_nat.settimeout(1)
    apply({"stateful":False,"nat":[{"name":"DNAT lab","type":"dnat","interface":"sentinel-b","protocol":"udp","port":49828,"to_address":"10.77.0.1","to_port":49829}]})
    payload = b"dnat-real-packet"
    udp = struct.pack("!HHHH",45678,49828,8+len(payload),0)+payload
    header = struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp),123,0,64,17,0,socket.inet_aton("10.77.0.2"),socket.inet_aton("10.77.0.1"))
    total = sum(struct.unpack("!10H",header)); total = (total & 65535)+(total >> 16); total = (total & 65535)+(total >> 16)
    header = header[:10]+struct.pack("!H",(~total)&65535)+header[12:]
    raw = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)); raw.bind(("sentinel-a",0))
    raw.send(mac + bytes.fromhex("020000000002") + b"\x08\x00" + header + udp)
    assert receive_nat.recvfrom(512)[0] == payload
    apply([])
    assert snapshot("unrelated_lab_table") == untouched
    print("PASS: DNAT rewrites an ingress UDP destination port; unrelated tables remain intact")

PY

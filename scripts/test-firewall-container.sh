#!/usr/bin/env bash
# Exercise the real helper/nftables only inside an isolated Docker network namespace.
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=${SIEM_FIREWALL_TEST_IMAGE:-sentinel-siem-deb:local}
docker_args=(--rm -i --network none --cap-drop ALL --cap-add NET_ADMIN)
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
PY

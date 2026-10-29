#!/usr/bin/env python3
"""Exercise actual DPDK PCAP PMDs, including two-port inline filtering.

Requires the native siem-dpdk executable and DPDK's net_pcap PMD. No physical
NIC, elevated privilege, hugepage configuration, or network access is used.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def packets(path):
    data = path.read_bytes()
    little = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    big = (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
    if len(data) < 24 or data[:4] not in little + big:
        raise AssertionError(f"Invalid PCAP output: {path}, header={data[:24].hex()}")
    endian = "<" if data[:4] in little else ">"
    result = []
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise AssertionError("Truncated PCAP record header")
        size = struct.unpack_from(endian + "IIII", data, offset)[2]
        offset += 16
        frame = data[offset:offset + size]
        if len(frame) != size:
            raise AssertionError("Truncated PCAP packet")
        result.append(frame)
        offset += size
    return result


def run(sensor, args):
    result = subprocess.run([str(sensor), *args], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f"DPDK failed ({result.returncode}):\n{result.stdout}\n{result.stderr}")
    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    errors = [row for row in records if row.get("type") == "error"]
    assert not errors, errors
    stats = [row for row in records if row.get("type") == "stats"]
    assert stats, "No actual sensor counters received"
    return records, stats[-1]


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensor", type=Path, default=root / "build/siem-dpdk")
    args = parser.parse_args()
    sensor = args.sensor.resolve()
    if not sensor.is_file():
        parser.error(f"Build the DPDK sensor first: {sensor}")
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix="sentinel-dpdk-test-") as directory:
        work = Path(directory)
        capture = work / "input.pcap"
        subprocess.run([sys.executable, str(root / "scripts/make-sample-pcap.py"), str(capture)],
                       check=True, capture_output=True)
        original = packets(capture)
        assert len(original) == 3
        empty = work / "empty.pcap"
        empty.write_bytes(capture.read_bytes()[:24])
        records, stats = run(sensor, ["--pcap", str(capture), "--seconds", "1"])
        assert stats["packets"] == 3 and stats["alerts"] == 2, stats
        assert stats["dropped"] == 0 and stats["forwarded"] == 0, stats
        events = [row for row in records if row.get("type") == "event"]
        assert len(events) == 3 and not any(row["blocked"] for row in events)
        assert any("SQL injection" in row["message"] for row in events)
        assert any("XSS" in row["message"] for row in events)
        print("PASS: native DPDK monitoring reads 3 packets, detects SQLi/XSS, blocks none")

        base = {"version": 2, "stateful": False}
        cases = [
            ("legacy-l7", [], [0], 2),
            ("legacy-l3l4", [{"name": "Lab HTTP block", "direction": "forward", "source": "10.0.0.0/8",
                       "destination": "any", "protocol": "tcp", "port": 80,
                       "action": "drop", "enabled": True}], [], 2),
            ("inspection-off", base, [0,1,2], 0),
            ("alert-only", dict(base, inspection={"mode":"alert", "sql_injection":True, "xss":True}), [0,1,2], 2),
            ("sql-only", dict(base, inspection={"mode":"block", "sql_injection":True}), [0,2], 1),
            ("default-drop", dict(base, defaults={"forward":"drop"}), [], 0),
            ("ports", dict(base, rules=[{"name":"Port ranges", "direction":"forward", "source":"any", "destination":"any", "protocol":"tcp", "source_ports":"1-65535", "destination_ports":"79-81,443", "action":"drop"}]), [], 0),
            ("host-block", dict(base, inspection={"mode":"block", "blocked_domains":["lab.invalid"]}), [], 3),
        ]
        for name, policy, expected_indices, expected_alerts in cases:
            expected_forwarded = len(expected_indices)
            policy_path = work / f"{name}.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            tx0, tx1 = work / f"{name}-tx0.pcap", work / f"{name}-tx1.pcap"
            eal = ["--lcores", f"0@{cpu}", "--main-lcore", "0", "--no-huge", "--no-pci",
                   "--no-shconf", "--no-telemetry",
                   f"--vdev=net_pcap0,rx_pcap={capture},tx_pcap={tx0}",
                   f"--vdev=net_pcap1,rx_pcap={empty},tx_pcap={tx1}"]
            records, stats = run(sensor, ["--inline", "--policy", str(policy_path), "--seconds", "1",
                                          "--", *eal])
            assert stats["packets"] == 3 and stats["alerts"] == expected_alerts, (name, stats)
            assert stats["forwarded"] == expected_forwarded, stats
            assert stats["dropped"] == 3 - expected_forwarded, stats
            assert len(packets(tx0)) == 0
            forwarded = packets(tx1)
            assert len(forwarded) == expected_forwarded
            assert forwarded == [original[i] for i in expected_indices], "Only permitted frames must be forwarded, unchanged"
            print(f"PASS: {name} inline forwards {expected_forwarded}, drops {3 - expected_forwarded}; TX PCAP verified")


if __name__ == "__main__":
    main()

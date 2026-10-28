#!/usr/bin/env python3
"""Generate harmless offline HTTP frames for the native DPDK integration test."""
import pathlib
import struct
import sys

target = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "samples/http-lab.pcap")
target.parent.mkdir(parents=True, exist_ok=True)
payloads = [b"GET / HTTP/1.1\r\nHost: lab.invalid\r\n\r\n",
            b"GET /?q=%27%20OR%201=1 HTTP/1.1\r\nHost: lab.invalid\r\n\r\n",
            b"GET /?q=%3Cscript%3E HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"]

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

with target.open("wb") as out:
    out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, payload in enumerate(payloads):
        src, dst = b"\x0a\0\0\x01", b"\x0a\0\0\x02"
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), index, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        tcp = struct.pack("!HHIIBBHHH", 50000 + index, 80, 1, 0, 0x50, 0x18, 65535, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
        frame = b"\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00" + ip + tcp + payload
        out.write(struct.pack("<IIII", 1793095200 + index, 0, len(frame), len(frame)))
        out.write(frame)
print(target)

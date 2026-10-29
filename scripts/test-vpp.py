#!/usr/bin/env python3
"""Run a real, private VPP instance and verify PCAP forwarding through pg0 -> pg1.

No physical NIC, host interface, firewall, hugepage or system service is changed.
Requires Linux, Python 3, and installed/built vpp + vppctl. --serve keeps the
tested instance available for the desktop GUI until Ctrl+C.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time


def read_packets(path):
    data = path.read_bytes()
    byte_orders = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
                   b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}
    if len(data) < 24 or data[:4] not in byte_orders:
        raise RuntimeError(f"Некорректный PCAP: {path}")
    endian = byte_orders[data[:4]]
    if struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise RuntimeError("Ожидался Ethernet PCAP")
    result, offset = [], 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise RuntimeError("Обрезан заголовок PCAP")
        length = struct.unpack_from(endian + "I", data, offset + 8)[0]
        offset += 16
        packet = data[offset:offset + length]
        if len(packet) != length:
            raise RuntimeError("Обрезан пакет PCAP")
        result.append(packet)
        offset += length
    return result


def main():
    root = Path(__file__).resolve().parents[1]
    local_bin = root / ".dev/vpp-build/bin"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true", help="После теста ждать Ctrl+C для проверки GUI")
    parser.add_argument("--vpp", default=str(local_bin / "vpp") if (local_bin / "vpp").is_file() else "vpp", help="Путь к настоящему vpp")
    parser.add_argument("--vppctl", default=str(local_bin / "vppctl") if (local_bin / "vppctl").is_file() else "vppctl", help="Путь к vppctl той же версии")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("Лаборатория VPP запускается на Linux")
    vpp, ctl = shutil.which(args.vpp), shutil.which(args.vppctl)
    if not vpp or not ctl:
        parser.error("Не найдены vpp и/или vppctl. Установите VPP по docs/NETWORK_LAB.md "
                     "или передайте --vpp /путь/vpp --vppctl /путь/vppctl. Тест не выполнен.")
    root = Path(__file__).resolve().parents[1]
    process = None
    with tempfile.TemporaryDirectory(prefix="sentinel-vpp-", dir="/tmp") as temporary:
        work = Path(temporary)
        log_path = work / "process.log"
        cli_socket = work / "cli.sock"
        template = (root / "samples/vpp-lab.conf").read_text(encoding="utf-8")
        config = template.replace("@RUNTIME@", str(work)).replace("@PREFIX@", work.name)
        config = config.replace("@CPU@", str(min(os.sched_getaffinity(0))))
        (work / "startup.conf").write_text(config, encoding="utf-8")

        def cli(command):
            result = subprocess.run([ctl, "-s", str(cli_socket), command],
                                    capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
            output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output).strip()
            if result.returncode or re.search(r"unknown input|unknown command|failed|not found|error:",
                                              output, re.IGNORECASE):
                raise RuntimeError(f"VPP CLI: {command}\n{output}")
            return output

        try:
            with log_path.open("w", encoding="utf-8") as log:
                process = subprocess.Popen([vpp, "-c", str(work / "startup.conf")],
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                deadline = time.monotonic() + 15
                while not cli_socket.exists():
                    if process.poll() is not None:
                        raise RuntimeError(f"VPP завершился при запуске (код {process.returncode})")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("VPP не создал CLI-сокет за 15 секунд")
                    time.sleep(0.1)
                print(cli("show version"), flush=True)
                capture = work / "input.pcap"
                subprocess.run([sys.executable, str(root / "scripts/make-sample-pcap.py"), str(capture)],
                               check=True, capture_output=True, timeout=5)
                output_pcap = work / "output.pcap"
                for command in [
                    "create packet-generator interface pg0",
                    "create packet-generator interface pg1",
                    "set interface state pg0 up",
                    "set interface state pg1 up",
                    "set interface l2 xconnect pg0 pg1",
                    "set interface l2 xconnect pg1 pg0",
                    f"packet-generator capture pg1 pcap {output_pcap} count 3",
                    f"packet-generator new {{ name sentinel source pg0 pcap {capture} limit 3 }}",
                    "packet-generator enable-stream sentinel",
                ]:
                    cli(command)
                deadline = time.monotonic() + 5
                while True:
                    streams = cli("show packet-generator")
                    if re.search(r"^sentinel\s+No\s+3\s", streams, re.MULTILINE):
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"Генератор не обработал 3 пакета:\n{streams}")
                    time.sleep(0.1)
                cli("packet-generator capture pg1 disable")
                if not output_pcap.exists():
                    raise RuntimeError("VPP не создал выходной PCAP; проверьте L2 xconnect\n" + cli("show interface") + "\n" + cli("show errors"))
                expected, actual = read_packets(capture), read_packets(output_pcap)
                if len(expected) != 3 or actual != expected:
                    raise RuntimeError(f"PCAP не совпадает: вход {len(expected)}, выход {len(actual)}")
                interfaces = cli("show interface")
                print(streams)
                print(interfaces)
                print("PASS: VPP pg0 → L2 xconnect → pg1: 3 Ethernet-кадра; выходной PCAP совпадает побайтно.",
                      flush=True)
                if args.serve:
                    print(f"В GUI откройте «Сеть» → VPP, CLI-сокет: {cli_socket}", flush=True)
                    print(f"Проверка вручную: {ctl} -s {cli_socket} show interface", flush=True)
                    print("Лаборатория работает. Ctrl+C завершит только этот VPP и удалит временные файлы.",
                          flush=True)
                    process.wait()
                    if process.returncode:
                        raise RuntimeError(f"VPP завершился (код {process.returncode})")
                return 0
        except KeyboardInterrupt:
            print("\nЛаборатория остановлена.")
            return 0
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            print(f"FAIL: {error}", file=sys.stderr)
            if log_path.exists():
                print(log_path.read_text(encoding="utf-8", errors="replace")[-6000:], file=sys.stderr)
            return 1
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            # Legacy VPP shared-memory API uses these exact names for our unique
            # prefix. Never touch a system VPP instance's global_vm/vpe-api.
            for suffix in ("-global_vm", "-vpe-api"):
                path = Path("/dev/shm") / (work.name + suffix)
                try:
                    path.unlink(missing_ok=True)
                except OSError as error:
                    print(f"Не удалось удалить временный SHM {path}: {error}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())

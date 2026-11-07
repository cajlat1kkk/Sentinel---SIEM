#!/usr/bin/env bash
# Read-only VPP/DPDK readiness report. Makes no network or service changes.
set -uo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
socket=${SIEM_VPP_SOCKET:-/run/vpp/cli.sock}
vppctl=$(command -v vppctl || true)
sensor="$project_root/build/siem-dpdk"

echo "== VPP =="
if command -v systemctl >/dev/null; then
    printf 'service: %s\n' "$(systemctl is-active vpp 2>/dev/null || true)"
fi
printf 'vppctl: %s\n' "${vppctl:-not found}"
printf 'socket: %s (%s)\n' "$socket" "$([[ -S $socket ]] && echo present || echo missing)"
if [[ -n $vppctl && -S $socket ]]; then
    "$vppctl" -s "$socket" show hardware-interfaces 2>&1 |
        grep -E '^[A-Za-z]|address .*[0-9a-f]{4}:[0-9a-f]{2}:|carrier|flags:' | head -40
fi

echo
echo "== DPDK ports =="
for device in /sys/bus/pci/devices/*; do
    [[ -r $device/class ]] || continue
    [[ $(<"$device/class") == 0x0200* ]] || continue
    bdf=$(basename "$device")
    driver=-
    [[ -L $device/driver ]] && driver=$(basename "$(readlink -f "$device/driver")")
    iommu=no
    [[ -e $device/iommu_group ]] && iommu=yes
    printf '%s  driver=%-12s iommu=%s\n' "$bdf" "$driver" "$iommu"
done

echo
echo "== Permissions =="
ls -ld /dev/hugepages 2>/dev/null || true
ls -l /dev/vfio/* 2>/dev/null || true
id -nG

echo
echo "== Binaries =="
printf 'siem-dpdk: %s\n' "$([[ -x $sensor ]] && echo "$sensor" || echo missing)"
printf 'siem-firewall-helper: %s\n' "$([[ -x $project_root/build/siem-firewall-helper ]] && echo present || echo missing)"

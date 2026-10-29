#!/usr/bin/env bash
# Build a private VPP core + CLI for the PCAP lab. Does not install/start a system service.
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for tool in curl tar sha256sum cmake ninja clang python3; do
    command -v "$tool" >/dev/null || { printf 'Missing build dependency: %s\n' "$tool" >&2; exit 2; }
done
source_root="$project_root/.dev/vpp-source"
mkdir -p "$source_root"
archive="$source_root/vpp.tar.gz"
expected=e3165f0209ae41d439d76ac6da11491eb07c7cecae199d7d9ed228155f4c9fcf
if [[ ! -f "$archive" ]]; then
    curl -fL --connect-timeout 15 --max-time 180 \
        https://codeload.github.com/FDio/vpp/tar.gz/refs/tags/v25.10 -o "$archive"
fi
printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status || { echo 'VPP archive checksum mismatch' >&2; exit 2; }
if [[ ! -d "$source_root/vpp-25.10" ]]; then
    tar -xf "$archive" -C "$source_root"
fi
printf 'v25.10-0-gsource\n' > "$source_root/vpp-25.10/src/scripts/.version"
if [[ ! -x "$project_root/.dev/vpp-python/bin/python3" ]]; then
    python3 -m venv "$project_root/.dev/vpp-python"
fi
"$project_root/.dev/vpp-python/bin/python3" -m pip install 'ply==3.11'
export GIT_CEILING_DIRECTORIES="$project_root/.dev"
export PATH="$project_root/.dev/vpp-python/bin:$PATH"
cmake -S "$source_root/vpp-25.10/src" -B "$project_root/.dev/vpp-build" -G Ninja \
    -DCMAKE_BUILD_TYPE=release -DCMAKE_C_COMPILER=clang \
    -DCMAKE_C_FLAGS=-Wno-error=implicit-enum-enum-cast \
    -DVPP_BUILD_NATIVE_ONLY=ON -DVPP_USE_LTO=OFF -DVPP_PLUGINS=, \
    -DPython3_EXECUTABLE="$project_root/.dev/vpp-python/bin/python3" \
    -DCMAKE_INSTALL_PREFIX="$project_root/.dev/vpp"
cmake --build "$project_root/.dev/vpp-build" --target vpp vppctl -j "${SIEM_BUILD_JOBS:-4}"
printf 'VPP ready: %s\nRun: bash scripts/test-vpp.sh\n' "$project_root/.dev/vpp-build/bin/vpp"

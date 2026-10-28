#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$project_root/dist/deb"
docker build --network "${SIEM_DOCKER_NETWORK:-default}" \
    --build-arg "BASE_IMAGE=${SIEM_DEB_BASE:-ubuntu:24.04}" \
    --build-arg "DEBIAN_MIRROR=${SIEM_DEBIAN_MIRROR:-}" \
    -f "$project_root/packaging/linux/Dockerfile" -t sentinel-siem-deb:local "$project_root"
container_id=$(docker create sentinel-siem-deb:local)
trap 'docker rm "$container_id" >/dev/null' EXIT
docker cp "$container_id:/work/build/sentinel-siem-0.2.0-Linux.deb" "$project_root/dist/deb/"

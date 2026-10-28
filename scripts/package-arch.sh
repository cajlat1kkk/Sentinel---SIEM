#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
package_dir="$project_root/dist/arch"
mkdir -p "$package_dir"
tar -czf "$package_dir/sentinel-siem-0.2.0.tar.gz" --transform='s,^,sentinel-siem-0.2.0/,' \
    -C "$project_root" CMakeLists.txt src assets tests packaging scripts samples docs .clang-format .github README.md
cp "$project_root/packaging/linux/PKGBUILD" "$package_dir/PKGBUILD"
cd "$package_dir"
makepkg --force --cleanbuild

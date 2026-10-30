#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
package_dir="$project_root/dist/arch"
mkdir -p "$package_dir"
project_version=$(python3 "$project_root/scripts/version.py")
tar -czf "$package_dir/sentinel-siem-$project_version.tar.gz" --transform="s,^,sentinel-siem-$project_version/," \
    -C "$project_root" CMakeLists.txt src assets tests packaging scripts samples docs .clang-format .github README.md
cp "$project_root/packaging/linux/PKGBUILD" "$package_dir/PKGBUILD"
sed -i "s/^pkgver=.*/pkgver=$project_version/" "$package_dir/PKGBUILD"
cd "$package_dir"
makepkg --force --cleanbuild

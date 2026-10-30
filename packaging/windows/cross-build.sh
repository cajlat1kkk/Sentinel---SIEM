#!/usr/bin/env bash
# Linux -> Windows x64, using pinned MSYS2 Qt/libpq binaries and native Qt host tools.
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
export SIEM_WINDOWS_SDK=${SIEM_WINDOWS_SDK:-/tmp/siem-windows-sdk}
export WINEPREFIX="$SIEM_WINDOWS_SDK/wineprefix"
export WINEDEBUG=${WINEDEBUG:--all}
qt_host=${SIEM_QT_HOST_PATH:-/usr}
project_version=$(python3 "$project_root/scripts/version.py")
for tool in cmake ninja python3 tar zstd x86_64-w64-mingw32-g++ x86_64-w64-mingw32-objdump wine winepath; do
    command -v "$tool" >/dev/null || { printf 'Missing tool: %s\n' "$tool" >&2; exit 1; }
done
python3 "$project_root/packaging/windows/cross-build.py" fetch
cat > "$SIEM_WINDOWS_SDK/toolchain.cmake" <<EOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH "$SIEM_WINDOWS_SDK/sysroot/mingw64" /usr/x86_64-w64-mingw32)
set(CMAKE_PREFIX_PATH "$SIEM_WINDOWS_SDK/sysroot/mingw64")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(QT_HOST_PATH "$qt_host" CACHE PATH "Native Qt host tools")
EOF
cmake -S "$project_root" -B "$SIEM_WINDOWS_SDK/build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$SIEM_WINDOWS_SDK/toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release -DSIEM_WITH_DPDK=OFF -DSIEM_BUILD_TESTS=ON
cmake --build "$SIEM_WINDOWS_SDK/build" -j "${SIEM_BUILD_JOBS:-4}"
python3 "$project_root/packaging/windows/cross-build.py" stage
portable="$project_root/dist/windows/portable"
portable_win=$(winepath -w "$portable")
if [ "${SIEM_WINDOWS_SMOKE:-1}" = 1 ]; then
    QT_QPA_PLATFORM=offscreen wine "$portable/sentinel-siem.exe" --demo --smoke-test
    QT_QPA_PLATFORM=offscreen wine "$portable/sentinel-siem.exe" --demo --theme night --smoke-test
    mkdir -p "$SIEM_WINDOWS_SDK/test-run"
    cp -a "$portable/." "$SIEM_WINDOWS_SDK/test-run/"
    cp "$SIEM_WINDOWS_SDK/build/siem-tests.exe" "$SIEM_WINDOWS_SDK/test-run/"
    cp "$SIEM_WINDOWS_SDK/sysroot/mingw64/bin/Qt6Test.dll" "$SIEM_WINDOWS_SDK/test-run/"
    test_report_win=$(winepath -w "$SIEM_WINDOWS_SDK/test-run/core-results.txt")
    wine "$SIEM_WINDOWS_SDK/test-run/siem-tests.exe" -o "$test_report_win,txt"
    cat "$SIEM_WINDOWS_SDK/test-run/core-results.txt"
    cp "$SIEM_WINDOWS_SDK/build/siem-ui-tests.exe" "$SIEM_WINDOWS_SDK/test-run/"
    ui_report_win=$(winepath -w "$SIEM_WINDOWS_SDK/test-run/ui-results.txt")
    QT_QPA_PLATFORM=offscreen wine "$SIEM_WINDOWS_SDK/test-run/siem-ui-tests.exe" -o "$ui_report_win,txt"
    cat "$SIEM_WINDOWS_SDK/test-run/ui-results.txt"
fi
script_win=$(winepath -w "$project_root/packaging/windows/installer.nsi")
output_win=$(winepath -w "$project_root/dist/windows/Sentinel-SIEM-$project_version-windows-x64-setup.exe")
uninstall_win=$(winepath -w "$SIEM_WINDOWS_SDK/uninstall-files.nsh")
wine "$SIEM_WINDOWS_SDK/sysroot/mingw64/bin/makensis.exe" /V2 \
    "/DVERSION=$project_version" "/DAPPDIR=$portable_win" "/DOUTPUT=$output_win" "/DUNINSTALL_LIST=$uninstall_win" "$script_win"
python3 - "$project_root/dist/windows" "$project_version" <<'PY'
import pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
shutil.make_archive(str(root / f'Sentinel-SIEM-{sys.argv[2]}-windows-x64-portable'), 'zip', root / 'portable')
print('Windows installer and portable ZIP:', root)
PY

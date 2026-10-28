$ErrorActionPreference = 'Stop'
# Run in a Visual Studio developer shell with Qt 6 bin in PATH and NSIS installed.
# PostgreSQL's libpq and dependencies must accompany the QPSQL Qt plugin.
$projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Set-Location $projectRoot
$pgBin = $env:SIEM_PG_RUNTIME_DIR
if (-not $pgBin) {
    $pgBin = Get-ChildItem 'C:\Program Files\PostgreSQL' -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1 | ForEach-Object { Join-Path $_.FullName 'bin' }
}
if (-not $pgBin -or -not (Test-Path "$pgBin\libpq.dll")) { throw 'Set SIEM_PG_RUNTIME_DIR to the PostgreSQL bin directory containing libpq.dll' }
cmake -S . -B build-windows -G Ninja -DCMAKE_BUILD_TYPE=Release -DSIEM_WITH_DPDK=OFF "-DSIEM_PG_RUNTIME_DIR=$pgBin"
if ($LASTEXITCODE -ne 0) { throw 'CMake configure failed' }
cmake --build build-windows --parallel 4
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
$env:PATH = "$pgBin;$env:PATH"
ctest --test-dir build-windows --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
Push-Location build-windows
cpack -G NSIS
if ($LASTEXITCODE -ne 0) { throw 'Packaging failed' }
Pop-Location

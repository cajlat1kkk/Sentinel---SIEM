#!/usr/bin/env bash
# Install ClamAV only in a disposable container, then detect a harmless custom fixture.
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
docker run --rm -i \
    --mount "type=bind,src=$project_root/tests/core_tests.cpp,dst=/source/core_tests.cpp,readonly" \
    --entrypoint /bin/bash sentinel-siem-deb:local -s <<'CONTAINER'
set -euo pipefail
apt-get -o Acquire::Retries=0 -o Acquire::https::Timeout=20 -o APT::Update::Error-Mode=any update >/dev/null
apt-get -o Acquire::Retries=0 -o Acquire::https::Timeout=20 install -y --no-install-recommends clamav >/dev/null
python3 - <<'PY'
from pathlib import Path
root = Path('/var/lib/clamav')
root.mkdir(parents=True, exist_ok=True)
marker = b'SENTINEL-CLAMAV-INTEGRATION-FIXTURE-ONLY'
(root / 'sentinel-lab.ndb').write_text('Sentinel.Integration:0:*:' + marker.hex() + '\n')
PY
cp /source/core_tests.cpp /work/tests/core_tests.cpp
cmake --build /work/build --target siem-tests -j 2 >/dev/null
SIEM_TEST_CLAMAV=1 /work/build/siem-tests clamavIntegration
CONTAINER

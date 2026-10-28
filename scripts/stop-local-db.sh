#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
pg_ctl -D "$project_root/.dev/postgres" -m fast -w stop

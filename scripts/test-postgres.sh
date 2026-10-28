#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d /tmp/sentinel-pg-test.XXXXXX)
test_port=${SIEM_TEST_PG_PORT:-55439}
cleanup() {
    pg_ctl -D "$test_root/data" -m fast stop >/dev/null 2>&1 || true
    rm -rf -- "$test_root"
}
trap cleanup EXIT
initdb -D "$test_root/data" --auth=trust --no-locale --encoding=UTF8 > "$test_root/init.log"
pg_ctl -D "$test_root/data" -l "$test_root/server.log" -o "-h 127.0.0.1 -p $test_port -k $test_root" -w start
createdb -h 127.0.0.1 -p "$test_port" sentinel_test
SIEM_TEST_PG_PORT="$test_port" "$project_root/build/siem-tests"
SIEM_DB_PORT="$test_port" SIEM_DB_NAME=sentinel_test SIEM_DB_USER="$(id -un)" QT_QPA_PLATFORM=offscreen \
    "$project_root/build/sentinel-siem" --connect-env --smoke-test

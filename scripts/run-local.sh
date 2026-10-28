#!/usr/bin/env bash
# Local development launcher: private PostgreSQL cluster + native desktop.
# Does not change the system PostgreSQL service or listen on external interfaces.
set -euo pipefail
umask 077
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
local_root="$project_root/.dev"
local_data="$local_root/postgres"
saved_port=55440
if [[ -f "$local_root/postgres-port" ]]; then
    saved_port=$(cat "$local_root/postgres-port")
fi
local_port=${SIEM_LOCAL_PG_PORT:-$saved_port}
[[ "$local_port" =~ ^[0-9]+$ ]] && ((local_port > 1023 && local_port < 65536)) || {
    echo 'SIEM_LOCAL_PG_PORT must be between 1024 and 65535' >&2; exit 2;
}
for binary in initdb pg_ctl createdb psql cmake; do
    command -v "$binary" >/dev/null || { echo "Missing dependency: $binary. See README.md." >&2; exit 2; }
done
mkdir -p "$local_root"
if [[ ! -f "$local_root/postgres-password" ]]; then
    if [[ -d "$local_data" ]]; then
        echo 'Existing local cluster has no password file. Restore .dev/postgres-password before continuing.' >&2
        exit 2
    fi
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$local_root/postgres-password"
fi
if [[ "$saved_port" != "$local_port" ]] && pg_ctl -D "$local_data" status >/dev/null 2>&1; then
    echo 'Stop the private cluster with scripts/stop-local-db.sh before changing its port.' >&2
    exit 2
fi
if [[ ! -f "$local_data/PG_VERSION" ]]; then
    initdb -D "$local_data" -U sentinel --pwfile="$local_root/postgres-password" \
        --auth=scram-sha-256 --locale=C.UTF-8 --encoding=UTF8 > "$local_root/init.log"
    printf '%s\n' "$local_port" > "$local_root/postgres-port"
fi
if ! pg_ctl -D "$local_data" status >/dev/null 2>&1; then
    # Disable Unix sockets for this cluster: use only the explicitly bound loopback TCP port.
    pg_ctl -D "$local_data" -l "$local_root/postgres.log" \
        -o "-h 127.0.0.1 -p $local_port -c unix_socket_directories=''" -w start
    printf '%s\n' "$local_port" > "$local_root/postgres-port"
fi
export PGPASSWORD
PGPASSWORD=$(cat "$local_root/postgres-password")
if [[ $(psql -h 127.0.0.1 -p "$local_port" -U sentinel -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname='sentinel'") != 1 ]]; then
    createdb -h 127.0.0.1 -p "$local_port" -U sentinel sentinel
fi
if [[ ! -x "$project_root/build/sentinel-siem" ]]; then
    cmake -S "$project_root" -B "$project_root/build" -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build "$project_root/build" -j 4
fi
export SIEM_DB_HOST=127.0.0.1 SIEM_DB_PORT="$local_port" SIEM_DB_NAME=sentinel SIEM_DB_USER=sentinel
export SIEM_DB_PASSWORD="$PGPASSWORD"
unset PGPASSWORD
exec "$project_root/build/sentinel-siem" --connect-env "$@"

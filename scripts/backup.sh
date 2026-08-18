#!/usr/bin/env bash
# Create a RailGate backup (database + REALITY key material).
#
#   ./backup.sh              write to $DATA_DIR/backups
#   ./backup.sh --list       list existing backups
#
# This is a thin wrapper around `vpnctl backup`, which performs a consistent
# SQLite snapshot rather than copying a file that may be mid-write.
set -euo pipefail

APP_ROOT="${APP_ROOT:-/opt/railgate}"
export PYTHONPATH="${PYTHONPATH:-$APP_ROOT}"

if [[ "${1:-}" == "--list" ]]; then
    exec python3 "$APP_ROOT/scripts/vpnctl" backups
fi

exec python3 "$APP_ROOT/scripts/vpnctl" backup "$@"

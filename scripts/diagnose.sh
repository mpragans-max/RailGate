#!/usr/bin/env bash
# Full RailGate diagnostics. Sensitive material is masked.
#
#   ./diagnose.sh          human-readable report
#   rg-diagnose            same command, installed on PATH
set -euo pipefail

APP_ROOT="${APP_ROOT:-/opt/railgate}"
export PYTHONPATH="${PYTHONPATH:-$APP_ROOT}"

exec python3 "$APP_ROOT/scripts/vpnctl" diagnose "$@"

#!/usr/bin/env bash
# RailGate container entrypoint.
#
#   (no arguments)  -> start the supervisor (Xray + admin API). This is what
#                      Railway runs.
#   any arguments   -> run them instead, e.g. `docker run railgate vpnctl list`
#                      or `docker run -it railgate bash`.
set -euo pipefail

export APP_ROOT="${APP_ROOT:-/opt/railgate}"
export PYTHONPATH="${PYTHONPATH:-$APP_ROOT}"
export PYTHONUNBUFFERED=1
export DATA_DIR="${DATA_DIR:-/data}"
export PORT="${PORT:-8080}"
export XRAY_PORT="${XRAY_PORT:-2443}"

if [[ $# -gt 0 ]]; then
    exec "$@"
fi

# The supervisor becomes PID 1 so SIGTERM from Railway reaches it directly and
# children are stopped and reaped cleanly during a deploy.
exec python3 "$APP_ROOT/scripts/supervisor.py"

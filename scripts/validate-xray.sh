#!/usr/bin/env bash
# Validate the Xray configuration with the real binary.
#
#   ./validate-xray.sh              validate the ACTIVE config on the volume
#   ./validate-xray.sh path.json    validate a specific file
#
# Exit code 0 = valid. Nothing is modified or restarted.
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
CONFIG="${1:-$DATA_DIR/xray/config.json}"

if [[ ! -x "$XRAY_BIN" ]]; then
    echo "ERROR: xray binary not found at $XRAY_BIN" >&2
    exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: configuration file not found: $CONFIG" >&2
    echo "       It is generated on first boot. Run: vpnctl resync" >&2
    exit 1
fi

echo "Binary : $("$XRAY_BIN" version | head -n 1)"
echo "Config : $CONFIG"
echo

if "$XRAY_BIN" run -test -c "$CONFIG"; then
    echo
    echo "RESULT: configuration is valid."
    exit 0
fi

echo
echo "RESULT: configuration is INVALID. The running configuration was not touched." >&2
exit 1

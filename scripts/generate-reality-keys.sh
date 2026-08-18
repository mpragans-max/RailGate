#!/usr/bin/env bash
# Generate (or inspect) the REALITY key material.
#
# Normally you never run this: the keys are created automatically on first boot
# and reused forever after, so redeploying does not invalidate client links.
#
#   ./generate-reality-keys.sh           show the current public material
#   ./generate-reality-keys.sh --rotate  generate a NEW key pair (destructive)
#
# Rotating invalidates every share link and QR code already handed out.
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
KEY_DIR="$DATA_DIR/xray"
PRIVATE_FILE="$KEY_DIR/reality-private-key"
PUBLIC_FILE="$KEY_DIR/reality-public-key"
SHORT_ID_FILE="$KEY_DIR/short-id"

rotate=0
[[ "${1:-}" == "--rotate" ]] && rotate=1

if [[ ! -x "$XRAY_BIN" ]]; then
    echo "ERROR: xray binary not found at $XRAY_BIN" >&2
    exit 1
fi

mkdir -p "$KEY_DIR"

if [[ -f "$PRIVATE_FILE" && $rotate -eq 0 ]]; then
    echo "REALITY key material already exists (reusing it)."
else
    if [[ $rotate -eq 1 ]]; then
        echo "WARNING: rotating the REALITY key pair invalidates every client link."
        read -r -p "Type 'rotate' to continue: " answer
        [[ "$answer" == "rotate" ]] || { echo "Cancelled."; exit 1; }
    fi

    output="$("$XRAY_BIN" x25519)"
    # v26.x prints: "PrivateKey: ..." / "Password (PublicKey): ..." / "Hash32: ..."
    private_key="$(awk -F': *' '/[Pp]rivate ?[Kk]ey/ {print $2; exit}' <<<"$output")"
    public_key="$(awk -F': *' '/Password|[Pp]ublic ?[Kk]ey/ {print $2; exit}' <<<"$output")"

    if [[ -z "$private_key" || -z "$public_key" ]]; then
        echo "ERROR: could not parse the output of '$XRAY_BIN x25519':" >&2
        echo "$output" >&2
        exit 1
    fi

    umask 077
    printf '%s\n' "$private_key" > "$PRIVATE_FILE"
    printf '%s\n' "$public_key"  > "$PUBLIC_FILE"
    openssl rand -hex 8          > "$SHORT_ID_FILE"
    chmod 600 "$PRIVATE_FILE"
    chmod 644 "$PUBLIC_FILE" "$SHORT_ID_FILE"
    echo "Generated new REALITY key material in $KEY_DIR"
fi

echo
echo "Client-side (public) values:"
echo "  Public key : $(cat "$PUBLIC_FILE")"
echo "  Short ID   : $(cat "$SHORT_ID_FILE")"
echo "  Private key: stored at $PRIVATE_FILE (never displayed)"
echo
echo "Apply the change with:  vpnctl resync --restart"

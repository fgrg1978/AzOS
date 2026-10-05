#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Deploy a new kernel to a running robot via OTA.
#
# Usage: ./tools/deploy.sh <robot-ip> [--platform vf2|k1] [--no-sign]
#
# Build → strip → sign → upload → watch boot.
set -e

CARGO="$HOME/.cargo/bin/cargo"
OBJCOPY="/opt/homebrew/opt/llvm/bin/llvm-objcopy"
PYTHON="/opt/homebrew/bin/python3.12"
REPO="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"
CURL="/usr/bin/curl"

ROBOT_IP="${1:?usage: $0 <robot-ip> [--platform vf2|k1] [--no-sign]}"
shift
PLATFORM="vf2"
SIGN=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform) PLATFORM="$2"; shift 2 ;;
        --no-sign)  SIGN=0; shift ;;
        *) echo "unknown option: $1"; exit 1 ;;
    esac
done

cd "$REPO"

echo "=== Build ($PLATFORM) ==="
"$CARGO" build --release --features "$PLATFORM" 2>&1 | /usr/bin/tail -3

ELF="target/riscv64imac-unknown-none-elf/release/azos_kernel"
BIN="target/kernel_${PLATFORM}.bin"
SIG="target/kernel_${PLATFORM}.sig"

echo ""
echo "=== Strip ==="
"$OBJCOPY" -O binary "$ELF" "$BIN"
SIZE=$(/usr/bin/stat -f%z "$BIN")
echo "binary: $BIN ($SIZE bytes)"

if [[ "$SIGN" -eq 1 ]]; then
    echo ""
    echo "=== Sign (F18) ==="
    if [[ ! -f "tools/keys/dev_priv.bin" ]]; then
        echo "error: tools/keys/dev_priv.bin not found."
        echo "hint : run 'python3 tools/gen_dev_key.py' once to generate."
        exit 1
    fi
    "$PYTHON" tools/sign_ota.py "$BIN" --priv tools/keys/dev_priv.bin --out "$SIG"
fi

echo ""
echo "=== Upload ($ROBOT_IP) ==="
UPLOAD_URL="http://${ROBOT_IP}:8080/ota/upload"
if [[ "$SIGN" -eq 1 ]]; then
    "$CURL" -s -X POST "$UPLOAD_URL" \
        -F "kernel=@${BIN}" \
        -F "signature=@${SIG}" \
        -F "platform=${PLATFORM}" \
        --max-time 60
else
    "$CURL" -s -X POST "$UPLOAD_URL" \
        -F "kernel=@${BIN}" \
        -F "platform=${PLATFORM}" \
        --max-time 60
fi

echo ""
echo "=== Watch boot ==="
echo "tailing robot status (Ctrl-C to stop)..."
"$CURL" -N "http://${ROBOT_IP}:8080/status/stream" || true

echo ""
echo "Done. Inspect /LOG/ on SD card if anything went wrong."

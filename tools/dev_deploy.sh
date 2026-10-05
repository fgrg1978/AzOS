#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# DEV01.C — Fast iteration deploy: build → strip → publish to TFTP → reset.
#
# Cycle time on M1 with incremental builds: ~5 seconds.
#
# Usage:
#   ./tools/dev_deploy.sh              # default: vf2 platform
#   ./tools/dev_deploy.sh --platform k1
#   ./tools/dev_deploy.sh --no-reset   # don't touch UART, just publish
#   ./tools/dev_deploy.sh --uart /dev/cu.usbserial-XXXX
#
# Pre-reqs:
#   1. sudo ./tools/dev_setup_tftp.sh start    (once per macOS reboot)
#   2. SD card has compiled boot.scr from boot/boot.scr.cmd
#   3. Board powered, UART connected (FTDI / built-in debug header)
#   4. Board and Mac on same L2 segment (Ethernet or shared WiFi)
set -e

# ── Constants ──────────────────────────────────────────────────────────────
CARGO="$HOME/.cargo/bin/cargo"
OBJCOPY="/opt/homebrew/opt/llvm/bin/llvm-objcopy"
REPO="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"
TFTP_ROOT="/private/tftpboot"
TFTP_KERNEL_NAME="kernel.bin"
KERNEL_ELF_NAME="kernel"
KERNEL_TARGET_TRIPLE="riscv64imac-unknown-none-elf"
DEFAULT_UART_GLOB="/dev/cu.usbserial-*"

# Defaults — overridable via flags
PLATFORM="vf2"
DO_RESET=1
UART_DEV=""

# ── Parse args ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform) PLATFORM="$2"; shift 2 ;;
        --no-reset) DO_RESET=0; shift ;;
        --uart)     UART_DEV="$2"; shift 2 ;;
        -h|--help)
            /usr/bin/sed -n '2,15p' "$0"
            exit 0
            ;;
        *) echo "unknown option: $1"; exit 1 ;;
    esac
done

cd "$REPO"

# ── 1. Build kernel ────────────────────────────────────────────────────────
echo "[1/4] cargo build --release --features $PLATFORM"
T_START=$(/bin/date +%s)

# Suppress most output so iteration feels fast; show last 3 lines for context.
"$CARGO" build --release --features "$PLATFORM" 2>&1 | /usr/bin/tail -3

ELF="target/${KERNEL_TARGET_TRIPLE}/release/${KERNEL_ELF_NAME}"
if [[ ! -f "$ELF" ]]; then
    echo "ERROR: kernel ELF not found: $ELF"
    echo "       (cargo build may have failed silently)"
    exit 1
fi

# ── 2. Convert ELF → flat binary for U-Boot booti ─────────────────────────
echo "[2/4] objcopy → flat binary"
BIN_TMP=$(/usr/bin/mktemp -t kernel.bin.XXXXXX)
"$OBJCOPY" -O binary "$ELF" "$BIN_TMP"
BIN_SIZE=$(/usr/bin/stat -f%z "$BIN_TMP")
echo "       binary: $BIN_SIZE bytes"

# ── 3. Publish to TFTP root ────────────────────────────────────────────────
echo "[3/4] publish → $TFTP_ROOT/$TFTP_KERNEL_NAME"
if [[ ! -d "$TFTP_ROOT" ]]; then
    echo "ERROR: $TFTP_ROOT does not exist."
    echo "       run: sudo ./tools/dev_setup_tftp.sh start"
    /bin/rm -f "$BIN_TMP"
    exit 1
fi

# Atomic publish: write to .tmp then rename. Avoids the board fetching a
# half-written file if TFTP request races with our copy.
TFTP_TMP="$TFTP_ROOT/${TFTP_KERNEL_NAME}.tmp"
TFTP_FINAL="$TFTP_ROOT/${TFTP_KERNEL_NAME}"

# Need sudo if TFTP_ROOT is owned by root:wheel (default).
if [[ -w "$TFTP_ROOT" ]]; then
    /bin/cp "$BIN_TMP" "$TFTP_TMP"
    /bin/mv "$TFTP_TMP" "$TFTP_FINAL"
else
    /usr/bin/sudo /bin/cp "$BIN_TMP" "$TFTP_TMP"
    /usr/bin/sudo /bin/mv "$TFTP_TMP" "$TFTP_FINAL"
fi
/bin/rm -f "$BIN_TMP"

# ── 4. Trigger reset on board ──────────────────────────────────────────────
if [[ "$DO_RESET" -eq 1 ]]; then
    echo "[4/4] reset board via UART"
    if "$REPO/tools/dev_reset.sh" ${UART_DEV:+--uart "$UART_DEV"}; then
        :
    else
        echo "       (reset failed — board may need manual power cycle)"
    fi
else
    echo "[4/4] skipping reset (--no-reset)"
fi

T_END=$(/bin/date +%s)
echo ""
echo "✓ Deploy complete in $((T_END - T_START))s. Watch boot:"
echo "    ./tools/dev_uart.py ${UART_DEV:+--device $UART_DEV}"

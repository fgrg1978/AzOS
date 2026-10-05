#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# DEV01.E — Reset RISC-V board via UART without touching the SD card.
#
# Strategy:
#   1. Open the FTDI/USB-UART device.
#   2. Drop DTR low for 100ms then high again. Many dev boards (VF2,
#      K1 with proper wiring) have RESET tied to DTR — this triggers a
#      hardware reset.
#   3. If DTR-reset doesn't apply (board has no such wiring), fall back
#      to sending the U-Boot "reset" command at the prompt (only works
#      if the board is currently sitting at the U-Boot CLI; useless if
#      the kernel is running and crashed without a panic handler).
#
# Usage:
#   ./tools/dev_reset.sh                         # auto-detect UART
#   ./tools/dev_reset.sh --uart /dev/cu.usbserial-A50285BI
#   ./tools/dev_reset.sh --method dtr            # hard reset (default)
#   ./tools/dev_reset.sh --method uboot          # send "reset\n" string
set -e

# ── Constants ──────────────────────────────────────────────────────────────
PYTHON="/opt/homebrew/bin/python3.12"
DEFAULT_UART_GLOB="/dev/cu.usbserial-*"
UART_BAUD=115200
DTR_PULSE_MS=100
UBOOT_PROMPT_WAIT_S=2

# Defaults
UART_DEV=""
METHOD="dtr"

# ── Parse args ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --uart)   UART_DEV="$2"; shift 2 ;;
        --method) METHOD="$2"; shift 2 ;;
        -h|--help)
            /usr/bin/sed -n '2,16p' "$0"
            exit 0
            ;;
        *) echo "unknown option: $1"; exit 1 ;;
    esac
done

# ── Auto-detect UART if not specified ──────────────────────────────────────
if [[ -z "$UART_DEV" ]]; then
    UART_DEV=$(/bin/ls $DEFAULT_UART_GLOB 2>/dev/null | /usr/bin/head -1 || true)
    if [[ -z "$UART_DEV" ]]; then
        echo "error: no UART device found matching $DEFAULT_UART_GLOB"
        echo "       plug in FTDI cable or pass --uart /dev/cu.usbserial-XXXX"
        exit 1
    fi
    echo "auto-detected UART: $UART_DEV"
fi

if [[ ! -e "$UART_DEV" ]]; then
    echo "error: UART device does not exist: $UART_DEV"
    exit 1
fi

# ── Drive the reset via Python (pyserial handles DTR + writes uniformly) ──
"$PYTHON" -c "
import sys, time, glob
try:
    import serial
except ImportError:
    print('error: pyserial not installed. run: pip3 install pyserial', file=sys.stderr)
    sys.exit(2)

UART_BAUD = $UART_BAUD
DTR_PULSE_MS = $DTR_PULSE_MS
UBOOT_PROMPT_WAIT_S = $UBOOT_PROMPT_WAIT_S
UART = '$UART_DEV'
METHOD = '$METHOD'

ser = serial.Serial(UART, UART_BAUD, timeout=1)
try:
    if METHOD == 'dtr':
        # DTR-pulse hardware reset.
        ser.dtr = False
        time.sleep(DTR_PULSE_MS / 1000.0)
        ser.dtr = True
        print(f'  ✓ DTR-pulse reset sent on {UART}')
    elif METHOD == 'uboot':
        # Send Ctrl-C to interrupt any auto-boot, then 'reset'.
        ser.write(b'\\x03')   # ctrl-C
        time.sleep(UBOOT_PROMPT_WAIT_S / 4.0)
        ser.write(b'\\nreset\\n')
        ser.flush()
        time.sleep(UBOOT_PROMPT_WAIT_S)
        print(f'  ✓ U-Boot reset command sent on {UART}')
    else:
        print(f'error: unknown method {METHOD!r} (use dtr|uboot)', file=sys.stderr)
        sys.exit(1)
finally:
    ser.close()
"

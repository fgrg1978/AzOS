#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Launch kernel in QEMU. Usage: ./tools/qemu.sh [mode]
#
# Modes:
#   (default)   — 1 CPU, minimal (fast start)
#   smp         — 4 CPUs
#   full        — 4 CPUs + VirtIO disk + network (TCP port 8080 forwarded)
#   rvv         — 1 CPU + RVV 1.0 vector extension
#   full-rvv    — 4 CPUs + disk + net + RVV 1.0
#   gdb         — 1 CPU + GDB server on :1234 (paused at start)

MAKE="/usr/bin/make"
REPO="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"
MODE="${1:-default}"

cd "$REPO"

case "$MODE" in
    smp)
        exec "$MAKE" qemu-smp
        ;;
    full)
        exec "$MAKE" qemu-full-smp
        ;;
    rvv)
        exec "$MAKE" qemu-rvv
        ;;
    full-rvv)
        exec "$MAKE" qemu-full-smp-rvv
        ;;
    gdb)
        exec "$MAKE" qemu-gdb
        ;;
    default|*)
        exec "$MAKE" qemu
        ;;
esac

#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Launch kernel in QEMU. Usage: ./tools/dev/qemu.sh [mode]
#
# Modes:
#   (default)   — 1 CPU, minimal (fast start)
#   smp         — 4 CPUs
#   full        — 4 CPUs + VirtIO disk + network (TCP port 8080 forwarded)
#   rvv         — 1 CPU + RVV 1.0 vector extension
#   full-rvv    — 4 CPUs + disk + net + RVV 1.0
#   gdb         — 1 CPU + GDB server on :1234 (paused at start)
#   hv-riscv64  — the H extension on (-cpu rv64,h=true): a hypervisor kernel (Kconfig VIRT) finds it
#   hv-aarch64  — EL2 resident (QEMU virt, virtualization=on): the boot stub keeps it
#   hv-x86_64   — AMD SVM in TCG (-cpu max,svm=on)

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
    hv-riscv64)
        # QEMU's default rv64 CPU has no H; without it the probe reports the
        # extension absent and a VIRT kernel boots without guests.
        exec "$MAKE" qemu QEMU_FLAGS="-machine virt -nographic -bios default -cpu rv64,h=true"
        ;;
    hv-aarch64)
        # `virtualization=on` gives the guest-less boot an EL2 to keep.
        exec "$MAKE" qemu-aarch64-el2
        ;;
    hv-x86_64)
        # TCG implements SVM (nested paging included); `max` is also what the
        # kernel's x86-64-v2 baseline needs.
        exec "$MAKE" qemu-x86_64 QEMU_X86_64_CPU=max,svm=on
        ;;
    default|*)
        exec "$MAKE" qemu
        ;;
esac

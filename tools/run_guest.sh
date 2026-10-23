#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# AzOS inside AzOS: boot the hypervisor kernel under QEMU with nested
# virtualisation and wait for the guest's banner.
#
#   tools/run_guest.sh <riscv64|aarch64> [--no-build] [--timeout SECONDS] [--log FILE]
#   tools/run_guest.sh <isa> --judge FILE      only judge a console log (no build, no QEMU)
#
# `make ARCH=<isa> azos-guest` (mk/images.mk) builds the host kernel
# (config/defconfigs/robot-sbc-<isa>-dev+qemu+linux+hv-host+hv-example-guest.config: VIRT on,
# Kconfig HV_EXAMPLE_GUEST), the
# guest kernel (config/defconfigs/generic-sbc-<isa>-dev+qemu+hv-guest.config) and the host volume that
# carries VMMD.ELF, VM/GUEST.BIN and VM/DISK.IMG; --no-build uses what it
# left. QEMU then runs the host with the CPU's virtualisation extension on
# (riscv64 -cpu rv64,h=true; aarch64 -M virt,virtualization=on,gic-version=3),
# and the script waits for the guest kernel's banner on the guest console: VMMD.ELF puts
# `[vm0] ` in front of every line the guest prints (vmmd/src/console.rs TAG),
# so the host kernel's own lines cannot pass for it. x86_64 is refused: the
# monitor has no entry for an x86_64 guest image yet (mk/images.mk).
#
# The tool is a manual one: the gate has no row that boots the guest, because the
# monitor cannot map a whole guest kernel's RAM today (Kconfig
# HV_EXAMPLE_GUEST_MEM_MIB); the gate runs only the judge's canary (--judge).
#
# Exit status: 0 the banner arrived, 1 it did not (the host's lines that say
# why are printed), 2 a build or a usage error. QEMU stays at most four at a
# time on the host (this waits for a slot, and takes it under a lock, so two
# runs cannot both see the last free one); the QEMU this starts is killed on
# the way out, whatever the exit, a signal (INT, TERM) included.

set -uo pipefail

usage() { echo "usage: $0 <riscv64|aarch64> [--no-build] [--timeout SECONDS] [--log FILE] | --judge FILE" >&2; exit 2; }

[ $# -ge 1 ] || usage
case "$1" in
    riscv64|rv)  ISA=riscv64 ;;
    aarch64|arm) ISA=aarch64 ;;
    x86_64|x86)  echo "run_guest: no x86_64 guest entry yet (mk/images.mk)" >&2; exit 2 ;;
    *) usage ;;
esac
shift
BUILD=1
TIMEOUT="${GUEST_TIMEOUT:-300}"
LOG=""
JUDGE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) BUILD=0; shift ;;
        --timeout)  [ $# -ge 2 ] || usage; TIMEOUT="$2"; shift 2 ;;
        --log)      [ $# -ge 2 ] || usage; LOG="$2"; shift 2 ;;
        --judge)    [ $# -ge 2 ] || usage; JUDGE="$2"; shift 2 ;;
        *) usage ;;
    esac
done
case "$TIMEOUT" in ''|*[!0-9]*|0) echo "run_guest: --timeout wants a positive number of seconds" >&2; exit 2 ;; esac

PID=""
LOCK="${AZOS_QEMU_SLOT_LOCK:-/tmp/azos-qemu-slot.lock.d}"
HELD=0
cleanup() {
    [ -z "$PID" ] || { kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }
    [ "$HELD" = 1 ] && rm -rf "$LOCK"
    return 0
}
# EXIT alone does not run for a signal that ends the shell: INT and TERM leave
# through `exit`, which does run it.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "$ISA" in
    riscv64) BANNER='AzOS Rust kernel booted!' ;;
    aarch64) BANNER='AzOS Rust kernel booted! (aarch64)' ;;
esac
# The guest's lines: `[vm0] ` first, the banner of the guest kernel after it.
guest_banner() { tr -d '\r' <"$1" | awk -v b="$BANNER" 'index($0, "[vm0] ") == 1 && index($0, b) { print; exit }'; }
if [ -n "$JUDGE" ]; then
    [ -n "$(guest_banner "$JUDGE")" ]
    exit $?
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AZOS_OUT="${AZOS_OUT:-$(python3 "$REPO_ROOT/tools/out_dir.py")}"; export AZOS_OUT
DIR="$AZOS_OUT/build/azos-guest/$ISA"
[ -n "$LOG" ] || LOG="$DIR/run.log"

if [ "$BUILD" = 1 ]; then
    mkdir -p "$DIR"
    if ! make -s -C "$REPO_ROOT" ARCH="$ISA" azos-guest </dev/null >"$DIR/build.log" 2>&1; then
        echo "run_guest: make ARCH=$ISA azos-guest failed (see $DIR/build.log):" >&2
        grep -a "error\|Error\|\*\*\*" "$DIR/build.log" | sed -n '1,20p' >&2
        exit 2
    fi
fi
for f in host.kernel host-volume.img; do
    [ -f "$DIR/$f" ] || { echo "run_guest: $DIR/$f is missing (make ARCH=$ISA azos-guest)" >&2; exit 2; }
done

# A copy of the volume per run: the host writes its FAT (boot counters, logs).
VOL="$DIR/run-volume.img"
cp "$DIR/host-volume.img" "$VOL"

DRIVE="-global virtio-mmio.force-legacy=false -drive file=$VOL,if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0"
case "$ISA" in
    riscv64)
        QEMU_BIN=qemu-system-riscv64
        QEMU_ARGS="-machine virt -cpu rv64,h=true -smp 2 -m 256M -nographic -bios default -kernel $DIR/host.kernel $DRIVE"
        ;;
    aarch64)
        QEMU_BIN=qemu-system-aarch64
        QEMU_ARGS="-M virt,virtualization=on,gic-version=3 -cpu max,pauth=on -smp 2 -m 256M -nographic -kernel $DIR/host.kernel $DRIVE"
        ;;
esac

qemu_count() { # QEMU processes on the host, any ISA
    echo $(( $(pgrep -x qemu-system-riscv64 | wc -l) + $(pgrep -x qemu-system-aarch64 | wc -l) + $(pgrep -x qemu-system-x86_64 | wc -l) ))
}

# A QEMU slot is taken under a lock: the count and the start are one step, so
# runs of this script (the gate starts several at once) cannot all pass the
# check on the same free slot. The lock is held until the new QEMU shows in the
# count (or a few seconds pass); a lock whose owner is gone is taken over.
take_lock() {
    until mkdir "$LOCK" 2>/dev/null; do
        owner="$(cat "$LOCK/pid" 2>/dev/null)"
        if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then rm -rf "$LOCK"; continue; fi
        sleep 1
    done
    HELD=1
    echo $$ >"$LOCK/pid"
}
take_lock
while [ "$(qemu_count)" -ge 4 ]; do sleep 2; done

mkdir -p "$(dirname "$LOG")"
: >"$LOG"
BEFORE="$(qemu_count)"
# shellcheck disable=SC2086
"$QEMU_BIN" $QEMU_ARGS </dev/null >"$LOG" 2>&1 &
PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(qemu_count)" -gt "$BEFORE" ] && break
    sleep 0.5
done
rm -rf "$LOCK"; HELD=0

DEADLINE=$((SECONDS + TIMEOUT))
FOUND=""
while [ "$SECONDS" -lt "$DEADLINE" ]; do
    FOUND="$(guest_banner "$LOG")"
    [ -n "$FOUND" ] && break
    kill -0 "$PID" 2>/dev/null || break
    sleep 1
done

if [ -n "$FOUND" ]; then
    echo "GUEST banner ($ISA): $FOUND"
    exit 0
fi
if kill -0 "$PID" 2>/dev/null; then
    echo "run_guest ($ISA): no guest banner within ${TIMEOUT}s" >&2
else
    echo "run_guest ($ISA): QEMU ended without a guest banner" >&2
fi
echo "  host lines about the guest ($LOG):" >&2
tr -d '\r' <"$LOG" | grep -a -i "\[HV\]\|vmmd\|\[vm0\]\|guest\|panic\|FAILED" | sed -n '1,30p;' | sed 's/^/    /' >&2
exit 1

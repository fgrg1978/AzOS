#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# vsbench_split: what the EL1/EL2 split costs on aarch64. The SAME tree is
# built twice, as a hosted image (VIRT_HOSTED, the stub) and as a split image
# (the resident monitor), and each is booted on the SAME QEMU line:
#
#   qemu-system-aarch64 -M virt,virtualization=on,gic-version=3 -icount shift=0,sleep=off
#
# under TCG (HVF has no nested EL2 on this host, so no row of the split runs on
# HVF). Under `-icount shift=0` virtual time advances one nanosecond per
# instruction: every ns/op below is instructions per op, identical across runs.
# TCG shows instructions only, never the cost of a two-stage walk or a cache
# miss: real numbers wait for a board.
#
# ARM TEST PHASE ONLY. The split image has never booted (ARCH_HAS_HYP_MONITOR
# is unset on arm, R14 has not run): nothing here ran when it was written, and
# the gate rows that wrap it wait for HYP_MON_ROWS=1.
#
# ## What it measures
#
# 1. Monitor lanes (kernel feature `hyp-cost-probe`,
#    kernel/src/entry/aarch64/ext/hyp_cost.rs): null call, PSCI call,
#    kernel-table map and write, text patch, TTBR0 write, CPU_ON to online.
#    Each is timed before the image lock and after the last lock in one boot, so
#    the split image's pair is the same code path with and without the monitor.
#    The hosted image runs the same lanes with nothing locked: its pair is the
#    control (how far a lane moves by itself).
# 2. System lanes: the ring-3 vsbench lanes of both images (syscall-floor,
#    ipc-roundtrip, ctxsw-loaded, mmap+munmap, map+touch/pg, thread
#    create+join, fork+exit, fork+exit+wait).
# 3. Linux pair, optional: the Linux vsbench of tools/bench/vsbench_aarch64.sh
#    booted with `kvm-arm.mode=nvhe` and with `kvm-arm.mode=protected` (pKVM) on
#    the same QEMU line. It needs the initramfs that script leaves
#    ($VSBENCH_SPLIT_LINUX_INITRAMFS, default its work dir's) and the arm64
#    Linux of tools/bench/vsbench_linux.conf. That the image has KVM built in,
#    and that pKVM initialises under TCG, are both unverified.
#
# `tools/bench/hyp_cost.py compare` judges the pair and prints the table; read
# its "how to read" text in the design notes. A kernel lane with no counterpart
# in Linux says so in its row.
#
# ## Run
#
#   bash tools/bench/vsbench_split.sh
#
# Env: QEMU_AARCH64, CARGO, WAIT_SECS (default 90, per boot), VSBENCH_SPLIT_CPU
# (default max,pauth=on: FEAT_FGT; cortex-a76 gives the TVM pin),
# VSBENCH_SPLIT_COST_SMP (default 2: the CPU_ON lane needs a secondary),
# VSBENCH_SPLIT_LINUX_IMAGE, VSBENCH_SPLIT_LINUX_INITRAMFS.

set -u
AZOS_OUT="${AZOS_OUT:-$(python3 "$(dirname "$0")/../lib/out_dir.py")}"; export AZOS_OUT
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CARGO="${CARGO:-cargo}"
QEMU_AARCH64="${QEMU_AARCH64:-qemu-system-aarch64}"
WAIT_SECS="${WAIT_SECS:-90}"
CPU="${VSBENCH_SPLIT_CPU:-max,pauth=on}"
COST_SMP="${VSBENCH_SPLIT_COST_SMP:-2}"
MACHINE="virt,virtualization=on,gic-version=3"
ICOUNT="-icount shift=0,sleep=off"
TARGET_DIR="${VSBENCH_SPLIT_TARGET:-$AZOS_OUT/target/vsbench-split}"
WORK="${VSBENCH_SPLIT_WORK:-$AZOS_OUT/build/vsbench-split}"
BENCH_MINIMAL_BANNER='[BENCH] bench-minimal: only idle+autorun run; all other tasks parked'
TRIPLE=aarch64-unknown-none-softfloat

die() { echo "vsbench_split: $*" >&2; exit 1; }
rm -rf "$WORK"; mkdir -p "$WORK" "$TARGET_DIR"

( cd "$REPO_ROOT" && make ALL_USER_IMAGES=1 "$AZOS_OUT/build/image_hashes_aarch64.rs" >/dev/null 2>&1 ) \
    || die "could not regenerate image_hashes_aarch64.rs"
( cd "$REPO_ROOT" && make "$AZOS_OUT/build/disk-aarch64-vsbench.img" >/dev/null 2>&1 ) \
    || die "could not build disk-aarch64-vsbench.img"
bash "$REPO_ROOT/tools/build/hyp_mon.sh" aarch64 "$AZOS_OUT/build/aarch64/hyp-mon.bin" >"$WORK/build-monitor.log" 2>&1 \
    || die "could not build the monitor blob, see $WORK/build-monitor.log"

CONFIG="$WORK/aarch64.config"
{ grep -v 'LOG_LEVEL' "$REPO_ROOT/config/defconfigs/robot-sbc-aarch64-dev+qemu+linux+gui.config" \
    && echo "CONFIG_LOG_LEVEL_WARN=y"; } >"$CONFIG" \
    && ( cd "$REPO_ROOT" && KCONFIG_CONFIG="$CONFIG" python3 -m olddefconfig >/dev/null 2>&1 ) \
    || die "could not expand the aarch64 configuration"

OBJCOPY="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
build() { # build <name> <selection>  -> $WORK/<name>.img
    local name="$1" sel="$2"
    ( cd "$REPO_ROOT" && args="$(python3 tools/build/kconfig_to_cargo.py --select "$sel" --out "$CONFIG.$name.sel" "$CONFIG")" \
        && env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$CONFIG.$name.sel" CARGO_TARGET_DIR="$TARGET_DIR/$name" \
           $CARGO build --release -p azos_kernel $args \
           --config 'build.rustflags=["-C","link-arg=-Tarch/aarch64/boot/linker-aarch64.ld"]' >"$WORK/build-$name.log" 2>&1 ) \
        || die "could not build the $name kernel (selection $sel), see $WORK/build-$name.log"
    "$OBJCOPY" -O binary "$TARGET_DIR/$name/$TRIPLE/release/kernel" "$WORK/$name.img" 2>/dev/null
    [ -f "$WORK/$name.img" ] || die "no image for $name"
}
# hosted: the stub resident (HV from VIRT_HOSTED). split: the monitor.
build hosted "bench-minimal,CONFIG_VIRT_HOSTED=y,hyp-cost-probe"
build split "bench-minimal,hyp-monitor-row,hyp-cost-probe"

run() { # run <name> <smp> <wait-for-regexp> <log> [<disk>]
    local name="$1" smp="$2" until="$3" log="$4" disk="${5:-}" i=0
    local drive=()
    [ -n "$disk" ] && drive=(-global virtio-mmio.force-legacy=false -drive "file=$disk,if=none,format=raw,id=hd0" -device virtio-blk-device,drive=hd0)
    "$QEMU_AARCH64" -M "$MACHINE" -cpu "$CPU" -smp "$smp" $ICOUNT -nographic -kernel "$WORK/$name.img" ${drive[@]+"${drive[@]}"} >"$log" 2>&1 &
    local pid=$!
    while [ "$i" -lt "$WAIT_SECS" ]; do
        tr -d '\r' <"$log" 2>/dev/null | grep -qE "$until" && break
        grep -aqE 'AARCH64-TRAP\] unhandled|KERNEL PANIC' "$log" 2>/dev/null && break
        kill -0 "$pid" 2>/dev/null || break
        i=$((i + 1)); sleep 1
    done
    kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

# One boot per image for the monitor lanes (two harts: CPU_ON has to start one),
# one for the system lanes (one hart, as vsbench_aarch64.sh: no placement jitter).
for n in hosted split; do
    run "$n" "$COST_SMP" '\[SMP\] hart 1 online' "$WORK/$n-cost.log"
    cp "$AZOS_OUT/build/disk-aarch64-vsbench.img" "$WORK/disk-$n.img"
    run "$n" 1 '\[VSBENCH\] azos ctxsw-loaded =|\[VSBENCH\] switch-loaded: REFUSED' "$WORK/$n-sys.log" "$WORK/disk-$n.img"
    # The two logs of an image are one log to the tool, the two-hart run last, so its lane numbers are the ones read.
    cat "$WORK/$n-sys.log" "$WORK/$n-cost.log" >"$WORK/$n.log"
    tr -d '\r' <"$WORK/$n-sys.log" | grep -qF "$BENCH_MINIMAL_BANNER" || die "the $n column lacks the bench-minimal banner"
done

# Linux nvhe and protected, when the pieces are there.
LINUX_IMAGE="${VSBENCH_SPLIT_LINUX_IMAGE:-$(sed -n 's/^aarch64=//p' "$REPO_ROOT/tools/bench/vsbench_linux.conf")}"
case "$LINUX_IMAGE" in "~/"*) LINUX_IMAGE="$HOME/${LINUX_IMAGE#\~/}" ;; esac
INITRAMFS="${VSBENCH_SPLIT_LINUX_INITRAMFS:-$AZOS_OUT/build/vsbench-aarch64-compare/initramfs-aarch64.cpio}"
LINUX_LOGS=()
if [ -f "$LINUX_IMAGE" ] && [ -f "$INITRAMFS" ]; then
    L_IMG="$LINUX_IMAGE"
    if gzip -t "$LINUX_IMAGE" 2>/dev/null; then L_IMG="$WORK/linux-Image"; gzip -dc "$LINUX_IMAGE" >"$L_IMG"; fi
    for mode in nvhe protected; do
        cp "$AZOS_OUT/build/disk-aarch64-vsbench.img" "$WORK/disk-linux-$mode.img"
        "$QEMU_AARCH64" -M "$MACHINE" -cpu "$CPU" -smp 1 $ICOUNT -nographic -kernel "$L_IMG" -initrd "$INITRAMFS" \
            -global virtio-mmio.force-legacy=false -drive "file=$WORK/disk-linux-$mode.img,if=none,format=raw,id=hd0" \
            -device virtio-blk-device,drive=hd0 -append "rdinit=/init console=ttyAMA0 kvm-arm.mode=$mode" >"$WORK/linux-$mode.log" 2>&1 &
        pid=$!; i=0
        while [ "$i" -lt "${VSBENCH_SPLIT_LINUX_WAIT:-180}" ]; do
            tr -d '\r' <"$WORK/linux-$mode.log" 2>/dev/null | grep -qE '\[VSBENCH\] side=linux done|Attempted to kill init' && break
            kill -0 "$pid" 2>/dev/null || break
            i=$((i + 1)); sleep 1
        done
        kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        LINUX_LOGS+=("$WORK/linux-$mode.log")
    done
else
    echo "vsbench_split: no Linux pair: needs $LINUX_IMAGE and the initramfs $INITRAMFS (run vsbench_aarch64.sh first); \
the Linux columns are SKIPPED" >&2
fi

python3 "$REPO_ROOT/tools/bench/hyp_cost.py" compare "$WORK/split.log" "$WORK/hosted.log" ${LINUX_LOGS[@]+"${LINUX_LOGS[@]}"}
rc=$?
echo "  Logs kept: $WORK"
exit "$rc"

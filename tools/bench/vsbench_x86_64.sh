#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# vsbench_x86_64: the SAME vsbench work tools/bench/vsbench_compare.sh (riscv64)
# and tools/bench/vsbench_aarch64.sh run, on x86_64: AzOS against Linux 6.12, both
# on QEMU `-M microvm` (the x86_64 line tools/gate/check_fast.sh boots), under
# `-icount shift=0,sleep=off`.
#
# ## The clock
# vsbench reads the TSC on x86_64 and scales it by a rate it measures once at
# start against each kernel's own ns clock (`bench_core::calibrate_tsc`).
# Under QEMU TCG the TSC is QEMU's virtual clock in ns, so with -icount
# shift=0 one tick is one guest instruction, as on the other two ISAs.
#
# ## The Linux/x86_64 column
# The bzImage is VSBENCH_X86_64_LINUX_IMAGE, else the `x86_64=` line of
# tools/bench/vsbench_linux.conf. A leading `~/` is $HOME. Absent file, the column is SKIPPED and says so; this script never
# downloads anything. The Linux vsbench ELF is built for the same
# `sdk/targets/x86_64-unknown-azos.json` target as the AzOS one (same codegen,
# the same image base, a static ET_EXEC) and runs as `/init` of an
# initramfs, console ttyS0. The disk lanes need virtio-mmio discovered by
# Linux on microvm (ACPI, or `virtio_mmio.device=` from QEMU's automatic
# command line, which needs VIRTIO_MMIO_CMDLINE_DEVICES).
#
# ## Lanes not run on this line (printed as SKIPPED, never silently absent)
# `net`, `tcp`: the microvm line has no NIC (the riscv64 compare attaches one
# with its host peers). Override with VSBENCH_LANES (a comma list of
# sections: ipc mem proc disk thread vdso ioring shell timer net tcp switch).
#
# Usage:
#   PATH="/Users/azor/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:/opt/homebrew/sbin" \
#     bash tools/bench/vsbench_x86_64.sh
# Environment: QEMU_X86_64 (default qemu-system-x86_64), CARGO (cargo),
# WAIT_SECS (90), VSBENCH_SMP (1), VSBENCH_LOG_LEVEL (warn),
# VSBENCH_AZOS_EXTRA_FEATURES, VSBENCH_BENCH_FEATURES, VSBENCH_LANES,
# VSBENCH_X86_64_LINUX_IMAGE, VSBENCH_X86_64_LINUX_WAIT (180).
# One QEMU at a time; each is killed by its own PID.

set -u
# Outputs live under $AZOS_OUT (tools/lib/out_dir.py), never in the checkout.
AZOS_OUT="${AZOS_OUT:-$(python3 "$(dirname "$0")/../lib/out_dir.py")}"; export AZOS_OUT

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CARGO="${CARGO:-cargo}"
QEMU_X86_64="${QEMU_X86_64:-qemu-system-x86_64}"
WAIT_SECS="${WAIT_SECS:-90}"
VSBENCH_SMP="${VSBENCH_SMP:-1}"
# VSBENCH_ICOUNT=0 (front memobj-multihart): no -icount, and one host thread
# per vCPU, which an x86 guest on a weaker-ordered host only gets when asked
# (`thread=multi`; QEMU then fences for the guest's order). For the `scale`
# lanes at VSBENCH_SMP=4: under -icount QEMU runs every vCPU on one host
# thread in turn, so no two harts ever run at once (see `scale_lanes`).
VSBENCH_ICOUNT="${VSBENCH_ICOUNT:-1}"
ICOUNT_ARGS="-icount shift=0,sleep=off"
[ "$VSBENCH_ICOUNT" = "1" ] || ICOUNT_ARGS="-accel tcg,thread=multi"
# tools/gate/check_fast.sh's x86_64 line, with x2APIC withheld from BOTH kernels.
# Under -icount, QEMU 11.0 TCG aborts with "Bad icount read" once AzOS
# (X86_X2APIC=probe) drives its local APIC through the x2APIC MSRs (measured
# 10-10: the abort follows the [ISA] line, no lane runs); with the xAPIC
# MMIO page the same kernel runs every lane. Linux runs on the same CPU.
MICROVM_ARGS="-M microvm -cpu max,-x2apic -m 256M -nographic -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04"
X86_SKIP_LANES="net tcp"
X86_SKIP_REASON="no NIC on the microvm line"
ALL_LANES="ipc mem proc disk thread vdso ioring shell timer net tcp switch"

BENCH_TARGET="${VSBENCH_X86_64_TARGET:-$AZOS_OUT/target/vsbench-x86_64-compare}"
WORK="${VSBENCH_X86_64_WORK:-$AZOS_OUT/build/vsbench-x86_64-compare}"

die() { echo "vsbench_x86_64: $*" >&2; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK" "$BENCH_TARGET"

BENCH_MINIMAL_BANNER='[BENCH] bench-minimal: only idle+autorun run; all other tasks parked'

# ── Lanes: the default is every section this line can run ─────────────────
if [ -z "${VSBENCH_LANES:-}" ]; then
    VSBENCH_LANES=""
    for l in $ALL_LANES; do
        case " $X86_SKIP_LANES " in *" $l "*) continue ;; esac
        VSBENCH_LANES="${VSBENCH_LANES:+$VSBENCH_LANES,}$l"
    done
fi
for l in $X86_SKIP_LANES; do
    printf ',%s,' "$VSBENCH_LANES" | grep -q ",$l," \
        || echo "vsbench_x86_64: SKIPPED $l: $X86_SKIP_REASON" >&2
done

# ── AzOS x86_64: disk image, then a bench-minimal kernel in its own target ─
VSBENCH_LOG_LEVEL="${VSBENCH_LOG_LEVEL:-warn}"
case "$VSBENCH_LOG_LEVEL" in
    err|warn|info|debug) ;;
    *) die "VSBENCH_LOG_LEVEL=$VSBENCH_LOG_LEVEL: want err, warn, info or debug" ;;
esac
AZ_LEVEL="CONFIG_LOG_LEVEL_$(printf '%s' "$VSBENCH_LOG_LEVEL" | tr '[:lower:]' '[:upper:]')=y"
( cd "$REPO_ROOT" && make $AZOS_OUT/build/image_hashes_x86_64.rs $AZOS_OUT/build/disk-x86_64-vsbench.img \
    VSBENCH_FEATURES="${VSBENCH_BENCH_FEATURES:-}" >"$WORK/build-disk.log" 2>&1 ) \
    || die "could not build $AZOS_OUT/build/disk-x86_64-vsbench.img — see $WORK/build-disk.log"

X_CONFIG="$WORK/qemu-x86_64.config"
# X86_TSC_CLOCK_ALWAYS: QEMU's TSC is not invariant, and the default
# (INVARIANT) would put the bench on the HPET with the vDSO fast path off.
{ grep -v 'LOG_LEVEL' "$REPO_ROOT/config/defconfigs/robot-sbc-x86_64-dev+qemu+linux+gui.config" && echo "$AZ_LEVEL" \
    && echo CONFIG_X86_TSC_CLOCK_ALWAYS=y; } >"$X_CONFIG" \
    && ( cd "$REPO_ROOT" && KCONFIG_CONFIG="$X_CONFIG" python3 -m olddefconfig >/dev/null 2>&1 ) \
    && grep -q '^CONFIG_ARCH_X86_64=y$' "$X_CONFIG" && grep -q "^$AZ_LEVEL\$" "$X_CONFIG" \
    || die "could not expand config/defconfigs/robot-sbc-x86_64-dev+qemu+linux+gui.config"
# The Makefile's `x86_64` recipe, into this script's own target directory.
X_ELF="$BENCH_TARGET/azos-x86_64/x86_64-unknown-none/release/kernel"
( cd "$REPO_ROOT" && args="$(python3 tools/build/kconfig_to_cargo.py --out "$X_CONFIG.sel" "$X_CONFIG" \
        --select "bench-minimal${VSBENCH_AZOS_EXTRA_FEATURES:+,$VSBENCH_AZOS_EXTRA_FEATURES}")" \
    && env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$X_CONFIG.sel" \
    CARGO_TARGET_DIR="$BENCH_TARGET/azos-x86_64" \
    RUSTFLAGS="-C link-arg=-Tarch/x86_64/boot/linker-x86_64.ld -C relocation-model=static --cfg curve25519_dalek_backend=\"serial\" $(python3 tools/build/kconfig_to_cargo.py --rustflags "$X_CONFIG")" \
    $CARGO build --release -p azos_kernel $args \
    >"$WORK/build-x86_64.log" 2>&1 ) \
    || die "could not build the x86_64 AzOS kernel (bench-minimal) — see $WORK/build-x86_64.log"
[ -f "$X_ELF" ] || die "no kernel at $X_ELF"

completion_lane() { # completion_lane <log>
    if ! printf ',%s,' "$VSBENCH_LANES" | grep -q ',switch,'; then
        tr -d '\r' <"$1" 2>/dev/null | grep -qF "[VSBENCH] side=azos done"
        return
    fi
    tr -d '\r' <"$1" 2>/dev/null \
        | grep -qE '\[VSBENCH\] azos ctxsw-loaded =|\[VSBENCH\] ctxsw-loaded: |\[VSBENCH\] switch-loaded: REFUSED'
}
stop_qemu() { # stop_qemu <pid>: QEMU under -icount ignores SIGTERM
    kill "$1" 2>/dev/null; sleep 2
    kill -0 "$1" 2>/dev/null && kill -9 "$1" 2>/dev/null; wait "$1" 2>/dev/null
}

X_LOG="$WORK/x86_64.log"
X_DISK="$WORK/disk-x86_64.img"
cp "$AZOS_OUT/build/disk-x86_64-vsbench.img" "$X_DISK"
printf '%s\n' "$VSBENCH_LANES" >"$WORK/lanes.txt"
mcopy -o -i "$X_DISK" "$WORK/lanes.txt" ::VSBLANES.TXT || die "could not add VSBLANES.TXT to $X_DISK"

"$QEMU_X86_64" $MICROVM_ARGS -smp "$VSBENCH_SMP" $ICOUNT_ARGS -kernel "$X_ELF" \
    -drive "file=$X_DISK,if=none,format=raw,id=hd0" -device virtio-blk-device,drive=hd0 \
    </dev/null >"$X_LOG" 2>&1 &
X_PID=$!
i=0
while [ "$i" -lt "$WAIT_SECS" ]; do
    completion_lane "$X_LOG" && break
    tr -d '\r' <"$X_LOG" 2>/dev/null | grep -aqE 'KERNEL PANIC|\[FATAL\]' && break
    kill -0 "$X_PID" 2>/dev/null || break
    i=$((i + 1)); sleep 1
done
stop_qemu "$X_PID"

# ── Linux/x86_64 ────────────────────────────────────────────────────────────
LINUX_X_IMAGE="${VSBENCH_X86_64_LINUX_IMAGE:-$(sed -n 's/^x86_64=//p' "$REPO_ROOT/tools/bench/vsbench_linux.conf")}"
case "$LINUX_X_IMAGE" in "~/"*) LINUX_X_IMAGE="$HOME/${LINUX_X_IMAGE#\~/}" ;; esac
echo "vsbench_x86_64: Linux/x86_64 column: ${LINUX_X_IMAGE:-(none configured)}" >&2
L_LOG="$WORK/linux-x86_64.log"
L_RAN=0
linux_done() { tr -d '\r' <"$1" 2>/dev/null | grep -qE '\[VSBENCH\] side=linux done|Attempted to kill init'; }
if [ -n "$LINUX_X_IMAGE" ] && [ -f "$LINUX_X_IMAGE" ]; then
    # The x86_64 native target spec (the AzOS side's codegen and image base, no
    # linker script), as a static ET_EXEC entered at its own `_start`.
    L_X_ELF="$BENCH_TARGET/vsbench-linux/x86_64-unknown-azos/release/vsbench"
    ( cd "$REPO_ROOT/userspace/bench/vsbench" \
      && CARGO_TARGET_DIR="$BENCH_TARGET/vsbench-linux" \
         RUSTFLAGS="-C relocation-model=static -C link-arg=-e_start $(python3 "$REPO_ROOT/tools/build/kconfig_to_cargo.py" --user-rustflags "$X_CONFIG")" \
         $CARGO +nightly build --release -Zjson-target-spec --target "$REPO_ROOT/sdk/targets/x86_64-unknown-azos.json" \
             --no-default-features --features "linux${VSBENCH_BENCH_FEATURES:+,$VSBENCH_BENCH_FEATURES}" \
    ) >"$WORK/build-linux-x86_64.log" 2>&1 \
        || die "could not build the Linux/x86_64 vsbench ELF — see $WORK/build-linux-x86_64.log"
    mkdir -p "$WORK/root-linux"
    cp "$L_X_ELF" "$WORK/root-linux/init" && chmod +x "$WORK/root-linux/init"
    ( cd "$WORK/root-linux" && find . | cpio -o -H newc ) >"$WORK/initramfs-x86_64.cpio" 2>/dev/null \
        || die "could not pack the Linux/x86_64 initramfs"
    L_DISK="$WORK/disk-linux-x86_64.img"
    cp "$AZOS_OUT/build/disk-x86_64-vsbench.img" "$L_DISK"
    "$QEMU_X86_64" $MICROVM_ARGS -smp "$VSBENCH_SMP" $ICOUNT_ARGS \
        -kernel "$LINUX_X_IMAGE" -initrd "$WORK/initramfs-x86_64.cpio" \
        -drive "file=$L_DISK,if=none,format=raw,id=hd0" -device virtio-blk-device,drive=hd0 \
        -append "rdinit=/init console=ttyS0 VSBENCH_LANES=$VSBENCH_LANES" </dev/null >"$L_LOG" 2>&1 &
    L_PID=$!
    i=0
    while [ "$i" -lt "${VSBENCH_X86_64_LINUX_WAIT:-180}" ]; do
        linux_done "$L_LOG" && break
        kill -0 "$L_PID" 2>/dev/null || break
        i=$((i + 1)); sleep 1
    done
    stop_qemu "$L_PID"
    L_RAN=1
else
    echo "vsbench_x86_64: no x86_64 Linux at '${LINUX_X_IMAGE}': the Linux/x86_64 column is SKIPPED \
(set VSBENCH_X86_64_LINUX_IMAGE or the x86_64= line of tools/bench/vsbench_linux.conf)" >&2
fi

# ── Verdict ────────────────────────────────────────────────────────────────
rc=0
completion_lane "$X_LOG" || { echo "vsbench_x86_64: x86_64 did not reach its last lane ($X_LOG)" >&2; rc=1; }
if grep -q "FAIL rc=" "$X_LOG" 2>/dev/null; then
    echo "vsbench_x86_64: an x86_64 lane failed:" >&2; grep "FAIL rc=" "$X_LOG" >&2; rc=1
fi
tr -d '\r' <"$X_LOG" 2>/dev/null | grep -qF "$BENCH_MINIMAL_BANNER" \
    || { echo "vsbench_x86_64: REFUSED the x86_64 column: its log lacks the bench-minimal banner ($X_LOG)" >&2; rc=1; }

# Name AND value in one pass, as vsbench_compare.sh's `lane_values`.
lane_values() { # lane_values <log> [side]  ->  "<lane>\t<ns>"
    local side="${2:-azos}"
    tr -d '\r' <"$1" 2>/dev/null \
        | grep "\[VSBENCH\] $side " \
        | grep ' ns/op' \
        | sed -E "s/.*\[VSBENCH\] $side +//; s/ +=/=/; s/= *([0-9]+) ns.*/\t\1/" \
        | sort -u
}
lane_values "$X_LOG" >"$WORK/x86_64.tsv"
: >"$WORK/linux-x86_64.tsv"
if [ "$L_RAN" = 1 ]; then
    lane_values "$L_LOG" linux >"$WORK/linux-x86_64.tsv"
    linux_done "$L_LOG" || echo "vsbench_x86_64: (not counted) Linux/x86_64 did not finish ($L_LOG)" >&2
    if grep -q "FAIL rc=" "$L_LOG" 2>/dev/null; then
        echo "vsbench_x86_64: (not counted) Linux/x86_64 lanes that failed:" >&2
        grep "FAIL rc=" "$L_LOG" | tr -d '\r' | sed 's/^/           /' >&2
    fi
fi
[ -s "$WORK/x86_64.tsv" ] || { echo "vsbench_x86_64: parsed NO lanes from x86_64 ($X_LOG)" >&2; rc=1; }

cell() { awk -F '\t' -v l="$2" '$1 == l { print $2; exit }' "$1" 2>/dev/null; }
sort -u "$WORK/x86_64.tsv" "$WORK/linux-x86_64.tsv" | cut -f1 | sort -u >"$WORK/lanes"
echo ""
if [ "$VSBENCH_ICOUNT" = "1" ]; then
    echo "  vsbench x86_64, microvm, -smp $VSBENCH_SMP -icount shift=0,sleep=off (instruction counts)."
else
    echo "  vsbench x86_64, microvm, -smp $VSBENCH_SMP $ICOUNT_ARGS (host-timed nanoseconds: read the ratios and their spread)."
fi
echo "  Sections run: $VSBENCH_LANES"
printf "    %-18s %14s %14s %8s\n" "lane" "azos-x86_64" "linux-x86_64" "az/lx"
L_MISSING=""
while read -r lane; do
    a="$(cell "$WORK/x86_64.tsv" "$lane")"
    l="$(cell "$WORK/linux-x86_64.tsv" "$lane")"
    q="-"
    if [ -n "$a" ] && [ -n "$l" ] && [ "$l" -gt 0 ]; then
        q="$(awk -v a="$a" -v l="$l" 'BEGIN { printf "%.2f", a / l }')"
    elif [ -n "$a" ] && [ "$L_RAN" = 1 ]; then
        L_MISSING="$L_MISSING $lane"
    fi
    printf "    %-18s %14s %14s %8s\n" "$lane" "${a:--}" "${l:--}" "$q"
done <"$WORK/lanes"
[ -n "$L_MISSING" ] && echo "  (not counted) x86_64 AzOS lanes with no Linux/x86_64 number:$L_MISSING"
echo ""
if [ "$L_RAN" = 1 ]; then echo "  Logs kept: $X_LOG , $L_LOG"; else echo "  Logs kept: $X_LOG"; fi
exit $rc

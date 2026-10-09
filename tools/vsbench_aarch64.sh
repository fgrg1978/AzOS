#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# vsbench_aarch64: the SAME vsbench work `tools/vsbench_compare.sh` runs on
# riscv64, booted on BOTH riscv64 and aarch64 AzOS under identical
# conditions, in the same script invocation — so the two ISA columns are
# directly comparable, not two numbers from two different sessions.
#
# ## Why this exists
#
# The aarch64 syscall-floor figure "268 instructions" that the parity program
# has been quoting came from one hand-run QEMU session. Nothing in the repo
# could reproduce it: `vsbench_compare.sh` hardcodes
# `riscv64imac-unknown-none-elf` (its target comes from `.cargo/config.toml`,
# and every path in it is riscv64-specific — the Linux comparison, the two
# AzOS columns, the seccomp column). A number nothing can re-measure cannot
# be defended, and this is the number the two ISAs get compared with.
#
# This script is deliberately NARROWER than `vsbench_compare.sh`: no Linux
# column (there is no aarch64 Linux reference image wired up here), no
# seccomp column, no azos-product column. It exists to answer exactly one
# question — "does the aarch64 AzOS number reproduce, and what is it
# relative to the SAME lane on riscv64 AzOS, under the SAME QEMU
# determinism knobs" — and to be re-run whenever that question needs
# re-asking.
#
# ## Determinism: -smp 1 -icount shift=0,sleep=off, on BOTH ISAs
#
# `vsbench_compare.sh`'s own header explains why (`VSBENCH_ICOUNT`/
# `VSBENCH_SMP` sections): `-icount shift=0` advances virtual time one unit
# per instruction, so a lane's "ns/op" becomes an instruction count —
# deterministic, identical across runs, blind to host load. `-smp 1` removes
# the cross-hart placement jitter `-smp 4` introduces (measured there: a
# 33x spread on an unchanged Linux binary at `-smp 4` vs bit-exact at
# `-smp 1`).
#
# **Verified empirically for aarch64 while writing this script (2026-09-23):**
# the SAME aarch64 kernel+disk booted twice under `-smp 1 -icount
# shift=0,sleep=off` produced BYTE-IDENTICAL `[VSBENCH]` output both times.
# riscv64 was already known deterministic this way; aarch64 had not been
# checked. It is deterministic PER BINARY — rebuilding after an unrelated
# source change can still shift a handful of lanes by a few ns (~4 ns
# observed on `fork+exit`/`fork+exit+wait` between two aarch64 kernels that
# differ only in unrelated printed-string lengths, changing static layout by
# a few bytes). That is expected and is not the kind of noise this script
# exists to filter out; the kind it filters out is host-load jitter, which
# `-icount` removes entirely.
#
# ## The clock: CNTFRQ_EL0 must be read, not assumed
#
# `userspace/bench/vsbench/src/bench_core.rs`'s `scale_ticks` fixed a real bug on
# 2026-09-22: it used to assume RISC-V's 10 MHz `time` CSR frequency for
# aarch64's `cntvct_el0` too, which runs at 1 GHz under QEMU `-cpu max` —
# every aarch64 lane read 100x too high (a "41,300-instruction" syscall
# floor). It now reads `CNTFRQ_EL0` at runtime on aarch64 and does the
# division in u128. This script's own aarch64 runs came back with a 268
# syscall-floor, not 26,800 or 41,300 — the fix held.
#
# ## What is asserted, and what is not
#
# Asserted: both sides reach their last lane (`switch-loaded` printed or
# refused), neither reports `FAIL rc=`, and — same principle as
# `vsbench_compare.sh` — the booted kernel actually carries the
# `bench-minimal` banner (a `--features vf2`-style stale-binary mistake would
# otherwise boot the full daemon set under the bench-minimal label).
#
# NOT asserted: any specific number, or any ratio between the two ISAs. This
# script reports; it does not gate. See "How to run this" below for why it
# is not wired into `tools/ci_check.sh`'s default sequence.
#
# ## The Linux/aarch64 column (N0, wave 15)
#
# `VSBENCH_AARCH64_LINUX_IMAGE` (default `$HOME/devel/vms/arm64/Image`): an
# arm64 Linux `Image`, raw or gzip. Present, the Linux side of vsbench is
# built for aarch64 (`abi_linux.rs` has an `svc 0` twin of every `ecall`),
# packed as `/init` of an uncompressed initramfs, and booted on the SAME
# QEMU line as the aarch64 AzOS column (machine, `-smp`, `-icount`, the
# same disk device with its own copy of the image; the CPU is the same `max`
# with `lpa2=off`, see `LINUX_A_CPU`). Its lanes print in a
# column of their own with the AzOS/Linux ratio. Absent, the column is
# skipped and says so. This script neither downloads nor builds a kernel.
#
# The column REPORTS: a Linux lane failure is printed and does not change
# the exit status (a distribution kernel may lack what a lane needs, e.g.
# `vfat` built as a module fails the `disk` lanes), and an aarch64 AzOS lane
# with no Linux number is listed by name. The only image on this machine
# when this was written is Ubuntu 20.04.5's 5.4.0-125-generic (CFS, not
# EEVDF), out of its installer ISO's `casper/vmlinuz`.
#
# ## How to run this
#
#   PATH="/Users/azor/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:/opt/homebrew/sbin" \
#     bash tools/vsbench_aarch64.sh
#
# Takes ~25-40 s: two full kernel builds (riscv64 + aarch64, `--features
# qemu,bench-minimal`, each into its own scratch `CARGO_TARGET_DIR` under
# `target/vsbench-aarch64-compare/` — never the repository's default
# `target/.../release`, which other builds and scenarios share and which a
# bench-minimal kernel must not leave behind) plus two ~10 s QEMU boots under
# `-icount`. NOT wired into `tools/ci_check.sh`'s default run: two extra
# from-scratch kernel builds per gate is not "cheap" by this repo's own
# standard for what belongs in every run (see `tools/vsbench_compare.sh`'s
# own row, which already costs a full riscv64+Linux double-boot and is opt-in
# in spirit even though it is wired in — this script adds a SECOND ISA's
# build+boot on top and stays a script you run by hand, matching this
# project's "no CI automation" standing order). Run it whenever the parity
# program needs a fresh aarch64-vs-riscv64 number, or after a change that
# could move either kernel's syscall path.
#
# Env overrides: QEMU_RISCV64 (default: /opt/homebrew/bin/qemu-system-riscv64),
# QEMU_AARCH64 (default: qemu-system-aarch64), CARGO (default: cargo),
# WAIT_SECS (default: 90, per boot), VSBENCH_SMP (default: 1 — see the
# determinism note above; only change this to deliberately reproduce the
# cross-hart jitter it exists to avoid).

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO="${CARGO:-cargo}"
QEMU_RISCV64="${QEMU_RISCV64:-/opt/homebrew/bin/qemu-system-riscv64}"
QEMU_AARCH64="${QEMU_AARCH64:-qemu-system-aarch64}"
WAIT_SECS="${WAIT_SECS:-90}"
VSBENCH_SMP="${VSBENCH_SMP:-1}"
ICOUNT_ARGS="-icount shift=0,sleep=off"

# NOT under $REPO_ROOT root, not under the default `target/.../release` — a
# scratch directory per the task's own environment rule ("scratch builds
# outside the repo or under target/"). This sits under target/ but in its
# OWN subdirectory, exactly like `vsbench_compare.sh`'s `BENCH_TARGET`.
BENCH_TARGET="${VSBENCH_AARCH64_TARGET:-$REPO_ROOT/target/vsbench-aarch64-compare}"
WORK="${VSBENCH_AARCH64_WORK:-$REPO_ROOT/build/vsbench-aarch64-compare}"

die() { echo "vsbench_aarch64: $*" >&2; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK"
mkdir -p "$BENCH_TARGET"

BENCH_MINIMAL_BANNER='[BENCH] bench-minimal: only idle+autorun run; all other tasks parked'

# ── Build prerequisites: image hash tables + disk images, both ISAs ─────────
( cd "$REPO_ROOT" && make build/image_hashes.rs >/dev/null 2>&1 ) \
    || die "could not regenerate build/image_hashes.rs"
( cd "$REPO_ROOT" && make build/image_hashes_aarch64.rs >/dev/null 2>&1 ) \
    || die "could not regenerate build/image_hashes_aarch64.rs (needs the \
aarch64 userspace ELFs — 'make userspace-aarch64' first if this is a clean checkout)"
( cd "$REPO_ROOT" && make build/disk-vsbench.img >/dev/null 2>&1 ) \
    || die "could not build build/disk-vsbench.img"
( cd "$REPO_ROOT" && make build/disk-aarch64-vsbench.img >/dev/null 2>&1 ) \
    || die "could not build build/disk-aarch64-vsbench.img"

# ── Build both kernels, bench-minimal, into their own scratch target dirs ───
# Both kernels at VSBENCH_LOG_LEVEL (default warn), as tools/vsbench_compare.sh
# builds its own: release kernels, not the gate's debug console.
VSBENCH_LOG_LEVEL="${VSBENCH_LOG_LEVEL:-warn}"
case "$VSBENCH_LOG_LEVEL" in
    err|warn|info|debug) ;;
    *) die "VSBENCH_LOG_LEVEL=$VSBENCH_LOG_LEVEL: want err, warn, info or debug" ;;
esac
AZ_LEVEL="CONFIG_LOG_LEVEL_$(printf '%s' "$VSBENCH_LOG_LEVEL" | tr '[:lower:]' '[:upper:]')=y"
# Wave 15: the same diagnostic knobs as tools/vsbench_compare.sh.
# VSBENCH_AZOS_EXTRA_FEATURES: extra kernel features on both ISAs (e.g.
# `switch-census`, whose `[SW-CENSUS]` lines need VSBENCH_LOG_LEVEL=debug).
# VSBENCH_LANES: only the named vsbench sections (see vsbench_compare.sh).
K_FEATURES="qemu,bench-minimal${VSBENCH_AZOS_EXTRA_FEATURES:+,$VSBENCH_AZOS_EXTRA_FEATURES}"
VSBENCH_LANES="${VSBENCH_LANES:-}"
R_CONFIG="$BENCH_TARGET/riscv64.config"
{ grep -v 'LOG_LEVEL' "${KCONFIG_CONFIG:-$REPO_ROOT/config/defconfigs/qemu.config}" \
    && echo "$AZ_LEVEL"; } >"$R_CONFIG.new" \
    && ( cd "$REPO_ROOT" && KCONFIG_CONFIG="$R_CONFIG.new" python3 -m olddefconfig >/dev/null 2>&1 ) \
    && grep -q "^$AZ_LEVEL\$" "$R_CONFIG.new" \
    || die "could not derive the riscv64 kernel configuration ($R_CONFIG.new)"
if cmp -s "$R_CONFIG.new" "$R_CONFIG"; then rm -f "$R_CONFIG.new"; else mv "$R_CONFIG.new" "$R_CONFIG"; fi
R_KERNEL="$BENCH_TARGET/azos-riscv64/riscv64imac-unknown-none-elf/release/kernel"
( cd "$REPO_ROOT" && KCONFIG_CONFIG="$R_CONFIG" CARGO_TARGET_DIR="$BENCH_TARGET/azos-riscv64" \
    $CARGO build --release --features "$K_FEATURES" >"$WORK/build-riscv64.log" 2>&1 ) \
    || die "could not build the riscv64 AzOS kernel (--features \
qemu,bench-minimal) — see $WORK/build-riscv64.log"
[ -f "$R_KERNEL" ] || die "no kernel at $R_KERNEL"

# The aarch64 kernel is soft-float (FP-free, user FP saved lazily), so it is
# built for `aarch64-unknown-none-softfloat`; userspace stays hard-float.
A_TRIPLE=aarch64-unknown-none-softfloat
A_ELF="$BENCH_TARGET/azos-aarch64/$A_TRIPLE/release/kernel"
A_IMG="$BENCH_TARGET/azos-aarch64/kernel.img"
# The aarch64 kernel's Kconfig, expanded the way tools/ci_check.sh's
# `aarch64_config` does it. Without KCONFIG_CONFIG this build read the root
# `.config` — an ARCH_RISCV64 config — so `azos_limits` gave the aarch64
# kernel riscv64 constants (TIMER_FREQ 10 MHz against the aarch64 config's
# value): every sleep/deadline lane in the aarch64 column fired early.
A_CONFIG="$WORK/qemu-aarch64.config"
{ grep -v 'LOG_LEVEL' "$REPO_ROOT/config/defconfigs/qemu-aarch64.config" && echo "$AZ_LEVEL"; } >"$A_CONFIG" \
    && ( cd "$REPO_ROOT" && KCONFIG_CONFIG="$A_CONFIG" python3 -m olddefconfig >/dev/null 2>&1 ) \
    && grep -q '^CONFIG_ARCH_AARCH64=y$' "$A_CONFIG" && grep -q "^$AZ_LEVEL\$" "$A_CONFIG" \
    || die "could not expand config/defconfigs/qemu-aarch64.config"
( cd "$REPO_ROOT" && env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
    KCONFIG_CONFIG="$A_CONFIG" \
    CARGO_TARGET_DIR="$BENCH_TARGET/azos-aarch64" \
    $CARGO build --release --target "$A_TRIPLE" -p azos_kernel \
    --features "$K_FEATURES" \
    --config 'build.rustflags=["-C","link-arg=-Tkernel/linker-aarch64.ld"]' \
    >"$WORK/build-aarch64.log" 2>&1 ) \
    || die "could not build the aarch64 AzOS kernel (--features \
qemu,bench-minimal) — see $WORK/build-aarch64.log"
[ -f "$A_ELF" ] || die "no kernel at $A_ELF"
A64_OBJCOPY="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
[ -x "$A64_OBJCOPY" ] || die "llvm-objcopy not found: $A64_OBJCOPY"
"$A64_OBJCOPY" -O binary "$A_ELF" "$A_IMG" 2>/dev/null
[ -f "$A_IMG" ] || die "ELF -> Image conversion failed: $A_IMG"

# ── Boot both, same completion rule vsbench_compare.sh uses ─────────────────
completion_lane() { # completion_lane <log>
    if [ -n "$VSBENCH_LANES" ] && ! printf ',%s,' "$VSBENCH_LANES" | grep -q ',switch,'; then
        tr -d '\r' <"$1" 2>/dev/null | grep -qF "[VSBENCH] side=azos done"
        return
    fi
    tr -d '\r' <"$1" 2>/dev/null \
        | grep -qE '\[VSBENCH\] azos ctxsw-loaded =|\[VSBENCH\] ctxsw-loaded: |\[VSBENCH\] switch-loaded: REFUSED'
}

R_LOG="$WORK/riscv64.log"
A_LOG="$WORK/aarch64.log"
R_DISK="$WORK/disk-riscv64.img"
A_DISK="$WORK/disk-aarch64.img"
cp "$REPO_ROOT/build/disk-vsbench.img" "$R_DISK"
cp "$REPO_ROOT/build/disk-aarch64-vsbench.img" "$A_DISK"
if [ -n "$VSBENCH_LANES" ]; then
    printf '%s\n' "$VSBENCH_LANES" >"$WORK/lanes.txt"
    for d in "$R_DISK" "$A_DISK"; do
        mcopy -o -i "$d" "$WORK/lanes.txt" ::VSBLANES.TXT || die "could not add VSBLANES.TXT to $d"
    done
fi

"$QEMU_RISCV64" -machine virt -nographic -bios default -smp "$VSBENCH_SMP" $ICOUNT_ARGS \
    -kernel "$R_KERNEL" \
    -global virtio-mmio.force-legacy=false \
    -drive "file=$R_DISK,if=none,format=raw,id=hd0" \
    -device virtio-blk-device,drive=hd0 >"$R_LOG" 2>&1 &
R_PID=$!
i=0
while [ "$i" -lt "$WAIT_SECS" ]; do
    completion_lane "$R_LOG" && break
    kill -0 "$R_PID" 2>/dev/null || break
    i=$((i + 1)); sleep 1
done
kill -9 "$R_PID" 2>/dev/null; wait "$R_PID" 2>/dev/null

"$QEMU_AARCH64" -M virt,gic-version=3 -cpu max,pauth=on -smp "$VSBENCH_SMP" $ICOUNT_ARGS -nographic \
    -kernel "$A_IMG" \
    -global virtio-mmio.force-legacy=false \
    -drive "file=$A_DISK,if=none,format=raw,id=hd0" \
    -device virtio-blk-device,drive=hd0 >"$A_LOG" 2>&1 &
A_PID=$!
i=0
while [ "$i" -lt "$WAIT_SECS" ]; do
    completion_lane "$A_LOG" && break
    grep -aq 'AARCH64-TRAP\] unhandled' "$A_LOG" 2>/dev/null && break
    kill -0 "$A_PID" 2>/dev/null || break
    i=$((i + 1)); sleep 1
done
kill -9 "$A_PID" 2>/dev/null; wait "$A_PID" 2>/dev/null

# ── Verdict ──────────────────────────────────────────────────────────────
# ── Linux/aarch64 (see the header) ────────────────────────────────────────
LINUX_A_IMAGE="${VSBENCH_AARCH64_LINUX_IMAGE:-$HOME/devel/vms/arm64/Image}"
# The AzOS line's CPU with `lpa2=off`: 5.4 predates FEAT_LPA2 and, offered it
# by this QEMU's `max`, prints nothing at all (measured: no `Linux version`
# line in 90 s; with `lpa2=off` it boots and runs the suite; its io_uring
# timeout/msg-ring and `disk` lanes fail on 5.4 and are listed).
LINUX_A_CPU="${VSBENCH_AARCH64_LINUX_CPU:-max,pauth=on,lpa2=off}"
L_LOG="$WORK/linux-aarch64.log"
L_RAN=0
linux_done() { # linux_done <log>
    tr -d '\r' <"$1" 2>/dev/null | grep -qE '\[VSBENCH\] side=linux done|Attempted to kill init'
}
if [ -f "$LINUX_A_IMAGE" ]; then
    L_A_ELF="$BENCH_TARGET/vsbench-linux/aarch64-unknown-none/release/vsbench"
    ( cd "$REPO_ROOT/userspace/bench/vsbench" \
      && CARGO_TARGET_DIR="$BENCH_TARGET/vsbench-linux" \
         RUSTFLAGS="-C link-arg=-Tlinux_aarch64.ld" \
         $CARGO +nightly build --release --target aarch64-unknown-none --no-default-features \
             --features "linux${VSBENCH_BENCH_FEATURES:+,$VSBENCH_BENCH_FEATURES}" \
    ) >"$WORK/build-linux-aarch64.log" 2>&1 \
        || die "could not build the Linux/aarch64 vsbench ELF — see $WORK/build-linux-aarch64.log"
    mkdir -p "$WORK/root-linux"
    cp "$L_A_ELF" "$WORK/root-linux/init" && chmod +x "$WORK/root-linux/init"
    ( cd "$WORK/root-linux" && find . | cpio -o -H newc ) >"$WORK/initramfs-aarch64.cpio" 2>/dev/null \
        || die "could not pack the Linux/aarch64 initramfs"
    L_IMG="$LINUX_A_IMAGE"
    if gzip -t "$LINUX_A_IMAGE" 2>/dev/null; then
        L_IMG="$WORK/linux-Image"
        gzip -dc "$LINUX_A_IMAGE" >"$L_IMG" || die "could not gunzip $LINUX_A_IMAGE"
    fi
    L_DISK="$WORK/disk-linux-aarch64.img"
    cp "$REPO_ROOT/build/disk-aarch64-vsbench.img" "$L_DISK"
    "$QEMU_AARCH64" -M virt,gic-version=3 -cpu "$LINUX_A_CPU" -smp "$VSBENCH_SMP" $ICOUNT_ARGS -nographic \
        -kernel "$L_IMG" -initrd "$WORK/initramfs-aarch64.cpio" \
        -global virtio-mmio.force-legacy=false \
        -drive "file=$L_DISK,if=none,format=raw,id=hd0" \
        -device virtio-blk-device,drive=hd0 \
        -append "rdinit=/init console=ttyAMA0${VSBENCH_LANES:+ VSBENCH_LANES=$VSBENCH_LANES}" >"$L_LOG" 2>&1 &
    L_PID=$!
    i=0
    while [ "$i" -lt "${VSBENCH_AARCH64_LINUX_WAIT:-180}" ]; do
        linux_done "$L_LOG" && break
        kill -0 "$L_PID" 2>/dev/null || break
        i=$((i + 1)); sleep 1
    done
    kill "$L_PID" 2>/dev/null; sleep 2
    kill -0 "$L_PID" 2>/dev/null && kill -9 "$L_PID" 2>/dev/null; wait "$L_PID" 2>/dev/null
    L_RAN=1
else
    echo "vsbench_aarch64: no arm64 Linux at $LINUX_A_IMAGE: the Linux/aarch64 column is SKIPPED \
(set VSBENCH_AARCH64_LINUX_IMAGE)" >&2
fi

rc=0
for pair in "riscv64:$R_LOG" "aarch64:$A_LOG"; do
    isa="${pair%%:*}" log="${pair#*:}"
    completion_lane "$log" || { echo "vsbench_aarch64: $isa did not reach its last lane ($log)" >&2; rc=1; }
    if grep -q "FAIL rc=" "$log" 2>/dev/null; then
        echo "vsbench_aarch64: a $isa lane failed:" >&2
        grep "FAIL rc=" "$log" >&2
        rc=1
    fi
    if ! tr -d '\r' <"$log" 2>/dev/null | grep -qF "$BENCH_MINIMAL_BANNER"; then
        echo "vsbench_aarch64: REFUSED the $isa column: its log lacks the \
bench-minimal banner ($log)" >&2
        rc=1
    fi
done
if grep -aq 'AARCH64-TRAP\] unhandled' "$A_LOG" 2>/dev/null; then
    echo "vsbench_aarch64: aarch64 took an unhandled exception during the run:" >&2
    grep -a 'AARCH64-TRAP' "$A_LOG" | tr -d '\r' | sed 's/^/           /' >&2
    rc=1
fi

# Name AND value in one pass — see vsbench_compare.sh's `lane_values` for why
# this is not two greps (a two-pass version silently printed `-` for both
# sides on 5 of 14 lanes while the check passed).
lane_values() { # lane_values <log> [side]  ->  "<lane>\t<ns>"
    local side="${2:-azos}"
    tr -d '\r' <"$1" 2>/dev/null \
        | grep "\[VSBENCH\] $side " \
        | grep ' ns/op' \
        | sed -E "s/.*\[VSBENCH\] $side +//; s/ +=/=/; s/= *([0-9]+) ns.*/\t\1/" \
        | sort -u
}
lane_values "$R_LOG" >"$WORK/riscv64.tsv"
lane_values "$A_LOG" >"$WORK/aarch64.tsv"
: >"$WORK/linux-aarch64.tsv"
if [ "$L_RAN" = 1 ]; then
    lane_values "$L_LOG" linux >"$WORK/linux-aarch64.tsv"
    linux_done "$L_LOG" || echo "vsbench_aarch64: (not counted) Linux/aarch64 did not finish ($L_LOG)" >&2
    if grep -q "FAIL rc=" "$L_LOG" 2>/dev/null; then
        echo "vsbench_aarch64: (not counted) Linux/aarch64 lanes that failed:" >&2
        grep "FAIL rc=" "$L_LOG" | tr -d '\r' | sed 's/^/           /' >&2
    fi
fi
[ -s "$WORK/riscv64.tsv" ] || { echo "vsbench_aarch64: parsed NO lanes from riscv64 ($R_LOG)" >&2; rc=1; }
[ -s "$WORK/aarch64.tsv" ] || { echo "vsbench_aarch64: parsed NO lanes from aarch64 ($A_LOG)" >&2; rc=1; }

cell() { awk -F '\t' -v l="$2" '$1 == l { print $2; exit }' "$1" 2>/dev/null; }
sort -u "$WORK/riscv64.tsv" "$WORK/aarch64.tsv" | cut -f1 | sort -u >"$WORK/lanes"

echo ""
echo "  vsbench, -smp $VSBENCH_SMP -icount shift=0,sleep=off (deterministic instruction counts)."
echo "  Same bench-minimal build+boot, both ISAs, this run. switch-loaded is a AzOS-only"
echo "  measure (see vsbench_compare.sh) and is not comparable across anything, ISA included,"
echo "  in the same way the other lanes are not."
printf "    %-18s %14s %14s %14s %8s\n" "lane" "aarch64" "riscv64" "linux-aarch64" "a64/lx"
L_MISSING=""
while read -r lane; do
    a="$(cell "$WORK/aarch64.tsv" "$lane")"
    r="$(cell "$WORK/riscv64.tsv" "$lane")"
    l="$(cell "$WORK/linux-aarch64.tsv" "$lane")"
    q="-"
    if [ -n "$a" ] && [ -n "$l" ] && [ "$l" -gt 0 ]; then
        q="$(awk -v a="$a" -v l="$l" 'BEGIN { printf "%.2f", a / l }')"
    elif [ -n "$a" ] && [ "$L_RAN" = 1 ]; then
        L_MISSING="$L_MISSING $lane"
    fi
    printf "    %-18s %14s %14s %14s %8s\n" "$lane" "${a:--}" "${r:--}" "${l:--}" "$q"
done <"$WORK/lanes"
[ -n "$L_MISSING" ] && echo "  (not counted) aarch64 AzOS lanes with no Linux/aarch64 number:$L_MISSING"
echo ""
if [ "$L_RAN" = 1 ]; then echo "  Logs kept: $R_LOG , $A_LOG , $L_LOG"; else echo "  Logs kept: $R_LOG , $A_LOG"; fi

exit $rc

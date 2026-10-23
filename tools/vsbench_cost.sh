#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# vsbench_cost.sh — what one Kconfig switch costs on the vsbench lanes.
#
#   tools/vsbench_cost.sh <SYMBOL> <permille> <lanes>
#
# The gate kernel (bench-minimal, tools/vsbench_compare.sh with
# VSBENCH_GATE_ONLY=1) is built twice from the same tree and the same base
# configuration ($KCONFIG_CONFIG, else config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config): once
# with `# CONFIG_<SYMBOL> is not set`, once with `CONFIG_<SYMBOL>=y`. Both boot
# the same VSBENCH.ELF under `-icount shift=0,sleep=off` at one hart
# (VSBENCH_SMP=1 with VSBENCH_ICOUNT=1 is bit-exact: a lane's ns/op is an
# instruction count, see vsbench_compare.sh), filtered to <lanes> (a
# VSBENCH_LANES list). The bound: every lane both runs measured costs at most
# <permille> per mille more with the switch on,
#
#     on * 1000 <= off * (1000 + permille)
#
# and the run fails when a lane is over it, when either column did not finish
# or measured no lane, or when the two columns measured different lanes.
#
# What one hart cannot show: a cost that needs two CPUs (a wake placed on
# another CPU than its last, a cross-CPU IPI) never runs here. The bound covers
# the paths the lanes take on one CPU; VSBENCH_SMP overrides it (not
# bit-exact above 1, so a bound that tight then measures the host).
#
# VSBENCH_COST_ON_FEATURES: extra kernel cargo features for the `on` column
# only (vsbench_compare.sh's VSBENCH_AZOS_EXTRA_FEATURES): the canary, a
# feature known to cost more than the bound (`lockdep`), must fail the row.
#
# The switch must reach the kernel through the .config (its `# cargo-feature:`
# tag, which tools/kconfig_to_cargo.py emits), checked below.
#
# Kernels: $AZOS_OUT/target/vsbench-cost-{off,on}; logs and the per-lane
# table: $AZOS_OUT/build/vsbench-cost-<symbol>/.

set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <SYMBOL> <permille> <lanes>" >&2; exit 2; }
SYM="$1" PERMILLE="$2" LANES="$3"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AZOS_OUT="${AZOS_OUT:-$(python3 "$(dirname "$0")/out_dir.py")}"; export AZOS_OUT
BASE="${KCONFIG_CONFIG:-$REPO_ROOT/config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config}"
OUT="$AZOS_OUT/build/vsbench-cost-$(printf '%s' "$SYM" | tr '[:upper:]' '[:lower:]')"
mkdir -p "$OUT"
die() { echo "vsbench-cost: $*" >&2; exit 1; }

# Per lane, `<lane>\t<ns>\t<instr>`: the `<lane> = <n> ns/op` line (the same
# parse as vsbench_compare.sh's lane_values: CR stripped, not anchored) and the
# retired instructions of its `<lane> pmc = <c> cyc/op <i> instr/op` line, or
# `-` when the lane printed none (PMU_USER; a lane prints it only when it
# reported its last batch, so a column can miss it). Under -icount ns/op is
# guest time, which for a lane that WAITS (spawn+wait sleeps until the child
# is reaped) moves in whole timer quanta for an instruction more or less; the
# instruction count is the cost of the code path, and the bound reads it
# wherever both columns have it. Measured 2026-10-22, spawn+wait with records
# off/on: 344,072 / 545,040 ns/op but 233,746 / 235,275 instr/op.
lanes_of() {
    local log; log="$(tr -d '\r' <"$1" 2>/dev/null | grep "\[VSBENCH\] azos ")"
    printf '%s\n' "$log" | grep " instr/op" \
        | sed -E "s/.*\[VSBENCH\] azos +//; s/ +pmc *=.* ([0-9]+) instr\/op.*/\t\1/" | sort -u >"$1.instr" || true
    printf '%s\n' "$log" | grep " ns/op" \
        | sed -E "s/.*\[VSBENCH\] azos +//; s/ +=/=/; s/= *([0-9]+) ns.*/\t\1/" | sort -u \
        | while IFS="$(printf '\t')" read -r lane n; do
              i="$(awk -F '\t' -v l="$lane" '$1 == l { print $2; exit }' "$1.instr")"
              printf '%s\t%s\t%s\n' "$lane" "$n" "${i:--}"
          done
}

line_of() { if [ "$1" = off ]; then echo "# CONFIG_$SYM is not set"; else echo "CONFIG_$SYM=y"; fi; }
for side in off on; do
    cfg="$OUT/$side.config" line="$(line_of "$side")"
    { grep -v -E "^(# )?CONFIG_$SYM[= ]" "$BASE"; echo "$line"; } >"$cfg"
    ( cd "$REPO_ROOT" && KCONFIG_CONFIG="$cfg" python3 -m olddefconfig >/dev/null ) || die "olddefconfig failed on $cfg"
    grep -qx "$line" "$cfg" || die "$line did not survive olddefconfig ($cfg): a dependency is off"
    ( cd "$REPO_ROOT" && python3 tools/kconfig_to_cargo.py "$cfg" ) >"$cfg.base"
done
cmp -s "$OUT/off.config.base" "$OUT/on.config.base" \
    && die "$SYM changes no feature kconfig_to_cargo.py derives: the A/B would compare one kernel with itself"

for side in off on; do
    extra=""
    if [ "$side" = on ] && [ -n "${VSBENCH_COST_ON_FEATURES:-}" ]; then
        extra="$VSBENCH_COST_ON_FEATURES"
        echo "vsbench-cost: CANARY: the on column also selects $extra" >&2
    fi
    echo "vsbench-cost: $side column ($(line_of "$side")), lanes $LANES" >&2
    KCONFIG_CONFIG="$OUT/$side.config" VSBENCH_AZOS_EXTRA_FEATURES="$extra" VSBENCH_GATE_ONLY=1 VSBENCH_ICOUNT=1 \
        VSBENCH_SMP="${VSBENCH_SMP:-1}" VSBENCH_LANES="$LANES" VSBENCH_WORK="$OUT/$side" \
        VSBENCH_TARGET="$AZOS_OUT/target/vsbench-cost-$side" \
        bash "$REPO_ROOT/tools/vsbench_compare.sh" >"$OUT/$side.out" 2>&1 \
        || { sed -n '1,40p' "$OUT/$side.out" >&2; die "the $side column failed ($OUT/$side.out)"; }
    lanes_of "$OUT/$side/azos-bench-minimal.log" >"$OUT/$side.tsv"
    [ -s "$OUT/$side.tsv" ] || die "the $side column measured no lane ($OUT/$side/azos-bench-minimal.log)"
done

cut -f1 "$OUT/off.tsv" >"$OUT/off.lanes"; cut -f1 "$OUT/on.tsv" >"$OUT/on.lanes"
cmp -s "$OUT/off.lanes" "$OUT/on.lanes" \
    || { diff "$OUT/off.lanes" "$OUT/on.lanes" >&2 || true; die "the two columns measured different lanes"; }

rc=0
printf '%-24s %6s %12s %12s %9s\n' lane metric off on "per mille" | tee "$OUT/table.txt"
while IFS="$(printf '\t')" read -r lane off_ns off_in; do
    on_ns="$(awk -F '\t' -v l="$lane" '$1 == l { print $2; exit }' "$OUT/on.tsv")"
    on_in="$(awk -F '\t' -v l="$lane" '$1 == l { print $3; exit }' "$OUT/on.tsv")"
    if [ "$off_in" != - ] && [ "$on_in" != - ]; then metric=instr off="$off_in" on="$on_in"
    else metric=ns off="$off_ns" on="$on_ns"; fi
    pm=$(( off > 0 ? (on - off) * 1000 / off : 0 ))
    verdict=ok
    if [ $(( on * 1000 )) -gt $(( off * (1000 + PERMILLE) )) ]; then verdict=OVER; rc=1; fi
    printf '%-24s %6s %12s %12s %9s %s\n' "$lane" "$metric" "$off" "$on" "$pm" "$verdict" | tee -a "$OUT/table.txt"
done <"$OUT/off.tsv"
n="$(wc -l <"$OUT/off.tsv" | tr -d ' ')"
if [ "$rc" -eq 0 ]; then
    echo "vsbench-cost: $SYM costs at most $PERMILLE per mille on all $n lanes ($LANES)"
else
    echo "vsbench-cost: $SYM is over $PERMILLE per mille on a lane ($OUT/table.txt)"
fi
exit $rc

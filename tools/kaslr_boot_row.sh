#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Boot one kernel image several times under QEMU and judge virtual KASLR from
# its console (Kconfig KASLR; the rows in tools/ci_check.sh build the images).
#
#   tools/kaslr_boot_row.sh <riscv64|aarch64|x86_64> <image> slid  [runs]
#   tools/kaslr_boot_row.sh <riscv64|aarch64|x86_64> <image> plain [runs]
#
# slid:  an image built with CONFIG_KASLR_PROBE=y on a development build.
#        Every boot must print `[KASLR] image slid to 0x<base>, <N> bits`,
#        map the image at that base (`[MM] Kernel image mapped at 0x<base>`),
#        make the RAM map's alias of it read-only and not executable, reach the
#        end of the early boot with no `FAILED:` or exception, and the bases
#        of the runs must not all be equal (a fixed base is a slide that does
#        nothing; with 8 bits of entropy at worst, 4 runs agree by chance with
#        probability 2^-24).
# plain: the canary, an image built with CONFIG_KASLR_NEVER=y. The same judge
#        must find NO slid line: `[KASLR] n: the image runs at its link
#        address`, and an image address in the link range. A row that reads
#        "slid" here is a row that passes without looking.
#
# KASLR_END_ERE (an extended regex) moves the end of the judged boot past the
# early boot, for an image that goes further: the gate's own ktest kernel is
# judged to its TAP plan (`^1\.\.[0-9]+$`, the test runner started). Only the
# log up to the first line matching it is judged (what a test prints after it
# is the ktest rows' business). KASLR_WAIT_S bounds each boot (default 90 s).
#
# Exit status 0 = the judgement holds. Output is terse; the logs are kept on
# failure in $KASLR_LOG_DIR (default: a fresh directory under $TMPDIR).
#
# QEMU is run one at a time (the tree allows four at once host-wide: callers
# that run rows in parallel own that budget). Needs no `timeout` or `head`.

set -u

isa="${1:-}"; img="${2:-}"; mode="${3:-}"; runs="${4:-4}"
case "$isa" in riscv64|aarch64|x86_64) ;; *) echo "usage: $0 <riscv64|aarch64|x86_64> <image> <slid|plain> [runs]" >&2; exit 2 ;; esac
case "$mode" in slid|plain) ;; *) echo "usage: $0 <isa> <image> <slid|plain> [runs]" >&2; exit 2 ;; esac
[ -f "$img" ] || { echo "kaslr row ($isa): no image at $img" >&2; exit 2; }

logdir="${KASLR_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/kaslr-$isa.XXXXXX")}"
mkdir -p "$logdir"

# The machine, as the Makefile boots this ISA (mk/vars.mk, mk/qemu.mk).
case "$isa" in
    riscv64) qemu=qemu-system-riscv64; args=(-machine virt -nographic -bios default -m 256M -smp 2 -kernel "$img") ;;
    aarch64) qemu=qemu-system-aarch64; args=(-M virt,gic-version=3 -cpu max,pauth=on -smp 2 -nographic -kernel "$img") ;;
    x86_64)  qemu=qemu-system-x86_64;  args=(-M microvm -cpu max -m 256M -nographic -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 -kernel "$img") ;;
esac

# What the early boot prints once the image has been mapped, aliased and the
# page tables checked: the line after which a failure of the slide would show.
end_marker='[MM] Heap test'
end_ere="${KASLR_END_ERE:-}"
wait_s="${KASLR_WAIT_S:-90}"
# at_end <log>: has the boot reached the end of what this row judges?
at_end() {
    [ -f "$1" ] || return 1
    if [ -n "$end_ere" ]; then tr -d '\r' <"$1" | grep -aqE "$end_ere"
    else grep -aqF "$end_marker" "$1" 2>/dev/null; fi
}
# cut_at_end <log>: keep the log up to the first end line (with an ERE end).
cut_at_end() {
    [ -n "$end_ere" ] || return 0
    tr -d '\r' <"$1" | awk -v e="$end_ere" '{ print } $0 ~ e { exit }' >"$1.cut" && mv "$1.cut" "$1"
}
fail=0
bases=""

one_boot() { # one_boot <n>: boots, waits for the end marker or a stop, echoes the log path
    local n="$1" log="$logdir/$isa-$mode-$n.log" pid i=0
    rm -f "$log"
    "$qemu" "${args[@]}" </dev/null >"$log" 2>&1 &
    pid=$!
    # 90 s is generous for TCG; the loop ends the moment the boot is judged.
    while [ "$i" -lt $((wait_s * 2)) ]; do
        at_end "$log" && break
        grep -aqE 'FAILED:|EXCEPTION\]|AARCH64-TRAP\] unhandled|\[FATAL\]|KASLR\] FATAL' "$log" 2>/dev/null && break
        kill -0 "$pid" 2>/dev/null || break
        i=$((i + 1)); sleep 0.5
    done
    kill "$pid" 2>/dev/null; sleep 0.2; kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    cut_at_end "$log"
    echo "$log"
}

n=1
while [ "$n" -le "$runs" ]; do
    log="$(one_boot "$n")"
    why=""
    if grep -aqE 'FAILED:|EXCEPTION\]|AARCH64-TRAP\] unhandled|\[FATAL\]|KASLR\] FATAL' "$log"; then
        why="the boot reported a failure: $(grep -aE 'FAILED:|EXCEPTION\]|AARCH64-TRAP\] unhandled|\[FATAL\]|KASLR\] FATAL' "$log" | tr -d '\r' | sed -n 1p)"
    elif ! at_end "$log"; then
        why="the boot never reached \"${end_ere:-$end_marker}\" (no console output at all, or it stopped after: $(tr -d '\r' <"$log" | LC_ALL=C tr -cd '[:print:]\n' | grep -a . | grep -av '^qemu-system' | sed -n '$p' | cut -c1-100))"
    elif [ "$mode" = slid ]; then
        line="$(tr -d '\r' <"$log" | grep -aE '^\[KASLR\] image slid to 0x[0-9a-f]+, [0-9]+ bits' | sed -n 1p)"
        if [ -z "$line" ]; then
            why="no \"[KASLR] image slid to 0x..\" line: $(grep -a '\[KASLR\]' "$log" | tr -d '\r' | sed -n 1p)"
        else
            base="$(printf '%s' "$line" | sed -E 's/.*slid to (0x[0-9a-f]+),.*/\1/')"
            if ! grep -aqF "[MM] Kernel image mapped at $base" "$log"; then
                why="the image is not mapped at the reported base $base"
            elif ! grep -aqE '\[MM\] Image alias in the RAM map: [0-9]+ pages read-only, not executable' "$log"; then
                why="the RAM map's alias of the image was not made read-only and not executable"
            else
                bases="$bases $base"
            fi
        fi
    else
        if grep -aqE '\[KASLR\] image slid' "$log"; then
            why="the canary image slid: the row would pass an image that does nothing"
        elif ! grep -aqF '[KASLR] n: the image runs at its link address' "$log"; then
            why="no \"[KASLR] n:\" line: $(grep -a '\[KASLR\]' "$log" | tr -d '\r' | sed -n 1p)"
        fi
    fi
    if [ -n "$why" ]; then
        echo "KASLR row ($isa, $mode, boot $n): $why"
        echo "  log kept: $log"
        fail=1
    else
        rm -f "$log"
    fi
    n=$((n + 1))
done

if [ "$fail" = 0 ] && [ "$mode" = slid ]; then
    distinct="$(printf '%s\n' $bases | sort -u | wc -l | tr -d ' ')"
    if [ "$runs" -ge 2 ] && [ "$distinct" -lt 2 ]; then
        echo "KASLR row ($isa, slid): $runs boots, one base ($bases ): the slide is not random"
        fail=1
    else
        echo "KASLR row ($isa, slid): $runs boots, $distinct distinct bases:$bases"
    fi
elif [ "$fail" = 0 ]; then
    echo "KASLR row ($isa, plain): $runs boots at the link address"
fi
exit "$fail"

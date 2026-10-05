#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Account for every line of a `console-splice-smoke` boot (see
# `console_splice_writer_task` in kernel/src/smokes/console_splice.rs).
#
#   tools/console_splice_count.sh <log>
#
# Exits 0 only when:
#   * the smoke finished (`[SPLICE] DONE`) and every one of its ring-3 lines
#     came out byte-exact — `[SPLICEU] n=NNNN <62 fixed bytes> END`, nothing
#     else on the line;
#   * every kernel smoke line that reached the wire is whole (`[SPLICEK]` and
#     `[SPLICEI]` lines match their own exact format), so none was spliced
#     into and none was cut by the drop policy;
#   * every kernel smoke line that did NOT reach the wire is covered by a
#     `[CONSOLE] dropped B kernel bytes (L lines)` report — a line may be
#     dropped for want of buffer room, never silently lost;
#   * the run contended at all: at least one kernel line in the window.
set -u
log="$1"
clean="$(mktemp)"
trap 'rm -f "$clean"' EXIT
# The UART emits "\n\r"; drop the CRs so a line is a line.
tr -d '\r' <"$log" >"$clean"
fill='abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
kfill='ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvutsrqponmlkjihgfedcba'
done_line="$(grep -a '^\[SPLICE\] DONE ' "$clean" | sed -n 1p)"
field() { printf '%s' "$done_line" | sed -n "s/.* $1=\([0-9]*\).*/\1/p"; }
expected="$(field lines)"
k_printed="$(field klines)"
i_printed="$(field isr_lines)"
started="$(grep -ao '\[SPLICEU\] n=' "$clean" | wc -l | tr -d ' ')"
intact="$(grep -acE "^\[SPLICEU\] n=[0-9]{4} ${fill} END$" "$clean")"
k_total="$(grep -ao '\[SPLICEK\] k=' "$clean" | wc -l | tr -d ' ')"
k_intact="$(grep -acE "^\[SPLICEK\] k=[0-9]{5,} ${kfill} KEND$" "$clean")"
i_total="$(grep -ao '\[SPLICEI\] isr=' "$clean" | wc -l | tr -d ' ')"
i_intact="$(grep -acE "^\[SPLICEI\] isr=[0-9]{5,} interrupt-context kernel line -{30} IEND$" "$clean")"
dropped="$(grep -aE '^\[CONSOLE\] dropped [0-9]+ kernel bytes \([0-9]+ lines\)' "$clean" \
           | sed -E 's/.*\(([0-9]+) lines\).*/\1/' | awk '{s+=$1} END {print s+0}')"
if [ -z "$expected" ] || [ -z "$k_printed" ] || [ -z "$i_printed" ]; then
    echo "no complete '[SPLICE] DONE' line: the smoke did not finish (started=$started intact=$intact)"
    exit 2
fi
spliced=$((expected - intact))
missing=$(( (k_printed - k_intact) + (i_printed - i_intact) ))
echo "expected=$expected started=$started intact=$intact spliced=$spliced kernel_printed=$k_printed kernel_seen=$k_total kernel_intact=$k_intact isr_printed=$i_printed isr_seen=$i_total isr_intact=$i_intact missing=$missing dropped_reported=$dropped"
# A run with no kernel line in it could not have spliced: not a pass.
if [ "$k_printed" -eq 0 ] && [ "$i_printed" -eq 0 ]; then
    echo "no kernel or ISR line during the window: the run did not contend"
    exit 3
fi
rc=0
[ "$started" -eq "$expected" ] && [ "$spliced" -eq 0 ] || { echo "ring-3 lines spliced or missing"; rc=1; }
[ "$k_total" -eq "$k_intact" ] && [ "$i_total" -eq "$i_intact" ] || { echo "a kernel line on the wire is torn"; rc=1; }
[ "$missing" -ge 0 ] && [ "$missing" -le "$dropped" ] || { echo "kernel lines lost without a drop report"; rc=1; }
exit $rc

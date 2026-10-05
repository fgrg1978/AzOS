#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# AzOS — security scan, unit 4 (races): census of the surface.
#
# Unit 4 was scoped on 2026-09-20. Its two named gaps turned out to carry
# declared orderings; what is open is the surface itself. This script
# re-derives that surface so no figure quoted for it is a
# copied constant — run it and compare. A number that has drifted means the
# tree moved, not that the doc was wrong to start with.
#
# Usage: bash tools/race_census.sh            # counts
#        bash tools/race_census.sh --list     # + every Relaxed access, file:line
#
# Scope is deliberately narrow: the scheduler and the kernel binary. Widening
# it is a scoping decision, not a flag.

set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

SCOPE="crates/core/sched/src kernel/src"

echo "== atomic orderings =="
for o in Relaxed Acquire Release AcqRel SeqCst; do
    n=$(grep -rho "Ordering::$o" --include="*.rs" $SCOPE 2>/dev/null | wc -l | tr -d ' ')
    printf "%-8s %s\n" "$o" "$n"
done

echo
echo "== Relaxed by file (occurrences, not lines) =="
# `grep -c` counts LINES, and lines carrying two Relaxed are common here, so a
# per-file `-c` does not sum to the total above. Count occurrences per file.
for f in $(grep -rl "Ordering::Relaxed" --include="*.rs" $SCOPE 2>/dev/null); do
    printf "%s:%s\n" "$f" "$(grep -o "Ordering::Relaxed" "$f" | wc -l | tr -d ' ')"
done | sort -t: -k2 -rn

echo
echo "== compare_exchange sites =="
echo "   (each one's failure argument is a Relaxed that is not an access;"
echo "    subtract them before treating the Relaxed count as a work list)"
grep -rc "compare_exchange" --include="*.rs" $SCOPE 2>/dev/null | grep -v ':0$' | sort -t: -k2 -rn

echo
echo "== static mut =="
grep -rn "static mut" --include="*.rs" $SCOPE 2>/dev/null | sed 's/\(:[0-9]*\):.*/\1/'

echo
echo "== unsynchronised sharing primitives (expected: none) =="
printf "UnsafeCell        %s\n" "$(grep -rho "UnsafeCell" --include="*.rs" $SCOPE 2>/dev/null | wc -l | tr -d ' ')"
printf "unsafe impl Sync  %s\n" "$(grep -rho "unsafe impl .*Sync" --include="*.rs" $SCOPE 2>/dev/null | wc -l | tr -d ' ')"

if [ "${1:-}" = "--list" ]; then
    echo
    echo "== every Relaxed access =="
    grep -rn "Ordering::Relaxed" --include="*.rs" $SCOPE 2>/dev/null
fi

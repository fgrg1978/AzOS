#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# The first landing on main's first-parent line where a gate row went red.
#
#   land_bisect.sh <good> <bad> "<row label>"
#
# Only first-parent commits of <good>..<bad> are candidates (a landing is one merge;
# the commits inside it are not tried). A binary search in a worktree of its own
# (nothing of the caller's checkout is touched, `git bisect` is not used), each probe
# `CI_TIER=rows CI_ROWS=<label> CI_JOBS=1 bash tools/gate/ci_check.sh`: exit 0 is
# good, a log that says the kernel did not build is skipped (a neighbour is tried
# in its place), anything else is bad.
#
#   LAND_BISECT_CMD   run instead of the gate row (in the worktree): 0 good, 125 skip, else bad
#   LAND_BISECT_VERIFY=1   first check that <good> is green and <bad> red
#   AZOS_OUT          base of the build output (default $HOME/azos-out/land-bisect-<pid>)
set -uo pipefail
[ $# -eq 3 ] || { sed -n '5,7p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
good="$1" bad="$2" label="$3"
src="$(cd "$(dirname "$0")/../.." && git rev-parse --show-toplevel)" || exit 2
git -C "$src" rev-parse --verify -q "$good^{commit}" >/dev/null || { echo "land_bisect: $good is not a commit"; exit 2; }
git -C "$src" rev-parse --verify -q "$bad^{commit}" >/dev/null || { echo "land_bisect: $bad is not a commit"; exit 2; }
wt="${LAND_BISECT_WT:-${TMPDIR:-/tmp}/land-bisect-$$}"
export AZOS_OUT="${AZOS_OUT:-$HOME/azos-out/land-bisect-$$}"
mkdir -p "$AZOS_OUT/logs"
git -C "$src" worktree add -q --detach "$wt" "$bad" || exit 2
trap 'git -C "$src" worktree remove --force "$wt" >/dev/null 2>&1' EXIT
if [ -d "$src/tools/keys" ]; then
    mkdir -p "$wt/tools/keys"
    for k in test_pub.bin test_priv.bin; do [ -f "$src/tools/keys/$k" ] && cp "$src/tools/keys/$k" "$wt/tools/keys/"; done
fi

commits=(); while IFS= read -r c; do commits+=("$c"); done < <(git -C "$src" rev-list --first-parent --reverse "$good..$bad")
n=${#commits[@]}
[ "$n" -gt 0 ] || { echo "land_bisect: no first-parent landing between $good and $bad"; exit 2; }

verdict=() # per index: g, b, s (skipped) or empty (not tried)
probe() { # probe <sha> -> sets V to g|b|s
    local sha="$1" log rc
    log="$AZOS_OUT/logs/$(git -C "$src" rev-parse --short "$sha").log"
    git -C "$wt" checkout -q --detach "$sha" || { V=s; return; }
    if [ -n "${LAND_BISECT_CMD:-}" ]; then
        (cd "$wt" && bash -c "$LAND_BISECT_CMD") >"$log" 2>&1; rc=$?
    else
        (cd "$wt" && CI_TIER=rows CI_ROWS="$label" CI_JOBS=1 bash tools/gate/ci_check.sh) >"$log" 2>&1; rc=$?
    fi
    if [ "$rc" = 0 ]; then V=g
    elif [ "$rc" = 125 ] || grep -qE 'did NOT build|did not build' "$log"; then V=s
    else V=b; fi
    echo "  $(git -C "$src" log -1 --format='%h %s' "$sha" | cut -c1-90): $V (rc=$rc, $log)" >&2
}

if [ "${LAND_BISECT_VERIFY:-0}" = 1 ]; then
    probe "$good"; [ "$V" = g ] || { echo "land_bisect: <good> $good is not green for \"$label\" ($V)"; exit 3; }
    probe "$bad"; [ "$V" = b ] || { echo "land_bisect: <bad> $bad is not red for \"$label\" ($V)"; exit 3; }
fi

lo=-1 hi=$((n - 1))   # commits[lo] is good (-1: <good> itself), commits[hi] is bad
verdict[$hi]=b
while [ $((hi - lo)) -gt 1 ]; do
    mid=$(((lo + hi) / 2)); pick=""
    # the nearest index to mid, upward then downward, that builds
    for off in $(seq 0 $((hi - lo))); do
        for i in $((mid + off)) $((mid - off)); do
            if [ "$i" -gt "$lo" ] && [ "$i" -lt "$hi" ] && [ -z "${verdict[$i]:-}" ]; then
                probe "${commits[$i]}"; verdict[$i]=$V
                [ "$V" != s ] && { pick=$i; break 2; }
            fi
        done
    done
    if [ -z "$pick" ]; then
        echo "land_bisect: every landing between the last good and the first bad one fails to build; the first bad landing is one of:"
        for i in $(seq $((lo + 1)) "$hi"); do git -C "$src" log -1 --format='  %h %s' "${commits[$i]}"; done
        exit 4
    fi
    if [ "${verdict[$pick]}" = g ]; then lo=$pick; else hi=$pick; fi
done
echo "first bad landing: $(git -C "$src" log -1 --format='%h %s' "${commits[$hi]}")"

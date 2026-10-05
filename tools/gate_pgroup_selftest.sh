#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Self-test for tools/gate_pgroup.sh: an interrupted gate kills what its host
# commands started, including a process that was re-parented away.
#
#     bash tools/gate_pgroup_selftest.sh          # expect: ok
#     CI_PGROUP_KILL_CANARY=1 bash tools/gate_pgroup_selftest.sh   # expect: FAIL
#
# A miniature gate (the same traps as tools/ci_check.sh: EXIT kills the
# registered groups, INT/TERM exit 130) runs one host command through
# `gate_pgroup_run`. The command orphans a sleeper at once — its subshell
# exits, so the sleeper's parent is launchd and `pgrep -P` from the gate
# never finds it, which is how a host-test binary escaped the tree kill —
# and then blocks. The driver TERMs the miniature gate and checks that it
# exited within 5 s and that the orphan is gone. Exit 0 on ok, 1 on FAIL.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/mini_gate.sh" <<EOF
GATE_PGROUP_DIR="$WORK/pgroups"
. "$ROOT/tools/gate_pgroup.sh"
trap gate_pgroup_kill_all EXIT
trap 'exit 130' INT TERM
gate_pgroup_run "$WORK/out" "$WORK" bash -c '(sleep 300 & echo \$! >"$WORK/orphan.pid"); sleep 300'
EOF

bash "$WORK/mini_gate.sh" &
gate=$!
deadline=$(( $(date +%s) + 10 ))
while [ ! -s "$WORK/orphan.pid" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.1; done
orphan="$(cat "$WORK/orphan.pid" 2>/dev/null)"
if [ -z "$orphan" ]; then
    echo "FAIL: the host command never started"; kill "$gate" 2>/dev/null; exit 1
fi
ppid="$(ps -o ppid= -p "$orphan" | tr -d ' ')"
pgid="$(ps -o pgid= -p "$orphan" | tr -d ' ')"
kill -TERM "$gate"
deadline=$(( $(date +%s) + 5 ))
while kill -0 "$gate" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.1; done
verdict=ok
if kill -0 "$gate" 2>/dev/null; then
    echo "FAIL: the gate did not exit within 5 s of TERM"; verdict=FAIL
    kill -KILL "$gate" 2>/dev/null
fi
sleep 0.3
if kill -0 "$orphan" 2>/dev/null; then
    echo "FAIL: orphan $orphan (re-parented to $ppid) outlived the interrupted gate"; verdict=FAIL
    kill -KILL "$orphan" 2>/dev/null
fi
# The rest of the command (its bash and second sleep) is in the orphan's
# group, which this test made: on FAIL it is still there, so clean it up.
[ "$verdict" = ok ] || kill -KILL -- "-$pgid" 2>/dev/null
[ "$verdict" = ok ] && echo "ok: gate exited on TERM, orphan $orphan (parent $ppid) killed with its group"
[ "$verdict" = ok ]

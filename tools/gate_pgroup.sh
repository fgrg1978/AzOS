# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Sourced by tools/ci_check.sh (and tools/gate_pgroup_selftest.sh): run a host
# command in a process group of its own, so an interrupted gate can kill
# everything it started, including processes that were re-parented away.
#
# Why (wave 13): the gate's tree kill (`par_kill_tree`) walks `pgrep -P` from
# its own PID down. A process whose parent died first is re-parented to
# launchd and drops out of that tree: a `azos_net_tests` binary started by
# the serial `net-tests (fleet ring)` row outlived an interrupted gate that
# way. A process group survives re-parenting, so the group is what is killed.
# And the old row ran cargo in the foreground of a command substitution:
# bash runs a trapped INT/TERM only after a foreground command ends, so the
# gate could not even react until cargo finished. `gate_pgroup_run` starts the
# command in the background and `wait`s, which a trapped signal interrupts.
#
# Each live group is a file named after its PGID in $GATE_PGROUP_DIR (one file
# per group, so parallel jobs never rewrite a shared list). A finished row
# sweeps its own group (anything it left behind) and removes the file; the
# gate's EXIT trap calls `gate_pgroup_kill_all` for the rest. The groups are
# made here, never inherited: the gate's own PGID may be shared with its
# caller, so it is never the target.
#
# CI_PGROUP_KILL_CANARY=1 turns every kill here into a no-op: the canary that
# the self-test's orphan check discriminates.

GATE_PGROUP_DIR="${GATE_PGROUP_DIR:-${TMPDIR:-/tmp}/gate-pgroups.$$}"
mkdir -p "$GATE_PGROUP_DIR"

# gate_pgroup_run <outfile> <dir> <command> [args...]: run the command in
# <dir>, stdin from /dev/null (a background group reading the terminal would
# stop on SIGTTIN), stdout and stderr to <outfile>; its exit status.
gate_pgroup_run() {
    local out="$1" dir="$2" pid rc
    shift 2
    (cd "$dir" && exec python3 -c 'import os, sys; os.setpgid(0, 0); os.execvp(sys.argv[1], sys.argv[1:])' "$@") \
        </dev/null >"$out" 2>&1 &
    pid=$!
    : >"$GATE_PGROUP_DIR/$pid"
    wait "$pid"
    rc=$?
    gate_pgroup_kill "$pid"
    rm -f "$GATE_PGROUP_DIR/$pid"
    return "$rc"
}

# gate_pgroup_kill <pgid>: TERM the group, KILL whatever is left after ~2 s.
gate_pgroup_kill() {
    [ "${CI_PGROUP_KILL_CANARY:-0}" = 1 ] && return 0
    local g="$1" i=0
    kill -TERM -- "-$g" 2>/dev/null || return 0
    while [ "$i" -lt 20 ] && pgrep -g "$g" >/dev/null 2>&1; do
        sleep 0.1
        i=$((i + 1))
    done
    kill -KILL -- "-$g" 2>/dev/null
    return 0
}

# gate_pgroup_kill_all: every group still registered (the gate is exiting).
gate_pgroup_kill_all() {
    local f
    for f in "$GATE_PGROUP_DIR"/*; do
        [ -e "$f" ] || continue
        gate_pgroup_kill "${f##*/}"
        rm -f "$f"
    done
    return 0
}

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# rr_row.sh — run one gate row under QEMU record until it fails, keep the recording.
#
#   tools/dev/rr_row.sh "<row label>" [--runs N] [--until ERE] [--keep-pass] [--out DIR]
#
#   --runs N      stop after N passing runs (default 10)
#   --until ERE   also stop at the first run whose console has a line matching ERE,
#                 whatever the row said (a canary row PASSES when its not-ok shows:
#                 `--until 'not ok [0-9]+ - inspect_refresh'` records that not-ok)
#   --keep-pass   when no run stops, keep the last passing recording (a pass to replay)
#   --out DIR     where recordings go (default $AZOS_OUT/rr)
#
# The row runs EXACTLY as in the gate: this script runs tools/gate/ci_check.sh with
# CI_TIER=rows for that one label, with a qemu-system-<arch> stand-in
# (tools/dev/rr_qemu.py) first on PATH. The stand-in takes the command line the row
# built, keeps the kernel and every disk image it starts from, adds
# `-icount shift=0,sleep=off,rr=record,rrfile=...` and turns disks into
# snapshot + blkreplay drives. Nothing changes in a kernel image, a Kconfig or a
# performance run: this is host tooling.
#
# A stopping run is kept in DIR/<row>-<time>/ with boot-K/{rr.bin, kernel, kernel.elf,
# disk-*.img, console.log, spec.json}, gate.txt (the row's output) and meta.json.
# Replay it with tools/dev/rr_replay.sh DIR/<row>-<time> [--gdb].
#
# What record/replay cannot take (tools/dev/rr_qemu.py header has the list): HVF/KVM,
# host network backends (virtio-net on -netdev user/tap), host sockets or ptys as
# consoles, the stall watcher (unset STALL_WATCH), USB passthrough, audio, windows,
# host directory shares, disks that are not `-drive if=none`. A row whose QEMU command
# has any of them is REFUSED with the reason (exit 3), never recorded to a replay that
# would diverge. With -smp N the vCPUs run round-robin in one thread under icount: the
# recording is deterministic, but a failure that needs the gate's multi-threaded
# interleaving may not show; repeat with --runs.
#
# Exit: 0 a failing/--until run was recorded; 1 N runs passed; 2 usage or setup
# error; 3 refused; 4 too many QEMU processes (more than 2) on the host.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$REPO/tools/lib/qemu_count.sh"

usage() { sed -n '/^#   tools/,/^#   --out/p' "$0" | sed 's/^# \{0,3\}//'; }
die() { echo "rr_row: $*" >&2; exit 2; }

label="" runs=10 until_re="" keep_pass=0 out=""
while [ $# -gt 0 ]; do
    case "$1" in
        --runs) [ $# -ge 2 ] || die "--runs needs a number"; runs="$2"; shift 2 ;;
        --until) [ $# -ge 2 ] || die "--until needs a regular expression"; until_re="$2"; shift 2 ;;
        --keep-pass) keep_pass=1; shift ;;
        --out) [ $# -ge 2 ] || die "--out needs a directory"; out="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option $1 (see --help)" ;;
        *) [ -z "$label" ] || die "one row label only (got '$label' and '$1')"; label="$1"; shift ;;
    esac
done
[ -n "$label" ] || { usage >&2; exit 2; }
case "$runs" in ''|*[!0-9]*|0) die "--runs must be a positive integer, not '$runs'" ;; esac
[ -z "${STALL_WATCH:-}" ] || { echo "rr_row: REFUSED: STALL_WATCH is set; the stall watcher's monitor and gdb sockets cannot be recorded (unset it)" >&2; exit 3; }
[ -n "${AZOS_OUT:-}" ] || die "AZOS_OUT is not set (the gate's output directory, outside iCloud)"
awk -F'\t' -v l="$label" '$1 == l { f = 1 } END { exit !f }' "$REPO/tools/gate/gate_rows.tsv" \
    || die "no gate row labelled '$label' in tools/gate/gate_rows.tsv"
for t in riscv64 aarch64 x86_64; do command -v "qemu-system-$t" >/dev/null || die "qemu-system-$t is not on PATH"; done
out="${out:-$AZOS_OUT/rr}"
mkdir -p "$out" || die "cannot make $out"
[ "$(qemu_count)" -le 2 ] || { echo "rr_row: $(qemu_count) QEMU processes are running (more than 2); not starting" >&2; exit 4; }
free_gb="$(df -g "$out" | awk 'NR == 2 { print $4 }')"
[ "${free_gb:-0}" -ge 25 ] || die "only ${free_gb} GB free under $out (need 25)"

tag="$(printf '%s' "$label" | tr -c 'A-Za-z0-9' '-')"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
work="$out/.work-$tag-$$"
wrap="$work/bin"
rm -rf "$work"; mkdir -p "$wrap"
for t in riscv64 aarch64 x86_64; do ln -s "$HERE/rr_qemu.py" "$wrap/qemu-system-$t"; done
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

n=0
while [ "$n" -lt "$runs" ]; do
    n=$((n + 1))
    rdir="$work/run"
    rm -rf "$rdir"; mkdir -p "$rdir"
    printf 'rr_row: run %s/%s of "%s"\n' "$n" "$runs" "$label"
    (cd "$REPO" && RR_DIR="$rdir" PATH="$wrap:$PATH" CI_TIER=rows CI_ROWS="$label" GATE_JOBS=1 \
        bash tools/gate/ci_check.sh) >"$rdir/gate.txt" 2>&1
    grc=$?
    if [ -s "$rdir/refused.txt" ]; then
        echo "rr_row: REFUSED: the row's QEMU command cannot be recorded for replay:" >&2
        sed 's/^/  /' "$rdir/refused.txt" >&2
        exit 3
    fi
    ls -d "$rdir"/boot-* >/dev/null 2>&1 || { sed -n '1,40p' "$rdir/gate.txt" >&2; die "the row started no QEMU (gate exit $grc); see $rdir/gate.txt"; }
    # The console copies are written once QEMU is gone.
    for b in "$rdir"/boot-*; do
        w=0; while [ ! -s "$b/console.log" ] && [ "$w" -lt 50 ]; do w=$((w + 1)); sleep 0.1; done
    done
    # The row's verdict line: "  <label>...  ok|FAIL".
    verdict="$(grep -aF -- "$label..." "$rdir/gate.txt" | sed -n '1p')"
    case "$verdict" in
        *FAIL*) state=fail ;;
        *ok*|*" ok") state=pass ;;
        *) sed -n '1,60p' "$rdir/gate.txt" >&2; die "no verdict for '$label' in the gate output (exit $grc); see $rdir/gate.txt" ;;
    esac
    marker=""; mboot=1
    if m="$(python3 "$HERE/rr_qemu.py" marker "$rdir" ${until_re:+--until "$until_re"})"; then
        mboot="${m%%$'\t'*}"; marker="${m#*$'\t'}"
    fi
    stop=""
    [ "$state" = fail ] && stop="the row failed"
    [ -z "$stop" ] && [ -n "$until_re" ] && [ -n "$marker" ] && stop="console line matches --until"
    if [ -n "$stop" ]; then
        keep="$out/$tag-$stamp"
        rm -rf "$keep"; mv "$rdir" "$keep"
        python3 - "$keep" "$label" "$n" "$stop" "$marker" "$mboot" "$state" <<'PY'
import json, sys
d, label, n, why, marker, boot, state = sys.argv[1:8]
json.dump({"row": label, "run": int(n), "reason": why, "marker": marker or None, "boot": int(boot), "row_verdict": state},
          open(d + "/meta.json", "w"), indent=1)
PY
        echo "rr_row: stopped at run $n: $stop"
        [ -n "$marker" ] && echo "rr_row: failure line: $marker"
        echo "rr_row: recording kept: $keep"
        echo "rr_row: replay it (console compared with the recording's):"
        echo "          tools/dev/rr_replay.sh $keep"
        echo "        paused at the first instruction, gdb stub on :1234, symbols loaded by $keep/gdb.cmd:"
        echo "          tools/dev/rr_replay.sh $keep --gdb"
        python3 "$HERE/rr_qemu.py" replay-cmd "$keep" --boot "$mboot" --gdb | sed 's/^/        raw command: /'
        exit 0
    fi
    last="$rdir"
    if [ "$n" -lt "$runs" ]; then rm -rf "$rdir"; fi
done
echo "rr_row: $runs run(s) passed, no failure to keep"
if [ "$keep_pass" = 1 ]; then
    keep="$out/$tag-$stamp-pass"
    rm -rf "$keep"; mv "$last" "$keep"
    python3 - "$keep" "$label" "$runs" <<'PY'
import json, sys
d, label, n = sys.argv[1:4]
json.dump({"row": label, "run": int(n), "reason": "passing run kept", "marker": None, "boot": 1, "row_verdict": "pass"},
          open(d + "/meta.json", "w"), indent=1)
PY
    echo "rr_row: last passing recording kept: $keep"
    echo "          tools/dev/rr_replay.sh $keep"
fi
exit 1

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# rr_replay.sh — replay a recording made by tools/dev/rr_row.sh.
#
#   tools/dev/rr_replay.sh DIR [--boot K] [--gdb [--port N] [--run-gdb]] [--limit S]
#
#   (no flags)  replay to the end and compare the console with the recording's: the
#               replay must print the same lines, the recorded failure line included.
#               Exit 0 identical, 1 diverged or the marker is missing, 2 usage error.
#   --gdb       replay with the gdb stub on :PORT (default 1234), paused at the first
#               instruction (-gdb tcp::PORT -S). DIR/gdb.cmd loads the kernel symbols:
#               `gdb -x DIR/gdb.cmd`. With --run-gdb the script starts the gdb it finds
#               for the ISA (riscv64-elf-gdb, aarch64-elf-gdb, x86_64-elf-gdb,
#               gdb-multiarch, gdb); none installed for aarch64/x86_64 here, then the
#               stub is left for you or an lldb (`gdb-remote localhost:PORT`).
#   --boot K    a row that boots QEMU several times has boot-1, boot-2, ...
#   --limit S   give up after S seconds of host time (default 900)
#
# The symbols of gdb.cmd are the ELF's link addresses: a KASLR kernel's slide is on its
# console (`[KASLR] image slid to`; tools/dev/stall_attach.py slide_from reads it).
#
# Reverse execution (reverse-continue) is not offered: it needs QEMU snapshots, i.e.
# qcow2 drives, and the recording wraps raw images with blkreplay.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
die() { echo "rr_replay: $*" >&2; exit 2; }

dir="" boot="" gdb=0 port=1234 run_gdb=0 limit=900
while [ $# -gt 0 ]; do
    case "$1" in
        --boot) [ $# -ge 2 ] || die "--boot needs a number"; boot="$2"; shift 2 ;;
        --gdb) gdb=1; shift ;;
        --run-gdb) gdb=1; run_gdb=1; shift ;;
        --port) [ $# -ge 2 ] || die "--port needs a number"; port="$2"; shift 2 ;;
        --limit) [ $# -ge 2 ] || die "--limit needs seconds"; limit="$2"; shift 2 ;;
        -h|--help) sed -n '/^#   tools/,/^# Reverse/p' "$0" | sed 's/^# \{0,3\}//'; exit 0 ;;
        -*) die "unknown option $1 (see --help)" ;;
        *) [ -z "$dir" ] || die "one recording directory only"; dir="$1"; shift ;;
    esac
done
[ -n "$dir" ] || die "usage: rr_replay.sh DIR [--boot K] [--gdb [--port N] [--run-gdb]] [--limit S]"
for v in "${boot:-0}" "$port" "$limit"; do case "$v" in ''|*[!0-9]*) die "'$v' is not a number" ;; esac; done
# The boot the failure is in (meta.json), else the first.
if [ -z "$boot" ]; then
    boot="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("boot", 1))' "$dir/meta.json" 2>/dev/null)"
    boot="${boot:-1}"
fi
[ -f "$dir/boot-$boot/spec.json" ] || die "$dir/boot-$boot/spec.json: not a recording (or no boot $boot)"
[ -f "$dir/boot-$boot/rr.bin" ] || die "$dir/boot-$boot/rr.bin is missing: the recording did not complete"

# Pulling the pieces out of spec.json and the ISA's gdb.
read -r prog isa elf < <(python3 -I - "$dir/boot-$boot/spec.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
print(s["prog"], s["isa"], s.get("elf") or "-")
PY
)
cmd="$(python3 "$HERE/rr_qemu.py" replay-cmd "$dir" --boot "$boot" $([ "$gdb" = 1 ] && echo "--gdb --port $port"))" || die "cannot build the replay command"
log="$dir/boot-$boot/replay.log"

if [ "$gdb" = 1 ]; then
    {
        case "$isa" in riscv64) echo "set architecture riscv:rv64" ;; esac
        [ "$elf" != "-" ] && echo "file $dir/boot-$boot/$elf"
        echo "target remote :$port"
        echo "# paused at the first instruction of the recorded run; 'continue' replays it."
        echo "# the replay ends with the recording."
    } >"$dir/gdb.cmd"
    echo "rr_replay: replay of boot $boot paused at start; gdb stub on :$port"
    echo "rr_replay: gdb: -x $dir/gdb.cmd   (kernel symbols: ${elf/#-/none found in the recording})"
    if [ "$run_gdb" = 1 ]; then
        g=""
        for c in "$isa-elf-gdb" "${isa}-linux-gnu-gdb" gdb-multiarch gdb; do command -v "$c" >/dev/null && { g="$c"; break; }; done
        # A plain gdb on macOS cannot debug a foreign ISA.
        [ "$g" = gdb ] && g=""
        if [ -z "$g" ]; then
            echo "rr_replay: no gdb for $isa installed; leaving the stub for you (lldb: gdb-remote localhost:$port)"
        else
            eval "$cmd" </dev/null >"$log" 2>&1 &
            qpid=$!
            sleep 1
            "$g" -q -x "$dir/gdb.cmd"
            kill -9 "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null
            exit 0
        fi
    fi
    echo "rr_replay: $cmd"
    eval "$cmd"
    exit 0
fi

eval "$cmd" </dev/null >"$log" 2>&1 &
qpid=$!
i=0
while [ "$i" -lt $((limit * 2)) ] && kill -0 "$qpid" 2>/dev/null; do i=$((i + 1)); sleep 0.5; done
if kill -0 "$qpid" 2>/dev/null; then
    kill -9 "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null
    echo "rr_replay: DIVERGED or hung: QEMU still running after ${limit} s; killed it; console so far: $log"
    exit 1
fi
wait "$qpid" 2>/dev/null; qrc=$?
if msg="$(python3 "$HERE/rr_qemu.py" compare "$dir" "$boot" "$log")"; then
    echo "rr_replay: SAME: $msg (QEMU exit $qrc)"
    exit 0
fi
echo "rr_replay: DIFFERENT: $msg (QEMU exit $qrc); replay console: $log"
exit 1

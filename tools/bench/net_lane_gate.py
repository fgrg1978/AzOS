#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The vsbench network lanes against their recorded baseline.

vsbench's UDP lane (`udp-roundtrip`, section `net`) and its two TCP bulk lanes
(`tcp-bulk-tx`, `tcp-bulk-rx`, section `tcp`) are booted under
`-smp 1 -icount shift=0,sleep=off`, where a lane's ns/op is an instruction
count: deterministic per binary, blind to host load. A change to the NIC path
may not make them dearer. The lanes of an ISA are `LANES_BY_ISA`. `check` fails a lane that is missing from the log or that costs more than the
baseline by `tolerance_permille`, and skips (exit 0, "SKIP") a lane the
baseline does not hold yet: recording one needs a QEMU run; `record` writes the baseline from a run of the tree that
is to be the reference (run it on main before the change lands).

    net_lane_gate.py check  <isa> <vsbench log>...
    net_lane_gate.py record <isa> <vsbench log>...

The Linux column, when the log has one, is printed beside the number: the
lanes are compared with Linux by `vsbench_compare.sh`, this only holds the line.
"""
import os
import re
import sys

LANES = ("udp-roundtrip", "tcp-bulk-tx", "tcp-bulk-rx")
# riscv64 and aarch64 run the TCP pass (a host peer, a pcap) beside the UDP lane;
# x86_64's microvm line has no NIC at all (the x86 PC phase).
LANES_BY_ISA = {"rv": LANES, "arm": LANES}
BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "net_lane_baseline.tsv")
LINE = re.compile(r"\[VSBENCH\] (azos|linux) +(\S+) +=+ *(\d+) ns/op")


def read_logs(paths):
    """{side: {lane: ns}} from the logs; the last value of a lane wins."""
    out = {"azos": {}, "linux": {}}
    for p in paths:
        with open(p, errors="replace") as f:
            for line in f:
                m = LINE.search(line.replace("\r", ""))
                if m and m.group(2) in LANES:
                    out[m.group(1)][m.group(2)] = int(m.group(3))
    return out


def read_baseline():
    tol, rows = 30, {}
    if not os.path.exists(BASELINE):
        return tol, rows
    for line in open(BASELINE):
        line = line.rstrip("\n")
        if line.startswith("# tolerance_permille"):
            tol = int(line.split()[2])
        elif line and not line.startswith("#"):
            isa, lane, ns = line.split("\t")
            rows[(isa, lane)] = int(ns)
    return tol, rows


def main(argv):
    if len(argv) < 4 or argv[1] not in ("check", "record"):
        print(__doc__, file=sys.stderr)
        return 2
    mode, isa, logs = argv[1], argv[2], argv[3:]
    lanes = LANES_BY_ISA.get(isa)
    if lanes is None:
        print(f"net_lane_gate: no network lane runs on {isa} ({', '.join(LANES_BY_ISA)})", file=sys.stderr)
        return 2
    seen = read_logs(logs)
    missing = [l for l in lanes if l not in seen["azos"]]
    if missing:
        print(f"net_lane_gate: no azos value for {', '.join(missing)} in {' '.join(logs)}", file=sys.stderr)
        return 1
    tol, rows = read_baseline()
    if mode == "record":
        rows.update({(isa, l): seen["azos"][l] for l in lanes})
        with open(BASELINE, "w") as f:
            f.write("# vsbench network lanes, ns/op = instructions under -icount shift=0 (tools/bench/net_lane_gate.py)\n")
            f.write(f"# tolerance_permille {tol}\n")
            for (i, l), ns in sorted(rows.items()):
                f.write(f"{i}\t{l}\t{ns}\n")
        return 0
    bad = 0
    for lane in lanes:
        now, base = seen["azos"][lane], rows.get((isa, lane))
        lx = seen["linux"].get(lane)
        tail = f"  linux {lx}" if lx else ""
        if base is None:
            print(f"net_lane_gate: SKIP {isa} {lane}: {now}, no baseline recorded{tail}")
        elif now * 1000 > base * (1000 + tol):
            print(f"net_lane_gate: {isa} {lane}: {now} against {base} (over by {(now - base) * 1000 // base} per mille, tolerance {tol}){tail}", file=sys.stderr)
            bad = 1
        else:
            print(f"net_lane_gate: {isa} {lane}: {now} against {base}{tail}")
    return bad


if __name__ == "__main__":
    sys.exit(main(sys.argv))

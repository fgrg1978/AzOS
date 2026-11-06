#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The network-lane gate (net_lane_gate.py) on made-up logs: a number at the
baseline passes, one over the tolerance fails, a missing lane and a missing
baseline fail. Prints one line a case; exits 1 when a case goes the wrong way."""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def log(path, udp, tx, rx):
    with open(path, "w") as f:
        for lane, ns in (("nic-egress", udp), ("tcp-bulk-tx", tx), ("tcp-bulk-rx", rx)):
            if ns is not None:
                f.write(f"[VSBENCH] azos {lane} = {ns} ns/op\n")


def main():
    if not os.environ.get("AZOS_OUT"):
        print("net_lane_gate_selftest: AZOS_OUT is not set", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(dir=os.environ["AZOS_OUT"]) as d:
        # The script keeps its baseline beside itself: run a copy in the temp dir.
        child = os.path.join(d, "net_lane_gate.py")
        src = open(os.path.join(HERE, "net_lane_gate.py")).read()
        open(child, "w").write(src.replace("os.path.dirname(os.path.abspath(__file__))", repr(d)))
        def go(mode, isa, path):
            return subprocess.run([sys.executable, "-I", child, mode, isa, path], capture_output=True).returncode

        def skips(isa, path, lanes):
            r = subprocess.run([sys.executable, "-I", child, "check", isa, path], capture_output=True, text=True)
            return r.returncode == 0 and r.stdout.count("SKIP") == lanes
        base, same, over, gone, tcp_wide, tcp_far = (os.path.join(d, n) for n in ("base", "same", "over", "gone", "tcp_wide", "tcp_far"))
        log(base, 1000, 2000, 3000)
        log(same, 1020, 2000, 3000)
        log(over, 1060, 2000, 3000)
        log(tcp_wide, 1000, 2200, 3200)
        log(tcp_far, 1000, 2400, 3000)
        log(gone, 1000, 2000, None)
        cases = [
            ("no baseline yet skips, and says so", 0 if skips("rv", base, 3) else 1, 0),
            ("record writes it", go("record", "rv", base), 0),
            ("the baseline itself passes", go("check", "rv", base), 0),
            ("2 per cent over is inside the tolerance", go("check", "rv", same), 0),
            ("6 per cent over on nic-egress fails", go("check", "rv", over), 1),
            ("10 per cent over on the TCP lanes is inside their tolerance", go("check", "rv", tcp_wide), 0),
            ("20 per cent over on a TCP lane fails", go("check", "rv", tcp_far), 1),
            ("a lane missing from the log fails", go("check", "rv", gone), 1),
            ("another ISA has no baseline yet and skips", 0 if skips("arm", base, 3) else 1, 0),
            ("an ISA with no network lane is refused", go("check", "x86", base), 2),
        ]
        bad = 0
        for name, got, want in cases:
            ok = got == want
            bad += not ok
            print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

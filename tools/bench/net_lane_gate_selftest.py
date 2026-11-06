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
        for lane, ns in (("udp-roundtrip", udp), ("tcp-bulk-tx", tx), ("tcp-bulk-rx", rx)):
            if ns is not None:
                f.write(f"[VSBENCH] azos {lane} = {ns} ns/op\n")


def main():
    with tempfile.TemporaryDirectory(dir=os.environ.get("AZOS_OUT")) as d:
        # The script keeps its baseline beside itself: run a copy in the temp dir.
        child = os.path.join(d, "net_lane_gate.py")
        src = open(os.path.join(HERE, "net_lane_gate.py")).read()
        open(child, "w").write(src.replace("os.path.dirname(os.path.abspath(__file__))", repr(d)))
        def go(mode, isa, path):
            return subprocess.run([sys.executable, "-I", child, mode, isa, path], capture_output=True).returncode
        base, same, over, gone = (os.path.join(d, n) for n in ("base", "same", "over", "gone"))
        log(base, 1000, 2000, 3000)
        log(same, 1020, 2000, 3000)
        log(over, 1000, 2000, 3200)
        log(gone, 1000, 2000, None)
        cases = [
            ("no baseline yet fails", go("check", "rv", base), 1),
            ("record writes it", go("record", "rv", base), 0),
            ("the baseline itself passes", go("check", "rv", base), 0),
            ("2 per cent over is inside the tolerance", go("check", "rv", same), 0),
            ("6 per cent over fails", go("check", "rv", over), 1),
            ("a lane missing from the log fails", go("check", "rv", gone), 1),
            ("another ISA has no baseline", go("check", "arm", base), 1),
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

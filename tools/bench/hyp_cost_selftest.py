#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""hyp_cost.py on made-up logs shaped like the kernel's. Each claim the tool
makes has a case that turns it red: a hosted log passed off as split, a split
log passed off as hosted, a lane that does not separate, a trap that is not
visible, a missing lane, a syscall that reaches the monitor. Prints one line a
case; exits 1 when a case goes the wrong way."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hyp_cost  # noqa: E402

OPS = 256
LANES = ("hvc-null", "psci-version", "pt-map-unmap", "pt-set", "text-patch", "ttbr0-write")


def log(d, name, mode, ratios, pin="fgt", up=None, drop=(), floor=300):
    """A boot: `ratios` maps a lane to after/before (before is 1000 ticks)."""
    up = (mode == "split") if up is None else up
    lines = []
    if up:
        lines.append("[BOOT] EL2:        monitor up")
        lines.append(f"[BOOT] EL2:        pinned ({pin}), 1 PE")
    lines += [f"[HYP] cost: mode {mode}", "[HYP] cost: timebase 62500000 Hz"]
    for lane in LANES:
        if lane in drop:
            lines.append(f"[HYP] cost: {lane}: no number")
            continue
        r = ratios.get(lane, 1.0)
        lines.append(f"[HYP] cost: {lane}: {OPS} ops, 1000 ticks before, {int(1000 * r)} ticks after")
    lines += ["[HYP] cost: done", f"[VSBENCH] azos syscall-floor = {floor} ns/op (1.00x floor)"]
    path = os.path.join(d, name)
    with open(path, "w") as f:
        f.write("\r\n".join(lines) + "\r\n")
    return path


SPLIT = {"pt-map-unmap": 1.6, "pt-set": 9.0, "text-patch": 1.5, "ttbr0-write": 1.0}


def verdict(path, want, pin=None):
    return hyp_cost.check(hyp_cost.Log(path), want, pin)


def main():
    if not os.environ.get("AZOS_OUT"):
        print("hyp_cost_selftest: AZOS_OUT is not set", file=sys.stderr)
        return 2
    cases = []
    with tempfile.TemporaryDirectory(dir=os.environ["AZOS_OUT"]) as d:
        split_fgt = log(d, "split_fgt", "split", SPLIT)
        split_tvm = log(d, "split_tvm", "split", {**SPLIT, "ttbr0-write": 3.0}, pin="tvm")
        hosted = log(d, "hosted", "hosted", {})
        cases.append(("split FGT image passes as split", not verdict(split_fgt, "split")))
        cases.append(("split TVM image passes as split", not verdict(split_tvm, "split")))
        cases.append(("hosted image passes as hosted (the control)", not verdict(hosted, "hosted")))
        # The canaries: the lane has to tell the two apart both ways.
        cases.append(("CANARY hosted log judged as split goes red", bool(verdict(hosted, "split"))))
        cases.append(("CANARY split log judged as hosted goes red", bool(verdict(split_fgt, "hosted"))))
        mislabelled = log(d, "mislabelled", "split", {}, up=False)
        cases.append(("CANARY split mode without the monitor banner goes red", bool(verdict(mislabelled, "split"))))
        flat = log(d, "flat", "split", {**SPLIT, "pt-set": 1.0})
        cases.append(("CANARY pt-set that does not separate goes red", bool(verdict(flat, "split"))))
        pin_off = log(d, "pin_off", "split", SPLIT, pin="tvm")
        cases.append(("CANARY TVM with the trap removed (ttbr0 flat) goes red", bool(verdict(pin_off, "split"))))
        trapping_fgt = log(d, "trapping_fgt", "split", {**SPLIT, "ttbr0-write": 3.0})
        cases.append(("CANARY FGT where ttbr0 traps goes red", bool(verdict(trapping_fgt, "split"))))
        noisy = log(d, "noisy", "hosted", {"pt-set": 2.0})
        cases.append(("CANARY hosted control that moves by itself goes red", bool(verdict(noisy, "hosted"))))
        gone = log(d, "gone", "split", SPLIT, drop=("pt-set",))
        cases.append(("CANARY a lane with no number goes red", bool(verdict(gone, "split"))))
        silent = os.path.join(d, "silent")
        open(silent, "w").write("[BOOT] EL2:        monitor up\n")
        try:
            verdict(silent, "split")
            cases.append(("CANARY a log with no lanes is unusable", False))
        except ValueError:
            cases.append(("CANARY a log with no lanes is unusable", True))
        # System lanes: a syscall must not reach the monitor with FGT.
        h = hyp_cost.Log(log(d, "h2", "hosted", {}, floor=300))
        s_ok = hyp_cost.Log(log(d, "s_ok", "split", SPLIT, floor=300))
        s_bad = hyp_cost.Log(log(d, "s_bad", "split", SPLIT, floor=420))
        cases.append(("syscall-floor equal passes", not hyp_cost.check_system(s_ok, h)))
        cases.append(("CANARY syscall-floor +40% with FGT goes red", bool(hyp_cost.check_system(s_bad, h))))
        table = hyp_cost.table(s_ok, h)
        cases.append(("the table names a Linux pair for every monitor lane", all(l in table for l in hyp_cost.MONITOR_LANES)))
    bad = 0
    for name, ok in cases:
        print(("ok   " if ok else "FAIL ") + name)
        bad += not ok
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

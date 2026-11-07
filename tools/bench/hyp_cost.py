#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""What the EL1/EL2 split costs, read from the logs of a split and a hosted boot.

Two kinds of lane, both under TCG with `-icount shift=0,sleep=off` (one
virtual nanosecond per instruction, so ns/op is instructions per op):

* monitor lanes, printed by the kernel feature `hyp-cost-probe`
  (kernel/src/entry/aarch64/ext/hyp_cost.rs) as
  `[HYP] cost: <lane>: <ops> ops, <before> ticks before, <after> ticks after`:
  the same code path timed before the image lock and after the last lock. In a
  split image `after` carries the monitor; in a hosted image nothing is locked
  and the pair is the control.
* system lanes, the ring-3 vsbench lanes of both images, same QEMU line.

`check` judges one boot, `compare` judges a pair and prints the table.
Exit status 0: every claim held; 1: one did not; 2: a log is unusable.
"""
import re
import sys

COST = re.compile(r"\[HYP\] cost: ([a-z0-9-]+): (\d+) ops, (\d+) ticks before, (\d+) ticks after")
NONE = re.compile(r"\[HYP\] cost: ([a-z0-9-]+): no number")
MODE = re.compile(r"\[HYP\] cost: mode (split|hosted|none)")
FREQ = re.compile(r"\[HYP\] cost: timebase (\d+) Hz")
CPUON = re.compile(r"\[HYP\] cost: cpu-on-online: 1 ops, (\d+) ticks")
PIN = re.compile(r"\[BOOT\] EL2:\s+pinned \((fgt|tvm)\)")
MONITOR_UP = "[BOOT] EL2:        monitor up"
VSB = re.compile(r"\[VSBENCH\] azos (\S.*?) += (\d+) ns/op")
VSB_LINUX = re.compile(r"\[VSBENCH\] linux (\S.*?) += (\d+) ns/op")

# lane: (min after/before in a split image, linux pair)
# The minimum is a structural claim: the monitor puts a call on the path, so the
# split pair must separate by at least this much. It is not a performance target.
MONITOR_LANES = {
    "hvc-null": (None, "none in a stock Linux image: KVM's host-to-hyp call is not reachable from ring 3 or "
                       "from a module-less initramfs; nearest measured lane: syscall-floor (EL0 to EL1). "
                       "Across builds: hosted answers the stub's HVC_PROBE, split the monitor's CALL_PROBE"),
    "psci-version": (None, "none: Linux's own PSCI calls are not timed from ring 3; the cpu online/offline "
                           "lane below is the pair (pKVM relays the host's PSCI to EL3)"),
    "pt-map-unmap": (1.2, "none: pKVM does not protect the host's own tables; nearest measured: mmap+munmap "
                          "and thread create+join on the system lanes (user tables are not funnelled)"),
    "pt-set": (2.0, "none: no pKVM call writes a host page-table word; a plain store is the hosted side"),
    "text-patch": (1.2, "none: pKVM does not lock the host's text; hosted writes through the text alias"),
    "ttbr0-write": (None, "ctxsw-loaded / ipc-roundtrip across address spaces on Linux nvhe vs protected "
                          "(pKVM runs the host with a stage 2 but does not trap TTBR0_EL1)"),
}
TTBR0_TRAP_MIN = 1.5     # TVM: every write traps
TTBR0_FLAT_MAX = 1.5     # FGT or hosted: no trap
CONTROL_BAND = (0.7, 1.3)  # a hosted image's before/after: the lane's own noise

SYSTEM_LANES = [
    ("syscall-floor", "same lane, Linux nvhe vs protected"),
    ("ipc-roundtrip", "pipe-pingpong (no IPC primitive of this kind in Linux)"),
    ("ctxsw-loaded", "same lane, Linux nvhe vs protected"),
    ("mmap+munmap", "same lane"),
    ("map+touch/pg", "same lane"),
    ("thread create+join", "same lane"),
    ("fork+exit+wait", "same lane"),
    ("fork+exit", "same lane"),
]
# AzOS lane name -> the Linux side's label where they differ.
LINUX_LANE = {"ipc-roundtrip": "pipe-pingpong"}
# FGT: a ring-3 syscall must not reach the monitor at all.
SYSCALL_FLOOR_MAX = 1.05


class Log:
    def __init__(self, path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            self.text = fh.read().replace("\r", "")
        t = self.text
        m = MODE.search(t)
        self.mode = m.group(1) if m else None
        m = FREQ.search(t)
        self.hz = int(m.group(1)) if m else None
        self.lanes = {n: (int(o), int(b), int(a)) for n, o, b, a in COST.findall(t)}
        self.skipped = set(NONE.findall(t))
        m = CPUON.search(t)
        self.cpu_on = int(m.group(1)) if m else None
        m = PIN.search(t)
        self.pin = m.group(1) if m else None
        self.monitor_up = MONITOR_UP in t
        self.vsb = {k: int(v) for k, v in VSB.findall(t)}
        self.vsb_linux = {k: int(v) for k, v in VSB_LINUX.findall(t)}

    def ratio(self, lane):
        _, b, a = self.lanes[lane]
        return a / b if b else float("inf")


def _fail(msgs, text):
    msgs.append(text)


def check(log, want, pin=None):
    """Claims about one boot. `want` is 'split' or 'hosted'."""
    bad = []
    if log.mode is None or log.hz is None:
        raise ValueError("no `[HYP] cost: mode` line: the image has no cost lanes or did not reach them")
    if log.mode != want:
        _fail(bad, f"the image says mode {log.mode}, the row expected {want}")
    if want == "split" and not log.monitor_up:
        _fail(bad, "no monitor-up banner: a hosted image labelled split")
    if want == "hosted" and log.monitor_up:
        _fail(bad, "a monitor-up banner in an image labelled hosted")
    for lane in MONITOR_LANES:
        if lane not in log.lanes:
            if lane == "hvc-null" and log.mode == "none":
                continue
            if lane in log.skipped and lane in ("text-patch",):
                continue
            _fail(bad, f"lane {lane} printed no number")
    for lane, (floor, _) in MONITOR_LANES.items():
        if lane not in log.lanes or lane == "ttbr0-write":
            continue
        r = log.ratio(lane)
        if want == "split" and floor is not None and r < floor:
            _fail(bad, f"{lane}: after/before {r:.2f}x, a split image must separate by {floor}x: the lane "
                       "cannot tell split from hosted")
        if want == "hosted" and not CONTROL_BAND[0] <= r <= CONTROL_BAND[1]:
            _fail(bad, f"{lane}: hosted control moved {r:.2f}x by itself (band {CONTROL_BAND})")
    if "ttbr0-write" in log.lanes:
        r = log.ratio("ttbr0-write")
        pin = pin or log.pin
        if want == "split" and pin == "tvm" and r < TTBR0_TRAP_MIN:
            _fail(bad, f"ttbr0-write: {r:.2f}x with the pin in TVM mode: the trap is not visible")
        elif want == "split" and pin == "fgt" and r > TTBR0_FLAT_MAX:
            _fail(bad, f"ttbr0-write: {r:.2f}x with FGT: the write must not trap")
        elif want == "hosted" and not CONTROL_BAND[0] <= r <= CONTROL_BAND[1]:
            _fail(bad, f"ttbr0-write: hosted control moved {r:.2f}x by itself")
    if want == "split" and log.pin is None:
        _fail(bad, "no `pinned (fgt|tvm)` line: the TTBR0 lane cannot be read")
    return bad


def check_system(split, hosted):
    bad = []
    for name, log in (("split", split), ("hosted", hosted)):
        if "syscall-floor" not in log.vsb:
            _fail(bad, f"the {name} boot printed no syscall-floor")
    if bad:
        return bad
    if split.pin == "fgt":
        r = split.vsb["syscall-floor"] / hosted.vsb["syscall-floor"]
        if r > SYSCALL_FLOOR_MAX:
            _fail(bad, f"syscall-floor split/hosted {r:.3f}x with FGT: a syscall must not reach the monitor")
    return bad


def ns_per_op(log, lane, which):
    ops, b, a = log.lanes[lane]
    ticks = b if which == "before" else a
    return ticks * 1e9 / log.hz / ops


def table(split, hosted, nvhe=None, protected=None):
    rows = []
    a = rows.append
    a(f"pin mode (split): {split.pin}; clock {split.hz} Hz. Under -icount shift=0 ns/op is instructions/op.")
    a("What pKVM and KVM do, in the Linux pair column, is from memory and not re-checked on this image.")
    a("")
    a(f"{'monitor lane':<14}{'hosted':>10}{'split before':>14}{'split after':>13}{'after/before':>14}   Linux pair")
    for lane, (_, pair) in MONITOR_LANES.items():
        if lane in split.lanes:
            sb, sa = ns_per_op(split, lane, "before"), ns_per_op(split, lane, "after")
            h = ns_per_op(hosted, lane, "after") if lane in hosted.lanes else None
            hs = f"{h:.0f}" if h is not None else "-"
            a(f"{lane:<14}{hs:>10}{sb:>14.0f}{sa:>13.0f}{split.ratio(lane):>13.2f}x   {pair}")
        else:
            a(f"{lane:<14}{'-':>10}{'-':>14}{'-':>13}{'no number':>14}   {pair}")
    if split.cpu_on is not None:
        h = f"{hosted.cpu_on * 1e9 / hosted.hz:.0f}" if hosted.cpu_on is not None else "-"
        a(f"{'cpu-on-online':<14}{h:>10}{split.cpu_on * 1e9 / split.hz:>14.0f}{'':>13}{'':>14}   "
          "Linux: write 1 to /sys/devices/system/cpu/cpuN/online under kvm-arm.mode=nvhe vs protected "
          "(lane not built; this one is the boot-time CPU_ON)")
    a("")
    a(f"{'system lane':<22}{'hosted ns/op':>14}{'split ns/op':>13}{'split/hosted':>14}{'Linux nvhe':>12}{'Linux prot.':>12}   Linux pair")
    for lane, pair in SYSTEM_LANES:
        h, s = hosted.vsb.get(lane), split.vsb.get(lane)
        ln = nvhe.vsb_linux.get(LINUX_LANE.get(lane, lane), "-") if nvhe else "-"
        lp = protected.vsb_linux.get(LINUX_LANE.get(lane, lane), "-") if protected else "-"
        ratio = f"{s / h:>13.3f}x" if h and s else f"{'no number':>14}"
        a(f"{lane:<22}{h or '-':>14}{s or '-':>13}{ratio}{ln:>12}{lp:>12}   {pair}")
    return "\n".join(rows)


def _load(path):
    try:
        return Log(path)
    except OSError as e:
        print(f"hyp_cost: {e}", file=sys.stderr)
        sys.exit(2)


def main(argv):
    if len(argv) >= 3 and argv[1] == "check":
        want, path = argv[2], argv[3]
        pin = argv[4] if len(argv) > 4 else None
        try:
            bad = check(_load(path), want, pin)
        except ValueError as e:
            print(f"hyp_cost: {e}", file=sys.stderr)
            return 2
    elif len(argv) in (4, 6) and argv[1] == "compare":
        split, hosted = _load(argv[2]), _load(argv[3])
        nvhe, protected = (_load(argv[4]), _load(argv[5])) if len(argv) == 6 else (None, None)
        try:
            bad = check(split, "split") + check(hosted, "hosted") + check_system(split, hosted)
        except ValueError as e:
            print(f"hyp_cost: {e}", file=sys.stderr)
            return 2
        print(table(split, hosted, nvhe, protected))
    else:
        print("usage: hyp_cost.py check <split|hosted> LOG [fgt|tvm] | compare SPLIT_LOG HOSTED_LOG [LINUX_NVHE_LOG LINUX_PROTECTED_LOG]", file=sys.stderr)
        return 2
    for b in bad:
        print(f"hyp_cost: {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

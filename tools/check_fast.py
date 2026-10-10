#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The judge of `make check-fast` (tools/check_fast.sh).

One QEMU log in, one `ok`/`FAIL` line per property out; exit 0 when every
property holds. The properties are the full gate's, read from
tools/ci_check.sh so the two cannot drift:

  ktest    the `ktest (rv|arm|x86)` rows: plan == KTEST_N_<ISA>, every test
           1..N reported exactly once, no `not ok`, the summary line, no
           `Bail out!`, and QEMU's exit status (0 rv/arm, 1 x86).
  canary   the ktest runtime-canary rows, all armed in ONE boot: the `not
           ok` set equals the union of the armed sets' expected names
           (each canary breaks exactly its own tests), every other test
           `ok`, the summary counts them, QEMU status (1 rv/arm, 3 x86).
  system   the abitest rows (`userspace: ABI conformance`, `aarch64
           abitest`, `x86_64 abitest`): the summary line, no FAIL line but
           the one known aarch64 gap, no live page-table root at teardown,
           no panic or unhandled trap; plus the boot's own milestones.

  check_fast.py ktest  <isa> <log> <qemu status>
  check_fast.py canary <isa> <log> <qemu status>
  check_fast.py system <isa> <log>
  check_fast.py cmdline <isa>      prints the canary boot's `canary=` list
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "tools", "ci_check.sh")

# The runtime-canary sets one canary boot arms together, per ISA, by the
# names of their gate variables (KTEST_<SET>_CANARIES / _CANARIED). Every set
# here is a non-panicking one whose row already boots it as a group; sets
# left out break other sets' tests (`chaos-inert` disarms `chaos-leak`'s
# point), stop the run (`ioring-rt-inline` bails, and needs a disk) or invert
# the verdict (`ktest-exit-pass`).
SETS = {
    "rv": ["RT", "LOCKDEP", "RCU", "IPC", ("spin-patch-skip", "spin_sites_patched")],
    "arm": ["RT", "LOCKDEP", "RCU", "IPC", ("spin-patch-skip", "spin_sites_patched"),
            ("pan-patch-skip", "a64_pan_sites_patched")],
    "x86": [("x86-fork-fp-skip,ioring-fsync-inline",
             "x86_ring3_syscall_fork_fp ioring_fsync_completes_after_flush"),
            ("x86-low-alias", "x86_low_half_maps_no_ram"),
            ("camera-encode-per-consumer", "camera_one_encode_per_frame"),
            "LOCKDEP", "RCU", "IPC"],
}
CLEAN_STATUS = {"rv": "0", "arm": "0", "x86": "1"}
FAILED_STATUS = {"rv": "1", "arm": "1", "x86": "3"}
PLAN_VAR = {"rv": "KTEST_N_RV", "arm": "KTEST_N_ARM", "x86": "KTEST_N_X86"}


def gate_vars():
    out = {}
    for line in open(GATE, encoding="utf-8", errors="replace"):
        m = re.match(r'\s*(KTEST_[A-Z0-9_]+)="?([^"#]*)"?\s*$', line)
        if m:
            out.setdefault(m.group(1), m.group(2).strip())
    return out


def canary_plan(isa):
    v = gate_vars()
    names, want = [], []
    for s in SETS[isa]:
        if isinstance(s, tuple):
            names += s[0].split(",")
            want += s[1].split()
        else:
            names += v["KTEST_%s_CANARIES" % s].replace("canary=", "").split(",")
            want += v["KTEST_%s_CANARIED" % s].split()
    return [n for n in names if n], sorted(set(want))


RESULTS = []


def prop(name, good, why=""):
    RESULTS.append(good)
    print("  %-44s %s" % (name, "ok" if good else "FAIL  " + why))


def read(log):
    return open(log, encoding="utf-8", errors="replace").read().replace("\r", "")


def judge_ktest(isa, log, status, want):
    text = read(log)
    n = int(gate_vars()[PLAN_VAR[isa]])
    plans = re.findall(r"^1\.\.(\d+)$", text, re.M)
    prop("ktest plan 1..%d (%s)" % (n, PLAN_VAR[isa]), plans[:1] == [str(n)],
         "plan %s" % (plans[:1] or "missing"))
    seen = {}
    for k in re.findall(r"^(?:not )?ok (\d+) - ", text, re.M):
        seen[int(k)] = seen.get(int(k), 0) + 1
    bad = [k for k in range(1, n + 1) if seen.get(k) != 1]
    prop("every test 1..%d reported once" % n, not bad,
         "tests %s reported %s times" % (bad[:5], [seen.get(k, 0) for k in bad[:5]]))
    got = sorted(re.findall(r"^not ok \d+ - ([A-Za-z0-9_]+)", text, re.M))
    prop("not-ok set == expected (%d)" % len(want), got == sorted(want),
         "got %s, expected %s" % (sorted(set(got) - set(want)) or "-",
                                  sorted(set(want) - set(got)) or "-"))
    prop("no Bail out!", "Bail out!" not in text,
         (re.findall(r"^Bail out!.*$", text, re.M) or [""])[0])
    summ = "# ktest: %d tests, %d passed" % (n, n - len(want))
    prop("summary '%s'" % summ, re.search("^" + re.escape(summ), text, re.M) is not None)
    exp = FAILED_STATUS[isa] if want else CLEAN_STATUS[isa]
    prop("QEMU exit status %s" % exp, status == exp, "status %s" % status)
    # Per test, by name: each canary's own test turned red (the
    # discrimination line the owner reads first).
    for t in want:
        prop("  canary breaks %s" % t, re.search(r"^not ok \d+ - %s\b" % t, text, re.M) is not None)


# Fixed strings every userspace boot prints on the way to abitest, the same
# on every ISA: the volume mounted, its signed CONFIG verified, autorun
# loading the image.
SYSTEM_MILESTONES = ["[FS] FAT32 mounted at /fat", "/fat/CONFIG.SIG v2 verified",
                     "[AUTORUN] Loading ELF: /fat/ABITEST.ELF"]
# abitest forks children that fault on purpose: user faults are logged
# ([X86-TRAP] user fault, [PAGE FAULT] killing) and are not crashes.
CRASH = r"^.*(?:KERNEL PANIC|\[FATAL\]|AARCH64-TRAP\] unhandled).*$"
KNOWN_ABITEST_GAPS = {"arm": ["vdso flags bit 0: rdtime native"]}


def judge_system(isa, log):
    text = read(log)
    for m in SYSTEM_MILESTONES:
        prop("boot: %s" % m, m in text)
    prop("abitest summary '[ABITEST] N check(s) run'",
         re.search(r"\[ABITEST\] [0-9]+ check\(s\) run", text) is not None)
    fails = re.findall(r"^\[ABITEST\]  FAIL  (.*)$", text, re.M)
    fails = [f for f in fails if not any(g in f for g in KNOWN_ABITEST_GAPS.get(isa, []))]
    prop("abitest: no FAIL line (known gaps excepted)", not fails, "; ".join(fails[:4]))
    prop("abitest: no live page-table root at teardown", "[MM] page-table root" not in text)
    crash = re.findall(CRASH, text, re.M)
    prop("no panic, fatal or unhandled trap", not crash, (crash or [""])[0][:120])


def main(a):
    if len(a) >= 2 and a[0] == "cmdline":
        print("canary=" + ",".join(canary_plan(a[1])[0]))
        return 0
    if len(a) < 3 or a[1] not in SETS:
        print(__doc__)
        return 2
    kind, isa, log = a[0], a[1], a[2]
    if not os.path.exists(log):
        prop("%s log" % kind, False, "no log %s" % log)
    elif kind == "ktest":
        judge_ktest(isa, log, a[3], [])
    elif kind == "canary":
        judge_ktest(isa, log, a[3], canary_plan(isa)[1])
    elif kind == "system":
        judge_system(isa, log)
    else:
        print(__doc__)
        return 2
    return 0 if RESULTS and all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

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

  Every kind, when CHECK_FAST_CONFIG names the kernel's expanded config and
  its KASLR policy is not `n` (KASLR_AVAILABLE): the boot slid the image
  (`[KASLR] image slid to 0x..`; QEMU always hands a seed). A `probe` image
  that runs at its link address is a build that lost the slide, and one
  that hangs after the slide fails the plan or the milestones anyway.

  check_fast.py ktest  <isa> <log> <qemu status>
  check_fast.py canary <isa> <log> <qemu status>
  check_fast.py system <isa> <log>
  check_fast.py cmdline <isa> [<config>]
                                   prints the canary boot's `canary=` list;
                                   exits 2 (stderr, nothing on stdout) when
                                   it does not fit the kernel's
                                   KERNEL_CMDLINE_MAX less CMDLINE_MARGIN
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "tools", "ci_check.sh")
KCONFIG_LIMITS = os.path.join(ROOT, "config", "limits", "config/limits/Kconfig.limits")
# Bytes of the kernel's command-line buffer (Kconfig KERNEL_CMDLINE_MAX) the
# canary list must leave free for other boot arguments. The kernel cuts a
# longer line silently: a name cut in half is not armed, its tests pass, and
# the canary judge fails with a diff that does not say why.
CMDLINE_MARGIN = 128

# The runtime-canary sets one canary boot arms together, per ISA, by the
# names of their gate variables (KTEST_<SET>_CANARIES / _CANARIED). Every set
# here is a non-panicking one whose row already boots it as a group; sets
# left out break other sets' tests (`chaos-inert` disarms `chaos-leak`'s
# point), stop the run (`ioring-rt-inline` bails, and needs a disk) or invert
# the verdict (`ktest-exit-pass`).
# The wait-graph canaries (WAIT_GRAPH, FUTEX_PI default y): each breaks only
# its own test(s), and the others stay ok.
# kmutex-steal-any lets the releaser's own re-lock overtake the queued
# waiter, so the held-back-newcomer test loses its graph owner too.
# kmutex-park-aba parks the held-back newcomer on its word alone after a
# widened window: the word's ABA loses its wake, so that test fails too.
# ipc-call-no-edge leaves every IPC call, ordinary or fast, without its
# wait-graph edge (the fast call is then taken with nothing to boost).
_WG = ("kmutex-steal-any,kmutex-park-aba,owner-died-silent,exit-keeps-graph,futex-pi-no-edge,"
       "futex-pi-exit-silent,futex-requeue-pi-plain,futex-requeue-pi-no-proxy,"
       "held-keeps-dead,claim-held-keeps-dead,ipc-call-no-edge",
       "kmutex_steal_rule_holds_for_top_waiter kmutex_held_back_newcomer_is_in_the_graph "
       "kmutex_owner_died_wakes_waiter waitgraph_exit_clears_state futex_pi_boosts_the_owner "
       "futex_pi_owner_exit_hands_over futex_requeue_pi_hands_the_mutex_over "
       "kmutex_dead_holder_leaves_the_held_table claim_dead_owner_leaves_the_held_table "
       "waitgraph_ipc_call_boosts_server ipc_fastpath_boosting_call_is_slow_and_boosts "
       "ipc_fastpath_call_edge_is_in_the_graph")
SETS = {
    "rv": ["RT", "LOCKDEP", "RCU", "IPC", "FUTEX", "KMUTEX", "SCHED", _WG, ("spin-patch-skip", "spin_sites_patched"),
           ("console-drop", "console_task_line_waits_never_drops"),
           ("tlb-space-mask-drop", "tlb_space_mask_reaches_the_harts_that_ran"),
           ("asid-per-thread", "asid_one_per_space_across_rollover"),
           ("copyout-raw-kernel-ctx", "copyout_refused_in_kernel_context")],
    "arm": ["RT", "LOCKDEP", "RCU", "IPC", "FUTEX", "KMUTEX", "SCHED", _WG, ("spin-patch-skip", "spin_sites_patched"),
            ("pan-patch-skip", "a64_pan_sites_patched"),
            ("console-drop", "console_task_line_waits_never_drops"),
            ("asid-per-thread", "asid_one_per_space_across_rollover"),
            ("copyout-raw-kernel-ctx", "copyout_refused_in_kernel_context")],
    "x86": [("x86-fork-fp-skip,ioring-fsync-inline",
             "x86_ring3_syscall_fork_fp ioring_fsync_completes_after_flush"),
            ("x86-low-alias", "x86_low_half_maps_no_ram"),
            ("camera-encode-per-consumer", "camera_one_encode_per_frame"),
            ("irq-storm", "irq_storm_is_contained"),
            ("console-drop", "console_task_line_waits_never_drops"),
            ("copyout-raw-kernel-ctx", "copyout_refused_in_kernel_context"),
            "LOCKDEP", "RCU", "IPC", "FUTEX", "KMUTEX", "SCHED", _WG],
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


def cmdline_max(config):
    """KERNEL_CMDLINE_MAX of the expanded `config` when it has one, else the
    Kconfig default under CANARY_RUNTIME (said on stderr)."""
    if config and os.path.exists(config):
        for line in open(config, encoding="utf-8", errors="replace"):
            m = re.match(r"CONFIG_KERNEL_CMDLINE_MAX=(\d+)\s*$", line)
            if m:
                return int(m.group(1)), config
    text = open(KCONFIG_LIMITS, encoding="utf-8").read()
    m = re.search(r"^config KERNEL_CMDLINE_MAX\n(?:[ \t].*\n)*?\s*default (\d+) if CANARY_RUNTIME\s*$", text, re.M)
    if not m:
        sys.exit("check_fast: no KERNEL_CMDLINE_MAX in %s nor a CANARY_RUNTIME default in %s"
                 % (config or "(no config)", KCONFIG_LIMITS))
    print("check_fast: %s; KERNEL_CMDLINE_MAX is the Kconfig default %s under CANARY_RUNTIME"
          % ("no KERNEL_CMDLINE_MAX in " + config if config else "no config given", m.group(1)), file=sys.stderr)
    return int(m.group(1)), KCONFIG_LIMITS


RESULTS = []


def prop(name, good, why=""):
    RESULTS.append(good)
    print("  %-44s %s" % (name, "ok" if good else "FAIL  " + why))


def kaslr_on(config):
    """Is Kconfig KASLR not `n` in the expanded `config` (where available)?"""
    if not config or not os.path.exists(config):
        return False
    lines = set(open(config, encoding="utf-8", errors="replace").read().split("\n"))
    return "CONFIG_KASLR_AVAILABLE=y" in lines and "CONFIG_KASLR_NEVER=y" not in lines


def judge_kaslr(log):
    """The slide property (module doc): judged only for a KASLR build."""
    if not kaslr_on(os.environ.get("CHECK_FAST_CONFIG")):
        return
    text = read(log)
    m = re.search(r"^\[KASLR\] image slid to 0x[0-9a-f]+, \d+ bits", text, re.M)
    prop("kaslr: image slid (KASLR not n)", m is not None,
         (re.findall(r"^.*\[KASLR\].*$", text, re.M) or ["no [KASLR] line"])[0][:120])


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
        line = "canary=" + ",".join(canary_plan(a[1])[0])
        cap, src = cmdline_max(a[2] if len(a) >= 3 else None)
        if len(line) > cap - CMDLINE_MARGIN:
            print("check_fast: FAIL the %s canary command line is %d bytes, over KERNEL_CMDLINE_MAX %d (%s) "
                  "less a %d-byte margin: the kernel would cut it and disarm the canaries past the cut; "
                  "raise KERNEL_CMDLINE_MAX" % (a[1], len(line), cap, src, CMDLINE_MARGIN), file=sys.stderr)
            return 2
        print(line)
        return 0
    if len(a) < 3 or a[1] not in SETS:
        print(__doc__)
        return 2
    kind, isa, log = a[0], a[1], a[2]
    if not os.path.exists(log):
        prop("%s log" % kind, False, "no log %s" % log)
    elif kind == "ktest":
        judge_kaslr(log)
        judge_ktest(isa, log, a[3], [])
    elif kind == "canary":
        judge_ktest(isa, log, a[3], canary_plan(isa)[1])
    elif kind == "system":
        judge_kaslr(log)
        judge_system(isa, log)
    else:
        print(__doc__)
        return 2
    return 0 if RESULTS and all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

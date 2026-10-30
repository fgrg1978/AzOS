#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The clean-console judge: a QEMU row that passed also fails on a warning its console printed.

Usage: console_judge.py judge --row LABEL --allow TSV --reg REGFILE [--keep DIR]
       console_judge.py check [--allow TSV] [--rows TSV]
       console_judge.py --self-test

`judge` reads the console files REGFILE names (tools/gate/qemu_tap.py wrote
them while the row ran), prints one line per finding and exits 1 when a
warning is not allowed for ROW, 0 when the consoles are clean, 3 when they are
clean but a console file was gone (the row removed it before its verdict: not
judged), 2 on a usage or allowlist error. With --keep the first dirty console is copied there: the
row removes its own log right after its verdict.

The console has no level tag: a warning is a line saying so, in the words the
kernel uses (CLASSES). The allowlist, tools/gate/console_allow.tsv, has four
tab-separated columns: a regex the row's label must match entirely (`.*` for
every row), a class (or `*`), a regex a warning line must contain, and the
reason. A line is allowed only by an entry that names what it is; the entry of
a row says what that row provokes on purpose.
"""

import argparse
import os
import re
import shutil
import sys

CLASSES = (
    ("gave-up", r"console program .* gave up"),
    ("did-not-run", r"did not run"),
    ("not-on-volume", r"not on this volume"),
    ("lockdep", r"\blockdep\b"),
    ("warn", r"\bWARN(ING)?\b"),
    ("recovery", r"recovery fallback|falling back"),
    ("bail-out", r"Bail out!"),
)
# Lines that match a class and are not a warning: the "guest did not run" line
# is the virtio/NVMe/AHCI driver telling that the HOST stalled the guest (an
# info line that counts host load); lockdep's summary and hold table are
# reports of a clean run, and a hold over the limit is a note, not a violation.
# A TAP failure's reason is the test's verdict, which the row judges by name; a
# canary's name on its arming lines is not lockdep speaking.
NOT_WARNINGS = (
    ("did-not-run", r"\] guest did not run for \d+ ms"),
    ("did-not-run", r"^not ok \d+ - "),
    ("lockdep", r"^not ok \d+ - "),
    ("lockdep", r"^\[CANARY\] armed: "),
    ("lockdep", r"^\[CMDLINE\] canary="),
    ("lockdep", r"^\[BOOT\] cmdline: "),
    ("lockdep", r"# lockdep: violations=0 "),
    ("lockdep", r"# lockdep: hold "),
    ("lockdep", r"lockdep: .*\(note[,)]"),
)
CLASS_RE = {n: re.compile(r) for n, r in CLASSES}
NOT_RE = [(n, re.compile(r)) for n, r in NOT_WARNINGS]
DEFAULT_ALLOW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "console_allow.tsv")
DEFAULT_ROWS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate_rows.tsv")


class AllowError(Exception):
    pass


def read_allow(path):
    """[(row_re, class, line_re, reason)] of the allowlist file, or AllowError."""
    out = []
    seen = set()
    for no, line in enumerate(open(path, encoding="utf-8").read().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) != 4 or not all(x.strip() for x in f):
            raise AllowError(f"{path}:{no}: want row, class, line and reason separated by tabs, none empty")
        row, cls, text, reason = f
        if cls != "*" and cls not in CLASS_RE:
            raise AllowError(f"{path}:{no}: unknown class {cls!r} (the classes: {', '.join(CLASS_RE)}, or *)")
        try:
            out.append((re.compile(row), cls, re.compile(text), reason))
        except re.error as e:
            raise AllowError(f"{path}:{no}: bad regex: {e}") from e
        if (row, cls, text) in seen:
            raise AllowError(f"{path}:{no}: listed twice")
        seen.add((row, cls, text))
    return out


def classes_of(line):
    """The warning classes a console line belongs to."""
    hit = [n for n, r in CLASS_RE.items() if r.search(line)]
    return [n for n in hit if not any(n == m and r.search(line) for m, r in NOT_RE)]


def judge_text(text, row, allow):
    """([(class, line)] not allowed for ROW, [(class, line)] allowed, lines scanned) of one console."""
    bad, ok, n = [], [], 0
    for raw in text.replace("\0", "").replace("\r", "").split("\n"):
        n += 1
        for cls in classes_of(raw):
            if any(r.fullmatch(row) and c in ("*", cls) and t.search(raw) for r, c, t, _ in allow):
                ok.append((cls, raw))
            else:
                bad.append((cls, raw))
    return bad, ok, n


def judge(reg, row, allow_path, keep=None):
    allow = read_allow(allow_path)
    paths = []
    for p in open(reg, encoding="utf-8").read().splitlines():
        if p and p not in paths:
            paths.append(p)
    dirty = gone = 0
    for p in paths:
        try:
            text = open(p, "rb").read().decode("utf-8", errors="replace")
        except OSError as e:
            print(f"console {p}: not judged ({e.strerror})")
            gone += 1
            continue
        bad, _, n = judge_text(text, row, allow)
        if not bad:
            continue
        dirty += 1
        by = {}
        for cls, line in bad:
            by.setdefault(cls, []).append(line)
        print(f"console {p}: {len(bad)} warning line(s) not allowed for this row")
        for cls, lines in by.items():
            for line in lines[:3]:
                print(f"  [{cls}] {line.strip()[:170]}")
            if len(lines) > 3:
                print(f"  [{cls}] ... {len(lines) - 3} more")
        if keep and dirty == 1:
            os.makedirs(keep, exist_ok=True)
            slug = re.sub(r"-+", "-", re.sub(r"[^A-Za-z0-9]", "-", row)).strip("-")
            shutil.copyfile(p, os.path.join(keep, slug + ".console.log"))
    return 1 if dirty else 3 if gone else 0


def row_keys(path):
    return [l.split("\t")[0] for l in open(path, encoding="utf-8").read().splitlines() if l and not l.startswith("#")]


def check(allow_path, rows_path):
    """Every row-specific entry names a row of the gate; returns the problems."""
    allow = read_allow(allow_path)
    keys = row_keys(rows_path)
    problems = []
    for r, cls, t, _ in allow:
        if r.pattern != ".*" and not any(r.fullmatch(k) for k in keys):
            problems.append(f"{allow_path}: row pattern {r.pattern!r} matches no row of {os.path.basename(rows_path)}")
    return problems


def self_test():
    import tempfile
    fails = []

    def expect(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    def cls(line):
        return classes_of(line)

    expect("give-up", cls("[CONSOLE] console program /bin/SH.ELF gave up: recovery console (it is not on this volume)"),
           ["gave-up", "not-on-volume"])
    expect("the pending notice is not a give-up", cls("[CONSOLE] user shell pending (recovery console after 10 s without it)"), [])
    expect("a help line naming the recovery console", cls("[ROBOT] OTA:  A/B firmware slots (recovery console: ota recv/status/verify)"), [])
    expect("a fallback", cls("[OTA] both slots bad - falling back to the legacy file"), ["recovery"])
    expect("volume", cls("[DRVLAUNCH] SSHD.ELF is not on this volume -- the component manager does not start it"), ["not-on-volume"])
    expect("warning", cls("[TOPO] WARNING: no signed topology on the volume"), ["warn"])
    expect("W^X WARN", cls("[MM] W^X WARN: 3 megapage(s) unsplit"), ["warn"])
    expect("host stall is not a warning", cls("[VIRTIO-BLK] guest did not run for 812 ms: command budgets extended"), [])
    expect("other did-not-run", cls("Bail out! ktest: x panicked; tests 5.. did not run (riscv64)"), ["did-not-run", "bail-out"])
    expect("lockdep clean summary", cls("# lockdep: violations=0 notes=2 edges=9"), [])
    expect("lockdep hold table", cls("# lockdep: hold SpinLock x holds=3 max=4us"), [])
    expect("lockdep note", cls("# lockdep: SpinLock held past LOCK_MAX_HOLD_US (note); SpinLock a.rs:1 taken at b.rs:2: held 9 us, limit 5 us"), [])
    expect("lockdep note outside a test", cls("lockdep: SpinLock held past LOCK_MAX_HOLD_US (note); SpinLock a.rs:1"), [])
    expect("lockdep note with its rule", cls("# lockdep: Mutex held across a device wait (note, rule F1); Mutex a.rs:1"), [])
    expect("a ktest named after lockdep", cls("ok 9 - lockdep_boot_phase_clean"), [])
    expect("lockdep violation outside a test", cls("lockdep: sleep or device wait under a SpinLock (block I/O); SpinLock a.rs:1"), ["lockdep"])
    expect("lockdep violation", cls("# lockdep: lock order inversion; SpinLock a.rs:1"), ["lockdep"])
    expect("lockdep summary with violations", cls("# lockdep: violations=2 notes=0"), ["lockdep"])
    expect("a test's reason is its verdict", cls("not ok 44 - fat_claim # the claim owner did not run at its waiter's priority"), [])
    expect("a test's lockdep reason", cls("not ok 93 - hold_bounded # lockdep violation (the `# lockdep:` line above)"), [])
    expect("a canary's name when armed", cls("[CANARY] armed: lockdep-hold (this boot breaks its property on purpose)"), [])
    expect("a canary's name on the command line", cls("[CMDLINE] canary=lockdep-hold"), [])
    expect("x86's command line", cls("[BOOT] cmdline: canary=rcu-free-no-grace,lockdep-rcu-sleep"), [])
    expect("ordinary line", cls("[BOOT] Starting scheduler on boot CPU"), [])
    expect("no substring match on 'warning' words in lower case", cls("[NET] warning-free link"), [])

    allow_text = ("# a comment\n"
                  ".*\twarn\t\\[TOPO\\] WARNING: no signed topology\tdev volume\n"
                  "sh: gave up\tgave-up\tconsole program /bin/SH.ELF gave up\tthe row provokes it\n"
                  "sh: gave up\t*\tfalling back\tthe same line\n")
    with tempfile.TemporaryDirectory() as d:
        ap = os.path.join(d, "allow.tsv")
        open(ap, "w").write(allow_text)
        allow = read_allow(ap)
        topo = "[TOPO] WARNING: no signed topology on the volume (x)"
        give = "[CONSOLE] console program /bin/SH.ELF gave up: recovery console (no input), falling back"
        bad, ok, _ = judge_text(topo + "\n" + give + "\n", "other row", allow)
        expect("baseline allows the topology warning only", ([c for c, _ in bad], [c for c, _ in ok]),
               (["gave-up", "recovery"], ["warn"]))
        bad, ok, _ = judge_text(topo + "\n" + give + "\n", "sh: gave up", allow)
        expect("the row that provokes it", (bad, [c for c, _ in ok]), ([], ["warn", "gave-up", "recovery"]))
        bad, _, _ = judge_text(topo + "\n" + "[X] WARNING: something new\n", "sh: gave up", allow)
        expect("a new warning in the same row is not allowed", [c for c, _ in bad], ["warn"])
        bad, _, _ = judge_text("[CONSOLE] console program /bin/SH.ELF gave up: recovery console (x)", "sh: gave up extra", allow)
        expect("the row pattern must match the whole label", [c for c, _ in bad], ["gave-up"])
        bad, _, _ = judge_text("[T] WARN\x00ING and\r\n[T] WARNING: nul\x00\r\n", "r", allow)
        expect("NUL and CR are dropped", [c for c, _ in bad], ["warn", "warn"])

        for why, text in (("a short line", "a\tb\tc\n"), ("an unknown class", ".*\tnope\tx\twhy\n"),
                          ("a bad regex", "(\twarn\tx\twhy\n"), ("an empty reason", ".*\twarn\tx\t\n"),
                          ("a duplicate", ".*\twarn\tx\twhy\n.*\twarn\tx\twhy2\n")):
            bp = os.path.join(d, "bad.tsv")
            open(bp, "w").write(text)
            try:
                read_allow(bp)
                fails.append(f"{why} was not refused")
            except AllowError:
                pass

        rows = os.path.join(d, "rows.tsv")
        open(rows, "w").write("sh: gave up\tn2\tx\n")
        expect("check: known row", check(ap, rows), [])
        open(rows, "w").write("renamed row\tn2\tx\n")
        expect("check: unknown row", len(check(ap, rows)), 2)

        # The CLI end to end: a registry naming a dirty console is refused, a clean one passes.
        log = os.path.join(d, "boot.log")
        reg = os.path.join(d, "reg")
        open(reg, "w").write(log + "\n")
        open(log, "w").write("[BOOT] Starting scheduler\n")
        expect("judge: clean console", judge(reg, "other row", ap), 0)
        open(log, "w").write("[BOOT] Starting scheduler\n[X] WARNING: planted\n")
        keep = os.path.join(d, "keep")
        expect("judge: planted warning", judge(reg, "other row", ap, keep), 1)
        expect("judge: evidence kept", os.path.isfile(os.path.join(keep, "other-row.console.log")), True)
        os.unlink(log)
        expect("judge: a vanished console is reported, not passed as judged", judge(reg, "other row", ap), 3)
    for f in fails:
        print("FAIL " + f)
    print(f"console_judge self-test: {'FAIL' if fails else 'ok'}")
    return 1 if fails else 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("judge")
    j.add_argument("--row", required=True)
    j.add_argument("--allow", default=DEFAULT_ALLOW)
    j.add_argument("--reg", required=True)
    j.add_argument("--keep")
    c = sub.add_parser("check")
    c.add_argument("--allow", default=DEFAULT_ALLOW)
    c.add_argument("--rows", default=DEFAULT_ROWS)
    a = ap.parse_args()
    try:
        if a.cmd == "judge":
            return judge(a.reg, a.row, a.allow, a.keep)
        problems = check(a.allow, a.rows)
    except AllowError as e:
        print(e)
        return 2
    for p in problems:
        print(p)
    print(f"console allowlist: {'FAIL' if problems else 'ok'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""What went red, in at most 40 lines per row.

  triage.py LOG [LOG ...]              a ci_check log (its `  <row>...  FAIL` blocks) or a row's console log
  triage.py --row LABEL --logdir DIR   one red row of a run, from the logs it kept in DIR
  triage.py ... --out FILE             write there too

Per red row: the name, the first failing assertion (`not ok`, `Bail out!`, or the
first detail line the gate printed), a panic with its backtrace symbolized against
the kernel ELF the row kept (tools/dev/symbolize_bt.py), the last 15 console lines
before the failure, the memory admission line, and the command that reruns only that
row. A log the row kept but that is gone, or an ELF that was not kept, is said
once, and the rest is read from what the gate printed.
"""
import argparse
import glob
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SYMBOLIZE = os.path.join(HERE, "../dev/symbolize_bt.py")
MAX_LINES = 40
TAIL = 15

ROW_RE = re.compile(r"^  (\S.*?)\.\.\.\s*FAIL\s*$")
FAILURE_RE = re.compile(r"^(?:not ok \d+ - |Bail out!|\[ABITEST\]\s+FAIL\b|KERNEL PANIC|\[PANIC\]|\[FATAL\]|.*\bpanicked at\b)")
BACKTRACE_RE = re.compile(r"\[PANIC\] backtrace:")
MEM_RE = re.compile(r"kernel reserve = \d+ of \d+ free pages")


def red_rows(text):
    """[(label, detail lines)] of a gate log: the block of indented lines under each FAIL."""
    rows, cur = [], None
    for line in text.replace("\r", "").split("\n"):
        m = ROW_RE.match(line)
        if m:
            cur = (m.group(1).strip(), [])
            rows.append(cur)
        elif cur is not None and line.startswith("      "):
            cur[1].append(line.strip())
        else:
            cur = None
    return rows


def tag_of(label):
    return re.sub(r"[^A-Za-z0-9]", "-", label)


def kept(details, key):
    for d in details:
        m = re.match(r"%s kept: (\S+)" % key, d) or re.search(r"%s kept: (\S+)" % key, d)
        if m:
            return m.group(1)
    return None


def find_logs(label, logdir):
    """(row log, kernel ELF) the run kept in logdir for this row, either may be None."""
    tag = tag_of(label)
    logs = [p for p in glob.glob(os.path.join(logdir, "*%s*.log" % tag)) if os.path.basename(p).startswith(("ktest-", tag, "x86-", "aarch64-")) or tag in os.path.basename(p)]
    elfs = [p for p in glob.glob(os.path.join(logdir, "kernel-*%s*" % tag)) if not p.endswith(".features")]
    elfs.sort(key=lambda p: not p.endswith(".elf"))
    return (sorted(logs)[0] if logs else None), (elfs[0] if elfs else None)


def first_failure(lines):
    for i, l in enumerate(lines):
        if FAILURE_RE.match(l.strip()) or FAILURE_RE.match(l):
            return i
    return None


def symbolize(elf, lines):
    if not elf or not os.path.isfile(elf):
        return ["(no kernel ELF kept%s: the backtrace stays as numbers)" % (" at " + elf if elf else "")]
    r = subprocess.run([sys.executable, SYMBOLIZE, elf], input="\n".join(lines) + "\n", capture_output=True, text=True)
    out = [l for l in (r.stdout + r.stderr).splitlines() if l.strip()]
    return out[:8] or ["(symbolize_bt printed nothing)"]


def triage_row(label, details, logpath, elfpath, logdir=None):
    out = ["== %s ==" % label]
    log_lines = None
    if logpath and os.path.isfile(logpath):
        with open(logpath, encoding="utf-8", errors="replace") as fh:
            log_lines = fh.read().replace("\r", "").split("\n")
    elif logpath:
        out.append("row log not found: %s (read from what the gate printed)" % logpath)
    fail_at = first_failure(log_lines) if log_lines is not None else None
    if fail_at is not None:
        out.append("first failure: " + log_lines[fail_at].strip()[:200])
    elif details:
        first = next((d for d in details if re.match(r"not ok \d+ - |Bail out!|\[ABITEST\]|FAIL\b", d)), details[0])
        out.append("first failure: " + first[:200])
    else:
        out.append("first failure: none found in the log")
    extra = [d for d in details if not d.startswith(("log kept:", "kernel kept:"))]
    if fail_at is not None and extra:
        out.append("gate said: " + extra[0][:200])
    elif len(extra) > 1:
        out += ["  " + d[:200] for d in extra[1:4]]
    if log_lines is not None:
        pan = next((i for i, l in enumerate(log_lines) if "KERNEL PANIC" in l or "[PANIC]" in l or "panicked at" in l), None)
        if pan is not None:
            out.append("panic: " + log_lines[pan].strip()[:200])
            bt = [l for l in log_lines[pan:pan + 40] if BACKTRACE_RE.search(l)]
            out += ["  " + s for s in (symbolize(elfpath, log_lines[: pan + 40] if bt else []) if bt else ["(no [PANIC] backtrace line: Kconfig PROFILER off?)"])]
        end = fail_at if fail_at is not None else len(log_lines)
        tail = [l for l in log_lines[:end] if l.strip()][-TAIL:]
        out.append("last %d lines before it:" % len(tail))
        out += ["  | " + l[:160] for l in tail]
        mem = next((m.group(0) for l in log_lines for m in [MEM_RE.search(l)] if m), None)
        out.append("memory admission: " + (mem or "no line in the log"))
    else:
        mem = next((m.group(0) for d in details for m in [MEM_RE.search(d)] if m), None)
        out.append("memory admission: " + (mem or "no log to read it from"))
    out.append('rerun: CI_TIER=rows CI_ROWS="%s" CI_JOBS=1 bash tools/gate/ci_check.sh' % label)
    if len(out) > MAX_LINES:
        keep = MAX_LINES - 2
        out = out[: keep - TAIL - 1] + ["  ..."] + out[-(TAIL + 1):]
        out = out[:MAX_LINES]
    return out


def triage_text(text, name="log", logdir=None):
    rows = red_rows(text)
    if rows:
        res = []
        for label, details in rows:
            logp, elfp = kept(details, "log"), kept(details, "kernel")
            if not logp and logdir:
                logp, _ = find_logs(label, logdir)
            if not elfp and logdir:
                _, elfp = find_logs(label, logdir)
            res.append(triage_row(label, details, logp, elfp))
        return res
    # A console log of one row.
    lines = text.replace("\r", "").split("\n")
    if first_failure(lines) is None:
        return [["== %s ==" % name, "no red row and no failure line in this log"]]
    return [triage_console(name, lines)]


def triage_console(name, lines, elf=None):
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write("\n".join(lines))
    try:
        return triage_row(name, [], fh.name, elf)
    finally:
        os.unlink(fh.name)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="*")
    ap.add_argument("--row")
    ap.add_argument("--logdir")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    blocks = []
    if a.row:
        logp, elfp = find_logs(a.row, a.logdir or ".")
        blocks.append(triage_row(a.row, [], logp, elfp))
    for p in a.logs:
        with open(p, encoding="utf-8", errors="replace") as fh:
            blocks += triage_text(fh.read(), os.path.basename(p), a.logdir)
    text = "\n".join("\n".join(b) for b in blocks)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0 if blocks else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Lint: every aarch64 QEMU line of the gate goes through tools/gate/qemu_a64.py.

The accelerator of an arm row is chosen in one place (HVF where the host has it,
TCG where the row needs it: tools/gate/qemu_a64.py). A row that names
`qemu-system-aarch64` itself runs under TCG whatever the host offers, which is
how 111 of 112 rows ran. So:

  * no gate script (tools/gate/ci_check.sh, tools/gate/*.sh, *.py) names
    `qemu-system-aarch64` outside a comment (the helper and the PATH tap, which
    work by that name, are the two files that may);
  * the rows that need CPU features the host lacks carry the `--tcg` tag:
    TAGGED lists the functions, and each must start QEMU through the helper with
    that tag on every line;
  * the helper's decision is what the table in TABLE says, so a row that gives
    `-icount`, a `virtualization=on` machine, a raspi machine, a CPU model other
    than `max`, or a counter frequency cannot be put on HVF.

  qemu_accel_lint.py              check the tree (exit 1 on a finding)
  qemu_accel_lint.py --self-test  canaries: a planted bare line, an untagged
                                  feature row and a wrong table entry must each
                                  be found
"""

import glob
import os
import re
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
HELPER = "tools/gate/qemu_a64.py"
NAMES_QEMU = {HELPER, "tools/gate/qemu_tap.py", "tools/lint/qemu_accel_lint.py"}

# Functions of tools/gate/ci_check.sh whose arm QEMU lines need TCG for the CPU
# features they test: the ktests (PAC, BTI, MTE, POE, GCS), the 64 KiB granule
# (Apple cores have none), the ID-register probe.
TAGGED = ("ktest_row", "aarch64_granule_row", "cpuid_probe_row")

# (argument line, accelerator under ACCEL=auto on a host with HVF)
TABLE = [
    ("-M virt,gic-version=3 -cpu max,pauth=on -smp 2", "hvf"),
    ("-M virt,gic-version=3,iommu=smmuv3 -cpu max,pauth=on", "hvf"),
    ("-M virt,virtualization=on,gic-version=3 -cpu max,pauth=on", "tcg"),
    ("-M virt,gic-version=3 -cpu max,pauth=on -icount shift=0,sleep=off", "tcg"),
    ("-M virt,gic-version=3 -cpu cortex-a76", "tcg"),
    ("-M virt,gic-version=3 -cpu max,pauth=on,cntfrq=19200000", "tcg"),
    ("-M raspi3b -kernel k", "tcg"),
    ("--tcg -M virt,gic-version=3 -cpu max,pauth=on", "tcg"),
]


def code_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            if not line.lstrip().startswith("#"):
                yield n, line.rstrip("\n")


def bare_names(files):
    """Lines that name qemu-system-aarch64 where a row should name the helper."""
    out = []
    for rel, text in files:
        if rel in NAMES_QEMU:
            continue
        for n, line in text:
            if "qemu-system-aarch64" in line:
                out.append(f"{rel}:{n}: {line.strip()[:100]}")
    return out


def functions(text):
    """{name: [lines]} of the shell functions of one file (to the next one)."""
    out, cur = {}, None
    for n, line in text:
        m = re.match(r"^\s*([A-Za-z0-9_]+)\(\)\s*\{", line)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
        if cur:
            out[cur].append(line)
    return out


def untagged(text):
    """Feature rows whose helper lines lack --tcg, and rows that do not exist."""
    fns = functions(text)
    out = []
    for name in TAGGED:
        body = fns.get(name)
        if body is None:
            out.append(f"{name}: no such function in tools/gate/ci_check.sh (TAGGED is stale)")
            continue
        starts = [l for l in body if "$QEMU_A64" in l and "$QEMU_A64_RV" not in l and "QEMU_A64=" not in l]
        if not starts:
            out.append(f"{name}: starts no aarch64 QEMU through $QEMU_A64")
        out += [f"{name}: {l.strip()[:90]} lacks --tcg" for l in starts if "--tcg" not in l]
    return out


def table_errors(accel_hvf="1"):
    env = dict(os.environ, AZOS_HVF_OK=accel_hvf, ACCEL="auto")
    bad = []
    for args, want in TABLE:
        got = subprocess.run([sys.executable, os.path.join(ROOT, HELPER), "--classify", *args.split()],
                             capture_output=True, text=True, env=env).stdout.split()[:1]
        if got != [want]:
            bad.append(f"{args!r}: {got} (wanted {want})")
    return bad


def load():
    files = []
    for pat in ("tools/gate/*.sh", "tools/gate/*.py"):
        for path in sorted(glob.glob(os.path.join(ROOT, pat))):
            files.append((os.path.relpath(path, ROOT), list(code_lines(path))))
    return files


def check():
    files = load()
    text = dict(files)["tools/gate/ci_check.sh"]
    out = bare_names(files) + untagged(text) + table_errors()
    if "$QEMU_A64" not in " ".join(l for _, l in text):
        out.append("ci_check.sh never names $QEMU_A64")
    return out


def self_test():
    bad = []
    planted = [("planted.sh", [(1, "    qemu-system-aarch64 -M virt -cpu max -kernel k &")])]
    if not bare_names(planted):
        bad.append("a bare qemu-system-aarch64 line was not found")
    if bare_names([("planted.sh", [(1, '    "$QEMU_A64" -M virt -cpu max -kernel k &')])]):
        bad.append("a line through the helper was flagged")
    fn = [(1, "ktest_row() {"), (2, '    "$QEMU_A64" -M virt -cpu max -kernel k &'), (3, "}")]
    if untagged(fn + [(4, "aarch64_granule_row() {"), (5, '    "$QEMU_A64" --tcg -M virt &'), (6, "}"),
                      (7, "cpuid_probe_row() {"), (8, '    "$QEMU_A64" --tcg -M virt &'), (9, "}")]) != [
            'ktest_row: "$QEMU_A64" -M virt -cpu max -kernel k & lacks --tcg']:
        bad.append("an untagged feature row was not the one finding")
    saved = list(TABLE)
    try:
        TABLE[0] = (TABLE[0][0], "tcg")
        if not table_errors():
            bad.append("a wrong table entry was not found")
    finally:
        TABLE[:] = saved
    if table_errors("0") == []:
        bad.append("with no HVF on the host the table still holds: the probe is not read")
    return bad


def main(argv):
    if "--self-test" in argv:
        bad = self_test()
        for b in bad:
            print(f"qemu_accel_lint self-test: {b}")
        return 1 if bad else 0
    out = check()
    for o in out:
        print(f"qemu_accel_lint: {o}")
    return 1 if out else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Lint: no `allow(dead_code)` in the kernel without a written reason.

Owner rule: no dead code; every mechanism has a real user. An unconditional
`#[allow(dead_code)]` (or `#![allow(dead_code)]`, or `allow(unused)`, the
lint group that contains it) silences the one check that finds code nothing
calls, on every ISA and every feature set at once, and it outlives the reason
it was added for.

Rule. Under `kernel/` and `crates/core/`, an `allow` attribute whose list
names `dead_code` or `unused` needs a `// reason: <why>` comment on its own
line or in the comment/attribute block right above it: the written case that
a real user exists where the compiler cannot see it (a symbol named only in
an asm string, a source file shared by `#[path]` with another crate).
Code used on one ISA or under one feature gets that `cfg` instead, or a
`cfg_attr(<the cfg>, allow(dead_code))`, which states its condition to the
compiler and is not counted here.

No baseline: every site in the tree carries its reason.

  python3 tools/lint/dead_code_lint.py               check (n0)
  python3 tools/lint/dead_code_lint.py --self-test   the lint's own canaries
"""
import os
import re
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
SCOPES = ("kernel", os.path.join("crates", "core"))
MARK = "reason:"
# `#[allow(...)]` / `#![allow(...)]`, the list possibly over several lines.
ALLOW = re.compile(r"#!?\[\s*allow\s*\(([^)]*)\)\s*\]", re.S)
NAMES = ("dead_code", "unused")


def findings_in(text):
    """[line numbers] of unjustified dead-code allows in one source."""
    lines = text.split("\n")
    out = []
    for m in ALLOW.finditer(text):
        names = [n.strip() for n in m.group(1).split(",")]
        if not any(n in NAMES for n in names):
            continue
        start = text.rfind("\n", 0, m.start()) + 1
        if "//" in text[start:m.start()]:
            continue  # inside a comment (a doc naming the attribute)
        ln = text.count("\n", 0, m.start())
        eol = text.find("\n", m.end())
        tail = text[m.end():eol if eol >= 0 else len(text)]
        if "//" in tail and MARK in tail.split("//", 1)[1]:
            continue
        ok = False
        i = ln - 1
        while i >= 0:
            s = lines[i].strip()
            if s.startswith("//"):
                if MARK in s:
                    ok = True
                    break
            elif not s.startswith("#["):
                break
            i -= 1
        if not ok:
            out.append(ln + 1)
    return out


def scan(root):
    """[(path, line)] over the scoped trees under `root`."""
    out = []
    for scope in SCOPES:
        base = os.path.join(root, scope)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in ("target", ".git"))
            for name in sorted(filenames):
                if not name.endswith(".rs"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    text = f.read()
                for ln in findings_in(text):
                    out.append((os.path.relpath(path, root), ln))
    return out


def self_test():
    cases = (
        ("#[allow(dead_code)]\nfn a() {}\n", 1, "a bare allow passes"),
        ("#![allow(dead_code)]\n", 1, "a bare inner allow passes"),
        ("#[allow(unused)]\nfn a() {}\n", 1, "a bare allow(unused) passes"),
        ("#[allow(\n    dead_code,\n)]\nfn a() {}\n", 1, "a multi-line allow passes"),
        ("#[allow(unused_mut, dead_code)]\nfn a() {}\n", 1, "dead_code in a list passes"),
        ("// reason: x\n\n#[allow(dead_code)]\nfn a() {}\n", 1, "a reason past a blank line counts"),
        ("// some comment\n#[allow(dead_code)] // no why\nfn a() {}\n", 1, "a comment without the mark counts"),
        ("// reason: named in global_asm!\n#[allow(dead_code)]\nfn a() {}\n", 0, "a reason above is refused"),
        ("#[allow(dead_code)] // reason: x\nfn a() {}\n", 0, "a trailing reason is refused"),
        ("/// doc\n// reason: x\n#[inline]\n#[allow(dead_code)]\nfn a() {}\n", 0, "a reason above another attribute is refused"),
        ("#[cfg_attr(not(feature = \"x\"), allow(dead_code))]\nfn a() {}\n", 0, "a cfg_attr allow is counted"),
        ("#[allow(unused_mut)]\nfn a() {}\n", 0, "allow(unused_mut) is counted"),
        ("/// `#[allow(dead_code)]` in a doc\nfn a() {}\n", 0, "a doc naming the attribute is counted"),
    )
    ok = True
    for text, want, what in cases:
        got = len(findings_in(text))
        if got != want:
            ok = False
            print(f"self-test FAIL: {what} (got {got} findings, want {want})")
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "kernel", "src"))
        os.makedirs(os.path.join(root, "crates", "core", "x", "src"))
        os.makedirs(os.path.join(root, "crates", "drivers", "y", "src"))
        for rel in ("kernel/src/a.rs", "crates/core/x/src/b.rs", "crates/drivers/y/src/c.rs"):
            with open(os.path.join(root, rel), "w") as f:
                f.write("#[allow(dead_code)]\nfn a() {}\n")
        got = sorted(p for p, _ in scan(root))
        want = ["crates/core/x/src/b.rs", "kernel/src/a.rs"]
        if got != want:
            ok = False
            print(f"self-test FAIL: scope is kernel/ and crates/core/ (got {got})")
    if ok:
        print("dead_code_lint self-test: ok")
    return 0 if ok else 1


def main(argv):
    if "--self-test" in argv:
        return self_test()
    found = scan(ROOT)
    for path, ln in found:
        print(f"{path}:{ln}: allow(dead_code) without a `// {MARK}` comment "
              "(delete the dead code, cfg it, or say who uses it)")
    if found:
        print(f"dead_code_lint: {len(found)} unjustified allow(s)")
        return 1
    print("dead_code_lint: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

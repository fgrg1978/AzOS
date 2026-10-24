#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Regenerate the option index ("Option index" table) of the configuration
guide, Documentation/config.md, or print it.

Usage: python3 tools/build/gen_config_index.py [--check | --list | --self-test]

Reads the Kconfig tree with kconfiglib (the root `Kconfig` and every topic file
it sources) and writes one row per declared symbol, sorted by name: the
symbol, the file that declares it, and its prompt text, or "(no prompt —
internal/derived)" for a promptless one. It also rewrites the option count in
the sentence above the table. Nothing else in the document is touched.

--check      exit 1 if the document is out of date; write nothing.
--list       print the table to stdout.
--self-test  --check on a document in a temporary directory: a current one
             passes, a missing row, a stale prompt or a stale count fails,
             and the regenerated one passes again (the lint tier runs it).
"""

import os
import re
import sys
import tempfile

import kconfiglib

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
DOC = os.path.join(REPO, "Documentation", "config.md")
HEADER = "| Option | File | Description |"
RULE = "|--------|------|-------------|"
COUNT_RE = re.compile(r"The index lists every declared option: \d+\.")


def rows():
    old = os.getcwd()
    os.chdir(REPO)
    try:
        kconf = kconfiglib.Kconfig("Kconfig", warn=False)
    finally:
        os.chdir(old)
    out = []
    for sym in kconf.unique_defined_syms:
        node = sym.nodes[0]
        prompt = next((n.prompt[0] for n in sym.nodes if n.prompt), None)
        desc = prompt if prompt else "(no prompt — internal/derived)"
        # config/Kconfig.userspace is generated at every parse (gitignored):
        # its symbols name the generator, a file the checkout has.
        where = node.filename
        if where.endswith("Kconfig.userspace"):
            where = "tools/build/gen_userspace_kconfig.py"
        out.append((sym.name, f"| `{sym.name}` | `{where}` | {desc} |"))
    out.sort(key=lambda r: r[0])
    return [r[1] for r in out]


def count_sentence(n):
    """The sentence above the table, with its option count (one spelling,
    which render() and the self-test share)."""
    return f"The index lists every declared option: {n}."


def render(text):
    lines = text.split("\n")
    start = lines.index(HEADER)
    assert lines[start + 1] == RULE, "unexpected table rule line"
    end = start + 2
    while end < len(lines) and lines[end].startswith("| `"):
        end += 1
    table = rows()
    new = lines[: start + 2] + table + lines[end:]
    body = "\n".join(new)
    body, n = COUNT_RE.subn(count_sentence(len(table)), body)
    assert n == 1, "count sentence not found"
    return body


def check(doc, quiet=False):
    with open(doc, encoding="utf-8") as f:
        text = f.read()
    if render(text) != text:
        if not quiet:
            print(f"{doc}: option index is out of date: run python3 tools/build/gen_config_index.py")
        return 1
    return 0


def self_test():
    table = rows()
    fails = []
    good = "\n".join(["# Guide", "", count_sentence(len(table)), "", HEADER, RULE] + table + ["", "After."]) + "\n"
    cases = (("current", good, 0),
             ("a row missing", good.replace(table[0] + "\n", "", 1), 1),
             ("a stale prompt", good.replace(table[-1], table[-1][:-2] + "x |", 1), 1),
             ("a stale count", good.replace(count_sentence(len(table)), count_sentence(1), 1), 1))
    with tempfile.TemporaryDirectory() as d:
        doc = os.path.join(d, "config.md")
        for name, text, want in cases:
            with open(doc, "w", encoding="utf-8") as f:
                f.write(text)
            got = check(doc, quiet=True)
            if got != want:
                fails.append(f"{name}: --check exit {got}, want {want}")
            if want:
                with open(doc, "w", encoding="utf-8") as f:
                    f.write(render(text))
                if check(doc, quiet=True) != 0:
                    fails.append(f"{name}: still out of date after regeneration")
    if fails:
        print("gen_config_index self-test FAILED:\n  " + "\n  ".join(fails))
        return 1
    print(f"gen_config_index self-test ok ({len(table)} options)")
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()
    if "--list" in sys.argv:
        print("\n".join([HEADER, RULE] + rows()))
        return 0
    doc = DOC
    if "--check" in sys.argv:
        return check(doc)
    with open(doc, encoding="utf-8") as f:
        text = f.read()
    new = render(text)
    if new != text:
        with open(doc, "w", encoding="utf-8") as f:
            f.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())

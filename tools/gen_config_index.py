#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Regenerate the option index ("Option index" table) of the configuration
guide, Documentation/config.md, or print it.

Usage: python3 tools/gen_config_index.py [--check | --list]

Reads the Kconfig tree with kconfiglib (the root `Kconfig` and every topic file
it sources) and writes one row per declared symbol, sorted by name: the
symbol, the file that declares it, and its prompt text, or "(no prompt —
internal/derived)" for a promptless one. It also rewrites the option count in
the sentence above the table. Nothing else in the document is touched.

--check  exit 1 if the document is out of date; write nothing.
--list   print the table to stdout.
"""

import os
import re
import sys

import kconfiglib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
        out.append((sym.name, f"| `{sym.name}` | `{node.filename}` | {desc} |"))
    out.sort(key=lambda r: r[0])
    return [r[1] for r in out]


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
    body, n = COUNT_RE.subn(f"The index lists every declared option: {len(table)}.", body)
    assert n == 1, "count sentence not found"
    return body


def main():
    if "--list" in sys.argv:
        print("\n".join([HEADER, RULE] + rows()))
        return 0
    doc = DOC
    with open(doc, encoding="utf-8") as f:
        text = f.read()
    new = render(text)
    if "--check" in sys.argv:
        if new != text:
            print(f"{doc}: option index is out of date: run python3 tools/gen_config_index.py")
            return 1
        return 0
    if new != text:
        with open(doc, "w", encoding="utf-8") as f:
            f.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())

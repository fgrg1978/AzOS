#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Regenerate the Kconfig option index ("Reference index" table) of the
configuration guide, or print it.

Usage: python3 tools/gen_config_index.py [--check | --list]

The guide is not part of the public tree. Its path is taken from
$AZOS_CONFIG_DOC, else the first of docs/CONFIG.md and rfcs/CONFIG.md that
exists (both are gitignored: kept locally, not published).
With no guide present, --check still parses the whole Kconfig tree (a
parse error or a symbol with no declaration fails it) and reports that the
document comparison was skipped; --list prints the table to stdout.

Reads the Kconfig tree with kconfiglib (the root `Kconfig` and every fragment
it sources) and writes one row per declared symbol, sorted by name: the
symbol, the fragment that declares it, and its prompt text, or "(no prompt —
internal/derived)" for a promptless one. It also rewrites the option count in
the paragraph above the table. Nothing else in the document is touched.

--check  exit 1 if the document is out of date; write nothing.
"""

import os
import re
import sys

import kconfiglib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_CANDIDATES = [
    os.path.join(REPO, "docs", "CONFIG.md"),
    os.path.join(REPO, "rfcs", "CONFIG.md"),
]


def find_doc():
    env = os.environ.get("AZOS_CONFIG_DOC")
    if env:
        return env
    for path in DOC_CANDIDATES:
        if os.path.exists(path):
            return path
    return None
HEADER = "| Option | Fragment | Description |"
RULE = "|--------|----------|-------------|"
COUNT_RE = re.compile(r"This index is now the FULL list — \d+ options")


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
    body, n = COUNT_RE.subn(f"This index is now the FULL list — {len(table)} options", body)
    assert n == 1, "count sentence not found"
    return body


def main():
    if "--list" in sys.argv:
        print("\n".join([HEADER, RULE] + rows()))
        return 0
    doc = find_doc()
    if doc is None:
        table = rows()
        if not table:
            print("gen_config_index: the Kconfig tree declares no symbols")
            return 1
        if "--check" in sys.argv:
            print(f"gen_config_index: Kconfig parsed, {len(table)} options; "
                  "no configuration guide present, document comparison skipped")
            return 0
        print("gen_config_index: no configuration guide found "
              "(set AZOS_CONFIG_DOC); use --list to print the table")
        return 1
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

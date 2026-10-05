#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Every host binary of a chip-logic crate carries that crate's source.

Wave 12 (DRVPLACE "same source"). A chip crate (crates/drivers/<name>) is
written once and hosted twice, in ring 3 and in the kernel. Its build script
(crates/drivers/chip_source.rs) hashes its src/ and generates the marker
`AZOS-CHIP-SRC <name> <16 hex>`, which each host prints at start and so
carries in its binary. This script hashes the same src/ in the tree, the same
way, and requires every binary given to carry exactly that marker: a host
that stopped linking the crate (the logic copied into it, or forked) carries
none, and one built from other source carries another value.

Usage: chip_source_check.py <name> <binary>...    exit 0 = all agree
       chip_source_check.py --hash <name>         print the tree's marker
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tree_hash(name):
    src = os.path.join(ROOT, "crates", "drivers", name, "src")
    files = []
    for d, _, fs in os.walk(src):
        for f in fs:
            p = os.path.join(d, f)
            files.append((os.path.relpath(p, src).replace(os.sep, "/").encode(), p))
    files.sort(key=lambda t: t[0])
    h = 0xCBF29CE484222325
    def eat(bs):
        nonlocal h
        for b in bs:
            h ^= b
            h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    for rel, p in files:
        eat(rel); eat(b"\0")
        with open(p, "rb") as fh:
            eat(fh.read())
        eat(b"\0")
    return "%016x" % h


def main(argv):
    if len(argv) == 3 and argv[1] == "--hash":
        print("AZOS-CHIP-SRC %s %s" % (argv[2], tree_hash(argv[2])))
        return 0
    if len(argv) < 3:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    name, bins = argv[1], argv[2:]
    want = tree_hash(name)
    pat = re.compile(rb"AZOS-CHIP-SRC " + re.escape(name.encode()) + rb" ([0-9a-f]{16})")
    bad = 0
    for b in bins:
        with open(b, "rb") as fh:
            found = sorted({m.group(1).decode() for m in pat.finditer(fh.read())})
        if found != [want]:
            what = "no marker" if not found else "marker " + ", ".join(found)
            print("chip_source_check: %s carries %s; the %s source in the tree is %s"
                  % (b, what, name, want), file=sys.stderr)
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

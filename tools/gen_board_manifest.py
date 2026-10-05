#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""gen_board_manifest.py — RFC-0005 board ELF derivation, owner decision 2026-09-24.

Turns the topology's declared board services into the NAME=path manifest the
board disk-image recipe mcopies. "An ELF ships on a BOARD's FAT32 volume iff
the topology declares a service that ELF provides" — this script is the only
place that rule is applied; nothing else picks the board ELF list.

The declared names come from `tests/host/topology-tests`'s `board_elfs` binary
(built with NO topology feature on, matching a board build — see that
binary's own doc comment). `crates/core/topology/src/builder.rs` is the single
source of truth: every unconditional `TaskSpec` row whose name ends `.ELF`.

Usage:
    python3 tools/gen_board_manifest.py <board_elfs.list> NAME=path ...

<board_elfs.list> is the `board_elfs` binary's stdout, one declared service
name per line (Makefile's `build/board_elfs.list` target produces it). The
NAME=path pairs are the Makefile's `IMAGE_ELFS` — every ELF name and build
path this tree knows how to build, board-shipped or not.

Fails (exit 1, message on stderr) if the topology declares a service with no
matching build path — an ORPHAN SERVICE: the topology names an ELF nothing
in the tree builds. Never silently drops it and never silently picks the old
hand-maintained list instead.

On success, prints "NAME=path" for the board's manifest, one line per
declared service, to stdout, for the Makefile recipe to mcopy.
"""

import sys


def compute_manifest(declared, available):
    """Compute the board manifest and any orphan services.

    declared: list[str] of topology-declared ELF names, in the order the
        topology emitted them (already deduplicated by the caller if it
        matters — this function also dedupes defensively).
    available: dict[str, str] mapping an ELF name to its build path, i.e.
        every name the Makefile's IMAGE_ELFS knows how to build.

    Returns (manifest, orphan_services):
        manifest: list[(name, path)] — the board's actual ship list.
        orphan_services: list[str] — declared names with no build path.
    """
    manifest = []
    orphans = []
    seen = set()
    for name in declared:
        if name in seen:
            continue
        seen.add(name)
        if name in available:
            manifest.append((name, available[name]))
        else:
            orphans.append(name)
    return manifest, orphans


def parse_pairs(pairs):
    available = {}
    for pair in pairs:
        name, sep, path = pair.partition("=")
        if not sep or not name or not path:
            sys.exit(f"gen_board_manifest.py: expected NAME=path, got {pair!r}")
        available[name] = path
    return available


def main(argv):
    if len(argv) < 2:
        sys.exit("usage: gen_board_manifest.py <board_elfs.list> NAME=path ...")
    list_path = argv[1]
    available = parse_pairs(argv[2:])

    with open(list_path, encoding="utf-8") as f:
        declared = [line.strip() for line in f if line.strip()]

    if not declared:
        sys.exit(
            "gen_board_manifest.py: the topology declares ZERO board "
            f"services ({list_path} is empty) — a board volume with no "
            "ELFs on it is certainly wrong; check "
            "crates/core/topology/src/builder.rs's board service registry."
        )

    manifest, orphans = compute_manifest(declared, available)
    if orphans:
        sys.exit(
            "gen_board_manifest.py: ORPHAN SERVICE — the topology declares "
            + ", ".join(sorted(orphans))
            + " but no Makefile recipe builds an ELF under that name "
            "(checked against IMAGE_ELFS). Add a build rule for it, or "
            "remove the topology row in crates/core/topology/src/builder.rs."
        )

    for name, path in manifest:
        print(f"{name}={path}")


if __name__ == "__main__":
    main(sys.argv)

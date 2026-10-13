#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""check_board_disk.py — post-build anti-drift gate for the board disk image.

Owner decision 2026-09-24: the build must FAIL if the volume and the
topology disagree, not silently pick one. `gen_board_manifest.py` derives
what SHOULD be on the disk from the topology; this script checks what
ACTUALLY landed there, by reading the FAT32 image back with `mdir` instead
of trusting the recipe that built it. That catches drift no matter how it
was introduced — a hand-added `mcopy` line, a stale manifest, a skipped
rebuild — not just drift this script's own generator could have caused.

Usage:
    python3 tools/check_board_disk.py <disk.img> <manifest.txt>

<manifest.txt> is gen_board_manifest.py's "NAME=path" output — the
topology-declared board manifest. Exits 1, naming both offending sets, if:
  - an ELF is on the disk image that the manifest does not declare
    (ORPHAN ELF — ships with no providing topology entry), or
  - the manifest declares a name that is not on the disk image
    (ORPHAN SERVICE — declared, but never actually shipped).
"""

import subprocess
import sys


def parse_mdir_elf_names(mdir_output):
    """Extract `.ELF` FAT32 8.3 names from `mdir -i disk.img ::` output.

    `mdir` prints one directory entry per line with the name in the first
    column (`-b` would print bare names only, but the default columnar
    output already has the name first and every other column is numeric or
    a date, so filtering tokens by the `.ELF` suffix is unambiguous).
    """
    names = set()
    for line in mdir_output.splitlines():
        for tok in line.split():
            if tok.endswith(".ELF"):
                names.add(tok)
    return names


def diff(disk_names, declared_names):
    """Returns (orphan_elfs, orphan_services), both sorted lists."""
    orphan_elfs = sorted(disk_names - declared_names)
    orphan_services = sorted(declared_names - disk_names)
    return orphan_elfs, orphan_services


def read_manifest_names(manifest_path):
    with open(manifest_path, encoding="utf-8") as f:
        return {line.partition("=")[0] for line in f if line.strip()}


def main(argv):
    if len(argv) != 3:
        sys.exit("usage: check_board_disk.py <disk.img> <manifest.txt>")
    disk_path, manifest_path = argv[1], argv[2]

    declared_names = read_manifest_names(manifest_path)
    result = subprocess.run(
        ["mdir", "-i", disk_path, "::"], capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.exit(
            f"check_board_disk.py: `mdir -i {disk_path} ::` failed:\n{result.stderr}"
        )
    disk_names = parse_mdir_elf_names(result.stdout)

    orphan_elfs, orphan_services = diff(disk_names, declared_names)
    if orphan_elfs or orphan_services:
        msg = ["check_board_disk.py: the board volume and the topology disagree."]
        if orphan_elfs:
            msg.append(
                f"  ORPHAN ELF on {disk_path} with no providing topology entry: "
                + ", ".join(orphan_elfs)
            )
        if orphan_services:
            msg.append(
                f"  ORPHAN SERVICE declared by the topology with no ELF on {disk_path}: "
                + ", ".join(orphan_services)
            )
        sys.exit("\n".join(msg))

    print(
        f"[BOARD] {disk_path} matches the topology-declared manifest "
        f"({len(declared_names)} ELFs)"
    )


if __name__ == "__main__":
    main(sys.argv)

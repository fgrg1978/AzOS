#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""seed_provision.py — write or read the persisted entropy seed on a disk image.

The kernel keeps a persisted entropy seed in a reserved sector past the end of
the FAT32 volume (`kernel/src/msc_gadget.rs`: the last MSC_RESERVED_TAIL_SECTORS
= 8 sectors of the medium; `RESERVED_SECTOR_ENTROPY_SEED` = 1 is the sector this
tool touches). At every boot it mixes that seed into the entropy pool and
replaces it with fresh pool output. A board with no entropy device has no other
source, so its first seed has to be put there once, from the host:

    tools/seed_provision.py build/disk.img            # random seed, new record
    tools/seed_provision.py --show build/disk.img     # print what is stored

`--show` prints `valid <sha256 of the seed bytes>` or `absent`, so two reads of
the same image can be compared without printing the seed itself.

Record format (one sector; see `crates/core/crypto/src/entropy.rs`):
    0   4   magic "SEED"
    4   1   version 1
    5  64   seed bytes
    69  4   first 4 bytes of SHA-256(magic || version || seed)

Only an image FILE is handled (the size comes from the file). The image must
carry the tail headroom (`make` builds one: 8 sectors past the FAT32 volume);
without it the kernel refuses to touch the tail, so this tool refuses to write
a sector that lies inside the FAT32 volume it can see at sector 0.
"""
import argparse
import hashlib
import os
import struct
import sys

SECTOR = 512
TAIL_SECTORS = 8
SEED_SECTOR = 1
MAGIC = b"SEED"
VERSION = 1
SEED_BYTES = 64


def record(seed: bytes) -> bytes:
    assert len(seed) == SEED_BYTES
    tag = hashlib.sha256(MAGIC + bytes([VERSION]) + seed).digest()[:4]
    return MAGIC + bytes([VERSION]) + seed + tag


def decode(sector: bytes):
    n = 4 + 1 + SEED_BYTES + 4
    if len(sector) < n or sector[:4] != MAGIC or sector[4] != VERSION:
        return None
    seed = sector[5:5 + SEED_BYTES]
    tag = hashlib.sha256(MAGIC + bytes([VERSION]) + seed).digest()[:4]
    return seed if sector[5 + SEED_BYTES:n] == tag else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("image")
    ap.add_argument("--show", action="store_true", help="read, do not write")
    a = ap.parse_args()

    size = os.path.getsize(a.image)
    if size % SECTOR or size // SECTOR <= TAIL_SECTORS:
        print(f"{a.image}: size {size} is not a whole number of sectors past the tail", file=sys.stderr)
        return 2
    cap = size // SECTOR
    tail_start = cap - TAIL_SECTORS
    off = (tail_start + SEED_SECTOR) * SECTOR

    with open(a.image, "r+b" if not a.show else "rb") as f:
        if a.show:
            f.seek(off)
            seed = decode(f.read(SECTOR))
            print("absent" if seed is None else "valid " + hashlib.sha256(seed).hexdigest())
            return 0
        f.seek(0)
        s0 = f.read(SECTOR)
        if s0[510:512] != b"\x55\xaa" or struct.unpack_from("<H", s0, 19)[0] != 0:
            print("sector 0 is not a FAT32 boot sector: cannot tell where the filesystem ends", file=sys.stderr)
            return 2
        tot32 = struct.unpack_from("<I", s0, 32)[0]
        if tot32 > tail_start:
            print(f"the FAT32 volume ({tot32} sectors) reaches the tail (starts at {tail_start}); "
                  "build the image with headroom first", file=sys.stderr)
            return 2
        sector = record(os.urandom(SEED_BYTES)).ljust(SECTOR, b"\0")
        f.seek(off)
        f.write(sector)
    print(f"{a.image}: wrote a {SEED_BYTES}-byte seed record at sector {tail_start + SEED_SECTOR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""link_key_provision.py — write the brain-link key record on a disk image.

The kernel reads the brain-link key, which is also the board's device seed, from
a reserved sector past the end of the FAT32 volume (`kernel/src/reserved_tail.rs`:
the last TAIL_SECTORS = 8 sectors of the medium; `LINK_KEY` = 0 is the sector
this tool touches), which the USB mass-storage export cannot address:

    tools/link_key_provision.py $AZOS_OUT/build/disk.img KEYFILE

KEYFILE holds the 32 raw key bytes. The peers that need the key itself
(`tools/link_peer.py`, `tools/fake_brain.py`, `login_enroll --seed`) keep
reading the raw bytes from their own copy; only the sector carries the record.

Record format (one sector; see `crates/core/crypto/src/secure_channel.rs`
`link_key_record_decode`):
    0   4   magic "KLNK"
    4   1   version 1
    5  32   key
    37  4   first 4 bytes of SHA-256(bytes 0..37)

The kernel refuses a sector that does not hold this record (a raw key, a torn
write, filesystem data) and leaves the link down. Only an image FILE is handled
(the size comes from the file).
"""
import argparse
import hashlib
import os
import sys

SECTOR = 512
TAIL_SECTORS = 8
LINK_KEY_SECTOR = 0
MAGIC = b"KLNK"
VERSION = 1
KEY_BYTES = 32


def record(key: bytes) -> bytes:
    assert len(key) == KEY_BYTES
    body = MAGIC + bytes([VERSION]) + key
    return body + hashlib.sha256(body).digest()[:4]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("image")
    ap.add_argument("keyfile", help=f"the {KEY_BYTES} raw key bytes")
    a = ap.parse_args()

    with open(a.keyfile, "rb") as f:
        key = f.read()
    if len(key) != KEY_BYTES or key == bytes(KEY_BYTES):
        print(f"{a.keyfile}: want {KEY_BYTES} bytes, not all zero (got {len(key)})", file=sys.stderr)
        return 2
    size = os.path.getsize(a.image)
    if size % SECTOR or size // SECTOR <= TAIL_SECTORS:
        print(f"{a.image}: size {size} is not a whole number of sectors past the tail", file=sys.stderr)
        return 2
    tail_start = size // SECTOR - TAIL_SECTORS
    with open(a.image, "r+b") as f:
        f.seek((tail_start + LINK_KEY_SECTOR) * SECTOR)
        f.write(record(key).ljust(SECTOR, b"\0"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

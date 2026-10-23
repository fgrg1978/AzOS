#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""azos_records.py — where the kernel's records lie on a disk image.

The kernel keeps its records (the brain-link key, the entropy seed, the device
record, the topology counter floor) one sector each, in TAIL_SECTORS sectors
(`kernel/src/reserved_tail.rs`):

  MBR or bare FAT32 medium   the last TAIL_SECTORS sectors (the reserved tail)
  GPT medium                 the AzOS records partition, type GUID
                             653ED7AA-51CA-43D8-9AF7-54775962C612
                             (`crates/drivers/block/src/partition.rs`
                             `GPT_RECORDS_GUID`)

A GPT laid out to its end keeps its backup table where the tail would be, so
the provisioning tools (`link_key_provision.py`, `seed_provision.py`,
`device_provision.py`) ask `records_start` instead of computing the tail: a
GPT image without a records partition is refused rather than having its
backup header overwritten.
"""
import struct
import uuid
import zlib

SECTOR = 512
TAIL_SECTORS = 8
RECORDS_GUID_TEXT = "653ED7AA-51CA-43D8-9AF7-54775962C612"
# As it lies in a GPT entry (the first three fields little-endian).
RECORDS_GUID = uuid.UUID(RECORDS_GUID_TEXT).bytes_le


def is_protective_mbr(s0: bytes) -> bool:
    """Sector 0 is an MBR with an 0xEE entry: the medium is GPT."""
    return len(s0) >= SECTOR and s0[510:512] == b"\x55\xaa" and any(
        s0[446 + 16 * i + 4] == 0xEE for i in range(4))


def gpt_records(f, image: str):
    """`(start, sectors)` of the records partition of the GPT medium open in
    `f`. Exits on a primary header or array whose CRC32 is wrong, and on a
    GPT without exactly one records partition."""
    f.seek(SECTOR)
    h = f.read(SECTOR)
    hsize = struct.unpack_from("<I", h, 12)[0] if len(h) == SECTOR else 0
    if h[:8] != b"EFI PART" or not 92 <= hsize <= SECTOR:
        raise SystemExit(f"{image}: protective MBR but no GPT header at LBA 1")
    if zlib.crc32(h[:16] + b"\0\0\0\0" + h[20:hsize]) != struct.unpack_from("<I", h, 16)[0]:
        raise SystemExit(f"{image}: GPT header CRC32 mismatch")
    entries_lba, n, esize, crc = struct.unpack_from("<QIII", h, 72)
    f.seek(entries_lba * SECTOR)
    arr = f.read(n * esize)
    if len(arr) != n * esize or zlib.crc32(arr) != crc:
        raise SystemExit(f"{image}: GPT entry array CRC32 mismatch")
    found = [struct.unpack_from("<QQ", arr, i * esize + 32)
             for i in range(n) if arr[i * esize:i * esize + 16] == RECORDS_GUID]
    if len(found) != 1:
        raise SystemExit(f"{image}: GPT medium with {len(found)} AzOS records partitions "
                         f"(type {RECORDS_GUID_TEXT}); want one")
    first, last = found[0]
    if last < first or last - first + 1 < TAIL_SECTORS:
        raise SystemExit(f"{image}: records partition LBA {first}..{last} holds fewer than "
                         f"{TAIL_SECTORS} sectors")
    return first, last - first + 1


def records_start(image: str, check_fat: bool = False) -> int:
    """The LBA of records sector 0 on `image`. With `check_fat`, a bare
    medium must have a FAT32 boot sector at LBA 0 whose volume ends before
    the tail (the kernel refuses any other tail, so a record written there
    would never be read)."""
    with open(image, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        if size % SECTOR or size // SECTOR <= TAIL_SECTORS:
            raise SystemExit(f"{image}: size {size} is not a whole number of sectors past the tail")
        f.seek(0)
        s0 = f.read(SECTOR)
        if is_protective_mbr(s0):
            return gpt_records(f, image)[0]
    tail_start = size // SECTOR - TAIL_SECTORS
    if check_fat:
        if s0[510:512] != b"\x55\xaa" or struct.unpack_from("<H", s0, 19)[0] != 0:
            raise SystemExit("sector 0 is not a FAT32 boot sector: cannot tell where the filesystem ends")
        tot32 = struct.unpack_from("<I", s0, 32)[0]
        if tot32 > tail_start:
            raise SystemExit(f"the FAT32 volume ({tot32} sectors) reaches the tail (starts at "
                             f"{tail_start}); build the image with headroom first")
    return tail_start

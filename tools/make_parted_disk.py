#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Build the gate's partitioned disk image (RFC-0048 P3, wave 9).

Usage: make_parted_disk.py SRC.img OUT.img

SRC is one of the Makefile's bare FAT32 images (a `mkfs.fat` superfloppy:
the FAT32 boot sector at LBA 0). OUT is a classic-MBR medium:

  LBA 0                  MBR, two primary entries
  LBA 2048               partition 0, type 0x0C: SRC's FAT32 volume, exactly
                         its BPB `tot_sec32` sectors
  after it               partition 1, type 0xDA (non-filesystem data): 64
                         zeroed sectors, the range `disk.part.1` names
  last 8 sectors         the reserved tail `kernel/src/msc_gadget.rs` keeps
                         (MSC_RESERVED_TAIL_SECTORS), inside no partition,
                         copied from SRC's own tail: it holds the device
                         record CONFIG.SIG v2 is bound to (wave 11), so the
                         volume's signed CONFIG.INI stays this device's

The volume's own `hidd_sec` is left as mkfs wrote it: the kernel locates the
volume from the table it parses, never from that field.
"""
import struct
import sys

SECTOR = 512
BASE = 2048
PART1_SECTORS = 64
TAIL_SECTORS = 8


def main():
    src, out = sys.argv[1], sys.argv[2]
    data = open(src, "rb").read()
    boot = data[:SECTOR]
    if boot[510:512] != b"\x55\xaa" or boot[82:90] != b"FAT32   ":
        sys.exit(f"{src}: LBA 0 is not a FAT32 boot sector")
    tot = struct.unpack_from("<I", boot, 32)[0]
    if tot == 0 or tot * SECTOR > len(data):
        sys.exit(f"{src}: tot_sec32 {tot} does not fit the file")
    vol = data[: tot * SECTOR]
    p1 = BASE + tot
    total = p1 + PART1_SECTORS + TAIL_SECTORS

    mbr = bytearray(SECTOR)
    for i, (ty, start, n) in enumerate(((0x0C, BASE, tot), (0xDA, p1, PART1_SECTORS))):
        o = 446 + 16 * i
        mbr[o] = 0x00
        mbr[o + 1 : o + 4] = b"\xfe\xff\xff"   # CHS unused: LBA addressing
        mbr[o + 4] = ty
        mbr[o + 5 : o + 8] = b"\xfe\xff\xff"
        struct.pack_into("<II", mbr, o + 8, start, n)
    mbr[510:512] = b"\x55\xaa"

    img = bytearray(total * SECTOR)
    img[:SECTOR] = mbr
    img[BASE * SECTOR : BASE * SECTOR + len(vol)] = vol
    if len(data) >= (tot + TAIL_SECTORS) * SECTOR:
        img[-TAIL_SECTORS * SECTOR:] = data[-TAIL_SECTORS * SECTOR:]
    with open(out, "wb") as f:
        f.write(img)
    print(f"[DISK] partitioned image: {out} (part 0 LBA {BASE}+{tot}, "
          f"part 1 LBA {p1}+{PART1_SECTORS}, {total} sectors)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Build the gate's partitioned disk images (wave 9; GPT: records partition).

Usage: make_parted_disk.py [--gpt] SRC.img OUT.img

SRC is one of the Makefile's bare FAT32 images (a `mkfs.fat` superfloppy:
the FAT32 boot sector at LBA 0). Without `--gpt`, OUT is a classic-MBR medium:

  LBA 0                  MBR, two primary entries
  LBA 2048               partition 0, type 0x0C: SRC's FAT32 volume, exactly
                         its BPB `tot_sec32` sectors
  after it               partition 1, type 0xDA (non-filesystem data): 64
                         zeroed sectors, the range `disk.part.1` names
  last 8 sectors         the reserved tail `kernel/src/reserved_tail.rs` keeps
                         (TAIL_SECTORS), inside no partition,
                         copied from SRC's own tail: it holds the device
                         record CONFIG.SIG v2 is bound to (wave 11), so the
                         volume's signed CONFIG.INI stays this device's

With `--gpt`, OUT is a GPT medium laid out to its end, as gdisk and Linux
lay one out (so it has no reserved tail: the backup table is there):

  LBA 0                  protective MBR (one 0xEE entry)
  LBA 1, 2..33           primary GPT header and its 128 x 128 B entry array
  LBA 2048               partition 0, Microsoft basic data: SRC's FAT32
                         volume, exactly its `tot_sec32` sectors
  after it               partition 1, the AzOS records partition
                         (`tools/image/azos_records.py` RECORDS_GUID), TAIL_SECTORS
                         sectors, copied from SRC's tail as above
  last 33 sectors        the backup entry array and, on the last sector, the
                         backup GPT header

The volume's own `hidd_sec` is left as mkfs wrote it: the kernel locates the
volume from the table it parses, never from that field.
"""
import struct
import sys
import uuid
import zlib

from azos_records import RECORDS_GUID, SECTOR, TAIL_SECTORS

BASE = 2048
PART1_SECTORS = 64
GPT_ENTRIES = 128
GPT_ENTRY = 128
GPT_ARRAY_SECTORS = GPT_ENTRIES * GPT_ENTRY // SECTOR
BASIC_DATA_GUID = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").bytes_le


def stable_guid(what):
    """A GUID that is the same on every build, so the image is too."""
    return uuid.uuid5(uuid.NAMESPACE_URL, "azos:make_parted_disk:" + what).bytes_le


def mbr_entry(mbr, i, ty, start, n):
    o = 446 + 16 * i
    mbr[o] = 0x00
    mbr[o + 1 : o + 4] = b"\xfe\xff\xff"   # CHS unused: LBA addressing
    mbr[o + 4] = ty
    mbr[o + 5 : o + 8] = b"\xfe\xff\xff"
    struct.pack_into("<II", mbr, o + 8, start, n)


def gpt_header(my, alt, first_usable, last_usable, entries_lba, array_crc):
    h = bytearray(SECTOR)
    struct.pack_into("<8sIIIIQQQQ16sQIII", h, 0, b"EFI PART", 0x00010000, 92, 0, 0,
                     my, alt, first_usable, last_usable, stable_guid("disk"), entries_lba,
                     GPT_ENTRIES, GPT_ENTRY, array_crc)
    struct.pack_into("<I", h, 16, zlib.crc32(h[:92]))
    return h


def gpt_entry(arr, i, ty, first, last, name):
    o = i * GPT_ENTRY
    struct.pack_into("<16s16sQQQ", arr, o, ty, stable_guid(f"part{i}"), first, last, 0)
    n = name.encode("utf-16-le")
    arr[o + 56 : o + 56 + len(n)] = n


def gpt_image(vol, tot, tail):
    rec = BASE + tot
    last_usable = rec + TAIL_SECTORS - 1
    total = last_usable + 1 + GPT_ARRAY_SECTORS + 1
    first_usable = 2 + GPT_ARRAY_SECTORS
    backup_array = total - 1 - GPT_ARRAY_SECTORS
    arr = bytearray(GPT_ENTRIES * GPT_ENTRY)
    gpt_entry(arr, 0, BASIC_DATA_GUID, BASE, BASE + tot - 1, "AZOS FAT32")
    gpt_entry(arr, 1, RECORDS_GUID, rec, last_usable, "AZOS RECORDS")
    crc = zlib.crc32(arr)

    mbr = bytearray(SECTOR)
    mbr_entry(mbr, 0, 0xEE, 1, min(total - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"

    img = bytearray(total * SECTOR)
    img[:SECTOR] = mbr
    img[SECTOR : 2 * SECTOR] = gpt_header(1, total - 1, first_usable, last_usable, 2, crc)
    img[2 * SECTOR : 2 * SECTOR + len(arr)] = arr
    img[BASE * SECTOR : BASE * SECTOR + len(vol)] = vol
    if tail is not None:
        img[rec * SECTOR : (rec + TAIL_SECTORS) * SECTOR] = tail
    img[backup_array * SECTOR : backup_array * SECTOR + len(arr)] = arr
    img[-SECTOR:] = gpt_header(total - 1, 1, first_usable, last_usable, backup_array, crc)
    return img, (f"GPT: part 0 LBA {BASE}+{tot}, records part 1 LBA {rec}+{TAIL_SECTORS}, "
                 f"backup header LBA {total - 1}, {total} sectors")


def mbr_image(vol, tot, tail):
    p1 = BASE + tot
    total = p1 + PART1_SECTORS + TAIL_SECTORS
    mbr = bytearray(SECTOR)
    mbr_entry(mbr, 0, 0x0C, BASE, tot)
    mbr_entry(mbr, 1, 0xDA, p1, PART1_SECTORS)
    mbr[510:512] = b"\x55\xaa"
    img = bytearray(total * SECTOR)
    img[:SECTOR] = mbr
    img[BASE * SECTOR : BASE * SECTOR + len(vol)] = vol
    if tail is not None:
        img[-TAIL_SECTORS * SECTOR:] = tail
    return img, f"part 0 LBA {BASE}+{tot}, part 1 LBA {p1}+{PART1_SECTORS}, {total} sectors"


def main():
    args = sys.argv[1:]
    gpt = args[:1] == ["--gpt"]
    if gpt:
        args = args[1:]
    if len(args) != 2:
        sys.exit("usage: make_parted_disk.py [--gpt] SRC.img OUT.img")
    src, out = args
    data = open(src, "rb").read()
    boot = data[:SECTOR]
    if boot[510:512] != b"\x55\xaa" or boot[82:90] != b"FAT32   ":
        sys.exit(f"{src}: LBA 0 is not a FAT32 boot sector")
    tot = struct.unpack_from("<I", boot, 32)[0]
    if tot == 0 or tot * SECTOR > len(data):
        sys.exit(f"{src}: tot_sec32 {tot} does not fit the file")
    vol = data[: tot * SECTOR]
    tail = None
    if len(data) >= (tot + TAIL_SECTORS) * SECTOR:
        tail = data[-TAIL_SECTORS * SECTOR:]
    img, what = (gpt_image if gpt else mbr_image)(vol, tot, tail)
    with open(out, "wb") as f:
        f.write(img)
    print(f"[DISK] partitioned image: {out} ({what})")


if __name__ == "__main__":
    main()

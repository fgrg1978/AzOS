#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""No page of a user ELF is touched by two PT_LOAD segments mapped differently.

The kernel loader maps each page with the permissions of its own segment and
refuses an image in which two segments with different mapped permissions
(read-only, read-execute, read-write: `elf_bounds::seg_perms`) share a page.
This lint reads the program headers of the built images so a linker script
change that brings the sharing back is named here, image by image, instead of
as an exec refused at boot. Cargo does not relink on a `.ld` edit, so a stale
image is also caught.

  elf_page_perms.py ELF...     exit 1 and name each mixed page
  elf_page_perms.py --self-test  the check finds a crafted mixed page
"""
import struct
import sys

PAGE = 4096


def perms(flags):
    return "RW" if flags & 2 else ("RX" if flags & 1 else "R")


def mixed_pages(data):
    """[(page, {perms})] for each page two differently mapped segments touch;
    None when `data` is not a 64-bit little-endian ELF."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    pages = {}
    for i in range(phnum):
        p_type, p_flags, _off, vaddr, _pa, _fs, memsz, _al = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * phentsize)
        if p_type != 1 or memsz == 0:
            continue
        for page in range(vaddr // PAGE, (vaddr + memsz + PAGE - 1) // PAGE):
            pages.setdefault(page, set()).add(perms(p_flags))
    return [(p * PAGE, sorted(v)) for p, v in sorted(pages.items()) if len(v) > 1]


def crafted(text_end, ro_start):
    """A header with an RX segment ending at `text_end` and an R one at
    `ro_start`."""
    hdr = bytearray(64 + 2 * 56)
    hdr[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", hdr, 32, 64)
    struct.pack_into("<HH", hdr, 54, 56, 2)
    struct.pack_into("<IIQQQQQQ", hdr, 64, 1, 5, 0, 0x10000, 0x10000, text_end - 0x10000,
                     text_end - 0x10000, PAGE)
    struct.pack_into("<IIQQQQQQ", hdr, 120, 1, 4, 0, ro_start, ro_start, 0x40, 0x40, PAGE)
    return bytes(hdr)


def self_test():
    shared = mixed_pages(crafted(0x10850, 0x10850))
    split = mixed_pages(crafted(0x10850, 0x11850))
    if shared != [(0x10000, ["R", "RX"])] or split != []:
        print(f"self-test: shared page read {shared}, split layout read {split}")
        return 1
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    bad = 0
    for path in argv:
        with open(path, "rb") as f:
            found = mixed_pages(f.read())
        if found:
            bad += 1
            for page, which in found[:3]:
                print(f"{path}: page {page:#x} mapped {'+'.join(which)}")
    if not argv:
        print("no ELF named")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

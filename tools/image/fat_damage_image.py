#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Damage a FAT32 image the way a cut write can: break a file's chain.

usage: fat_damage_image.py <image> <NAME.EXT>

The file (in the root directory, 8.3 name) must span at least two clusters.
Its second cluster's FAT entry is set to 0 (free) in every FAT copy, so its
chain runs through a free cluster and its tail is reached by nothing, and the
volume is marked unclean (FAT[1] bit 27 clear), so the next mount checks it.
The gate row `fs check: a damaged FAT32 boot volume is served read-only`
boots the result. Prints one line; exits non-zero when the file is missing or
too short.
"""
import struct
import sys


def main():
    path, name = sys.argv[1], sys.argv[2].upper()
    base, _, ext = name.partition('.')
    want = base.ljust(8).encode() + ext.ljust(3).encode()
    with open(path, 'r+b') as f:
        img = bytearray(f.read())
        bps, spc, rsvd, nfats = struct.unpack_from('<HBHB', img, 11)
        fatsz, = struct.unpack_from('<I', img, 36)
        root, = struct.unpack_from('<I', img, 44)
        fat = rsvd * bps
        data = (rsvd + nfats * fatsz) * bps
        csize = spc * bps

        def entry(c):
            return struct.unpack_from('<I', img, fat + 4 * c)[0] & 0x0FFFFFFF

        def put(c, v):
            for k in range(nfats):
                o = fat + k * fatsz * bps + 4 * c
                old, = struct.unpack_from('<I', img, o)
                struct.pack_into('<I', img, o, (old & 0xF0000000) | v)

        first, c, seen = None, root, 0
        while first is None and 2 <= c < 0x0FFFFFF8 and seen < 4096:
            off = data + (c - 2) * csize
            for e in range(off, off + csize, 32):
                if img[e] == 0:
                    break
                if bytes(img[e:e + 11]) == want and img[e + 11] & 0x18 == 0:
                    hi, = struct.unpack_from('<H', img, e + 20)
                    lo, = struct.unpack_from('<H', img, e + 26)
                    first = hi << 16 | lo
                    break
            c, seen = entry(c), seen + 1
        if first is None:
            sys.exit("fat_damage_image: no %s in the root directory" % name)
        second = entry(first)
        if not 2 <= second < 0x0FFFFFF8:
            sys.exit("fat_damage_image: %s has one cluster" % name)
        put(second, 0)
        for k in range(nfats):
            o = fat + k * fatsz * bps + 4
            v, = struct.unpack_from('<I', img, o)
            struct.pack_into('<I', img, o, v & ~0x08000000)
        f.seek(0)
        f.write(img)
    print("fat_damage_image: %s chain %d -> %d cut (cluster %d free), volume unclean" % (name, first, second, second))


if __name__ == '__main__':
    main()

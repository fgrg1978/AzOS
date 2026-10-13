#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Derive and check the Zbc CRC-32 constants lx/glue/lxbase.c uses (wave 13).

Computes z^64 mod P, z^96 mod P, floor(z^64 / P) and P bit-reversed in 64
bits, prints them, and checks the folding algorithm (a model of `clmulr`)
against the table CRC on random data. Exit 1 on any mismatch, or when the
constants differ from the ones in lxbase.c.
"""
import os
import random
import re
import struct
import sys

M = (1 << 64) - 1
P = 0x104C11DB7


def clmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        b >>= 1
    return r


def clmulr(a, b):
    return (clmul(a, b) >> 63) & M


def rev(a, n=64):
    return int(bin(a)[2:].zfill(n)[::-1], 2)


def pmod(a, p):
    while a.bit_length() >= p.bit_length():
        a ^= p << (a.bit_length() - p.bit_length())
    return a


def pdiv(a, p):
    q = 0
    while a and a.bit_length() >= p.bit_length():
        s = a.bit_length() - p.bit_length()
        q |= 1 << s
        a ^= p << s
    return q


K64R, K96R, MUR, PR = rev(pmod(1 << 64, P)), rev(pmod(1 << 96, P)), rev(pdiv(1 << 64, P)), rev(P)
# The 2-word fold: z^(d-1) mod P, so the product of a reflected word and the
# reflected constant is the reflected 128-bit product, split across words.
C128, C192 = rev(pmod(1 << 127, P)), rev(pmod(1 << 191, P))
TABLE = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
    TABLE.append(c)


def crc_table(crc, data):
    for b in data:
        crc = (crc >> 8) ^ TABLE[(crc ^ b) & 0xFF]
    return crc


def fold1(a, w):
    return w ^ clmulr((a << 32) & M, K96R) ^ clmulr(a & 0xFFFFFFFF00000000, K64R)


def crc_fold(crc, data):
    """The algorithm of lxbase.c's crc32_le_zbc, word for word."""
    words = struct.unpack("<%dQ" % (len(data) // 8), data)
    a, i = crc ^ words[0], 1
    if len(words) >= 2:
        h, l, i = a, words[1], 2
        while len(words) - i >= 4:
            for _ in range(2):
                h, l = (words[i] ^ (clmul(h, C192) & M) ^ (clmul(l, C128) & M),
                        words[i + 1] ^ (clmul(h, C192) >> 64) ^ (clmul(l, C128) >> 64))
                i += 2
        a = fold1(h, l)
    for w in words[i:]:
        a = fold1(a, w)
    y = clmulr((a << 32) & M, K64R) ^ (a >> 32)
    q = (clmulr((y << 32) & M, MUR) << 32) & M
    return (y ^ clmulr(q, PR)) >> 32


def main():
    consts = {"ZBC_K64R": K64R, "ZBC_K96R": K96R, "ZBC_MUR": MUR, "ZBC_PR": PR, "ZBC_C128": C128, "ZBC_C192": C192}
    for k, v in consts.items():
        print(f"{k} = {v:#018x}")
    bad = 0
    rnd = random.Random(13)
    for _ in range(500):
        crc = rnd.getrandbits(32)
        data = bytes(rnd.getrandbits(8) for _ in range(8 * rnd.randint(1, 24)))
        bad += crc_fold(crc, data) != crc_table(crc, data)
    src = open(os.path.join(os.path.dirname(__file__), "..", "..", "lx", "glue", "lxbase.c")).read()
    for k, v in consts.items():
        m = re.search(r"#define\s+" + k + r"\s+(0x[0-9a-fA-F]+)ULL", src)
        if not m or int(m.group(1), 16) != v:
            print(f"lxbase.c: {k} is {m.group(1) if m else 'missing'}, want {v:#018x}")
            bad += 1
    print("zbc_crc_constants:", "FAIL" if bad else "500 random messages equal to the table CRC; lxbase.c agrees")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

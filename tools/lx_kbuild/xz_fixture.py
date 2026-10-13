#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Write the plaintext of the lx/ xz fixture (RFC-0053 L1) to stdout.

The Linux driver server regenerates the same bytes independently
(`userspace/services/lxsrv`, `xz_pattern`) and compares them with what the
upstream xz_dec.ko decompressed from XZTEST.XZ. Changing one side without the
other turns the row red, which is the point.
"""
import sys

SIZE = 49152
WORDS = [b"azos", b"linux", b"module", b"driver", b"server", b"ring", b"three", b"xz",
         b"decode", b"stream", b"block", b"page", b"token", b"verify", b"map", b"exec"]
SEED = 0x4C58_585A_5445_5354
M = (1 << 64) - 1


def pattern(seed=SEED, size=SIZE):
    x, out = seed, bytearray()
    while len(out) < size:
        x ^= (x << 13) & M
        x ^= x >> 7
        x ^= (x << 17) & M
        out += WORDS[x >> 60]
        out += b"\n" if (x >> 56) & 7 == 0 else b" "
    return bytes(out[:size])


if __name__ == "__main__":
    seed = int(sys.argv[1], 0) if len(sys.argv) > 1 else SEED
    sys.stdout.buffer.write(pattern(seed))

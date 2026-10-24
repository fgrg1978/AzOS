#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""
AzOS — delta generator for whole-system updates.

A whole-system update is a bundle (`tools/sign/sign_ota.py bundle`): the signed
manifest, then the parts. The running slot holds the bundle it was staged from,
so a new bundle can be sent as a patch against it. This tool makes that patch.

    python3 tools/image/ota_delta.py make OLD.bundle NEW.bundle -o NEW.azd
    python3 tools/image/ota_delta.py apply OLD.bundle NEW.azd -o NEW.bundle
    python3 tools/image/ota_delta.py info NEW.azd

The format is `crates/core/ota/src/pure.rs` ("Delta updates"): a head with the
SHA-256 of the base and of the result, then COPY (src_off, len) and INSERT
(bytes) ops. The device applies it by reading the running slot's set and hands
the result to the ordinary stager, which verifies the bundle's signature and
every part's hash. The delta is not signed and does not need to be: it can only
produce a bundle the manifest's signature covers, or one that is refused.

`make` checks its own output by applying it before it writes anything.

The matcher is greedy and forward-biased. The device reads the base through a
sequential file stream (`pure.rs::SetBase`), so a COPY whose source lies behind
the previous one costs a reopen; among the places a block of the new bundle
occurs in the old one this prefers the first at or after the previous source.
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

MAGIC = b"AZDL"
FORMAT = 1
HEAD_LEN = 80
OP_COPY = 1
OP_INSERT = 2

# The matcher indexes the old bundle in blocks of this many bytes, aligned, and
# looks for every one of them at every offset of the new bundle: a block that
# moved by any distance is found, and a match is then grown both ways.
BLOCK = 32
# A COPY op is 9 bytes; a match shorter than that is cheaper inserted.
MIN_COPY = 16
# Places one block is remembered at (the ones nearest the start of the old bundle).
MAX_CANDIDATES = 8
U32_MAX = 0xFFFF_FFFF


def _ops_bytes(ops: list) -> bytes:
    out = bytearray()
    for op in ops:
        if op[0] == OP_COPY:
            out += struct.pack("<BII", OP_COPY, op[1], op[2])
        else:
            out += struct.pack("<BI", OP_INSERT, len(op[1])) + op[1]
    return bytes(out)


def diff(old: bytes, new: bytes) -> list:
    """Ops that turn `old` into `new`: ("copy", src, len) / ("insert", bytes)."""
    index = {}
    for off in range(0, len(old) - BLOCK + 1, BLOCK):
        where = index.setdefault(old[off:off + BLOCK], [])
        if len(where) < MAX_CANDIDATES:      # a run of zeros must not make every lookup long
            where.append(off)

    ops = []          # (OP_COPY, src, len) | (OP_INSERT, bytes)
    pending = bytearray()
    last_src = 0
    i = 0
    n = len(new)

    def flush():
        if pending:
            ops.append((OP_INSERT, bytes(pending)))
            pending.clear()

    while i < n:
        cand = index.get(new[i:i + BLOCK]) if i + BLOCK <= n else None
        if not cand:
            pending.append(new[i])
            i += 1
            continue
        # Forward-biased: the first source at or after the last one, else the first.
        src = next((c for c in cand if c >= last_src), cand[0])
        end_old = src + BLOCK
        end_new = i + BLOCK
        while end_old < len(old) and end_new < n and old[end_old] == new[end_new]:
            end_old += 1
            end_new += 1
        # Grow backwards into the bytes that would be inserted.
        while pending and src > 0 and old[src - 1] == pending[-1]:
            src -= 1
            pending.pop()
        length = end_old - src
        if length < MIN_COPY:
            pending += new[i:end_new]
        else:
            flush()
            # Contiguous with the previous copy: one op.
            if ops and ops[-1][0] == OP_COPY and ops[-1][1] + ops[-1][2] == src:
                ops[-1] = (OP_COPY, ops[-1][1], ops[-1][2] + length)
            else:
                ops.append((OP_COPY, src, length))
            last_src = src + length
        i = end_new
    flush()
    return ops


def make(old: bytes, new: bytes) -> bytes:
    if len(old) > U32_MAX or len(new) > U32_MAX or not new:
        raise ValueError("bundles must be 1..4 GiB")
    delta = (MAGIC + struct.pack("<HHI", FORMAT, 0, len(old)) + hashlib.sha256(old).digest()
             + struct.pack("<I", len(new)) + hashlib.sha256(new).digest() + _ops_bytes(diff(old, new)))
    if apply(old, delta) != new:
        raise AssertionError("the delta does not reproduce the new bundle")
    return delta


def parse_head(delta: bytes):
    if len(delta) < HEAD_LEN or delta[:4] != MAGIC:
        raise ValueError("not a delta")
    fmt, flags, base_len = struct.unpack_from("<HHI", delta, 4)
    if fmt != FORMAT or flags != 0:
        raise ValueError(f"format {fmt}, flags {flags}: not a delta this tool reads")
    base_sha = delta[12:44]
    (result_len,) = struct.unpack_from("<I", delta, 44)
    return base_len, base_sha, result_len, delta[48:80]


def apply(old: bytes, delta: bytes) -> bytes:
    """What the device does: refuse a wrong base or a damaged delta, else the result."""
    base_len, base_sha, result_len, result_sha = parse_head(delta)
    if len(old) != base_len or hashlib.sha256(old).digest() != base_sha:
        raise ValueError("this is not the base the delta was made against")
    out = bytearray()
    p = HEAD_LEN
    while p < len(delta):
        tag = delta[p]
        if tag == OP_COPY and p + 9 <= len(delta):
            src, length = struct.unpack_from("<II", delta, p + 1)
            p += 9
            if length == 0 or src + length > len(old):
                raise ValueError("a COPY reaches outside the base")
            out += old[src:src + length]
        elif tag == OP_INSERT and p + 5 <= len(delta):
            (length,) = struct.unpack_from("<I", delta, p + 1)
            p += 5
            if length == 0 or p + length > len(delta):
                raise ValueError("an INSERT runs past the delta")
            out += delta[p:p + length]
            p += length
        else:
            raise ValueError(f"bad op at {p}")
        if len(out) > result_len:
            raise ValueError("the ops are longer than the result")
    if len(out) != result_len or hashlib.sha256(out).digest() != result_sha:
        raise ValueError("the ops do not produce the result the head names")
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="AzOS whole-system update delta")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make", help="delta from the old bundle to the new one")
    m.add_argument("old", type=Path)
    m.add_argument("new", type=Path)
    m.add_argument("-o", "--out", type=Path, required=True)
    a = sub.add_parser("apply", help="apply a delta (what the device does)")
    a.add_argument("old", type=Path)
    a.add_argument("delta", type=Path)
    a.add_argument("-o", "--out", type=Path, required=True)
    i = sub.add_parser("info", help="print a delta's head")
    i.add_argument("delta", type=Path)
    args = ap.parse_args()

    try:
        if args.cmd == "make":
            old, new = args.old.read_bytes(), args.new.read_bytes()
            delta = make(old, new)
            args.out.write_bytes(delta)
            print(f"delta {args.out}: {len(delta)} bytes for a {len(new)}-byte bundle "
                  f"({100 * len(delta) / len(new):.1f}%)")
        elif args.cmd == "apply":
            args.out.write_bytes(apply(args.old.read_bytes(), args.delta.read_bytes()))
        else:
            d = args.delta.read_bytes()
            base_len, base_sha, result_len, result_sha = parse_head(d)
            print(f"base   {base_len} bytes sha256 {base_sha.hex()}")
            print(f"result {result_len} bytes sha256 {result_sha.hex()}")
            print(f"delta  {len(d)} bytes")
    except (ValueError, AssertionError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

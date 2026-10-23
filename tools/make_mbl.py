#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""make_mbl.py -- write (or check) a signed model bundle, `.MBL`.

A bundle is one model and every way the machine may run it: a manifest, its
signature and the variant blobs. The layout is the contract of
`userspace/lib/ml/src/bundle.rs`, which is also the only reader; this file is
the only writer. All integers are little-endian.

    manifest (56 + 72 * n bytes)                                  <- signed
      0   4  magic "AZMB"
      4   2  version 1
      6   2  n, the variants (1..=8)
      8   4  zero
     12   4  input tensor bytes
     16   4  output tensor bytes
     20   4  manifest length (56 + 72 * n)
     24  24  name, ASCII, NUL-padded
     48   8  fallback list: variant indices in order of preference, a
             permutation of 0..n, then 0xFF
     56  72  per variant:
              0 u32 backend (1 gguf, 2 spirv, 3 vendor)
              4 u32 variant id
              8 u64 blob offset in the file (8-aligned, after the signature)
             16 u64 blob length
             24 u32 worst-case time, microseconds (cost table)
             28 u32 energy per run, microjoules
             32 u32 working memory, bytes
             36 u32 zero
             40 32  SHA-256 of the blob
    signature (SIG_BYTES = 72): a `DSIG` container (tools/sigalg.py,
             crates/core/crypto/src/sig.rs): "DSIG", algorithm id (1 =
             Ed25519), signature length (64), then the Ed25519 signature
             over the manifest's exact bytes
    blobs, each 8-aligned, in the order of --variant

Usage:
    make_mbl.py --name NAME --in-bytes N --out-bytes N \\
        --variant gguf:1:policy.gguf:800:120:4096 \\
        --variant vendor:2:policy.npu:90:15:65536 \\
        [--fallback 2,1] [--priv tools/keys/test_priv.bin] --out POLICY.MBL
      --variant is BACKEND:ID:FILE:WCET_US:ENERGY_UJ:MEM_BYTES. --fallback
      lists variant IDs in the order of preference (default: the order of
      --variant). The signing key is the topology key the other signed data
      files use (tools/gen_test_key.py makes the test one).
      --expect-ref-from FILE:CONST fails the build unless the bundle's model
      reference is the `const CONST: u64 = 0x...;` of the Rust source FILE. A
      client that names its model at compile time (the kernel's behavior loop,
      `kernel/src/behavior_ml.rs`) pins the reference there; the reference is
      the digest of the manifest, so it changes with the weights, the cost
      table or the name, and the failure prints the value the source needs.

    make_mbl.py --check FILE.MBL [--pub tools/keys/test_pub.bin]
      Verify the signature, the length and digest of every blob, and print the
      model reference a client names the bundle by.
"""
import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import azos_tools  # noqa: E402
import sigalg

MAGIC = b"AZMB"
VERSION = 1
MAX_VARIANTS = 8
HEADER_BYTES = 56
VARIANT_BYTES = 72
SIG_BYTES = 8 + 64  # a DSIG of an Ed25519 signature
BLOB_ALIGN = 8
NAME_BYTES = 24
BACKENDS = {"gguf": 1, "spirv": 2, "vendor": 3}

KEYS = Path(azos_tools.ROOT).resolve() / "tools/keys"


def die(msg):
    print(f"make_mbl: {msg}", file=sys.stderr)
    sys.exit(1)


def u32(v, what):
    if not 0 <= v < 1 << 32:
        die(f"{what} does not fit 32 bits: {v}")
    return v


def parse_variant(spec):
    parts = spec.split(":")
    if len(parts) != 6:
        die(f"--variant {spec!r}: want BACKEND:ID:FILE:WCET_US:ENERGY_UJ:MEM_BYTES")
    backend, vid, path, wcet, energy, mem = parts
    if backend not in BACKENDS:
        die(f"--variant {spec!r}: backend is one of {', '.join(BACKENDS)}")
    try:
        vid, wcet, energy, mem = (int(x, 0) for x in (vid, wcet, energy, mem))
    except ValueError:
        die(f"--variant {spec!r}: id, wcet, energy and memory are integers")
    blob = Path(path).read_bytes()
    if not blob:
        die(f"--variant {spec!r}: {path} is empty")
    if u32(wcet, "wcet_us") == 0:
        die(f"--variant {spec!r}: a signed worst case of 0 bounds nothing")
    return dict(backend=BACKENDS[backend], id=u32(vid, "id"), blob=blob, wcet=wcet,
                energy=u32(energy, "energy_uj"), mem=u32(mem, "mem_bytes"))


def build(name, in_bytes, out_bytes, variants, fallback_ids, signer):
    n = len(variants)
    if not 1 <= n <= MAX_VARIANTS:
        die(f"a bundle holds 1..={MAX_VARIANTS} variants, not {n}")
    raw = name.encode("ascii", "strict") if name.isascii() else die("the name must be ASCII")
    if not raw or len(raw) > NAME_BYTES or any(not 0x21 <= c <= 0x7E for c in raw):
        die(f"the name is 1..={NAME_BYTES} printable ASCII characters without spaces")
    if u32(in_bytes, "in-bytes") == 0 or u32(out_bytes, "out-bytes") == 0:
        die("a tensor of 0 bytes is not a tensor")
    ids = [v["id"] for v in variants]
    if len(set(ids)) != n:
        die("variant ids must be unique")
    order = ids if fallback_ids is None else fallback_ids
    if sorted(order) != sorted(ids):
        die("--fallback must list every variant id exactly once")
    fb = bytes(ids.index(i) for i in order) + b"\xff" * (MAX_VARIANTS - n)

    mlen = HEADER_BYTES + VARIANT_BYTES * n
    off = mlen + SIG_BYTES
    records = b""
    blobs = b""
    for v in variants:
        off = (off + BLOB_ALIGN - 1) & ~(BLOB_ALIGN - 1)
        blobs += b"\0" * (off - (mlen + SIG_BYTES + len(blobs)))
        records += struct.pack("<IIQQIIII32s", v["backend"], v["id"], off, len(v["blob"]), v["wcet"],
                               v["energy"], v["mem"], 0, hashlib.sha256(v["blob"]).digest())
        blobs += v["blob"]
        off += len(v["blob"])
    manifest = (MAGIC + struct.pack("<HHIIII", VERSION, n, 0, in_bytes, out_bytes, mlen)
                + raw.ljust(NAME_BYTES, b"\0") + fb + records)
    assert len(manifest) == mlen
    return manifest + sigalg.dsig(signer, signer.sign(manifest)) + blobs


def model_ref(manifest):
    return int.from_bytes(hashlib.sha256(manifest).digest()[:8], "little")


def expect_ref(spec, data):
    """Die unless the bundle's model_ref is the `const NAME: u64` of the source."""
    path, _, name = spec.rpartition(":")
    if not path or not name:
        die("--expect-ref-from wants FILE:CONST")
    m = re.search(r"\bconst\s+%s\s*:\s*u64\s*=\s*(0x[0-9A-Fa-f_]+)\s*;" % re.escape(name), Path(path).read_text())
    if not m:
        die(f"{path}: no `const {name}: u64 = 0x...;`")
    want = int(m.group(1).replace("_", ""), 16)
    (mlen,) = struct.unpack_from("<I", data, 20)
    got = model_ref(data[:mlen])
    if got != want:
        die(f"{path}: {name} is 0x{want:016x} but the bundle's model_ref is 0x{got:016x}; "
            f"set `const {name}: u64 = 0x{got:016x};`")


def check(path, pub):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    data = Path(path).read_bytes()
    if data[:4] != MAGIC or len(data) < 24:
        die(f"{path}: not a bundle")
    (mlen,) = struct.unpack_from("<I", data, 20)
    n = (mlen - HEADER_BYTES) // VARIANT_BYTES
    if mlen != HEADER_BYTES + VARIANT_BYTES * n or not 1 <= n <= MAX_VARIANTS or len(data) < mlen + SIG_BYTES:
        die(f"{path}: the manifest length does not match a whole number of variants")
    manifest, dsig = data[:mlen], data[mlen:mlen + SIG_BYTES]
    alg_id, _, sig_len = sigalg.info()
    if dsig[:4] != sigalg.DSIG_MAGIC or struct.unpack_from("<HH", dsig, 4) != (alg_id, sig_len) or len(dsig) != SIG_BYTES:
        die(f"{path}: the signature is not a DSIG of the device's algorithm")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(dsig[8:], manifest)
    except InvalidSignature:
        die(f"{path}: the signature does not verify")
    for i in range(n):
        kind, vid, off, ln, wcet, energy, mem, _, sha = struct.unpack_from(
            "<IIQQIIII32s", manifest, HEADER_BYTES + i * VARIANT_BYTES)
        blob = data[off:off + ln]
        if len(blob) != ln or hashlib.sha256(blob).digest() != sha:
            die(f"{path}: variant {vid}: the blob is not the length and digest the manifest signs")
        print(f"variant {vid}: backend {kind}, {ln} bytes, wcet {wcet} us, {energy} uJ, {mem} B")
    print(f"model_ref 0x{model_ref(manifest):016x}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name")
    ap.add_argument("--in-bytes", type=lambda s: int(s, 0))
    ap.add_argument("--out-bytes", type=lambda s: int(s, 0))
    ap.add_argument("--variant", action="append", default=[])
    ap.add_argument("--fallback", help="variant ids in order of preference, comma-separated")
    ap.add_argument("--priv", default=str(KEYS / "test_priv.bin"), help="raw 32-byte Ed25519 seed")
    ap.add_argument("--pub", default=str(KEYS / "test_pub.bin"), help="raw 32-byte public key for --check")
    ap.add_argument("--out")
    ap.add_argument("--check", metavar="FILE")
    ap.add_argument("--expect-ref-from", metavar="FILE:CONST")
    a = ap.parse_args()

    if a.check:
        pub = Path(a.pub).read_bytes()
        if len(pub) != 32:
            die(f"{a.pub}: a raw Ed25519 public key is 32 bytes")
        check(a.check, pub)
        return
    if None in (a.name, a.in_bytes, a.out_bytes, a.out) or not a.variant:
        ap.error("--name, --in-bytes, --out-bytes, --variant and --out are required")
    signer = sigalg.signer(Path(a.priv))
    fb = None
    if a.fallback:
        try:
            fb = [int(x, 0) for x in a.fallback.split(",")]
        except ValueError:
            die("--fallback is a comma-separated list of variant ids")
    data = build(a.name, a.in_bytes, a.out_bytes, [parse_variant(v) for v in a.variant], fb, signer)
    if a.expect_ref_from:
        expect_ref(a.expect_ref_from, data)
    Path(a.out).write_bytes(data)
    print(f"{a.out}: {len(data)} bytes, {len(a.variant)} variant(s)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""F18 — Sign an OTA kernel image with Ed25519.

Reads the raw kernel .BIN and writes a matching .SIG file containing the
`FirmwareSignature` header expected by crates/core/crypto/src/ed25519.rs:

    Offset  Size  Field
    0       4     magic "RSIG"
    4       1     algorithm (1 = manifest-v1)
    5       32    public key (raw)
    37      64    signature (raw)
    101     4     payload size (u32 LE)
    105     4     firmware version (u32 LE)

Total header = 109 bytes.

## Manifest binding (2026-09-26, U09-4 / U11-4 / security finding #10)

The signature does NOT cover the raw image bytes any more. It covers a
fixed 40-byte manifest:

    fw_version(4, LE) || payload_size(4, LE) || sha256(image)(32)

binding the firmware version into the signed material. Before this, the OTA
anti-rollback floor compared `min_fw_version` against `fw_version` from the
UNSIGNED 24-byte wire header (`crates/core/ota/src/pure.rs::OtaHeader`) — any
sender could claim any version for a genuinely-signed old image, which
defeats anti-rollback entirely. Algorithm byte 0 (raw-image signing, no
version binding) is refused by `sig_parse_header` for exactly this reason:
a `.SIG` in that format is not trusted to state any version at all, rather
than silently treated as version 0.

Usage:
    python3 tools/sign_ota.py path/to/kernel.bin --fw-version 42 \\
        [--priv tools/keys/dev_priv.bin]

Outputs:
    path/to/kernel.sig  (same basename, .sig extension)
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("error: install the 'cryptography' package: pip install cryptography", file=sys.stderr)
    sys.exit(1)

SIG_MAGIC = b"RSIG"
SIG_ALGORITHM_ED25519_LEGACY = 0   # refused by the kernel — no version binding
SIG_ALGORITHM_MANIFEST_V1 = 1      # the only algorithm the kernel accepts
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
SIG_HEADER_SIZE = 4 + 1 + ED25519_PUBLIC_KEY_SIZE + ED25519_SIGNATURE_SIZE + 4 + 4


def manifest_message(fw_version: int, payload_size: int, digest: bytes) -> bytes:
    """Must match `azos_crypto::ed25519::manifest_message` byte-for-byte."""
    assert len(digest) == 32
    return struct.pack("<II", fw_version, payload_size) + digest


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("image", type=Path, help="Raw kernel binary to sign")
    p.add_argument(
        "--fw-version",
        type=int,
        default=0,
        help="Firmware version bound into the signed manifest (default: 0 — "
             "explicit default so a caller that forgets this flag gets a "
             "version that can never raise the anti-rollback floor, rather "
             "than an accidentally-high one).",
    )
    p.add_argument(
        "--priv",
        type=Path,
        default=Path(__file__).parent / "keys" / "dev_priv.bin",
        help="Ed25519 private key (raw 32-byte seed)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output .sig path (default: <image>.sig replacing .bin extension)",
    )
    args = p.parse_args()

    if not args.priv.exists():
        print(f"error: private key not found: {args.priv}", file=sys.stderr)
        print("hint: run tools/gen_dev_key.py first.", file=sys.stderr)
        return 1
    if args.fw_version < 0 or args.fw_version > 0xFFFF_FFFF:
        print("error: --fw-version must fit in a u32", file=sys.stderr)
        return 1

    priv_raw = args.priv.read_bytes()
    if len(priv_raw) != ED25519_PUBLIC_KEY_SIZE:
        print("error: private key is not 32 bytes", file=sys.stderr)
        return 1

    priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    image = args.image.read_bytes()
    digest = hashlib.sha256(image).digest()
    msg = manifest_message(args.fw_version, len(image), digest)
    signature = priv.sign(msg)

    assert len(pub_raw) == ED25519_PUBLIC_KEY_SIZE
    assert len(signature) == ED25519_SIGNATURE_SIZE

    header = bytearray()
    header += SIG_MAGIC
    header.append(SIG_ALGORITHM_MANIFEST_V1)
    header += pub_raw
    header += signature
    header += struct.pack("<I", len(image))
    header += struct.pack("<I", args.fw_version)
    assert len(header) == SIG_HEADER_SIZE

    out = args.out
    if out is None:
        out = args.image.with_suffix(".sig")
    out.write_bytes(bytes(header))

    print(f"✓ signed {args.image} ({len(image)} bytes, fw_version={args.fw_version})")
    print(f"  sha256 : {digest.hex()}")
    print(f"  sig out: {out} ({SIG_HEADER_SIZE} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

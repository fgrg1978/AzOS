#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""sigalg.py: the signature algorithm of this tree's trust anchors, and the
signed containers, as the build tools write them.

The other half of `crates/core/crypto/src/sig.rs`: the same ids, the same key
and signature lengths, the same `RSIG` and `DSIG` layouts and signed messages.
The algorithm is Ed25519, `SigAlg::CONFIGURED`; a signer for another comes
with its verifier in the crate.

    sigalg.signer(seed_path)             -> Signer (.sign(msg), .public)
    sigalg.rsig(signer, payload, fw)     -> the KERN_x.SIG bytes
    sigalg.dsig(signature)               -> the CAPS.SIG / POLICY.SIG bytes
"""

import hashlib
import struct
import sys
from pathlib import Path

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import azos_tools  # noqa: E402

ROOT = Path(azos_tools.ROOT).resolve()

# name -> (id, key_len, sig_len): SigAlg::id / key_len / sig_len. Ids 2 (ML-DSA-65)
# and 3 (SLH-DSA-SHA2-128s) are reserved; a signer for one comes with its verifier.
ALGS = {"ed25519": (1, 32, 64)}

RSIG_MAGIC = b"RSIG"
RSIG_FIXED_LEN = 48
RSIG_DOMAIN = b"azos-rsig-v2"
DSIG_MAGIC = b"DSIG"


def info(name="ed25519"):
    """`(id, key_len, sig_len)` of `name` (`SigAlg::CONFIGURED`: Ed25519)."""
    return ALGS[name]


class Signer:
    """An Ed25519 private key (a raw 32-byte seed) and its public half."""

    def __init__(self, seed: bytes):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            print("error: install the 'cryptography' package: pip install cryptography", file=sys.stderr)
            sys.exit(1)
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        self.alg = "ed25519"

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def signer(path: Path) -> Signer:
    """Load the private key at `path` (a raw seed)."""
    if not path.is_file():
        print(f"error: private key not found: {path}", file=sys.stderr)
        print("hint: run tools/gen_dev_key.py or tools/gen_test_key.py first.", file=sys.stderr)
        sys.exit(1)
    raw = path.read_bytes()
    if len(raw) != 32:
        print(f"error: {path} is {len(raw)} bytes, want 32 (a raw Ed25519 seed)", file=sys.stderr)
        sys.exit(1)
    return Signer(raw)


def key_id(alg_id: int, key: bytes) -> bytes:
    """`azos_crypto::sig::key_id`: sha256(alg_le16 || key)."""
    return hashlib.sha256(struct.pack("<H", alg_id) + key).digest()


def manifest_message(alg_id: int, fw_version: int, payload_size: int, digest: bytes) -> bytes:
    """`azos_crypto::sig::manifest_message`, byte for byte."""
    assert len(digest) == 32
    return RSIG_DOMAIN + struct.pack("<HII", alg_id, fw_version, payload_size) + digest


def rsig(s: Signer, payload: bytes, fw_version: int) -> bytes:
    """The `RSIG` file of `payload`: what the device reads as KERN_x.SIG."""
    alg_id, key_len, sig_len = info(s.alg)
    assert len(s.public) == key_len
    digest = hashlib.sha256(payload).digest()
    signature = s.sign(manifest_message(alg_id, fw_version, len(payload), digest))
    assert len(signature) == sig_len
    out = (RSIG_MAGIC + struct.pack("<HH", alg_id, sig_len) + key_id(alg_id, s.public)
           + struct.pack("<II", len(payload), fw_version) + signature)
    assert len(out) == RSIG_FIXED_LEN + sig_len
    return out


def dsig(s: Signer, signature: bytes) -> bytes:
    """The `DSIG` file around `signature`: what the device reads as CAPS.SIG."""
    alg_id, _, sig_len = info(s.alg)
    assert len(signature) == sig_len
    return DSIG_MAGIC + struct.pack("<HH", alg_id, sig_len) + signature

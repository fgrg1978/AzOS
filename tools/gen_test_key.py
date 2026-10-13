#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Generate the Ed25519 **TEST** key pair used by the secure-boot CI gate.

Writes:
  tools/keys/test_priv.bin   (32-byte raw seed — gitignored, NEVER committed)
  tools/keys/test_pub.bin    (32-byte raw public key — also gitignored)

# Why this exists at all, and why it generates instead of shipping a key

`crates/core/ota/build.rs` embeds `tools/keys/prod_pub.bin` into the kernel if that
file exists, and silently falls back to an all-zero key if it does not. A zero
key makes `secure_boot_verify_slot_detailed()` return `NoTrustedKey` on its
very first line — before `read_sig_file`, before `sig_parse_header`, before
`sig_verify`. The CI gate that asserted "enforced secure boot refuses to boot"
was therefore passing without the Ed25519 code ever running, and passing for a
*different reason* depending on whether the developer happened to have a
production key sitting in `tools/keys/`. Machine-dependent green is worse than
red: it cannot be reproduced, so it cannot be debugged.

The gate now pins `PROD_PUBKEY_PATH` at this test key, so the outcome is the
same on a fresh clone as on a machine with a real production key installed.

# Why the key pair is generated, not committed

Committing the public half is safe in itself (that is what the note in
`tools/keys/.gitignore` means), but committing *both* halves of a working test
pair is not: any kernel accidentally built against a committed `test_pub.bin`
would trust firmware signed with the matching well-known private key, and the
whole point of secure boot is that no such key exists. Generating a random pair
on demand keeps the secret genuinely secret while still being reproducible in
the only sense that matters for CI — every clone gets a pair whose public half
is embedded in the kernel and whose private half signs the fixture, so every
clone reaches the same verdict.

This script deliberately does NOT touch `prod_pub.bin`: writing there would
silently change the key embedded in every other build on the machine.

# Self-healing

`tools/gen_dev_key.py` refuses to overwrite an existing private key, which is
right for a key a human might care about. This one is different: it keeps an
existing `test_priv.bin` (so the kernel does not need rebuilding on every CI
run) but ALWAYS re-derives `test_pub.bin` from it. A stale or hand-deleted
public half would otherwise surface as `PubkeyMismatch` at boot with no
indication of where the mismatch came from.

Requires the `cryptography` Python package: pip install cryptography
"""

import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("error: install the 'cryptography' package: pip install cryptography",
          file=sys.stderr)
    sys.exit(1)

SEED_LEN = 32

KEY_DIR = Path(__file__).parent / "keys"
PRIV_PATH = KEY_DIR / "test_priv.bin"
PUB_PATH = KEY_DIR / "test_pub.bin"

KEY_DIR.mkdir(exist_ok=True, parents=True)

# Reuse an existing seed when it is intact. Rewriting it on every invocation
# would change the embedded public key, and `crates/core/ota/build.rs` has a
# `rerun-if-changed` on that file — every CI run would rebuild the ota crate
# and everything downstream of it, kernel included, for no benefit.
if PRIV_PATH.exists() and PRIV_PATH.stat().st_size == SEED_LEN:
    priv = Ed25519PrivateKey.from_private_bytes(PRIV_PATH.read_bytes())
    reused = True
else:
    priv = Ed25519PrivateKey.generate()
    PRIV_PATH.write_bytes(priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(PRIV_PATH, 0o600)
    reused = False

pub_raw = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

# Always rewrite the public half — see "Self-healing" above. Skip the write
# when the bytes already match so the file mtime stays put and cargo does not
# rebuild the ota crate for an identical key.
if not (PUB_PATH.exists() and PUB_PATH.read_bytes() == pub_raw):
    PUB_PATH.write_bytes(pub_raw)

print(f"[TESTKEY] private: {PRIV_PATH} ({'reused' if reused else 'generated'}, mode 0600)")
print(f"[TESTKEY] public : {PUB_PATH} ({pub_raw[:4].hex()}...)")

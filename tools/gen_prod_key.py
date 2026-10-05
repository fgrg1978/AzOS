#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""OT05 — Generate the PRODUCTION Ed25519 key pair for secure boot.

This is the production counterpart of `gen_dev_key.py`. Run it ONCE before
the first real deploy. The private key is written to `tools/keys/prod_priv.bin`
and MUST be backed up offline (USB drive, password manager, HSM). If the
private key is lost, signed firmware can no longer be produced — the only
recovery is reflashing the recovery slot.

Outputs:
  tools/keys/prod_priv.bin   (32 bytes raw seed — KEEP SECRET, gitignored)
  tools/keys/prod_pub.bin    (32 bytes raw public key — read by build.rs)

The `crates/core/ota/build.rs` script reads `prod_pub.bin` at compile time and
embeds the bytes into `SECURE_BOOT_PUBKEY`. Without `prod_pub.bin`, the
kernel falls back to the all-zero dev key (BootTrust::Unverified).

Refuses to overwrite an existing `prod_priv.bin` — if you really want to
rotate, delete the file manually first AND ensure all signed firmware in
the field has been rotated to the new key (otherwise rollback breaks).

Requires: pip install cryptography
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

KEY_DIR   = Path(__file__).parent / "keys"
PRIV_PATH = KEY_DIR / "prod_priv.bin"
PUB_PATH  = KEY_DIR / "prod_pub.bin"

KEY_DIR.mkdir(exist_ok=True, parents=True)

if PRIV_PATH.exists():
    print(f"error: {PRIV_PATH} already exists.", file=sys.stderr)
    print("       Delete it manually if you really want to rotate.", file=sys.stderr)
    print("       NOTE: rotating breaks rollback to firmware signed with the old key.",
          file=sys.stderr)
    sys.exit(1)

priv = Ed25519PrivateKey.generate()
priv_raw = priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
pub_raw = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

PRIV_PATH.write_bytes(priv_raw)
os.chmod(PRIV_PATH, 0o600)
PUB_PATH.write_bytes(pub_raw)

print(f"✓ private: {PRIV_PATH} (mode 0600 — BACK THIS UP OFFLINE)")
print(f"✓ public : {PUB_PATH}")
print()
print("Public key (paste into commit message or release notes):")
print("  " + " ".join(f"{b:02x}" for b in pub_raw))
print()
print("Next steps:")
print("  1. Back up prod_priv.bin to an offline location.")
print("  2. Rebuild the kernel — build.rs picks up prod_pub.bin automatically.")
print("  3. Sign firmware images with: tools/sign_ota.py --priv prod_priv.bin <kernel.bin>")

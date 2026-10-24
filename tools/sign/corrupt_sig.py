#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Flip one bit inside the Ed25519 signature of an `RSIG` file.

Usage:
    python3 tools/sign/corrupt_sig.py <in.sig> <out.sig>

# Why a whole tool for one bit flip

The secure-boot CI gate needs a *cryptographic* rejection, not a bookkeeping
one. Deleting the `.SIG` file makes `secure_boot_verify_slot_detailed()` bail at
`read_sig_file` (`SignatureAbsent`); scribbling on the magic makes it bail at
`Rsig::parse` (`SignatureMalformed`); swapping the signer id
makes it bail at the constant-time key comparison (`PubkeyMismatch`). All three
reject, none of them ever calls `sig_verify`, so none of them proves the
Ed25519 verifier does anything at all. Only a signature that is
well-formed, carries the trusted key, and is *mathematically wrong* forces the
verifier to run the point arithmetic and return false — `SignatureInvalid`.

# Why byte 80 specifically

`RSIG` layout (see `tools/sign/sign_ota.py` and `crates/core/crypto/src/sig.rs`):

    0    4   magic "RSIG"
    4    2   algorithm id (1 = Ed25519, the only one signed here)
    6    2   signature length
    8   32   id of the signing key
    40   4   payload size
    44   4   firmware version
    48  64   signature   <- R = [48..80), s = [80..112)

Byte 80 is `s[0]`, the LEAST significant byte of the scalar `s`. Flipping its
low bit keeps `s` far below the group order L, so the signature stays
*canonical* and survives `ed25519_dalek::Signature::from_bytes` and the
strictness checks in `verify_strict`. The rejection therefore comes from the
verification equation itself rather than from an early structural bail-out —
which is precisely the code path the gate is meant to prove is alive.

Flipping a byte of `R` (or the top byte of `s`) would usually work too, but can
land on a non-canonical encoding and be rejected before any curve arithmetic
happens — the same "green for the wrong reason" trap this whole exercise exists
to close.
"""

import sys
from pathlib import Path

# Offsets into the RSIG header — see module docstring.
SIG_MAGIC = b"RSIG"
ALG_ED25519 = 1
SIG_FILE_SIZE = 48 + 64  # an Ed25519 RSIG, 112 bytes
SIG_S_LOW_BYTE_OFFSET = 48 + 32  # = 80, s[0]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    data = bytearray(src.read_bytes())

    # Fail loudly rather than emitting a file that would be rejected as
    # malformed: a "corrupted signature" fixture that never reaches the
    # verifier tests nothing, and would do it quietly.
    if len(data) < SIG_FILE_SIZE:
        print(f"error: {src} is {len(data)} bytes, need at least {SIG_FILE_SIZE}",
              file=sys.stderr)
        return 1
    if bytes(data[0:4]) != SIG_MAGIC:
        print(f"error: {src} does not start with {SIG_MAGIC!r}", file=sys.stderr)
        return 1
    if int.from_bytes(data[4:6], "little") != ALG_ED25519:
        print(f"error: {src} is not an Ed25519 RSIG; the s[0] flip is Ed25519's", file=sys.stderr)
        return 1

    data[SIG_S_LOW_BYTE_OFFSET] ^= 0x01
    dst.write_bytes(bytes(data))

    print(f"[CORRUPT] {src} -> {dst}: flipped bit 0 of byte "
          f"{SIG_S_LOW_BYTE_OFFSET} (s[0]) — signature stays canonical, "
          f"verification must fail")
    return 0


if __name__ == "__main__":
    sys.exit(main())

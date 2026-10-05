#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Flip one bit inside the Ed25519 signature of an `RSIG` file.

Usage:
    python3 tools/corrupt_sig.py <in.sig> <out.sig>

# Why a whole tool for one bit flip

The secure-boot CI gate needs a *cryptographic* rejection, not a bookkeeping
one. Deleting the `.SIG` file makes `secure_boot_verify_slot_detailed()` bail at
`read_sig_file` (`SignatureAbsent`); scribbling on the magic makes it bail at
`sig_parse_header` (`SignatureMalformed`); swapping the embedded public key
makes it bail at the constant-time key comparison (`PubkeyMismatch`). All three
reject, none of them ever calls `sig_verify`, so none of them proves the
Ed25519 verifier does anything at all. Only a signature that is
well-formed, carries the trusted key, and is *mathematically wrong* forces the
verifier to run the point arithmetic and return false — `SignatureInvalid`.

# Why byte 69 specifically

`RSIG` layout (see `tools/sign_ota.py` and `crates/core/crypto/src/ed25519.rs`):

    0    4   magic "RSIG"
    4    1   algorithm (1 = manifest-v1; the only one the kernel parses)
    5   32   public key
    37  64   signature   <- R = [37..69), s = [69..101)
    101  4   payload size
    105  4   firmware version

Byte 69 sits inside the signature regardless of header version — the
manifest-v1 header (109 bytes, with the trailing `fw_version` field) is
longer than the legacy 105-byte one this offset was first written against,
but the signature field itself did not move.

Byte 69 is `s[0]`, the LEAST significant byte of the scalar `s`. Flipping its
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
SIG_HEADER_SIZE = 4 + 1 + 32 + 64 + 4 + 4  # manifest-v1, 109 bytes
SIG_S_LOW_BYTE_OFFSET = 37 + 32  # = 69, s[0]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    data = bytearray(src.read_bytes())

    # Fail loudly rather than emitting a file that would be rejected as
    # malformed: a "corrupted signature" fixture that never reaches the
    # verifier tests nothing, and would do it quietly.
    if len(data) < SIG_HEADER_SIZE:
        print(f"error: {src} is {len(data)} bytes, need at least {SIG_HEADER_SIZE}",
              file=sys.stderr)
        return 1
    if bytes(data[0:4]) != SIG_MAGIC:
        print(f"error: {src} does not start with {SIG_MAGIC!r}", file=sys.stderr)
        return 1

    data[SIG_S_LOW_BYTE_OFFSET] ^= 0x01
    dst.write_bytes(bytes(data))

    print(f"[CORRUPT] {src} -> {dst}: flipped bit 0 of byte "
          f"{SIG_S_LOW_BYTE_OFFSET} (s[0]) — signature stays canonical, "
          f"verification must fail")
    return 0


if __name__ == "__main__":
    sys.exit(main())

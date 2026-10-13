#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""gen_config_sig.py — W2-B5: sign CONFIG.INI (or any topology-format file)
with the shared topology/config Ed25519 key.

# Why this exists

U10-2 (audit unit 10, 2026-09-25): CONFIG.INI lives on the USB-exposed FAT
volume and, unsigned, decides whether the kill switch is armed
(`estop_gpio_pin`), whether the brain link is encrypted (`link_encrypt`),
whether an OTA listener spawns at boot (`ota_auto_recv_port`), whether the
board halts into a synthetic-bench loop instead of booting (`bench_boot`),
and which ELF `autorun=` hands the drivetrain to. `crates/core/topology/src/verify.rs`
already has real Ed25519 verification for `CAPS.TOML`/`SCHED.TOML` — a bare
64-byte raw signature over the file's exact bytes, checked against
`crates/core/topology`'s embedded `TRUSTED_PUBKEY` — but nothing signed CONFIG.INI
with that same mechanism until now. `crates/core/config/src/signed.rs`
(`cfg_load_verified`) is the kernel-side half: it never calls `cfg_load` on
untrusted bytes, only on bytes whose `.SIG` sidecar verified.

# The signature format — deliberately NOT `tools/sign_ota.py`'s RSIG format

`sign_ota.py` writes a 105-byte header (magic + algorithm + embedded pubkey +
signature + payload size) because a firmware image's `.SIG` travels with no
other context. Topology's `.SIG` sidecars carry only the bare 64-byte
signature — see `crates/core/topology/src/verify.rs`'s `ED25519_SIGNATURE_SIZE`
check and `tools/corrupt_sig.py`'s header table, which is `sign_ota.py`'s,
NOT this one. This script writes the topology-shaped sidecar: exactly 64
raw bytes, nothing else. Do not point `tools/corrupt_sig.py` at a file this
script produced — its byte offsets are for the OTA RSIG header.

# Key

Reuses `tools/keys/test_priv.bin` (default) — the same on-demand-generated
Ed25519 pair `tools/gen_test_key.py` produces for the secure-boot CI gate,
and the same one `crates/core/topology/build.rs` embeds as `TRUSTED_PUBKEY` by
default (its public half, `tools/keys/test_pub.bin`). Run
`tools/gen_test_key.py` first if `test_priv.bin` does not exist yet.

Usage:
    python3 tools/gen_config_sig.py <file> [--priv tools/keys/test_priv.bin] [--out <file>.SIG]
    python3 tools/gen_config_sig.py CONFIG.INI --config-v2 --counter N \
        (--device-id <32 hex> | --image <disk image>) --out CONFIG.SIG

# CONFIG.SIG is format v2 (wave 11, RFC-0054 finding 7)

A bare signature over the file's bytes can be replayed: an older, validly
signed CONFIG.INI (one with `link_encrypt` off, say) copied onto the same
device, or onto any device sharing the key, verifies. `--config-v2` binds the
signature to one device and to a counter the kernel never lets go backwards
(the device record in reserved tail sector 2, `tools/device_provision.py`):

    0   4   magic "KCFG"
    4   1   version 2
    5   3   zero
    8  16   device id
    24  8   counter, u64 little-endian, >= 1
    32 64   Ed25519 signature over
            "AZOS-CFG-SIG-v02" || device id || counter (LE) || SHA-256(file)

The kernel refuses a bare 64-byte CONFIG.SIG (v1), a counter below the floor
it recorded, and a device id that is not its own. The ML data sidecars
(MLP.SIG, POLICY.SIG) stay bare 64-byte signatures: this flag is for
CONFIG.INI only. `--image` reads the device id from a provisioned image.

Signs <file>'s exact current bytes and writes the 64-byte raw signature to
<file>.SIG (or --out). Exits 1 with a message on stderr if the private key
is missing or the wrong size — never silently signs with a placeholder.

# If the output ever lands on a FAT32 volume: mind 8.3

The default `<file>.SIG` naming is fine for a host-side build artifact, but
if the SIGNED file's own name already has a dot (`CONFIG.INI`, `CAPS.TOML`),
appending `.SIG` produces a name with TWO dots — not a valid FAT 8.3 short
name (one dot; base <=8 chars; extension <=3 chars). `crates/fs/fs/src/fat32.rs`
has no VFAT/long-filename support, so `azos_fs::vfs_open` can only ever
find a file by its exact 8.3 short name; `mkfs.fat`/`mcopy` silently mangle
a two-dot name into an auto-generated short name instead (verified: writing
"CONFIG.INI.SIG" lands as "CONFIG~1.SIG" on disk, not the literal string).
For anything this script signs that will be `mcopy`'d onto a board/QEMU disk
image, always pass `--out` with a real 8.3 name that shares the signed
file's BASE name under a different extension — e.g. `--out CONFIG.SIG` for
`CONFIG.INI` (mirrors the existing `KERN_A.BIN`/`KERN_A.SIG` pair) — rather
than relying on the `<file>.SIG` default.
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("error: install the 'cryptography' package: pip install cryptography",
          file=sys.stderr)
    sys.exit(1)

SEED_LEN = 32
SIGNATURE_LEN = 64
DEVICE_ID_LEN = 16
CONFIG_SIG_MAGIC = b"KCFG"
CONFIG_SIG_DOMAIN = b"AZOS-CFG-SIG-v02"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("file", type=Path, help="File to sign (e.g. CONFIG.INI)")
    p.add_argument(
        "--priv",
        type=Path,
        default=Path(__file__).parent / "keys" / "test_priv.bin",
        help="Ed25519 private key (raw 32-byte seed). Default: tools/keys/test_priv.bin",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output .SIG path. Default: <file>.SIG",
    )
    p.add_argument("--config-v2", action="store_true",
                   help="write a CONFIG.SIG v2 sidecar (device id + counter)")
    p.add_argument("--counter", type=int, default=None, help="v2: counter (>= 1)")
    p.add_argument("--device-id", default=None, help="v2: device id, 32 hex digits")
    p.add_argument("--image", type=Path, default=None,
                   help="v2: read the device id from this provisioned disk image")
    args = p.parse_args()

    if not args.file.is_file():
        print(f"error: {args.file} is not a file", file=sys.stderr)
        return 1

    if not args.priv.is_file():
        print(
            f"error: private key {args.priv} not found — run "
            f"tools/gen_test_key.py first (or pass --priv)",
            file=sys.stderr,
        )
        return 1
    seed = args.priv.read_bytes()
    if len(seed) != SEED_LEN:
        print(
            f"error: {args.priv} is {len(seed)} bytes, want {SEED_LEN} "
            f"(a raw Ed25519 seed, not a PEM/DER file)",
            file=sys.stderr,
        )
        return 1

    priv = Ed25519PrivateKey.from_private_bytes(seed)
    payload = args.file.read_bytes()

    if args.config_v2:
        if args.counter is None or args.counter < 1 or args.counter >= 1 << 64:
            print("error: --config-v2 needs --counter N with 1 <= N < 2^64", file=sys.stderr)
            return 1
        if (args.device_id is None) == (args.image is None):
            print("error: --config-v2 needs exactly one of --device-id, --image", file=sys.stderr)
            return 1
        if args.image is not None:
            sys.path.insert(0, str(Path(__file__).parent))
            import device_provision
            rec = device_provision.read_record(str(args.image))
            if rec is None:
                print(f"error: {args.image} carries no device record "
                      "(tools/device_provision.py first)", file=sys.stderr)
                return 1
            device_id = rec[0]
        else:
            try:
                device_id = bytes.fromhex(args.device_id)
            except ValueError:
                device_id = b""
        if len(device_id) != DEVICE_ID_LEN:
            print(f"error: the device id must be {DEVICE_ID_LEN} bytes", file=sys.stderr)
            return 1
        counter = struct.pack("<Q", args.counter)
        message = CONFIG_SIG_DOMAIN + device_id + counter + hashlib.sha256(payload).digest()
        signature = priv.sign(message)
        assert len(signature) == SIGNATURE_LEN
        sidecar = CONFIG_SIG_MAGIC + bytes([2, 0, 0, 0]) + device_id + counter + signature
        assert len(sidecar) == 96
        out_path = args.out or args.file.with_name(args.file.name + ".SIG")
        out_path.write_bytes(sidecar)
        print(
            f"[SIGN] {args.file} ({len(payload)} bytes) -> {out_path} "
            f"(CONFIG.SIG v2, device {device_id.hex()}, counter {args.counter}, key {args.priv})"
        )
        return 0

    signature = priv.sign(payload)
    assert len(signature) == SIGNATURE_LEN, (
        f"internal error: Ed25519 signature was {len(signature)} bytes, "
        f"expected {SIGNATURE_LEN}"
    )

    out_path = args.out or args.file.with_name(args.file.name + ".SIG")
    out_path.write_bytes(signature)

    print(
        f"[SIGN] {args.file} ({len(payload)} bytes) -> {out_path} "
        f"({SIGNATURE_LEN}-byte raw Ed25519 signature, key {args.priv})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

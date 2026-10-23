#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""F18 — Sign an OTA kernel image.

Reads the raw kernel .BIN and writes a matching .SIG file: the `RSIG`
container of `crates/core/crypto/src/sig.rs` (`tools/sigalg.py` is its Python
half). The algorithm is Ed25519 (`SigAlg::CONFIGURED`); the layout is

    Offset  Size  Field
    0       4     magic "RSIG"
    4       2     algorithm id (1 = Ed25519)
    6       2     signature length
    8       32    id of the signing key: sha256(alg_le16 || public key)
    40      4     payload size (u32 LE)
    44      4     firmware version (u32 LE)
    48      n     signature

Total = 48 + signature length (112 bytes for Ed25519).

## Manifest binding

The signature does NOT cover the raw image bytes. It covers a fixed manifest

    "azos-rsig-v2" || alg(2, LE) || fw_version(4, LE) || payload_size(4, LE)
        || sha256(image)(32)

binding the algorithm and the firmware version into the signed material. The
OTA anti-rollback floor compares `min_fw_version` against the version inside
the signature, never the one in the UNSIGNED 24-byte wire header
(`crates/core/ota/src/pure.rs::OtaHeader`), which any sender could set to
anything for a genuinely-signed old image.

Usage:
    python3 tools/sign_ota.py path/to/kernel.bin --fw-version 42 \\
        [--priv tools/keys/dev_priv.bin]

Outputs:
    path/to/kernel.sig  (same basename, .sig extension)

## Whole-system update bundle

    python3 tools/sign_ota.py bundle OUT.AZU --epoch 5 --fw-version 42 \\
        --kernel kernel.bin --caps CAPS.TOM --caps-sig CAPS.SIG \\
        --sched SCHED.TOM --config CONFIG.INI [--config-sig CONFIG.SIG] \\
        [--image BRAIN.ELF ...] [--platform qemu|vf2|k1] [--priv KEY]

One signed manifest over the kernel (and its `.sig`, made here with the same key
unless `--kernel-sig` names one), the topology, the configuration and the
userspace images, followed by the parts: the file `pkg update` hands to the
installer (`crates/core/ota/src/update.rs` has the wire form). `--epoch` is the
anti-rollback floor of the whole system: a device that has confirmed epoch N
refuses a bundle below N. The signature is over a domain tag and the manifest
body, so it is never also valid as a kernel signature or a package signature.
"""

import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import azos_tools  # noqa: E402
import sigalg  # noqa: E402


def load_key(path: Path) -> sigalg.Signer:
    return sigalg.signer(path)


def kernel_sig(priv: sigalg.Signer, image: bytes, fw_version: int) -> bytes:
    """The `.sig` file of a kernel image: the `RSIG` container."""
    return sigalg.rsig(priv, image, fw_version)


# ── Whole-system update bundle (crates/core/ota/src/update.rs) ───────────────

UPDATE_MAGIC = b"AZUM"
UPDATE_FORMAT = 1
UPDATE_DOMAIN = b"AZOS-SYSUPDATE-V1\0"
UPDATE_MAX_PARTS = 32
KIND_KERNEL, KIND_KERNEL_SIG, KIND_TOPOLOGY, KIND_CONFIG, KIND_IMAGE = 1, 2, 3, 4, 5
PLATFORMS = {"qemu": 0, "vf2": 1, "k1": 2}
NAME_RE = re.compile(r"^[A-Z0-9_]{1,8}(\.[A-Z0-9_]{1,3})?$")


def build_bundle(priv: sigalg.Signer, epoch: int, fw_version: int, platform: int,
                 parts: list) -> bytes:
    """The bundle: manifest (signed) then the parts' bytes in table order.

    `parts` is a list of (kind, name, bytes). Must match `Manifest::parse`
    byte-for-byte; the host suite (tests/host/pkg-tests) feeds this output to the
    installer."""
    if len(parts) > UPDATE_MAX_PARTS:
        raise ValueError(f"at most {UPDATE_MAX_PARTS} parts")
    body = bytearray()
    body += UPDATE_MAGIC
    alg_id, _, sig_len = sigalg.info(priv.alg)
    body += struct.pack("<HHIIB3xHH", UPDATE_FORMAT, alg_id, epoch, fw_version, platform, len(parts), sig_len)
    for kind, name, data in parts:
        if not NAME_RE.match(name):
            raise ValueError(f"{name!r} is not an upper-case 8.3 name")
        if not data:
            raise ValueError(f"{name} is empty")
        body += struct.pack("<B3xI12s", kind, len(data), name.encode())
        body += hashlib.sha256(data).digest()
    signature = priv.sign(UPDATE_DOMAIN + bytes(body))
    assert len(signature) == sig_len
    out = bytes(body) + signature
    for _, _, data in parts:
        out += data
    return out


def bundle_main(argv: list) -> int:
    p = argparse.ArgumentParser(prog="sign_ota.py bundle")
    p.add_argument("out", type=Path, help="bundle to write")
    p.add_argument("--epoch", type=int, required=True, help="anti-rollback epoch of the whole system")
    p.add_argument("--fw-version", type=int, required=True, help="kernel firmware version")
    p.add_argument("--platform", choices=PLATFORMS, default="qemu")
    p.add_argument("--kernel", type=Path, required=True)
    p.add_argument("--kernel-sig", type=Path, default=None, help="default: made here with --priv")
    p.add_argument("--caps", type=Path, required=True, help="CAPS.TOM")
    p.add_argument("--caps-sig", type=Path, required=True, help="CAPS.SIG")
    p.add_argument("--sched", type=Path, required=True, help="SCHED.TOM")
    p.add_argument("--config", type=Path, required=True, help="CONFIG.INI")
    p.add_argument("--config-sig", type=Path, default=None, help="CONFIG.SIG")
    p.add_argument("--image", type=Path, action="append", default=[], help="a userspace program, NAME.ELF")
    p.add_argument("--priv", type=Path, default=Path(azos_tools.ROOT) / "tools/keys/dev_priv.bin")
    a = p.parse_args(argv)

    for v in (a.epoch, a.fw_version):
        if not 0 <= v <= 0xFFFF_FFFF:
            print("error: --epoch and --fw-version must fit in a u32", file=sys.stderr)
            return 1
    priv = load_key(a.priv)
    kernel = a.kernel.read_bytes()
    ksig = a.kernel_sig.read_bytes() if a.kernel_sig else kernel_sig(priv, kernel, a.fw_version)
    parts = [
        (KIND_KERNEL, "KERN.BIN", kernel),
        (KIND_KERNEL_SIG, "KERN.SIG", ksig),
        (KIND_TOPOLOGY, "CAPS.TOM", a.caps.read_bytes()),
        (KIND_TOPOLOGY, "CAPS.SIG", a.caps_sig.read_bytes()),
        (KIND_TOPOLOGY, "SCHED.TOM", a.sched.read_bytes()),
        (KIND_CONFIG, "CONFIG.INI", a.config.read_bytes()),
    ]
    if a.config_sig:
        parts.append((KIND_CONFIG, "CONFIG.SIG", a.config_sig.read_bytes()))
    for img in a.image:
        parts.append((KIND_IMAGE, img.name.upper(), img.read_bytes()))
    try:
        data = build_bundle(priv, a.epoch, a.fw_version, PLATFORMS[a.platform], parts)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    a.out.write_bytes(data)
    print(f"✓ bundle {a.out} ({len(data)} bytes, {len(parts)} parts, epoch={a.epoch}, fw_version={a.fw_version})")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "bundle":
        return bundle_main(sys.argv[2:])
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
        default=Path(azos_tools.ROOT) / "tools/keys/dev_priv.bin",
        help="private key of the configured algorithm (Ed25519: a raw 32-byte seed)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output .sig path (default: <image>.sig replacing .bin extension)",
    )
    args = p.parse_args()

    if args.fw_version < 0 or args.fw_version > 0xFFFF_FFFF:
        print("error: --fw-version must fit in a u32", file=sys.stderr)
        return 1

    priv = load_key(args.priv)
    image = args.image.read_bytes()
    header = kernel_sig(priv, image, args.fw_version)
    digest = hashlib.sha256(image).digest()

    out = args.out
    if out is None:
        out = args.image.with_suffix(".sig")
    out.write_bytes(bytes(header))

    print(f"✓ signed {args.image} ({len(image)} bytes, fw_version={args.fw_version})")
    print(f"  sha256 : {digest.hex()}")
    print(f"  sig out: {out} ({len(header)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

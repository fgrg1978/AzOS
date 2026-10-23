#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""mk_ucode.py: the signed microcode image the x86 kernel loads at boot
(Kconfig X86_UCODE_LOAD; the format is crates/core/arch-x86_64/src/cpu/ucode.rs).

    UCODE.BIN = RSIG (tools/sigalg.py, by the update key) || payload
    payload   = "AZUCODE\\0" | version 1 (u32) | sections (u32)
                then per section: tag (4) | body length (u32) | 8 zero bytes |
                body | zero padding to 16 bytes
    sections  = "INTL": the Intel files (intel-ucode/), concatenated
                "AMDC": the AMD containers (microcode_amd*.bin), concatenated

The vendors' files are read where they were downloaded (AZOS_DL, see
mk/firmware.mk), never committed. Each Intel update and AMD container is
walked once here, so a truncated download fails the build, not the boot.

    python3 tools/mk_ucode.py --out UCODE.BIN --priv KEY \\
        [--intel FILE ...] [--amd FILE ...] [--fw-version N]
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import sigalg  # noqa: E402

MAGIC = b"AZUCODE\0"
VERSION = 1
TAG_INTEL = b"INTL"
TAG_AMD = b"AMDC"
AMD_MAGIC = 0x00414D44


def intel_updates(data: bytes, name: str) -> int:
    """The updates in one intel-ucode file (header version 1, sizes that fit)."""
    off, n = 0, 0
    while off < len(data):
        if len(data) - off < 48:
            raise SystemExit(f"error: {name}: {len(data) - off} trailing bytes after update {n}")
        hdrver, = struct.unpack_from("<I", data, off)
        datasize, totalsize = struct.unpack_from("<II", data, off + 28)
        if datasize == 0:
            totalsize = 2048
        if hdrver != 1 or totalsize < 48 or off + totalsize > len(data):
            raise SystemExit(f"error: {name}: update {n} at {off:#x} is malformed")
        off += totalsize
        n += 1
    return n


def amd_containers(data: bytes, name: str) -> int:
    """The containers in one microcode_amd*.bin (magic, equivalence table, patch sections)."""
    off, n = 0, 0
    while off < len(data):
        magic, kind, eq = struct.unpack_from("<III", data, off)
        if magic != AMD_MAGIC or kind != 0 or off + 12 + eq > len(data):
            raise SystemExit(f"error: {name}: container {n} at {off:#x} is malformed")
        off += 12 + eq
        while off + 8 <= len(data) and struct.unpack_from("<I", data, off)[0] == 1:
            off += 8 + struct.unpack_from("<I", data, off + 4)[0]
        if off > len(data):
            raise SystemExit(f"error: {name}: container {n} runs past the end")
        n += 1
    return n


def payload(sections: list) -> bytes:
    out = bytearray(MAGIC + struct.pack("<II", VERSION, len(sections)))
    for tag, body in sections:
        out += tag + struct.pack("<I", len(body)) + bytes(8) + body
        out += bytes(-len(out) % 16)
    return bytes(out)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--priv", type=Path, required=True, help="the update key's private half (raw Ed25519 seed)")
    p.add_argument("--intel", type=Path, nargs="*", default=[], help="intel-ucode files")
    p.add_argument("--amd", type=Path, nargs="*", default=[], help="microcode_amd*.bin containers")
    p.add_argument("--fw-version", type=int, default=0, help="the RSIG's signed version")
    a = p.parse_args()
    sections, counts = [], []
    if a.intel:
        files = sorted(a.intel)
        body = b"".join(f.read_bytes() for f in files)
        counts.append(f"{sum(intel_updates(f.read_bytes(), f.name) for f in files)} Intel updates")
        sections.append((TAG_INTEL, body))
    if a.amd:
        files = sorted(a.amd)
        body = b"".join(f.read_bytes() for f in files)
        counts.append(f"{sum(amd_containers(f.read_bytes(), f.name) for f in files)} AMD containers")
        sections.append((TAG_AMD, body))
    if not sections:
        raise SystemExit("error: no --intel or --amd file: nothing to load")
    body = payload(sections)
    signer = sigalg.signer(a.priv)
    a.out.write_bytes(sigalg.rsig(signer, body, a.fw_version) + body)
    print(f"[UCODE] {a.out}: {', '.join(counts)}, {len(body)} payload bytes, signed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

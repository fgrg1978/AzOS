#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Check the Linux boot Image header a flat kernel binary opens with.

    tools/gate/image_header.py <rv|arm> <kernel ELF> <flat binary>

The flat binary (`objcopy -O binary` of the ELF) is what U-Boot `booti` and
QEMU's `-kernel` loader take as an Image. They read the 64-byte header at its
offset 0 (Documentation/arch/riscv/boot-image-header.rst,
Documentation/arch/arm64/booting.rst): the magic at 0x38 (riscv64: "RSC\\x05";
`booti` prints "Bad Linux RISCV Image magic!" without it), image_size at 0x10
(`booti` refuses 0) and text_offset at 0x08 (the image is placed at the start
of RAM plus this). Each field is checked against the ELF, not against the
linker's own arithmetic:

  * code0 is a jump/branch to offset 64, the first byte after the header;
  * image_size == _kernel_end - _start;
  * _dram_base + text_offset == the load address of the binary's first byte
    (the lowest PT_LOAD physical address), so the loader puts the image where
    it is linked.

Exit 0 when all hold, 1 with one line per failure.
"""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../dev/farm"))
from farm_elf import ElfError, symbols  # noqa: E402

PT_LOAD = 1
MAGIC = {"rv": (0x38, b"RSC\x05"), "arm": (0x38, b"ARM\x64")}
HEADER_LEN = 64


def first_load_paddr(path: str) -> int:
    with open(path, "rb") as f:
        data = f.read()
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    loads = []
    for i in range(phnum):
        kind, _flags, _off, _vaddr, paddr, filesz, _memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * phentsize)
        if kind == PT_LOAD and filesz:
            loads.append(paddr)
    if not loads:
        raise ElfError(f"{path}: no loadable segment")
    return min(loads)


def code0_target(isa: str, word: int) -> int | None:
    """The byte offset code0 jumps to, None when it is not a jump."""
    if isa == "rv":
        if word & 0xFFF != 0x06F:  # jal x0 (`j`)
            return None
        imm = ((word >> 31) & 1) << 20 | ((word >> 12) & 0xFF) << 12 | ((word >> 20) & 1) << 11 \
            | ((word >> 21) & 0x3FF) << 1
        return imm - (1 << 21) if imm & (1 << 20) else imm
    if word >> 26 != 0b000101:  # b
        return None
    imm = word & 0x3FFFFFF
    return (imm - (1 << 26) if imm & (1 << 25) else imm) * 4


def check(isa: str, elf: str, image: str) -> list[str]:
    with open(image, "rb") as f:
        head = f.read(HEADER_LEN)
    if len(head) < HEADER_LEN:
        return [f"{image}: {len(head)} bytes, shorter than the {HEADER_LEN}-byte header"]
    bad = []
    at, magic = MAGIC[isa]
    if head[at:at + len(magic)] != magic:
        bad.append(f"magic at {at:#x} is {head[at:at + len(magic)].hex()}, want {magic.hex()}")
    word, = struct.unpack_from("<I", head, 0)
    target = code0_target(isa, word)
    if target != HEADER_LEN:
        bad.append(f"code0 {word:#010x} jumps to {target}, want {HEADER_LEN} (past the header)")
    text_offset, image_size = struct.unpack_from("<QQ", head, 0x08)
    syms = symbols(elf)
    missing = [s for s in ("_start", "_kernel_end", "_dram_base") if s not in syms]
    if missing:
        return bad + [f"{elf}: no symbol {', '.join(missing)}"]
    want_size = syms["_kernel_end"] - syms["_start"]
    if image_size == 0 or image_size != want_size:
        bad.append(f"image_size {image_size:#x}, want _kernel_end - _start = {want_size:#x}")
    load = first_load_paddr(elf)
    if syms["_dram_base"] + text_offset != load:
        bad.append(f"_dram_base {syms['_dram_base']:#x} + text_offset {text_offset:#x} != load address {load:#x}")
    return bad


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] not in MAGIC:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    try:
        bad = check(argv[1], argv[2], argv[3])
    except (OSError, ElfError, struct.error) as e:
        bad = [str(e)]
    for line in bad:
        print(line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""How many tests a kernel image holds: its `azos_ktest` registry.

The linker script brackets the section with `__start_azos_ktest` /
`__stop_azos_ktest` (crates/core/ktest) and an entry is 32 bytes on a 64-bit
target, so the count is `(end - start) / 32`: the plan a clean boot must print.
The gate keeps that number by hand (KTEST_N_RV); a board image has its own
feature set (no `qemu`, `chaos` and `decisions` only if its config says so), so
the farm reads it off the image it built. ELF64 little-endian only, which is
every ISA this tree builds.
"""

from __future__ import annotations

import struct

KTEST_ENTRY_BYTES = 32
SHT_SYMTAB = 2


class ElfError(Exception):
    pass


def symbols(path: str) -> dict:
    """name -> value of the ELF64-LE file's symbol table."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or len(data) < 64 or data[4] != 2 or data[5] != 1:
        raise ElfError(f"{path}: not an ELF64 little-endian file")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    for (_n, kind, _fl, _addr, off, size, link, _info, _al, entsize) in sections:
        if kind != SHT_SYMTAB:
            continue
        strtab = sections[link]
        stroff = strtab[4]
        out = {}
        for i in range(size // (entsize or 24)):
            name, _info2, _other, _shndx, value, _sz = struct.unpack_from("<IBBHQQ", data, off + i * (entsize or 24))
            end = data.index(b"\0", stroff + name)
            out[data[stroff + name:end].decode("ascii", "replace")] = value
        return out
    raise ElfError(f"{path}: no symbol table (a stripped image?)")


def registry_count(path: str) -> int:
    syms = symbols(path)
    try:
        span = syms["__stop_azos_ktest"] - syms["__start_azos_ktest"]
    except KeyError:
        raise ElfError(f"{path}: no __start_azos_ktest/end: built without the ktest feature") from None
    if span < 0 or span % KTEST_ENTRY_BYTES:
        raise ElfError(f"{path}: the ktest registry spans {span} bytes, not a multiple of {KTEST_ENTRY_BYTES}")
    return span // KTEST_ENTRY_BYTES

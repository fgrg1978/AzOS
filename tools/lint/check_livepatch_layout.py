#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Live-update build hooks: the linker scripts and a linked kernel against
the Kconfig (config/kernel/Kconfig.livepatch, "Live-update build hooks").

  check_livepatch_layout.py scripts
      every kernel linker script (arch/*/boot/linker*.ld) defines
      `.text.patch_pool` with __patch_pool_start/_end and `.azos_patch` with
      __azos_patch_start/_end, and the pool lies before `_text_end` where
      the script has one (so the W^X and no-exec-outside-the-image checks
      cover it).

  check_livepatch_layout.py elf <kernel.elf> <.config> [llvm-nm]
      the four symbols exist, __patch_pool_end - __patch_pool_start is
      exactly LIVEPATCH_POOL_KIB KiB, the pool is inside [_text_start,
      _text_end], and a table the build filled holds whole 8-byte entries.
      With CONFIG_LIVEPATCH=y also: how many `.azos_patch` entries hold the
      entry slot the redirect overwrites (the ISA's, a 4-aligned part of it
      on riscv64), that `livepatch_probe_target` is one of them, and the
      kernel build-id.

  check_livepatch_layout.py build-id <kernel.elf> [llvm-nm]
      the kernel build-id a patch is bound to: SHA-256 of
      [_text_start, _text_end) as linked (what the kernel computes at boot,
      kernel/src/boot/isa.rs), 64 hex digits; a `[livepatch.NAME]` row pins
      16 to 64 of the leading digits.

Exit 0 when everything holds, 1 with one line per failure otherwise.
"""
import glob
import hashlib
import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = azos_tools.ROOT
SITE_BYTES = 8  # azos_arch_api::isa::PATCH_SITE_BYTES


def check_scripts() -> list[str]:
    bad: list[str] = []
    scripts = sorted(glob.glob(os.path.join(ROOT, "arch", "*", "boot", "linker*.ld")))
    for path in scripts:
        name = os.path.relpath(path, ROOT)
        src = re.sub(r"/\*.*?\*/", "", open(path, encoding="utf-8").read(), flags=re.S)
        for needle in (".text.patch_pool", "__patch_pool_start = .", "__patch_pool_end = .",
                       ".azos_patch", "__azos_patch_start = .", "__azos_patch_end = .",
                       "__patch_pool_bytes", ".patch_pool_anchor"):
            if needle not in src:
                bad.append(f"{name}: missing `{needle}`")
        pool, text_end = src.find("__patch_pool_end = ."), src.find("_text_end = .")
        if text_end >= 0 and 0 <= pool and pool > text_end:
            bad.append(f"{name}: the patch pool is after _text_end (outside the text range)")
    # The list is derived (every arch/*/boot/linker*.ld),
    # so a new script is checked, not counted.
    if len(scripts) < 2:
        bad.append(f"expected the kernel linker scripts, found {len(scripts)}")
    return bad


def config_int(path: str, key: str) -> int:
    for line in open(path, encoding="utf-8"):
        if line.startswith(f"{key}="):
            return int(line.split("=", 1)[1].strip(), 0)
    return 0


class Image:
    """The loadable bytes of an ELF64 little-endian kernel, by virtual
    address: what the CPU sees once the segments are placed (the part of a
    segment past its file size is zero)."""

    EM_X86_64, EM_RISCV, EM_AARCH64 = 62, 243, 183

    def __init__(self, path: str) -> None:
        self.data = open(path, "rb").read()
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
            raise ValueError(f"{os.path.basename(path)}: not an ELF64 little-endian file")
        self.machine = struct.unpack_from("<H", d, 18)[0]
        phoff, = struct.unpack_from("<Q", d, 32)
        phentsize, phnum = struct.unpack_from("<HH", d, 54)
        self.segs = []
        for i in range(phnum):
            p_type, _flags, off, vaddr, _paddr, filesz, memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", d, phoff + i * phentsize)
            if p_type == 1 and memsz:
                self.segs.append((vaddr, off, filesz, memsz))

    def read(self, va: int, n: int) -> bytes:
        """`n` bytes at `va`, across segments. Past a segment's file bytes, up
        to its last page, the loader leaves zeros (the tail of the page, and a
        pool that is all zero)."""
        out = bytearray()
        while len(out) < n:
            at = va + len(out)
            # A segment holding the address; failing that, the zero tail of
            # the last page of one that ends before it.
            seg = next((g for g in self.segs if g[0] <= at < g[0] + g[3]), None)
            if seg is not None:
                vaddr, off, filesz, memsz = seg
                take = min(n - len(out), vaddr + memsz - at)
            else:
                seg = next((g for g in self.segs if g[0] <= at < ((g[0] + g[3] + 0xfff) & ~0xfff)), None)
                if seg is None:
                    raise ValueError(f"address {at:#x} is in no loadable segment")
                vaddr, off, filesz, memsz = seg
                take = min(n - len(out), ((vaddr + memsz + 0xfff) & ~0xfff) - at)
            have = max(0, min(take, filesz - (at - vaddr)))
            start = off + (at - vaddr)
            out += self.data[start:start + have] + bytes(take - have)
        return bytes(out)


def build_id(img: Image, sym: dict) -> str:
    return hashlib.sha256(img.read(sym["_text_start"], sym["_text_end"] - sym["_text_start"])).hexdigest()


# The entry slot -Z patchable-function-entry leaves, per e_machine, and the
# redirect inside it (azos_mm::text_poke::patch::{site, entry_is_slot}): one
# aarch64 nop; on riscv64 a nop or two c.nops at the first 4-aligned address of
# the slot (a function is 2-aligned, so the slot may start with one c.nop that
# falls into the jal); on x86_64 the five-byte nopl disp8(%rax,%rax).
def entry_patchable(img: "Image", va: int) -> bool:
    if img.machine == Image.EM_AARCH64:
        return va % 4 == 0 and img.read(va, 4) == bytes.fromhex("1f2003d5")
    if img.machine == Image.EM_RISCV:
        lead = (-va) % 4
        b = img.read(va, lead + 4)
        return b[:lead] in (b"", b"\x01\x00") and b[lead:] in (bytes.fromhex("13000000"), bytes.fromhex("01000100"))
    if img.machine == Image.EM_X86_64:
        return img.read(va, 4) == bytes.fromhex("0f1f4400")  # nopl disp8(%rax,%rax)
    return False


def symbols(elf: str, nm: str) -> dict:
    out = subprocess.run([nm, elf], capture_output=True, text=True, check=True).stdout
    sym = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            sym[parts[2]] = int(parts[0], 16)
    return sym


def check_sites(img: Image, sym: dict) -> tuple[int, int, list[str]]:
    """(entries, patchable entries, failures): an entry that is not patchable is
    a function that cannot be replaced (a riscv64 entry with too few nops, say),
    not an error; the one function the image must be able to replace is the
    demonstrator's."""
    start, end = sym["__azos_patch_start"], sym["__azos_patch_end"]
    table = img.read(start, end - start)
    entries = [struct.unpack_from("<Q", table, i)[0] for i in range(0, len(table) - len(table) % SITE_BYTES, SITE_BYTES)]
    ok = {va for va in entries if entry_patchable(img, va)}
    bad: list[str] = []
    probe = sym.get("livepatch_probe_target")
    if probe is None:
        bad.append("livepatch_probe_target (the allowlist's demonstrator) is not in the image")
    elif probe not in ok:
        bad.append(f"livepatch_probe_target at {probe:#x} has no entry slot a redirect can overwrite "
                   f"(LIVEPATCH_ENTRY_NOPS: 1 aarch64, 3 riscv64, 5 x86_64)")
    return len(entries), len(ok), bad


def config_bool(path: str, key: str) -> bool:
    return any(line.strip() == f"{key}=y" for line in open(path, encoding="utf-8"))


def check_elf(elf: str, config: str, nm: str) -> list[str]:
    sym = symbols(elf, nm)
    bad: list[str] = []
    need = ["__patch_pool_start", "__patch_pool_end", "__azos_patch_start",
            "__azos_patch_end", "_text_start", "_text_end"]
    for n in need:
        if n not in sym:
            bad.append(f"{os.path.basename(elf)}: symbol {n} missing")
    if bad:
        return bad
    want = config_int(config, "CONFIG_LIVEPATCH_POOL_KIB") * 1024
    got = sym["__patch_pool_end"] - sym["__patch_pool_start"]
    if got != want:
        bad.append(f"pool is {got} bytes, LIVEPATCH_POOL_KIB wants {want}")
    if want and not (sym["_text_start"] <= sym["__patch_pool_start"]
                     and sym["__patch_pool_end"] <= sym["_text_end"]):
        bad.append("the pool is outside [_text_start, _text_end]")
    sites = sym["__azos_patch_end"] - sym["__azos_patch_start"]
    if sites % SITE_BYTES:
        bad.append(f".azos_patch is {sites} bytes, not whole {SITE_BYTES}-byte entries")
    if config_int(config, "CONFIG_LIVEPATCH_ENTRY_NOPS") == 0 and sites:
        bad.append(f"LIVEPATCH_ENTRY_NOPS=0 but .azos_patch holds {sites // SITE_BYTES} entries")
    extra = ""
    if config_bool(config, "CONFIG_LIVEPATCH"):
        img = Image(elf)
        if "_text_start" not in sym or "_text_end" not in sym:
            bad.append("_text_start/_text_end missing: no build-id")
        else:
            extra = f" build={build_id(img, sym)[:32]}"
        if not want:
            bad.append("CONFIG_LIVEPATCH=y but LIVEPATCH_POOL_KIB=0")
        n, ok, why = check_sites(img, sym)
        bad += [f"{os.path.basename(elf)}: {b}" for b in why]
        extra += f" patchable={ok}/{n}"
    print(f"[LIVEPATCH] {os.path.basename(elf)}: pool={got // 1024} KiB "
          f"sites={sites // SITE_BYTES}{extra}")
    return bad


def main() -> int:
    a = sys.argv[1:]
    if a[:1] == ["scripts"]:
        bad = check_scripts()
    elif a[:1] == ["elf"] and len(a) >= 3:
        nm = a[3] if len(a) > 3 else "llvm-nm"
        bad = check_elf(a[1], a[2], nm)
    elif a[:1] == ["build-id"] and len(a) >= 2:
        sym = symbols(a[1], a[2] if len(a) > 2 else "llvm-nm")
        if "_text_start" not in sym or "_text_end" not in sym:
            print("check_livepatch_layout: _text_start/_text_end missing", file=sys.stderr)
            return 1
        print(build_id(Image(a[1]), sym))
        return 0
    else:
        print(__doc__)
        return 2
    for b in bad:
        print(f"check_livepatch_layout: {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""No user ELF maps read-only data executable.

Three checks per image, at the page size the kernel maps (`--page`, the
aarch64 granule of a 16/64 KiB build; 4096 by default):

  * no page is touched by two PT_LOAD segments mapped differently. The
    kernel loader maps each page with the permissions of its own segment and
    refuses an image in which two segments with different mapped permissions
    (read-only, read-execute, read-write: `elf_bounds::seg_perms`) share one;
  * no executable PT_LOAD maps the ELF or program headers: the loader refuses
    that too (`elf_bounds::check_exec_headers`, Kconfig
    ELF_REFUSE_EXEC_HEADERS). It is what a layout that folds `.rodata` into
    the text segment looks like from the program headers alone (lld
    `--no-rosegment`, GNU ld without `-z separate-code`);
  * no allocated, non-executable section (`.rodata`, `.data`, ...) lies inside
    an executable PT_LOAD. The section headers say what the loader cannot
    see: a script that keeps the headers out of the text segment and still
    puts `.rodata` in it (GNU ld without PHDRS). The loader never reads the
    section headers (a streamed exec has only the program headers), so this
    check lives here, on every built image.

The lint names each image so a linker change that brings any of these back
is named here instead of as an exec refused at boot (or not refused at all).
Cargo does not relink on a `.ld` edit, so a stale image is also caught.

  elf_page_perms.py [--page N] ELF...  exit 1 and name each finding
  elf_page_perms.py --self-test        each check finds its crafted image
"""
import struct
import sys

PAGE = 4096


def perms(flags):
    return "RW" if flags & 2 else ("RX" if flags & 1 else "R")


def loads(data):
    """[(p_flags, p_offset, p_vaddr, p_filesz, p_memsz)] of the non-empty
    PT_LOADs; None when `data` is not a 64-bit little-endian ELF."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(phnum):
        p_type, p_flags, off, vaddr, _pa, filesz, memsz, _al = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * phentsize)
        if p_type == 1 and memsz:
            out.append((p_flags, off, vaddr, filesz, memsz))
    return out


def mixed_pages(data, page=PAGE):
    """[(page, {perms})] for each page two differently mapped segments touch;
    None when `data` is not a 64-bit little-endian ELF."""
    segs = loads(data)
    if segs is None:
        return None
    pages = {}
    for p_flags, _off, vaddr, _fs, memsz in segs:
        for pg in range(vaddr // page, (vaddr + memsz + page - 1) // page):
            pages.setdefault(pg, set()).add(perms(p_flags))
    return [(p * page, sorted(v)) for p, v in sorted(pages.items()) if len(v) > 1]


def executable(p_flags):
    """Mapped executable by the loader (`seg_perms`: writable wins)."""
    return p_flags & 1 and not p_flags & 2


def exec_headers(data):
    """[vaddr] of each executable PT_LOAD whose file range holds a byte of the
    ELF header or the program header table."""
    segs = loads(data) or []
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    end = max(64, phoff + phentsize * phnum)
    return [va for f, off, va, fs, _ms in segs if executable(f) and fs and off < end]


def exec_data_sections(data):
    """[(name, addr)] of each SHF_ALLOC section without SHF_EXECINSTR that
    overlaps an executable PT_LOAD; [] when there are no section headers."""
    segs = [s for s in (loads(data) or []) if executable(s[0])]
    shoff, = struct.unpack_from("<Q", data, 40)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    if not shoff or not shnum or shstrndx >= shnum:
        return []
    stroff, = struct.unpack_from("<Q", data, shoff + shstrndx * shentsize + 24)
    out = []
    for i in range(shnum):
        name, _t, flags, addr, _off, size = struct.unpack_from(
            "<IIQQQQ", data, shoff + i * shentsize)
        if not flags & 2 or flags & 4 or not size:
            continue
        if any(addr < va + ms and va < addr + size for _f, _o, va, _fs, ms in segs):
            nm = data[stroff + name:data.index(b"\0", stroff + name)].decode()
            out.append((nm, addr))
    return out


def findings(data, page=PAGE):
    """Each check's findings as lines; None when not a 64-bit LE ELF."""
    mixed = mixed_pages(data, page)
    if mixed is None:
        return None
    out = [f"page {p:#x} mapped {'+'.join(w)}" for p, w in mixed]
    out += [f"executable segment at {va:#x} maps the ELF headers" for va in exec_headers(data)]
    out += [f"{nm} at {a:#x} lies in an executable segment" for nm, a in exec_data_sections(data)]
    return out


def crafted(text_end, ro_start, text_off=0x1000, sections=()):
    """A header with an RX segment ending at `text_end` and an R one at
    `ro_start`, the RX one at file offset `text_off`; `sections`:
    [(name, flags, addr, size)] section headers."""
    names = b"\0" + b"".join(n.encode() + b"\0" for n, *_ in sections) + b".shstrtab\0"
    nsec = len(sections) + 2 if sections else 0
    hdr = bytearray(64 + 2 * 56 + len(names) + nsec * 64)
    hdr[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", hdr, 32, 64)
    struct.pack_into("<HH", hdr, 54, 56, 2)
    struct.pack_into("<IIQQQQQQ", hdr, 64, 1, 5, text_off, 0x10000, 0x10000, text_end - 0x10000,
                     text_end - 0x10000, PAGE)
    struct.pack_into("<IIQQQQQQ", hdr, 120, 1, 4, 0x2000, ro_start, ro_start, 0x40, 0x40, PAGE)
    if sections:
        stro = 64 + 2 * 56
        hdr[stro:stro + len(names)] = names
        sh = stro + len(names)
        struct.pack_into("<Q", hdr, 40, sh)
        struct.pack_into("<HHH", hdr, 58, 64, nsec, nsec - 1)
        pos = 1
        for i, (n, flags, addr, size) in enumerate(sections, 1):
            struct.pack_into("<IIQQQQ", hdr, sh + i * 64, pos, 1, flags, addr, 0, size)
            pos += len(n) + 1
        struct.pack_into("<IIQQQQ", hdr, sh + (nsec - 1) * 64, pos, 3, 0, 0, stro, len(names))
    return bytes(hdr)


def self_test():
    shared = mixed_pages(crafted(0x10850, 0x10850))
    split = mixed_pages(crafted(0x10850, 0x11850))
    if shared != [(0x10000, ["R", "RX"])] or split != []:
        print(f"self-test: shared page read {shared}, split layout read {split}")
        return 1
    # The same split layout is mixed at a 16 KiB page.
    if mixed_pages(crafted(0x10850, 0x11850), 16384) != [(0x10000, ["R", "RX"])]:
        print("self-test: a 16 KiB page shared by RX and R was not found")
        return 1
    # `--no-rosegment`: the text segment starts at file offset 0.
    if exec_headers(crafted(0x10850, 0x11850, text_off=0)) != [0x10000] \
            or exec_headers(crafted(0x10850, 0x11850)) != []:
        print("self-test: an executable segment over the ELF headers was not found")
        return 1
    ro_in_text = crafted(0x10850, 0x11850, sections=[(".text", 6, 0x10000, 0x800),
                                                     (".rodata", 2, 0x10800, 0x50)])
    ro_apart = crafted(0x10850, 0x11850, sections=[(".text", 6, 0x10000, 0x850),
                                                   (".rodata", 2, 0x11850, 0x40)])
    if exec_data_sections(ro_in_text) != [(".rodata", 0x10800)] or exec_data_sections(ro_apart) != []:
        print(f"self-test: .rodata in the text segment read {exec_data_sections(ro_in_text)}, "
              f"apart read {exec_data_sections(ro_apart)}")
        return 1
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    page = PAGE
    if argv[:1] == ["--page"]:
        page = int(argv[1])
        argv = argv[2:]
    bad = 0
    for path in argv:
        with open(path, "rb") as f:
            found = findings(f.read(), page)
        if found:
            bad += 1
            for line in found[:3]:
                print(f"{path}: {line}")
    if not argv:
        print("no ELF named")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

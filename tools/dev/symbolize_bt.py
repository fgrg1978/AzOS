#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""symbolize_bt.py — a panic's backtrace from a console log, as function, file and line.

    symbolize_bt.py <kernel ELF> [LOG] [--slide 0xN]

With Kconfig PROFILER the panic path and every fatal trap print the
frame-pointer chain of the CPU that stopped:

    [PANIC] backtrace: 0x80201234 0x80205678 (stopped: root)

The addresses are return addresses of the running image. A kernel that KASLR
slid prints `[KASLR] image slid to 0x<base>, ...` early in the same log; the
slide is that base minus the ELF's `_text_start`, taken from the last such line
before the backtrace (none, or a kernel that ran at its link address: no
slide; `--slide` names it when the log lacks it, as a release image's does).
Each address is looked up one byte before the return address, inside the
call, with the DWARF of the ELF (inlined callers come out as their own lines).

LOG is read from standard input when absent. Exit status: 0 when every address
of every backtrace resolved, 1 when one did not or the log has no backtrace,
2 for a usage error or when no addr2line is installed.
"""
import argparse
import os
import re
import shutil
import struct
import subprocess
import sys

# GNU binutils' or LLVM's, whichever is installed: the same command line. The
# generic ELF64 reader of a GNU build for any one ISA reads the others.
ADDR2LINE = ["llvm-addr2line", "addr2line", "riscv64-unknown-elf-addr2line", "riscv64-elf-addr2line",
             "aarch64-elf-addr2line", "aarch64-none-elf-addr2line", "x86_64-elf-addr2line"]

BACKTRACE = re.compile(r"\[PANIC\] backtrace:((?: 0x[0-9a-fA-F]+)*) \(stopped: ([^)]*)\)")
SLID = re.compile(r"\[KASLR\] image slid to (0x[0-9a-fA-F]+),")


def elf_symbol(path, name):
    """The value of symbol `name` in an ELF64 little-endian file, or None."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("%s: not an ELF64 little-endian file" % path)
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    for _n, kind, _fl, _addr, off, size, link, _info, _al, entsize in sections:
        if kind != 2:  # SHT_SYMTAB
            continue
        stroff, strsize = sections[link][4], sections[link][5]
        strtab = data[stroff:stroff + strsize]
        for i in range(size // entsize):
            st_name, _info, _other, _shndx, value, _sz = struct.unpack_from("<IBBHQQ", data, off + i * entsize)
            end = strtab.find(b"\0", st_name)
            if strtab[st_name:end].decode("ascii", "replace") == name:
                return value
    return None


def find_addr2line(candidates=ADDR2LINE, path=None):
    for name in candidates:
        found = shutil.which(name, path=path)
        if found:
            return found
    return None


def lookup(addr2line, elf, addr):
    """[(function, "file:line")] for one address, innermost first."""
    out = subprocess.run([addr2line, "-f", "-i", "-C", "-e", elf, "0x%x" % addr],
                         capture_output=True, text=True, check=False).stdout.splitlines()
    return [(out[i], out[i + 1]) for i in range(0, len(out) - 1, 2)]


def unresolved(where):
    return where.startswith("??") or where.endswith(":0") or where.endswith(":?")


def symbolize(elf, text, addr2line, slide=None):
    """Print every backtrace of `text`; return (backtraces, unresolved addresses)."""
    link_base = elf_symbol(elf, "_text_start")
    found = bad = 0
    pending = slide or 0
    for line in text.splitlines():
        m = SLID.search(line)
        if m and slide is None and link_base is not None:
            pending = int(m.group(1), 16) - link_base
        m = BACKTRACE.search(line)
        if not m:
            continue
        found += 1
        addrs = [int(a, 16) for a in m.group(1).split()]
        print("[PANIC] backtrace, %d frames, slide %#x, stopped: %s" % (len(addrs), pending, m.group(2)))
        for n, ret in enumerate(addrs):
            frames = lookup(addr2line, elf, ret - pending - 1)
            if not frames or unresolved(frames[0][1]):
                bad += 1
                print("  #%-2d %#x  ?? (not in %s at slide %#x)" % (n, ret, os.path.basename(elf), pending))
                continue
            for k, (func, where) in enumerate(frames):
                print("  #%-2d %#x  %s at %s%s" % (n, ret, func, where, "  (inlined into the next)" if k < len(frames) - 1 else ""))
    return found, bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1].strip())
    ap.add_argument("elf")
    ap.add_argument("log", nargs="?")
    ap.add_argument("--slide", type=lambda s: int(s, 0))
    a = ap.parse_args(argv)
    addr2line = find_addr2line()
    if addr2line is None:
        print("symbolize_bt: no addr2line installed, looked for: " + " ".join(ADDR2LINE), file=sys.stderr)
        return 2
    try:
        text = open(a.log, errors="replace").read() if a.log else sys.stdin.read()
        found, bad = symbolize(a.elf, text.replace("\r", ""), addr2line, a.slide)
    except (OSError, ValueError) as e:
        print("symbolize_bt: %s" % e, file=sys.stderr)
        return 2
    if found == 0:
        print("symbolize_bt: no '[PANIC] backtrace:' line in the log", file=sys.stderr)
        return 1
    if bad:
        print("symbolize_bt: %d address(es) not in the ELF: another build, or a slide the log lacks "
              "(a release image does not print its base; --slide 0xN)" % bad, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

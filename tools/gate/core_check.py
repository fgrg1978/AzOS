#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Read back the core file of a ring-3 child that faulted with known registers
(abichild `fault-regs`) and check it, as the gate's `core file: a fault` rows do.

    core_check.py <riscv64|aarch64|x86_64> <image ELF the task ran> <whole|cut> <limit bytes> <CORE.ELF>...

llvm-readobj (PATH, else the toolchain's) must parse the file's headers, program
headers and notes; then NT_PRSTATUS must hold the known values in the ISA's
user_regs_struct slots, the PT_LOAD that holds the stack-marker address must
hold the marker, the "AzOS" note must be the image's SHA-256, and a `cut` core
must be exactly `limit` bytes. Of the core files given (the task's siblings that faulted
earlier have theirs too) the one whose registers hold the known values is checked. Exit 0
and one `core ok` line, or 1 and why.
"""
import hashlib
import os
import shutil
import struct
import subprocess
import sys

A, B, MARK = 0x5EE1C0DE0001, 0x5EE1C0DE0002, 0xA5A5000000000010
# (machine, slot of A, slot of B, slot of the marker address, slot of the pc)
ISAS = {"riscv64": (243, 18, 19, 20, 0), "aarch64": (183, 23, 24, 25, 32), "x86_64": (62, 2, 1, 3, 16)}


def fail(why):
    print("core FAIL:", why)
    sys.exit(1)


def readobj():
    exe = shutil.which("llvm-readobj")
    if exe:
        return exe
    try:
        root = subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True, check=True).stdout.strip()
        for d, _, files in os.walk(os.path.join(root, "lib", "rustlib")):
            if "llvm-readobj" in files:
                return os.path.join(d, "llvm-readobj")
    except (OSError, subprocess.CalledProcessError):
        pass
    fail("no llvm-readobj on PATH or in the toolchain")


def parse(isa, path):
    """The core's program headers, loads and register/digest notes, or why not."""
    machine = ISAS[isa][0]
    data = open(path, "rb").read()
    r = subprocess.run([readobj(), "--file-headers", "--program-headers", "--notes", path], capture_output=True, text=True)
    if r.returncode != 0 or "error" in (r.stdout + r.stderr).lower():
        fail("llvm-readobj: " + (r.stderr or r.stdout)[:200])
    if data[:4] != b"\x7fELF" or struct.unpack_from("<HH", data, 16) != (4, machine):
        fail("%s is not an ET_CORE of this machine" % path)
    phnum = struct.unpack_from("<H", data, 56)[0]
    phs = [struct.unpack_from("<IIQQQQQQ", data, 64 + 56 * i) for i in range(phnum)]
    notes = [p for p in phs if p[0] == 4]
    loads = [p for p in phs if p[0] == 1]
    if len(notes) != 1 or not loads:
        fail("expected one PT_NOTE and at least one PT_LOAD")
    n = data[notes[0][2]:notes[0][2] + notes[0][5]]
    off, regs, digest = 0, None, None
    while off + 12 <= len(n):
        nsz, dsz, ty = struct.unpack_from("<III", n, off)
        name = n[off + 12:off + 12 + nsz].rstrip(b"\0")
        d0 = off + 12 + ((nsz + 3) & ~3)
        desc = n[d0:d0 + dsz]
        if name == b"CORE" and ty == 1:
            if struct.unpack_from("<I", desc, 32)[0] == 0:
                fail("pr_pid is 0")
            regs = struct.unpack_from("<%dQ" % ((dsz - 112 - 8) // 8), desc, 112)
        if name == b"AzOS" and ty == 1:
            digest = desc
        off = d0 + ((dsz + 3) & ~3)
    if regs is None or digest is None:
        fail("no NT_PRSTATUS or no image note")
    return data, loads, regs, digest


def main():
    isa, image, mode, limit = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    _, ia, ib, im, ipc = ISAS[isa]
    cores = [parse(isa, p) for p in sys.argv[5:]]
    mine = [c for c in cores if c[2][ia] == A and c[2][ib] == B]
    if not mine:
        fail("none of %d core files holds the known registers %#x %#x" % (len(cores), A, B))
    data, loads, regs, digest = mine[0]
    if regs[ipc] == 0:
        fail("the pc is 0")
    hit = [p for p in loads if p[3] <= regs[im] < p[3] + p[5]]
    if len(hit) != 1:
        fail("no PT_LOAD holds the stack marker at %#x" % regs[im])
    p = hit[0]
    got = struct.unpack_from("<8Q", data, p[2] + regs[im] - p[3])
    if got != tuple(MARK + i for i in range(8)):
        fail("the stack marker reads %s" % [hex(x) for x in got])
    want = hashlib.sha256(open(image, "rb").read()).digest()
    if digest != want:
        fail("image digest %s, the image on the volume is %s" % (digest.hex()[:12], want.hex()[:12]))
    if mode == "cut" and len(data) != limit:
        fail("a cut core is %d bytes, the budget is %d" % (len(data), limit))
    if mode == "whole" and len(data) >= limit:
        fail("a whole core reached the budget")
    print("core ok: %s %d bytes, %d segments, marker at %#x, image %s" % (mode, len(data), len(loads), regs[im], digest.hex()[:12]))


main()

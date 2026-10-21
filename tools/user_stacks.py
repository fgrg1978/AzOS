#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Does each ring-3 image ask for the stack its deepest call chain needs?

    user_stacks.py [--config .config] [--margin PERCENT] [--stack-kb KB] ELF...

A user stack is not grown: the loader maps exactly what the image asks for in
its `PT_GNU_STACK` header (`p_memsz`; the `.azos_stack` section of its linker
script, or `-z stack-size` on x86_64), or Kconfig `USER_STACK_SIZE_KB` when it
asks for none, and the page below is unmapped. A program that outgrows it is
killed by a write fault at an address that means nothing to its author:
`MLSRV.ELF` died at every start (`[PAGE FAULT] write at 0x7fffb670`) and
`ps` in the shell at `0x7fff9998`, 18 and 25 KiB below a 16 KiB stack's top.

For each image this reads that request and the deepest static call chain from
its entry (`tools/stack_chain.py`: every frame summed, calls resolved through
the symbol table), and fails when the chain plus a margin is over the request.
The chain is a LOWER bound -- indirect calls are not followed, and a frame
reserved inside a callee is only seen through its prologue -- so the margin is
what stands for them (default 25%). It also fails when the request is over
`USER_STACK_MAX_KB`, which the loader would refuse.

A stripped image has no symbols to read a chain from, and an x86_64 image is not
read by the chain tool: both are reported and only their request is checked
against the ceiling (the relibc programs are the first). A thread that runs on a stack of its own is a
second root, named in THREADS below with the symbol that is its stack.

`--stack-kb` replaces every request: the canary of the gate row, which must
fail for the images that need more than that.

Exit status 1 when an image is over, 2 when one cannot be read.
"""
import argparse
import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack_chain  # noqa: E402
import stack_frames  # noqa: E402
from stack_frames import aarch64_frames  # noqa: E402

PT_GNU_STACK = 0x6474E551
EM_RISCV, EM_AARCH64 = 243, 183

# image -> [(root function, symbol whose size is the stack that thread runs on)]
# None today: `MLSRV.ELF` served its endpoint on a thread of its own (a 44 KiB
# static) while its main thread served the driver-server queue; it serves on its
# main thread now and the main-thread chain covers it.
THREADS = {}


def config_kb(path, key, default):
    try:
        with open(path, encoding="utf-8") as f:
            m = re.search(r"^CONFIG_%s=(\d+)$" % key, f.read(), re.M)
        return int(m.group(1)) if m else default
    except OSError:
        return default


def elf_info(path):
    """`(entry, GNU_STACK p_memsz or None, e_machine)` of an ELF64 little-endian image."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError(f"{path}: not an ELF64 little-endian image")
    machine = struct.unpack_from("<H", data, 18)[0]
    entry = struct.unpack_from("<Q", data, 24)[0]
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    memsz = None
    for i in range(phnum):
        ph = phoff + i * phentsize
        if struct.unpack_from("<I", data, ph)[0] == PT_GNU_STACK:
            memsz = struct.unpack_from("<Q", data, ph + 40)[0]
    return entry, memsz, machine


def symbols(path):
    """`{name: (address, size)}` of the defined symbols, and the entry's name."""
    out = subprocess.run([os.path.join(stack_frames.llvm_bin(), "llvm-nm"), "-S", "-C", "--defined-only", path],
                         capture_output=True, text=True)
    syms = {}
    for line in out.stdout.splitlines():
        p = line.split(None, 3)
        if len(p) == 4:
            syms[p[3]] = (int(p[0], 16), int(p[1], 16))
    return syms


def check(path, args, default_kb, max_kb):
    name = os.path.basename(path)
    entry, memsz, machine = elf_info(path)
    request = args.stack_kb * 1024 if args.stack_kb else (memsz or default_kb * 1024)
    kind = "asks" if memsz else "default"
    if request > max_kb * 1024:
        print(f"OVER {name}: asks {request // 1024} KiB, USER_STACK_MAX_KB is {max_kb}")
        return False
    if machine not in (EM_RISCV, EM_AARCH64):
        print(f"{name}: chain not read for e_machine {machine} (RISC-V and aarch64 only); asks {request // 1024} KiB, {kind}")
        return True
    syms = symbols(path)
    root = next((n for n, (a, _) in syms.items() if a == entry and not n.startswith(".L")), None)
    if root is None:
        print(f"{name}: no symbols, not checked (stack {request // 1024} KiB, {kind})")
        return True
    ok = True
    runs = [(root, request, "main thread")]
    for fn, sym in THREADS.get(name, []):
        if sym not in syms:
            print(f"{name}: thread stack symbol {sym} is gone: update THREADS in tools/user_stacks.py")
            return False
        runs.append((fn, syms[sym][1], f"thread on {sym}"))
    for fn, stack, what in runs:
        try:
            depth, path_, _, _ = stack_chain.analyze(path, fn)
        except KeyError as e:
            print(f"{name}: {e.args[0]}")
            return False
        need = depth * (100 + args.margin) // 100
        verdict = "ok"
        if need > stack:
            verdict = "OVER"
            ok = False
        print(f"{verdict:4} {name}: {what}: chain {depth} B (+{args.margin}% = {need} B) of {stack} B"
              f" ({kind if what == 'main thread' else 'static'}); deepest: "
              + " > ".join(n.split("::")[-1][:28] for n in path_[:4]))
    return ok


def self_test():
    """Canaries of the parts that read bytes: each one fails on the bug it names."""
    import tempfile

    def elf(memsz, with_header=True):
        # ELF64 LE header (64 bytes) + one program header (56 bytes).
        h = bytearray(64 + 56 * (1 if with_header else 0))
        h[0:4] = b"\x7fELF"
        h[4], h[5] = 2, 1
        struct.pack_into("<H", h, 18, EM_RISCV)
        struct.pack_into("<Q", h, 24, 0x10000)
        struct.pack_into("<Q", h, 32, 64)
        struct.pack_into("<HH", h, 54, 56, 1 if with_header else 0)
        if with_header:
            struct.pack_into("<I", h, 64, PT_GNU_STACK)
            struct.pack_into("<Q", h, 64 + 40, memsz)
        return bytes(h)

    failures = []

    def expect(what, got, want):
        if got != want:
            failures.append(f"{what}: got {got!r}, want {want!r}")

    with tempfile.TemporaryDirectory() as d:
        for name, blob, want in (("ask", elf(0x9000), (0x10000, 0x9000, EM_RISCV)),
                                 ("zero", elf(0), (0x10000, 0, EM_RISCV)),
                                 ("none", elf(0, with_header=False), (0x10000, None, EM_RISCV))):
            path = os.path.join(d, name)
            with open(path, "wb") as f:
                f.write(blob)
            expect(f"elf_info {name}", elf_info(path), want)
        cfg = os.path.join(d, "config")
        with open(cfg, "w") as f:
            f.write("CONFIG_USER_STACK_SIZE_KB=16\n# CONFIG_USER_STACK_MAX_KB is not set\n")
        expect("config_kb set", config_kb(cfg, "USER_STACK_SIZE_KB", 1), 16)
        expect("config_kb absent", config_kb(cfg, "USER_STACK_MAX_KB", 256), 256)
        expect("config_kb no file", config_kb(os.path.join(d, "missing"), "USER_STACK_SIZE_KB", 7), 7)
    # aarch64 prologues as LLVM writes them: pre-indexed saves and `sub sp`
    # in one or two steps, a `lsl #12` immediate, and a leaf that reserves none.
    text = "\n".join([
        "0000000000010000 <big>:",
        "   10000: stp x29, x30, [sp, #-0x60]!",
        "   10004: mov x29, sp",
        "   10008: sub sp, sp, #0x3, lsl #12",
        "   1000c: sub sp, sp, #0x20",
        "   10010: bl 0x10100 <callee>",
        "   10014: sub sp, sp, #0x999",
        "0000000000010100 <callee>:",
        "   10100: str x30, [sp, #-0x10]!",
        "   10104: stp x20, x19, [sp, #0x20]",
        "   10108: ldr x0, [x0]",
        "0000000000010200 <leaf>:",
        "   10200: add x0, x0, #0x1",
        "   10204: ret",
    ])
    spans = [(0x10000, 0x100, "big"), (0x10100, 0x100, "callee"), (0x10200, 0x10, "leaf")]

    def owner(addr):
        return next((n for a, z, n in spans if a <= addr < a + z), "?")

    got = aarch64_frames(text, owner)
    expect("aarch64 big", got.get("big"), 0x60 + 0x3000 + 0x20)
    expect("aarch64 callee", got.get("callee"), 0x10)
    expect("aarch64 leaf", got.get("leaf"), None)
    if failures:
        print("\n".join(failures))
        sys.exit(1)
    print("user_stacks self-test: ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("elf", nargs="*")
    ap.add_argument("--config", default=".config")
    ap.add_argument("--margin", type=int, default=25, help="percent added to the static chain")
    ap.add_argument("--stack-kb", type=int, default=0, help="replace every image's request (the canary)")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.elf:
        ap.error("no image given")
    default_kb = config_kb(args.config, "USER_STACK_SIZE_KB", 16)
    max_kb = config_kb(args.config, "USER_STACK_MAX_KB", 256)
    good = True
    for path in args.elf:
        try:
            good &= check(path, args, default_kb, max_kb)
        except (OSError, ValueError) as e:
            print(f"{path}: {e}")
            sys.exit(2)
    sys.exit(0 if good else 1)


if __name__ == "__main__":
    main()

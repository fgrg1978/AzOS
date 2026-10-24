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
its entry (`tools/lint/stack_chain.py`: every frame summed, calls resolved through
the symbol table), and fails when the chain plus a margin is over the request.
The chain is a LOWER bound -- indirect calls are not followed -- so the
margin is what stands for them (default 25%). A function it reaches whose
stack pointer the frame dataflow cannot bound (`stack_frames.UNBOUNDED_ALLOWED`
names the ones that may) fails the image. It also fails when the request is over
`USER_STACK_MAX_KB`, which the loader would refuse.

A stripped image has no symbols to read a chain from: it is reported and only
its request is checked against the ceiling (the relibc programs are the
first). A thread that runs on a stack of its own is a second root, named in
THREADS below with the symbol that is its stack.

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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402,F401
import stack_chain  # noqa: E402
import stack_frames  # noqa: E402

PT_GNU_STACK = 0x6474E551
EM_RISCV, EM_AARCH64, EM_X86_64 = 243, 183, 62

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
    if machine not in (EM_RISCV, EM_AARCH64, EM_X86_64):
        print(f"{name}: chain not read for e_machine {machine}; asks {request // 1024} KiB, {kind}")
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
            print(f"{name}: thread stack symbol {sym} is gone: update THREADS in tools/lint/user_stacks.py")
            return False
        runs.append((fn, syms[sym][1], f"thread on {sym}"))
    for fn, stack, what in runs:
        try:
            c = stack_chain.analyze(path, fn)
        except KeyError as e:
            print(f"{name}: {e.args[0]}")
            return False
        need = c.depth * (100 + args.margin) // 100
        warnings, on_path = stack_chain.fallback_notes(c)
        verdict = "ok"
        if need > stack:
            verdict = "UNDECIDED" if on_path else "OVER"
            ok = False
        for w in warnings:
            print(f"{name}: {w}")
        for w in c.unbounded[0]:
            print(f"{name}: {w}")
            ok = False
        print(f"{verdict:4} {name}: {what}: chain {c.depth} B (+{args.margin}% = {need} B) of {stack} B"
              f" ({kind if what == 'main thread' else 'static'}); deepest: "
              + " > ".join(n.split("::")[-1][:28] for n in c.path[:4]))
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
    # aarch64 frames as LLVM writes them: pre-indexed saves and `sub sp` in
    # one or two steps, a `lsl #12` immediate, a reservation after a call
    # (the frame is the deepest point, not the prologue), and a leaf that
    # reserves none.
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
        "   1010c: ret",
        "0000000000010200 <leaf>:",
        "   10200: add x0, x0, #0x1",
        "   10204: ret",
    ])
    spans = [(0x10000, 0x100, "big"), (0x10100, 0x100, "callee"), (0x10200, 0x10, "leaf")]

    def owner(addr):
        return next((n for a, z, n in spans if a <= addr < a + z), None)

    got = stack_frames.analyze(text, owner, "aarch64").frames
    expect("aarch64 big", got.get("big"), 0x60 + 0x3000 + 0x20 + 0x999)
    expect("aarch64 callee", got.get("callee"), 0x10)
    expect("aarch64 leaf", got.get("leaf"), None)
    # Call edges by the address reached: `.Lpcrel_hi1` is defined in `a` and
    # again in `b` (one set of local labels per compilation unit), `a`'s jump
    # to its own label is no call, and `c` reaches `b` by `auipc` (a negative
    # immediate) + `jalr`. Looking the label up by name made `a` call `b`.
    text = "\n".join([
        "0000000000020000 <a>:",
        "   20000: auipc ra, 0x0",
        "   20004: jalr 0x100(ra) <callee>",
        "0000000000020008 <.Lpcrel_hi1>:",
        "   20008: j 0x20010 <.Lpcrel_hi1+0x8>",
        "   2000c: nop",
        "   20010: ret",
        "0000000000020100 <callee>:",
        "   20100: ret",
        "0000000000020200 <b>:",
        "0000000000020200 <.Lpcrel_hi1>:",
        "   20200: ret",
        "0000000000021300 <c>:",
        "   21300: auipc t1, 0xfffff",
        "   21304: jalr -0x100(t1) <.Lpcrel_hi1>",
    ])
    spans = [(0x20000, 0x14, "a"), (0x20100, 4, "callee"), (0x20200, 0x10, "b"), (0x21300, 8, "c")]
    got = stack_chain.edges(stack_frames.analyze(text, owner, "riscv64"), owner)
    expect("call edges", {f: sorted(cs) for f, cs in got.items()}, {"a": ["callee"], "c": ["b"]})
    # The panic handler is its own root: 20 functions that can panic, all
    # called by the handler, are one knot through it. The chain is the
    # trap's own down to the panic call, plus the handler's own once.
    h = stack_chain.PANIC_HANDLERS[0]
    g = {"root": {"g0"}, "pbc": {h}, h: {f"g{i}" for i in range(20)}}
    g.update({f"g{i}": {"pbc"} for i in range(20)})
    fr = {"root": 16, "pbc": 48, h: 500, **{f"g{i}": 100 + i for i in range(20)}}
    c = stack_chain.chain(g, fr, "root")
    expect("panic chain", (c.path, c.panic), (["root", "g0", "pbc"], (500 + 119 + 48, [h, "g19", "pbc"])))
    expect("panic depth", c.depth, 16 + 100 + 48 + 500 + 119 + 48)
    # A panic inside the handler (kernel/src/panic.rs `nested`) enters it
    # twice more: its frame and `nested`'s chain on top of the deepest point,
    # then its frame and `nested`'s frame. A handler without `nested` (a
    # ring-3 image's) is charged its own chain alone, as above.
    n = stack_chain.PANIC_NESTED
    g = {"root": {h}, h: {"report", n}, n: {"freeze"}, "report": {"fs"}}
    fr = {"root": 16, h: 300, "report": 400, "fs": 2000, n: 64, "freeze": 32}
    c = stack_chain.chain(g, fr, "root")
    expect("nested panic charge", c.depth, 16 + (300 + 400 + 2000) + 300 + (64 + 32) + 300 + 64)
    # A knot past the DP's size is walked, not charged whole: a hub and 20
    # spokes that call it back are one component, and no simple path holds
    # two spokes.
    g = {"root": {"hub"}, "hub": {f"s{i}" for i in range(20)}}
    g.update({f"s{i}": {"hub", "leaf"} if i == 3 else {"hub"} for i in range(20)})
    fr = {"root": 16, "hub": 200, "leaf": 1000, **{f"s{i}": 100 + i for i in range(20)}}
    c = stack_chain.chain(g, fr, "root")
    expect("walked knot", (c.depth, c.path, c.panic, c.fallbacks),
           (16 + 200 + 103 + 1000, ["root", "hub", "s3", "leaf"], None, []))
    # The same knot past a 10-step walk: charged its sum, and said so, with
    # the block on the chain (the verdict rests on it).
    walk_max, stack_chain.WALK_MAX = stack_chain.WALK_MAX, 10
    try:
        c = stack_chain.chain(g, fr, "root")
    finally:
        stack_chain.WALK_MAX = walk_max
    warnings, on_path = stack_chain.fallback_notes(c)
    expect("fallback charge", c.depth, 16 + 200 + sum(100 + i for i in range(20)) + 1000)
    expect("fallback named", (len(c.fallbacks), len(warnings), on_path), (1, 1, True))
    expect("fallback warning", warnings[0][:40] if warnings else None, "WARNING: a recursive block of 21 functio")
    # x86_64 frames: the return address, pushes, 4 KiB steps with the probe
    # between them, `addq $-0x80`, the probe loop of a frame too big to unroll
    # (bounded by its compare with %r11, the probes not counted again), and a
    # push after the prologue, which is the frame's too.
    text = "\n".join([
        "ffffffff80001000 <big>:",
        "ffffffff80001000:  endbr64",
        "ffffffff80001004:  pushq %rbp",
        "ffffffff80001005:  pushq %rbx",
        "ffffffff80001006:  subq $0x1000, %rsp   # imm = 0x1000",
        "ffffffff8000100d:  movq $0x0, (%rsp)",
        "ffffffff80001015:  subq $0x18, %rsp",
        "ffffffff80001019:  movq %rdi, %rbx",
        "ffffffff8000101c:  pushfq",
        "ffffffff80001100 <looped>:",
        "ffffffff80001100:  movq %rsp, %r11",
        "ffffffff80001103:  subq $0x10000, %r11   # imm = 0x10000",
        "ffffffff8000110a:  subq $0x1000, %rsp   # imm = 0x1000",
        "ffffffff80001111:  movq $0x0, (%rsp)",
        "ffffffff80001119:  cmpq %r11, %rsp",
        "ffffffff8000111c:  jne 0xffffffff8000110a <looped+0xa>",
        "ffffffff8000111e:  subq $0x20, %rsp",
        "ffffffff80001122:  movq %rdi, %rax",
        "ffffffff80001200 <red>:",
        "ffffffff80001200:  addq $-0x80, %rsp",
        "ffffffff80001204:  retq",
        "ffffffff80001300 <leaf>:",
        "ffffffff80001300:  retq",
    ])
    spans = [(0xffffffff80001000, 0x100, "big"), (0xffffffff80001100, 0x100, "looped"),
             (0xffffffff80001200, 0x100, "red"), (0xffffffff80001300, 0x10, "leaf")]

    def owner(addr):
        return next((n for a, z, n in spans if a <= addr < a + z), None)

    got = stack_frames.analyze(text, owner, "x86_64").frames
    expect("x86_64 big", got.get("big"), 8 + 16 + 0x1000 + 0x18 + 8)
    expect("x86_64 probe loop", got.get("looped"), 8 + 0x10000 + 0x20)
    expect("x86_64 addq", got.get("red"), 8 + 0x80)
    expect("x86_64 leaf", got.get("leaf"), 8)
    # x86_64 thunk calls: the target from a RIP-relative `leaq` (argument
    # set-up between), through a callee-saved copy, and as a tail jump where
    # both paths agree; none from a memory load, from two paths that
    # disagree, or across a call (which clobbers %r11).
    t = "callq 0xffffffff80009000 <__x86_indirect_thunk_r11>"
    text = "\n".join([
        "ffffffff80002000 <a>:",
        "ffffffff80002000:  leaq 0x100(%rip), %r11 # 0xffffffff80003000 <callee>",
        "ffffffff80002007:  movl $0x1, %esi",
        "ffffffff8000200c:  " + t,
        "ffffffff8000200f:  leaq 0x100(%rip), %r11 # 0xffffffff80003300 <vt>",
        "ffffffff80002011:  movq 0x10(%rax), %r11",
        "ffffffff80002015:  " + t,
        "ffffffff8000201a:  leaq 0x100(%rip), %r12 # 0xffffffff80003100 <other>",
        "ffffffff80002021:  movq %r12, %r11",
        "ffffffff80002024:  " + t,
        "ffffffff80002029:  callq 0xffffffff80003200 <direct>",
        "ffffffff8000202e:  jmp 0xffffffff80002000 <a>",
        "ffffffff80002100 <b>:",
        "ffffffff80002100:  leaq 0x100(%rip), %r11 # 0xffffffff80003000 <callee>",
        "ffffffff80002107:  testq %rdi, %rdi",
        "ffffffff8000210a:  je 0xffffffff80002113 <b+0x13>",
        "ffffffff8000210c:  leaq 0x100(%rip), %r11 # 0xffffffff80003100 <other>",
        "ffffffff80002113:  " + t,
        "ffffffff80002118:  retq",
        "ffffffff80002200 <c>:",
        "ffffffff80002200:  leaq 0x100(%rip), %r11 # 0xffffffff80003000 <callee>",
        "ffffffff80002207:  testq %rdi, %rdi",
        "ffffffff8000220a:  je 0xffffffff80002211 <c+0x11>",
        "ffffffff8000220c:  movl $0x2, %esi",
        "ffffffff80002211:  jmp 0xffffffff80009000 <__x86_indirect_thunk_r11>",
        "ffffffff80002300 <d>:",
        "ffffffff80002300:  leaq 0x100(%rip), %r11 # 0xffffffff80003000 <callee>",
        "ffffffff80002307:  callq 0xffffffff80003200 <direct>",
        "ffffffff8000230c:  " + t,
        "ffffffff80002311:  retq",
    ])
    spans = [(0xffffffff80002000, 0x100, "a"), (0xffffffff80002100, 0x100, "b"),
             (0xffffffff80002200, 0x100, "c"), (0xffffffff80002300, 0x100, "d"),
             (0xffffffff80003000, 0x10, "callee"), (0xffffffff80003100, 0x10, "other"),
             (0xffffffff80003200, 0x10, "direct"), (0xffffffff80003300, 0x10, "vt"), (0xffffffff80009000, 0x20, "__x86_indirect_thunk_r11")]
    stats = {}
    got = stack_chain.edges(stack_frames.analyze(text, owner, "x86_64"), owner, stats)
    expect("x86_64 thunk edges", {f: sorted(cs) for f, cs in got.items()},
           {"a": ["callee", "direct", "other"], "c": ["callee"], "d": ["direct"]})
    expect("x86_64 thunk counts", (stats.get("thunk"), stats.get("indirect")), (6, 3))
    # Shrink-wrapped frames: LLVM tests for an early return before it
    # reserves, so a reader that stops at the prologue's first other
    # instruction sees none of the frame. One fixture per ISA, each with the
    # early exit first: riscv64 with a frame too big for one `addi` (`lui` +
    # `sub sp`); aarch64 with a reservation in an arm only its jump table
    # reaches (`br` through a loaded offset); x86_64 with the frame realigned
    # to 64 bytes and given back through the frame pointer.
    def owner_of(spans):
        return lambda addr: next((n for a, z, n in spans if a <= addr < a + z), None)

    text = "\n".join([
        "0000000000030000 <sw>:",
        "   30000: beqz a0, 0x3002c <sw+0x2c>",
        "   30004: addi sp, sp, -0x30",
        "   30008: sd ra, 0x28(sp)",
        "   3000c: lui a1, 0x1",
        "   30010: sub sp, sp, a1",
        "   30014: jal 0x30100 <callee>",
        "   30018: lui a1, 0x1",
        "   3001c: add sp, sp, a1",
        "   30020: ld ra, 0x28(sp)",
        "   30024: addi sp, sp, 0x30",
        "   30028: ret",
        "   3002c: ret",
        "0000000000030100 <callee>:",
        "   30100: ret",
    ])
    an = stack_frames.analyze(text, owner_of([(0x30000, 0x30, "sw"), (0x30100, 4, "callee")]), "riscv64")
    expect("riscv64 shrink-wrapped", (an.frames.get("sw"), an.unbounded), (0x30 + 0x1000, {}))
    text = "\n".join([
        "0000000000040000 <sw>:",
        "   40000: cbz x0, 0x40048 <sw+0x48>",
        "   40004: stp x29, x30, [sp, #-0x20]!",
        "   40008: mov x29, sp",
        "   4000c: sub sp, sp, #0x200",
        "   40010: adr x8, 0x40024 <sw+0x24>",
        "   40014: ldrb w9, [x8, x1]",
        "   40018: add x8, x8, x9, lsl #2",
        "   4001c: br x8",
        "   40020: b 0x4003c <sw+0x3c>",
        "   40024: sub sp, sp, #0x400",
        "   40028: bl 0x40100 <callee>",
        "   4002c: add sp, sp, #0x400",
        "   40030: b 0x4003c <sw+0x3c>",
        "   40034: nop",
        "   40038: nop",
        "   4003c: mov sp, x29",
        "   40040: ldp x29, x30, [sp], #0x20",
        "   40044: ret",
        "   40048: ret",
        "0000000000040100 <callee>:",
        "   40100: ret",
    ])
    an = stack_frames.analyze(text, owner_of([(0x40000, 0x4c, "sw"), (0x40100, 4, "callee")]), "aarch64")
    expect("aarch64 shrink-wrapped", (an.frames.get("sw"), an.unbounded, an.seeded), (0x20 + 0x200 + 0x400, {}, 1))
    text = "\n".join([
        "ffffffff80004000 <sw>:",
        "ffffffff80004000:  testq %rdi, %rdi",
        "ffffffff80004003:  je 0xffffffff80004022 <sw+0x22>",
        "ffffffff80004005:  pushq %rbp",
        "ffffffff80004006:  movq %rsp, %rbp",
        "ffffffff80004009:  pushq %rbx",
        "ffffffff8000400a:  andq $-0x40, %rsp",
        "ffffffff8000400e:  subq $0x80, %rsp",
        "ffffffff80004015:  callq 0xffffffff80004100 <callee>",
        "ffffffff8000401a:  leaq -0x8(%rbp), %rsp",
        "ffffffff8000401e:  popq %rbx",
        "ffffffff8000401f:  popq %rbp",
        "ffffffff80004020:  retq",
        "ffffffff80004022:  retq",
        "ffffffff80004100 <callee>:",
        "ffffffff80004100:  retq",
    ])
    an = stack_frames.analyze(text, owner_of([(0xffffffff80004000, 0x30, "sw"),
                                              (0xffffffff80004100, 1, "callee")]), "x86_64")
    # 8 return address, 16 pushes, 56 at most to a 64-byte boundary from a
    # sp 24 below a 16-aligned one, 128 reserved.
    expect("x86_64 shrink-wrapped", (an.frames.get("sw"), an.unbounded), (8 + 16 + 56 + 0x80, {}))
    # The probe loop of a frame too big to unroll, as LLVM writes it on
    # riscv64 and aarch64 (x86_64's is above): sp steps down a page at a
    # time until it equals the bound register; the loop is bounded by that
    # compare, and the frame is the bound plus what follows it.
    text = "\n".join([
        "0000000000060000 <rvprobe>:",
        "   60000: lui t1, 0x10",
        "   60004: sub t1, sp, t1",
        "   60008: lui t2, 0x1",
        "   6000c: sub sp, sp, t2",
        "   60010: sd zero, 0x0(sp)",
        "   60014: bne sp, t1, 0x60008 <rvprobe+0x8>",
        "   60018: addi sp, sp, -0x30",
        "   6001c: ret",
    ])
    an = stack_frames.analyze(text, owner_of([(0x60000, 0x20, "rvprobe")]), "riscv64")
    expect("riscv64 probe loop", (an.frames.get("rvprobe"), an.unbounded), (0x10000 + 0x30, {}))
    text = "\n".join([
        "0000000000061000 <a64probe>:",
        "   61000: sub x9, sp, #0x10, lsl #12",
        "   61004: sub sp, sp, #0x1, lsl #12",
        "   61008: cmp sp, x9",
        "   6100c: str xzr, [sp]",
        "   61010: b.ne 0x61004 <a64probe+0x4>",
        "   61014: sub sp, sp, #0x30",
        "   61018: ret",
    ])
    an = stack_frames.analyze(text, owner_of([(0x61000, 0x20, "a64probe")]), "aarch64")
    expect("aarch64 probe loop", (an.frames.get("a64probe"), an.unbounded), (0x10000 + 0x30, {}))
    # A call that never returns (a panic) ends its path: what follows it is
    # another block, reached at its own depth. Falling through from the
    # `pushq` that aligned the panic call into the loop below made the loop
    # look as if it lowered sp on every pass (`parse_unsigned_int`, x86_64).
    text = "\n".join([
        "ffffffff80005000 <scan>:",
        "ffffffff80005000:  cmpq %rsi, %rdi",
        "ffffffff80005003:  jae 0xffffffff8000500b <scan+0xb>",
        "ffffffff80005005:  pushq %rax",
        "ffffffff80005006:  callq 0xffffffff80005100 <fail>",
        "ffffffff8000500b:  incq %rdi",
        "ffffffff8000500e:  jmp 0xffffffff80005000 <scan>",
        "ffffffff80005100 <fail>:",
        "ffffffff80005100:  callq 0xffffffff80005200 <halt>",
        "ffffffff80005105:  ud2",
        "ffffffff80005200 <halt>:",
        "ffffffff80005200:  hlt",
        "ffffffff80005201:  jmp 0xffffffff80005200 <halt>",
    ])
    an = stack_frames.analyze(text, owner_of([(0xffffffff80005000, 0x10, "scan"), (0xffffffff80005100, 8, "fail"),
                                              (0xffffffff80005200, 3, "halt")]), "x86_64")
    expect("x86_64 no return", (an.frames.get("scan"), an.unbounded), (16, {}))
    # Code outside every sized symbol: a spinlock's slow path, which inline
    # assembly places after its function, pushes an argument and calls a
    # trampoline that has a zero-size symbol and pops that argument as it
    # returns (`retq $8`). The function's flow follows its jump into the slow
    # path; the trampoline is measured from the call, and is an edge.
    text = "\n".join([
        "ffffffff80007000 <lock>:",
        "ffffffff80007000:  pushq %rbx",
        "ffffffff80007001:  movl $0x1, %eax",
        "ffffffff80007006:  testl %eax, %eax",
        "ffffffff80007008:  jne 0xffffffff80007100 <lock+0x100>",
        "ffffffff8000700a:  popq %rbx",
        "ffffffff8000700b:  retq",
        "ffffffff80007100:  pushq %rdi",
        "ffffffff80007101:  callq 0xffffffff80007200 <tramp>",
        "ffffffff80007106:  jmp 0xffffffff80007006 <lock+0x6>",
        "ffffffff80007200 <tramp>:",
        "ffffffff80007200:  pushq %rax",
        "ffffffff80007201:  pushq %rcx",
        "ffffffff80007202:  popq %rcx",
        "ffffffff80007203:  popq %rax",
        "ffffffff80007204:  retq $0x8",
    ])
    own = owner_of([(0xffffffff80007000, 0xc, "lock")])
    an = stack_frames.analyze(text, own, "x86_64", labels={0xffffffff80007200: "tramp"})
    expect("x86_64 out-of-line slow path", (an.frames.get("lock"), an.frames.get("tramp"), an.unbounded),
           (8 + 8 + 8, 8 + 16, {}))
    expect("routine edge", {f: sorted(cs) for f, cs in stack_chain.edges(an, own).items()}, {"lock": ["tramp"]})
    # Unbounded: sp lowered by a loaded value (an alloca), sp lowered on every
    # pass of a loop, sp set from memory (a stack switch). Each is named, and
    # refused unless UNBOUNDED_ALLOWED gives a reason; the frame is the part
    # that can be bounded.
    text = "\n".join([
        "0000000000050000 <alloca>:",
        "   50000: addi sp, sp, -0x10",
        "   50004: ld a1, 0x0(a0)",
        "   50008: sub sp, sp, a1",
        "   5000c: ret",
        "0000000000050100 <switch>:",
        "   50100: addi sp, sp, -0x20",
        "   50104: ld sp, 0x8(a1)",
        "   50108: ret",
    ])
    an = stack_frames.analyze(text, owner_of([(0x50000, 0x10, "alloca"), (0x50100, 0x10, "switch")]), "riscv64")
    expect("unbounded alloca", (an.frames.get("alloca"), an.unbounded.get("alloca")),
           (0x10, [(0x50008, "adjusts sp by a value it cannot bound: sub sp,sp,a1")]))
    expect("unbounded switch", (an.frames.get("switch"), an.unbounded.get("switch")),
           (0x20, [(0x50104, "sets sp from a value it does not derive from sp: ld sp,0x8(a1)")]))
    expect("unbounded refused", stack_frames.unbounded_verdicts(an.unbounded, {"alloca"}, {"sw*": "a switch"}),
           (["UNBOUNDED alloca: adjusts sp by a value it cannot bound: sub sp,sp,a1 at 0x50008"], []))
    expect("unbounded allowed", stack_frames.unbounded_verdicts(an.unbounded, None, {"sw*": "a switch"})[1],
           ["unbounded, allowed: switch: a switch"])
    text = "\n".join([
        "ffffffff80006000 <grow>:",
        "ffffffff80006000:  pushq %rax",
        "ffffffff80006001:  decq %rdi",
        "ffffffff80006004:  jne 0xffffffff80006000 <grow>",
        "ffffffff80006006:  retq",
    ])
    an = stack_frames.analyze(text, owner_of([(0xffffffff80006000, 8, "grow")]), "x86_64")
    expect("unbounded loop", an.unbounded.get("grow"), [(0xffffffff80006000, "lowers sp on every pass of a loop")])
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

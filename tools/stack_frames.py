#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Largest stack frame per function in a RISC-V, aarch64 or x86_64 image, against a limit.

    stack_frames.py <elf> --limit BYTES [--boot-limit BYTES] [--boot FUNCTION ...] [--top N]

A function's frame is the deepest its stack pointer goes below the one its
caller left it, on ANY path through the function. It is found by a forward
dataflow over the function's control flow (`flow`): at each instruction, the
stack pointer as an offset from its value at entry, and the registers that
hold an offset from it (the frame pointer, a probe loop's bound) or a constant
(what `sub sp, sp, rX` takes its size from, a call's target). One decoder per
ISA turns an instruction into the few effects the dataflow knows
(`decode_riscv64`, `decode_aarch64`, `decode_x86_64`); the dataflow is shared.
Each instruction is attributed through the symbol table, never through
objdump's own headers, which split a body at every local label. An x86_64
frame also counts the return address its caller's `call` pushed, which
riscv64 and aarch64 keep inside the frame they reserve.

Until 2026-10-24 a frame was read from the prologue alone, the steps that
lower sp before the first other instruction. LLVM shrink-wraps: a function
that can return early tests first and reserves its frame after the test, or
reserves more on one path only. Those reservations were missed -- 1,494 of
5,048 functions of the x86_64 kernel, and riscv64 and aarch64 read their
prologues the same way.

An adjustment the dataflow cannot bound -- sp lowered by a register it does
not know (an alloca), sp set from a value not derived from it (a stack
switch), sp lowered on every pass of a loop -- is UNBOUNDED: the frame is a
lower bound, the function is named, and the row fails unless
`UNBOUNDED_ALLOWED` gives the reason that function may do it.

Why the gate needs this: a table sized by a Kconfig limit and declared as a
local lives on whichever stack runs the function. Kernel task stacks are
KERNEL_STACK_SIZE_KB (32 KiB on rv64, 16 on embedded, 4 KiB of it guard), and
the limits differ by up to 256x between profiles, so a function that is
harmless on edge overflows on fleet. The fleet image's first boots faulted four ways like that: the
topology on the boot stack, a `cpu_remove` scratch array of MAX_TASKS
entries, and a machine-sized FdTable per kernel file operation.
Guard pages turn an overflow into a fault only when the frame is smaller than
the guard; a larger frame steps over it into the neighbouring stack.

`--limit` applies to every function except those named with `--boot`, which
run only on the boot stack and get `--boot-limit` (a name with `*` is an
fnmatch pattern, for a generic instance whose full name carries its type
arguments). Exit status 1 when any frame is over its limit or unbounded
without a reason, 2 when the image or the tools cannot be read.

The LLVM tools come from the toolchain's llvm-tools component
(rust-toolchain.toml), or from $LLVM_BIN when set.
"""
import argparse
import bisect
import collections
import fnmatch
import os
import re
import subprocess
import sys

# Functions whose stack pointer the dataflow cannot bound, by name (fnmatch),
# each with the reason it may: the frame the tool charges them is the part it
# can bound. A function that is not here and moves sp out of the dataflow's
# reach fails the row.
UNBOUNDED_ALLOWED = {
    "_start": "the boot entry: sp is set to the boot stack (kernel/src/entry/<isa>/asm/boot.S)",
    "_secondary_start": "a secondary hart's entry: sp is set to its own boot stack",
    "_aarch64_secondary_entry": "a secondary core's entry: sp is set to its own boot stack",
    "trap_entry_common": "the riscv64 trap entry swaps sp with sscratch, the kernel stack (trap_entry.S)",
    "context_switch": "loads the next task's saved sp (kernel/src/entry/<isa>/asm/context_switch.S)",
    "azos_sched::process::sret_to_user": "never returns: loads the user sp and enters user mode",
    "azos_sched::process::sret_to_user_forked": "never returns: loads the user sp and enters user mode",
    "aarch64_ret_to_user*": "never returns: sp becomes the trap frame it erets from (aarch64 trap_entry.S)",
    "x86_64_ret_to_user": "never returns: sp becomes the trap frame it returns to ring 3 from (x86_64 trap_entry.S)",
    "x86_64_ipc_resume_stub": "a resume point: leaves through the syscall return, which loads the user sp",
    "azos_cpu_resume_restore": "resume from suspend: loads the sp azos_cpu_save_run saved (entry/<isa>/resume.rs)",
}


def llvm_bin():
    if os.environ.get("LLVM_BIN"):
        return os.environ["LLVM_BIN"]
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True).stdout.strip()
    host = next((l.split(": ", 1)[1] for l in subprocess.run(
        ["rustc", "-vV"], capture_output=True, text=True).stdout.splitlines() if l.startswith("host: ")), "")
    return os.path.join(sysroot, "lib", "rustlib", host, "bin")


FORMATS = {"elf64-littleriscv": "riscv64", "elf64-littleaarch64": "aarch64", "elf64-x86-64": "x86_64"}


# What `disassemble` reads: the listing, address -> the sized function
# holding it (None outside every one), every defined symbol's name, the ISA
# (a value of `FORMATS`, "" when none fits), the sized functions' addresses,
# and the zero-size code symbols' names by address (hand-written assembly).
Image = collections.namedtuple("Image", "text owner names isa starts labels")


def disassemble(elf, tools):
    """The [`Image`] of `elf`: llvm-objdump's text, names demangled."""
    nm = subprocess.run([os.path.join(tools, "llvm-nm"), "-S", "-C", "--defined-only", elf],
                        capture_output=True, text=True)
    dis = subprocess.run([os.path.join(tools, "llvm-objdump"), "-d", "-C", "--no-show-raw-insn", elf],
                         capture_output=True, text=True)
    if nm.returncode or dis.returncode:
        sys.stderr.write(nm.stderr + dis.stderr)
        sys.exit(2)
    syms, names, labels = [], set(), {}
    for line in nm.stdout.splitlines():
        p = line.split(None, 3)
        if len(p) == 4:
            names.add(p[3])
            if p[2] in "tTwW" and int(p[1], 16):
                syms.append((int(p[0], 16), int(p[1], 16), p[3]))
            elif p[2] in "tT" and not p[3].startswith((".L", "$")):
                labels[int(p[0], 16)] = p[3]
    syms.sort()
    starts = [s[0] for s in syms]

    def owner(addr):
        i = bisect.bisect_right(starts, addr) - 1
        return syms[i][2] if i >= 0 and addr < syms[i][0] + syms[i][1] else None

    head = dis.stdout[:400]
    isa = next((i for f, i in FORMATS.items() if f in head), "")
    return Image(dis.stdout, owner, names, isa, frozenset(starts), labels)


# ---------------------------------------------------------------- listing --

# One instruction: its address, mnemonic, operands without spaces (the
# annotation `<sym+off>` and the comment cut off), the annotation's symbol,
# and the address an x86_64 RIP-relative operand makes (`# 0x...`).
Insn = collections.namedtuple("Insn", "addr op args ann made")
LINE = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$")
# x86_64 prefixes objdump prints as a word of their own: the instruction is
# the next one (`rep` stays, X86_IMPLICIT knows what it writes).
X86_PREFIXES = {"lock", "notrack", "bnd", "xacquire", "xrelease", "data16", "addr32", "rex64",
                "cs", "ds", "es", "fs", "gs", "ss"}
MASK64 = (1 << 64) - 1


def listing(text, owner, isa, starts=frozenset()):
    """`(bodies, runs)` of an objdump listing. `bodies`, `[(function,
    [Insn])]`, one per body in address order: a body starts where the owner
    changes or at one of `starts` (local symbols of one name are separate
    bodies). `runs`, `[[Insn]]`: the stretches of code outside every sized
    symbol -- hand-written assembly behind zero-size labels, and the slow
    paths inline assembly places after its function (a spinlock's call to
    `azos_spin_tas_tramp32`). A function's flow follows its jumps into them
    (`flow`), and a call into one is measured from there (`analyze`)."""
    funcs, runs, prev = [], [], None
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        f = owner(addr)
        op, rest, ann, made = m.group(2), m.group(3), None, None
        if op in X86_PREFIXES and rest:
            op, _, rest = rest.partition(" ")
        lt = rest.find("<")
        if lt >= 0:
            ann = re.sub(r"\+0x[0-9a-f]+$", "", rest[lt + 1:rest.rfind(">")])
            rest = rest[:lt]
        if isa == "x86_64":
            c = re.search(r"#\s*(0x[0-9a-f]+)", rest)
            made = int(c.group(1), 16) if c else None
            rest = rest.split("#", 1)[0]
        elif isa == "aarch64":
            rest = rest.split("//", 1)[0]
        ins = Insn(addr, op, rest.replace(" ", "").replace("\t", ""), ann, made)
        if f is None:
            if prev is not None:
                runs.append([])
                prev = None
            if not runs:
                runs.append([])
            runs[-1].append(ins)
            continue
        if f != prev or addr in starts:
            funcs.append((f, []))
            prev = f
        funcs[-1][1].append(ins)
    return funcs, runs


def split_ops(args):
    """Operands split at the commas outside `[...]` and `(...)`."""
    out, depth, cur = [], 0, ""
    for ch in args:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def num(s):
    return int(s.lstrip("#$"), 0)


def s64(x):
    x &= MASK64
    return x - (1 << 64) if x >> 63 else x


def sext32(x):
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x >> 31 else x


# --------------------------------------------------------------- dataflow --
#
# A state maps a register to ("S", off), the stack pointer at entry plus
# `off`, or to ("C", value), a constant. "sp" is always an ("S", off); a
# register in no entry is unknown. "flags" holds the two registers the last
# compare compared.
#
# An effect is a tuple:
#   ("set", dst, src, k)          dst = src + k (src None: the constant k)
#   ("add", dst, a, b, sign, sh)  dst = a + sign * (b << sh) (sh None: unknown)
#   ("and", dst, a, b)            dst = a & b (b an int or a register)
#   ("sext32"|"zext32", dst)      a 32-bit result (a constant stays one)
#   ("movk", dst, imm, sh)        aarch64's 16-bit insert into a constant
#   ("kill", r, ...)              written with what the dataflow cannot know
#   ("cmp", a, b)                 flags = (a, b)
#   ("flags",)                    flags clobbered
# A control-flow tuple is (kind, target, reg, off, cc, thunk): kind "next",
# "call" (falls through when the callee returns), "jump", "cond" (falls
# through), "ret" (`off`: the bytes x86_64's `retq $N` pops for its caller)
# or "end" (a trap: `ud2`, `unimp`, `brk`); the target address, or the
# register (plus `off`) that holds it; cc "eq"/"ne" when the
# branch is taken exactly when the compared registers are equal/differ; thunk
# when the call or jump goes through an x86_64 retpoline thunk (the target in
# `reg`).
NEXT = ("next", None, None, 0, None, False)
RET = ("ret", None, None, 0, None, False)
END = ("end", None, None, 0, None, False)
NEG = {"eq": "ne", "ne": "eq", None: None}
# Times one instruction's sp may deepen before the loop it is in counts as
# lowering sp on every pass. A probe loop deepens it once per page: 1,024
# allows a 4 MiB frame.
WIDEN = 1024

Frame = collections.namedtuple("Frame", "depth events sites seeded")


def _value(st, r):
    if r is None:
        return None
    if r == "zero":
        return ("C", 0)
    return st.get(r)


def _apply(st, effects):
    """`(state, event)` after `effects`: an event (and no state) when sp is
    written with something the dataflow cannot bound."""
    st = dict(st)
    for e in effects:
        k = e[0]
        if k == "cmp":
            st["flags"] = (e[1], e[2])
            continue
        if k == "flags":
            st.pop("flags", None)
            continue
        if k == "kill":
            if "sp" in e[1:]:
                return None, "sets sp from a value it does not derive from sp"
            for r in e[1:]:
                st.pop(r, None)
            continue
        dst, reads_sp, new = e[1], False, None
        if k == "set":
            if e[2] is None:
                new = ("C", s64(e[3]))
            else:
                v = _value(st, e[2])
                reads_sp = e[2] == "sp"
                if v:
                    new = ("S", v[1] + e[3]) if v[0] == "S" else ("C", s64(v[1] + e[3]))
        elif k == "add":
            a, b, sign, sh = _value(st, e[2]), _value(st, e[3]), e[4], e[5]
            reads_sp = e[2] == "sp"
            if a and b and sh is not None:
                if b[0] == "C":
                    off = sign * (b[1] << sh)
                    new = ("S", a[1] + off) if a[0] == "S" else ("C", s64(a[1] + off))
                elif a[0] == "C" and sign > 0 and sh == 0:
                    new = ("S", b[1] + a[1])
                elif a[0] == "S" and sign < 0 and sh == 0:
                    new = ("C", a[1] - b[1])
        elif k == "and":
            a = _value(st, e[2])
            m = e[3] if isinstance(e[3], int) else _value(st, e[3])
            m = m if isinstance(m, int) or m is None else (m[1] if m[0] == "C" else None)
            reads_sp = e[2] == "sp"
            if a and m is not None:
                if a[0] == "C":
                    new = ("C", s64(a[1] & m))
                elif m < 0 and (-m) & (-m - 1) == 0:
                    # Aligning down to A = -m bytes, from a caller's sp that
                    # is 16-aligned: at most A - 16 + (off mod 16) more.
                    pad = -m - 16 + a[1] % 16 if -m >= 16 else -m - 1
                    new = ("S", a[1] - pad)
        elif k in ("sext32", "zext32"):
            v = st.get(dst)
            if v and v[0] == "C":
                new = ("C", sext32(v[1]) if k == "sext32" else v[1] & 0xFFFFFFFF)
        elif k == "movk":
            v = st.get(dst)
            if v and v[0] == "C":
                new = ("C", s64(v[1] & ~(0xFFFF << e[3]) | e[2] << e[3]))
        if dst == "zero":
            continue
        if dst == "sp":
            if not new or new[0] != "S":
                return None, ("adjusts sp by a value it cannot bound" if reads_sp
                              else "sets sp from a value it does not derive from sp")
            st["sp"] = new
        elif new:
            st[dst] = new
        else:
            st.pop(dst, None)
    return st, None


def _join(old, new):
    """The state where two paths meet: sp at the deeper of the two, every
    other register only when both paths agree on it."""
    out = {r: v for r, v in old.items() if r != "sp" and new.get(r) == v}
    out["sp"] = min(old["sp"], new["sp"])
    return out


def _refine(st, cc):
    """The state on an edge taken when the compared registers are equal
    (cc "eq") or differ ("ne"), when one of them is sp and the other a known
    offset from it -- a probe loop's bound: equal, sp is at the bound; differ
    while sp is already there, the edge is never taken (None)."""
    fl = st.get("flags")
    if not cc or not fl or "sp" not in fl:
        return st
    bound = st.get(fl[0] if fl[1] == "sp" else fl[1])
    if not bound or bound[0] != "S":
        return st
    if cc == "eq":
        return dict(st, sp=bound)
    return None if st["sp"] == bound else st


def flow(body, decoded, entry, noreturn=frozenset(), more=None, start=None, pops=None):
    """The [`Frame`] of one function: `body` its instructions, `decoded` the
    `(effects, control flow)` of each, `entry` sp's offset at entry (minus
    the return address on x86_64), `noreturn` the addresses of the functions
    that never return, `more` address -> the `(Insn, decoded)` of the code
    outside every sized symbol from there on (see `listing`), `start` the
    address to begin at when `body` is empty (a routine in that code), and
    `pops` address -> the bytes the function there pops off its caller's
    stack as it returns (the spinlock trampoline's `retq $8` takes the word
    its caller pushed).

    `depth` is the deepest sp gets below the caller's on any path; `events`
    the `(address, what)` of each unbounded write; `sites` per call or jump,
    `(kind, target address or None, thunk)`, the target read through the
    register's state where it is one; `seeded` whether jump-table arms had
    to be reached from the indirect jumps' state.

    The flow follows fall-through and the branches inside the function, and
    its jumps into code no sized symbol holds. A path ends at a return, a
    jump into another function (a tail call), a call that does not return (a
    panic: what follows it is another block, often at another depth) or an
    unbounded write. Where paths meet, sp is the deeper of theirs. An
    indirect jump (a jump table) has no known target, so its arms are never
    reached: once the rest is settled, every unreached instruction that
    nothing falls into starts from the indirect jumps' state, until none is
    left."""
    body, decoded = list(body), list(decoded)
    at = {ins.addr: i for i, ins in enumerate(body)}
    fall = [i + 1 for i in range(len(body) - 1)] + [None] * bool(body)
    state, raised = [None] * len(body), [0] * len(body)
    events, sites, indirect, stopped = [], {}, [], set()
    deepest, seeded = entry, False

    def index(t):
        """The index of the instruction at `t`, the code outside every sized
        symbol from `t` appended first when it is that (None otherwise)."""
        if t in at:
            return at[t]
        first = prev = None
        for ins, d in (more(t) if more else ()):
            if ins.addr in at:
                if prev is not None:
                    fall[prev] = at[ins.addr]
                break
            j = len(body)
            body.append(ins)
            decoded.append(d)
            at[ins.addr] = j
            fall.append(None)
            state.append(None)
            raised.append(0)
            if prev is None:
                first = j
            else:
                fall[prev] = j
            prev = j
            if d[1][0] in ("jump", "ret", "end"):
                break
        return first

    def target(st, fl):
        if fl[1] is not None or fl[2] is None:
            return fl[1]
        v = _value(st, fl[2])
        return (v[1] + fl[3]) & MASK64 if v and v[0] == "C" else None

    def push(j, st):
        if j is None or j in stopped or st is None:
            return
        old = state[j]
        if old is None:
            state[j] = st
        else:
            merged = _join(old, st)
            if merged == old:
                return
            state[j] = merged
            if merged["sp"] != old["sp"]:
                raised[j] += 1
                if raised[j] > WIDEN:
                    events.append((body[j].addr, "lowers sp on every pass of a loop"))
                    stopped.add(j)
                    return
        work.append(j)

    work = []
    push(0 if start is None else index(start), {"sp": ("S", entry)})
    while True:
        while work:
            i = work.pop()
            if i in stopped:
                continue
            st = state[i]
            effects, fl = decoded[i]
            kind = fl[0]
            if kind in ("call", "jump", "cond"):
                sites[i] = (kind, target(st, fl), fl[5])
            out, ev = _apply(st, effects)
            if ev:
                events.append((body[i].addr, f"{ev}: {body[i].op} {body[i].args}"))
                stopped.add(i)
                continue
            deepest = min(deepest, out["sp"][1])
            if kind == "call" and sites[i][1] not in noreturn:
                popped = pops(sites[i][1]) if pops and sites[i][1] is not None else 0
                push(fall[i], dict(out, sp=("S", out["sp"][1] + popped)) if popped else out)
            elif kind == "next":
                push(fall[i], out)
            elif kind in ("jump", "cond"):
                t = sites[i][1]
                if kind == "cond":
                    push(fall[i], _refine(out, NEG[fl[4]]))
                if t is None:
                    indirect.append(out)
                else:
                    push(index(t), _refine(out, fl[4]))
        falls_in = {fall[i] for i, (effects, fl) in enumerate(decoded)
                    if fl[0] in ("next", "cond") or fl[0] == "call" and sites.get(i, fl)[1] not in noreturn}
        seeds = [i for i in range(len(body)) if state[i] is None and i not in stopped and i not in falls_in]
        if not indirect or not seeds:
            break
        seeded = True
        begin = indirect[0]
        for o in indirect[1:]:
            begin = _join(begin, o)
        for i in seeds:
            push(i, begin)
    for i, (effects, fl) in enumerate(decoded):
        if fl[0] in ("call", "jump", "cond") and i not in sites:
            sites[i] = (fl[0], fl[1], fl[5])
    return Frame(-deepest, events, [sites[i] for i in sorted(sites)], seeded)


# --------------------------------------------------------------- riscv64 --

RV_GPR = {"zero", "ra", "sp", "gp", "tp", *(f"t{i}" for i in range(7)), *(f"s{i}" for i in range(12)),
          *(f"a{i}" for i in range(8))}
RV_CALL = (("kill", "ra", *(f"t{i}" for i in range(7)), *(f"a{i}" for i in range(8))), ("flags",))
RV_STORES = {"sb", "sh", "sw", "sd", "fsh", "fsw", "fsd", "fsq"}
RV_BRANCH2 = {"beq": "eq", "bne": "ne", "blt": None, "bge": None, "bltu": None, "bgeu": None,
              "bgt": None, "ble": None, "bgtu": None, "bleu": None}
RV_BRANCH1 = {"beqz": "eq", "bnez": "ne", "blez": None, "bgez": None, "bltz": None, "bgtz": None}
RV_ADDR = re.compile(r"^(-?(?:0x[0-9a-f]+|\d+))\((\w+)\)$")


def decode_riscv64(ins):
    op = ins.op[2:] if ins.op.startswith("c.") else ins.op
    a = ["s0" if x == "fp" else x for x in split_ops(ins.args)]
    if op in RV_BRANCH2 and len(a) == 3:
        cc = RV_BRANCH2[op]
        return ((("cmp", a[0], a[1]),) if cc else ()), ("cond", num(a[2]), None, 0, cc, False)
    if op in RV_BRANCH1 and len(a) == 2:
        cc = RV_BRANCH1[op]
        return ((("cmp", a[0], "zero"),) if cc else ()), ("cond", num(a[1]), None, 0, cc, False)
    if op == "j":
        return (), ("jump", num(a[0]), None, 0, None, False)
    if op == "jal":
        rd, t = a if len(a) == 2 else ("ra", a[0])
        if rd == "zero":
            return (), ("jump", num(t), None, 0, None, False)
        return RV_CALL, ("call", num(t), None, 0, None, False)
    if op in ("jalr", "jr"):
        rd = "ra" if op == "jalr" else "zero"
        if op == "jalr" and len(a) >= 2 and a[0] in RV_GPR:
            rd, a = a[0], a[1:]
        m = RV_ADDR.match(a[0])
        rs, off = (m.group(2), num(m.group(1))) if m else (a[0], num(a[1]) if len(a) > 1 else 0)
        if rd == "zero":
            return (), ("jump", None, rs, off, None, False)
        return RV_CALL, ("call", None, rs, off, None, False)
    if op in ("ret", "mret", "sret"):
        return (), RET
    if op == "unimp":
        return (), END
    if op == "lui":
        return (("set", a[0], None, sext32(num(a[1]) << 12)),), NEXT
    if op == "auipc":
        return (("set", a[0], None, ins.addr + sext32(num(a[1]) << 12)),), NEXT
    if op == "li":
        return (("set", a[0], None, num(a[1])),), NEXT
    if op == "mv":
        return (("set", a[0], a[1], 0),), NEXT
    if op in ("addi", "addiw"):
        e = (("set", a[0], a[1], num(a[2])),)
        return (e + (("sext32", a[0]),) if op == "addiw" else e), NEXT
    if op in ("add", "sub", "addw", "subw"):
        e = (("add", a[0], a[1], a[2], -1 if op[0] == "s" else 1, 0),)
        return (e + (("sext32", a[0]),) if op[-1] == "w" else e), NEXT
    if op == "neg":
        return (("add", a[0], "zero", a[1], -1, 0),), NEXT
    if op in ("andi", "and"):
        return (("and", a[0], a[1], num(a[2]) if op == "andi" else a[2]),), NEXT
    if op == "ecall":
        return (("kill", "a0", "a1"),), NEXT
    if op in RV_STORES or not a or a[0] not in RV_GPR:
        return (), NEXT
    return (("kill", a[0]),), NEXT


# --------------------------------------------------------------- aarch64 --

A64_REGS = {**{f"x{i}": f"x{i}" for i in range(31)}, **{f"w{i}": f"x{i}" for i in range(31)},
            "sp": "sp", "wsp": "sp", "xzr": "zero", "wzr": "zero", "fp": "x29", "lr": "x30"}
A64_CALL = (("kill", *(f"x{i}" for i in range(19)), "x30"), ("flags",))
# What writes no general register.
A64_NO_DEST = {"msr", "dc", "ic", "at", "tlbi", "dsb", "dmb", "isb", "hint", "nop", "bti", "paciasp",
               "pacibsp", "autiasp", "autibsp", "wfi", "wfe", "sev", "sevl", "yield", "clrex", "prfm",
               "prfum", "csdb", "esb", "sb", "tst", "fcmp", "fcmpe", "ccmp", "ccmn", "cmn"}
A64_FLAGS = {"cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fcmpe", "adds", "subs", "ands", "bics", "negs",
             "adcs", "sbcs", "ngcs"}
A64_SHIFT = re.compile(r"^(lsl|uxtx|sxtx)#(\d+)$")


def decode_aarch64(ins):
    op, a = ins.op, split_ops(ins.args)
    r = [A64_REGS.get(x) for x in a]
    flags = (("flags",),) if op in A64_FLAGS or (op == "msr" and "nzcv" in ins.args) else ()
    if op == "b":
        return (), ("jump", num(a[0]), None, 0, None, False)
    if op == "bl":
        return A64_CALL, ("call", num(a[0]), None, 0, None, False)
    if op == "blr":
        return A64_CALL, ("call", None, r[0], 0, None, False)
    if op == "br":
        return (), ("jump", None, r[0], 0, None, False)
    if op.startswith("b."):
        return (), ("cond", num(a[0]), None, 0, {"b.eq": "eq", "b.ne": "ne"}.get(op), False)
    if op in ("cbz", "cbnz", "tbz", "tbnz"):
        return (), ("cond", num(a[-1]), None, 0, None, False)
    if op in ("ret", "retaa", "retab", "eret", "eretaa", "eretab"):
        return (), RET
    if op in ("brk", "udf", "hlt"):
        return (), END
    if op in ("svc", "hvc", "smc"):
        return (("kill", *(f"x{i}" for i in range(18))),), NEXT
    mem = next((i for i, x in enumerate(a) if x.startswith("[")), None)
    if mem is not None:
        inner = split_ops(a[mem].rstrip("!")[1:-1])
        base, wb = A64_REGS.get(inner[0]), None
        if a[mem].endswith("!") and len(inner) > 1:
            wb = num(inner[1])
        elif mem + 1 < len(a) and a[mem + 1].startswith("#"):
            wb = num(a[mem + 1])
        e = []
        if op.startswith(("ld", "swp", "cas")):
            e.append(("kill", *(x for x in r[:mem] if x)))
        elif op.startswith(("stx", "stlx")):
            e.append(("kill", r[0]))
        if wb is not None and base:
            e.append(("set", base, base, wb))
        return tuple(e), NEXT
    if op == "cmp" and len(a) == 2 and r[1]:
        return (("cmp", r[0], r[1]),), NEXT
    if op in A64_NO_DEST or op == "cmp" or not a or not r[0]:
        return flags, NEXT
    d, w = r[0], a[0].startswith("w")
    narrow = (("zext32", d),) if w else ()
    if op in ("add", "sub", "adds", "subs") and len(a) >= 3:
        sign, sh = (-1 if op.startswith("sub") else 1), 0
        if len(a) == 4:
            m = A64_SHIFT.match(a[3])
            sh = int(m.group(2)) if m else None
        if a[2].startswith("#"):
            e = ("set", d, r[1], sign * (num(a[2]) << sh)) if sh is not None else ("kill", d)
        else:
            e = ("add", d, r[1], r[2], sign, sh) if r[2] else ("kill", d)
        return (e,) + narrow + flags, NEXT
    if op in ("mov", "movz", "movn") and len(a) >= 2:
        if a[1].startswith("#"):
            v = num(a[1])
            if len(a) == 3:
                m = A64_SHIFT.match(a[2])
                v <<= int(m.group(2)) if m else 0
            v = ~v if op == "movn" else v
            return (("set", d, None, v & 0xFFFFFFFF if w else v),), NEXT
        if r[1]:
            return (("set", d, r[1], 0),) + narrow, NEXT
    if op == "movk" and len(a) >= 2:
        m = A64_SHIFT.match(a[2]) if len(a) == 3 else None
        return (("movk", d, num(a[1]), int(m.group(2)) if m else 0),), NEXT
    if op in ("adr", "adrp"):
        return (("set", d, None, num(a[1])),), NEXT
    if op in ("and", "ands") and len(a) == 3:
        return (("and", d, r[1], num(a[2]) if a[2].startswith("#") else r[2]),) + narrow + flags, NEXT
    return (("kill", d),) + flags, NEXT


# ---------------------------------------------------------------- x86_64 --

# The 16 general registers by every name a write can give them (`%r11d`
# writes %r11, `%eax` and `%al` write %rax); %rsp is "sp" on every ISA.
X86_REGS = {}
for _r in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
    for _n in ("r" + _r, "e" + _r, _r):
        X86_REGS[_n] = "r" + _r
for _r in ("a", "b", "c", "d"):
    X86_REGS[_r + "l"] = X86_REGS[_r + "h"] = "r" + _r + "x"
for _r in ("si", "di", "bp", "sp"):
    X86_REGS[_r + "l"] = "r" + _r
for _i in range(8, 16):
    for _s in ("", "d", "w", "b"):
        X86_REGS[f"r{_i}{_s}"] = f"r{_i}"
X86_REGS.update({n: "sp" for n, v in X86_REGS.items() if v == "rsp"})
# What a call does not preserve (SysV): %r11 is among them, so a thunk
# target never survives a call.
X86_CALL = (("kill", "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"), ("flags",))
# Writes no operand names.
X86_IMPLICIT = {
    "cpuid": {"rax", "rbx", "rcx", "rdx"}, "syscall": {"rcx", "r11"}, "sysretq": {"rcx", "r11"},
    "rdtsc": {"rax", "rdx"}, "rdtscp": {"rax", "rcx", "rdx"}, "rdmsr": {"rax", "rdx"},
    "xgetbv": {"rax", "rdx"}, "rdpkru": {"rax", "rdx"},
    "rep": {"rax", "rcx", "rsi", "rdi"}, "repe": {"rax", "rcx", "rsi", "rdi"},
    "repne": {"rax", "rcx", "rsi", "rdi"}, "loop": {"rcx"},
    "cqto": {"rdx"}, "cltd": {"rdx"}, "cltq": {"rax"}, "cwtl": {"rax"},
    **{op + w: {"rax", "rsi", "rdi"} for op in ("movs", "stos", "lods", "cmps", "scas") for w in "bwlq"},
    **{op + w: {"rax", "rdx"} for op in ("mul", "div", "idiv", "cmpxchg") for w in ("", "b", "w", "l", "q")},
    "cmpxchg8b": {"rax", "rdx"}, "cmpxchg16b": {"rax", "rdx"},
}
# Ops that only read their operands.
X86_READS = re.compile(r"^(cmp[bwlq]?|test[bwlq]?|bt[bwlq]?|nop[wlq]?|prefetch\w*|u?comis[sd]|endbr64)$")
# Ops that leave the flags as they were.
X86_KEEPS_FLAGS = re.compile(r"^(mov\w*|cmov\w*|lea[lq]?|push\w*|pop[qw]?|nop[wlq]?|endbr64|set\w+)$")
X86_RETS = ("retq", "ret", "iretq", "sysretq", "lretq")
X86_TRAPS = ("ud2", "ud1", "int3")
X86_THUNK = re.compile(r"^__x86_indirect_thunk_(\w+)$")
X86_MEM = re.compile(r"^(-?(?:0x[0-9a-f]+|\d+))?\(%(\w+)(?:,%(\w+))?(?:,\d+)?\)$")


def _x86_reg(s):
    return X86_REGS.get(s[1:]) if s.startswith("%") else None


def decode_x86_64(ins):
    op, a = ins.op, split_ops(ins.args)
    if op in X86_RETS:
        return (), ("ret", None, None, num(a[0]), None, False) if a else RET
    if op in X86_TRAPS:
        return (), END
    if op.startswith("call") or op.startswith("j"):
        kind = "call" if op.startswith("call") else "jump" if op in ("jmp", "jmpq") else "cond"
        cc = {"je": "eq", "jz": "eq", "jne": "ne", "jnz": "ne"}.get(op)
        thunk = X86_THUNK.match(ins.ann or "")
        if thunk:
            fl = (kind, None, X86_REGS.get(thunk.group(1)), 0, cc, True)
        elif a and a[0].startswith("*"):
            fl = (kind, None, _x86_reg(a[0][1:]), 0, cc, False)
        else:
            fl = (kind, num(a[0]) if a and re.fullmatch(r"0x[0-9a-f]+", a[0]) else None, None, 0, cc, False)
        return (X86_CALL if kind == "call" else ()), fl
    dst = _x86_reg(a[-1]) if a else None
    flags = () if X86_KEEPS_FLAGS.match(op) else (("flags",),)
    e = [("kill", *X86_IMPLICIT[op])] if op in X86_IMPLICIT else []
    if op.startswith("push"):
        e.append(("set", "sp", "sp", -2 if op == "pushw" else -8))
    elif op.startswith("pop") and not op.startswith("popcnt"):
        if dst:
            e.append(("kill", dst))
        e.append(("set", "sp", "sp", 2 if op == "popw" else 8))
    elif op in ("leave", "leaveq"):
        e += [("set", "sp", "rbp", 8), ("kill", "rbp")]
    elif op.startswith("cmp") and len(a) == 2 and _x86_reg(a[0]) and dst:
        return (("cmp", _x86_reg(a[0]), dst),), NEXT
    elif X86_READS.match(op) or not dst:
        pass
    elif op in ("movq", "movabsq", "movl") and len(a) == 2 and (a[0].startswith("$") or _x86_reg(a[0])):
        if a[0].startswith("$"):
            v = num(a[0])
            e.append(("set", dst, None, v & 0xFFFFFFFF if op == "movl" else v))
        else:
            e.append(("set", dst, _x86_reg(a[0]), 0))
            if op == "movl":
                e.append(("zext32", dst))
    elif op == "leaq" and len(a) == 2:
        m = X86_MEM.match(a[0])
        if m and m.group(2) == "rip" and ins.made is not None:
            e.append(("set", dst, None, ins.made))
        elif m and not m.group(3) and X86_REGS.get(m.group(2)):
            e.append(("set", dst, X86_REGS[m.group(2)], num(m.group(1) or "0")))
        else:
            e.append(("kill", dst))
    elif op in ("addq", "subq") and len(a) == 2:
        sign = -1 if op == "subq" else 1
        if a[0].startswith("$"):
            e.append(("set", dst, dst, sign * num(a[0])))
        elif _x86_reg(a[0]):
            e.append(("add", dst, dst, _x86_reg(a[0]), sign, 0))
        else:
            e.append(("kill", dst))
    elif op == "andq" and len(a) == 2 and (a[0].startswith("$") or _x86_reg(a[0])):
        e.append(("and", dst, dst, s64(num(a[0])) if a[0].startswith("$") else _x86_reg(a[0])))
    elif op.startswith(("xchg", "xadd", "cmpxchg")):
        e.append(("kill", *{r for x in a for r in [_x86_reg(x)] if r}))
    else:
        e.append(("kill", dst))
    return tuple(e) + flags, NEXT


# Per ISA: its decoder, and sp's offset at entry (x86_64's `call` pushed the
# return address below the caller's sp).
DECODERS = {"riscv64": (decode_riscv64, 0), "aarch64": (decode_aarch64, 0), "x86_64": (decode_x86_64, -8)}
# Mnemonics whose decoding depends on the instruction's own address.
PC_RELATIVE = {"auipc"}

Analysis = collections.namedtuple("Analysis", "frames unbounded sites seeded routines")


def analyze(text, owner, isa, starts=frozenset(), labels=None):
    """The [`Analysis`] of an objdump listing for `isa` (`owner`, `starts`
    and `labels` as an [`Image`]'s): `frames`, function -> its frame in bytes
    (functions that reserve none are left out on riscv64 and aarch64);
    `unbounded`, function -> its unbounded writes `[(address, what)]`;
    `sites`, function -> its calls and jumps (see [`flow`]); `seeded`, how
    many functions needed their jump-table arms seeded; `routines`, address
    -> name of each routine outside every sized symbol that a call reaches,
    measured like a function from there (`labels` names it; `asm@<address>`
    when nothing does)."""
    decode, entry = DECODERS[isa]
    cache, bodies = {}, []

    def dec(ins):
        if ins.op in PC_RELATIVE:
            return decode(ins)
        key = (ins.op, ins.args, ins.ann, ins.made)
        d = cache.get(key)
        if d is None:
            d = cache[key] = decode(ins)
        return d

    funcs, runs = listing(text, owner, isa, starts)
    for f, body in funcs:
        bodies.append((f, body, [dec(ins) for ins in body]))
    where = {ins.addr: (r, k) for r, run in enumerate(runs) for k, ins in enumerate(run)}

    def more(t):
        if t in where:
            r, k = where[t]
            for ins in runs[r][k:]:
                yield ins, dec(ins)

    popping = {body[0].addr: fl[3] for f, body, decoded in bodies for effects, fl in decoded
               if fl[0] == "ret" and fl[3]}

    def pops(t):
        if t in where:
            return next((d[1][3] for ins, d in more(t) if d[1][0] == "ret"), 0)
        return popping.get(t, 0)

    noreturn = never_return(bodies)
    frames, unbounded, sites, seeded = {}, {}, collections.defaultdict(list), 0
    routines, todo = {}, []

    def record(f, fr):
        nonlocal seeded
        if fr.depth > frames.get(f, 0):
            frames[f] = fr.depth
        if fr.events:
            unbounded.setdefault(f, []).extend(fr.events)
        sites[f] += fr.sites
        seeded += fr.seeded
        for kind, t, _ in fr.sites:
            if kind == "call" and t in where and t not in routines:
                routines[t] = (labels or {}).get(t, f"asm@{t:#x}")
                todo.append(t)

    for f, body, decoded in bodies:
        record(f, flow(body, decoded, entry, noreturn, more, pops=pops))
    while todo:
        t = todo.pop()
        record(routines[t], flow([], [], entry, noreturn, more, t, pops))
    return Analysis(frames, unbounded, sites, seeded, routines)


def never_return(bodies):
    """The start addresses of the bodies that never return: no return
    instruction, and every jump out of them (a tail call) to one that never
    returns either. A call to one ends its caller's path. A body that jumps
    through a register it cannot read is taken to return."""
    out = {}   # start -> the starts it tail-jumps to, for the bodies with no return
    for f, body, decoded in bodies:
        lo, hi = body[0].addr, body[-1].addr
        tails, returns = set(), False
        for (effects, fl) in decoded:
            if fl[0] == "ret" or fl[0] == "jump" and fl[1] is None:
                returns = True
                break
            if fl[0] in ("jump", "cond") and fl[1] is not None and not lo <= fl[1] <= hi:
                tails.add(fl[1])
        if not returns:
            out[lo] = tails
    changed = True
    while changed:
        changed = False
        for start in list(out):
            if any(t not in out for t in out[start]):
                del out[start]
                changed = True
    return frozenset(out)


def frames(elf, tools):
    """The [`Analysis`] of `elf`."""
    im = disassemble(elf, tools)
    if not im.isa:
        sys.stderr.write(f"{elf}: not a riscv64, aarch64 or x86_64 image\n")
        sys.exit(2)
    return analyze(im.text, im.owner, im.isa, im.starts, im.labels)


def unbounded_verdicts(unbounded, functions=None, allowed=None):
    """`(refused, excused)` of an [`Analysis`]'s `unbounded`, restricted to
    `functions` when given: the lines of the functions no entry of `allowed`
    (default `UNBOUNDED_ALLOWED`) names, and of those one does, with its
    reason."""
    allowed = UNBOUNDED_ALLOWED if allowed is None else allowed
    refused, excused = [], []
    for f in sorted(unbounded):
        if functions is not None and f not in functions:
            continue
        why = next((r for p, r in allowed.items() if fnmatch.fnmatchcase(f, p)), None)
        addr, what = unbounded[f][0]
        more = f" (and {len(unbounded[f]) - 1} more)" if len(unbounded[f]) > 1 else ""
        if why:
            excused.append(f"unbounded, allowed: {f}: {why}")
        else:
            refused.append(f"UNBOUNDED {f}: {what} at {addr:#x}{more}")
    return refused, excused


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("elf")
    ap.add_argument("--limit", type=int, required=True)
    ap.add_argument("--boot-limit", type=int, default=0)
    ap.add_argument("--boot", action="append", default=[])
    ap.add_argument("--top", type=int, default=5)
    a = ap.parse_args()
    if not os.path.isfile(a.elf):
        sys.stderr.write(f"no image at {a.elf}\n")
        sys.exit(2)
    an = frames(a.elf, llvm_bin())
    fr = an.frames
    over = []
    for f, size in sorted(fr.items(), key=lambda x: -x[1]):
        boot = any(fnmatch.fnmatchcase(f, b) if "*" in b else f == b for b in a.boot)
        limit = a.boot_limit if boot else a.limit
        if size > limit:
            over.append((size, limit, f))
    for size, f in sorted(((s, f) for f, s in fr.items()), reverse=True)[:a.top]:
        print(f"{size:9d}  {f}")
    refused, excused = unbounded_verdicts(an.unbounded)
    if excused:
        print(f"           unbounded sp allowed by UNBOUNDED_ALLOWED in {len(excused)} function(s)")
    for size, limit, f in over:
        print(f"OVER {size} > {limit}: {f}")
    for line in refused:
        print(line)
    sys.exit(1 if over or refused else 0)


if __name__ == "__main__":
    main()

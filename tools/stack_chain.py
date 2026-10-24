#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Deepest call chain in a riscv64, aarch64 or x86_64 kernel image, against a stack budget.

    stack_chain.py <elf> --limit BYTES [--root SYMBOL ...] [--frames N]

The frame lint (tools/stack_frames.py) asks whether any single function is too
big for the stack. That is not what overflows a stack. On 2026-09-15 every
brain-peer boot died in a kernel page fault with no frame anywhere near the
limit: ten small and medium frames in one chain summed past the 12 KiB a
16 KiB task stack has above its guard page. This tool asks the question that
actually matters -- how deep can one trap go -- and it found that the embedded
profile still did not fit its own deepest syscall chain after that night's fix.

HOW IT WORKS. Frames come from stack_frames.frames(), which sums a whole
prologue. Edges come from every call and tail jump llvm-objdump annotates,
resolved by the address they reach (`edges`), so an `auipc`+`jalr` long call
is resolved exactly like a `jal`; on x86_64 the retpoline thunk's target is
read from the instruction stream (`x86_64_edges`). The deepest chain is the
maximum sum over paths from each root, plus the panic handler's own chain
once (`chain`). The roots are the Rust functions each ISA's trap entry
(`kernel/src/entry/<isa>/asm/trap_entry.S`) calls on the task's stack
(`ROOTS`); `--root` replaces them.

WHAT IT DOES NOT SEE, and therefore why this is a LOWER bound:
  * Indirect calls through a function pointer or a vtable are not followed:
    on riscv64 and aarch64 a `jalr`/`blr` through a register no `auipc` just
    set, on x86_64 a thunk call whose register was loaded from memory. x86_64
    prints how many thunk calls that leaves.
  * Recursion is cut at the first repeat; a recursive cycle's true depth is
    a run-time property this cannot know. Cuts are counted and printed.
  * Inlined code has no symbol: its locals are already inside its caller's
    frame, but a chain that only exists inside an inlined body is attributed
    to the caller, which is correct, while a root that was inlined away
    cannot be named on the command line.
A limit set from this number therefore needs margin, not equality.

THE BUDGET. A kernel task stack is KERNEL_STACK_SIZE_BYTES with the first
page a guard, so the usable depth is that minus 4096. Out of it must come the
deepest chain and the trap frame that starts it (288 bytes on riscv64, 192 on
x86_64: the gate's `chain_row`). An interrupt taken on top costs only that
frame since 2026-09-16: its handler runs on the hart's own interrupt stack
(kernel/src/entry/<isa>/asm/trap_entry.S).

Exit 1 when the chain is over the limit, or when a recursive block too big to
walk decides the verdict (see `longest`); 2 when the image cannot be read.
"""
import argparse
import bisect
import collections
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack_frames

CALL = ("jal", "jalr", "j", "tail", "c.j", "c.jal", "c.jalr", "c.jr", "jr", "bl", "b")


# The Rust functions each ISA's trap entry calls on the task's stack, by the
# format llvm-objdump names: the exception and interrupt dispatch, the lean
# native-syscall entries that skip it (Chain E cut 7), and the reschedule
# after an interrupt.
ROOTS = {
    "elf64-littleriscv": ("riscv64_trap_handler", "riscv64_native_syscall", "riscv64_fast_ipc_syscall",
                          "trap_resched"),
    "elf64-littleaarch64": ("aarch64_trap_entry", "aarch64_trap_resched"),
    "elf64-x86-64": ("x86_64_trap_entry", "x86_64_native_syscall", "x86_64_fast_ipc_syscall",
                     "x86_64_trap_resched"),
}


def call_graph(elf, tools, stats=None):
    """`(graph, names, format)`: the image's call graph, its function names and
    the file format llvm-objdump read (a key of `ROOTS`). `stats` (a dict)
    gets the x86_64 thunk counts."""
    nm = subprocess.run([os.path.join(tools, "llvm-nm"), "-S", "-C", "--defined-only", elf],
                        capture_output=True, text=True)
    dis = subprocess.run([os.path.join(tools, "llvm-objdump"), "-d", "-C", "--no-show-raw-insn", elf],
                         capture_output=True, text=True)
    if nm.returncode or dis.returncode:
        sys.stderr.write(nm.stderr + dis.stderr)
        sys.exit(2)
    syms = []
    for line in nm.stdout.splitlines():
        p = line.split(None, 3)
        if len(p) == 4 and p[2] in "tTwW" and int(p[1], 16):
            syms.append((int(p[0], 16), int(p[1], 16), p[3]))
    syms.sort()
    starts = [s[0] for s in syms]

    def owner(addr):
        i = bisect.bisect_right(starts, addr) - 1
        return syms[i][2] if i >= 0 and addr < syms[i][0] + syms[i][1] else None

    fmt = next((f for f in ROOTS if f in dis.stdout[:400]), "")
    graph = x86_64_edges(dis.stdout, owner, stats) if fmt == "elf64-x86-64" else edges(dis.stdout, owner)
    return graph, {s[2] for s in syms}, fmt


# `jal`/`j`/`bl`/`b` print their target address; `jalr`/`jr` print an offset
# from a register an `auipc` just before set.
AUIPC = re.compile(r"^(\w+),(-?0x[0-9a-f]+|-?\d+)$")
JALR = re.compile(r"^(?:\w+,)?(-?0x[0-9a-f]+|-?\d+)\((\w+)\)$")


def edges(text, owner):
    """The call graph of an objdump listing: function -> the functions it
    calls or tail-jumps to, each resolved through `owner` (address -> the
    function holding it).

    A call is resolved by the ADDRESS it reaches, not by the name objdump
    annotates it with. Images keep the assembler's local labels
    (`.Lpcrel_hiN`, one set per compilation unit) and objdump names a target
    by the nearest one, `<.Lpcrel_hi164+0x1a>`, a name 57 functions of the
    2026-10-24 qemu kernel define. Looking the name up resolved a branch to
    the last of them: `ip::iface_get`'s jump to its own exit "called"
    `waitgraph::effective`, and edges like it knotted 331 functions into one
    recursive component that the chain charged whole (32 KiB of a 54 KiB
    chain). A symbol annotation (`<memcpy>`) is unique and used as given."""
    graph = collections.defaultdict(set)
    hi = {}  # register -> the address its `auipc` made, in the current function
    cur = None
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if not m:
            continue
        addr, op, rest = int(m.group(1), 16), m.group(2), m.group(3)
        f = owner(addr)
        if f != cur:
            cur, hi = f, {}
        args = re.sub(r"\s*<.*$", "", rest).replace(" ", "")
        if op == "auipc":
            a = AUIPC.match(args)
            if a:
                imm = int(a.group(2), 0) & 0xFFFFF
                hi[a.group(1)] = addr + ((imm ^ 0x80000) - 0x80000 << 12)
            continue
        if op not in CALL:
            continue
        ann = re.search(r"<(.+?)(\+0x[0-9a-f]+)?>\s*$", rest)
        if not (f and ann):
            continue
        target = ann.group(1)
        if target.startswith(".L"):
            to = re.search(r"(?:^|,)(0x[0-9a-f]+)$", args)
            j = JALR.match(args)
            if to:
                target = owner(int(to.group(1), 16))
            elif j and j.group(2) in hi:
                target = owner(hi[j.group(2)] + int(j.group(1), 0))
            else:
                continue
        if target and target != f:
            graph[f].add(target)
    return graph


# x86_64 (AT&T syntax). The 16 general registers by every name a write can
# give them (`%r11d` writes %r11, `%eax` and `%al` write %rax).
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
# What a call does not preserve (SysV): %r11 is among them, so a thunk
# target never survives a call.
X86_CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
# Writes no operand names. Only these can hide a write to a register the
# model tracks; every other instruction is taken to write each register its
# operands name, which can lose a target but never invents one.
X86_IMPLICIT = {
    "cpuid": {"rax", "rbx", "rcx", "rdx"}, "syscall": {"rcx", "r11"}, "sysretq": {"rcx", "r11"},
    "rdtsc": {"rax", "rdx"}, "rdtscp": {"rax", "rcx", "rdx"}, "rdmsr": {"rax", "rdx"},
    "xgetbv": {"rax", "rdx"}, "rdpkru": {"rax", "rdx"}, "leave": {"rbp"}, "leaveq": {"rbp"},
    "rep": {"rax", "rcx", "rsi", "rdi"}, "repe": {"rax", "rcx", "rsi", "rdi"},
    "repne": {"rax", "rcx", "rsi", "rdi"}, "loop": {"rcx"},
    "cqto": {"rdx"}, "cltd": {"rdx"}, "cltq": {"rax"}, "cwtl": {"rax"},
    **{op + w: {"rax", "rsi", "rdi"} for op in ("movs", "stos", "lods", "cmps", "scas") for w in "bwlq"},
    **{op + w: {"rax", "rdx"} for op in ("mul", "div", "idiv", "cmpxchg") for w in ("", "b", "w", "l", "q")},
    "cmpxchg8b": {"rax", "rdx"}, "cmpxchg16b": {"rax", "rdx"},
}
# Ops that only read their operands (and %rsp, which nothing tracks).
X86_READS = re.compile(r"^(cmp[bwlq]?|test[bwlq]?|push(q|w|fq)?|bt[bwlq]?|nop[wlq]?|prefetch\w*|u?comis[sd])$")
X86_ENDS = ("jmp", "jmpq", "retq", "ret", "ud2", "iretq", "sysretq", "lretq")
X86_THUNK = re.compile(r"^__x86_indirect_thunk_(\w+)$")


def x86_regs(args):
    """The registers an AT&T operand list names, by their 64-bit name."""
    return {X86_REGS[r] for r in re.findall(r"%(\w+)", args) if r in X86_REGS}


def x86_64_edges(text, owner, stats=None):
    """[`edges`] for an x86_64 listing. Every call the compiler could not make
    direct goes through a retpoline thunk (`callq __x86_indirect_thunk_r11`,
    the target in %r11), so a call graph read off the call instructions alone
    has no edges at all: 19 of every 20 calls in the 2026-10-24 x86_64 qemu
    kernel are thunk calls, and most of them are static -- LLVM materialises
    the callee's address and calls through the thunk because the build asks
    for retpolines, not because the callee is unknown.

    So the thunk register is tracked forward through each function's control
    flow (fall-through and the branches inside it), as the address it holds
    at each instruction: a RIP-relative `leaq` (objdump prints the address it
    makes) or an immediate sets it, a register move copies it, a call kills
    every caller-saved register, and any other write -- a load from memory, an
    arithmetic op, an implicit write (`X86_IMPLICIT`) -- kills it. Two paths
    that meet keep an address only when both hold the same one. A thunk call
    or tail jump whose register holds a known address at that point is an
    edge to the function at that address, exactly like a direct call; one
    whose register was loaded from memory (a vtable, a spilled pointer, a
    function pointer argument) is a truly indirect call and, as on riscv64
    and aarch64, not followed. `stats` (a dict) counts both."""
    graph = collections.defaultdict(set)
    funcs = {}   # function -> [(addr, op, args, branch target, annotation, address made)]
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if not m:
            continue
        addr, op, rest = int(m.group(1), 16), m.group(2), m.group(3)
        f = owner(addr)
        if not f:
            continue
        comment = re.search(r"#\s*(0x[0-9a-f]+)", rest)
        args = re.sub(r"\s*#.*$", "", rest)
        ann = re.search(r"<(.+?)(\+0x[0-9a-f]+)?>\s*$", args)
        args = re.sub(r"\s*<.*$", "", args).replace(" ", "")
        to = None
        if op.startswith("j") or op.startswith("call"):
            t = re.fullmatch(r"(0x[0-9a-f]+)", args)
            to = int(t.group(1), 16) if t else None
        funcs.setdefault(f, []).append((addr, op, args, to, ann.group(1) if ann else None,
                                        int(comment.group(1), 16) if comment else None))
    counts = collections.Counter()
    for f, body in funcs.items():
        at = {ins[0]: i for i, ins in enumerate(body)}
        state = [None] * len(body)   # per instruction: {register: address} on entry
        state[0] = {}
        work = [0]
        while work:
            i = work.pop()
            addr, op, args, to, ann, made = body[i]
            regs = dict(state[i])
            for r in X86_IMPLICIT.get(op, ()):
                regs.pop(r, None)
            if op.startswith("call"):
                for r in X86_CALLER_SAVED:
                    regs.pop(r, None)
            elif op == "leaq" and "(%rip)," in args and made is not None:
                regs[X86_REGS[args.rsplit(",%", 1)[1]]] = made
            elif op in ("movq", "movabsq") and "," in args and args.split(",")[-1].startswith("%"):
                src, dst = args.rsplit(",", 1)
                d = X86_REGS.get(dst[1:])
                imm = re.fullmatch(r"\$(-?0x[0-9a-f]+|-?\d+)", src)
                if imm:
                    regs[d] = int(imm.group(1), 0) & (1 << 64) - 1
                elif src.startswith("%") and X86_REGS.get(src[1:]) in regs:
                    regs[d] = regs[X86_REGS[src[1:]]]
                else:
                    regs.pop(d, None)
            elif not (op.startswith("j") or X86_READS.match(op)
                      or (op.startswith("mov") and not args.split(",")[-1].startswith("%"))):
                for r in x86_regs(args):
                    regs.pop(r, None)
            nxt = []
            if to is not None and op.startswith("j") and to in at:
                nxt.append(at[to])
            if op not in X86_ENDS and i + 1 < len(body):
                nxt.append(i + 1)
            for j in nxt:
                if state[j] is None:
                    state[j] = regs
                    work.append(j)
                else:
                    merged = {r: v for r, v in state[j].items() if regs.get(r) == v}
                    if merged != state[j]:
                        state[j] = merged
                        work.append(j)
        for i, (addr, op, args, to, ann, made) in enumerate(body):
            if not (op.startswith("call") or op.startswith("j")):
                continue
            thunk = X86_THUNK.match(ann or "")
            if thunk:
                counts["thunk"] += 1
                target = (state[i] or {}).get(X86_REGS.get(thunk.group(1)))
                if target is None or owner(target) is None:
                    counts["indirect"] += 1
                    continue
                target = owner(target)
            elif args.startswith("*"):
                counts["indirect"] += 1
                continue
            elif to is not None:
                target = owner(to)
            else:
                continue
            if target and target != f:
                graph[f].add(target)
    if stats is not None:
        stats.update(counts)
    return graph


# The `#[panic_handler]`, by the name each toolchain gives it.
PANIC_HANDLERS = ("__rustc::rust_begin_unwind", "rust_begin_unwind")
# Steps a recursive block too big for the exact DP may take in `longest`'s
# walk before it is charged the sum of its frames instead.
WALK_MAX = 1_000_000

Chain = collections.namedtuple("Chain", "depth path frames knots panic fallbacks")


def load(elf, stats=None):
    """`(graph, frames, names, format)` of `elf`: see [`call_graph`]."""
    tools = stack_frames.llvm_bin()
    frames = stack_frames.frames(elf, tools)
    graph, names, fmt = call_graph(elf, tools, stats)
    return graph, frames, names, fmt


def analyze(elf, root):
    """The [`Chain`] of `root` in `elf` (a function of it): see [`chain`].
    `KeyError` when `root` is no symbol of the image."""
    graph, frames, names, _ = load(elf)
    if root not in names:
        raise KeyError(f"no symbol {root} in {elf}")
    return chain(graph, frames, root)


def fallback_notes(c):
    """`(warnings, on_path)` for a [`Chain`]: one line per recursive block
    charged its sum (`longest`), and whether one of them is on the deepest
    chain or the panic handler's, so that the verdict rests on that charge."""
    lines, on = [], set(c.path) | set(c.panic[1] if c.panic else ())
    for members in c.fallbacks:
        lines.append(f"WARNING: a recursive block of {len(members)} functions passed {WALK_MAX:,} walk "
                     f"steps and is charged the sum of its frames, "
                     f"{sum(c.frames.get(f, 0) for f in members)} B: " + ", ".join(sorted(members)[:4])
                     + (", ..." if len(members) > 4 else ""))
    return lines, any(f in on for m in c.fallbacks for f in m)


def chain(graph, frames, root):
    """The [`Chain`] of `root` over `graph` (function -> callees) with
    `frames`: `depth`, the deepest chain from `root`, the panic handler's
    charge included; `path`, the functions on it; `frames`; `knots`, the
    mutually recursive components; `panic`, the handler's own chain
    `(depth, path)` (None when `root` cannot reach it); `fallbacks`, the
    recursive blocks charged their sum (`longest`).

    THE PANIC HANDLER IS ITS OWN ROOT. Anything that can panic calls it, and
    it calls the heap, the console and the file system (the crash log), which
    can all panic: through it, 155 functions of the 2026-10-24 qemu kernel are
    one recursive component, too big to walk and charged whole (14.7 KiB).
    So the calls into the handler are cut, its chain is measured from it over
    the cut graph, and that depth is added to the deepest chain once, as if
    the deepest frame panicked. A panic inside the handler is not followed:
    a second one takes the reset path and runs the report again
    (kernel/src/panic.rs), which no static bound sees -- the component was
    charged one pass before, and this is the same single pass."""
    reach, todo = {root}, [root]
    while todo:
        for c in graph.get(todo.pop(), ()):
            if c not in reach:
                reach.add(c)
                todo.append(c)
    handler = next((h for h in PANIC_HANDLERS if h in reach), None)
    if handler is not None:
        graph = {f: {c for c in cs if c != handler} for f, cs in graph.items()}
    total, path, knots, fallbacks = longest(graph, frames, root)
    panic = None
    if handler is not None and handler != root:
        pdepth, ppath, _, pfall = longest(graph, frames, handler)
        fallbacks += [m for m in pfall if m not in fallbacks]
        panic = (pdepth, ppath)
        total += pdepth
    return Chain(total, path, frames, knots, panic, fallbacks)


def longest(graph, frames, root):
    """`(depth, path, knots, fallbacks)`: the deepest chain from `root` over
    `graph`, the functions on it, the mutually recursive components, and the
    ones past `WALK_MAX` charged their sum."""
    # Recursion makes "the deepest chain" ill-defined, and a depth-first walk
    # that just cuts a cycle and memoises what it found gives a DIFFERENT
    # answer depending on which callee it happened to visit first -- two runs
    # of an earlier version of this tool reported 12,512 and 15,984 bytes for
    # the same image, because Python randomises the iteration order of a set
    # of strings. A lint that is not deterministic is not a lint.
    #
    # So the graph is condensed first: Tarjan's strongly connected components,
    # then the longest path over the resulting DAG, which has no cycles by
    # construction. A component of more than one function is a recursive knot
    # whose true depth is a run-time property; it is charged the SUM of its
    # members' frames -- one pass around the knot -- and printed, so a human
    # can decide whether that recursion is bounded.
    index, low, onstack, stack, comp = {}, {}, set(), [], {}
    comps = []
    order = {f: sorted(cs) for f, cs in graph.items()}

    def strongconnect(root):
        work = [(root, 0)]
        while work:
            v, i = work.pop()
            if i == 0:
                index[v] = low[v] = len(index)
                stack.append(v)
                onstack.add(v)
            recurse = False
            for j, w in enumerate(order.get(v, ())[i:], start=i):
                if w not in index:
                    work.append((v, j + 1))
                    work.append((w, 0))
                    recurse = True
                    break
                if w in onstack:
                    low[v] = min(low[v], index[w])
            if recurse:
                continue
            if low[v] == index[v]:
                members = []
                while True:
                    w = stack.pop()
                    onstack.discard(w)
                    comp[w] = len(comps)
                    members.append(w)
                    if w == v:
                        break
                comps.append(members)
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])

    for f in sorted(set(order) | {root}):
        if f not in index:
            strongconnect(f)

    # Longest path over the condensation. Inside a component the exact
    # longest SIMPLE path is computed with a subset DP (Held-Karp shape):
    # dp[mask][v] is the deepest chain that STARTS at v and stays inside the
    # component using only members of `mask`, plus the best exit from
    # wherever it ends. Charging the whole component's sum instead -- one
    # pass around the knot -- overstated the embedded image by 4 KiB, because
    # the 14 mutually recursive functions of the TCP/IP send path cannot all
    # be on one path. A component too big for the DP (2^k masks) is walked
    # instead: every simple path inside it, depth first, with the best exit
    # at each step -- the same quantity. The TCP/IP knot is 25 functions, and
    # charged whole it was 13.4 KiB of a 25.4 KiB chain where its deepest
    # simple path is 10.9 KiB; its walk is ~3,000 steps. Only past
    # WALK_MAX steps is a component charged its sum, since an exponential
    # lint is no lint either. The sum of a component's frames is at least any
    # simple path through it, so that charge can fail a chain the walk would
    # pass and never the other way round: it is returned (`fallbacks`), the
    # tool names the block, and a chain over its limit through one is not a
    # measured overflow but an undecided verdict (`main`).
    DP_MAX = 18
    fallbacks = []
    succ_comp = [set() for _ in comps]
    for f, cs in order.items():
        for c in cs:
            if c in comp and comp[c] != comp[f]:
                succ_comp[comp[f]].add(comp[c])

    best_node = {}          # function -> deepest chain starting at it
    next_of = {}            # function -> the function it continues into

    def walk(members, inside, out):
        """Per member, the deepest chain from it: `(depth, the members it
        runs through)`; None past WALK_MAX steps."""
        best, steps = {}, 0
        for start in members:
            top, top_path = -1, None
            work = [(start, frames.get(start, 0), (start,))]
            while work:
                v, acc, path = work.pop()
                steps += 1
                if steps > WALK_MAX:
                    return None
                if acc + out[v][0] > top:
                    top, top_path = acc + out[v][0], path
                for w in reversed(order.get(v, ())):
                    if w in inside and w not in path:
                        work.append((w, acc + frames.get(w, 0), path + (w,)))
            best[start] = (top, list(top_path))
        return best
    for ci, members in enumerate(comps):
        inside = {f: i for i, f in enumerate(members)}
        # Best way OUT of each member: into another component, already settled.
        out = {}
        for f in members:
            b, n = 0, None
            for c in order.get(f, ()):
                if c in comp and comp[c] != ci and best_node.get(c, 0) > b:
                    b, n = best_node[c], c
            out[f] = (b, n)
        if len(members) == 1:
            f = members[0]
            best_node[f] = frames.get(f, 0) + out[f][0]
            next_of[f] = out[f][1]
            continue
        if len(members) > DP_MAX:
            walked = walk(members, inside, out)
            if walked is not None:
                for f, (d, p) in walked.items():
                    best_node[f] = d
                    next_of[f] = ("walked", p, out[p[-1]][1])
                continue
            fallbacks.append(members)
            total = sum(frames.get(f, 0) for f in members)
            b, n = max((out[f] for f in members), key=lambda t: t[0])
            for f in members:
                best_node[f] = total + b
                next_of[f] = n
            continue
        k = len(members)
        edges = [[j for j in (inside[c] for c in order.get(members[i], ()) if c in inside) if j != i]
                 for i in range(k)]
        fr = [frames.get(f, 0) for f in members]
        dp = [[-1] * k for _ in range(1 << k)]
        step = [[None] * k for _ in range(1 << k)]
        for mask in range(1, 1 << k):
            for v in range(k):
                if not mask & (1 << v):
                    continue
                best, nxt_in = out[members[v]][0], None
                rest = mask & ~(1 << v)
                for w in edges[v]:
                    if rest & (1 << w) and dp[rest][w] > best:
                        best, nxt_in = dp[rest][w], w
                dp[mask][v] = fr[v] + best
                step[mask][v] = nxt_in
        full = (1 << k) - 1
        for v in range(k):
            best_node[members[v]] = dp[full][v]
        # The continuation is recorded per (mask, node) so the printed chain
        # is the one that was actually measured, not a plausible-looking one.
        comp_step = (members, dp, step, full, out)
        for v in range(k):
            next_of[members[v]] = ("in-component", comp_step, v)

    def chain_from(root):
        total, path, cur = best_node.get(root, 0), [], root
        while cur is not None:
            n = next_of.get(cur)
            if isinstance(n, tuple) and n[0] == "walked":
                path.extend(n[1])
                cur = n[2]
            elif isinstance(n, tuple) and n[0] == "in-component":
                members, dp, step, full, out = n[1]
                mask, v = full, n[2]
                while v is not None:
                    path.append(members[v])
                    nv = step[mask][v]
                    mask &= ~(1 << v)
                    if nv is None:
                        cur = out[members[v]][1]
                        break
                    v = nv
                else:
                    cur = None
            else:
                path.append(cur)
                cur = n
        return total, path

    knots = [m for m in comps if len(m) > 1]

    total, path = chain_from(root)
    return total, path, knots, fallbacks


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("elf")
    ap.add_argument("--limit", type=int, required=True)
    # B2-04 (2026-09-24): riscv64's trap dispatch now enters at
    # `riscv64_trap_handler` (kernel/src/entry/riscv64/mod.rs), which routes through
    # `TrapContext`; the old `main.rs::trap_handler` is deleted. Gate 173 went
    # red on all three `stack chain` rows with "no symbol trap_handler" — the
    # tool was looking for a root that no longer exists. A root of `ROOTS`
    # that is gone fails the same way.
    ap.add_argument("--root", action="append", help="a root instead of the ISA's entry functions (repeatable)")
    ap.add_argument("--frames", type=int, default=12, help="frames of the chain to print")
    a = ap.parse_args()
    if not os.path.isfile(a.elf):
        sys.stderr.write(f"no image at {a.elf}\n")
        sys.exit(2)
    stats = {}
    graph, frames, names, fmt = load(a.elf, stats)
    roots = a.root or ROOTS.get(fmt, ())
    missing = [r for r in roots if r not in names]
    if not roots or missing:
        sys.stderr.write(f"no symbol {', '.join(missing) or '(no root for ' + repr(fmt) + ')'} in {a.elf}\n")
        sys.exit(2)
    chains = {r: chain(graph, frames, r) for r in roots}
    root = max(roots, key=lambda r: chains[r].depth)
    c = chains[root]
    over = c.depth > a.limit
    print(f"{c.depth:9d}  deepest chain from {root} (limit {a.limit})")
    for f in c.path[:a.frames]:
        print(f"{frames.get(f, 0):9d}  {f}")
    if len(c.path) > a.frames:
        print(f"           ... {len(c.path) - a.frames} more frames")
    if c.panic:
        print(f"{c.panic[0]:9d}  + the panic handler's own chain: " + " > ".join(c.panic[1][:6]))
    if len(roots) > 1:
        print("           the other roots: " + ", ".join(f"{r} {chains[r].depth}" for r in roots if r != root))
    if c.knots:
        print(f"           mutually recursive components on the path are charged "
              f"their longest simple path: {len(c.knots)} in the image "
              f"(largest {max(len(k) for k in c.knots)} functions)")
    if stats.get("thunk"):
        print(f"           x86_64 thunk calls: {stats['thunk']}, "
              f"{stats['thunk'] - stats.get('indirect', 0)} with a static target; "
              f"{stats.get('indirect', 0)} indirect calls not followed")
    seen = []
    for r in roots:
        seen += [w for w in fallback_notes(chains[r])[0] if w not in seen]
    for w in seen:
        print(w)
    for r in roots:
        if chains[r].depth <= a.limit:
            continue
        if fallback_notes(chains[r])[1]:
            print(f"UNDECIDED {chains[r].depth} > {a.limit}: the chain from {r} runs through a block "
                  f"charged its sum, which the walk might not reach; raise WALK_MAX to decide it")
        else:
            print(f"OVER {chains[r].depth} > {a.limit}: chain from {r}")
    sys.exit(1 if over else 0)


if __name__ == "__main__":
    main()

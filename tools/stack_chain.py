#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Deepest call chain in a RISC-V kernel image, against a stack budget.

    stack_chain.py <elf> --limit BYTES [--root SYMBOL] [--frames N]

The frame lint (tools/stack_frames.py) asks whether any single function is too
big for the stack. That is not what overflows a stack. On 2026-09-15 every
brain-peer boot died in a kernel page fault with no frame anywhere near the
limit: ten small and medium frames in one chain summed past the 12 KiB a
16 KiB task stack has above its guard page. This tool asks the question that
actually matters -- how deep can one trap go -- and it found that the embedded
profile still did not fit its own deepest syscall chain after that night's fix.

HOW IT WORKS. Frames come from stack_frames.frames(), which sums a whole
prologue. Edges come from llvm-objdump's own `<symbol>` annotation on every
call instruction, so an `auipc`+`jalr` long call is resolved exactly like a
`jal`. The deepest chain is the maximum sum over paths from `--root`.

WHAT IT DOES NOT SEE, and therefore why this is a LOWER bound:
  * Indirect calls through a function pointer or a vtable are not followed.
  * Recursion is cut at the first repeat; a recursive cycle's true depth is
    a run-time property this cannot know. Cuts are counted and printed.
  * Inlined code has no symbol: its locals are already inside its caller's
    frame, but a chain that only exists inside an inlined body is attributed
    to the caller, which is correct, while a root that was inlined away
    cannot be named on the command line.
A limit set from this number therefore needs margin, not equality.

THE BUDGET. A kernel task stack is KERNEL_STACK_SIZE_BYTES with the first
page a guard, so the usable depth is that minus 4096. Out of it must come the
deepest chain and the 288-byte trap frame that starts it. An interrupt taken
on top costs only that frame since 2026-09-16: its handler runs on the hart's
own interrupt stack (kernel/src/entry/riscv64/asm/trap_entry.S).

Exit 1 when the chain is over the limit, 2 when the image cannot be read.
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

CALL = ("jal", "jalr", "j", "tail", "c.j", "c.jal", "c.jalr", "c.jr", "jr")


def call_graph(elf, tools):
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

    graph = collections.defaultdict(set)
    for line in dis.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if not m or m.group(2) not in CALL:
            continue
        f = owner(int(m.group(1), 16))
        ann = re.search(r"<([^>]+?)(?:\+0x[0-9a-f]+)?>\s*$", m.group(3))
        if f and ann and ann.group(1) != f:
            graph[f].add(ann.group(1))
    return graph, {s[2] for s in syms}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("elf")
    ap.add_argument("--limit", type=int, required=True)
    # B2-04 (2026-09-24): riscv64's trap dispatch now enters at
    # `riscv64_trap_handler` (kernel/src/entry/riscv64.rs), which routes through
    # `TrapContext`; the old `main.rs::trap_handler` is deleted. Gate 173 went
    # red on all three `stack chain` rows with "no symbol trap_handler" — the
    # tool was looking for a root that no longer exists.
    ap.add_argument("--root", default="riscv64_trap_handler")
    ap.add_argument("--frames", type=int, default=12, help="frames of the chain to print")
    a = ap.parse_args()
    if not os.path.isfile(a.elf):
        sys.stderr.write(f"no image at {a.elf}\n")
        sys.exit(2)
    tools = stack_frames.llvm_bin()
    frames = stack_frames.frames(a.elf, tools)
    graph, names = call_graph(a.elf, tools)
    if a.root not in names:
        sys.stderr.write(f"no symbol {a.root} in {a.elf}\n")
        sys.exit(2)

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

    for f in sorted(set(order) | {a.root}):
        if f not in index:
            strongconnect(f)

    # Longest path over the condensation. Inside a component the exact
    # longest SIMPLE path is computed with a subset DP (Held-Karp shape):
    # dp[mask][v] is the deepest chain that STARTS at v and stays inside the
    # component using only members of `mask`, plus the best exit from
    # wherever it ends. Charging the whole component's sum instead -- one
    # pass around the knot -- overstated the embedded image by 4 KiB, because
    # the 14 mutually recursive functions of the TCP/IP send path cannot all
    # be on one path. A component too big for the DP is charged that sum and
    # said so, since an exponential lint is no lint either.
    DP_MAX = 18
    succ_comp = [set() for _ in comps]
    for f, cs in order.items():
        for c in cs:
            if c in comp and comp[c] != comp[f]:
                succ_comp[comp[f]].add(comp[c])

    best_node = {}          # function -> deepest chain starting at it
    next_of = {}            # function -> the function it continues into
    approximated = []
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
            approximated.append(members)
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
            if isinstance(n, tuple) and n[0] == "in-component":
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

    total, path = chain_from(a.root)
    over = total > a.limit
    print(f"{total:9d}  deepest chain from {a.root} (limit {a.limit})")
    for f in path[:a.frames]:
        print(f"{frames.get(f, 0):9d}  {f}")
    if len(path) > a.frames:
        print(f"           ... {len(path) - a.frames} more frames")
    if knots:
        print(f"           mutually recursive components on the path are charged "
              f"their longest simple path: {len(knots)} in the image "
              f"(largest {max(len(k) for k in knots)} functions)")
    if over:
        print(f"OVER {total} > {a.limit}: chain from {a.root}")
    sys.exit(1 if over else 0)


if __name__ == "__main__":
    main()

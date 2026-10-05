#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Largest stack frame per function in a RISC-V kernel image, against a limit.

    stack_frames.py <elf> --limit BYTES [--boot-limit BYTES] [--boot FUNCTION ...] [--top N]

A frame is read from the function's prologue: `addi sp, sp, -N`, or
`sub sp, sp, rX` with rX loaded by `lui`/`addi`/`li` just before. Each
instruction is attributed through the symbol table, never through objdump's
own headers, which split a body at every local label.

Why the gate needs this: a table sized by a Kconfig limit and declared as a
local lives on whichever stack runs the function. Kernel task stacks are
KERNEL_STACK_SIZE_KB (32 KiB on rv64, 16 on embedded, 4 KiB of it guard), and
the limits differ by up to 256x between profiles, so a function that is
harmless on edge overflows on fleet. The fleet image's first boots faulted four ways like that: the
topology on the boot stack, `lease_release_all` and `cpu_remove` scratch arrays
of MAX_TASKS entries, and a machine-sized FdTable per kernel file operation.
Guard pages turn an overflow into a fault only when the frame is smaller than
the guard; a larger frame steps over it into the neighbouring stack.

`--limit` applies to every function except those named with `--boot`, which
run only on the boot stack and get `--boot-limit`. Exit status 1 when any frame
is over its limit, 2 when the image or the tools cannot be read.

The LLVM tools come from the toolchain's llvm-tools component
(rust-toolchain.toml), or from $LLVM_BIN when set.
"""
import argparse
import bisect
import os
import re
import subprocess
import sys


def llvm_bin():
    if os.environ.get("LLVM_BIN"):
        return os.environ["LLVM_BIN"]
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True).stdout.strip()
    host = next((l.split(": ", 1)[1] for l in subprocess.run(
        ["rustc", "-vV"], capture_output=True, text=True).stdout.splitlines() if l.startswith("host: ")), "")
    return os.path.join(sysroot, "lib", "rustlib", host, "bin")


def frames(elf, tools):
    nm = subprocess.run([os.path.join(tools, "llvm-nm"), "-S", "-C", "--defined-only", elf],
                        capture_output=True, text=True)
    dis = subprocess.run([os.path.join(tools, "llvm-objdump"), "-d", "--no-show-raw-insn", elf],
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
        return syms[i][2] if i >= 0 and addr < syms[i][0] + syms[i][1] else "?"

    # A frame is often reserved in more than one step: LLVM saves the callee-
    # saved registers after a first `addi sp`, then lowers sp again for the
    # locals (`ip::send_flags`: 2032 + 1104 bytes). Reading only the largest
    # single step undercounted every such function, so the decrements are
    # summed for as long as the prologue lasts: sp adjustments, register saves
    # and the constant loads a `sub sp` needs. The first other instruction
    # ends it.
    prologue_ops = ("addi", "addiw", "sd", "lui", "li", "sub")
    reg, out = {}, {}
    cur, total, in_prologue = None, 0, False
    for line in dis.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+(\w+)\s*(.*)$", line)
        if not m:
            reg = {}
            continue
        addr, op, args = int(m.group(1), 16), m.group(2), m.group(3).replace(" ", "").split(",")
        f = owner(addr)
        if f != cur:
            cur, total, in_prologue, reg = f, 0, True, {}
        if not in_prologue:
            continue
        if op not in prologue_ops:
            in_prologue = False
            continue
        try:
            step = 0
            if op == "lui" and len(args) == 2:
                reg[args[0]] = int(args[1], 0) << 12
            elif op == "li" and len(args) == 2:
                reg[args[0]] = int(args[1], 0)
            elif op in ("addi", "addiw") and len(args) == 3:
                if args[0] == "sp" and args[1] == "sp":
                    step = -int(args[2], 0)
                elif args[1] in reg:
                    reg[args[0]] = reg[args[1]] + int(args[2], 0)
                else:
                    in_prologue = False
            elif op == "sub" and args[:2] == ["sp", "sp"] and len(args) == 3 and args[2] in reg:
                step = reg[args[2]]
            elif op == "sub":
                in_prologue = False
            if step > 0:
                total += step
                out[f] = max(out.get(f, 0), total)
        except ValueError:
            in_prologue = False
    return out


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
    fr = frames(a.elf, llvm_bin())
    over = []
    for f, size in sorted(fr.items(), key=lambda x: -x[1]):
        limit = a.boot_limit if f in a.boot else a.limit
        if size > limit:
            over.append((size, limit, f))
    for size, f in sorted(((s, f) for f, s in fr.items()), reverse=True)[:a.top]:
        print(f"{size:9d}  {f}")
    for size, limit, f in over:
        print(f"OVER {size} > {limit}: {f}")
    sys.exit(1 if over else 0)


if __name__ == "__main__":
    main()

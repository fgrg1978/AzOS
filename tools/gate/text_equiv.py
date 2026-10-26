#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""text_equiv.py A.elf B.elf : are the two kernels' code the same?

Written for energy invariant I4: a seam that must fold to
the code it replaced in the default build is proven by comparing that build
before and after, on both ISAs. Also the restructure block's equivalence
check: a commit that only moves files or crates must leave every function's
code as it was, on all three ISAs.

The link order of functions follows codegen-unit and symbol names, and the
mangled names carry each crate's hash, which changes whenever any crate's
dependency set or package id changes (a crate move); LLVM's `anon.<hash>.N`
data labels and RISC-V's `.Lpcrel_hiN` labels are renumbered too. So a byte
compare of .text says "different" for an identical program. This compares
per function instead, over every executable section:

* functions are keyed by their demangled name with every crate/anon hash
  removed (demangled, since a v0 name's back-references are byte offsets
  that move when a crate hash changes length); one name can hold several
  bodies (instantiations that differ only in hashes), compared as a multiset;
* every instruction is compared as printed, except the displacement of
  PC-relative instructions (auipc/adrp/adr and the lo12 instruction that
  consumes their register, x86 `disp(%rip)`: data references; and
  branches/calls), whose value moves with the layout. A branch target inside
  the function is compared as its offset from the function start; one
  outside as its symbol (hash removed). An immediate that falls inside one of
  the ELF's allocated sections is an absolute address and compares as ADDR.
  x86 names a rip operand's target after the nearest symbol: the name
  counts only when the target is a symbol or lies inside one's object
  (st_size); past the end it is unnamed data (a panic `Location`, a
  string) whose neighbour moves with the layout, and compares as D;
* a symbol annotation is the whole `<...>` (generics nest: `<A<B>>::f`);
* trailing padding (unimp, int3, udf, nops) is the fill up to the next
  function's alignment, not code;
* identical-code folding keeps one of the folded names, and which one
  follows the layout: a body only under name X in A and only under name Y
  in B, unique on both sides, is one function renamed, and every reference
  to X in A reads as Y (printed as `folded renames`).
Also undone: aarch64 linker relaxation (`adrp+add` vs `nop+adr`), and
RISC-V's `mv` / bare `jalr ra` spellings of a zero lo12 displacement.
Prints counts and the first mismatching functions (`--show N`, default 15);
exit 1 on any mismatch.
A canary: two builds that differ by one real instruction must mismatch (the
ENERGY report shows the energy-on build failing it).
"""
import bisect, re, subprocess, sys, collections
def _objdump():
    """$OBJDUMP, else the llvm-objdump of the active Rust toolchain."""
    import os
    if os.environ.get("OBJDUMP"):
        return os.environ["OBJDUMP"]
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True).stdout.strip()
    host = [l.split()[1] for l in subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout.splitlines() if l.startswith("host:")][0]
    return f"{sysroot}/lib/rustlib/{host}/bin/llvm-objdump"
OBJDUMP = _objdump()
HASH = re.compile(r"::h[0-9a-f]{16}|\[[0-9a-f]{1,16}\]|Cs[0-9A-Za-z]+_|anon\.[0-9a-f]{32}\.\d+|\.llvm\.\d+")
HEX = re.compile(r"-?0x[0-9a-f]+")
HDR = re.compile(r"^([0-9a-f]+) <(.*)>:$")
INS = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$")
DATA = {"auipc", "adrp", "adr"}
BR = {"jal","j","jalr","beq","bne","blt","bge","bltu","bgeu","beqz","bnez","blez","bgez","bltz",
      "bgtz","bgt","ble","bgtu","bleu","c.j","c.jal","c.beqz","c.bnez","tail","call",
      "bl","b","cbz","cbnz","tbz","tbnz","callq","jmp","jmpq"}
# x86 conditional jumps (je, jne, jae, jrcxz, ...).
X86_JCC = re.compile(r"j(n?[abceglopsz]e?|[pc]xz|ecxz|rcxz)")
def relax(raw):
    """Undo aarch64 linker relaxation: `adrp xN, P; add xN, xN, :lo12:` and
    `nop; adr xN, A` are the same address load, and which one the linker
    emits depends only on the distance to the target (the layout)."""
    out = []; i = 0
    while i < len(raw):
        a, mn, ops = raw[i]
        nx = raw[i + 1] if i + 1 < len(raw) else None
        if nx and mn == "adrp" and nx[1] == "add":
            r = ops.split(",")[0].strip(); p = [x.strip() for x in nx[2].split(",")]
            if len(p) >= 2 and p[0] == r and p[1] == r:
                out.append((a, "ADDR", r)); i += 2; continue
        if nx and mn == "nop" and nx[1] == "adr":
            out.append((a, "ADDR", nx[2].split(",")[0].strip())); i += 2; continue
        out.append(raw[i]); i += 1
    return out
PAD = {"unimp", "c.unimp", "int3", "udf", "nop", "nopw", "nopl"}
def named(v, objs):
    """Is v a symbol's address, or inside a sized object?"""
    starts, iv = objs
    if v in starts:
        return True
    i = bisect.bisect_right(iv, (v, 2**64)) - 1
    return i >= 0 and v < iv[i][1]
def norm_fn(start, raw, ranges, objs):
    while raw and raw[-1][1] in PAD:
        raw = raw[:-1]
    if not raw:
        return None
    raw = relax(raw)
    # Every register some auipc/adrp of this function writes: its lo12
    # consumer can sit anywhere after it, including before it in layout order
    # (a loop). Over-masking only loses the comparison of that immediate.
    live = {o.split(",")[0].strip() for _, mn, o in raw if mn in DATA}
    def absolute(m):
        """An immediate inside an allocated section is an address."""
        t = m.group(0); v = int(t.lstrip("-"), 16)
        v = (-v if t.startswith("-") else v) & (2**64 - 1)
        return "ADDR" if any(lo <= v < hi for lo, hi in ranges) else t
    body = []
    for addr, mn, ops in raw:
        # x86 prints a rip operand's resolved address as `# 0x... <sym>`.
        note = ""
        if re.search(r"#\s*0x", ops):
            ops, _, c = ops.partition("#"); ops = ops.strip()
            s = re.search(r"<(.*)>", c)
            if s:
                v = int(re.search(r"0x([0-9a-f]+)", c).group(1), 16)
                note = "#<" + HASH.sub("H", s.group(1)) + ">" if named(v, objs) else "#<D>"
        sym = re.search(r"<(.*)>", ops)
        base = re.sub(r"<.*>", "", ops).strip()
        base = re.sub(r"-?0x[0-9a-f]+\(%rip\)", "IMM(%rip)", base)
        regs = [r.strip() for r in base.split(",")]
        isbr = mn in BR or mn.startswith("b.") or bool(X86_JCC.fullmatch(mn))
        srcs = [r for i, r in enumerate(regs) if i > 0 or "(" in r]
        uses = any(re.search(rf"\b{r0}\b", r) for r0 in live for r in srcs)
        tag = ""
        if mn in DATA or uses:
            base = re.sub(r"#-?(0x[0-9a-f]+|\d+)|-?0x[0-9a-f]+", "IMM", base)
        elif isbr:
            m = HEX.search(base)
            if m and not m.group(0).startswith("-"):
                t = int(m.group(0), 16)
                if start <= t <= raw[-1][0]:
                    tag = f"+{t - start:#x}"
                elif sym:
                    tag = HASH.sub("H", sym.group(1))
                base = HEX.sub("T", base)
            else:
                base = HEX.sub(absolute, base)
        else:
            base = HEX.sub(absolute, base)
        if mn == "mv" and uses:
            # `addi rd, rs, 0` prints as `mv`: a lo12 of zero.
            mn, base = "addi", base + ", IMM"
        if mn in ("jalr", "jr") and (uses or base in live):
            # `jalr ra` is `jalr 0(ra)`: a zero displacement prints bare.
            base = re.sub(r"^(IMM)?\(?(\w+)\)?$", r"IMM(\2)", base)
        body.append(f"{mn} {base} {tag} {note}".strip())
    return tuple(body)
def alloc_ranges(path):
    """[start, end) of every allocated section (`objdump -h`: Idx Name Size VMA Type)."""
    out = subprocess.run([OBJDUMP, "-h", path], capture_output=True, text=True, check=True).stdout
    rs = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4 and p[0].isdigit():
            size, vma = int(p[2], 16), int(p[3], 16)
            if vma and size:
                rs.append((vma, vma + size))
    return rs
def objects(path):
    """Every symbol's address, and the merged [start, end) of the sized ones
    (`objdump -t`: addr flags section<TAB>size name)."""
    out = subprocess.run([OBJDUMP, "-t", path], capture_output=True, text=True, check=True).stdout
    starts = set(); iv = []
    for line in out.splitlines():
        head, tab, tail = line.partition("\t")
        p = head.split(); q = tail.split()
        if not tab or not p or not q:
            continue
        try:
            lo, size = int(p[0], 16), int(q[0], 16)
        except ValueError:
            continue
        starts.add(lo)
        if size:
            iv.append((lo, lo + size))
    iv.sort(); merged = []
    for lo, hi in iv:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return starts, merged
def funcs(path):
    ranges = alloc_ranges(path); objs = objects(path)
    out = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", "--demangle", path],
                         capture_output=True, text=True, check=True).stdout
    fs = collections.defaultdict(list); cur = None; start = 0; raw = []; sec = ""
    def flush():
        if cur is not None and raw:
            body = norm_fn(start, raw, ranges, objs)
            if body is not None: fs[cur].append(body)
    for line in out.splitlines():
        if line.startswith("Disassembly of section "):
            flush(); cur = None; raw = []; sec = line.split()[-1].rstrip(":"); continue
        m = HDR.match(line)
        if m and m.group(2).startswith(".L"):
            continue  # local label (RISC-V .Lpcrel_hiN), not a function
        if m:
            flush(); cur = sec + " " + HASH.sub("H", m.group(2)); start = int(m.group(1), 16); raw = []; continue
        m = INS.match(line)
        if m and cur is not None:
            raw.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))
    flush()
    return fs
args = sys.argv[1:]
show = 15
if len(args) >= 2 and args[0] == "--show":
    show = int(args[1]); args = args[2:]
if len(args) != 2:
    sys.exit("usage: text_equiv.py [--show N] A.elf B.elf")
a, b = funcs(args[0]), funcs(args[1])
def folded(a, b):
    """Pairs (X in A only, Y in B only) with the same bodies, unique on both
    sides and in the same section: one folded function, renamed."""
    def lone(x, y):
        by = collections.defaultdict(list)
        for k, v in x.items():
            if k not in y: by[tuple(sorted(v))].append(k)
        return {body: ks[0] for body, ks in by.items() if len(ks) == 1}
    la, lb = lone(a, b), lone(b, a)
    return [(la[body], lb[body]) for body in la
            if body in lb and la[body].split(" ", 1)[0] == lb[body].split(" ", 1)[0]]
renames = folded(a, b)
for ka, kb in renames:
    x, y = ka.split(" ", 1)[1], kb.split(" ", 1)[1]
    ref = re.compile(r"(?<=[ <])" + re.escape(x) + r"(?=$|[ +>])")
    a[kb] = a.pop(ka)
    for k, v in a.items():
        a[k] = [tuple(ref.sub(y, i) if x in i else i for i in body) for body in v]
na = sum(len(v) for v in a.values()); nb = sum(len(v) for v in b.values())
ia = sum(len(x) for v in a.values() for x in v); ib = sum(len(x) for v in b.values() for x in v)
print(f"A: {na} functions, {ia} instructions; B: {nb} functions, {ib} instructions")
bad = [k for k in sorted(set(a) | set(b)) if sorted(a.get(k, [])) != sorted(b.get(k, []))]
print(f"folded renames: {len(renames)}; mismatching functions: {len(bad)}")
for ka, kb in renames[:show]:
    print("   renamed:", ka[:100], "->", kb.split(" ", 1)[1][:100])
for k in bad[:show]:
    print("  ", k[:150], [len(x) for x in a.get(k, [])], [len(x) for x in b.get(k, [])])
sys.exit(1 if bad else 0)

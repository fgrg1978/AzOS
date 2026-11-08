#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""bti_pads_lint.py: every aarch64 assembly indirect-branch target carries a landing pad.

The compiler puts `bti` pads in what it emits (`-Z branch-protection=bti`);
hand-written assembly (.S files and `global_asm!` blocks) does not get them.
With BTI enforced on the kernel's text (Kconfig `A64_BTI_ENFORCE`) an indirect
branch to an instruction that is not a pad raises a Branch Target Exception,
so the assembly must carry its own. Three rules:

  paired   `adr`/`adrp xN, LABEL` followed within a few lines by `br xN` or
           `blr xN`: LABEL's first instruction is a pad (`br` needs `bti j`/`jc`,
           `blr` needs `bti c`/`jc` or `paciasp`; through x16/x17 any pad)
  listed   tools/lint/bti_pads.tsv names the labels something outside the
           assembly branches to (firmware, a function pointer, `ret`-less
           resumes): each must start with a pad, and the row must still find
           its label
  addressed  a `.globl` code label of the scanned assembly whose address Rust
           takes (`NAME as ...`) is listed or starts with a pad: a pointer
           to it can be branched to. An `eret` target (`elr... = NAME as`)
           is not checked: its SPSR.BTYPE is 0

  bti_pads_lint.py              check the tree
  bti_pads_lint.py --self-test  the lint's own canaries
"""
import glob
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = azos_tools.ROOT
LIST = "tools/lint/bti_pads.tsv"
SCAN = ("kernel/src/entry/aarch64/**/*.S", "kernel/src/entry/aarch64/**/*.rs", "arch/aarch64/src/**/*.rs",
        "crates/drivers/lx/emul/src/switch/aarch64.rs")
PAD_J = re.compile(r"^(hint\s+#(36|38)\b|bti\s+(j|jc)\b)")
PAD_C = re.compile(r"^(hint\s+#(34|38|25)\b|bti\s+(c|jc)\b|paciasp\b)")
PAD_ANY = re.compile(r"^(hint\s+#(34|36|38|25)\b|bti\b|paciasp\b)")
LABEL = re.compile(r"^([A-Za-z_.$][\w.$]*|\d+):(.*)$")
ADR = re.compile(r"^adrp?\s+(x\d+)\s*,\s*([A-Za-z_.$][\w.$]*|\d+[fb])\b")
BR = re.compile(r"^(br|blr)\s+(x\d+)\b")
SKIP = re.compile(r"^(\.|//|;|#|$)")
GLOBL = re.compile(r"^\.glob(?:a)?l\s+([A-Za-z_][\w$.]*)")
SECTION = re.compile(r"^\.(pushsection|section)\s+([^\s,]+)(.*)$")
RUST = ("kernel/src/**/*.rs", "arch/**/*.rs", "crates/**/*.rs")


def lines_of(path):
    """(lineno, text) with Rust string wrappers, comments and indentation removed."""
    out = []
    in_block = False
    for n, raw in enumerate(open(path, encoding="utf-8", errors="replace"), 1):
        t = raw.strip()
        if in_block:
            if "*/" in t:
                in_block = False
                t = t.split("*/", 1)[1].strip()
            else:
                continue
        if t.startswith("/*") and "*/" not in t:
            in_block = True
            continue
        t = t.strip('",').replace("\\n", "").strip()
        t = re.split(r"\s*(//|;)", t)[0].strip()
        out.append((n, t))
    return out


def first_insn(lines, idx):
    """The first instruction after line idx (labels on their own line are skipped)."""
    for n, t in lines[idx + 1:]:
        if SKIP.match(t) and not t.startswith("."):
            if t == "" or t.startswith(("//", ";", "#")):
                continue
        if t.startswith("."):
            continue
        m = LABEL.match(t)
        if m and not m.group(2).strip():
            continue
        if m:
            t = m.group(2).strip()
        return n, t
    return None, ""


def find_label(lines, name, near):
    if name[-1] in "fb" and name[:-1].isdigit():
        num, fwd = name[:-1], name[-1] == "f"
        order = range(near + 1, len(lines)) if fwd else range(near, -1, -1)
        for i in order:
            m = LABEL.match(lines[i][1])
            if m and m.group(1) == num:
                return i
        return None
    for i, (_, t) in enumerate(lines):
        m = LABEL.match(t)
        if m and m.group(1) == name:
            return i
    return None


def check_file(path, rel, problems):
    lines = lines_of(path)
    for i, (n, t) in enumerate(lines):
        m = ADR.match(t)
        if not m:
            continue
        reg, label = m.groups()
        for _, u in lines[i + 1:i + 7]:
            b = BR.match(u)
            if b and b.group(2) == reg:
                j = find_label(lines, label, i)
                if j is None:
                    break
                ln, insn = first_insn(lines, j)
                # x16/x17 (BTYPE 01) still land on a pad: any of them, `paciasp` included.
                ok = PAD_ANY if reg in ("x16", "x17") else PAD_J if b.group(1) == "br" else PAD_C
                if not ok.match(insn):
                    problems.append(f"{rel}:{n}: `{b.group(1)} {reg}` lands on `{label}`, whose first instruction `{insn}` is no landing pad")
                break
            if re.match(rf"^(adrp?|mov|ldr)\s+{reg}\b", u):
                break


def code_globals(path):
    """{name: line index} of the `.globl` labels defined in an executable section."""
    lines = lines_of(path)
    globs, defs = set(), {}
    code, stack = True, []
    for i, (_, t) in enumerate(lines):
        m = GLOBL.match(t)
        if m:
            globs.add(m.group(1))
            continue
        m = SECTION.match(t)
        if m:
            here = m.group(2).startswith(".text") or "x" in m.group(3)
            if m.group(1) == "pushsection":
                stack.append(code)
            code = here
            continue
        if t.startswith(".popsection"):
            code = stack.pop() if stack else True
            continue
        if re.match(r"^\.text\b", t):
            code = True
            continue
        if re.match(r"^\.(data|rodata|bss)\b", t):
            code = False
            continue
        m = LABEL.match(t)
        if m and code:
            defs.setdefault(m.group(1), i)
    return {n: defs[n] for n in globs if n in defs}, lines


def check_addressed(root, files, problems):
    listed = set()
    for raw in open(os.path.join(root, LIST), encoding="utf-8"):
        if not raw.startswith("#") and raw.strip():
            listed.add(raw.split("\t")[1].strip() if "\t" in raw else "")
    labels = {}
    for f in files:
        defs, lines = code_globals(f)
        for name, i in defs.items():
            labels.setdefault(name, (os.path.relpath(f, root), lines, i))
    if not labels:
        return
    want = re.compile(r"(?<![\w.])(" + "|".join(re.escape(n) for n in sorted(labels)) + r")\s+as\s")
    eret = re.compile(r"elr\w*\s*=\s*$")
    seen = set()
    for f in sorted({g for pat in RUST for g in glob.glob(os.path.join(root, pat), recursive=True)}):
        if "/target/" in f:
            continue
        for n, raw in enumerate(open(f, encoding="utf-8", errors="replace"), 1):
            code = raw.split("//", 1)[0]
            for m in want.finditer(code):
                name = m.group(1)
                if name in seen or name in listed or eret.search(code[:m.start()]):
                    continue
                seen.add(name)
                rel, lines, i = labels[name]
                ln, insn = first_insn(lines, i)
                if not PAD_ANY.match(insn):
                    problems.append(f"{rel}:{lines[i][0]}: `{name}` has its address taken "
                                    f"({os.path.relpath(f, root)}:{n}) but starts with `{insn}`: give it a pad, or list it in {LIST}")


def check_listed(root, problems):
    path = os.path.join(root, LIST)
    for ln, raw in enumerate(open(path, encoding="utf-8"), 1):
        if raw.startswith("#") or not raw.strip():
            continue
        rel, label, why = (raw.rstrip("\n").split("\t") + ["", ""])[:3]
        full = os.path.join(root, rel)
        if not os.path.exists(full):
            problems.append(f"{LIST}:{ln}: {rel} does not exist")
            continue
        lines = lines_of(full)
        i = find_label(lines, label, 0)
        if i is None:
            problems.append(f"{LIST}:{ln}: no label `{label}` in {rel}")
            continue
        n, insn = first_insn(lines, i)
        if not PAD_ANY.match(insn):
            problems.append(f"{rel}:{lines[i][0]}: `{label}` is entered by an indirect branch ({why}) but starts with `{insn}`")


def run(root):
    problems = []
    files = sorted({f for pat in SCAN for f in glob.glob(os.path.join(root, pat), recursive=True)})
    scanned = 0
    for f in files:
        rel = os.path.relpath(f, root)
        check_file(f, rel, problems)
        scanned += 1
    check_listed(root, problems)
    check_addressed(root, files, problems)
    return problems, scanned


def self_test():
    bad = 0
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "kernel/src/entry/aarch64/asm"))
        os.makedirs(os.path.join(d, "tools/lint"))
        a = os.path.join(d, "kernel/src/entry/aarch64/asm/x.S")
        r = os.path.join(d, "kernel/src/user.rs")

        def go(body, listing="", rust=""):
            open(a, "w").write(body)
            open(os.path.join(d, LIST), "w").write(listing)
            open(r, "w").write(rust)
            return run(d)[0]

        good = "    adr x9, 1f\n    br x9\n1:\n    hint #36\n    nop\nentry:\n    hint #38\n    ret\n"
        if go(good, "kernel/src/entry/aarch64/asm/x.S\tentry\tfirmware\n"):
            print("self-test: a clean file was refused")
            bad += 1
        if not go("    adr x9, 1f\n    br x9\n1:\n    nop\n"):
            print("self-test: a br target with no pad was accepted")
            bad += 1
        if not go("    adr x16, 1f\n    br x16\n1:\n    nop\n"):
            print("self-test: an x16 br target with no pad was accepted")
            bad += 1
        if go("    adr x16, 1f\n    br x16\n1:\n    hint #34\n"):
            print("self-test: an x16 br target with bti c was refused")
            bad += 1
        if not go("    adr x9, 1f\n    br x9\n1:\n    hint #34\n"):
            print("self-test: a br target with only bti c was accepted")
            bad += 1
        if not go(good, "kernel/src/entry/aarch64/asm/x.S\tmissing\tfirmware\n"):
            print("self-test: a listed label that is gone was accepted")
            bad += 1
        if not go(good.replace("entry:\n    hint #38", "entry:\n    nop"), "kernel/src/entry/aarch64/asm/x.S\tentry\tfirmware\n"):
            print("self-test: a listed label with no pad was accepted")
            bad += 1
        entry = ".globl ent\nent:\n    nop\n    ret\n"
        if not go(entry, rust="let p = ent as *const () as usize;\n"):
            print("self-test: an addressed global with no pad was accepted")
            bad += 1
        if go(entry.replace("ent:\n    nop", "ent:\n    hint #34"), rust="let p = ent as *const () as usize;\n"):
            print("self-test: an addressed global with a pad was refused")
            bad += 1
        if go(entry, rust="f.elr_el1 = ent as *const () as u64;\n"):
            print("self-test: an eret target was held to a pad")
            bad += 1
        if go(".section .hyp, \"a\"\n" + entry, rust="let p = ent as *const () as usize;\n"):
            print("self-test: a data label was held to a pad")
            bad += 1
        if go(entry, rust="ent();\n"):
            print("self-test: a direct call was held to a pad")
            bad += 1
    return bad


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(1 if self_test() else 0)
    probs, n = run(ROOT)
    for p in probs:
        print("FAIL " + p)
    if probs:
        sys.exit(1)
    print(f"bti_pads_lint: ok, {n} files scanned")

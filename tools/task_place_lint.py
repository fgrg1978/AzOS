#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Lint: a kernel task is pinned by a placement class, never by a CPU number.

Which CPU a board has is a fact of the board (the firmware's CPU map), and
which CPU a kernel task runs on is a Kconfig choice (config/kernel/Kconfig.tasks,
TASK_*_PLACE, resolved by azos_percpu::place). A literal in a task creation
fixes both in the code: riscv64 pinned net-poll to CPU 3 on every board, so
under `-smp 2` the scheduler re-pinned it with a warning, and on the K1's
eight harts CPUs 4..7 got no kernel work.

Rule. In kernel/src, the CPU argument (the last one) of `task_create_affinity`,
`try_task_create_affinity` and `create_sys_wdt_task` is a violation when it is
  * an integer literal other than -1 (no pin), with or without `as i8`;
  * a name bound in the same file to one (`const X: i8 = 3;`, `let x: i8 = 3;`);
  * an expression built on a literal CPU (`2.min(n - 1)`, `if c { 2 } else ..`).
A computed CPU (`cpu as i8`, `place::pin(..)`, a parameter) is not.

Ratchet. Test code pins on purpose (two tasks on the SAME CPU, or on two
different ones so they contend): per-file violation counts in
tools/task_place_lint.baseline may only fall; a count below the baseline
fails too, until the baseline is lowered (`--update-baseline`), so a fixed
site cannot silently come back.

  python3 tools/task_place_lint.py               check (the gate row)
  python3 tools/task_place_lint.py --list        every violation, per file
  python3 tools/task_place_lint.py --self-test   the lint's own canaries
"""
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = "kernel/src"
BASELINE = "tools/task_place_lint.baseline"
FNS = ("task_create_affinity", "try_task_create_affinity", "create_sys_wdt_task")

CALL_RE = re.compile(r"\b(" + "|".join(FNS) + r")\s*\(")
FN_DEF_RE = re.compile(r"\bfn\s+(" + "|".join(FNS) + r")\b")
LIT_RE = re.compile(r"^-?\d+(?:_?\d)*(?:i8|usize|u8)?(?:\s+as\s+i8)?$")
IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")
# A literal CPU inside an expression: `2.min(..)`, `3.max(..)`, `{ 2 }`.
EXPR_LIT_RE = re.compile(r"(?<![\w.])\d+\s*\.\s*(?:min|max)\s*\(|\{\s*-?\d+\s*\}")


CHAR_RE = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^'\\])'")


def strip(text):
    """Comments, string and char contents removed; every newline kept, so
    line numbers still match the file."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append("\n" * text.count("\n", i, j))
            i = j
        elif c == '"' or (c == "r" and re.match(r'r#*"', text[i:i + 8]) and not text[i - 1:i].isalnum()):
            if c == "r":
                hashes = re.match(r'r(#*)"', text[i:]).group(1)
                end = '"' + hashes
                j = text.find(end, i + 2 + len(hashes))
                j = n if j < 0 else j + len(end)
            else:
                j = i + 1
                while j < n and text[j] != '"':
                    j += 2 if text[j] == "\\" else 1
                j += 1
            out.append('""' + "\n" * text.count("\n", i, j))
            i = j
        elif c == "'" and CHAR_RE.match(text, i):
            out.append("' '")
            i = CHAR_RE.match(text, i).end()
        else:
            out.append(c)
            i += 1
    return "".join(out)


def last_arg(text, open_paren):
    """The last top-level argument of the call whose `(` is at `open_paren`."""
    depth, i, start = 0, open_paren, open_paren + 1
    args = []
    while i < len(text):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[start:i])
                break
        elif c == "," and depth == 1:
            args.append(text[start:i])
            start = i + 1
        i += 1
    args = [a.strip() for a in args if a.strip()]
    return args[-1] if args else ""


NAME_RE = re.compile(r"\b(const|let)\s+(?:mut\s+)?([A-Za-z_]\w*)\s*:\s*(?:i8|u8|u32|usize)\s*=\s*([^;]+);")


def literal_names(text):
    """Names bound to a literal CPU (`const X: i8 = 3;`, `let h: usize = 2;`,
    `const H: i8 = if cfg!(..) { 1 } else { 0 };`), and whether each is
    visible from other files (a `pub` const, as a shared smoke constant)."""
    out = {}
    for m in NAME_RE.finditer(text):
        expr = m.group(3).strip()
        if (LIT_RE.match(expr) and not re.match(r"^-1(?:i8)?$", expr)) or EXPR_LIT_RE.search(expr):
            line_start = text.rfind("\n", 0, m.start()) + 1
            shared = m.group(1) == "const" and text[line_start:m.start()].strip().startswith("pub")
            out[m.group(2)] = shared
    return out


def violates(arg, names):
    arg = re.sub(r"\s+as\s+i8$", "", arg)
    if LIT_RE.match(arg):
        return not re.match(r"^-1(?:i8)?$", arg)
    if IDENT_RE.match(arg):
        return arg in names
    return bool(EXPR_LIT_RE.search(arg))


def scan(text, shared=None):
    """[(line_no, function, argument)] of the violations in one file;
    `shared`: the literal `pub` consts of the other files."""
    code = strip(text)
    names = dict(shared or {})
    names.update(literal_names(code))
    out = []
    for m in CALL_RE.finditer(code):
        if FN_DEF_RE.search(code[max(0, m.start() - 4):m.end()]):
            continue
        arg = last_arg(code, m.end() - 1)
        if violates(arg, names):
            out.append((code.count("\n", 0, m.start()) + 1, m.group(1), " ".join(arg.split())))
    return out


def collect(root):
    texts = {}
    for d, _, files in os.walk(os.path.join(root, SRC)):
        for f in files:
            if f.endswith(".rs"):
                p = os.path.join(d, f)
                with open(p, encoding="utf-8") as fh:
                    texts[os.path.relpath(p, root)] = fh.read()
    shared = {}
    for t in texts.values():
        shared.update({k: v for k, v in literal_names(strip(t)).items() if v})
    found = {}
    for rel, t in texts.items():
        v = scan(t, shared)
        if v:
            found[rel] = v
    return found


def load_baseline(root):
    base = {}
    p = os.path.join(root, BASELINE)
    if not os.path.exists(p):
        return base
    with open(p, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            n, path = ln.split("\t")
            base[path] = int(n)
    return base


def check(root):
    found = collect(root)
    base = load_baseline(root)
    errors = []
    for rel in sorted(set(found) | set(base)):
        n, b = len(found.get(rel, [])), base.get(rel, 0)
        if n > b:
            for ln, fn, arg in found[rel]:
                errors.append(f"{rel}:{ln}: `{fn}` pins to `{arg}`: name a placement class "
                              f"(tasks::place, Kconfig TASK_*_PLACE), not a CPU")
            errors.append(f"{rel}: {n} literal CPU pins, baseline {b}")
        elif n < b:
            errors.append(f"{rel}: {n} literal CPU pins, below baseline {b}: "
                          f"lower it (--update-baseline)")
    return errors, {rel: len(v) for rel, v in found.items()}


def write_baseline(root, counts):
    with open(os.path.join(root, BASELINE), "w", encoding="utf-8") as f:
        f.write("# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"
                "# SPDX-FileCopyrightText: 2026 Fernando Rodriguez\n"
                "# tools/task_place_lint.py ratchet: task creations pinned to a literal\n"
                "# CPU, per file (test code that pins on purpose). Counts may only go\n"
                "# down. Regenerate with --update-baseline.\n")
        for rel, n in sorted(counts.items()):
            f.write(f"{n}\t{rel}\n")


def listing(root):
    for rel, v in sorted(collect(root).items()):
        for ln, fn, arg in v:
            print(f"{rel}:{ln}: {fn} -> {arg}")


def self_test():
    """Canaries: each must give the stated verdict on a synthetic tree."""
    def tree(body, baseline=""):
        d = tempfile.mkdtemp()
        p = os.path.join(d, SRC, "main.rs")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write("fn kernel_main() {\n" + body + "\n}\n")
        os.makedirs(os.path.join(d, os.path.dirname(BASELINE)), exist_ok=True)
        with open(os.path.join(d, BASELINE), "w") as f:
            f.write(baseline)
        return d
    c = 'azos_sched::task_create_affinity("t", f, 0, PRIO, {});'
    cases = [
        ("a literal CPU", tree(c.format("3")), False),
        ("a literal CPU over lines",
         tree('azos_sched::task_create_affinity(\n    "t", f, 0,\n    PRIO, 2,\n);'), False),
        ("a literal through a const", tree("const HART: i8 = 1;\n" + c.format("HART")), False),
        ("a literal through a let", tree("let net_poll_hart: i8 = 3;\n" + c.format("net_poll_hart")), False),
        ("a literal inside min", tree(c.format("2.min(num_cpus - 1) as i8")), False),
        ("a usize const cast", tree("const CPU: usize = 2;\n" + c.format("CPU as i8")), False),
        ("a const behind a cfg if", tree("const H: i8 = if cfg!(x) { 1 } else { 0 };\n" + c.format("H")), False),
        ("a literal behind a cfg if", tree("create_sys_wdt_task(if cfg!(x) { 2 } else { n });"), False),
        ("the fallible form", tree('try_task_create_affinity("w", f, i, P, 0);'), False),
        ("no pin (-1)", tree(c.format("-1")), True),
        ("a const of -1", tree("const ANY: i8 = -1;\n" + c.format("ANY")), True),
        ("a placement class", tree(c.format("place::pin(place::NET_POLL)")), True),
        ("a computed CPU", tree(c.format("cpu as i8")), True),
        ("a parameter", tree("create_sys_wdt_task(hart);"), True),
        ("a literal in a comment", tree("// task_create_affinity(\"t\", f, 0, P, 3);"), True),
        ("a literal in a string", tree('kprintln!("task_create_affinity(t, 3)");'), True),
        ("the definition is not a call",
         tree("pub fn task_create_affinity(n: &str, a: i8) -> usize { 0 }"), True),
        ("baseline covers the count", tree(c.format("1"), f"1\t{SRC}/main.rs\n"), True),
        ("baseline above the count (ratchet)", tree(c.format("-1"), f"1\t{SRC}/main.rs\n"), False),
    ]
    ok = True
    for name, d, want in cases:
        errs, _ = check(d)
        got = not errs
        if got != want:
            ok = False
            print(f"self-test FAILED: {name}: expected {'pass' if want else 'fail'}, got "
                  f"{'pass' if got else 'fail'} {errs[:3]}")
    print("task_place_lint self-test: " + ("ok" if ok else "FAILED"))
    return ok


def main(argv):
    if "--self-test" in argv:
        return 0 if self_test() else 1
    if "--list" in argv:
        listing(ROOT)
        return 0
    errors, counts = check(ROOT)
    if "--update-baseline" in argv:
        write_baseline(ROOT, counts)
        errors, counts = check(ROOT)
    for e in errors:
        print(e)
    if errors:
        return 1
    print(f"task_place_lint: ok ({sum(counts.values())} literal CPU pins in test code, at baseline)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

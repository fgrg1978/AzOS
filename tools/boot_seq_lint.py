#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Lint: every ISA runs the same early-boot steps, in one place.

The common early-boot sequence (console, firmware table, memory map, page
tables, W^X/NX, guards, heap, vDSO, ...) lives in `boot::early_main`
(kernel/src/boot/early.rs); each ISA's `kernel/src/entry/<isa>/boot_hooks.rs`
supplies the hooks it calls. A step that an ISA re-implements in its own
hooks can be forgotten by the next ISA, and nothing goes red: the boot just
lacks it (this happened with `install_sched_hooks` on aarch64).

Rule. A *step* is a call to one of the functions in `STEPS` below. In an
ISA's early-boot code (its `boot_hooks.rs`, minus the late functions in
`LATE_FNS`), every step call is a violation unless a `// boot-seq: <why>`
comment sits on its line or in the comment block right above it (or above the `fn` holding it): a reviewed
decision that the step cannot be in the generic sequence (it runs at a
different point of that ISA's boot, so moving it would change the boot
order). And every step must be reachable on each full ISA (`FULL_ISAS`):
present in `early.rs`, or present (justified) in that ISA's hooks. A step
that is in neither has been lost.

Ratchet. Per-file violation counts in tools/boot_seq_lint.baseline may only
fall; a count below the baseline fails too, until the baseline is lowered
(`--update-baseline`), so a fixed site cannot silently come back.

  python3 tools/boot_seq_lint.py               check (the gate row)
  python3 tools/boot_seq_lint.py --list        ordered steps, per ISA
  python3 tools/boot_seq_lint.py --diff        riscv64 vs aarch64 order delta
  python3 tools/boot_seq_lint.py --self-test   the lint's own canaries
"""
import difflib
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERIC = "kernel/src/boot/early.rs"
HOOKS = "kernel/src/entry/{}/boot_hooks.rs"
ISAS = ("riscv64", "aarch64", "x86_64")
# ISAs whose boot runs to the scheduler; x86_64 is a skeleton that stops at
# its first `todo!()`, so a step missing there is expected.
FULL_ISAS = ("riscv64", "aarch64")
BASELINE = "tools/boot_seq_lint.baseline"
MARK = "boot-seq:"

# The common early-boot steps, by their last path segments.
STEPS = (
    "uart::init", "console_register",
    "dtb_parse", "discover_cpus", "dtb_pci_host",
    "pmm::init", "pstore::reserve", "vmm::init",
    "map_mmio_region", "enable_paging",
    "split_mega_range", "enforce_wx", "verify_wx",
    "strip_exec_outside_image", "verify_no_exec_outside_image",
    "null_guard", "setup_stack_guard_pages", "kheap::init",
    "install_vdso", "dtb_irq_triggers", "set_line_release_hook",
)
# Steps that map one device each: early_main maps what every ISA maps (the
# console), and a hook may still map its own devices with a justification.
MULTI = ("map_mmio_region",)
# Functions of boot_hooks.rs that run after early boot.
LATE_FNS = ("arch_map_late_mmio", "arch_wake_secondaries", "arch_enter_scheduler",
            "its", "its_ready")

CALL_RE = re.compile(r"((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*(?:::<[^>]*>)?\s*\(")
FN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?fn\s+(\w+)")


def step_of(path):
    for s in STEPS:
        if path == s or path.endswith("::" + s) or ("::" not in s and path.split("::")[-1] == s):
            return s
    return None


def strip_strings(code):
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', code)


def scan(text, skip_fns=()):
    """[(line_no, step, justified)] in source order."""
    out = []
    lines = text.split("\n")
    cur_fn = None
    fn_justified = False
    stmt_justified = False
    comment_block = []
    for i, raw in enumerate(lines, 1):
        m = FN_RE.match(raw)
        if m:
            cur_fn = m.group(1)
            # A marker above the `fn` justifies every step in its body.
            fn_justified = any(MARK in c for c in comment_block)
        stripped = raw.strip()
        if stripped.startswith("//"):
            comment_block.append(stripped)
            continue
        code, _, trailing = raw.partition("//")
        if cur_fn in skip_fns:
            comment_block = []
            continue
        # A marker above a statement covers it to its `;` (calls split over
        # lines: `let x = unsafe {` / `step(...)` / `};`).
        if any(MARK in c for c in comment_block):
            stmt_justified = True
        justified = fn_justified or stmt_justified or MARK in trailing
        for cm in CALL_RE.finditer(strip_strings(code)):
            s = step_of(cm.group(1))
            if s:
                out.append((i, s, justified))
        if stripped and not stripped.startswith("#["):
            comment_block = []
        if ";" in code:
            stmt_justified = False
    return out


def read(root, rel):
    p = os.path.join(root, rel)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return f.read()


def collect(root):
    gen = read(root, GENERIC)
    generic = scan(gen) if gen is not None else []
    per_isa = {}
    for isa in ISAS:
        t = read(root, HOOKS.format(isa))
        per_isa[isa] = scan(t, LATE_FNS) if t is not None else []
    return generic, per_isa


def load_baseline(root):
    base = {}
    t = read(root, BASELINE)
    if t is None:
        return base
    for ln in t.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        n, path = ln.split("\t")
        base[path] = int(n)
    return base


def check(root):
    generic, per_isa = collect(root)
    gen_steps = {s for _, s, _ in generic}
    errors = []
    counts = {}
    for isa, calls in per_isa.items():
        rel = HOOKS.format(isa)
        bad = [(ln, s) for ln, s, j in calls if not j]
        dup = [(ln, s) for ln, s, j in calls if j and s in gen_steps and s not in MULTI]
        counts[rel] = len(bad)
        for ln, s in dup:
            errors.append(f"{rel}:{ln}: `{s}` is justified here but boot::early_main already runs it")
        if isa in FULL_ISAS:
            have = gen_steps | {s for _, s, _ in calls}
            for s in STEPS:
                if s not in have:
                    errors.append(f"{rel}: step `{s}` is lost: not in {GENERIC} nor in this ISA's hooks")
        per_isa[isa] = (calls, bad)
    base = load_baseline(root)
    for rel, n in sorted(counts.items()):
        b = base.get(rel, 0)
        if n > b:
            isa = rel.split("/")[3]
            for ln, s in per_isa[isa][1]:
                errors.append(f"{rel}:{ln}: common step `{s}` in per-ISA code: move it to "
                              f"boot::early_main, or justify it with `// {MARK} <why>`")
            errors.append(f"{rel}: {n} unjustified step calls, baseline {b}")
        elif n < b:
            errors.append(f"{rel}: {n} unjustified step calls, below baseline {b}: "
                          f"lower it (--update-baseline)")
    for rel in base:
        if rel not in counts:
            errors.append(f"{BASELINE}: names {rel}, which is not a hooks file")
    return errors, counts


def write_baseline(root, counts):
    with open(os.path.join(root, BASELINE), "w", encoding="utf-8") as f:
        f.write("# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"
                "# SPDX-FileCopyrightText: 2026 Fernando Rodriguez\n"
                "# tools/boot_seq_lint.py ratchet: unjustified common-step calls per\n"
                "# boot_hooks.rs. Counts may only go down. Regenerate with --update-baseline.\n")
        for rel, n in sorted(counts.items()):
            if n:
                f.write(f"{n}\t{rel}\n")


def listing(root):
    generic, per_isa = collect(root)
    print(f"{GENERIC}: " + (" > ".join(s for _, s, _ in generic) or "(none)"))
    for isa in ISAS:
        calls = per_isa[isa]
        print(f"{isa}: " + (" > ".join(s + ("" if j else "*") for _, s, j in calls) or "(none)"))
    print("(* = unjustified)")


def diff(root):
    _, per_isa = collect(root)
    a = [s for _, s, _ in per_isa["riscv64"]]
    b = [s for _, s, _ in per_isa["aarch64"]]
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            print("  same    " + " > ".join(a[i1:i2]))
        else:
            print(f"  {tag:7} riscv64: {' > '.join(a[i1:i2]) or '-'} | aarch64: {' > '.join(b[j1:j2]) or '-'}")


def self_test():
    """Canaries: each must give the stated verdict on a synthetic tree."""
    full = "\n".join(f"    {s}(x);" for s in STEPS)
    def tree(generic, rv, arm, baseline=""):
        d = tempfile.mkdtemp()
        def put(rel, body):
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(body)
        if generic is not None:
            put(GENERIC, "pub fn early_main() {\n" + generic + "\n}\n")
        put(HOOKS.format("riscv64"), "pub fn hook() {\n" + rv + "\n}\n")
        put(HOOKS.format("aarch64"), "pub fn hook() {\n" + arm + "\n}\n")
        put(HOOKS.format("x86_64"), "pub fn hook() {}\n")
        put(BASELINE, baseline)
        return d
    rest = "\n".join(f"    {s}(x);" for s in STEPS if s != "install_vdso")
    just = "    // boot-seq: runs at a different point per ISA\n    crate::install_vdso(1);"
    cases = [
        ("all steps generic, hooks clean", tree(full, "", ""), True),
        ("an unjustified step in a hook", tree(full, "    azos_mm::pmm::init(a, b, c);", ""), False),
        ("a justified step in both hooks", tree(rest, just, just), True),
        ("a justified step on the line itself",
         tree(rest, "    crate::install_vdso(1); // boot-seq: why", just), True),
        ("a justified step one ISA forgot", tree(rest, just, ""), False),
        ("a justified step also in early_main", tree(full, just, just), False),
        ("a marker above the fn covers its body",
         tree(rest, "}\n/// boot-seq: why\n#[inline(always)]\npub fn h2() {\n    crate::install_vdso(1);", just), True),
        ("a marker above a split statement covers it",
         tree(rest, "    // boot-seq: why\n    let v = unsafe {\n        crate::install_vdso(1)\n    };", just), True),
        ("a marker does not outlive its statement",
         tree(full, "    // boot-seq: why\n    let v = 1;\n    azos_mm::vmm::init(a, b);", ""), False),
        ("a late fn is not early boot",
         tree(full, "pub fn arch_wake_secondaries() { azos_mm::pmm::init(); }", ""), True),
        ("a step inside a string is not a call",
         tree(full, '    kprintln!("vmm::init(x)");', ""), True),
        ("baseline covers the count",
         tree(full, "    azos_mm::vmm::init(a, b);", "",
              f"1\t{HOOKS.format('riscv64')}\n"), True),
        ("baseline above the count (ratchet)",
         tree(full, "", "", f"1\t{HOOKS.format('riscv64')}\n"), False),
    ]
    ok = True
    for name, d, want in cases:
        errs, _ = check(d)
        got = not errs
        if got != want:
            ok = False
            print(f"self-test FAILED: {name}: expected {'pass' if want else 'fail'}, got "
                  f"{'pass' if got else 'fail'} {errs[:3]}")
    print("boot_seq_lint self-test: " + ("ok" if ok else "FAILED"))
    return ok


def main(argv):
    root = ROOT
    if "--self-test" in argv:
        return 0 if self_test() else 1
    if "--list" in argv:
        listing(root)
        return 0
    if "--diff" in argv:
        diff(root)
        return 0
    errors, counts = check(root)
    if "--update-baseline" in argv:
        write_baseline(root, counts)
        errors, counts = check(root)
    for e in errors:
        print(e)
    if errors:
        return 1
    total = sum(counts.values())
    print(f"boot_seq_lint: ok ({total} unjustified step calls, at baseline)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

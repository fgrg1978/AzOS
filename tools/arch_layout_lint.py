#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The three ISAs share one file layout (S1): the same module set in each.

A module is a top-level name of a source directory: `foo.rs`, `foo.S` or the
directory `foo/` all name the module `foo` (`lib` and `mod` are crate roots,
not modules). Three directories per ISA are compared:

  arch   crates/core/arch-<isa>/src      the ISA crate
  entry  kernel/src/entry/<isa>          the kernel's per-ISA trap/boot entry
  asm    kernel/src/entry/<isa>/asm      the asm files (names include the suffix)

This lint fails when:

  1. a module of REQUIRED is missing on an ISA and the gap is not in
     ALLOW_MISSING;
  2. an ALLOW_MISSING entry is stale: the module exists after all, or is not in
     REQUIRED, or names an unknown ISA;
  3. a module outside REQUIRED sits at the top level of a directory instead of
     under `ext/` (ISA-only extras are `ext/` material) and is not in
     ALLOW_EXTRA;
  4. an ALLOW_EXTRA entry is stale: the module is gone, or is required now;
  5. a directory has no `ext` (arch, entry), the one place for ISA-only code.

Every allowlist row carries its reason. The list is the open work of S1: a row
is deleted when the gap closes, and the lint makes sure it is.

    python3 tools/arch_layout_lint.py              lint the tree (exit 1 on a finding)
    python3 tools/arch_layout_lint.py --self-test  the canary: a synthetic violation
                                                   of every rule must turn it red
"""

import os
import sys
import tempfile

ISAS = ("riscv64", "aarch64", "x86_64")

# group -> directory, relative to the repo root, with {isa}.
DIRS = {
    "arch": "crates/core/arch-{isa}/src",
    "entry": "kernel/src/entry/{isa}",
    "asm": "kernel/src/entry/{isa}/asm",
}

REQUIRED = {
    "arch": (
        "api_impl", "cache", "cpu", "ext", "firmware", "fork_regs", "fp", "irq",
        "lat_hook", "mmu", "platform_impl", "pmu", "seed", "smp", "spin", "timer", "tlb",
        "trap",
    ),
    "entry": (
        "arch_entry", "asm", "board_map", "boot_hooks", "ext", "fp", "irq", "resume",
        "smp", "trap",
    ),
    "asm": ("boot.S", "context_switch.S", "trap_entry.S"),
}

# Groups that must own an `ext` (ISA-only code goes there).
NEEDS_EXT = ("arch", "entry")

# (group, isa, module) -> why the ISA lacks a required module today.
ALLOW_MISSING = {
    ("arch", "riscv64", "fork_regs"):
        "the fork snapshot is the trap frame's GPR block itself (azos_sched::UserRegs = [u64; 32], x0..x31)",
    ("arch", "riscv64", "smp"):
        "secondary harts start from kernel/src/entry/riscv64/smp.rs (SBI HSM hart_start)",
    ("arch", "riscv64", "timer"):
        "the timer is the CLINT/ACLINT in irq/clint.rs",
    ("arch", "aarch64", "tlb"):
        "TLBI sequences live in mmu and api_impl (broadcast TLBI VAAE1IS)",
    ("arch", "aarch64", "trap"):
        "the TrapFrame lives in kernel/src/entry/aarch64/mod.rs",
    ("arch", "x86_64", "api_impl"):
        "the Cpu, Interrupts and Mmu impls are inline in lib.rs",
    ("arch", "x86_64", "cache"):
        "x86 DMA is cache-coherent: no maintenance operations to host",
    ("arch", "x86_64", "lat_hook"):
        "lat-trace is not implemented on x86_64",
    ("entry", "x86_64", "board_map"):
        "the memory map comes from Limine (entry/x86_64/ext/limine.rs) and ACPI, not a board table",
    ("entry", "riscv64", "fp"):
        "the FP state is saved by arch-riscv64 fp and context_switch.S, no entry hook",
}

# (group, isa, module) -> why a module outside REQUIRED sits outside ext/.
ALLOW_EXTRA = {
    ("arch", "aarch64", "sysregs"):
        "AArch64 system register accessors; belongs under ext/ (S1 move pending: ~150 `sysregs::` "
        "uses across the kernel, mm, sched and the host suites repoint at once)",
    ("asm", "riscv64", "context_switch_rvv.S"): "the RVV context switch variant (rvv feature)",
    ("asm", "x86_64", "ap_entry.S"): "the AP long-mode entry (x86 SIPI start)",
}

ROOTS = ("lib", "mod")


def modules(path, group):
    """The set of module names in `path`, or None if the directory is missing."""
    if not os.path.isdir(path):
        return None
    names = set()
    for e in os.listdir(path):
        full = os.path.join(path, e)
        if group == "asm":
            if os.path.isfile(full):
                names.add(e)
            continue
        if os.path.isdir(full):
            names.add(e)
        else:
            stem, ext = os.path.splitext(e)
            if ext in (".rs", ".S") and stem not in ROOTS:
                names.add(stem)
    return names


def lint(root, required=REQUIRED, allow_missing=ALLOW_MISSING, allow_extra=ALLOW_EXTRA):
    out = []
    for group, tmpl in DIRS.items():
        have = {}
        for isa in ISAS:
            rel = tmpl.format(isa=isa)
            m = modules(os.path.join(root, rel), group)
            if m is None:
                out.append(f"{rel}: directory missing")
                m = set()
            have[isa] = m
        req = set(required[group])
        for isa in ISAS:
            rel = tmpl.format(isa=isa)
            for name in sorted(req - have[isa]):
                if (group, isa, name) not in allow_missing:
                    out.append(f"{rel}: required module `{name}` missing "
                               f"(add it, or list the gap in ALLOW_MISSING with its reason)")
            for name in sorted(have[isa] - req):
                if name == "ext" or (group, isa, name) in allow_extra:
                    continue
                where = "the only ISA" if all(name not in have[o] for o in ISAS if o != isa) \
                    else "some ISAs"
                out.append(f"{rel}: `{name}` is on {where} but not in REQUIRED: "
                           f"move it under ext/ (or require it everywhere)")
            if group in NEEDS_EXT and have[isa] and "ext" not in have[isa]:
                out.append(f"{rel}: no ext/ for ISA-only code")
        for (g, isa, name), why in sorted(allow_missing.items()):
            if g != group:
                continue
            if isa not in ISAS:
                out.append(f"ALLOW_MISSING {g}/{isa}/{name}: unknown ISA")
            elif name not in req:
                out.append(f"ALLOW_MISSING {g}/{isa}/{name}: not a required module, drop the row")
            elif name in have[isa]:
                out.append(f"ALLOW_MISSING {g}/{isa}/{name}: stale, the module exists ({why})")
        for (g, isa, name), why in sorted(allow_extra.items()):
            if g != group:
                continue
            if isa not in ISAS:
                out.append(f"ALLOW_EXTRA {g}/{isa}/{name}: unknown ISA")
            elif name in req:
                out.append(f"ALLOW_EXTRA {g}/{isa}/{name}: required now, drop the row")
            elif name not in have[isa]:
                out.append(f"ALLOW_EXTRA {g}/{isa}/{name}: stale, the module is gone ({why})")
    for g in set(k[0] for k in list(allow_missing) + list(allow_extra)):
        if g not in DIRS:
            out.append(f"allowlist names unknown group `{g}`")
    return out


def self_test():
    """Fixtures on a toy spec: the clean tree passes, each rule has a mutant that fails."""
    req = {"arch": ("cpu", "ext", "irq"), "entry": ("asm", "ext", "trap"), "asm": ("boot.S",)}
    miss = {("arch", "aarch64", "irq"): "irq is in cpu here"}
    extra = {("asm", "x86_64", "ap.S"): "AP entry"}
    tree = {}
    for isa in ISAS:
        tree[f"crates/core/arch-{isa}/src"] = ["cpu.rs", "ext/mod.rs", "irq.rs", "lib.rs"]
        tree[f"kernel/src/entry/{isa}"] = ["ext/mod.rs", "mod.rs", "trap.rs", "asm/boot.S"]
    tree["crates/core/arch-aarch64/src"].remove("irq.rs")
    tree["kernel/src/entry/x86_64"].append("asm/ap.S")

    def build(base, files):
        for d, names in files.items():
            for n in names:
                p = os.path.join(base, d, n)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, "w").close()

    def run(mutate=None, am=miss, ae=extra):
        t = {k: list(v) for k, v in tree.items()}
        if mutate:
            mutate(t)
        with tempfile.TemporaryDirectory() as base:
            build(base, t)
            return lint(base, req, am, ae)

    a = "crates/core/arch-riscv64/src"
    mutants = [
        ("clean toy tree", None, miss, extra, None),
        ("required module missing", lambda t: t[a].remove("cpu.rs"), miss, extra,
         "required module `cpu` missing"),
        ("ISA-only module outside ext/", lambda t: t[a].append("pmu.rs"), miss, extra,
         "`pmu` is on the only ISA"),
        ("ISA-only module under ext/", lambda t: t[a].append("ext/pmu.rs"), miss, extra, None),
        ("module on two ISAs, not required",
         lambda t: (t[a].append("tlb.rs"), t["crates/core/arch-x86_64/src"].append("tlb.rs")),
         miss, extra, "`tlb` is on some ISAs"),
        ("stale ALLOW_MISSING (module exists)",
         lambda t: t["crates/core/arch-aarch64/src"].append("irq.rs"), miss, extra,
         "ALLOW_MISSING arch/aarch64/irq: stale"),
        ("stale ALLOW_EXTRA (module gone)",
         lambda t: t["kernel/src/entry/x86_64"].remove("asm/ap.S"), miss, extra,
         "ALLOW_EXTRA asm/x86_64/ap.S: stale"),
        ("unlisted gap", None, {}, extra, "required module `irq` missing"),
        ("no ext/ directory",
         lambda t: t["kernel/src/entry/riscv64"].remove("ext/mod.rs"), miss, extra,
         "no ext/ for ISA-only code"),
        ("ISA directory missing",
         lambda t: t.pop("kernel/src/entry/aarch64"), miss, extra, "directory missing"),
        ("ALLOW_MISSING row for a non-required module",
         None, {**miss, ("arch", "riscv64", "zzz"): "x"}, extra, "not a required module"),
    ]
    bad = 0
    for name, mut, am, ae, want in mutants:
        found = run(mut, am, ae)
        ok = (not found) if want is None else any(want in f for f in found)
        bad += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: {'red' if found else 'green'}")
        if not ok:
            for f in found:
                print(f"      {f}")
    return 1 if bad else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if argv[1:]:
        print(__doc__)
        return 2
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = lint(root)
    for f in found:
        print(f)
    if not found:
        print(f"arch layout: {sum(len(v) for v in REQUIRED.values())} required modules "
              f"x 3 ISAs, {len(ALLOW_MISSING)} gaps and {len(ALLOW_EXTRA)} extras listed")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""pt_writes_lint.py: a stage-1 page-table word is written only through the funnel
(crates/core/mm/src/pt.rs: pt_set, pt_store, pt_cas).

A monitor that protects the kernel half's tables (VIRT_SPLIT) can take over only
what goes through one place; a store that bypasses it faults at stage 2 on a split
image, and on every other image it is a write nobody can audit. So in the scanned
files a raw volatile write, store, swap, fetch-and-modify or compare-and-swap on
anything but an UPPER_CASE static (a counter or flag, never a table) is counted by
hand in tools/lint/pt_writes.tsv, one row per file, with the exact count and why
those sites are not page-table words. A new site fails until someone has looked
at it and either uses the funnel or counts it here.

Scanned: the mm crate's files that build or install table words (they name an
`Mmu` word builder, or are pte_install.rs); any other file outside arch/ that
names one (only mm may build a word); and the arch boot-table files listed in
ARCH_TABLES, which run before the funnel exists or cannot reach it.

  pt_writes_lint.py              check the tree
  pt_writes_lint.py --self-test  the lint's own canaries
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
from arch_cfg_lint import strip_rust  # noqa: E402

REPO = azos_tools.ROOT
BASELINE = "tools/lint/pt_writes.tsv"
FUNNEL = "crates/core/mm/src/pt.rs"
MM = "crates/core/mm/src"
EXTRA_MM = {"crates/core/mm/src/pte_install.rs"}
ARCH_TABLES = (
    "arch/aarch64/src/mmu/setup.rs",
    "arch/riscv/src/mmu.rs",
    "arch/riscv/src/api_impl.rs",
    "arch/x86_64/src/mmu.rs",
    "arch/x86_64/src/mmu/kaslr_boot.rs",
)
# The trait's declaration and the ISAs' definitions of the word builders.
DEFINES = ("arch/api/src/lib.rs", "arch/aarch64/src/api_impl.rs", "arch/riscv/src/api_impl.rs",
           "arch/aarch64/src/mmu/mod.rs", "arch/x86_64/src/lib.rs", "arch/x86_64/src/mmu.rs")
SCAN_ROOTS = ("crates", "kernel", "arch", "userspace")
SKIP_DIRS = {"target", "build", ".git", "third_party", "tests"}
MIN_SCANNED = 3
BUILDER = re.compile(r"\b(?:pte_make_leaf|pte_make_table|pte_make_contig_leaf|pte_share_cow|pte_break_cow|pte_contig_member|PTE_BBM_PARK)\b")
VOLATILE = re.compile(r"\bwrite_volatile\b")
METHOD = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\([^()]*\))?\s*\.\s*(?:store|swap|fetch_(?:add|sub|or|and|xor|max|min)|compare_exchange(?:_weak)?)\s*\(")


def sites(src):
    """Raw write sites in `src` (comments and strings blanked), UPPER_CASE receivers left out."""
    src = strip_rust(src)
    n = len(VOLATILE.findall(src))
    for m in METHOD.finditer(src):
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", m.group(1)):
            n += 1
    return n, bool(BUILDER.search(src))


def rust_files(repo):
    for root in SCAN_ROOTS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(repo, root)):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(".rs"):
                    yield os.path.relpath(os.path.join(dirpath, name), repo)


def scan(repo):
    """{relative path: raw sites}, and how many files were read."""
    found, scanned = {}, 0
    for rel in rust_files(repo):
        if rel == FUNNEL or rel in DEFINES and rel not in ARCH_TABLES:
            continue
        with open(os.path.join(repo, rel), encoding="utf-8", errors="replace") as f:
            n, builds = sites(f.read())
        in_mm = rel.startswith(MM + "/")
        wanted = (in_mm and (builds or rel in EXTRA_MM)) or (builds and not rel.startswith("arch/")) or rel in ARCH_TABLES
        if not wanted:
            continue
        scanned += 1
        if n:
            found[rel] = n
    return found, scanned


def load_baseline(path):
    rows = {}
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 3 or not parts[1].isdigit() or not parts[2].strip():
                raise ValueError(f"{path}:{lineno}: want <file><TAB><count><TAB><why these are not page-table words>")
            rows[parts[0]] = int(parts[1])
    return rows


def check(repo, baseline, min_scanned=MIN_SCANNED):
    found, scanned = scan(repo)
    errors = []
    if scanned < min_scanned:
        errors.append(f"scanned only {scanned} files (expected at least {min_scanned}): the walk is broken")
    for rel, n in sorted(found.items()):
        want = baseline.get(rel, 0)
        if n != want:
            errors.append(f"{rel}: {n} raw write site(s), {BASELINE} counts {want}: "
                          f"a page-table word goes through pt_set, pt_store or pt_cas; anything else is counted there by hand")
    for rel, want in sorted(baseline.items()):
        if rel not in found:
            errors.append(f"{BASELINE}: {rel} counts {want}, the tree has none: drop the row")
    return errors, scanned


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, MM)
        os.makedirs(src)
        vmm = os.path.join(src, "vmm.rs")

        def put(text):
            with open(vmm, "w", encoding="utf-8") as f:
                f.write(text)

        put("// write_volatile in a comment is not a site\nfn f() { let _ = ARCH.pte_make_leaf(0, 0, 0); COUNTER.fetch_add(1, O); FLAG.store(1, O); }\n")
        errors, scanned = check(tmp, {}, 1)
        if errors or scanned != 1:
            return f"a clean file was flagged: {errors} ({scanned} scanned)"
        for name, site in (("a volatile store", "unsafe { core::ptr::write_volatile(p, w) }"),
                           ("a store", "slot.store(w, O);"),
                           ("a call receiver", "pt_word(l0, i).store(w, O);"),
                           ("a compare-and-swap", "let _ = leaf.compare_exchange(a, b, O, O);"),
                           ("a swap", "table.swap(0, O);")):
            put(f"fn f() {{ let _ = ARCH.pte_make_table(0); {site} }}\n")
            errors, _ = check(tmp, {}, 1)
            if len(errors) != 1 or "vmm.rs: 1 raw" not in errors[0]:
                return f"{name} was not flagged: {errors}"
        rel = f"{MM}/vmm.rs"
        errors, _ = check(tmp, {rel: 1}, 1)
        if errors:
            return f"a counted site was flagged: {errors}"
        errors, _ = check(tmp, {rel: 2}, 1)
        if not errors:
            return "a count above the tree passed"
        put("fn f() { let _ = ARCH.pte_make_table(0); }\n")
        errors, _ = check(tmp, {rel: 1}, 1)
        if not errors or "drop the row" not in errors[0]:
            return f"a stale row passed: {errors}"
        funnel = os.path.join(src, "pt.rs")
        with open(funnel, "w", encoding="utf-8") as f:
            f.write("fn f() { unsafe { core::ptr::write_volatile(p, w) } let _ = ARCH.pte_make_table(0); }\n")
        errors, _ = check(tmp, {}, 1)
        if errors:
            return f"the funnel was flagged: {errors}"
        other = os.path.join(tmp, "kernel/src")
        os.makedirs(other)
        with open(os.path.join(other, "x.rs"), "w", encoding="utf-8") as f:
            f.write("fn f() { let w = ARCH.pte_make_leaf(0, p, 0); slot.store(w, O); }\n")
        errors, _ = check(tmp, {}, 1)
        if len(errors) != 1 or "x.rs: 1 raw" not in errors[0]:
            return f"a word built outside mm was not flagged: {errors}"
    return None


def main():
    if "--self-test" in sys.argv[1:]:
        why = self_test()
        if why:
            print(f"pt_writes_lint self-test FAILED: {why}")
            return 1
        print("pt_writes_lint self-test: ok (each raw write form flagged, counted site passes, stale row, the funnel and a word built outside mm)")
        return 0
    errors, scanned = check(REPO, load_baseline(os.path.join(REPO, BASELINE)))
    for e in errors:
        print(f"ERROR {e}")
    if errors:
        return 1
    print(f"pt_writes_lint: ok, {scanned} files scanned")
    return 0


if __name__ == "__main__":
    sys.exit(main())

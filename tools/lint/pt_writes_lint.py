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
ARCH_TABLES, which run before the funnel exists or cannot reach it. A site is a
volatile write, a store, swap, fetch-and-modify or compare-and-swap whatever its
receiver (an UPPER_CASE static is a counter or flag, never a table), a raw
`ptr::write`, `write_bytes`, `copy_nonoverlapping`, a `*p = w` assignment, and
an `asm!` block with a store to memory other than the stack; the `.S` files
under the scanned roots are counted the same way by instruction. A listed path
that matches no file fails: a rename must not drop a file from the scan.

  pt_writes_lint.py              check the tree
  pt_writes_lint.py --self-test  the lint's own canaries
"""
import glob
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
    "arch/riscv*/src/mmu.rs",
    "arch/riscv*/src/api_impl.rs",
    "arch/x86_64/src/mmu.rs",
    "arch/x86_64/src/mmu/kaslr_boot.rs",
)
# The trait's declaration and the ISAs' definitions of the word builders.
DEFINES = ("arch/api/src/lib.rs", "arch/aarch64/src/api_impl.rs", "arch/riscv*/src/api_impl.rs",
           "arch/aarch64/src/mmu/mod.rs", "arch/x86_64/src/lib.rs", "arch/x86_64/src/mmu.rs")
SCAN_ROOTS = ("crates", "kernel", "arch", "userspace")
SKIP_DIRS = {"target", "build", ".git", "third_party", "tests"}
MIN_SCANNED = 3
BUILDER = re.compile(r"\b(?:pte_make_leaf|pte_make_table|pte_make_contig_leaf|pte_share_cow|pte_break_cow|pte_contig_member|PTE_BBM_PARK)\b")
RAW = re.compile(r"\b(?:write_volatile|write_unaligned|write_bytes|copy_nonoverlapping|copy_from|copy_to)\b|\bptr::write\b")
METHOD = re.compile(r"\.\s*(?:store|swap|fetch_(?:add|sub|or|and|xor|nand|max|min|update)|compare_exchange(?:_weak)?)\s*\(")
DEREF = re.compile(r"(?:^|[;{}])[ \t]*\*[ \t]*(?![A-Z][A-Z0-9_]*\b)[A-Za-z_(][^;{}\n]*?[ \t][+\-*/%&|^]?=[ \t]", re.M)
ASM_CALL = re.compile(r"\b(?:global_)?asm!\s*\(")
# A store to memory that is not the stack, on the three ISAs.
STORE = re.compile(
    r"\b(?:str[bh]?|stp|stnp|stlr[bh]?|stur[bh]?|stxr|stlxr|cas[a-z]*|swp[a-z]*|ld(?:add|set|clr|eor)[a-z]*)\s[^\n\"]*\[(?!sp\b)"
    r"|\b(?:sd|sw|sh|sb)\s+[^\n\",]+,\s*-?\w*\((?!sp\b)"
    r"|\bamo[a-z]+\.[a-z.]+"
    r"|\block\s+cmpxchg|\bxchg\b"
    r"|\bmov[a-z]*\s+(?:(?:qword|dword|word|byte)\s+ptr\s+)?\[")


def count_asm(raw):
    """asm! blocks (and the text of an .S file) with a store to memory other than the stack."""
    return len(STORE.findall(raw))


def asm_blocks(raw):
    """The text inside each asm!(...) call of `raw`."""
    for m in ASM_CALL.finditer(raw):
        depth, i = 1, m.end()
        while i < len(raw) and depth:
            depth += {"(": 1, ")": -1}.get(raw[i], 0)
            i += 1
        yield raw[m.end():i]


def receiver_is_static(src, dot):
    """Does the expression before the `.` at `dot` end in an UPPER_CASE name?"""
    i = dot
    while i > 0 and src[i - 1].isspace():
        i -= 1
    j = i
    while j > 0 and (src[j - 1].isalnum() or src[j - 1] == "_"):
        j -= 1
    return j < i and re.fullmatch(r"[A-Z][A-Z0-9_]*", src[j:i]) is not None


def sites(src):
    """Raw write sites in a Rust source (comments and strings blanked, asm read raw), and whether it names a word builder."""
    stripped = strip_rust(src)
    n = len(RAW.findall(stripped)) + len(DEREF.findall(stripped))
    n += sum(1 for m in METHOD.finditer(stripped) if not receiver_is_static(stripped, m.start()))
    n += sum(1 for block in asm_blocks(src) if STORE.search(block))
    return n, bool(BUILDER.search(stripped))


def asm_sites(text):
    """Store instructions in a `.S` file (comments dropped)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?m)(//|@|;).*$", "", text)
    return count_asm(text)


def walk(repo, suffix):
    for root in SCAN_ROOTS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(repo, root)):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(suffix):
                    yield os.path.relpath(os.path.join(dirpath, name), repo)


def expand(repo, patterns):
    """The files `patterns` name, and the patterns that name none."""
    files, missing = set(), []
    for pat in patterns:
        hits = glob.glob(os.path.join(repo, pat))
        if not hits:
            missing.append(pat)
        files.update(os.path.relpath(h, repo) for h in hits)
    return files, missing


def scan(repo):
    """{relative path: raw sites}, how many files were read, the listed paths that match nothing."""
    found, scanned = {}, 0
    tables, gone = expand(repo, ARCH_TABLES)
    defines, gone_defines = expand(repo, DEFINES)
    for rel in walk(repo, ".rs"):
        if rel == FUNNEL or rel in defines and rel not in tables:
            continue
        with open(os.path.join(repo, rel), encoding="utf-8", errors="replace") as f:
            n, builds = sites(f.read())
        in_mm = rel.startswith(MM + "/")
        wanted = (in_mm and (builds or rel in EXTRA_MM)) or (builds and not rel.startswith("arch/")) or rel in tables
        if not wanted:
            continue
        scanned += 1
        if n:
            found[rel] = n
    for rel in walk(repo, ".S"):
        with open(os.path.join(repo, rel), encoding="utf-8", errors="replace") as f:
            n = asm_sites(f.read())
        scanned += 1
        if n:
            found[rel] = n
    return found, scanned, gone + gone_defines


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


def check(repo, baseline, min_scanned=MIN_SCANNED, strict=True):
    found, scanned, gone = scan(repo)
    errors = [f"{pat}: listed in the lint and matches no file: a rename must update it" for pat in gone if strict]
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
        errors, scanned = check(tmp, {}, 1, strict=False)
        if errors or scanned != 1:
            return f"a clean file was flagged: {errors} ({scanned} scanned)"
        for name, site in (("a volatile store", "unsafe { core::ptr::write_volatile(p, w) }"),
                           ("a store", "slot.store(w, O);"),
                           ("a call receiver", "pt_word(l0, i).store(w, O);"),
                           ("a compare-and-swap", "let _ = leaf.compare_exchange(a, b, O, O);"),
                           ("a swap", "table.swap(0, O);"),
                           ("an indexed receiver", "tables[i].store(w, O);"),
                           ("a nested call receiver", "f(g(x)).store(w, O);"),
                           ("a block receiver", "unsafe { &*p }.store(w, O);"),
                           ("a fetch_update", "t.fetch_update(O, O, |w| Some(w));"),
                           ("a fetch_nand", "t.fetch_nand(1, O);"),
                           ("ptr::write", "unsafe { core::ptr::write(p, w) };"),
                           ("write_bytes", "unsafe { p.write_bytes(0, 8) };"),
                           ("copy_nonoverlapping", "unsafe { core::ptr::copy_nonoverlapping(a, b, 8) };"),
                           ("a deref assignment", "unsafe { *p = w; }"),
                           ("a compound deref assignment", "unsafe { *p |= w; }"),
                           ("an aarch64 asm store", 'unsafe { core::arch::asm!("str {w}, [{p}]", w = in(reg) w, p = in(reg) p) };'),
                           ("a riscv asm store", 'unsafe { core::arch::asm!("sd {w}, 0({p})", w = in(reg) w, p = in(reg) p) };'),
                           ("an x86 asm store", 'unsafe { core::arch::asm!("mov qword ptr [{p}], {w}", w = in(reg) w, p = in(reg) p) };')):
            put(f"fn f() {{ let _ = ARCH.pte_make_table(0); {site} }}\n")
            errors, _ = check(tmp, {}, 1, strict=False)
            if len(errors) != 1 or "vmm.rs: 1 raw" not in errors[0]:
                return f"{name} was not flagged: {errors}"
        rel = f"{MM}/vmm.rs"
        errors, _ = check(tmp, {rel: 1}, 1, strict=False)
        if errors:
            return f"a counted site was flagged: {errors}"
        errors, _ = check(tmp, {rel: 2}, 1, strict=False)
        if not errors:
            return "a count above the tree passed"
        put("fn f() { let _ = ARCH.pte_make_table(0); }\n")
        errors, _ = check(tmp, {rel: 1}, 1, strict=False)
        if not errors or "drop the row" not in errors[0]:
            return f"a stale row passed: {errors}"
        put("fn f() { let _ = ARCH.pte_make_table(0); unsafe { core::arch::asm!(\"stp x0, x1, [sp, #-16]!\") }; let _ = a * b == c; let _ = x.load(O); }\n")
        errors, _ = check(tmp, {}, 1, strict=False)
        if errors:
            return f"a stack push, a multiplication or a load was flagged: {errors}"
        sfile = os.path.join(tmp, "kernel/src/entry/aarch64/asm")
        os.makedirs(sfile)
        with open(os.path.join(sfile, "x.S"), "w", encoding="utf-8") as f:
            f.write("stp x0, x1, [sp, #-16]!   // stack\n  str x2, [x3, #8]\n")
        errors, _ = check(tmp, {}, 1, strict=False)
        if len(errors) != 1 or "x.S: 1 raw" not in errors[0]:
            return f"a store in an .S file was not flagged, or a stack push was: {errors}"
        os.remove(os.path.join(sfile, "x.S"))
        errors, _ = check(tmp, {}, 1)
        if not errors or "matches no file" not in errors[0]:
            return f"a listed path that matches no file passed: {errors}"
        put("fn f() { let _ = ARCH.pte_make_table(0); }\n")
        funnel = os.path.join(src, "pt.rs")
        with open(funnel, "w", encoding="utf-8") as f:
            f.write("fn f() { unsafe { core::ptr::write_volatile(p, w) } let _ = ARCH.pte_make_table(0); }\n")
        errors, _ = check(tmp, {}, 1, strict=False)
        if errors:
            return f"the funnel was flagged: {errors}"
        other = os.path.join(tmp, "kernel/src")
        os.makedirs(other, exist_ok=True)
        with open(os.path.join(other, "x.rs"), "w", encoding="utf-8") as f:
            f.write("fn f() { let w = ARCH.pte_make_leaf(0, p, 0); slot.store(w, O); }\n")
        errors, _ = check(tmp, {}, 1, strict=False)
        if len(errors) != 1 or "x.rs: 1 raw" not in errors[0]:
            return f"a word built outside mm was not flagged: {errors}"
    return None


def main():
    if "--self-test" in sys.argv[1:]:
        why = self_test()
        if why:
            print(f"pt_writes_lint self-test FAILED: {why}")
            return 1
        print("pt_writes_lint self-test: ok (every raw write form flagged, a stack push and a load not, counted site passes, stale row, the funnel, a word built outside mm, an .S store, a listed path that matches nothing)")
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

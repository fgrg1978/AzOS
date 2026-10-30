#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""mmio_accessors.py: code that runs on aarch64 reaches a device only through
azos_arch_api::mmio (arch/api/src/mmio.rs).

`read_volatile`/`write_volatile` leave the addressing mode to the compiler, and
a writeback or pair form on a device aborts the VM under HVF (arch/api/src/mmio.rs
says why). The compiler cannot tell a register from RAM, and neither can a grep:
so every raw volatile access in the scanned tree must be accounted for by
tools/lint/mmio_accessors.tsv, one row per file, with the exact count and why those
sites are memory. A new site in any file fails, whichever it is, until someone
has looked at it and either uses the accessor or counts it here by hand.

  mmio_accessors.py              check the tree; prints how many files it scanned
  mmio_accessors.py --self-test  the lint's own canaries
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
from arch_cfg_lint import strip_rust  # noqa: E402

REPO = azos_tools.ROOT
BASELINE = "tools/lint/mmio_accessors.tsv"
ACCESSOR = "arch/api/src/mmio.rs"
SCAN_ROOTS = ("arch/aarch64", "kernel/src", "crates/drivers", "userspace/drivers", "userspace/tests/captest")
# Never built for aarch64.
SKIP_PREFIXES = ("kernel/src/entry/riscv64/", "kernel/src/entry/x86_64/")
SKIP_DIRS = {"target", "build", ".git", "third_party"}
# Fewer files than this means the walk went wrong, not that the tree shrank.
MIN_SCANNED = 400
RAW = re.compile(r"\b(?:read|write)_volatile\b")
FORMS = re.compile(r'"(?:ldr|str)[bh]? \{v:[wx]\}, \[\{a\}\]"')
ALL_ASM = re.compile(r'"(?:ldr|str)[^"]*"')
WIDTHS = 8  # read and write of four widths


def count_sites(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return len(RAW.findall(strip_rust(f.read())))


def scan(repo):
    """{relative path: raw volatile sites}, and how many files were read."""
    sites, scanned = {}, 0
    for root in SCAN_ROOTS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(repo, root)):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if not name.endswith(".rs"):
                    continue
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, repo)
                if rel.startswith(SKIP_PREFIXES):
                    continue
                scanned += 1
                n = count_sites(path)
                if n:
                    sites[rel] = n
    return sites, scanned


def load_baseline(path):
    rows = {}
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 3 or not parts[0].isdigit() or not parts[2].strip():
                raise ValueError(f"{path}:{lineno}: want <count><TAB><file><TAB><why these are memory>")
            rows[parts[1]] = int(parts[0])
    return rows


def check(repo, baseline, min_scanned=MIN_SCANNED):
    """The list of errors, and how many files were scanned."""
    sites, scanned = scan(repo)
    errors = []
    if scanned < min_scanned:
        errors.append(f"scanned only {scanned} files (expected at least {min_scanned}): the walk is broken")
    for rel, n in sorted(sites.items()):
        want = baseline.get(rel, 0)
        if n != want:
            errors.append(
                f"{rel}: {n} raw volatile access(es), {BASELINE} counts {want}: "
                f"a device register goes through azos_arch_api::mmio; memory is counted there by hand")
    for rel, want in sorted(baseline.items()):
        if rel not in sites:
            errors.append(f"{BASELINE}: {rel} counts {want}, the tree has none: drop the row")
    return errors, scanned


def check_accessor(path):
    with open(path, encoding="utf-8") as f:
        src = f.read()
    forms = FORMS.findall(src)
    if len(forms) != WIDTHS or len(ALL_ASM.findall(src)) != WIDTHS:
        return [f"{ACCESSOR}: want {WIDTHS} ldr/str templates with a bare base register, "
                f"found {len(forms)} of {len(ALL_ASM.findall(src))}"]
    return []


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "crates/drivers/x/src")
        os.makedirs(src)
        good = os.path.join(src, "good.rs")
        planted = os.path.join(src, "planted.rs")
        with open(good, "w", encoding="utf-8") as f:
            f.write("// read_volatile in a comment is not a site\nfn f() {}\n")
        errors, scanned = check(tmp, {}, 2 + 1)
        if scanned != 1 or len(errors) != 1 or "scanned only" not in errors[0]:
            return f"a tree of one file: scanned {scanned}, errors {errors}"
        with open(planted, "w", encoding="utf-8") as f:
            f.write("unsafe fn f(b: usize) { core::ptr::write_volatile((b + 4) as *mut u32, 1) }\n")
        errors, scanned = check(tmp, {}, 2)
        if scanned != 2 or len(errors) != 1 or "planted.rs: 1 raw" not in errors[0]:
            return f"a planted site was not flagged: scanned {scanned}, errors {errors}"
        rel = "crates/drivers/x/src/planted.rs"
        errors, _ = check(tmp, {rel: 1}, 2)
        if errors:
            return f"a counted site was flagged: {errors}"
        errors, _ = check(tmp, {rel: 2}, 2)
        if not errors:
            return "a count above the tree passed"
        errors, _ = check(tmp, {rel: 1, "crates/drivers/x/src/gone.rs": 1}, 2)
        if not errors or "gone.rs" not in errors[0]:
            return f"a stale row passed: {errors}"
        with open(planted, "w", encoding="utf-8") as f:
            f.write('asm!("str {v:w}, [{a}], #4")\n')
        if not check_accessor(planted):
            return "a writeback template passed the accessor check"
    errors = check_accessor(os.path.join(REPO, ACCESSOR))
    if errors:
        return f"the real accessor fails its own check: {errors}"
    return None


def main():
    if "--self-test" in sys.argv[1:]:
        why = self_test()
        if why:
            print(f"mmio_accessors self-test FAILED: {why}")
            return 1
        print("mmio_accessors self-test: ok (planted site flagged, counted site passes, stale row and writeback form flagged)")
        return 0
    errors, scanned = check(REPO, load_baseline(os.path.join(REPO, BASELINE)))
    errors += check_accessor(os.path.join(REPO, ACCESSOR))
    for e in errors:
        print(f"ERROR {e}")
    if errors:
        return 1
    print(f"mmio_accessors: ok, {scanned} files scanned")
    return 0


if __name__ == "__main__":
    sys.exit(main())

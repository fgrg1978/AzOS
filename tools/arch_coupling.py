#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Inventory of ISA coupling outside the arch crates: the arch-contract migration list.

Counts and classifies

  1. every facade bypass `azos_arch::<module>::...` (including `use azos_arch::{..}`
     groups): code that reaches an ISA crate's module directly instead of the
     `arch-api` contract (traits + `ARCH` + `PAGE_SIZE`/`PAGE_SHIFT`);
  2. every `cfg(target_arch)` site (`#[cfg]`, `#![cfg]`, `cfg!`, `cfg_attr`),
     with the coverage verdict of tools/arch_cfg_lint.py;
  3. every *whole per-ISA function in a shared file*: an `fn` item guarded by a
     `target_arch` cfg outside the arch crates.

For each bypassed module item it says whether it exists on both ISAs (a trait
candidate), on one (ISA-private: its caller needs a trait method or a
`compile_error!` branch), or is already covered by the contract (a mechanical
migration).

Scope: the .rs files under crates/ kernel/ domains/ lx/ userspace/, minus the
arch crates (same as tools/arch_cfg_lint.py). Comments and string literals are
ignored.

Usage:
    python3 tools/arch_coupling.py              # summary counts
    python3 tools/arch_coupling.py --md FILE    # full markdown table
"""

import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arch_cfg_lint as L  # noqa: E402

REPO = L.REPO
ISA_CRATES = {"rv": "crates/core/arch-riscv64/src", "arm": "crates/core/arch-aarch64/src"}
API = "crates/core/arch-api/src/lib.rs"


isa_owned = L.isa_owned


def isa_surface(src_dir):
    """{module: set(pub item names)} of one ISA crate (top-level pub mods)."""
    lib = open(os.path.join(REPO, src_dir, "lib.rs"), encoding="utf-8").read()
    mods = {}
    for m in re.finditer(r"^\s*pub mod (\w+)\s*;", L.strip_rust(lib), re.M):
        name = m.group(1)
        f = os.path.join(REPO, src_dir, name + ".rs")
        if not os.path.exists(f):
            f = os.path.join(REPO, src_dir, name, "mod.rs")
        items = set()
        if os.path.exists(f):
            s = L.strip_rust(open(f, encoding="utf-8").read())
            for im in re.finditer(r"\bpub\s+(?:unsafe\s+|const\s+|extern\s+\"?C?\"?\s*)*(?:fn|const|static|struct|enum|type|trait|mod)\s+(?:mut\s+)?(\w+)", s):
                items.add(im.group(1))
            for um in re.finditer(r"\bpub\s+use\s+([^;]+);", s):
                for w in re.findall(r"(\w+)\s*(?:,|\}|$)", um.group(1)):
                    items.add(w)
        mods[name] = items
    return mods


def contract_names():
    """Trait method names and pub consts/types of arch-api (the contract)."""
    s = L.strip_rust(open(os.path.join(REPO, API), encoding="utf-8").read())
    methods = set(re.findall(r"^\s*(?:unsafe\s+)?fn\s+(\w+)", s, re.M))
    names = set(re.findall(r"\bpub\s+(?:const|struct|enum|trait|type|fn)\s+(\w+)", s))
    return methods, names


def expand_use(s, i):
    """Paths named right after `azos_arch::` at index i (handles `{}` groups)."""
    m = re.match(r"\s*\{", s[i:])
    if m:
        ob = i + m.end() - 1
        cb = L.match_close(s, ob)
        body = s[ob + 1:cb - 1]
        out, depth, cur = [], 0, ""
        for ch in body + ",":
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            if ch == "," and depth == 0:
                cur = cur.strip()
                if cur:
                    if "{" in cur:
                        head = cur[:cur.index("{")].rstrip(":").strip()
                        for sub in expand_use(cur, cur.index("{")):
                            out.append(head + "::" + sub)
                    else:
                        out.append(re.sub(r"\s+as\s+\w+$", "", cur))
                cur = ""
            else:
                cur += ch
        return out
    m = re.match(r"(\w+(?:\s*::\s*\w+)*)", s[i:])
    return [re.sub(r"\s+", "", m.group(1))] if m else []


def bypasses(surf):
    """List of (rel, line, module, item) facade bypasses."""
    isa_mods = set(surf["rv"]) | set(surf["arm"])
    out = []
    for rel, path in L.iter_files():
        text = open(path, encoding="utf-8", errors="replace").read()
        if "azos_arch::" not in text:
            continue
        s = L.strip_rust(text)
        for m in re.finditer(r"\bazos_arch::", s):
            for p in expand_use(s, m.end()):
                segs = p.split("::")
                if segs[0] in isa_mods:
                    item = segs[1] if len(segs) > 1 else "<module>"
                    out.append((rel, L.line_of(s, m.start()), segs[0], item))
    return out


def whole_fns():
    """[(rel, line, fn name, isa-tag)] fn items under a positive target_arch cfg."""
    out = []
    for rel, path in L.iter_files():
        if isa_owned(rel):
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        if "target_arch" not in text:
            continue
        s = L.strip_rust(text)
        for st in L.scan_text(text):
            if st.kind != "attr" or "pos" not in L.arch_polarity(st.pred):
                continue
            body = s[st.end:st.item_end]
            body = re.sub(r"#!?\[[^\]]*\]", "", body)
            m = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:unsafe\s+)?(?:extern\s+\S*\s*)?fn\s+(\w+)", body)
            if m:
                arches = sorted(L.arch_names(st.pred))
                out.append((rel, st.line, m.group(1), "/".join(arches)))
    return out


def cfg_sites():
    per_dir, kinds, total, unc = collections.Counter(), collections.Counter(), 0, 0
    for rel, path in L.iter_files():
        text = open(path, encoding="utf-8", errors="replace").read()
        if "target_arch" not in text:
            continue
        for st in L.scan_text(text):
            total += 1
            unc += (not st.covered) and not isa_owned(rel)
            kinds[(st.kind, st.covered)] += 1
            parts = rel.split("/")
            key = "/".join(parts[:3]) if parts[0] in ("crates", "userspace", "domains") else "/".join(parts[:3]) if parts[0] == "kernel" and len(parts) > 3 else rel
            per_dir[key] += 1
    return total, unc, kinds, per_dir


def classify(mod, item, surf, methods, names):
    rv, arm = surf["rv"], surf["arm"]
    if item in names or item in methods:
        return "contract"
    in_rv = mod in rv and (item == "<module>" or item in rv[mod])
    in_arm = mod in arm and (item == "<module>" or item in arm[mod])
    if in_rv and in_arm:
        return "both"
    if in_rv:
        return "rv-only"
    if in_arm:
        return "arm-only"
    return "unresolved"


def main(argv):
    surf = {k: isa_surface(v) for k, v in ISA_CRATES.items()}
    methods, names = contract_names()
    bp = bypasses(surf)
    total, unc, kinds, per_dir = cfg_sites()
    wf = whole_fns()
    shared = [b for b in bp if not isa_owned(b[0])]
    print(f"facade bypasses: {len(bp)} ({len(shared)} in shared files, {len(bp) - len(shared)} in ISA-owned files)")
    print(f"target_arch cfg sites: {total} (uncovered by arch_cfg_lint: {unc})")
    print(f"whole per-ISA fns in shared files: {len(wf)}")
    if "--md" not in argv:
        return 0
    out = argv[argv.index("--md") + 1]
    by_mod = collections.Counter(m for _, _, m, _ in bp)
    by_item = collections.Counter((m, i) for _, _, m, i in bp)
    files_by_item = collections.defaultdict(set)
    for rel, _, m, i in bp:
        files_by_item[(m, i)].add(rel)
    w = []
    w.append("# Arch coupling inventory (tools/arch_coupling.py)\n")
    w.append(f"- facade bypasses `azos_arch::<mod>::`: **{len(bp)}** "
             f"({len(shared)} in shared files, {len(bp) - len(shared)} in ISA-owned files such as "
             "`kernel/src/entry/<isa>*`, which are that port's own code)")
    w.append(f"- `target_arch` cfg sites: **{total}**, uncovered (no else / compile_error!): **{unc}**")
    w.append(f"- whole per-ISA functions in shared files: **{len(wf)}**\n")
    w.append("## ISA module surface\n")
    w.append("| module | riscv64 | aarch64 |\n|---|---|---|")
    for mod in sorted(set(surf["rv"]) | set(surf["arm"])):
        w.append(f"| {mod} | {'yes' if mod in surf['rv'] else '-'} | {'yes' if mod in surf['arm'] else '-'} |")
    w.append("\n## Bypasses by module\n")
    w.append("| module | sites |\n|---|---|")
    for mod, n in by_mod.most_common():
        w.append(f"| {mod} | {n} |")
    w.append("\n## Bypasses by item (the migration list)\n")
    w.append("Class: `contract` = already in arch-api (mechanical); `both` = on both ISAs (trait candidate); "
             "`rv-only`/`arm-only` = ISA-private (caller needs a trait method or a compile_error! branch).\n")
    w.append("Files marked `*` are ISA-owned (not inherited by a new ISA).\n")
    w.append("| module::item | sites | class | files |\n|---|---|---|---|")
    for (mod, item), n in by_item.most_common():
        cls = classify(mod, item, surf, methods, names)
        files = ", ".join(f + ("*" if isa_owned(f) else "") for f in sorted(files_by_item[(mod, item)]))
        w.append(f"| {mod}::{item} | {n} | {cls} | {files} |")
    w.append("\n## cfg(target_arch) sites by directory\n")
    w.append("| directory | sites |\n|---|---|")
    for d, n in per_dir.most_common():
        w.append(f"| {d} | {n} |")
    w.append("\n| kind | covered | sites |\n|---|---|---|")
    for (k, c), n in sorted(kinds.items()):
        w.append(f"| {k} | {c} | {n} |")
    w.append("\n## Whole per-ISA functions in shared files\n")
    w.append("| file:line | fn | guard |\n|---|---|---|")
    for rel, line, name, tag in wf:
        w.append(f"| {rel}:{line} | {name} | {tag} |")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(w) + "\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

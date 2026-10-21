#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Lint: shared code must not vanish, or reach past the facade, on a new ISA.

Two ratchets, one tool: (1) `cfg(target_arch)` branches that vanish on a new
ISA, (2) facade bypasses: references to ISA-specific arch modules. Part (1):

A shared file that says

    #[cfg(target_arch = "riscv64")]  fence_rv();
    #[cfg(target_arch = "aarch64")]  fence_arm();

compiles on a third ISA with NO fence at all. Nothing is red: the branch just
disappears. This lint makes every such site carry its answer for "any other
ISA", so a port fails to COMPILE instead of losing code.

Rule. A *violation* is a positive `target_arch` guard (an outer attribute
`#[cfg(...)]`, an inner `#![cfg(...)]`, or an `if cfg!(...) { }` without an
`else`) outside the arch crates that has no complement. A guard is covered when

  * its own predicate mentions `target_arch` under a `not(...)` (it IS the else
    branch: `#[cfg(not(target_arch = "riscv64"))]`); or
  * it sits in a *chain* of adjacent sibling items/statements, each guarded by
    a `target_arch` cfg, and some member of the chain is an else branch (as
    above) or contains `compile_error!`; or
  * the file has a covered `compile_error!` guard of its own (a file-level
    `#[cfg(not(any(target_arch = ...)))] compile_error!(...)` covers every
    site in that file: the file cannot compile on an ISA it does not know); or
  * it is a `cfg!(...)` used as a value, or as an `if` condition WITH an
    `else` (both arms compile on every ISA, so nothing can vanish); or
  * a `// arch-only: <why>` comment sits right above it: a reviewed
    decision that the code has no counterpart elsewhere (a diagnostic, an
    optimisation, an ISA-only register), so its absence on another ISA is
    not a loss.

A `riscv64` / `aarch64` pair is NOT a complement: that is exactly the case that
vanishes on x86_64. `cfg_attr(target_arch ...)` is exempt (it changes an
attribute, it does not remove code); the inventory still counts it.

Files that only build for one ISA (`kernel/src/entry/<isa>*`, `<isa>_*.rs`)
are exempt: nothing in them can vanish on another ISA.

Ratchet. `tools/arch_cfg_lint.baseline` lists today's violations per FILE (not
per line, so unrelated edits that move lines do not trip it). A file above its
baseline count, or a file not in the baseline with any violation, fails. A file
below its count passes and is reported, so the baseline can be lowered with
`--update-baseline`, which refuses to raise any count.

Part (2), facade bypass (the `[facade]` section of the same baseline). Shared
code is meant to reach the ISA only through the `arch-api` contract and the
`azos_arch::ARCH` singleton. A *facade reference* is a path
`azos_arch::<module>...` (a `use azos_arch::{..}` group counts one per leaf)
whose module is not present on all three ISA crates (`csr`, `sbi`, `rvv`,
`sysregs`, `gic`, `mpidr`, `fp_state`, `fpu`, `hw`, `cbo`, ...), or whose
module is `irq` and whose next segment is a chip (`irq::plic`, `irq::gic`,
`irq::apic`, ...), or whose module is `ext` (the per-ISA extras, declared on
every ISA but ISA-specific inside: `ext::<sub>` always counts).
`use azos_arch::csr;` followed by `csr::read()` counts the import and every
use; so does importing one chip (`use azos_arch::irq::gic;`) or one `ext`
module. The module sets are read from each arch crate's
`lib.rs` (and `irq/mod.rs`), by NAME, so a file rename inside an arch crate
moves nothing; a renamed or new module is picked up as it appears, and the
integrator re-runs `--update` after a batch of picks. Scope: the files of
`SCAN_ROOTS` outside the arch crates and outside `kernel/src/entry/` (the
ports' own entry code). Same ratchet: per-file, a count above its baseline or
a file not in it fails. `--update` rewrites the section from the tree (it
may raise a count: that is the explicit step after a rename) and prints the
differences.

Usage:
    python3 tools/arch_cfg_lint.py                 # both ratchets (ci_check row)
    python3 tools/arch_cfg_lint.py --facade        # facade ratchet only (n0 tier row)
    python3 tools/arch_cfg_lint.py --list [PATH]   # every cfg violation, with line
    python3 tools/arch_cfg_lint.py --list-facade [PATH]  # every facade reference
    python3 tools/arch_cfg_lint.py --update-baseline     # cfg part, lower only
    python3 tools/arch_cfg_lint.py --update              # facade part, rewrite
    python3 tools/arch_cfg_lint.py --self-test     # canaries on built fixtures
"""

import os
import re
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(REPO, "tools", "arch_cfg_lint.baseline")

# Shared code lives here; the arch crates are where per-ISA code belongs.
SCAN_ROOTS = ("crates", "kernel", "domains", "lx", "userspace")
ARCH_CRATES = (
    "crates/core/arch/",
    "crates/core/arch-api/",
    "crates/core/arch-riscv64/",
    "crates/core/arch-aarch64/",
    "crates/core/arch-x86_64/",
)
# The ISAs with a directory under kernel/src/entry/ (x86_64: a skeleton).
ISAS = ("riscv64", "aarch64", "x86_64")
SKIP_DIRS = {"target", "build", ".git", "target 2", "build 2", "third_party"}
# The ports' own entry code: allowed to name its ISA's modules.
ENTRY_DIR = "kernel/src/entry/"


# ── source scanning (shared with tools/arch_coupling.py) ────────────────────

def strip_rust(src):
    """Blank comments and string/char literal contents, keeping offsets/lines."""
    out = list(src)
    i, n = 0, len(src)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "r" and re.match(r'r#*"', src[i:i + 70]) and not (i and (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = re.match(r'r(#*)"', src[i:])
            close = '"' + m.group(1)
            j = src.find(close, i + len(m.group(0)))
            j = n if j < 0 else j + len(close)
            blank(i + 1, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1
        elif c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                j = src.find("'", i + 2)
                j = n if j < 0 else j
                blank(i + 1, j)
                i = j + 1
            elif i + 2 < n and src[i + 2] == "'":
                blank(i + 1, i + 2)
                i += 3
            else:
                i += 1  # a lifetime
        else:
            i += 1
    return "".join(out)


def match_close(s, i):
    """Index just past the bracket matching the opener at s[i]."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[s[i]]]
    j = i + 1
    while j < len(s) and stack:
        ch = s[j]
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")]}":
            if ch == stack[-1]:
                stack.pop()
            else:
                return len(s)
        j += 1
    return j


def parse_pred(text):
    """Parse a cfg predicate into nested (name, value, children) tuples."""
    toks = re.findall(r'[A-Za-z_][A-Za-z0-9_]*|"[^"]*"|[(),=]', text)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def expr():
        name = peek()
        pos[0] += 1
        if peek() == "=":
            pos[0] += 1
            val = peek()
            pos[0] += 1
            return (name, val, [])
        if peek() == "(":
            pos[0] += 1
            kids = []
            while peek() not in (")", None):
                kids.append(expr())
                if peek() == ",":
                    pos[0] += 1
            pos[0] += 1
            return (name, None, kids)
        return (name, None, [])

    try:
        return expr()
    except Exception:
        return ("?", None, [])


def arch_polarity(node, neg=False):
    """Set of polarities ('pos'/'neg') under which target_arch appears."""
    name, _, kids = node
    if name == "target_arch":
        return {"neg" if neg else "pos"}
    out = set()
    for k in kids:
        out |= arch_polarity(k, neg ^ (name == "not"))
    return out


def arch_names(node):
    """Every ISA name a predicate mentions (`target_arch = "..."`)."""
    name, val, kids = node
    out = set()
    if name == "target_arch" and val:
        out.add(val.strip('"'))
    for k in kids:
        out |= arch_names(k)
    return out


class Site:
    __slots__ = ("kind", "start", "end", "pred", "line", "covered", "why", "attr_start", "item_end")

    def __init__(self, kind, start, end, pred, line):
        self.kind, self.start, self.end, self.pred, self.line = kind, start, end, pred, line
        self.covered, self.why = False, ""
        self.attr_start = start
        self.item_end = end


def line_of(s, idx, _cache={}):
    return s.count("\n", 0, idx) + 1


def item_end(s, i):
    """End of the item/statement starting at i (after its attributes)."""
    n = len(s)
    # skip further attributes
    while True:
        while i < n and s[i].isspace():
            i += 1
        if s.startswith("#[", i) or s.startswith("#![", i):
            j = s.find("[", i)
            i = match_close(s, j)
            continue
        break
    # An `fn` item ends at its body or `;`, never at a comma: the commas of
    # `-> Result<(), E>` are in its signature.
    is_fn = re.match(r'(pub(\([^)]*\))?\s+)?((const|unsafe|async)\s+|extern\s+"[^"]*"\s+)*fn\b', s[i:i + 80]) is not None
    depth = 0
    j = i
    while j < n:
        ch = s[j]
        if s.startswith("::<", j):
            # turbofish generics: their commas do not end the statement
            depth, j = 0, j + 2
            while j < n:
                if s[j] == "<":
                    depth += 1
                elif s[j] == ">":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                j += 1
            continue
        if ch in "([":
            j = match_close(s, j)
            continue
        if ch == "{":
            j = match_close(s, j)
            # a `{}` block at depth 0 ends an item (fn, mod, impl, block stmt)
            # unless the item continues (`else`, `=`-expression, `.method`).
            k = j
            while k < n and s[k].isspace():
                k += 1
            if s.startswith("else", k) or (k < n and s[k] in ".?;"):
                if k < n and s[k] == ";":
                    return k + 1
                continue
            return j
        if ch == ";" or (ch == "," and not is_fn):
            return j + 1
        if ch in ")]}":
            return j
        j += 1
    return n


def find_sites(s, text=None):
    """All target_arch cfg sites in stripped source s (`text`, the original,
    supplies the predicates: stripping blanks their string literals)."""
    text = s if text is None else text
    sites = []
    for m in re.finditer(r"#(!?)\[\s*(cfg|cfg_attr)\s*\(", s):
        open_b = s.find("[", m.start())
        close_b = match_close(s, open_b)
        paren = s.find("(", m.start())
        pend = match_close(s, paren)
        pred_text = text[paren + 1:pend - 1]
        if m.group(2) == "cfg_attr":
            # only the condition (first argument) matters
            depth, cut = 0, len(pred_text)
            for k, ch in enumerate(pred_text):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif ch == "," and depth == 0:
                    cut = k
                    break
            pred_text = pred_text[:cut]
        if "target_arch" not in pred_text:
            continue
        kind = "cfg_attr" if m.group(2) == "cfg_attr" else ("inner" if m.group(1) else "attr")
        st = Site(kind, m.start(), close_b, parse_pred(pred_text), line_of(s, m.start()))
        if kind == "attr":
            st.item_end = item_end(s, close_b)
        sites.append(st)
    for m in re.finditer(r"\bcfg!\s*\(", s):
        paren = s.find("(", m.start())
        pend = match_close(s, paren)
        pred_text = text[paren + 1:pend - 1]
        if "target_arch" not in pred_text:
            continue
        sites.append(Site("expr", m.start(), pend, parse_pred(pred_text), line_of(s, m.start())))
    sites.sort(key=lambda x: x.start)
    return sites


ARCH_ONLY_RE = re.compile(r"//\s*arch-only:\s*\S")


def _marker_above(text, pos):
    """`// arch-only: <why>` on a line above `pos`, separated from it only
    by attributes, doc/plain comments or blank lines."""
    if not text:
        return False
    line_start = text.rfind("\n", 0, pos) + 1
    j = line_start
    while j > 0:
        prev_end = j - 1
        prev_start = text.rfind("\n", 0, prev_end) + 1
        line = text[prev_start:prev_end].strip()
        if ARCH_ONLY_RE.search(line):
            return True
        if line.startswith(("#[", "//")) or not line:
            j = prev_start
            continue
        return False
    return False


def classify(s, sites, text=""):
    """Mark each site covered or not (see module doc)."""
    attrs = [x for x in sites if x.kind == "attr"]
    # chains of adjacent guarded siblings
    chains, cur = [], []
    for st in attrs:
        if cur:
            gap = s[cur[-1].item_end:st.start]
            gap = re.sub(r"#!?\[[^\]]*\]", "", gap)  # other attributes on the item
            if gap.strip(" \t\r\n;,") == "":
                cur.append(st)
                continue
            chains.append(cur)
        cur = [st]
    if cur:
        chains.append(cur)

    # A file-level guard is a chain member that is an else branch and holds
    # a compile_error!: on any ISA outside the set K it names, the file does
    # not compile. It covers a chain only if that chain handles every ISA in
    # K, or a K member would silently lose the chain's code.
    guards = []
    for ch in chains:
        if any(_marker_above(text, x.start) for x in ch):
            for x in ch:
                x.covered, x.why = True, "arch-only: marker on the chain"
            continue
        else_like = any("neg" in arch_polarity(x.pred) for x in ch)
        has_ce = any("compile_error!" in s[x.end:x.item_end] for x in ch)
        for x in ch:
            if "neg" in arch_polarity(x.pred) and "compile_error!" in s[x.end:x.item_end]:
                guards.append(arch_names(x.pred))
        for x in ch:
            if "neg" in arch_polarity(x.pred):
                x.covered, x.why = True, "is an else branch"
            elif else_like:
                x.covered, x.why = True, "chain has an else branch"
            elif has_ce:
                x.covered, x.why = True, "chain has compile_error!"

    for st in sites:
        if st.covered:
            continue
        # An explicit, reviewed decision that the guarded code has no
        # counterpart on other ISAs: `// arch-only: <why>` above it.
        if _marker_above(text, st.start):
            st.covered, st.why = True, "arch-only: marker"
            continue
        if st.kind == "cfg_attr":
            st.covered, st.why = True, "cfg_attr (exempt)"
        elif st.kind == "inner" and "neg" in arch_polarity(st.pred):
            st.covered, st.why = True, "is an else branch"
        elif st.kind == "expr":
            if "neg" in arch_polarity(st.pred) or s[:st.start].rstrip().endswith("!"):
                st.covered, st.why = True, "is an else branch"
                continue
            back = max(s.rfind(";", 0, st.start), s.rfind("{", 0, st.start), s.rfind("}", 0, st.start))
            head = s[back + 1:st.start]
            if not re.search(r"\bif\b", head):
                st.covered, st.why = True, "cfg! used as a value"
                continue
            ob = s.find("{", st.end)
            if ob < 0:
                continue
            cb = match_close(s, ob)
            rest = s[cb:cb + 40].lstrip()
            if rest.startswith("else"):
                st.covered, st.why = True, "if cfg! has an else"
    if guards:
        for ch in chains:
            handled = set()
            for x in ch:
                handled |= arch_names(x.pred)
            if any(k <= handled for k in guards):
                for x in ch:
                    if not x.covered:
                        x.covered, x.why = True, "file-level compile_error! guard"
        for st in sites:
            if not st.covered and st.kind != "attr" and any(k <= arch_names(st.pred) for k in guards):
                st.covered, st.why = True, "file-level compile_error! guard"
    return sites


def scan_text(text):
    s = strip_rust(text)
    return classify(s, find_sites(s, text), text)


def isa_owned(rel):
    """A file that only ever builds for one ISA (`kernel/src/entry/<isa>*`,
    `.../<isa>_*.rs`): it is that port's own code, so a `target_arch` guard
    in it has nothing to vanish from. Exempt from the lint, still counted by
    tools/arch_coupling.py."""
    parts = rel.split("/")
    return any(p in ISAS or p in tuple(i + ".rs" for i in ISAS) or
               p.startswith(tuple(i + "_" for i in ISAS)) for p in parts)


def iter_files(root=REPO):
    for top in SCAN_ROOTS:
        base = os.path.join(root, top)
        for dp, dns, fns in os.walk(base):
            dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
            for fn in sorted(fns):
                if not fn.endswith(".rs"):
                    continue
                path = os.path.join(dp, fn)
                rel = os.path.relpath(path, root)
                if rel.startswith(ARCH_CRATES):
                    continue
                yield rel, path


def violations(root=REPO):
    """{relpath: [Site, ...]} of uncovered sites."""
    out = {}
    for rel, path in iter_files(root):
        if isa_owned(rel):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        if "target_arch" not in text:
            continue
        bad = [x for x in scan_text(text) if not x.covered]
        if bad:
            out[rel] = bad
    return out


def expand_use(s, i):
    """Paths named right after `azos_arch::` at index i (handles `{}` groups)."""
    m = re.match(r"\s*\{", s[i:])
    if m:
        ob = i + m.end() - 1
        cb = match_close(s, ob)
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
    if not m:
        return []
    head = re.sub(r"\s+", "", m.group(1))
    g = re.match(r"\s*::\s*\{", s[i + m.end():])
    if g:  # `azos_arch::irq::{plic, gic}`
        return [head + "::" + sub for sub in expand_use(s, i + m.end() + g.end() - 1)]
    return [head]


# ── facade bypass: references to ISA-specific arch modules ──────────────────

def pub_mods(path):
    """Names declared `pub mod X;` in one Rust file ([] when it is missing)."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        s = strip_rust(f.read())
    return re.findall(r"^\s*pub\s+mod\s+(\w+)\s*;", s, re.M)


def arch_modules(root=REPO):
    """(specific, chips): the arch modules absent from at least one ISA crate,
    and the interrupt-controller modules under `irq` (all ISA-specific).
    Read from the crates' lib.rs / irq module by name, so a file move inside a
    crate changes nothing."""
    per_isa, chips = [], set()
    for isa in ISAS:
        src = os.path.join(root, "crates", "core", "arch-" + isa, "src")
        mods = set(pub_mods(os.path.join(src, "lib.rs")))
        if not mods:
            raise ValueError(f"no `pub mod` in crates/core/arch-{isa}/src/lib.rs: "
                             "the facade lint cannot tell which modules are ISA-specific")
        per_isa.append(mods)
        for irq in (os.path.join(src, "irq", "mod.rs"), os.path.join(src, "irq.rs")):
            chips.update(pub_mods(irq))
    return set.union(*per_isa) - set.intersection(*per_isa), chips


def facade_refs(text, specific, chips):
    """[(line, name)] facade references in one file: `name` is the module, or
    `irq::<chip>` / `ext::<sub>` (see the module docstring for what counts)."""
    s = strip_rust(text)
    refs, alias, irq_alias = [], set(), False
    for m in re.finditer(r"\bazos_arch::", s):
        line = line_of(s, m.start())
        for p in expand_use(s, m.end()):
            segs = p.split("::")
            if len(segs) > 1 and segs[-1] == "self":  # `use azos_arch::irq::{self, ..}`
                segs.pop()
            if segs[0] == "irq" and len(segs) == 1:
                irq_alias = True
            elif segs[0] in ("irq", "ext") and len(segs) > 1:
                # `ext` is declared on every ISA (the same layout) yet holds
                # only ISA-specific extension modules, so it always counts.
                if segs[0] == "ext" or segs[1] in chips:
                    refs.append((line, f"{segs[0]}::{segs[1]}"))
                    if len(segs) == 2:
                        alias.add(segs[1])
            elif segs[0] in specific:
                refs.append((line, segs[0]))
                if len(segs) == 1:
                    alias.add(segs[0])
    for a in sorted(alias):
        for m in re.finditer(rf"(?<![\w:]){a}::", s):
            refs.append((line_of(s, m.start()), a))
    if irq_alias and chips:
        for m in re.finditer(r"(?<![\w:])irq::(%s)\b" % "|".join(sorted(chips)), s):
            refs.append((line_of(s, m.start()), "irq::" + m.group(1)))
    return sorted(refs)


def facade(root=REPO):
    """{relpath: [(line, name), ...]} facade references outside the arch crates
    and the ports' entry code."""
    specific, chips = arch_modules(root)
    out = {}
    for rel, path in iter_files(root):
        if rel.startswith(ENTRY_DIR):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        if "azos_arch::" not in text:
            continue
        refs = facade_refs(text, specific, chips)
        if refs:
            out[rel] = refs
    return out


SECTIONS = ("cfg", "facade")


def read_baselines(path):
    """{section: {relpath: count}}. Lines before the first `[section]` header
    are the `cfg` section (the file's original, header-less part)."""
    out = {s: {} for s in SECTIONS}
    sec = "cfg"
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                sec = line.strip("[]")
                if sec not in out or line != f"[{sec}]":
                    raise ValueError(f"{path}:{ln}: unknown section {line!r}")
                continue
            parts = line.split("\t")
            if len(parts) != 2 or not parts[0].isdigit():
                raise ValueError(f"{path}:{ln}: malformed line {line!r} (want COUNT<TAB>PATH)")
            out[sec][parts[1]] = int(parts[0])
    return out


def load_baselines():
    return read_baselines(BASELINE) if os.path.exists(BASELINE) else {s: {} for s in SECTIONS}


def write_baselines(path, base):
    """Write {section: {relpath: count}}; `cfg` first and header-less."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n")
        f.write("# SPDX-FileCopyrightText: 2026 Fernando Rodriguez\n")
        f.write("# tools/arch_cfg_lint.py ratchet: uncovered cfg(target_arch) sites per file.\n")
        f.write("# Counts may only go down. Regenerate with --update-baseline.\n")
        for rel, n in sorted(base["cfg"].items()):
            f.write(f"{n}\t{rel}\n")
        f.write("[facade]\n")
        f.write("# Facade bypass: azos_arch::<ISA-specific module> references per file.\n")
        f.write("# Counts may only go down. Rewrite with --update (a rename raises them).\n")
        for rel, n in sorted(base["facade"].items()):
            f.write(f"{n}\t{rel}\n")


def check_counts(counts, base, what):
    """(errors, shrinkable) lists of strings for per-file `counts`
    ({relpath: [item, ...]}) against `base` ({relpath: allowed}); `what` names
    the thing counted. Items are objects with `.line` or (line, name) tuples."""
    def line(x):
        return x.line if hasattr(x, "line") else x[0]
    errors, shrink = [], []
    for rel, items in sorted(counts.items()):
        allowed = base.get(rel, 0)
        if len(items) > allowed:
            lines = ", ".join(str(line(x)) for x in items)
            errors.append(f"{rel}: {len(items)} {what} (baseline {allowed}); lines {lines}")
    for rel, cnt in sorted(base.items()):
        now = len(counts.get(rel, []))
        if now < cnt:
            shrink.append(f"{rel}: {cnt} -> {now}")
    return errors, shrink


def check(viol, base):
    return check_counts(viol, base, "uncovered target_arch cfg")


def check_facade(refs, base):
    return check_counts(refs, base, "facade references (azos_arch::<ISA-specific module>)")


def self_test():
    """Canaries on fixtures: each property must bite, and the fixed form pass."""
    pair = ('#[cfg(target_arch = "riscv64")]\nfn f() { fence_rv(); }\n'
            '#[cfg(target_arch = "aarch64")]\nfn f() { fence_arm(); }\n')
    cases = [
        # (name, source, expected uncovered count)
        ("pair without else vanishes", pair, 2),
        ("pair + not(any) else", pair + '#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]\nfn f() { compile_error!("port"); }\n', 0),
        ("pair + compile_error member", pair + '#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]\ncompile_error!("port");\n', 0),
        ("file-level guard covers distant pair",
         '#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]\ncompile_error!("port");\nuse x;\n' + pair, 0),
        ("file guard naming a 3rd ISA does not cover a 2-ISA pair",
         '#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]\ncompile_error!("port");\nuse x;\n' + pair, 2),
        ("statement guard", 'fn g() {\n    #[cfg(target_arch = "riscv64")]\n    unsafe { fence() };\n    work();\n}\n', 1),
        ("not() alone is else", '#[cfg(not(target_arch = "riscv64"))]\nfn h() {}\n', 0),
        ("feature-only not() is still positive", '#[cfg(all(target_arch = "aarch64", not(feature = "x")))]\nfn h() {}\n', 1),
        ("fn signature commas",
         '#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]\ncompile_error!("port");\n'
         '#[cfg(target_arch = "riscv64")]\nfn a() -> Result<(), i32> { Err(1) }\n'
         '#[cfg(target_arch = "aarch64")]\nfn a() -> Result<(), i32> { Err(2) }\n'
         '#[cfg(target_arch = "x86_64")]\nfn a() -> Result<(), i32> { Err(3) }\n', 0),
        ("turbofish commas", 'fn b() {\n    #[cfg(target_arch = "riscv64")]\n    f::<A, B>(x);\n    #[cfg(not(target_arch = "riscv64"))]\n    f::<C, D>(x);\n}\n', 0),
        ("if cfg! without else", 'fn k() { if cfg!(target_arch = "riscv64") { fence(); } work(); }\n', 1),
        ("if cfg! with else", 'fn k() { if cfg!(target_arch = "riscv64") { fence(); } else { other(); } }\n', 0),
        ("if !cfg! is the else", 'fn k() { if !cfg!(target_arch = "riscv64") { return; } fence(); }\n', 0),
        ("cfg! as value", 'const A: bool = cfg!(target_arch = "riscv64");\n', 0),
        ("arch-only marker", '// arch-only: a riscv64 diagnostic\n#[cfg(target_arch = "riscv64")]\nfn m() {}\n', 0),
        ("marker needs a reason", '// arch-only:\n#[cfg(target_arch = "riscv64")]\nfn m() {}\n', 1),
        ("cfg_attr exempt", '#[cfg_attr(target_arch = "riscv64", inline)]\nfn m() {}\n', 0),
        ("comment ignored", '// #[cfg(target_arch = "riscv64")]\nfn n() {}\n', 0),
        ("inner attr", '#![cfg(target_arch = "riscv64")]\nfn p() {}\n', 1),
    ]
    fails = 0
    for name, src, want in cases:
        got = sum(1 for x in scan_text(src) if not x.covered)
        ok = got == want
        fails += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: uncovered {got}, want {want}")
    # ratchet buckets on a temp tree
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "crates", "x", "src"))
        f = os.path.join(td, "crates", "x", "src", "lib.rs")
        bl = os.path.join(td, "baseline")
        with open(f, "w") as h:
            h.write(pair)
        write_baselines(bl, {"cfg": {r: len(v) for r, v in violations(td).items()}, "facade": {}})
        base = lambda: read_baselines(bl)["cfg"]  # noqa: E731
        e, _ = check(violations(td), base())
        r1 = not e
        with open(f, "a") as h:
            h.write('#[cfg(target_arch = "riscv64")]\nfn q() {}\n')
        e, _ = check(violations(td), base())
        r2 = bool(e)
        with open(f, "w") as h:
            h.write(pair + '#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]\ncompile_error!("port");\n')
        e, sh = check(violations(td), base())
        r3 = not e and bool(sh)
        with open(bl, "a") as h:
            h.write("garbage line\n")
        try:
            read_baselines(bl)
            r4 = False
        except ValueError:
            r4 = True
    for name, ok in (("ratchet: baseline as recorded passes", r1),
                     ("ratchet: a NEW violation fails", r2),
                     ("ratchet: a FIXED violation passes and is reported", r3),
                     ("ratchet: malformed baseline is an error, not a pass", r4)):
        fails += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    return fails + facade_self_test()


def facade_self_test():
    """Canaries for the facade-bypass ratchet, on a built arch tree."""
    fails = 0

    def put(root, rel, text):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as h:
            h.write(text)

    def report(name, ok):
        nonlocal fails
        fails += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")

    def build_arch(root, rv_mods="cpu csr sbi cbo irq ext"):
        for isa, mods in (("riscv64", rv_mods), ("aarch64", "cpu sysregs cbo irq ext"), ("x86_64", "cpu hw irq ext")):
            put(root, f"crates/core/arch-{isa}/src/lib.rs", "".join(f"pub mod {m};\n" for m in mods.split()))
        put(root, "crates/core/arch-riscv64/src/irq/mod.rs", "pub mod plic;\npub mod clint;\n")
        put(root, "crates/core/arch-aarch64/src/irq.rs", "pub mod gic;\n")
        put(root, "crates/core/arch-x86_64/src/irq/mod.rs", "pub mod apic;\n")

    spec, chips = {"csr", "sbi", "sysregs", "cbo", "hw"}, {"plic", "gic", "apic", "clint"}
    cases = [
        # (name, source, expected reference count)
        ("path to an ISA-only module", "fn f() { azos_arch::csr::read(); }\n", 1),
        ("module on 2 of 3 ISAs counts", "fn f() { azos_arch::cbo::flush(); }\n", 1),
        ("module on all 3 ISAs does not", "fn f() { azos_arch::cpu::id(); azos_arch::ARCH.x(); }\n", 0),
        ("irq itself does not, irq::<chip> does", "fn f() { azos_arch::irq::enable(); azos_arch::irq::gic::eoir1(); }\n", 1),
        ("use group counts one per leaf", "use azos_arch::{csr, sbi::call, cpu, irq::{plic, gic}};\n", 4),
        ("imported module: import + each use", "use azos_arch::csr;\nfn f() { csr::read(); csr::write(); }\n", 3),
        ("imported irq: each chip use", "use azos_arch::irq;\nfn f() { irq::plic::x(); irq::enable(); }\n", 1),
        ("ext is on every ISA but always counts", "fn f() { azos_arch::ext::csr::read(); azos_arch::ext::rvv::x(); azos_arch::ext(); }\n", 2),
        ("imported chip: import + each use", "use azos_arch::irq::gic;\nfn f() { gic::eoir1(); }\n", 2),
        ("imported ext module: import + each use", "use azos_arch::ext::csr;\nfn f() { csr::read(); }\n", 2),
        ("self leaf is the module itself", "use azos_arch::irq::gic::{self, Gic};\nfn f() { gic::eoir1(); }\n", 3),
        ("group after a path: one per leaf", "use azos_arch::irq::{plic, gic};\nfn f() { plic::x(); }\n", 3),
        ("group after a path, module imported", "use azos_arch::ext::{csr, rvv};\nfn f() { rvv::x(); }\n", 3),
        ("local path with the same name is not a use", "use azos_arch::csr;\nfn f() { crate::csr::read(); x::csr::y(); }\n", 1),
        ("comment and string ignored", '// azos_arch::csr::read()\nfn f() { let _ = "azos_arch::csr::x"; }\n', 0),
        ("azos_arch_api is not the facade", "fn f() { azos_arch_api::csr::read(); }\n", 0),
    ]
    for name, src, want in cases:
        got = len(facade_refs(src, spec, chips))
        report(f"{name}: {got}, want {want}", got == want)
    with tempfile.TemporaryDirectory() as td:
        build_arch(td)
        got = arch_modules(td)
        report("arch_modules: absent-from-one-ISA modules and irq chips",
               got == ({"csr", "sbi", "sysregs", "cbo", "hw"}, {"plic", "clint", "gic", "apic"}))
        put(td, "kernel/src/a.rs", "fn f() { azos_arch::csr::read(); }\n")
        put(td, "kernel/src/entry/riscv64.rs", "fn f() { azos_arch::csr::read(); azos_arch::sbi::x(); }\n")
        put(td, "crates/core/arch-riscv64/src/trap.rs", "fn f() { azos_arch::csr::read(); }\n")
        bl = os.path.join(td, "baseline")
        write_baselines(bl, {"cfg": {}, "facade": {r: len(v) for r, v in facade(td).items()}})
        report("scope: arch crates and kernel/src/entry/ are not counted",
               list(facade(td)) == ["kernel/src/a.rs"])
        base = lambda: read_baselines(bl)["facade"]  # noqa: E731
        e, _ = check_facade(facade(td), base())
        report("facade ratchet: baseline as recorded passes", not e)
        put(td, "kernel/src/a.rs", "fn f() { azos_arch::csr::read(); azos_arch::csr::write(); }\n")
        e, _ = check_facade(facade(td), base())
        report("facade ratchet: +1 reference in a file fails", len(e) == 1)
        put(td, "kernel/src/a.rs", "fn f() { azos_arch::csr::read(); }\n")
        put(td, "kernel/src/b.rs", "fn f() { azos_arch::sbi::call(); }\n")
        e, _ = check_facade(facade(td), base())
        report("facade ratchet: a new file fails", len(e) == 1 and "b.rs" in e[0])
        put(td, "kernel/src/b.rs", "fn f() {}\n")
        put(td, "kernel/src/a.rs", "fn f() {}\n")
        e, sh = check_facade(facade(td), base())
        report("facade ratchet: a FIXED file passes and is reported", not e and bool(sh))
        put(td, "kernel/src/a.rs", "fn f() { azos_arch::csr::read(); azos_arch::csr::write(); }\n")
        write_baselines(bl, {"cfg": {}, "facade": {r: len(v) for r, v in facade(td).items()}})
        e, _ = check_facade(facade(td), base())
        report("facade --update: rewriting the baseline accepts +1", not e)
        # a renamed module is picked up by name, a file move changes nothing
        put(td, "crates/core/arch-riscv64/src/lib.rs", "pub mod cpu;\npub mod cbo;\npub mod irq;\npub mod csr2;\n")
        put(td, "kernel/src/c.rs", "fn f() { azos_arch::csr2::read(); }\n")
        e, _ = check_facade(facade(td), base())
        report("facade ratchet: a module new to the arch crate is counted", len(e) == 1 and "c.rs" in e[0])
        put(td, "crates/core/arch-riscv64/src/lib.rs", "// no modules\n")
        try:
            facade(td)
            report("facade: an arch crate with no modules is an error", False)
        except ValueError:
            report("facade: an arch crate with no modules is an error", True)
        with open(bl, "a") as h:
            h.write("[bogus]\n")
        try:
            read_baselines(bl)
            report("facade: unknown baseline section is an error", False)
        except ValueError:
            report("facade: unknown baseline section is an error", True)
    return fails


def arg_path(argv, flag):
    i = argv.index(flag)
    return argv[i + 1] if len(argv) > i + 1 and not argv[i + 1].startswith("--") else ""


def main(argv):
    if "--self-test" in argv:
        n = self_test()
        print("self-test:", "FAIL" if n else "ok")
        return 1 if n else 0
    try:
        base = load_baselines()
        refs = facade()
    except ValueError as e:
        print(f"arch_cfg_lint: {e}")
        return 2
    viol = violations()
    total = sum(len(v) for v in viol.values())
    nrefs = sum(len(v) for v in refs.values())
    if "--list" in argv:
        only = arg_path(argv, "--list")
        for rel, sites in sorted(viol.items()):
            if only and not rel.startswith(only):
                continue
            for x in sites:
                print(f"{rel}:{x.line}: {x.kind}")
        print(f"total uncovered: {total} in {len(viol)} files")
        return 0
    if "--list-facade" in argv:
        only = arg_path(argv, "--list-facade")
        for rel, rs in sorted(refs.items()):
            if only and not rel.startswith(only):
                continue
            for line, name in rs:
                print(f"{rel}:{line}: {name}")
        print(f"total facade references: {nrefs} in {len(refs)} files")
        return 0
    errors, shrink = check(viol, base["cfg"])
    if "--facade" in argv:
        errors, shrink = [], []
    ferrors, fshrink = check_facade(refs, base["facade"])
    if "--update-baseline" in argv:
        if errors and "--force" not in argv:
            print("refusing to raise the baseline:")
            for e in errors:
                print("  " + e)
            return 1
        base["cfg"] = {rel: len(v) for rel, v in viol.items()}
        write_baselines(BASELINE, base)
        print(f"baseline written: {total} uncovered sites in {len(viol)} files")
        return 0
    if "--update" in argv:
        for line in ferrors:
            print("raised: " + line.split(";")[0])
        for line in fshrink:
            print("lowered: " + line)
        base["facade"] = {rel: len(v) for rel, v in refs.items()}
        write_baselines(BASELINE, base)
        print(f"facade baseline written: {nrefs} references in {len(refs)} files")
        return 0
    if errors:
        for e in errors:
            print(e)
        print("each target_arch cfg in shared code needs an else branch "
              "(cfg(not(...))) or a compile_error! for any other ISA; see tools/arch_cfg_lint.py")
    if ferrors:
        for e in ferrors:
            print(e)
        print("shared code reaches the ISA through the arch-api traits and azos_arch::ARCH, "
              "not through an ISA-specific module (csr, sbi, sysregs, irq::<chip>, ...); "
              "after an arch-crate rename run tools/arch_cfg_lint.py --update")
    if errors or ferrors:
        return 1
    print((f"arch_cfg_lint: {total} uncovered (baseline {sum(base['cfg'].values())}); "
           if "--facade" not in argv else "arch_cfg_lint: ")
          + f"{nrefs} facade references (baseline {sum(base['facade'].values())})"
          + (f"; {len(shrink)} cfg files below baseline, run --update-baseline" if shrink else "")
          + (f"; {len(fshrink)} facade files below baseline, run --update" if fshrink else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Unsafe budget: how much `unsafe` each crate carries, and a gate that stops it growing.

The count is per crate (the directory of the nearest Cargo.toml above a .rs
file), over every .rs file except tests (a `tests/` directory, an item or
module under `#[cfg(test)]` or `#[test]`, a file behind `#[cfg(test)] mod x;`,
a file with `#![cfg(test)]`), `target/` and `third_party/`. Comments, strings
and char literals are skipped by a small lexer, so `// unsafe {` and "unsafe"
do not count. Four columns:

  blocks   `unsafe { .. }` and `unsafe extern "C" { .. }`
  fns      `unsafe fn name` and `unsafe extern "C" fn name` (definitions; a
           function-pointer TYPE `unsafe fn(..)` is not unsafe code)
  impls    `unsafe impl` and `unsafe trait`
  attrs    `#[unsafe(no_mangle)]`, `#[unsafe(link_section = ..)]`, ...

The count is of source text: a macro body counts once, where it is written,
and every `#[cfg(..)]` arm counts, so a per-ISA function is one per ISA.

tools/lint/unsafe_budget.tsv is the checked-in baseline: `crate<TAB>blocks<TAB>fns<TAB>
impls<TAB>attrs`, one line per crate with at least one, sorted. The gate
compares the tree against it. A crate whose total is above its baseline (or a
new crate with any) FAILS: the change grew the unsafe budget, and the commit
must say so by updating the baseline (`--update`), which puts the growth in
the diff for the reviewer. Any other difference (fewer, or the same total
split differently) fails too until the baseline is updated: it is a ratchet,
so a removed `unsafe` cannot silently come back. The per-release number is
the `--report` total at the release commit.

  unsafe_budget.py              check the tree against the baseline (the gate row)
  unsafe_budget.py --update     rewrite the baseline from the tree
  unsafe_budget.py --report     per-crate table and total
  unsafe_budget.py --self-test  the tool's own canaries, on fixtures
"""
import bisect
import json
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = azos_tools.ROOT
BASELINE = "tools/lint/unsafe_budget.tsv"
FIELDS = ("blocks", "fns", "impls", "attrs")
# Directory names never walked, anywhere.
PRUNE = {"target", "tests", "third_party"}
# Source trees that are a crate's modules without being a crate: the files
# overlaid on relibc (userspace/lib/relibc-azos) are compiled inside upstream's
# Cargo package, so they have no Cargo.toml of their own. Each counts as a crate.
EXTRA_CRATES = ("userspace/lib/relibc-azos/overlay",)

_IDENT_START = re.compile(r"[A-Za-z_]")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def lex(src, pos=None):
    """Rust source -> list of tokens; comments and literals are reduced to
    ('str', '') / ('chr', '') so only code remains. Identifiers are ('id', text),
    everything else a one-character ('p', c). With a `pos` list, the source
    offset each token starts at is appended to it."""
    toks = []
    i, n = 0, len(src)
    while i < n:
        start, before = i, len(toks)
        c = src[i]
        if c.isspace():
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif c == '"' or (c in "bcr" and _string_start(src, i)):
            i = _skip_string(src, i)
            toks.append(("str", ""))
        elif c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                j = src.find("'", i + 2)
                i = n if j < 0 else j + 1
                toks.append(("chr", ""))
            elif i + 2 < n and src[i + 2] == "'":
                i += 3
                toks.append(("chr", ""))
            else:  # a lifetime or a label
                m = _IDENT.match(src, i + 1)
                i = m.end() if m else i + 1
        elif _IDENT_START.match(c):
            m = _IDENT.match(src, i)
            word = m.group()
            i = m.end()
            if word == "r" and src.startswith("#", i) and _IDENT_START.match(src[i + 1:i + 2] or " "):
                m = _IDENT.match(src, i + 1)  # r#ident: a raw identifier
                word, i = m.group(), m.end()
            toks.append(("id", word))
        elif c.isdigit():
            while i < n and (src[i].isalnum() or src[i] == "_"):
                i += 1
        else:
            toks.append(("p", c))
            i += 1
        if pos is not None and len(toks) > before:
            pos.append(start)
    return toks


def _string_start(src, i):
    """True when src[i] (one of b, c, r) opens a string literal prefix."""
    j = i
    if src[j] in "bc":
        j += 1
    if j < len(src) and src[j] == "r":
        j += 1
        while j < len(src) and src[j] == "#":
            j += 1
    return j < len(src) and src[j] == '"' and j > i


def _skip_string(src, i):
    """Index past the string literal whose prefix (b, c, r, br, cr, r#..) starts at i."""
    n = len(src)
    raw = False
    hashes = 0
    while src[i] != '"':
        if src[i] == "r":
            raw = True
        elif src[i] == "#":
            hashes += 1
        i += 1
    i += 1
    if raw:
        end = '"' + "#" * hashes
        k = src.find(end, i)
        return n if k < 0 else k + len(end)
    while i < n:
        if src[i] == "\\":
            i += 2
        elif src[i] == '"':
            return i + 1
        else:
            i += 1
    return n


def _match(toks, i, open_c, close_c):
    """Index just past the group opened at toks[i] == open_c."""
    depth = 0
    while i < len(toks):
        t = toks[i]
        if t == ("p", open_c):
            depth += 1
        elif t == ("p", close_c):
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def _skip_item(toks, i, test_mods):
    """toks[i] starts an item (after its attributes): return the index past it.
    A `mod name;` is recorded in test_mods (its file is a test file)."""
    if (i + 2 < len(toks) and toks[i][1] == "mod" and toks[i + 1][0] == "id"
            and toks[i + 2] == ("p", ";")):
        test_mods.add(toks[i + 1][1])
    depth = 0
    while i < len(toks):
        t = toks[i]
        if t[0] == "p":
            if t[1] in "([":
                depth += 1
            elif t[1] in ")]":
                depth -= 1
            elif t[1] == ";" and depth == 0:
                return i + 1
            elif t[1] == "{" and depth == 0:
                return _match(toks, i, "{", "}")
        i += 1
    return i


def _is_test_attr(body):
    """body: the attribute's tokens as text, no spaces (`cfg(test)`, `test`)."""
    return body in ("test", "cfg(test)") or body.startswith("cfg(all(test,")


def count(src):
    """-> (counts dict, set of `#[cfg(test)] mod x;` names, whole-file-is-test flag,
    code lines). Code lines are the source lines on which a token outside a test
    item starts: blank lines, comments and tests do not count."""
    pos = []
    toks = lex(src, pos)
    c = dict.fromkeys(FIELDS, 0)
    test_mods = set()
    skipped = []  # [from, to) token ranges of test items
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t == ("p", "#"):
            j = i + 1
            inner = j < n and toks[j] == ("p", "!")
            if inner:
                j += 1
            if j < n and toks[j] == ("p", "["):
                end = _match(toks, j, "[", "]")
                body = "".join(x[1] for x in toks[j + 1:end - 1])
                if _is_test_attr(body):
                    if inner:
                        return c, test_mods, True, 0
                    # the attributes that follow belong to the same item
                    first, i = i, end
                    while i + 1 < n and toks[i] == ("p", "#") and toks[i + 1] == ("p", "["):
                        i = _match(toks, i + 1, "[", "]")
                    i = _skip_item(toks, i, test_mods)
                    skipped.append((first, i))
                    continue
                if body.startswith("unsafe("):
                    c["attrs"] += 1
                i = end
                continue
        if t == ("id", "unsafe"):
            a = toks[i + 1] if i + 1 < n else ("", "")
            b = toks[i + 2] if i + 2 < n else ("", "")
            d = toks[i + 3] if i + 3 < n else ("", "")
            if a == ("p", "{"):
                c["blocks"] += 1
            elif a == ("id", "fn"):
                if b[0] == "id":  # a definition, not `unsafe fn(..)`
                    c["fns"] += 1
            elif a in (("id", "impl"), ("id", "trait")):
                c["impls"] += 1
            elif a == ("id", "extern"):
                abi = 2 if b[0] == "str" else 1
                nxt = toks[i + 1 + abi] if i + 1 + abi < n else ("", "")
                after = toks[i + 2 + abi] if i + 2 + abi < n else ("", "")
                if nxt == ("p", "{"):
                    c["blocks"] += 1
                elif nxt == ("id", "fn") and after[0] == "id":
                    c["fns"] += 1
        i += 1
    return c, test_mods, False, _code_lines(src, pos, skipped)


def _code_lines(src, pos, skipped):
    """Distinct source lines that start a token outside the `skipped` ranges."""
    nl = [m.start() for m in re.finditer("\n", src)]
    lines, k = set(), 0
    for a, b in skipped + [(len(pos), len(pos))]:
        lines.update(bisect.bisect_left(nl, pos[t]) for t in range(k, a))
        k = b
    return len(lines)


def crate_of(root, path):
    """Repository-relative directory of the nearest Cargo.toml above `path` (or
    of an `EXTRA_CRATES` tree)."""
    d = os.path.dirname(path)
    while True:
        if os.path.isfile(os.path.join(root, d, "Cargo.toml")) or d in EXTRA_CRATES:
            return d or "."
        if not d:
            return "(none)"
        d = os.path.dirname(d)


def tracked_rs(root):
    """Sorted repository-relative .rs paths from `git ls-files`: only tracked files
    count, so an untracked scratch file (scratch/moved/*.rs) cannot move
    the number. PRUNE directories and dot-directories are still skipped."""
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z", "--cached", "--", "*.rs"],
                             check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise SystemExit(f"unsafe_budget: git ls-files failed in {root}: {e}")
    files = []
    for rel in sorted(out.decode("utf-8", "replace").split("\0")):
        if not rel.endswith(".rs") or not os.path.isfile(os.path.join(root, rel)):
            continue
        dirs = rel.split("/")[:-1]
        if any(d in PRUNE or d.startswith(".") for d in dirs):
            continue
        files.append(os.path.normpath(rel))
    return files


def scan(root, kernel=None):
    """-> {crate: row} for the whole tree. A row holds the FIELDS counts, `lines`
    (code lines, see count()), `unsafe_lines` (the code lines of the files with
    at least one unsafe), `forbid` (every crate root carries
    `#![forbid(unsafe_code)]`) and `kernel` (the crate is linked into a kernel
    image, kernel_crates(); `kernel` overrides that set). Crates with no
    unsafe, no forbid and outside the kernel are dropped."""
    if kernel is None:
        kernel = kernel_crates(root)
    files = tracked_rs(root)
    per_file, excluded = {}, set()
    for rel in files:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as f:
            counts, test_mods, test_file, lines = count(f.read())
        per_file[rel] = counts, lines
        if test_file:
            excluded.add(rel)
        d, base = os.path.dirname(rel), os.path.basename(rel)
        # `mod x;` lives at d/x.rs or d/x/mod.rs; from a non-mod-rs file
        # d/base.rs it lives under d/base/.
        home = d if base in ("mod.rs", "lib.rs", "main.rs") else os.path.join(d, base[:-3])
        for m in test_mods:
            excluded.add(os.path.join(home, m + ".rs"))
            excluded.add(os.path.join(home, m, "mod.rs"))
    out = {}
    for rel, (counts, lines) in per_file.items():
        if rel in excluded or _under_excluded_mod(rel, excluded):
            continue
        cr = out.setdefault(crate_of(root, rel), dict.fromkeys(FIELDS + ("lines", "unsafe_lines"), 0))
        for k in FIELDS:
            cr[k] += counts[k]
        cr["lines"] += lines
        if sum(counts.values()):
            cr["unsafe_lines"] += lines
    for name, cr in out.items():
        cr["forbid"] = forbids_unsafe(root, name)
        cr["kernel"] = name in kernel
    return {k: v for k, v in sorted(out.items()) if _total(v) or v["forbid"] or v["kernel"]}


def _total(row):
    return sum(row[k] for k in FIELDS)


def _under_excluded_mod(rel, excluded):
    """A submodule of an excluded `x/mod.rs` or `x.rs` (its files live under x/)."""
    d = os.path.dirname(rel)
    while d:
        if d + ".rs" in excluded or os.path.join(d, "mod.rs") in excluded:
            return True
        d = os.path.dirname(d)
    return False


def crate_roots(root, crate):
    """Repository-relative root files (library and binaries) of the crate whose
    Cargo.toml is in `crate`: the `path`s of its `[lib]` and `[[bin]]` tables,
    plus cargo's own defaults that exist (src/lib.rs when `[lib]` names no
    path, src/main.rs and src/bin/*.rs unless `autobins = false`)."""
    toml = os.path.join(root, crate, "Cargo.toml")
    if not os.path.isfile(toml):
        return []
    paths, section, lib_path, autobins = [], None, False, True
    with open(toml, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            m = re.match(r"^\[\[?\s*([A-Za-z0-9_.-]+)\s*\]\]?", line)
            if m:
                section = m.group(1)
                continue
            m = re.match(r'^path\s*=\s*"([^"]+)"', line)
            if m and section in ("lib", "bin"):
                paths.append(m.group(1))
                lib_path |= section == "lib"
            if section == "package" and re.match(r"^autobins\s*=\s*false\b", line):
                autobins = False
    if not lib_path:
        paths.append("src/lib.rs")
    if autobins:
        paths.append("src/main.rs")
        bindir = os.path.join(root, crate, "src", "bin")
        if os.path.isdir(bindir):
            paths += ["src/bin/" + b for b in os.listdir(bindir) if b.endswith(".rs")]
    roots = {os.path.normpath(os.path.join(crate, p)) for p in paths}
    return sorted(r for r in roots if os.path.isfile(os.path.join(root, r)))


def has_forbid(src):
    """The source carries the inner attribute `#![forbid(.., unsafe_code, ..)]`."""
    toks = lex(src)
    for i in range(len(toks) - 2):
        if toks[i] == ("p", "#") and toks[i + 1] == ("p", "!") and toks[i + 2] == ("p", "["):
            body = toks[i + 3:_match(toks, i + 2, "[", "]") - 1]
            if body[:2] == [("id", "forbid"), ("p", "(")] and ("id", "unsafe_code") in body:
                return True
    return False


def forbids_unsafe(root, crate):
    """Every root of the crate forbids unsafe code (a crate with no root does not)."""
    roots = crate_roots(root, crate)
    for r in roots:
        with open(os.path.join(root, r), encoding="utf-8", errors="replace") as f:
            if not has_forbid(f.read()):
                return False
    return bool(roots)


# The kernel images: (manifest, package). Every crate linked into one of them
# is kernel code; the rest of the tree (ring-3 programs and libraries, host
# tools and tests, proc macros) is counted but not in the kernel share.
KERNEL_ROOTS = (("Cargo.toml", "azos_kernel"), ("micro/Cargo.toml", "azos_micro"))


def kernel_crates(root):
    """Repository-relative directories of the crates linked into a kernel image:
    the path packages reachable from KERNEL_ROOTS through normal dependencies
    (not build or dev ones; a proc macro runs on the build host, so neither it
    nor what it uses counts), with every feature on and for every target, as
    `cargo metadata --offline` resolves them."""
    real = os.path.realpath(root)
    out = set()
    for manifest, name in KERNEL_ROOTS:
        cmd = ["cargo", "metadata", "--offline", "--format-version", "1", "--all-features",
               "--manifest-path", os.path.join(root, manifest)]
        try:
            meta = json.loads(subprocess.run(cmd, check=True, capture_output=True).stdout)
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            raise SystemExit(f"unsafe_budget: {' '.join(cmd)} failed: {e}")
        pk = {p["id"]: p for p in meta["packages"]}
        deps = {n["id"]: [d["pkg"] for d in n["deps"] if any(k["kind"] is None for k in d["dep_kinds"])]
                for n in meta["resolve"]["nodes"]}
        todo = [i for i, p in pk.items() if p["name"] == name]
        if not todo:
            raise SystemExit(f"unsafe_budget: no package {name} in {manifest}")
        seen = set()
        while todo:
            i = todo.pop()
            if i in seen or any("proc-macro" in t["kind"] for t in pk[i]["targets"]):
                continue
            seen.add(i)
            todo += deps.get(i, [])
        for i in seen:
            p = pk[i]
            rel = os.path.relpath(os.path.dirname(os.path.realpath(p["manifest_path"])), real)
            if p["source"] is None and not rel.startswith("..") \
                    and not any(d in PRUNE for d in rel.split(os.sep)):
                out.add(os.path.normpath(rel))
    return out


def ratio(part, whole, scale):
    """part/whole in 1/scale units, rounded half up (0 when whole is 0)."""
    return (scale * part + whole // 2) // whole if whole else 0


def totals(cur):
    """-> {total: per mille} over the kernel crates' code lines: `unsafe-share`,
    the lines of files with unsafe; `allowed-share`, the lines of crates that
    do not forbid unsafe code (the share Asterinas reports for its framekernel)."""
    k = [v for v in cur.values() if v["kernel"]]
    lines = sum(v["lines"] for v in k)
    return {"unsafe-share": ratio(sum(v["unsafe_lines"] for v in k), lines, 1000),
            "allowed-share": ratio(sum(v["lines"] for v in k if not v["forbid"]), lines, 1000)}


def share(row):
    """A kernel crate's unsafe share, in percent; None outside the kernel."""
    return ratio(row["unsafe_lines"], row["lines"], 100) if row["kernel"] else None


COLS = FIELDS + ("forbid", "share")
# The totals the baseline ratchets. The allowed share is reported, not
# ratcheted: it rises with every line added to a crate that may use unsafe,
# so the ratchet on it is the allowed SET (a lost forbid, a new kernel crate
# without one), checked per crate.
TOTALS = ("unsafe-share",)


def read_baseline(path):
    """-> (rows, totals): rows {crate: {FIELDS..., forbid: 0|1, share: int|None}},
    totals {name: per mille}."""
    base, tot = {}, {}
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if cols[0].startswith("@"):
                if len(cols) != 2 or cols[0][1:] not in TOTALS or not cols[1].isdigit():
                    raise SystemExit(f"{path}:{no}: want @<{'|'.join(TOTALS)}><TAB>per-mille, got {line!r}")
                tot[cols[0][1:]] = int(cols[1])
                continue
            if (len(cols) != 1 + len(COLS) or not all(c.isdigit() for c in cols[1:-1])
                    or cols[-2] not in ("0", "1") or not (cols[-1].isdigit() or cols[-1] == "-")):
                raise SystemExit(f"{path}:{no}: want crate<TAB>{'<TAB>'.join(COLS)}, got {line!r}")
            if cols[0] in base:
                raise SystemExit(f"{path}:{no}: duplicate crate {cols[0]}")
            row = dict(zip(COLS, map(int, cols[1:-1])))
            row["share"] = None if cols[-1] == "-" else int(cols[-1])
            base[cols[0]] = row
    return base, tot


HEADER = (
    "# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"
    "# SPDX-FileCopyrightText: 2026 Fernando Rodriguez\n"
    "# Unsafe budget baseline (tools/lint/unsafe_budget.py): unsafe blocks, fns, impls and\n"
    "# attributes per crate, tests excluded; forbid = every crate root carries\n"
    "# #![forbid(unsafe_code)]; share = for a kernel crate, the percent of its code\n"
    "# lines that are in files with unsafe (- outside the kernel). @unsafe-share:\n"
    "# the same over all kernel crates, per mille. Counts, forbid and the kernel set\n"
    "# must equal the tree; a count that grew, a lost forbid, a kernel crate that\n"
    "# joins without one, or a share above its line fails. Update in\n"
    "# the same commit (python3 tools/lint/unsafe_budget.py --update); a growth needs\n"
    "# its reason in the commit message.\n"
    "# crate\t" + "\t".join(COLS) + "\n"
)


def write_baseline(path, cur):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(HEADER)
        for cr, v in cur.items():
            s = share(v)
            f.write(cr + "\t" + "\t".join(str(v[k]) for k in FIELDS) + "\t%d\t%s\n"
                    % (v["forbid"], "-" if s is None else s))
        t = totals(cur)
        for k in TOTALS:
            f.write(f"@{k}\t{t[k]}\n")


def compare(base, cur, base_tot=None):
    """-> (grew, stale, notes): messages. grew = what the ratchet forbids (a crate
    above its baseline total, a lost forbid, a forbid over counted unsafe, a
    share above its baseline); stale = any other difference in counts, forbid
    or the kernel set; notes = shares below the baseline (they pass; --update
    locks them in)."""
    grew, stale, notes = [], [], []
    zero = dict.fromkeys(FIELDS, 0)
    for cr in sorted(set(base) | set(cur)):
        b, c = base.get(cr), cur.get(cr)
        bc = {k: b[k] for k in FIELDS} if b else zero
        cc = {k: c[k] for k in FIELDS} if c else zero
        if bc != cc:
            bt, ct = sum(bc.values()), sum(cc.values())
            delta = " ".join(f"{k} {bc[k]}->{cc[k]}" for k in FIELDS if bc[k] != cc[k])
            (grew if ct > bt else stale).append(f"{cr}: total {bt} -> {ct} ({delta})")
        bf, cf = bool(b and b["forbid"]), bool(c and c["forbid"])
        if bf and not cf:
            grew.append(f"{cr}: lost #![forbid(unsafe_code)]")
        elif cf and not bf:
            stale.append(f"{cr}: now forbids unsafe code")
        if cf and sum(cc.values()):
            grew.append(f"{cr}: forbids unsafe code but carries {sum(cc.values())}")
        bs, cs = b["share"] if b else None, share(c) if c else None
        if bs is None and cs is not None:
            (stale if cf else grew).append(f"{cr}: now a kernel crate" + ("" if cf else ", without #![forbid(unsafe_code)]"))
        elif bs is not None and cs is None:
            stale.append(f"{cr}: no longer a kernel crate")
        elif cs is not None and cs > bs:
            grew.append(f"{cr}: unsafe share {bs}% -> {cs}%")
        elif cs is not None and cs < bs:
            notes.append(f"{cr}: unsafe share {bs}% -> {cs}%")
    if base_tot is not None:
        t = totals(cur)
        for k in TOTALS:
            v = t[k]
            if k not in base_tot:
                stale.append(f"@{k}: missing")
            elif v > base_tot[k]:
                grew.append(f"kernel {k}: {base_tot[k] / 10:.1f}% -> {v / 10:.1f}%")
            elif v < base_tot[k]:
                notes.append(f"kernel {k}: {base_tot[k] / 10:.1f}% -> {v / 10:.1f}%")
    return grew, stale, notes


def check(root, kernel=None):
    path = os.path.join(root, BASELINE)
    if not os.path.isfile(path):
        print(f"FAIL: {BASELINE} is missing (python3 tools/lint/unsafe_budget.py --update)")
        return 1
    base, base_tot = read_baseline(path)
    cur = scan(root, kernel)
    grew, stale, notes = compare(base, cur, base_tot)
    for m in grew:
        print("FAIL (unsafe budget grew): " + m)
    for m in stale:
        print("FAIL (baseline stale): " + m)
    for m in notes:
        print("note (below the baseline; --update locks it in): " + m)
    if grew or stale:
        print("update the baseline in the same commit: python3 tools/lint/unsafe_budget.py --update")
        return 1
    t = totals(cur)
    print(f"unsafe budget ok: {sum(_total(v) for v in cur.values())} in "
          f"{sum(1 for v in cur.values() if _total(v))} crates, "
          f"{sum(1 for v in cur.values() if v['forbid'])} forbid unsafe; kernel unsafe share "
          f"{t['unsafe-share'] / 10:.1f}%, allowed {t['allowed-share'] / 10:.1f}%")
    return 0


def report(root, kernel=None):
    cur = scan(root, kernel)
    print("%-44s %6s %4s %5s %5s %6s  %7s %7s %5s %s" % (
        ("crate",) + FIELDS + ("total", "lines", "unsafeL", "share", "")))
    tot = dict.fromkeys(FIELDS, 0)
    for cr, v in sorted(cur.items(), key=lambda kv: (-_total(kv[1]), kv[0])):
        s = share(v)
        print("%-44s %6d %4d %5d %5d %6d  %7d %7d %5s %s" % (
            (cr,) + tuple(v[k] for k in FIELDS) + (_total(v), v["lines"], v["unsafe_lines"],
                                                    "-" if s is None else f"{s}%",
                                                    "forbid" if v["forbid"] else "")))
        for k in FIELDS:
            tot[k] += v[k]
    print("%-44s %6d %4d %5d %5d %6d" % (("TOTAL",) + tuple(tot[k] for k in FIELDS) + (sum(tot.values()),)))
    k = [v for v in cur.values() if v["kernel"]]
    t = totals(cur)
    print(f"kernel: {len(k)} crates, {sum(v['lines'] for v in k)} code lines; "
          f"{sum(v['unsafe_lines'] for v in k)} in files with unsafe ({t['unsafe-share'] / 10:.1f}%), "
          f"{sum(v['lines'] for v in k if not v['forbid'])} in crates allowed unsafe "
          f"({t['allowed-share'] / 10:.1f}%); {sum(1 for v in k if v['forbid'])} crates forbid it")
    return 0


# ---- self-test -------------------------------------------------------------

def _put(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)


def self_test():
    fails = []

    def eq(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    def tot(src):
        return tuple(count(src)[0][k] for k in FIELDS)

    # the lexer: only code counts
    eq("code", tot("fn f() { unsafe { g() } }"), (1, 0, 0, 0))
    eq("comments", tot("// unsafe { x }\n/* unsafe { /* nested unsafe { */ } */ fn f() {}"), (0, 0, 0, 0))
    eq("doc comment", tot("/// unsafe impl Send for X {}\nfn f() {}"), (0, 0, 0, 0))
    eq("strings", tot('let a = "unsafe { } \\" unsafe {"; let b = r#"unsafe { "x" }"#; let c = b"unsafe {";'),
       (0, 0, 0, 0))
    eq("char vs lifetime", tot("fn f<'a>(x: &'a u8) -> char { let c = '\"'; let d = '\\''; unsafe { g() } }"),
       (1, 0, 0, 0))
    eq("lifetime then unsafe", tot("impl<'a> X<'a> { unsafe fn f(&self) {} }"), (0, 1, 0, 0))
    eq("identifier", tot("let unsafe_code = 1; #![forbid(unsafe_code)]"), (0, 0, 0, 0))
    # each kind
    eq("fn", tot("pub unsafe fn f() {} const unsafe fn g() {}"), (0, 2, 0, 0))
    eq("extern fn", tot('pub unsafe extern "C" fn f() {} unsafe extern fn g() {}'), (0, 2, 0, 0))
    eq("extern block", tot('unsafe extern "C" { fn f(); }'), (1, 0, 0, 0))
    eq("fn pointer type", tot('type A = unsafe fn(u8); type B = unsafe extern "C" fn(u8);'), (0, 0, 0, 0))
    eq("impl and trait", tot("unsafe impl Send for X {} pub unsafe trait T {}"), (0, 0, 2, 0))
    eq("attrs", tot('#[unsafe(no_mangle)] pub extern "C" fn f() {} #[unsafe(link_section = ".x")] static S: u8 = 0;'),
       (0, 0, 0, 2))
    # tests are excluded
    eq("cfg(test) mod", tot("fn f() { unsafe { a() } }\n#[cfg(test)]\nmod tests { fn t() { unsafe { b() } } }\n"),
       (1, 0, 0, 0))
    eq("cfg(test) item + attrs", tot("#[cfg(test)]\n#[allow(dead_code)]\nunsafe fn f() { unsafe { x() } }\nunsafe fn g() {}"),
       (0, 1, 0, 0))
    eq("#[test]", tot("#[test]\nfn t() { unsafe { x() } }\nfn r() { unsafe { y() } }"), (1, 0, 0, 0))
    eq("cfg(not(test)) counts", tot("#[cfg(not(test))]\nfn f() { unsafe { x() } }"), (1, 0, 0, 0))
    eq("cfg(all(test, ..))", tot("#[cfg(all(test, feature = \"x\"))]\nmod m { unsafe fn f() {} }"), (0, 0, 0, 0))
    eq("cfg(test) use group", tot("#[cfg(test)]\nuse a::{b, c};\nfn f() { unsafe { x() } }"), (1, 0, 0, 0))
    eq("inner cfg(test)", count("#![cfg(test)]\nunsafe fn f() {}")[2], True)
    eq("cfg(test) mod decl", sorted(count("#[cfg(test)]\nmod tests;\nmod real;")[1]), ["tests"])
    # code lines: blank, comment and test lines do not count
    eq("code lines", count("fn f() {\n\n    // c\n    unsafe { g() }\n}\n/* a\nb */\n#[cfg(test)]\nmod t {\n    fn x() {}\n}\n"
                           "#[test]\nfn y() {}\nfn z() {}\n")[3], 4)
    eq("string interior lines", count('const S: &str = "a\n\nb\nc";\n')[3], 2)
    # the forbid attribute
    eq("forbid", has_forbid("//! doc\n#![no_std]\n#![forbid(unsafe_code)]\n"), True)
    eq("forbid in a list", has_forbid("#![forbid(missing_docs, unsafe_code)]"), True)
    eq("deny is not forbid", has_forbid("#![deny(unsafe_code)]"), False)
    eq("commented forbid", has_forbid("// #![forbid(unsafe_code)]\n"), False)
    eq("outer forbid", has_forbid("#[forbid(unsafe_code)]\nfn f() {}"), False)

    # the tree walk: crates, exclusions
    with tempfile.TemporaryDirectory() as root:
        _put(root, "a/Cargo.toml", "")
        _put(root, "a/src/lib.rs", "pub fn f() { unsafe { g() } }\n#[cfg(test)]\nmod tests;\nmod ok;\n#[cfg(test)]\nmod helper;\n")
        _put(root, "a/src/ok.rs", "pub unsafe fn h() {}\n")
        _put(root, "a/src/safe.rs", "pub fn s() {}\n")
        _put(root, "a/src/tests.rs", "fn t() { unsafe { x() } }\n")
        _put(root, "a/src/helper/mod.rs", "mod deep;\nfn t() { unsafe { x() } }\n")
        _put(root, "a/src/helper/deep.rs", "fn t() { unsafe { x() } }\n")
        _put(root, "a/tests/it.rs", "fn t() { unsafe { x() } }\n")
        _put(root, "a/target/gen.rs", "fn t() { unsafe { x() } }\n")
        _put(root, "a/inner/Cargo.toml", "")
        _put(root, "a/inner/src/lib.rs", "unsafe impl Send for X {}\nunsafe impl Sync for X {}\n")
        _put(root, "third_party/z/Cargo.toml", "")
        _put(root, "third_party/z/lib.rs", "unsafe fn z() {}\n")
        _put(root, "tests/host/t/Cargo.toml", "")
        _put(root, "tests/host/t/src/lib.rs", "unsafe fn z() {}\n")
        _put(root, "b/Cargo.toml", "")
        _put(root, "b/src/lib.rs", "#![forbid(unsafe_code)]\nfn f() {}\n")
        # roots from Cargo.toml: a [lib] path, a [[bin]] path, src/main.rs
        _put(root, "c/Cargo.toml", '[package]\nname = "c"\n[lib]\npath = "x.rs"\n[[bin]]\nname = "t"\npath = "tool/t.rs"\n')
        _put(root, "c/x.rs", "#![forbid(unsafe_code)]\n")
        _put(root, "c/tool/t.rs", "#![forbid(unsafe_code)]\nfn main() {}\n")
        _put(root, "c/src/main.rs", "fn main() {}\n")
        _put(root, "s/Cargo.toml", "")
        _put(root, "s/src/lib.rs", "fn f() {}\n")
        _put(root, EXTRA_CRATES[0] + "/src/m.rs", "unsafe fn o() {}\n")
        subprocess.run(["git", "-C", root, "init", "-q"], check=True)
        subprocess.run(["git", "-C", root, "add", "-A"], check=True)
        # canary: an untracked .rs file must not count (before the git-only scan
        # it was walked and counted); a dot-directory one is tracked but pruned.
        _put(root, "a/src/untracked.rs", "unsafe fn u() {}\nfn v() { unsafe { w() } }\n")
        _put(root, "scratch/moved/x.rs", "unsafe impl Send for Q {}\n")
        kernel = {"a", "b"}
        cur = scan(root, kernel)
        eq("scan", {k: tuple(v[f] for f in FIELDS) for k, v in cur.items()},
           {"a": (1, 1, 0, 0), "a/inner": (0, 0, 2, 0), "b": (0, 0, 0, 0), EXTRA_CRATES[0]: (0, 1, 0, 0)})
        eq("lines", {k: (v["lines"], v["unsafe_lines"]) for k, v in cur.items() if v["kernel"]},
           {"a": (4, 3), "b": (2, 0)})
        eq("forbid", sorted(k for k, v in cur.items() if v["forbid"]), ["b"])
        eq("roots", crate_roots(root, "c"), ["c/src/main.rs", "c/tool/t.rs", "c/x.rs"])
        eq("one root without forbid", forbids_unsafe(root, "c"), False)
        _put(root, "c/src/main.rs", "#![forbid(unsafe_code)]\nfn main() {}\n")
        eq("every root forbids", forbids_unsafe(root, "c"), True)
        eq("no root, no forbid", forbids_unsafe(root, EXTRA_CRATES[0]), False)
        eq("share", share(cur["a"]), 75)
        eq("totals", totals(cur), {"unsafe-share": 500, "allowed-share": 667})

        # the gate: equal passes, growth and drift fail, --update repairs
        def run(argv):
            old = sys.argv, sys.stdout
            sys.argv, sys.stdout = ["unsafe_budget.py"] + argv, open(os.devnull, "w")
            try:
                return main(root, kernel)
            finally:
                sys.stdout.close()
                sys.argv, sys.stdout = old

        def diff():
            base, tot = read_baseline(os.path.join(root, BASELINE))
            return compare(base, scan(root, kernel), tot)
        eq("missing baseline fails", run([]), 1)
        eq("update", run(["--update"]), 0)
        eq("equal passes", run([]), 0)
        _put(root, "a/src/ok.rs", "pub unsafe fn h() {}\npub unsafe fn h2() {}\n")
        eq("growth fails", run([]), 1)
        eq("growth message", "a: total 2 -> 3 (fns 1->2)" in diff()[0], True)
        run(["--update"])
        eq("updated passes", run([]), 0)
        # canary: a crate that loses #![forbid(unsafe_code)] fails, and so does
        # the kernel's allowed share it raises
        _put(root, "b/src/lib.rs", "#![deny(unsafe_code)]\nfn f() {}\n")
        eq("lost forbid fails", run([]), 1)
        eq("lost forbid message", diff()[0], ["b: lost #![forbid(unsafe_code)]"])
        _put(root, "b/src/lib.rs", "#![forbid(unsafe_code)]\nfn f() { unsafe { x() } }\n")
        eq("forbid over unsafe fails", "b: forbids unsafe code but carries 1" in diff()[0], True)
        _put(root, "b/src/lib.rs", "#![forbid(unsafe_code)]\nfn f() {}\n")
        eq("restored passes", run([]), 0)
        # canary: more lines in a file with unsafe, no new unsafe: the share
        # grows and fails; more lines elsewhere lower it and pass
        _put(root, "a/src/ok.rs", "pub unsafe fn h() {}\npub unsafe fn h2() {}\nfn p() {}\nfn q() {}\n")
        eq("share growth fails", run([]), 1)
        eq("share growth message", diff()[0][0], "a: unsafe share 80% -> 86%")
        run(["--update"])
        _put(root, "a/src/safe.rs", "pub fn s() {}\nfn t() {}\nfn u() {}\n")
        eq("share drop passes", run([]), 0)
        eq("share drop is a note", diff()[2][0], "a: unsafe share 86% -> 67%")
        kernel.add("s")
        eq("new kernel crate without forbid fails", diff()[0], ["s: now a kernel crate, without #![forbid(unsafe_code)]"])
        run(["--update"])
        kernel.add("c")
        eq("new kernel crate with forbid is stale", diff()[:2], ([], ["c: now a kernel crate"]))
        run(["--update"])
        _put(root, "s/src/lib.rs", "fn f() { unsafe { x() } }\n")
        eq("new unsafe fails", run([]), 1)
        run(["--update"])
        _put(root, "s/src/lib.rs", "fn f() {}\n")
        eq("shrink is stale", run([]), 1)
        eq("shrink is not growth", diff()[0], [])
        run(["--update"])
        _put(root, "a/src/ok.rs", "pub fn h() { unsafe { x() } }\npub unsafe fn h2() {}\nfn p() {}\nfn q() {}\n")
        eq("same total, split differently, is stale", run([]), 1)
        for bad in ("a\tx\n", "a\t1\t0\t0\t0\t2\t-\n", "@unsafe-share\tx\n", "@other\t1\n"):
            _put(root, BASELINE, bad)
            try:
                read_baseline(os.path.join(root, BASELINE))
                fails.append(f"malformed baseline accepted: {bad!r}")
            except SystemExit:
                pass
    if fails:
        print("unsafe_budget self-test FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("unsafe_budget self-test ok")
    return 0


def main(root=ROOT, kernel=None):
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if args == ["--update"]:
        write_baseline(os.path.join(root, BASELINE), scan(root, kernel))
        return 0
    if args == ["--report"]:
        return report(root, kernel)
    if args:
        print(__doc__)
        return 2
    return check(root, kernel)


if __name__ == "__main__":
    sys.exit(main())

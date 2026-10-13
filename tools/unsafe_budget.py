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

tools/unsafe_budget.tsv is the checked-in baseline: `crate<TAB>blocks<TAB>fns<TAB>
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
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join("tools", "unsafe_budget.tsv")
FIELDS = ("blocks", "fns", "impls", "attrs")
# Directory names never walked, anywhere.
PRUNE = {"target", "tests", "third_party"}
# Directories never walked at the repository root (build outputs).
PRUNE_ROOT = {"build"}
# Source trees that are a crate's modules without being a crate: the files
# overlaid on relibc (userspace/lib/relibc-azos) are compiled inside upstream's
# Cargo package, so they have no Cargo.toml of their own. Each counts as a crate.
EXTRA_CRATES = ("userspace/lib/relibc-azos/overlay",)

_IDENT_START = re.compile(r"[A-Za-z_]")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def lex(src):
    """Rust source -> list of tokens; comments and literals are reduced to
    ('str', '') / ('chr', '') so only code remains. Identifiers are ('id', text),
    everything else a one-character ('p', c)."""
    toks = []
    i, n = 0, len(src)
    while i < n:
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
    """-> (counts dict, set of `#[cfg(test)] mod x;` names, whole-file-is-test flag)."""
    toks = lex(src)
    c = dict.fromkeys(FIELDS, 0)
    test_mods = set()
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
                        return c, test_mods, True
                    # the attributes that follow belong to the same item
                    i = end
                    while i + 1 < n and toks[i] == ("p", "#") and toks[i + 1] == ("p", "["):
                        i = _match(toks, i + 1, "[", "]")
                    i = _skip_item(toks, i, test_mods)
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
    return c, test_mods, False


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


def scan(root):
    """-> {crate: {field: n}} for the whole tree (crates with a zero total are dropped)."""
    files = []
    for dp, dns, fns in os.walk(root):
        rel = os.path.relpath(dp, root)
        dns[:] = sorted(d for d in dns if d not in PRUNE and not d.startswith(".")
                        and not (rel == "." and d in PRUNE_ROOT))
        files += [os.path.normpath(os.path.join(rel, f)) for f in sorted(fns) if f.endswith(".rs")]
    per_file, excluded = {}, set()
    for rel in files:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as f:
            counts, test_mods, test_file = count(f.read())
        per_file[rel] = counts
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
    for rel, counts in per_file.items():
        if rel in excluded or _under_excluded_mod(rel, excluded):
            continue
        cr = out.setdefault(crate_of(root, rel), dict.fromkeys(FIELDS, 0))
        for k in FIELDS:
            cr[k] += counts[k]
    return {k: v for k, v in sorted(out.items()) if sum(v.values())}


def _under_excluded_mod(rel, excluded):
    """A submodule of an excluded `x/mod.rs` or `x.rs` (its files live under x/)."""
    d = os.path.dirname(rel)
    while d:
        if d + ".rs" in excluded or os.path.join(d, "mod.rs") in excluded:
            return True
        d = os.path.dirname(d)
    return False


def read_baseline(path):
    base = {}
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) != 1 + len(FIELDS) or not all(c.isdigit() for c in cols[1:]):
                raise SystemExit(f"{path}:{no}: want crate<TAB>{'<TAB>'.join(FIELDS)}, got {line!r}")
            if cols[0] in base:
                raise SystemExit(f"{path}:{no}: duplicate crate {cols[0]}")
            base[cols[0]] = dict(zip(FIELDS, map(int, cols[1:])))
    return base


HEADER = (
    "# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"
    "# SPDX-FileCopyrightText: 2026 Fernando Rodriguez\n"
    "# Unsafe budget baseline (tools/unsafe_budget.py): unsafe blocks, fns, impls and\n"
    "# attributes per crate, tests excluded. The gate fails when the tree differs from\n"
    "# this file: a crate that grew needs a reviewed bump in the same commit\n"
    "# (python3 tools/unsafe_budget.py --update), one that shrank lowers it.\n"
    "# crate\t" + "\t".join(FIELDS) + "\n"
)


def write_baseline(path, counts):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(HEADER)
        for cr, v in counts.items():
            f.write(cr + "\t" + "\t".join(str(v[k]) for k in FIELDS) + "\n")


def compare(base, cur):
    """-> (grew, stale): messages. grew = a crate above its baseline total."""
    grew, stale = [], []
    for cr in sorted(set(base) | set(cur)):
        b = base.get(cr, dict.fromkeys(FIELDS, 0))
        c = cur.get(cr, dict.fromkeys(FIELDS, 0))
        if b == c:
            continue
        bt, ct = sum(b.values()), sum(c.values())
        delta = " ".join(f"{k} {b[k]}->{c[k]}" for k in FIELDS if b[k] != c[k])
        (grew if ct > bt else stale).append(f"{cr}: total {bt} -> {ct} ({delta})")
    return grew, stale


def check(root):
    path = os.path.join(root, BASELINE)
    if not os.path.isfile(path):
        print(f"FAIL: {BASELINE} is missing (python3 tools/unsafe_budget.py --update)")
        return 1
    grew, stale = compare(read_baseline(path), scan(root))
    for m in grew:
        print("FAIL (unsafe grew beyond the baseline): " + m)
    for m in stale:
        print("FAIL (baseline stale): " + m)
    if grew or stale:
        print("update the baseline in the same commit: python3 tools/unsafe_budget.py --update")
        return 1
    print(f"unsafe budget ok: {sum(sum(v.values()) for v in read_baseline(path).values())} in "
          f"{len(read_baseline(path))} crates")
    return 0


def report(root):
    cur = scan(root)
    print("%-48s %7s %5s %6s %6s %6s" % (("crate",) + FIELDS + ("total",)))
    tot = dict.fromkeys(FIELDS, 0)
    for cr, v in sorted(cur.items(), key=lambda kv: (-sum(kv[1].values()), kv[0])):
        print("%-48s %7d %5d %6d %6d %6d" % ((cr,) + tuple(v[k] for k in FIELDS) + (sum(v.values()),)))
        for k in FIELDS:
            tot[k] += v[k]
    print("%-48s %7d %5d %6d %6d %6d" % (("TOTAL",) + tuple(tot[k] for k in FIELDS) + (sum(tot.values()),)))
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

    # the tree walk: crates, exclusions
    with tempfile.TemporaryDirectory() as root:
        _put(root, "a/Cargo.toml", "")
        _put(root, "a/src/lib.rs", "pub fn f() { unsafe { g() } }\n#[cfg(test)]\nmod tests;\nmod ok;\n#[cfg(test)]\nmod helper;\n")
        _put(root, "a/src/ok.rs", "pub unsafe fn h() {}\n")
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
        _put(root, "build/gen.rs", "unsafe fn z() {}\n")
        _put(root, "b/Cargo.toml", "")
        _put(root, "b/src/lib.rs", "#![forbid(unsafe_code)]\nfn f() {}\n")
        _put(root, EXTRA_CRATES[0] + "/src/m.rs", "unsafe fn o() {}\n")
        cur = scan(root)
        eq("scan", cur, {"a": {"blocks": 1, "fns": 1, "impls": 0, "attrs": 0},
                         "a/inner": {"blocks": 0, "fns": 0, "impls": 2, "attrs": 0},
                         EXTRA_CRATES[0]: {"blocks": 0, "fns": 1, "impls": 0, "attrs": 0}})

        # the gate: equal passes, growth and drift fail, --update repairs
        def run(argv):
            old = sys.argv, sys.stdout
            sys.argv, sys.stdout = ["unsafe_budget.py"] + argv, open(os.devnull, "w")
            try:
                return main(root)
            finally:
                sys.stdout.close()
                sys.argv, sys.stdout = old
        eq("missing baseline fails", run([]), 1)
        eq("update", run(["--update"]), 0)
        eq("equal passes", run([]), 0)
        _put(root, "a/src/ok.rs", "pub unsafe fn h() {}\npub unsafe fn h2() {}\n")
        eq("growth fails", run([]), 1)
        eq("growth message", [m for m in compare(read_baseline(os.path.join(root, BASELINE)), scan(root))[0]],
           ["a: total 2 -> 3 (fns 1->2)"])
        run(["--update"])
        eq("updated passes", run([]), 0)
        _put(root, "b/src/lib.rs", "fn f() { unsafe { x() } }\n")
        eq("new crate fails", run([]), 1)
        run(["--update"])
        _put(root, "b/src/lib.rs", "fn f() {}\n")
        eq("shrink is stale", run([]), 1)
        eq("shrink is not growth", compare(read_baseline(os.path.join(root, BASELINE)), scan(root))[0], [])
        run(["--update"])
        _put(root, "a/src/ok.rs", "pub fn h() { unsafe { x() } }\npub unsafe fn h2() {}\n")
        eq("same total, split differently, is stale", run([]), 1)
        _put(root, BASELINE, "a\tx\n")
        try:
            read_baseline(os.path.join(root, BASELINE))
            fails.append("malformed baseline accepted")
        except SystemExit:
            pass
    if fails:
        print("unsafe_budget self-test FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("unsafe_budget self-test ok")
    return 0


def main(root=ROOT):
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if args == ["--update"]:
        write_baseline(os.path.join(root, BASELINE), scan(root))
        return 0
    if args == ["--report"]:
        return report(root)
    if args:
        print(__doc__)
        return 2
    return check(root)


if __name__ == "__main__":
    sys.exit(main())

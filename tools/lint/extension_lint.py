#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""An extension is what its Kconfig symbol, its manifest and its install say.

The contract is crates/core/ext-api (`Manifest`); an extension is installed by
`azos_actuation::providers::install`. For every `EXT_<NAME>` symbol of
config/extensions/Kconfig:

  - exactly one `Manifest` static (`name:` its first field) is named
    `<name>`, the symbol lowercased, and it lives under crates/domains/<name>/;
  - exactly one `providers::install(&<that static>)` registers it;
  - a `Manifest` static no symbol names, or an install of a static that is no
    manifest, is an error.

And the base does not name an extension: no crate under crates/core and no
file under kernel/src names a crate of crates/domains, except from an item
`#[cfg(...)]`-gated on `use-robot` (or on a kernel feature that implies it),
and a crates/core or kernel Cargo.toml lists such a crate only as an optional
dependency its `use-robot` feature turns on.

  python3 tools/lint/extension_lint.py               check (n0)
  python3 tools/lint/extension_lint.py --self-test   a tree with each violation
"""

import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = azos_tools.ROOT
GATE = "use-robot"
MANIFEST = re.compile(
    r"\bstatic\s+(\w+)\s*:\s*(?:azos_ext_api::)?Manifest\s*=\s*(?:azos_ext_api::)?Manifest\s*\{\s*name\s*:\s*\"([^\"]*)\"")
INSTALL = re.compile(r"\bproviders::install\(\s*&\s*(?:\w+::)*(\w+)\s*\)")


def rust_files(root, *trees):
    for tree in trees:
        for d, subdirs, names in os.walk(os.path.join(root, tree)):
            subdirs[:] = sorted(s for s in subdirs if s not in ("target", ".git"))
            for n in sorted(names):
                if n.endswith(".rs"):
                    yield os.path.join(d, n)


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def tokens(src):
    """(kind, text, line): attributes whole, identifiers, and { } ( ) [ ] ; , only.
    Comments, strings and chars are skipped."""
    out, i, n, line = [], 0, len(src), 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
        elif src.startswith("/*", i):
            depth = 0
            while i < n:
                if src.startswith("/*", i):
                    depth += 1
                    i += 2
                elif src.startswith("*/", i):
                    depth -= 1
                    i += 2
                    if depth == 0:
                        break
                else:
                    line += src[i] == "\n"
                    i += 1
        elif c == '"' or (c == "r" and re.match(r'r#*"', src[i:i + 8])) or (c == "b" and src.startswith('b"', i)):
            m = re.match(r'(?:b?r(#*)")', src[i:i + 12])
            if m:
                end = '"' + m.group(1)
                j = src.find(end, i + m.end())
                j = n if j < 0 else j + len(end)
            else:
                j = i + (2 if c == "b" else 1)
                while j < n and src[j] != '"':
                    j += 2 if src[j] == "\\" else 1
                j += 1
            line += src.count("\n", i, j)
            i = j
        elif c == "'":
            m = re.match(r"'(?:\\.[^']*|[^\\'])'", src[i:i + 12])
            i += m.end() if m else 1
        elif c == "#" and re.match(r"#!?\[", src[i:i + 3]):
            j = src.index("[", i)
            depth, k = 0, j
            while k < n:
                if src[k] == '"':
                    k += 1
                    while k < n and src[k] != '"':
                        k += 2 if src[k] == "\\" else 1
                elif src[k] == "[":
                    depth += 1
                elif src[k] == "]":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            out.append(("attr", src[i:k + 1], line))
            line += src.count("\n", i, k + 1)
            i = k + 1
        elif c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(("id", src[i:j], line))
            i = j
        else:
            if c in "{}()[];,":
                out.append(("p", c, line))
            i += 1
    return out


def cfg_implies(expr, implied):
    """Does the `cfg` expression hold only where a feature of `implied` is on?"""
    expr = expr.strip()
    m = re.match(r"(all|any|not)\s*\((.*)\)$", expr, re.S)
    if m:
        args, depth, cur = [], 0, ""
        for ch in m.group(2) + ",":
            if ch == "," and depth == 0:
                if cur.strip():
                    args.append(cur)
                cur = ""
                continue
            depth += ch == "("
            depth -= ch == ")"
            cur += ch
        if m.group(1) == "all":
            return any(cfg_implies(a, implied) for a in args)
        if m.group(1) == "any":
            return bool(args) and all(cfg_implies(a, implied) for a in args)
        return False
    m = re.match(r'feature\s*=\s*"([^"]*)"$', expr)
    return bool(m) and m.group(1) in implied


def attr_implies(attr, implied):
    m = re.match(r"#!?\[\s*cfg\s*\((.*)\)\s*\]$", attr, re.S)
    return bool(m) and cfg_implies(m.group(1), implied)


def features(cargo_text):
    """{feature: [items]} of a Cargo.toml's [features] table."""
    m = re.search(r"^\[features\]\s*$(.*?)(?=^\[|\Z)", cargo_text, re.S | re.M)
    out = {}
    if not m:
        return out
    for fm in re.finditer(r"^([\w-]+)\s*=\s*\[(.*?)\]", m.group(1), re.S | re.M):
        body = re.sub(r"#[^\n]*", "", fm.group(2))
        out[fm.group(1)] = re.findall(r'"([^"]*)"', body)
    return out


def implied_features(cargo_path):
    """`use-robot` and every feature of the crate that turns it on."""
    feats = features(read(cargo_path)) if os.path.exists(cargo_path) else {}
    implied = {GATE}
    changed = True
    while changed:
        changed = False
        for f, items in feats.items():
            if f not in implied and any(i in implied for i in items):
                implied.add(f)
                changed = True
    return implied


def domain_crates(root):
    """{package name: directory} of crates/domains."""
    out = {}
    for d, subdirs, names in os.walk(os.path.join(root, "crates", "domains")):
        subdirs[:] = [s for s in subdirs if s not in ("target", ".git")]
        if "Cargo.toml" in names:
            m = re.search(r'^name\s*=\s*"([^"]+)"', read(os.path.join(d, "Cargo.toml")), re.M)
            if m:
                out[m.group(1)] = d
    return out


def crate_roots(root):
    """(crate root file, Cargo.toml) of the kernel and of every crates/core crate."""
    out = []
    kernel = os.path.join(root, "kernel")
    if os.path.exists(os.path.join(kernel, "src", "main.rs")):
        out.append((os.path.join(kernel, "src", "main.rs"), os.path.join(kernel, "Cargo.toml")))
    core = os.path.join(root, "crates", "core")
    for name in sorted(os.listdir(core)) if os.path.isdir(core) else []:
        for f in ("lib.rs", "main.rs"):
            p = os.path.join(core, name, "src", f)
            if os.path.exists(p):
                out.append((p, os.path.join(core, name, "Cargo.toml")))
                break
    return out


def local_aliases(toks, implied):
    """Names a file binds to its own stand-in when the gate is off
    (`#[cfg(not(feature = "use-robot"))] use crate::no_robot::robot as azos_robot;`)."""
    out, off = set(), False
    for idx, (kind, text, _) in enumerate(toks):
        if kind == "attr":
            m = re.match(r"#\[\s*cfg\s*\(\s*not\s*\((.*)\)\s*\)\s*\]$", text, re.S)
            off = bool(m) and cfg_implies(m.group(1), implied)
        elif text == ";":
            off = False
        elif off and text == "as" and idx + 1 < len(toks):
            out.add(toks[idx + 1][1])
    return out


def scan_file(path, names, implied, file_gated, root, seen, hits):
    """Names of `names` outside a gated item, in `path` and the modules it declares."""
    if path in seen or not os.path.exists(path):
        return
    seen.add(path)
    stack, pending = [], False  # an open bracket: (gated inside, `pending` to restore at its close)
    attrs = []
    toks = tokens(read(path))
    file_gated = file_gated or any(k == "attr" and t.startswith("#!") and attr_implies(t, implied) for k, t, _ in toks)
    names = names - local_aliases(toks, implied)
    stem = os.path.splitext(os.path.basename(path))[0]
    base = os.path.dirname(path) if stem in ("main", "lib", "mod") else os.path.join(os.path.dirname(path), stem)
    for idx, (kind, text, line) in enumerate(toks):
        gated = file_gated or pending or any(g for g, _ in stack)
        if kind == "attr":
            if not text.startswith("#!"):
                attrs.append(text)
                pending = pending or attr_implies(text, implied)
        elif kind == "id":
            if text in names and not gated:
                hits.append((os.path.relpath(path, root), line, text))
            if (text == "mod" and idx + 2 < len(toks) and toks[idx + 1][0] == "id" and toks[idx + 2][1] == ";"):
                child = toks[idx + 1][1]
                given = [re.search(r'path\s*=\s*"([^"]*)"', a) for a in attrs]
                given = [g.group(1) for g in given if g]
                cands = [os.path.join(os.path.dirname(path), given[0])] if given else [
                    os.path.join(base, child + ".rs"), os.path.join(base, child, "mod.rs")]
                for c in cands:
                    scan_file(c, names, implied, gated, root, seen, hits)
        elif text == "{":
            stack.append((pending, False))
            pending, attrs = False, []
        elif text in "([":
            stack.append((pending, pending))
        elif text == "}":
            opened = stack.pop()[0] if stack else False
            pending = opened and idx + 1 < len(toks) and toks[idx + 1][1] == "else"
            attrs = []
        elif text in ")]":
            if stack:
                pending = stack.pop()[1]
        elif text in ";,":
            pending, attrs = False, []


def check(root):
    errs = []
    domains = domain_crates(root)

    kconfig = os.path.join(root, "config", "extensions", "Kconfig")
    symbols = re.findall(r"^config EXT_(\w+)", read(kconfig), re.M) if os.path.exists(kconfig) else []
    wanted = {s.lower(): "EXT_" + s for s in symbols}

    manifests, installs = {}, []
    for f in rust_files(root, "crates", "kernel"):
        rel = os.path.relpath(f, root)
        if rel.startswith(os.path.join("crates", "core", "ext-api")):
            continue
        stripped = re.sub(r"//[^\n]*", "", read(f))
        for m in MANIFEST.finditer(stripped):
            manifests.setdefault(m.group(2), []).append((m.group(1), rel))
        for m in INSTALL.finditer(stripped):
            installs.append((m.group(1), rel))

    for name, sym in sorted(wanted.items()):
        found = manifests.get(name, [])
        if len(found) != 1:
            errs.append(f"{sym}: {len(found)} `Manifest` statics named \"{name}\" (want exactly 1)")
            continue
        static, rel = found[0]
        if not rel.startswith(os.path.join("crates", "domains", name) + os.sep):
            errs.append(f"{sym}: manifest `{static}` is in {rel}, not under crates/domains/{name}/")
        n = sum(1 for s, _ in installs if s == static)
        if n != 1:
            errs.append(f"{sym}: manifest `{static}` is installed {n} times (want exactly 1)")
    all_statics = {s for found in manifests.values() for s, _ in found}
    for name, found in sorted(manifests.items()):
        if name not in wanted:
            for static, rel in found:
                errs.append(f"{rel}: manifest `{static}` is named \"{name}\", which no EXT_ symbol of config/extensions/Kconfig names")
    for static, rel in installs:
        if static not in all_statics:
            errs.append(f"{rel}: installs `{static}`, which is no `Manifest` static")

    names = set(domains)
    for root_rs, cargo in crate_roots(root):
        implied = implied_features(cargo)
        hits, seen = [], set()
        scan_file(root_rs, names, implied, False, root, seen, hits)
        crate_dir = os.path.dirname(os.path.dirname(root_rs))
        for f in rust_files(root, os.path.relpath(os.path.join(crate_dir, "src"), root)):
            if f not in seen:
                scan_file(f, names, implied, False, root, seen, hits)
        for rel, line, name in hits:
            errs.append(f"{rel}:{line}: names `{name}` outside an item gated on `{GATE}`")
        if os.path.exists(cargo):
            errs.extend(cargo_errors(root, cargo, names))
    return sorted(set(errs))


def cargo_errors(root, cargo, names):
    text = read(cargo)
    rel = os.path.relpath(cargo, root)
    out = []
    feats = features(text)
    for m in re.finditer(r"^(\w+)\s*=\s*(.*)$", text, re.M):
        if m.group(1) not in names:
            continue
        section = text.rfind("\n[", 0, m.start())
        header = text[section + 1:text.find("\n", section + 1)] if section >= 0 else ""
        if "dependencies" not in header:
            continue
        if "optional = true" not in m.group(2):
            out.append(f"{rel}: depends on `{m.group(1)}` without `optional = true`")
        elif f"dep:{m.group(1)}" not in feats.get(GATE, []):
            out.append(f"{rel}: optional dependency `{m.group(1)}` is not turned on by `{GATE}` alone")
    return out


def self_test():
    """A tree with one of each violation, and the same tree cleaned."""
    files = {
        "config/extensions/Kconfig": "config EXT_FOO\n\tbool\nconfig EXT_BAR\n\tbool\nconfig EXT_BAZ\n\tbool\n",
        "crates/core/ext-api/src/lib.rs": "pub struct Manifest;\n",
        "crates/domains/foo/foo/Cargo.toml": '[package]\nname = "azos_foo"\n',
        "crates/domains/foo/foo/src/lib.rs":
            'pub static FOO: azos_ext_api::Manifest = azos_ext_api::Manifest { name: "foo", api_level: 1, providers: &[] };\n'
            "pub fn install() { azos_actuation::providers::install(&FOO); }\n",
        "crates/domains/bar/bar/src/lib.rs":
            'pub static BAR: Manifest = Manifest { name: "bar", api_level: 1, providers: &[] };\n',
        "crates/domains/elsewhere/src/lib.rs":
            'pub static BAZ: Manifest = Manifest { name: "baz", api_level: 1, providers: &[] };\n'
            "pub fn install() { providers::install(&BAZ); providers::install(&NOPE); }\n"
            'pub static STRAY: Manifest = Manifest { name: "stray", api_level: 1, providers: &[] };\n',
        "crates/core/c/Cargo.toml":
            '[features]\nuse-robot = ["dep:azos_foo"]\nsmoke = ["use-robot"]\n[dependencies]\nazos_foo = { path = "x", optional = true }\n',
        "crates/core/c/src/lib.rs":
            '#[cfg(feature = "use-robot")]\nuse azos_foo::A;\n'
            '#[cfg(all(feature = "smoke", target_os = "none"))]\nfn gated() { azos_foo::b(); }\n'
            '#[cfg(feature = "use-robot")]\nmod gated_mod;\n'
            "// azos_foo in a comment\nconst S: &str = \"azos_foo\";\n"
            "fn open() { azos_foo::c(); }\n"
            '#[cfg(any(feature = "use-robot", feature = "other"))]\nfn any_of() { azos_foo::d(); }\n',
        "crates/core/c/src/gated_mod.rs": "fn g() { azos_foo::e(); }\n",
        "kernel/Cargo.toml": '[features]\nuse-robot = []\n[dependencies]\nazos_foo = { path = "x" }\n',
        "kernel/src/main.rs": "mod boot;\nfn k() { azos_foo::f(); }\n",
        "kernel/src/boot.rs": '#![cfg(feature = "use-robot")]\nfn b() { azos_foo::g(); }\n',
    }
    with tempfile.TemporaryDirectory() as tmp:
        for rel, body in files.items():
            p = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(body)
        got = check(tmp)
        want = sorted([
            "EXT_BAR: manifest `BAR` is installed 0 times (want exactly 1)",
            "EXT_BAZ: manifest `BAZ` is in crates/domains/elsewhere/src/lib.rs, not under crates/domains/baz/",
            "crates/domains/elsewhere/src/lib.rs: installs `NOPE`, which is no `Manifest` static",
            "crates/domains/elsewhere/src/lib.rs: manifest `STRAY` is named \"stray\", "
            "which no EXT_ symbol of config/extensions/Kconfig names",
            f"crates/core/c/src/lib.rs:9: names `azos_foo` outside an item gated on `{GATE}`",
            f"crates/core/c/src/lib.rs:11: names `azos_foo` outside an item gated on `{GATE}`",
            f"kernel/src/main.rs:2: names `azos_foo` outside an item gated on `{GATE}`",
            "kernel/Cargo.toml: depends on `azos_foo` without `optional = true`",
        ])
        if got != want:
            print("self-test FAIL")
            for w in sorted(set(want) - set(got)):
                print("  not seen:", w)
            for g in sorted(set(got) - set(want)):
                print("  unexpected:", g)
            return 1
        clean = dict(files)
        clean["config/extensions/Kconfig"] = "config EXT_FOO\n\tbool\n"
        clean["crates/domains/bar/bar/src/lib.rs"] = ""
        clean["crates/domains/elsewhere/src/lib.rs"] = ""
        clean["crates/core/c/src/lib.rs"] = (
            '#[cfg(feature = "smoke")]\nuse azos_foo::A;\n#[cfg(feature = "use-robot")]\nmod gated_mod;\n'
            '#[cfg(not(feature = "use-robot"))]\nuse crate::none::foo as azos_foo;\nfn alias() { azos_foo::x(); }\n'
            '#[cfg(feature = "use-robot")]\nfn e() { if a { azos_foo::y(); } else { azos_foo::z(); } }\n')
        clean["kernel/Cargo.toml"] = '[features]\nuse-robot = ["dep:azos_foo"]\n[dependencies]\nazos_foo = { path = "x", optional = true }\n'
        clean["kernel/src/main.rs"] = "mod boot;\n"
        for rel, body in clean.items():
            with open(os.path.join(tmp, rel), "w", encoding="utf-8") as fh:
                fh.write(body)
        left = check(tmp)
        if left:
            print("self-test FAIL: a clean tree reports:")
            print("\n".join(left))
            return 1
    print("extension_lint self-test: ok")
    return 0


def main():
    if "--self-test" in sys.argv[1:]:
        return self_test()
    errs = check(ROOT)
    for e in errs:
        print(e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())

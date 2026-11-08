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
    manifest, is an error, except a base provider's: a `Manifest` under
    crates/drivers/ (the board's kill switch), whose crate is an optional
    dependency of kernel/Cargo.toml (its Kconfig symbol turns it on), which
    owns no effect provider (`providers: &[]`) and which is installed exactly
    once.

And the base does not name an extension: no crate under crates/core and no
file under kernel/src names a crate of crates/domains, except from an item
`#[cfg(...)]`-gated on `use-robot` (or on a kernel feature that implies it),
and a crates/core or kernel Cargo.toml lists such a crate only as an optional
dependency its `use-robot` feature turns on.

And an extension does not reach into the base: a crate under crates/domains/
depends on crates of its own extension, on ext-api, on crates/drivers and
crates/lib, and on the base crates SURFACE names, nothing else. SURFACE is the
set the robot links today; it only shrinks.
Every dependency table counts (normal, dev, build, `[target.*]`,
`[dependencies.X]`), and what a crates/lib crate links in turn is held to the
same surface, except `crates/lib/bench` (BENCH_ONLY: it links the subsystems it
measures).

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
# The base crates (and arch/facade) the robot extension links today. A new
# dependency of an extension on one not listed here is a new reach into the
# base: it is added here by a reviewed edit, or the extension goes through
# ext-api instead.
SURFACE = {
    "arch/facade",
    "crates/core/abi", "crates/core/actuation", "crates/core/channel", "crates/core/common",
    "crates/core/config", "crates/core/crypto", "crates/core/ipc", "crates/core/limits", "crates/core/percpu", "crates/core/rings",
    "crates/core/sched", "crates/core/sync", "crates/core/syscall", "crates/core/topology", "crates/core/wcet-macro",
}
EXTENSION_OPEN = ("crates/core/ext-api", "crates/drivers", "crates/lib")
# crates/lib crates whose own dependencies the closure check skips. The bench
# harness links mm, ota, fs and net/stack because those are what it measures;
# it is a measuring tool, not a path from the extension into those subsystems,
# and the kernel that runs it links them anyway.
BENCH_ONLY = {"crates/lib/bench"}
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

    manifests, installs, bodies = {}, [], {}
    for f in rust_files(root, "crates", "kernel"):
        rel = os.path.relpath(f, root)
        if rel.startswith(os.path.join("crates", "core", "ext-api")):
            continue
        stripped = re.sub(r"//[^\n]*", "", read(f))
        for m in MANIFEST.finditer(stripped):
            manifests.setdefault(m.group(2), []).append((m.group(1), rel))
            end = stripped.find("};", m.end())
            bodies[(m.group(1), rel)] = stripped[m.end():end if end >= 0 else len(stripped)]
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
    for (static, rel), body in sorted(bodies.items()):
        if not re.search(r"\bapi_level\s*:\s*(?:azos_ext_api::)?API_LEVEL\b", body):
            errs.append(f"{rel}: manifest `{static}` names its contract level by a literal (use azos_ext_api::API_LEVEL)")
    for name, found in sorted(manifests.items()):
        if name not in wanted:
            for static, rel in found:
                if rel.startswith(os.path.join("crates", "drivers") + os.sep):
                    errs.extend(base_provider_errors(root, static, rel, installs, bodies[(static, rel)]))
                else:
                    errs.append(f"{rel}: manifest `{static}` is named \"{name}\", which no EXT_ symbol of config/extensions/Kconfig names")
    for static, rel in installs:
        if static not in all_statics:
            errs.append(f"{rel}: installs `{static}`, which is no `Manifest` static")

    errs.extend(surface_errors(root))
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


def logical_lines(text):
    """The manifest's lines, comments dropped, with an inline table or an array
    that continues over several lines (Cargo accepts them; the gate's python3
    may be the system 3.9, which has no tomllib) joined onto one."""
    out, buf, depth = [], "", 0
    for line in text.split("\n"):
        masked = re.sub(r'"[^"]*"|\'[^\']*\'', lambda m: "_" * len(m.group(0)), line)
        code = line[:masked.index("#")] if "#" in masked else line
        depth += masked[:len(code)].count("{") + masked[:len(code)].count("[") - masked[:len(code)].count("}") - masked[:len(code)].count("]")
        if buf or depth > 0:
            buf = (buf + " " + code.strip()).strip()
        else:
            buf = code.strip()
        if depth <= 0:
            if buf and not (buf.startswith("[") and "=" not in buf and not buf.endswith("]")):
                out.append(buf)
            buf, depth = "", 0
    return out


def scalar(v):
    v = v.strip()
    if v in ("true", "false"):
        return v == "true"
    m = re.match(r'^"([^"]*)"$|^\'([^\']*)\'$', v)
    return (m.group(1) if m.group(1) is not None else m.group(2)) if m else v


def inline_table(body):
    """`{ a = "x", b = true, c = [..] }` as a dict (arrays are kept as text)."""
    out = {}
    for m in re.finditer(r'([\w-]+)\s*=\s*("[^"]*"|\'[^\']*\'|\[[^\]]*\]|[^,}\s]+)', body):
        out[m.group(1)] = scalar(m.group(2))
    return out


HEADER = re.compile(r"^\[+\s*(?:target\s*\.\s*(?:'[^']*'|\"[^\"]*\"|[^.\]]+)\s*\.\s*)?"
                    r"((?:dev-|build-)?dependencies|workspace\s*\.\s*dependencies)\s*(?:\.\s*([\w-]+))?\s*\]+$")


def read_deps(path):
    """[(table, name, spec)] of a manifest: `table` is dependencies,
    dev-dependencies, build-dependencies or workspace.dependencies, in the
    normal tables, under `[target.<cfg>.*]`, and as `[dependencies.<name>]`."""
    out, cur, single = [], None, None
    with open(path, encoding="utf-8") as fh:
        lines = logical_lines(fh.read())
    for line in lines:
        if line.startswith("["):
            m = HEADER.match(line)
            cur = re.sub(r"\s+", "", m.group(1)) if m else None
            single = (m.group(2), {}) if m and m.group(2) else None
            if single:
                out.append((cur, single[0], single[1]))
            continue
        kv = re.match(r"^([\w-]+)\s*=\s*(.*)$", line)
        if cur is None or not kv:
            continue
        if single:
            single[1][kv.group(1)] = scalar(kv.group(2))
        else:
            val = kv.group(2).strip()
            out.append((cur, kv.group(1), inline_table(val[1:-1]) if val.startswith("{") else {"version": scalar(val)}))
    return out


def workspace_paths(root):
    """{package: directory} of the root Cargo.toml's workspace dependencies."""
    path = os.path.join(root, "Cargo.toml")
    deps = read_deps(path) if os.path.exists(path) else []
    return {n: spec["path"] for t, n, spec in deps if t == "workspace.dependencies" and "path" in spec}


def manifest_deps(path):
    """(name, table, spec) of every dependency a manifest declares."""
    for table, name, spec in read_deps(path):
        if table != "workspace.dependencies":
            yield name, table, spec


def dep_target(root, rel_dir, name, spec, ws):
    """The directory (relative to the root) a dependency names, or None."""
    if "path" in spec:
        return os.path.normpath(os.path.join(rel_dir, spec["path"]))
    if spec.get("workspace") and name in ws:
        return os.path.normpath(ws[name])
    return None


def outside_surface(target, own):
    """Is `target` a crate an extension may not depend on?"""
    if target == own or target.startswith(own + os.sep):
        return False
    if any(target == o or target.startswith(o + os.sep) for o in EXTENSION_OPEN):
        return False
    return target not in SURFACE


def surface_errors(root):
    """Dependencies of an extension crate outside its own extension, ext-api,
    crates/drivers, crates/lib and SURFACE, and what a crates/lib crate it
    uses links in turn (BENCH_ONLY excepted)."""
    errs = []
    ws = workspace_paths(root)
    base = os.path.join(root, "crates", "domains")
    for d, subdirs, names in os.walk(base):
        subdirs[:] = sorted(s for s in subdirs if s not in ("target", ".git"))
        if "Cargo.toml" not in names:
            continue
        rel_dir = os.path.relpath(d, root)
        own = os.path.join("crates", "domains", os.path.relpath(d, base).split(os.sep)[0])
        for name, _, spec in manifest_deps(os.path.join(d, "Cargo.toml")):
            target = dep_target(root, rel_dir, name, spec, ws)
            if target is None:
                continue
            if outside_surface(target, own):
                errs.append(f"{rel_dir}/Cargo.toml: `{name}` ({target}) is outside the extension surface "
                            f"(its own extension, ext-api, crates/drivers, crates/lib, SURFACE)")
            elif target.startswith("crates/lib" + os.sep):
                errs.extend(lib_closure_errors(root, rel_dir, name, target, own, ws))
    return errs


def lib_closure_errors(root, rel_dir, via_name, start, own, ws):
    """What the crates/lib crate `start` links, through further crates/lib crates."""
    errs, seen, todo = [], set(), [start]
    while todo:
        cur = todo.pop()
        if cur in seen or cur in BENCH_ONLY or not os.path.exists(os.path.join(root, cur, "Cargo.toml")):
            continue
        seen.add(cur)
        for name, kind, spec in manifest_deps(os.path.join(root, cur, "Cargo.toml")):
            if kind == "dev-dependencies":
                continue
            target = dep_target(root, cur, name, spec, ws)
            if target is None:
                continue
            if target.startswith("crates/lib" + os.sep):
                todo.append(target)
            elif outside_surface(target, own):
                errs.append(f"{rel_dir}/Cargo.toml: `{via_name}` links `{name}` ({target}) through {cur}, "
                            f"outside the extension surface")
    return errs


def package_of(root, rel):
    """The package name of the crate that holds file `rel`."""
    d = os.path.dirname(os.path.join(root, rel))
    while d.startswith(root) and not os.path.exists(os.path.join(d, "Cargo.toml")):
        d = os.path.dirname(d)
    m = re.search(r'^name\s*=\s*"([^"]+)"', read(os.path.join(d, "Cargo.toml")), re.M)
    return m.group(1) if m else None


def base_provider_errors(root, static, rel, installs, body):
    out = []
    # A base provider owns no effect kind and no stop work: those are an
    # extension's, and a driver that claimed a kind would make an image
    # without the extension serve it.
    if not re.search(r"\bproviders\s*:\s*&\s*\[\s*\]", body):
        out.append(f"{rel}: base provider `{static}` declares effect providers (a base provider has `providers: &[]`)")
    pkg = package_of(root, rel)
    kernel = os.path.join(root, "kernel", "Cargo.toml")
    dep = re.search(rf"^{re.escape(pkg or '')}\s*=\s*\{{([^}}]*)\}}", read(kernel), re.M) if pkg else None
    if dep is None or "optional = true" not in dep.group(1):
        out.append(f"{rel}: base provider `{static}`: `{pkg}` is not an optional dependency of kernel/Cargo.toml")
    n = sum(1 for s, _ in installs if s == static)
    if n != 1:
        out.append(f"{rel}: base provider `{static}` is installed {n} times (want exactly 1)")
    return out


def cargo_errors(root, cargo, names):
    rel = os.path.relpath(cargo, root)
    out = []
    feats = features(read(cargo))
    for name, _, spec in manifest_deps(cargo):
        if spec.get("package", name) not in names and name not in names:
            continue
        if not spec.get("optional"):
            out.append(f"{rel}: depends on `{name}` without `optional = true`")
        elif f"dep:{name}" not in feats.get(GATE, []):
            out.append(f"{rel}: optional dependency `{name}` is not turned on by `{GATE}` alone")
    return out


def self_test():
    """A tree with one of each violation, and the same tree cleaned."""
    files = {
        "config/extensions/Kconfig": "config EXT_FOO\n\tbool\nconfig EXT_BAR\n\tbool\nconfig EXT_BAZ\n\tbool\n",
        "crates/core/ext-api/src/lib.rs": "pub struct Manifest;\n",
        "Cargo.toml": '[workspace.dependencies]\nazos_hv = { path = "crates/core/hv" }\n'
            'azos_energy = { path = "crates/core/energy" }\nazos_pkg = { path = "crates/core/pkg" }\n'
            'azos_trace = { path = "crates/core/trace" }\n',
        "crates/domains/foo/foo/Cargo.toml":
            '[package]\nname = "azos_foo"\n[dependencies]\nazos_hv = { workspace = true }\n'
            'azos_recovery = {\n  path = "../../../core/recovery"\n}\nazos_gps = { path = "../../../drivers/gps" }\n'
            'azos_ext_api = { path = "../../../core/ext-api" }\nazos_abi = { path = "../../../core/abi" }\n'
            'azos_wrap = { path = "../../../lib/wrap" }\nazos_bench = { path = "../../../lib/bench" }\n'
            '[dependencies.azos_energy]\nworkspace = true\n'
            "[target.'cfg(target_arch = \"riscv64\")'.dependencies]\nazos_pkg = { workspace = true }\n"
            '[dev-dependencies]\nazos_trace = { workspace = true }\n'
            '[build-dependencies]\nazos_inspect = { path = "../../../core/inspect" }\n',
        "crates/lib/wrap/Cargo.toml": '[package]\nname = "azos_wrap"\n[dependencies]\nazos_mm = { path = "../../core/mm" }\n'
            'azos_gps = { path = "../../drivers/gps" }\n[dev-dependencies]\nazos_net = { path = "../../net/stack" }\n',
        "crates/lib/bench/Cargo.toml": '[package]\nname = "azos_bench"\n[dependencies]\nazos_fs = { path = "../../fs" }\n',
        "crates/domains/foo/foo/src/lib.rs":
            'pub static FOO: azos_ext_api::Manifest = azos_ext_api::Manifest { name: "foo", api_level: API_LEVEL, providers: &[] };\n'
            "pub fn install() { azos_actuation::providers::install(&FOO); }\n",
        "crates/domains/bar/bar/src/lib.rs":
            'pub static BAR: Manifest = Manifest { name: "bar", api_level: 1, providers: &[] };\n',
        "crates/domains/elsewhere/src/lib.rs":
            'pub static BAZ: Manifest = Manifest { name: "baz", api_level: API_LEVEL, providers: &[] };\n'
            "pub fn install() { providers::install(&BAZ); providers::install(&NOPE); }\n"
            'pub static STRAY: Manifest = Manifest { name: "stray", api_level: API_LEVEL, providers: &[] };\n',
        "crates/drivers/sw/Cargo.toml": '[package]\nname = "azos_sw"\n',
        "crates/drivers/sw/src/lib.rs":
            'pub static SW: Manifest = Manifest { name: "sw", api_level: API_LEVEL, providers: &[] };\n',
        "crates/drivers/hard/Cargo.toml": '[package]\nname = "azos_hard"\n',
        "crates/drivers/hard/src/lib.rs":
            'pub static HARD: Manifest = Manifest { name: "hard", api_level: API_LEVEL, providers: &[] };\n',
        "crates/drivers/kind/Cargo.toml": '[package]\nname = "azos_kind"\n',
        "crates/drivers/kind/src/lib.rs":
            'pub static KIND: Manifest = Manifest { name: "kind", api_level: API_LEVEL, '
            'providers: &[Provider { name: "p", kinds: &[1] }], hooks: &[] };\n',
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
        "kernel/Cargo.toml": '[features]\nuse-robot = []\n[dependencies]\nazos_foo = { path = "x" }\n'
            'azos_sw = { path = "s", optional = true }\nazos_hard = { path = "h" }\n'
            'azos_kind = { path = "k", optional = true }\n',
        "kernel/src/main.rs": "mod boot;\nfn k() { azos_foo::f(); }\n"
            "fn p() { providers::install(&azos_sw::SW); providers::install(&azos_hard::HARD); "
            "providers::install(&azos_hard::HARD); providers::install(&azos_kind::KIND); }\n",
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
            "crates/domains/bar/bar/src/lib.rs: manifest `BAR` names its contract level by a literal (use azos_ext_api::API_LEVEL)",
            "EXT_BAZ: manifest `BAZ` is in crates/domains/elsewhere/src/lib.rs, not under crates/domains/baz/",
            "crates/domains/elsewhere/src/lib.rs: installs `NOPE`, which is no `Manifest` static",
            "crates/domains/elsewhere/src/lib.rs: manifest `STRAY` is named \"stray\", "
            "which no EXT_ symbol of config/extensions/Kconfig names",
            f"crates/core/c/src/lib.rs:9: names `azos_foo` outside an item gated on `{GATE}`",
            f"crates/core/c/src/lib.rs:11: names `azos_foo` outside an item gated on `{GATE}`",
            f"kernel/src/main.rs:2: names `azos_foo` outside an item gated on `{GATE}`",
            "kernel/Cargo.toml: depends on `azos_foo` without `optional = true`",
            "crates/drivers/hard/src/lib.rs: base provider `HARD`: `azos_hard` is not an optional dependency of kernel/Cargo.toml",
            "crates/drivers/hard/src/lib.rs: base provider `HARD` is installed 2 times (want exactly 1)",
            "crates/drivers/kind/src/lib.rs: base provider `KIND` declares effect providers (a base provider has `providers: &[]`)",
            "crates/domains/foo/foo/Cargo.toml: `azos_hv` (crates/core/hv) is outside the extension surface "
            "(its own extension, ext-api, crates/drivers, crates/lib, SURFACE)",
            "crates/domains/foo/foo/Cargo.toml: `azos_recovery` (crates/core/recovery) is outside the extension surface "
            "(its own extension, ext-api, crates/drivers, crates/lib, SURFACE)",
            "crates/domains/foo/foo/Cargo.toml: `azos_energy` (crates/core/energy) is outside the extension surface "
            "(its own extension, ext-api, crates/drivers, crates/lib, SURFACE)",
            "crates/domains/foo/foo/Cargo.toml: `azos_pkg` (crates/core/pkg) is outside the extension surface "
            "(its own extension, ext-api, crates/drivers, crates/lib, SURFACE)",
            "crates/domains/foo/foo/Cargo.toml: `azos_trace` (crates/core/trace) is outside the extension surface "
            "(its own extension, ext-api, crates/drivers, crates/lib, SURFACE)",
            "crates/domains/foo/foo/Cargo.toml: `azos_inspect` (crates/core/inspect) is outside the extension surface "
            "(its own extension, ext-api, crates/drivers, crates/lib, SURFACE)",
            "crates/domains/foo/foo/Cargo.toml: `azos_wrap` links `azos_mm` (crates/core/mm) through crates/lib/wrap, "
            "outside the extension surface",
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
        clean["kernel/Cargo.toml"] = ('[features]\nuse-robot = ["dep:azos_foo"]\n[dependencies]\nazos_foo = { path = "x", optional = true }\n'
                                      'azos_sw = { path = "s", optional = true }\n')
        clean["kernel/src/main.rs"] = "mod boot;\nfn p() { providers::install(&azos_sw::SW); }\n"
        clean["crates/lib/wrap/Cargo.toml"] = '[package]\nname = "azos_wrap"\n'
        clean["crates/domains/foo/foo/Cargo.toml"] = '[package]\nname = "azos_foo"\n[dependencies]\nazos_abi = { path = "../../../core/abi" }\n'
        clean["crates/drivers/hard/src/lib.rs"] = ""
        clean["crates/drivers/kind/src/lib.rs"] = ""
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

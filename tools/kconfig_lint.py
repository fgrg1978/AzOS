#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""kconfig_lint.py — Kconfig is the only source of truth for the build.

Checks (exit 1 on any ERROR; REPORT lines never fail):

  tags      every `# cargo-feature:` tag names a cargo feature of
            kernel/Cargo.toml, sits inside a `config` block of a symbol that
            exists, and each feature is owned by exactly one symbol and each
            symbol owns at most one feature.
  select    no `select` of a visible symbol (one with a prompt): a select
            forces the value past `depends on` and the user's choice, and the
            visible symbol then lies in `make menuconfig`.
  default    kernel/Cargo.toml has no `default` features: Kconfig is the
            only source of the feature set.
  reader    every symbol has a reader: its name (or CONFIG_<name>, or the
            <name>_BYTES constant azos_limits emits) outside a comment in
            code or a build file (READER_DIRS), a Kconfig expression of
            another symbol (depends, default, select, imply, range), or, for
            a `# cargo-feature:` symbol, its feature quoted in a cfg or a
            Cargo.toml. A choice member is read when any member of its choice
            is (the others are the choice's implicit else). The symbols of
            the generated config/Kconfig.userspace are exempt (read through
            images.mk by pattern).
  tautology no symbol has two or more defaults that all give the same value
            with one of them unconditional: the conditions decide nothing.
  once      no symbol is defined in two places (kconfiglib merges them
            silently).
  report    (never fails) features a board feature enables that are not the board itself
            (policy that belongs to Kconfig, not to the board).

Usage: python3 tools/kconfig_lint.py [--self-test]
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kconfig_to_cargo as k2c  # noqa: E402

_CONFIG_RE = re.compile(r"^\s*(?:menu)?config\s+(\w+)\s*$")
_PROMPT_RE = re.compile(r'^\s*(?:(?:bool|tristate|int|hex|string)\s+"|prompt\s+")')
_SELECT_RE = re.compile(r"^\s*select\s+(\w+)")
_KEYWORD_RE = re.compile(r"^\s*(?:choice|endchoice|menu|endmenu|if|endif|comment|source|mainmenu)\b")


def parse_symbols(files, root):
    """`(visible, selects)`: the symbols with a prompt, and the
    `(symbol, selected, file:line)` triples."""
    visible, selects = set(), []
    defined = set()
    for path in files:
        cur = None
        rel = os.path.relpath(path, root)
        with open(path, encoding="utf-8") as fh:
            for no, line in enumerate(fh, 1):
                m = _CONFIG_RE.match(line)
                if m:
                    cur = m.group(1)
                    defined.add(cur)
                    continue
                if _KEYWORD_RE.match(line):
                    cur = None
                    continue
                if cur is None:
                    continue
                if _PROMPT_RE.match(line):
                    visible.add(cur)
                m = _SELECT_RE.match(line)
                if m:
                    selects.append((cur, m.group(1), f"{rel}:{no}"))
    return defined, visible, selects


def cargo_features(cargo_toml):
    """name -> list of entries, for the `[features]` table of a Cargo.toml."""
    text = open(cargo_toml, encoding="utf-8").read()
    sec = re.search(r"^\[features\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    out = {}
    for m in re.finditer(r"^([A-Za-z0-9_-]+)\s*=\s*\[(.*?)\]", sec.group(1), re.M | re.S):
        body = "\n".join(l.split("#", 1)[0] for l in m.group(2).splitlines())
        out[m.group(1)] = re.findall(r'"([^"]+)"', body)
    return out


TEST_HOOK_RE = re.compile(r"(-smoke|-canary|-probe|-test|-row|-bench|-census|-sim|-freeze|"
                          r"-window|-spin|-safety|-skip|-keep|-census|-trace|-timing|-sync|"
                          r"-in-lock|-profile|-hooks)(-\w+)*$")


# Where a symbol's reader may live (the code, the build, the tools and the tests).
READER_DIRS = ("kernel", "crates", "micro", "lx", "userspace", "sdk", "domains", "boot",
               "formal", "mk", "tools", "tests")
READER_SKIP_DIRS = {"target", ".git", "__pycache__", "node_modules"}
_SLASH_COMMENT = (".rs", ".c", ".h", ".S", ".s", ".ld", ".x", ".zig", ".cpp")
_HASH_COMMENT = (".py", ".sh", ".mk", ".toml", ".cfg", ".conf", ".txt", ".yaml", ".yml",
                 ".json", ".tla")
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_QUOTED_RE = re.compile(r'"([A-Za-z0-9_/-]+)"')
GENERATED_KCONFIG = "Kconfig.userspace"


def reader_index(root):
    """(tokens, quoted): every identifier outside a line comment, and every
    double-quoted word, in the files under READER_DIRS and the Makefile."""
    tokens, quoted = set(), set()
    paths = [os.path.join(root, "Makefile")]
    for d in READER_DIRS:
        for dirpath, dirs, files in os.walk(os.path.join(root, d)):
            dirs[:] = [x for x in dirs if x not in READER_SKIP_DIRS]
            paths += [os.path.join(dirpath, f) for f in files]
    for path in paths:
        base = os.path.basename(path)
        if path.endswith(_SLASH_COMMENT):
            style = "//"
        elif path.endswith(_HASH_COMMENT) or base == "Makefile":
            style = "#"
        else:
            continue
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for line in text.splitlines():
            if style == "//":
                line = line.split("//", 1)[0]
            else:
                if line.lstrip().startswith("#") and not line.startswith("#!"):
                    continue
                line = re.sub(r"\s#\s.*$", "", line)
            tokens.update(_TOKEN_RE.findall(line))
            quoted.update(q.rsplit("/", 1)[-1] for q in _QUOTED_RE.findall(line))
    return tokens, quoted


def kconfig_checks(root, tags):
    """The `reader`, `tautology` and `once` checks over the loaded tree."""
    from kconfiglib import Kconfig, Choice, Symbol, expr_items, expr_str

    errors = []
    here = os.getcwd()
    os.chdir(root)
    try:
        kconf = Kconfig("Kconfig", warn_to_stderr=False)
    finally:
        os.chdir(here)

    # once
    for sym in kconf.unique_defined_syms:
        if len(sym.nodes) > 1:
            where = ", ".join(f"{os.path.relpath(n.filename, root) if os.path.isabs(n.filename) else n.filename}:{n.linenr}"
                              for n in sym.nodes)
            errors.append(f"once: {sym.name} is defined {len(sym.nodes)} times: {where}")

    # tautology (the defaults as written: `orig_defaults` leave out the
    # propagated `depends on`)
    for sym in kconf.unique_defined_syms:
        defs = [d for n in sym.nodes for d in n.orig_defaults]
        if len(defs) >= 2 and len({expr_str(v) for v, _ in defs}) == 1 \
                and any(c is kconf.y for _, c in defs):
            n = sym.nodes[0]
            errors.append(f"tautology: {n.filename}:{n.linenr}: {sym.name} has {len(defs)} defaults, "
                          f"all {expr_str(defs[0][0])}: keep the unconditional one")

    # reader
    kref = set()

    def add(expr):
        kref.update(i.name for i in expr_items(expr) if isinstance(i, Symbol))

    for node in kconf.node_iter():
        add(node.dep)
        own_choice = isinstance(node.item, Choice)
        for value, cond in getattr(node, "orig_defaults", []):
            add(cond)
            if not own_choice:  # a choice's own `default MEMBER` is not a reader
                add(value)
        for attr in ("orig_selects", "orig_implies", "orig_ranges"):
            for entry in getattr(node, attr, []):
                for e in entry:
                    add(e)
    tokens, quoted = reader_index(root)

    def read(name):
        return (name in tokens or "CONFIG_" + name in tokens or name + "_BYTES" in tokens
                or name in kref or (name in tags and tags[name] in quoted))

    for sym in kconf.unique_defined_syms:
        if all(n.filename.endswith(GENERATED_KCONFIG) for n in sym.nodes):
            continue
        group = sym.choice.syms if sym.choice is not None else [sym]
        if not any(read(m.name) for m in group):
            n = sym.nodes[0]
            errors.append(f"reader: {n.filename}:{n.linenr}: {sym.name} has no reader "
                          "(no code, build file, Kconfig expression or cargo feature names it)")
    return errors


def gen_userspace(root):
    """config/Kconfig.userspace is generated (not committed): make it current."""
    import subprocess
    subprocess.run([sys.executable, os.path.join(root, "tools", "gen_userspace_kconfig.py")],
                   cwd=root, check=True)


def lint(root=k2c.REPO_ROOT, cargo_toml=k2c.KERNEL_CARGO_TOML, generate=True, kconfig=True):
    errors, report = [], []
    if generate:
        gen_userspace(root)
    files = k2c.kconfig_files(root)
    tags, orphans = k2c.parse_cargo_feature_tags(root)
    defined, visible, selects = parse_symbols(files, root)
    feats = cargo_features(cargo_toml)

    for o in orphans:
        errors.append(f"tags: {o}: `# cargo-feature:` outside a config block")
    by_feat, by_sym = {}, {}
    for sym, feat, inv, where in tags:
        by_feat.setdefault(feat, []).append(sym)
        by_sym.setdefault(sym, []).append(feat)
        if feat not in feats:
            errors.append(f"tags: {where}: {sym} names `{feat}`, which is not a feature of {os.path.relpath(cargo_toml, root)}")
    for feat, syms in by_feat.items():
        if len(syms) > 1:
            errors.append(f"tags: feature `{feat}` is owned by {len(syms)} symbols: {', '.join(syms)}")
    for sym, fs in by_sym.items():
        if len(fs) > 1:
            errors.append(f"tags: {sym} owns {len(fs)} features: {', '.join(fs)}")

    for sym, target, where in selects:
        if target in visible:
            errors.append(f"select: {where}: {sym} selects the visible symbol {target}")

    if kconfig:
        errors += kconfig_checks(root, {sym: feat for sym, feat, _, _ in tags})

    # The feature set comes from Kconfig alone: no cargo `default`.
    if feats.get("default"):
        errors.append("default: kernel/Cargo.toml `default` is not empty: "
                      + ", ".join(feats["default"]))

    # --- report only ---
    board_feats = {f for f in by_feat if any(s.startswith("BOARD_") for s in by_feat[f])}
    for b in sorted(board_feats):
        extra = [e for e in feats.get(b, [])
                 if not e.startswith("dep:") and e.split("/", 1)[-1].rstrip("?") != b
                 and not e.endswith("/" + b) and not e.endswith("?/" + b)]
        if extra:
            report.append(f"board feature `{b}` also enables (policy?): {', '.join(extra)}")
    untagged = sorted(f for f in feats if f != "default" and f not in by_feat
                      and not TEST_HOOK_RE.search(f))
    if untagged:
        report.append(f"{len(untagged)} cargo features neither tagged nor test hooks by name: "
                      + ", ".join(untagged))
    return errors, report


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "config"))
        open(os.path.join(d, "Kconfig"), "w").write('source "config/Kconfig.a"\n')
        open(os.path.join(d, "config", "Kconfig.a"), "w").write(
            'config A\n\t# cargo-feature: fa\n\tbool "a"\n'
            'config B\n\t# cargo-feature: fa\n\tbool\n\tselect A\n'
            'config C\n\t# cargo-feature: nosuch\n\tbool\n'
            'endmenu\n# cargo-feature: fa\nconfig D\n\tbool\n\tselect HIDDEN\n'
            'config HIDDEN\n\tbool\n')
        ct = os.path.join(d, "Cargo.toml")
        open(ct, "w").write('[features]\ndefault = ["fa"]\nfa = []\n[dependencies]\n')
        errors, _ = lint(d, ct, generate=False, kconfig=False)
        want = ["owned by 2 symbols", "not a feature", "outside a config block",
                "selects the visible symbol A", "is not empty"]
        miss = [w for w in want if not any(w in e for e in errors)]
        if miss or any("HIDDEN" in e for e in errors):
            print("kconfig_lint self-test FAILED:", miss, errors)
            return 1
    # The reader / tautology / once checks, on a tree kconfiglib parses. Each
    # `bad` symbol must be flagged and no `good` one.
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "config"))
        os.makedirs(os.path.join(d, "kernel", "src"))
        open(os.path.join(d, "Kconfig"), "w").write('source "config/Kconfig.a"\n')
        open(os.path.join(d, "config", "Kconfig.a"), "w").write(
            'config DEAD\n\tbool "no reader"\n'
            'config IN_COMMENT\n\tbool "named only in a comment"\n'
            'config BY_CODE\n\tint "read by the code"\n\tdefault 3 if BY_KCONFIG\n\tdefault 3\n'
            'config BY_KCONFIG\n\tbool "read by a Kconfig expression"\n'
            'config BY_FEATURE\n\t# cargo-feature: feat-x\n\tbool "read through its feature"\n'
            'config TWICE\n\tbool "defined twice"\n'
            'config TWICE\n\tbool\n'
            'config NOT_TAUT\n\tint "two values"\n\tdefault 1 if BY_KCONFIG\n\tdefault 2\n'
            'choice\n\tprompt "a choice"\n\tdefault CH_A\n'
            'config CH_A\n\tbool "read"\nconfig CH_B\n\tbool "implicit else"\nendchoice\n'
            'choice\n\tprompt "a dead choice"\n\tdefault DC_A\n'
            'config DC_A\n\tbool "a"\nconfig DC_B\n\tbool "b"\nendchoice\n')
        open(os.path.join(d, "kernel", "src", "lib.rs"), "w").write(
            "// IN_COMMENT TWICE NOT_TAUT\n"
            "const X: u32 = azos_limits::BY_CODE + azos_limits::TWICE as u32 + azos_limits::NOT_TAUT;\n"
            "#[cfg(feature = \"feat-x\")] fn f() {}\nconst Y: bool = azos_limits::CH_A;\n")
        ct = os.path.join(d, "Cargo.toml")
        open(ct, "w").write('[features]\nfeat-x = []\n[dependencies]\n')
        errors, _ = lint(d, ct, generate=False)
        bad = ["reader: config/Kconfig.a:1: DEAD ", "IN_COMMENT has no reader", "DC_A has no reader",
               "DC_B has no reader", "tautology: config/Kconfig.a:5: BY_CODE ", "once: TWICE "]
        good = ["BY_KCONFIG ", "BY_FEATURE ", "CH_A ", "CH_B ", "NOT_TAUT "]
        miss = [b for b in bad if not any(b in e for e in errors)]
        wrong = [g for g in good if any(g in e for e in errors)]
        if miss or wrong:
            print("kconfig_lint self-test FAILED (reader/tautology/once): missed", miss,
                  "flagged", wrong, errors)
            return 1
    print("kconfig_lint self-test ok")
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()
    errors, report = lint()
    for r in report:
        print("REPORT", r)
    for e in errors:
        print("ERROR", e)
    if errors:
        print(f"kconfig_lint: {len(errors)} error(s)")
        return 1
    print("kconfig_lint: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

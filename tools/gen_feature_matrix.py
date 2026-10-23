#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The OS feature matrix, generated from the Kconfig tree.

Every user-visible bool / tristate symbol and every choice (a symbol or choice
with a prompt) is one row, grouped by the Kconfig file that defines it and the
menu it sits in. There is one column per config/defconfigs/*.config, expanded
the way `make defconfig-<name>` does (the defconfig loaded by kconfiglib, which
is what `python3 -m olddefconfig` runs): `y` / `n` / `m` for a symbol, the
selected member (the prefix the members share is dropped) for a choice. A
symbol whose dependencies are unmet reads `n`, as it does in the .config.

The output is deterministic: files, menus and symbols are sorted, nothing
depends on the date or the host. Documentation/os-feature-matrix.md is this
script's output and nothing else; edit the Kconfig fragments and regenerate.

    python3 tools/gen_feature_matrix.py            write the matrix
    python3 tools/gen_feature_matrix.py --check    exit 1 when the committed
                                                   matrix is not what the
                                                   Kconfig tree yields (a gate
                                                   row, tools/gate_tier.sh n0)
    python3 tools/gen_feature_matrix.py --self-test
                                                   canaries on a synthetic tree
"""

import argparse
import glob
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import azos_tools  # noqa: E402

ROOT = azos_tools.ROOT
OUT = os.path.join("Documentation", "os-feature-matrix.md")
DEFCONFIG_DIR = os.path.join("config", "defconfigs")
REGEN = "python3 tools/gen_feature_matrix.py"


def esc(text):
    """A prompt as one markdown table cell: no pipe, tag, link or code span."""
    out = []
    for ch in text:
        if ch == "|":
            out.append("\\|")
        elif ch == "`":
            out.append("'")
        elif ch in "<>&":
            out.append({"<": "&lt;", ">": "&gt;", "&": "&amp;"}[ch])
        elif ch in "[]*\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return " ".join("".join(out).split())


def common_prefix(names):
    """The longest prefix the names share, cut at a `_` boundary."""
    if len(names) < 2:
        return ""
    pre = os.path.commonprefix(names)
    return pre[: pre.rfind("_") + 1] if "_" in pre else ""


def collect(kconf):
    """{(file, menu path): [row]} for every prompted bool / tristate symbol and
    choice. A row is (sort key, kind, name, prompt, node item)."""
    from kconfiglib import BOOL, TRISTATE, MENU, Choice, Symbol

    groups, seen = {}, set()

    def walk(node, menus):
        while node:
            item = node.item
            if node.prompt and item is not None:
                key = None
                if isinstance(item, Symbol) and item.type in (BOOL, TRISTATE) \
                        and id(item) not in seen:
                    key = (0, item.name, item.name)
                elif isinstance(item, Choice) and id(item) not in seen:
                    label = item.name or node.prompt[0]
                    key = (1, label, item.name or "")
                if key:
                    seen.add(id(item))
                    groups.setdefault((node.filename, menus), []).append(
                        (key, item, node.prompt[0]))
            if node.list:
                sub = menus
                if item == MENU and node.prompt:
                    sub = menus + (node.prompt[0],)
                walk(node.list, sub)
            node = node.next

    walk(kconf.top_node.list, ())
    return groups


def value_of(item):
    from kconfiglib import Choice

    if isinstance(item, Choice):
        sel = item.selection
        return sel.name if sel else "n"
    return item.str_value


def render(root, defdir):
    """The matrix text for the Kconfig tree under `root` and the defconfigs in
    `defdir` (both absolute)."""
    import kconfiglib

    cwd = os.getcwd()
    saved = {k: os.environ.pop(k, None) for k in ("srctree", "KCONFIG_CONFIG")}
    os.chdir(root)
    try:
        kconf = kconfiglib.Kconfig("Kconfig", warn_to_stderr=False)
        groups = collect(kconf)
        files = sorted(glob.glob(os.path.join(defdir, "*.config")))
        cols = [os.path.basename(f)[: -len(".config")] for f in files]
        values = []  # per defconfig: {id(item): value}
        for f in files:
            kconf.load_config(f)
            values.append({id(it): value_of(it)
                           for rows in groups.values() for _, it, _ in rows})
        n_rows = sum(len(r) for r in groups.values())
        prefixes = {}
        for rows in groups.values():
            for _, it, _ in rows:
                if isinstance(it, kconfiglib.Choice):
                    prefixes[id(it)] = common_prefix(
                        [s.name for s in it.syms])
    finally:
        os.chdir(cwd)
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v

    rel = os.path.relpath(defdir, root)
    o = [
        "<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->",
        "<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->",
        f"<!-- Generated by {REGEN}; edit the Kconfig fragments, not this file. -->",
        "# OS feature matrix",
        "",
        "Every user-visible Kconfig option that is a switch (a bool or tristate with a",
        "prompt) or a choice, grouped by the Kconfig file and menu that define it, with its",
        "value in each defconfig. A value is what the defconfig yields once Kconfig has",
        "expanded it, as `make defconfig-<name>` does: `y` or `n` for an option (an option",
        "whose dependencies are unmet reads `n`), the selected member for a choice (the",
        "prefix its members share is dropped). Numeric and string options are not listed.",
        "",
        f"The file is generated by `{REGEN}`, which `--check` compares",
        "against the Kconfig tree. How options, presets and defconfigs work is in",
        "[config.md](config.md).",
        "",
        f"Options and choices: {n_rows}. Defconfigs: {len(cols)}.",
        "",
        "## Defconfigs",
        "",
        "| Column | File |",
        "|---|---|",
    ]
    for c in cols:
        o.append(f"| {c} | {rel}/{c}.config |")
    o.append("")

    fkeys = sorted({k[0] for k in groups})
    for fn in fkeys:
        o += [f"## {fn}", ""]
        for menus in sorted(m for (f, m) in groups if f == fn):
            if menus:
                o += ["### " + " / ".join(esc(m) for m in menus), ""]
            o.append("| Symbol | Prompt | " + " | ".join(cols) + " |")
            o.append("|---|---|" + "---|" * len(cols))
            for key, it, prompt in sorted(groups[(fn, menus)], key=lambda r: r[0]):
                if key[0] == 1:
                    name = "choice " + (f"`{it.name}`" if it.name else "")
                    pre = prefixes[id(it)]
                    cells = [v[id(it)][len(pre):] if v[id(it)].startswith(pre)
                             else v[id(it)] for v in values]
                    name = name.strip()
                else:
                    name = f"`{it.name}`"
                    cells = [v[id(it)] for v in values]
                o.append(f"| {name} | {esc(prompt)} | " + " | ".join(cells) + " |")
            o.append("")
    while o and o[-1] == "":
        o.pop()
    return "\n".join(o) + "\n"


def check(text, path, quiet=False):
    """0 when `path` holds exactly `text`; else 1 with the first difference."""
    say = (lambda *_: None) if quiet else print
    shown = os.path.relpath(path, ROOT) if path.startswith(ROOT) else path
    try:
        with open(path, encoding="utf-8") as f:
            have = f.read()
    except OSError:
        say(f"gen_feature_matrix: {shown} is missing; run {REGEN}")
        return 1
    if have == text:
        return 0
    a, b = have.split("\n"), text.split("\n")
    for i, (x, y) in enumerate(zip(a, b), 1):
        if x != y:
            say(f"gen_feature_matrix: {shown} is stale at line {i}; run {REGEN}")
            say(f"  committed: {x[:140]}")
            say(f"  generated: {y[:140]}")
            return 1
    say(f"gen_feature_matrix: {shown} is stale ({len(a)} vs {len(b)} lines); run {REGEN}")
    return 1


SELF_KCONFIG = '''mainmenu "T"
config TOP
\tbool "Top switch"
menu "Alpha | beta"
config A
\tbool "Feature `A` <x>"
config B
\tbool "Feature B"
\tdefault y
config NEEDS_A
\tbool "Needs A"
\tdepends on A
\tdefault y
config HIDDEN
\tbool
\tdefault y
config LIMIT
\tint "A number"
\tdefault 4
choice SPEED
\tprompt "Speed"
\tdefault SPEED_SLOW
config SPEED_SLOW
\tbool "Slow"
config SPEED_FAST
\tbool "Fast"
endchoice
endmenu
'''


def self_test():
    bad = []

    def expect(cond, what):
        if not cond:
            bad.append(what)

    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "config", "defconfigs"))
        with open(os.path.join(d, "Kconfig"), "w") as f:
            f.write(SELF_KCONFIG)
        dc = os.path.join(d, "config", "defconfigs")
        with open(os.path.join(dc, "one.config"), "w") as f:
            f.write("CONFIG_A=y\nCONFIG_SPEED_FAST=y\n")
        with open(os.path.join(dc, "two.config"), "w") as f:
            f.write("CONFIG_TOP=y\n")
        text = render(d, dc)
        rows = {ln.split("|")[1].strip(): [c.strip() for c in ln.split("|")[3:-1]]
                for ln in text.split("\n") if ln.startswith("| ") and "`" in ln.split("|")[1]
                or ln.startswith("| choice")}
        expect(rows.get("`A`") == ["y", "n"], f"A: {rows.get('`A`')}")
        expect(rows.get("`B`") == ["y", "y"], f"B: {rows.get('`B`')}")
        expect(rows.get("`TOP`") == ["n", "y"], f"TOP: {rows.get('`TOP`')}")
        expect(rows.get("`NEEDS_A`") == ["y", "n"], f"dependency: {rows.get('`NEEDS_A`')}")
        expect(rows.get("choice `SPEED`") == ["FAST", "SLOW"], f"choice: {rows.get('choice `SPEED`')}")
        expect("HIDDEN" not in text, "a promptless symbol is listed")
        expect("LIMIT" not in text, "an int is listed")
        expect("### Alpha \\| beta" in text, "menu heading missing or unescaped")
        expect("Feature 'A' &lt;x&gt;" in text, "prompt not escaped")
        expect(text == render(d, dc), "two renders differ")
        out = os.path.join(d, "m.md")
        expect(check(text, out, quiet=True) == 1, "a missing file passed --check")
        with open(out, "w") as f:
            f.write(text)
        expect(check(text, out, quiet=True) == 0, "an identical file failed --check")
        with open(out, "w") as f:
            f.write(text.replace("| `B` |", "| `B2` |", 1))
        expect(check(text, out, quiet=True) == 1, "a stale file passed --check")
        with open(os.path.join(dc, "two.config"), "w") as f:
            f.write("CONFIG_TOP=y\nCONFIG_B=n\n")
        with open(out, "w") as f:
            f.write(text)
        expect(check(render(d, dc), out, quiet=True) == 1, "a changed defconfig passed --check")
    for b in bad:
        print("gen_feature_matrix self-test FAIL:", b)
    if not bad:
        print("gen_feature_matrix self-test ok")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 when the committed matrix is stale")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    text = render(ROOT, os.path.join(ROOT, DEFCONFIG_DIR))
    out = os.path.join(ROOT, OUT)
    if args.check:
        return check(text, out)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

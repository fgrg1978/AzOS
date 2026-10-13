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


def gen_userspace(root):
    """config/Kconfig.userspace is generated (not committed): make it current."""
    import subprocess
    subprocess.run([sys.executable, os.path.join(root, "tools", "gen_userspace_kconfig.py")],
                   cwd=root, check=True)


def lint(root=k2c.REPO_ROOT, cargo_toml=k2c.KERNEL_CARGO_TOML, generate=True):
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
        errors, _ = lint(d, ct, generate=False)
        want = ["owned by 2 symbols", "not a feature", "outside a config block",
                "selects the visible symbol A", "is not empty"]
        miss = [w for w in want if not any(w in e for e in errors)]
        if miss or any("HIDDEN" in e for e in errors):
            print("kconfig_lint self-test FAILED:", miss, errors)
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

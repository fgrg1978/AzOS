#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Gate row: VIRT_SPLIT and SECURITY_CONFIDENTIAL are refused while no ISA has
a resident monitor (ARCH_HAS_HYP_MONITOR), and the refusal is seen, not silent.

    python3 tools/gate/hyp_refusal_row.py ISA [--canary]     ISA: riscv64 | aarch64 | x86_64

For each of the two symbols, on the given ISA:
  - `make config` does not offer it (not visible) and setting it leaves it n;
  - a config that asks for it is reported by tools/build/kconfig_dropped.py
    (exit 1, the symbol named), the check `make defconfig-NAME` and
    check_presets run;
  - a hand-written .config that still carries it stops the build of
    azos_limits ("validation FAIL"), the crate every kernel build reads.

--canary runs the same judge on a copy of the Kconfig tree with the
`ARCH_HAS_HYP_MONITOR` dependencies removed: the judge must then FAIL. Exit 0
means the refusal holds (or, under --canary, that the judge caught the hole).
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
ROOT = azos_tools.ROOT

SYMBOLS = ("VIRT_SPLIT", "SECURITY_CONFIDENTIAL")
ISAS = ("riscv64", "aarch64", "x86_64")


def kconfig_tree(canary, td):
    """The tree to judge: this checkout, or a copy whose symbols no longer wait for a monitor."""
    if not canary:
        return ROOT
    for name in ("Kconfig", "config"):
        src = os.path.join(ROOT, name)
        (shutil.copytree if os.path.isdir(src) else shutil.copy)(src, os.path.join(td, name))
    for rel in ("config/axes/Kconfig.virt", "config/axes/Kconfig.security"):
        path = os.path.join(td, rel)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        text = text.replace("depends on ARCH_HAS_HYP_MONITOR && ", "depends on ").replace(
            "        depends on ARCH_HAS_HYP_MONITOR\n", "")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return td


def judge(isa, tree, td):
    """The reasons the refusal does not hold on `isa` in `tree` (empty: it holds)."""
    from kconfiglib import Kconfig

    sys.path.insert(0, os.path.join(ROOT, "tools/build"))
    import kconfig_dropped

    bad = []
    arch = f"CONFIG_ARCH_{isa.upper()}=y"
    os.chdir(tree)
    kconf = Kconfig("Kconfig", warn_to_stderr=False)
    base = os.path.join(td, "base.config")
    with open(base, "w", encoding="utf-8") as fh:
        fh.write(arch + "\n")
    kconf.load_config(base)
    for name in SYMBOLS:
        sym = kconf.syms[name]
        if sym.visibility != 0:
            bad.append(f"{name} is offered by `make config` on {isa}")
        sym.set_value("y")
        if sym.str_value == "y":
            bad.append(f"{name} stays y when `make config` sets it on {isa}")
    kconf.load_config(base)
    kconf.write_config(os.path.join(td, "expanded.config"))
    for name in SYMBOLS:
        asked = os.path.join(td, f"ask-{name}.config")
        with open(asked, "w", encoding="utf-8") as fh:
            fh.write(f"{arch}\nCONFIG_{name}=y\n")
        kconf.load_config(asked)
        if name not in [n for n, _ in kconfig_dropped.dropped(kconf)]:
            bad.append(f"a config asking for {name} on {isa} is not reported as dropped")
        if tree == ROOT:
            r = subprocess.run([sys.executable, os.path.join(ROOT, "tools/build/kconfig_dropped.py"), asked],
                               capture_output=True, text=True)
            if r.returncode != 1 or f"CONFIG_{name}=y is refused" not in r.stderr:
                bad.append(f"kconfig_dropped.py rc={r.returncode} on {name}/{isa}: {r.stderr.strip()[:120]}")
    if tree == ROOT:
        for name in SYMBOLS:
            raw = os.path.join(td, f"raw-{name}.config")
            with open(os.path.join(td, "expanded.config"), encoding="utf-8") as src, \
                    open(raw, "w", encoding="utf-8") as dst:
                dst.write(src.read() + f"CONFIG_{name}=y\n")
            env = dict(os.environ, KCONFIG_CONFIG=raw)
            r = subprocess.run(["cargo", "check", "-q", "-p", "azos_limits"], cwd=ROOT, env=env,
                               capture_output=True, text=True)
            if r.returncode == 0 or "validation FAIL: VIRT_SPLIT / SECURITY_CONFIDENTIAL" not in r.stderr:
                bad.append(f"the azos_limits build accepted a .config with {name} on {isa} (rc={r.returncode})")
    return bad


def main(argv):
    canary = "--canary" in argv
    args = [a for a in argv if a != "--canary"]
    if len(args) != 1 or args[0] not in ISAS:
        print(__doc__)
        return 2
    with tempfile.TemporaryDirectory() as td:
        tree_dir = os.path.join(td, "tree")
        os.mkdir(tree_dir)
        work = os.path.join(td, "work")
        os.mkdir(work)
        bad = judge(args[0], kconfig_tree(canary, tree_dir), work)
    for b in bad:
        print(f"      {'canary caught: ' if canary else ''}{b}")
    if canary:
        return 0 if bad else 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

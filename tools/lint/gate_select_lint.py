#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Every build selection the gate names is one `--select` accepts.

A selection is a quoted comma list of kernel cargo features and `CONFIG_<SYM>=<v>`
lines in tools/gate/ci_check.sh, gate_tier.sh and check_fast.sh (what `kbuild`,
`a64_kbuild`, `x86_kbuild` and the rows hand to `--select`, tools/gate/ci_cargo.py). Each one found (a `$var`
part is dropped) is applied with tools/build/kconfig_to_cargo.py `select` to
the gate's base configuration of each ISA, as `primary_config` builds it: the
generic gate defconfig (the robot one for a selection that closes over
`use-robot`, as `gate_defc` picks) plus GATE_KCONFIG_EXTRA. It must be
accepted on at least one ISA: a selection refused everywhere is a row that
cannot build, which a canary row would otherwise read as its canary biting.

  gate_select_lint.py              check; list every refused selection
  gate_select_lint.py --list       also print what each selection sets
  gate_select_lint.py --self-test  the canaries (a refused and an accepted one)
"""

import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
import kconfig_to_cargo as k2c  # noqa: E402

ROOT = azos_tools.ROOT
GATE = os.path.join(ROOT, "tools/gate/ci_check.sh")
# The other gate scripts whose builds name a selection.
OTHERS = [os.path.join(ROOT, f) for f in ("tools/gate/gate_tier.sh", "tools/gate/check_fast.sh")]
ARCHES = ("riscv64", "aarch64", "x86_64")
_QUOTED = re.compile(r'"([^"\n]*)"')
_VAR = re.compile(r"\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@])")
_TOKEN = re.compile(r"^(CONFIG_[A-Z0-9_]+=\S+|[a-z0-9][a-z0-9_-]*(/[a-z0-9_-]+)?)$")


_ARG = re.compile(r'(?:\bkbuild|\ba64_kbuild|\ba64_kbuild_out|\bx86_kbuild|--select)\s+("[^"\n]*"|[^\s"]+)')


def selections(text, feats):
    """The selection strings of the gate's text: every quoted comma list, and
    every argument of a build helper or `--select`, whose tokens are all kernel
    features or Kconfig lines, one of them a feature (a single quoted word
    counts only when it is a test hook: otherwise it is a row's label as often
    as a selection)."""
    out = set()
    raws = [r for r in _QUOTED.findall(text) if "," in r or (r in feats and k2c.TEST_HOOK_RE.search(r))]
    raws += [a.strip('"') for a in _ARG.findall(text)]
    for raw in raws:
        s = ",".join(t for t in _VAR.sub("", raw).split(",") if t)
        toks = s.split(",") if s else []
        if not toks or not all(_TOKEN.match(t) for t in toks):
            continue
        if not any(t in feats or ("/" in t and k2c.TEST_HOOK_RE.search(t)) for t in toks):
            continue
        if all(t.startswith("CONFIG_") or t in feats or "/" in t for t in toks):
            out.add(s)
    return sorted(out)


def gate_extra(text):
    """GATE_KCONFIG_EXTRA: its CONFIG_ lines and the all-on userspace lines."""
    m = re.search(r'^GATE_KCONFIG_EXTRA="(.*?)"$', text, re.M | re.S)
    lines = [l for l in (m.group(1).splitlines() if m else []) if l.startswith("CONFIG_")]
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools/build/gen_userspace_kconfig.py"), "--all-on"],
                       cwd=ROOT, capture_output=True, text=True, check=True)
    return lines + r.stdout.splitlines()


def base(work, preset, arch, extra):
    path = os.path.join(work, f"{preset}-{arch}.config")
    if not os.path.exists(path):
        src = os.path.join(ROOT, "config", "defconfigs", f"{preset}-sbc-{arch}-dev+qemu+linux+gui.config")
        with open(src, encoding="utf-8") as fh:
            text = fh.read()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n".join(extra) + "\n")
        subprocess.run([sys.executable, "-m", "olddefconfig"], cwd=ROOT, check=True, capture_output=True,
                       env=dict(os.environ, KCONFIG_CONFIG=path))
    return path


def robot(sel, feats):
    seen, todo = set(), [t for t in sel.split(",") if t in feats]
    while todo:
        f = todo.pop()
        if f == "use-robot":
            return True
        for e in feats.get(f, []):
            if not e.startswith("dep:") and "/" not in e and e not in seen:
                seen.add(e)
                todo.append(e)
    return False


def judge(sels, work, extra, feats, show=False):
    """[(selection, why)] for the selections refused on every ISA."""
    bad = []
    for s in sels:
        preset = "robot" if robot(s, feats) else "generic"
        whys = []
        for arch in ARCHES:
            out = os.path.join(work, "sel.config")
            try:
                k2c.select(base(work, preset, arch, extra), s.split(","), out)
            except k2c.SelectError as e:
                whys.append(f"{arch}: {e}")
                continue
            if show:
                got = k2c.read_dot_config(out) or {}
                was = k2c.read_dot_config(base(work, preset, arch, extra)) or {}
                moved = sorted(f"{k}={v}" for k, v in got.items() if was.get(k, "n") != v)
                print(f"{s} [{preset} {arch}]: {' '.join(moved) or '(nothing)'}")
            break
        else:
            bad.append((s, "; ".join(whys)))
    return bad


def self_test(work, extra, feats):
    found = selections('kbuild "qemu,lx-verify-canary" x\npar_row r "qemu,CONFIG_LINUX_DRIVERS=y,lx-verify-canary$x"\n'
                       'echo "not a, selection"\nbuild "rvv" --select CONFIG_RV_V_PROBE=y\n', feats)
    want = ["qemu,CONFIG_LINUX_DRIVERS=y,lx-verify-canary", "qemu,lx-verify-canary"]
    if found != want:
        print(f"gate_select_lint self-test FAILED: found {found}, want {want}")
        return 1
    bad = [s for s, _ in judge(found, work, extra, feats)]
    if bad != ["qemu,lx-verify-canary"]:
        print(f"gate_select_lint self-test FAILED: refused {bad}, want only the selection without LINUX_DRIVERS")
        return 1
    print("gate_select_lint self-test ok")
    return 0


def main(argv):
    feats = k2c.cargo_features(k2c.KERNEL_CARGO_TOML)
    with open(GATE, encoding="utf-8") as fh:
        text = fh.read()
    extra = gate_extra(text)
    out_root = os.environ.get("AZOS_OUT") or tempfile.gettempdir()
    os.makedirs(out_root, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gate-select-", dir=out_root) as work:
        if "--self-test" in argv:
            return self_test(work, extra, feats)
        others = "".join(open(f, encoding="utf-8").read() for f in OTHERS if os.path.exists(f))
        sels = selections(text + others, feats)
        bad = judge(sels, work, extra, feats, show="--list" in argv)
    for s, why in bad:
        print(f"gate_select_lint: `{s}` is refused on every ISA: {why[:400]}")
    if not bad:
        print(f"gate_select_lint: ok ({len(sels)} selections)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

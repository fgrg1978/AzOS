#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""check_neverallow.py — no preset's topology breaks a neverallow rule
(`make check-neverallow`).

The rules are `azos_topology::neverallow::RULES` (crates/core/topology/src/neverallow.rs).
This script builds the topology each configuration would run and has the host
checker (tests/host/topology-tests/src/bin/topo_neverallow.rs) apply them:

  * every PRESET_* of config/axes/Kconfig.preset on every ISA (the way
    tools/check_presets.py expands them);
  * every config/defconfigs/*.config as it stands (the board images);
  * the micro kernel's signed topology (tools/micro_topology.py), parsed under
    config/defconfigs/generic-embedded-riscv64-dev+board-generic+micro.config.

Each configuration is expanded with kconfiglib, as `olddefconfig` does. The
cargo features of the kernel it asks for (tools/kconfig_to_cargo.py) are
followed through kernel/Cargo.toml to the `azos_topology/...` features they
turn on, which is what `make topology-files` does with `cargo tree`; the rows
only a kernel of one ISA declares come with `emit-target-<isa>`. The checker
runs under that configuration's `.config` (the image's domain, the limits).
`azos_limits` refuses a configuration whose sizes cannot be a kernel (a heap
as large as the RAM, say); the topology does not read those sizes, so such a
configuration is checked under the same `.config` with the failing size symbols
raised (see `relax_sizes`), never skipped. A configuration that still does not
build, other than those on the `UNBUILDABLE_OK` list (empty), fails the run.
Two configurations that agree on the ISA, the topology features and every
Kconfig value the topology crate reads get one run.

`--canary` is the other half: the same checker, built with the topology
feature `neverallow-row-canary` (a ring-3 row that is not an actuation row
holding a PWM write grant), must REFUSE, naming rule 0. A checker that passed
it would be one that checks nothing. Three outcomes, never conflated: refused
(the canary discriminates), admitted (it does not: FAIL), did not build (FAIL).

    python3 tools/check_neverallow.py [--list] [--canary] [--only SUBSTRING]
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from out_dir import out_root  # noqa: E402
import check_presets  # noqa: E402
import kconfig_lint  # noqa: E402
import kconfig_to_cargo as k2c  # noqa: E402

HOST_CRATE = os.path.join(ROOT, "tests", "host", "topology-tests")
TOPOLOGY_SRC = os.path.join(ROOT, "crates", "core", "topology", "src")
DEFCONFIGS = os.path.join(ROOT, "config", "defconfigs")
MICRO_DEFCONFIG = "generic-embedded-riscv64-dev+board-generic+micro.config"
TARGET_DIR = os.path.join(out_root(), "target", "neverallow-check")

# Configurations (by name) that may fail azos_limits validation even with the
# size symbols relaxed, and be left unchecked. Empty: a configuration that
# cannot be checked is a configuration whose topology could ship unchecked.
UNBUILDABLE_OK = frozenset()

ISA_FEATURE = {"CONFIG_ARCH_RISCV64": "emit-target-riscv64", "CONFIG_ARCH_AARCH64": "emit-target-aarch64",
               "CONFIG_ARCH_X86_64": "emit-target-x86_64"}


def cargo():
    return shutil.which("cargo") or os.path.expanduser("~/.cargo/bin/cargo")


def limits_read_by_topology():
    """Kconfig symbols the topology crate reads as `azos_limits::NAME`, plus the
    ones a rule depends on: the values that decide what the topology is."""
    names = {"USE_DESKTOP", "TOPOLOGY_DRIVETRAIN", "TOPOLOGY_NEVERALLOW"}
    for fn in os.listdir(TOPOLOGY_SRC):
        if fn.endswith(".rs"):
            with open(os.path.join(TOPOLOGY_SRC, fn), encoding="utf-8") as fh:
                names.update(re.findall(r"azos_limits::([A-Z][A-Z0-9_]*)", fh.read()))
    return sorted(names)


def topology_features(kernel_features, table):
    """The `azos_topology` features that building the kernel with
    `kernel_features` turns on: `azos_topology/F` and `azos_topology?/F` edges,
    followed through the kernel's own features."""
    out, seen, todo = set(), set(), list(kernel_features)
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        if "/" in f:
            crate, feat = f.split("/", 1)
            if crate.rstrip("?") == "azos_topology":
                out.add(feat)
            continue
        for entry in table.get(f, []):
            if not entry.startswith("dep:"):
                todo.append(entry)
    return sorted(out)


def kernel_features(cfg_path):
    """`--features a,b,c` of tools/kconfig_to_cargo.py for an expanded config."""
    r = subprocess.run([sys.executable, os.path.join(HERE, "kconfig_to_cargo.py"), cfg_path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"kconfig_to_cargo.py: {r.stderr.strip()[:200]}")
    m = re.search(r"--features (\S+)", r.stdout)
    return m.group(1).split(",") if m else []


_TABLE = None


def kernel_table():
    """kernel/Cargo.toml's `[features]`, read once."""
    global _TABLE
    if _TABLE is None:
        _TABLE = kconfig_lint.cargo_features(k2c.KERNEL_CARGO_TOML)
    return _TABLE


class Config:
    """One configuration to check: a name, its expanded .config, and what the
    topology of that image is built from."""

    def __init__(self, name, path, cfg, micro=False):
        self.name, self.path, self.cfg, self.micro = name, path, cfg, micro
        arch = next((k for k in k2c.ARCH_TO_TARGET if cfg.get(k) == "y"), "CONFIG_ARCH_RISCV64")
        self.isa_feature = ISA_FEATURE.get(arch)
        self.features = ["dev-key"] if micro else sorted(set(
            topology_features(kernel_features(path), kernel_table()) + ["dev-key"]))
        self.key = (micro, self.isa_feature, tuple(self.features),
                    tuple((n, cfg.get("CONFIG_" + n, "n")) for n in limits_read_by_topology()))


def expand(kconf, text, path):
    """Write `text` as a config, expand it as `olddefconfig` does, return the
    parsed result and the warnings the expansion raised."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    before = len(kconf.warnings)
    kconf.load_config(path)
    kconf.write_config(path)
    return k2c.read_dot_config(path), list(kconf.warnings[before:])


def configs(tmp, only):
    from kconfiglib import Kconfig

    os.chdir(ROOT)
    kconf = Kconfig("Kconfig", warn_to_stderr=False)
    out = []
    n = 0

    def add(name, text, micro=False):
        nonlocal n
        if only and only not in name:
            return
        n += 1
        path = os.path.join(tmp, f"c{n}.config")
        cfg, warns = expand(kconf, text, path)
        if warns:
            raise RuntimeError(f"{name}: the expansion warns: {warns[0]}")
        out.append(Config(name, path, cfg, micro))

    for preset in check_presets.presets(kconf):
        for arch in sorted(k2c.ARCH_TO_TARGET):
            add(f"{preset} on {arch.removeprefix('CONFIG_ARCH_').lower()}",
                f"CONFIG_{preset}=y\n{arch}=y\n")
    for fn in sorted(os.listdir(DEFCONFIGS)):
        if fn.endswith(".config"):
            with open(os.path.join(DEFCONFIGS, fn), encoding="utf-8") as fh:
                add(f"defconfig {fn[:-len('.config')]}", fh.read(), micro=(fn == MICRO_DEFCONFIG))
    return out


def relax_sizes(cfg_path, why):
    """The path of a copy of `cfg_path` whose size symbols satisfy the
    `azos_limits` validation that failed with `why`, or None when `why` is not
    about the sizes. Only KERNEL_HEAP_SIZE and RAM_SIZE change: the topology
    crate reads neither (limits_read_by_topology() holds the symbols it reads,
    and this function refuses to run if either were in it)."""
    assert not {"KERNEL_HEAP_SIZE", "RAM_SIZE"} & set(limits_read_by_topology()), \
        "the topology reads a size symbol: relaxing it would change what is checked"
    with open(cfg_path, encoding="utf-8") as fh:
        text = fh.read()
    vals = {m.group(1): int(m.group(2)) for m in re.finditer(r"^CONFIG_(\w+)=(\d+)$", text, re.M)}
    heap = vals.get("KERNEL_HEAP_SIZE")
    if heap is None:
        return None
    new = {}
    if "KERNEL_HEAP_SIZE" in why and "RAM_SIZE" in why:
        new["RAM_SIZE"] = heap // 1024 * 2 + 1
    else:
        m = re.search(r"estimated minimum (\d+) bytes", why)
        if not m:
            return None
        new["KERNEL_HEAP_SIZE"] = int(m.group(1)) // 1024 + 1
        ram = vals.get("RAM_SIZE")
        if ram is not None and new["KERNEL_HEAP_SIZE"] >= ram * 1024:
            new["RAM_SIZE"] = new["KERNEL_HEAP_SIZE"] // 1024 * 2 + 1
    for name, v in new.items():
        line = f"CONFIG_{name}={v}"
        if re.search(rf"^CONFIG_{name}=", text, re.M):
            text = re.sub(rf"^CONFIG_{name}=.*$", line, text, flags=re.M)
        else:
            text += line + "\n"
    out = cfg_path + ".relaxed"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    return out


def run_checker(cfg_path, features, files=()):
    """`(returncode, output)` of topo_neverallow built for this configuration."""
    env = dict(os.environ, KCONFIG_CONFIG=os.path.abspath(cfg_path), CARGO_TARGET_DIR=TARGET_DIR)
    feats = " ".join(f if f in ("dev-key",) or f.startswith("emit-target-") else f"azos_topology/{f}"
                     for f in features)
    cmd = [cargo(), "run", "-q", "--release", "--bin", "topo_neverallow", "--features", feats]
    if files:
        cmd += ["--", *files]
    r = subprocess.run(cmd, cwd=HOST_CRATE, env=env, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def canary(cs):
    """The checker must refuse the canary topology."""
    c = next((c for c in cs if not c.micro and "+qemu" in c.name), cs[0])
    feats = c.features + ["neverallow-row-canary"]
    if c.isa_feature:
        feats.append(c.isa_feature)
    rc, out = run_checker(c.path, feats)
    if rc == 1 and "REFUSED rule 0 (actuation-outside-actuation-row)" in out and "NEVERALLOW.ELF" in out:
        print(f"check-neverallow: canary refused: {out.splitlines()[-1][:160]}")
        return 0
    if rc == 0:
        print("check-neverallow: FAIL the canary topology was ADMITTED: the checker checks nothing")
    else:
        print(f"check-neverallow: FAIL the canary did not build or run (rc {rc}):")
        print("    " + "\n    ".join(out.splitlines()[-8:]))
    return 1


def main():
    argv = sys.argv[1:]
    only = argv[argv.index("--only") + 1] if "--only" in argv else None
    with tempfile.TemporaryDirectory() as tmp:
        cs = configs(tmp, only)
        if "--list" in argv:
            for c in cs:
                print(f"{c.name}: {' '.join(c.features)} {c.isa_feature or ''}".rstrip())
            return 0
        if "--canary" in argv:
            return canary(cs)
        groups = {}
        for c in cs:
            groups.setdefault(c.key, []).append(c)
        micro_dir = os.path.join(tmp, "micro-topology")
        failures, unbuildable = [], []
        for key, members in groups.items():
            c = members[0]
            feats = c.features + ([c.isa_feature] if c.isa_feature else [])
            files = ()
            if c.micro:
                subprocess.run([sys.executable, os.path.join(HERE, "micro_topology.py"), micro_dir],
                               check=True, capture_output=True)
                files = (os.path.join(micro_dir, "CAPS.TOM"), os.path.join(micro_dir, "SCHED.TOM"))
            rc, out = run_checker(c.path, feats, files)
            names = ", ".join(m.name for m in members)
            # `azos_limits` refuses a configuration whose sizes no kernel
            # could be built from (a heap as large as the RAM, say). That is
            # that build's refusal, not a neverallow rule's, and the topology
            # does not read those sizes: check it under the same config with
            # the sizes raised, so the preset is never left unchecked.
            why = re.search(r"validation FAIL: (.*)", out)
            if rc != 0 and why and "neverallow: REFUSED" not in out:
                relaxed = relax_sizes(c.path, why.group(1))
                if relaxed:
                    print(f"check-neverallow: {names}: sizes relaxed ({why.group(1)[:90]}...)")
                    rc, out = run_checker(relaxed, feats, files)
                    why = re.search(r"validation FAIL: (.*)", out)
            if rc != 0 and why and "neverallow: REFUSED" not in out:
                unbuildable.append((names, why.group(1)[:140], all(m.name in UNBUILDABLE_OK for m in members)))
            elif rc != 0:
                failures.append((names, rc, out))
        for names, why, allowed in unbuildable:
            print(f"check-neverallow: {'skipped (allowed)' if allowed else 'FAIL not checked'} {names}: {why}")
        for names, rc, out in failures:
            print(f"check-neverallow: FAIL {names}")
            print("    " + ("\n    ".join(out.splitlines()[-8:]) or f"rc {rc}, no output"))
        if failures or any(not allowed for _, _, allowed in unbuildable):
            return 1
        print(f"check-neverallow: ok ({len(cs)} configurations, {len(groups)} distinct topologies, "
              f"{len(unbuildable)} allowed unchecked)")
        return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host test that a ring-3 image is built with the codegen flags of its own ISA:

  1. sdk_cargo.py refuses a configuration of another ISA, before it runs cargo;
  2. for every (ISA of .config) x (ARCH of `make check`), the configuration each
     SDK image of `make -n check` is built from is an expansion of that image's
     ISA;
  3. the signed topology of each ISA is emitted from a configuration of that ISA;
  4. an expansion (qemu-dev.config, aarch64.config, x86_64.config) that an earlier make
     left for another ISA's configuration does not give the images the flags of the
     configuration they are built with.

    python3 tools/build/test_user_isa.py      (exit 0 = all pass)
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
import out_dir  # noqa: E402

REPO = azos_tools.ROOT
ISAS = ("riscv64", "aarch64", "x86_64")
FAILS = []
OUT = os.path.join(out_dir.out_root(), "user-isa-test")


def check(cond, what):
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        FAILS.append(what)


def make(args, out, **kw):
    env = dict(os.environ, AZOS_OUT=out, CARGO_NET_OFFLINE="true")
    return subprocess.run(["make", *args], cwd=REPO, env=env, capture_output=True, text=True, **kw)


def sdk_cargo_refuses(tmp):
    for cfg_isa in ISAS:
        cfg = os.path.join(tmp, cfg_isa + ".config")
        with open(cfg, "w") as f:
            f.write(f"CONFIG_ARCH_{cfg_isa.upper()}=y\n")
        for isa in ISAS:
            try:
                r = subprocess.run([sys.executable, "tools/build/sdk_cargo.py", "--isa", isa, "--kconfig", cfg,
                                    "--", "build", "--manifest-path", "/nonexistent/Cargo.toml"],
                                   cwd=REPO, capture_output=True, text=True, timeout=30)
                refused = r.returncode != 0 and f"selects {cfg_isa}" in r.stderr
            except subprocess.TimeoutExpired:
                refused = False
            check(refused == (isa != cfg_isa), f"sdk_cargo --isa {isa} with a {cfg_isa} configuration: "
                  + ("refused" if isa != cfg_isa else "not refused for its own ISA"))


def image_configs_follow_arch(tmp):
    out = OUT
    for cfg_isa in ISAS:
        cfg = os.path.join(tmp, cfg_isa + "-stub.config")
        with open(cfg, "w") as f:
            f.write(f"CONFIG_ARCH_{cfg_isa.upper()}=y\nCONFIG_USERSPACE_WHY=y\n")  # a std program: an SDK image in the table
        for arch in ISAS:
            r = make(["-n", f"ARCH={arch}", f"KCONFIG_CONFIG={cfg}", "check"], out)
            seen = re.findall(r"sdk_cargo\.py --isa (\w+) --kconfig (\S+)", r.stdout)
            wrong = []
            for isa, path in seen:
                name = os.path.basename(path)
                of = cfg_isa if name == "qemu-dev.config" else next((i for i in ISAS if name.startswith(i)), "?")
                if of != isa:
                    wrong.append(f"--isa {isa} from {name} ({of})")
            check(seen and not wrong, f".config {cfg_isa}, make check ARCH={arch}: {len(seen)} SDK images, "
                  + ("each from its own ISA" if not wrong else "; ".join(sorted(set(wrong)))))


def topology_follows_its_isa(tmp):
    for cfg_isa in ISAS:
        cfg = os.path.join(tmp, cfg_isa + "-topo.config")
        with open(cfg, "w") as f:
            f.write(f"CONFIG_ARCH_{cfg_isa.upper()}=y\n")
        for isa in ISAS:
            want = ("qemu-dev.config" if cfg_isa == "riscv64" else "riscv64.config") if isa == "riscv64" else isa + ".config"
            r = make(["-n", f"KCONFIG_CONFIG={cfg}", os.path.join(OUT, "build", "topo", isa, "CAPS.TOM")], OUT)
            kconfigs = set(re.findall(re.escape(os.path.join(OUT, "build")) + r"/([\w-]+\.config)\b", r.stdout))
            check(want in kconfigs and (isa != "riscv64" or kconfigs == {want}),
                  f".config {cfg_isa}, topology of {isa}: emitted from {want} ({', '.join(sorted(kconfigs))})")


def stale_expansion(tmp, isa, option, target, elf, wanted):
    """An expansion an earlier make left for the configuration of another ISA is not read for the
    flags of the configuration the images are built with: `option` sets a flag only this one has."""
    cfg, other = os.path.join(tmp, isa + ".config"), os.path.join(tmp, "other.config")
    make([f"KCONFIG_CONFIG={cfg}", f"defconfig-generic-sbc-{isa}-dev+qemu+linux+gui"], OUT)
    with open(cfg, "a") as f:
        f.write(option + "\n")
    subprocess.run([sys.executable, "-m", "olddefconfig"], cwd=REPO, env=dict(os.environ, KCONFIG_CONFIG=cfg),
                   capture_output=True, check=True)
    other_isa = "x86_64" if isa != "x86_64" else "aarch64"
    make([f"KCONFIG_CONFIG={other}", f"defconfig-generic-sbc-{other_isa}-dev+qemu+linux+gui"], OUT)
    exp = os.path.join(OUT, "build", target)
    make([f"KCONFIG_CONFIG={cfg}", exp], OUT)
    time.sleep(1.1)  # make 3.81 compares whole seconds: a stamp or expansion made in the same second as the one it replaces is not newer
    make([f"KCONFIG_CONFIG={other}", exp], OUT)
    time.sleep(1.1)
    r = make([f"KCONFIG_CONFIG={cfg}", "USPACE_BUILD=echo", os.path.join(OUT, "build", elf)], OUT)
    flags = " ".join(sorted(set(re.findall(r"^--target .*rustflags=(\[.*\])$", r.stdout, re.M))))
    check(wanted(flags), f"{isa}: the images of a {option} configuration are built with its flags ({flags or 'no flags seen'})")


def stale_expansions(tmp):
    stale_expansion(tmp, "riscv64", "CONFIG_RV_ZBB_REQUIRE=y", "qemu-dev.config", "logd.elf",
                    lambda f: "target-feature=+zbb" in f)
    stale_expansion(tmp, "aarch64", "CONFIG_A64_BTI_NEVER=y", "aarch64.config", "aarch64/logd.elf",
                    lambda f: 'branch-protection=pac-ret"' in f and "bti" not in f)
    stale_expansion(tmp, "x86_64", "CONFIG_X86_CET_IBT_NEVER=y", "x86_64.config", "x86_64/logd.elf",
                    lambda f: "azos_stable_metadata" in f and "cf-protection" not in f)


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    with tempfile.TemporaryDirectory() as tmp:
        sdk_cargo_refuses(tmp)
        image_configs_follow_arch(tmp)
        topology_follows_its_isa(tmp)
        stale_expansions(tmp)
    print("test_user_isa:", "FAIL" if FAILS else "ok")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

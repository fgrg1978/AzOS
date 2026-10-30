#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host test that a ring-3 image is built with the codegen flags of its own ISA:

  1. sdk_cargo.py refuses a configuration of another ISA, before it runs cargo;
  2. for every (ISA of .config) x (ARCH of `make check`), the configuration each
     SDK image of `make -n check` is built from is an expansion of that image's
     ISA;
  3. a qemu-dev.config that an earlier make left for another ISA does not give
     the riscv64 images the flags of the configuration they are built with.

    python3 tools/build/test_user_isa.py      (exit 0 = all pass)
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

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
            f.write(f"CONFIG_ARCH_{cfg_isa.upper()}=y\n")
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


def stale_development_config(tmp):
    out = OUT
    rv, x86 = os.path.join(tmp, "rv.config"), os.path.join(tmp, "x86.config")
    make([f"KCONFIG_CONFIG={rv}", "defconfig-generic-sbc-riscv64-dev+qemu+linux+gui"], out)
    with open(rv, "a") as f:
        f.write("CONFIG_RV_ZBB_REQUIRE=y\n")
    subprocess.run([sys.executable, "-m", "olddefconfig"], cwd=REPO, env=dict(os.environ, KCONFIG_CONFIG=rv),
                   capture_output=True, check=True)
    make([f"KCONFIG_CONFIG={x86}", "defconfig-generic-sbc-x86_64-dev+qemu+linux+gui"], out)
    dev = os.path.join(OUT, "build", "qemu-dev.config")
    make([f"KCONFIG_CONFIG={rv}", dev], out)
    make([f"KCONFIG_CONFIG={x86}", dev], out)
    left = "CONFIG_ARCH_X86_64=y" in open(dev).read()
    r = make([f"KCONFIG_CONFIG={rv}", "USPACE_BUILD=echo", os.path.join(OUT, "build", "logd.elf")], out)
    flags = set(re.findall(r"rustflags=\[[^\]]*\]", r.stdout))
    check(left, "the earlier make left an x86_64 qemu-dev.config")
    check(len(flags) == 1 and "target-feature=+zbb" in "".join(flags),
          f"the riscv64 images of a RV_ZBB_REQUIRE configuration are built with +zbb ({' '.join(sorted(flags)) or 'no flags seen'})")


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    with tempfile.TemporaryDirectory() as tmp:
        sdk_cargo_refuses(tmp)
        image_configs_follow_arch(tmp)
        stale_development_config(tmp)
    print("test_user_isa:", "FAIL" if FAILS else "ok")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

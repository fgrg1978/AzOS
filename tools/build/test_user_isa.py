#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host test that a ring-3 image is built with the codegen flags of its own ISA:

  1. sdk_cargo.py refuses a configuration of another ISA, before it runs cargo;
  2. for every (ISA of .config) x (ARCH of `make check`), the configuration each
     SDK image of `make -n check` is built from is an expansion of that image's
     ISA.

    python3 tools/build/test_user_isa.py      (exit 0 = all pass)
"""

import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

REPO = azos_tools.ROOT
ISAS = ("riscv64", "aarch64", "x86_64")
FAILS = []


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
    out = os.path.join(tmp, "out")
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


def main():
    with tempfile.TemporaryDirectory() as tmp:
        sdk_cargo_refuses(tmp)
        image_configs_follow_arch(tmp)
    print("test_user_isa:", "FAIL" if FAILS else "ok")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

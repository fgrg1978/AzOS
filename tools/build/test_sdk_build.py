#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_sdk_build.py: the SDK is keyed by what changes its bytes.

    python3 tools/build/test_sdk_build.py            keys only (no build)
    python3 tools/build/test_sdk_build.py --build    also build the riscv64 SDK twice and once more after a change

The key (tools/build/sdk_cargo.py sdk_key) covers the toolchain, the port layer,
the target and the Kconfig values std is built with, and nothing else:

  1. the three ISAs have three keys, and the key is stable between runs;
  2. a Kconfig value that changes std's bytes (an allocator knob, the ISA level a
     program is built for) changes the key; one that does not (the log level) leaves it;
  3. a std program refuses an SDK whose key is not the current one;
  4. with --build: `sdk_build.py` twice builds nothing the second time, and builds
     again after a symbol that changes std.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "../lib"))
import sdk_cargo  # noqa: E402

ROOT = sdk_cargo.ROOT
FAILS = []
DEFCONFIGS = {
    "riscv64": "config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config",
    "aarch64": "config/defconfigs/robot-sbc-aarch64-dev+qemu+linux+gui.config",
    "x86_64": "config/defconfigs/robot-sbc-x86_64-dev+qemu+linux+gui.config",
}


def check(cond, what):
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        FAILS.append(what)


def expand(tmp, isa, name, edits=()):
    """The ISA's development configuration, expanded, with `edits` (CONFIG_X=v lines) applied."""
    path = os.path.join(tmp, name)
    with open(os.path.join(ROOT, DEFCONFIGS[isa]), encoding="utf-8") as f:
        lines = f.read().splitlines()
    syms = {e.split("=")[0] for e in edits}
    lines = [ln for ln in lines if ln.split("=")[0] not in syms]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines + list(edits)) + "\n")
    r = subprocess.run([sys.executable, "-m", "olddefconfig"], cwd=ROOT, env=dict(os.environ, KCONFIG_CONFIG=path),
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"olddefconfig failed: {r.stderr}")
    return path


def value(path, sym):
    with open(path, encoding="utf-8") as f:
        m = re.search(rf"^CONFIG_{sym}=(.*)$", f.read(), re.M)
    return m.group(1) if m else None


def main():
    build = "--build" in sys.argv
    tmp = tempfile.mkdtemp(prefix="sdk-key-")
    try:
        base = {isa: expand(tmp, isa, f"{isa}.config") for isa in DEFCONFIGS}
        keys = {isa: sdk_cargo.sdk_key(isa, base[isa], 4096) for isa in DEFCONFIGS}
        check(len(set(keys.values())) == 3, "the three ISAs have three SDK keys")
        check(keys["riscv64"] == sdk_cargo.sdk_key("riscv64", base["riscv64"], 4096), "the key is the same on a second run")
        check(keys["aarch64"] != sdk_cargo.sdk_key("aarch64", base["aarch64"], 16384), "the aarch64 granule is in the key")

        quarantine = int(value(base["riscv64"], "USER_ALLOC_QUARANTINE_KB"))
        knob = expand(tmp, "riscv64", "knob.config", [f"CONFIG_USER_ALLOC_QUARANTINE_KB={quarantine + 64}"])
        check(sdk_cargo.sdk_key("riscv64", knob, 4096) != keys["riscv64"], "an allocator knob std is built with changes the key")
        level = expand(tmp, "riscv64", "level.config", ["CONFIG_LOG_LEVEL_WARN=y"])
        check(value(level, "LOG_LEVEL_WARN") == "y" and sdk_cargo.sdk_key("riscv64", level, 4096) == keys["riscv64"],
              "the kernel log level leaves the key alone")
        isa = expand(tmp, "riscv64", "isa.config", ["CONFIG_RV_ZBB_REQUIRE=y"])
        check(sdk_cargo.user_isa_flags("riscv64", isa) != sdk_cargo.user_isa_flags("riscv64", base["riscv64"])
              and sdk_cargo.sdk_key("riscv64", isa, 4096) != keys["riscv64"],
              "a codegen extension a program is built with (RV_ZBB_REQUIRE) changes the key")

        stale = os.path.join(tmp, "sdk")
        os.makedirs(stale)
        with open(os.path.join(stale, "key"), "w", encoding="utf-8") as f:
            f.write("0" * 64 + "\n")
        r = subprocess.run([sys.executable, os.path.join(HERE, "sdk_cargo.py"), "--isa", "riscv64", "--kconfig", base["riscv64"],
                            "--sdk", stale, "--", "build", "--release", "--manifest-path", "userspace/services/why/Cargo.toml"],
                           cwd=ROOT, capture_output=True, text=True)
        check(r.returncode != 0 and "run make sdk" in r.stderr, "a std program refuses an SDK of another key")

        if build:
            out = os.path.join(tmp, "out")
            run = lambda cfg: subprocess.run([sys.executable, os.path.join(HERE, "sdk_build.py"), "--isa", "riscv64", "--kconfig", cfg,
                                              "--out", out], cwd=ROOT, capture_output=True, text=True)
            r1 = run(base["riscv64"])
            check(r1.returncode == 0 and "built" in r1.stdout, f"sdk_build builds the SDK ({r1.stdout.strip()[-60:]})")
            lib = os.path.join(out, "sysroot", "lib", "rustlib", "riscv64imac-unknown-azos", "lib")
            have = sorted(os.listdir(lib)) if os.path.isdir(lib) else []
            check(any(n.startswith("libstd-") for n in have) and any(n.startswith("libcore-") for n in have),
                  f"the sysroot holds std and core ({len(have)} libraries)")
            stamp = os.stat(os.path.join(lib, [n for n in have if n.startswith("libstd-")][0])).st_mtime_ns if have else 0
            r2 = run(base["riscv64"])
            have2 = sorted(os.listdir(lib)) if os.path.isdir(lib) else []
            check(r2.returncode == 0 and "up to date" in r2.stdout and "Compiling" not in r2.stderr + r2.stdout
                  and have2 == have and os.stat(os.path.join(lib, [n for n in have2 if n.startswith("libstd-")][0])).st_mtime_ns == stamp,
                  "the second build builds nothing")
            r3 = run(knob)
            check(r3.returncode == 0 and "built" in r3.stdout, "a changed allocator knob builds the SDK again")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"{len(FAILS)} failed" if FAILS else "all pass")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

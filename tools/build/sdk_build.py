#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""sdk_build.py: build the native SDK of one ISA.

    sdk_build.py --isa riscv64 --kconfig $AZOS_OUT/build/qemu-dev.config --out $AZOS_OUT/sdk/riscv64

The SDK is a sysroot for `<isa>-unknown-azos`: `core`, `alloc`, `std`,
`panic_abort` and their dependencies, built with -Zbuild-std from the port in
sdk/std and crates/core/stdrt, under the target in sdk/targets. A std program is
then built against it (`sdk_cargo.py --sdk <out>`) and compiles only its own
crates. `<out>/key` names what the sysroot was built from: the toolchain, the
port layer, the target and the Kconfig values that change its bytes
(sdk_cargo.py sdk_key). Run with the same key it builds nothing; with another,
it rebuilds.
"""
import argparse
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402,F401
import sdk_cargo  # noqa: E402

ROOT = sdk_cargo.ROOT
DRIVER = "sdk/driver/Cargo.toml"


def sysroot_lib(sdk_dir, target):
    return os.path.join(sdk_dir, "sysroot", "lib", "rustlib", target, "lib")


def current(sdk_dir, key):
    try:
        with open(os.path.join(sdk_dir, "key"), encoding="utf-8") as f:
            return f.read().strip() == key
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--isa", required=True, choices=sorted(sdk_cargo.TARGETS))
    ap.add_argument("--kconfig", required=True)
    ap.add_argument("--page-size", type=int, default=4096)
    ap.add_argument("--out", required=True, help="the SDK directory")
    a = ap.parse_args()
    OUT_DIR = os.path.abspath(a.out)
    target = sdk_cargo.TARGETS[a.isa]
    key = sdk_cargo.sdk_key(a.isa, os.path.join(ROOT, a.kconfig), a.page_size)
    if current(OUT_DIR, key):
        # make orders the SDK's key file after its sources by mtime: say it is still current.
        os.utime(os.path.join(OUT_DIR, "key"))
        print(f"[SDK] {a.isa}: up to date ({key[:12]})")
        return
    os.makedirs(OUT_DIR, exist_ok=True)
    try:
        os.remove(os.path.join(OUT_DIR, "key"))
    except FileNotFoundError:
        pass
    cmd = [sys.executable, "tools/build/sdk_cargo.py", "--isa", a.isa, "--kconfig", a.kconfig,
           "--page-size", str(a.page_size), "--target-dir", os.path.join(OUT_DIR, "target"),
           "--", "build", "--release", "--manifest-path", DRIVER]
    subprocess.run(cmd, cwd=ROOT, check=True)

    deps = os.path.join(OUT_DIR, "target", target, "release", "deps")
    lib = sysroot_lib(OUT_DIR, target)
    shutil.rmtree(os.path.join(OUT_DIR, "sysroot"), ignore_errors=True)
    os.makedirs(lib)
    for name in sorted(os.listdir(deps)):
        if name.endswith(".rlib") and not name.startswith("libazos_sdk_driver"):
            shutil.copy2(os.path.join(deps, name), lib)
    # rustc finds rust-lld, the linker the targets name, under the sysroot it is given.
    host = subprocess.run(["rustc", "-vV"], cwd=ROOT, check=True, capture_output=True, text=True).stdout
    host = [ln.split()[1] for ln in host.splitlines() if ln.startswith("host:")][0]
    real = subprocess.run(["rustc", "--print", "sysroot"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    hostdir = os.path.join(OUT_DIR, "sysroot", "lib", "rustlib", host)
    os.symlink(os.path.join(real, "lib", "rustlib", host), hostdir)
    with open(os.path.join(OUT_DIR, "key"), "w", encoding="utf-8") as f:
        f.write(key + "\n")
    print(f"[SDK] {a.isa}: built {len(os.listdir(lib))} libraries ({key[:12]})")


if __name__ == "__main__":
    main()

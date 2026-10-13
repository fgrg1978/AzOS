#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""sdk_cargo.py: run cargo for the native SDK target of one ISA.

    sdk_cargo.py --isa riscv64 --kconfig build/qemu-dev.config -- build --release --manifest-path userspace/services/why/Cargo.toml

builds a std program for `riscv64imac-unknown-azos` (aarch64, x86_64 likewise):
`-Zbuild-std` builds `std` from the tree tools/sdk_std.py assembles (the port
in sdk/std plus crates/core/stdrt), for the target in sdk/targets, linked with
sdk/ld/user_<isa>.ld. Everything configurable comes from the expanded Kconfig
named by `--kconfig` and nothing else: the ISA baseline flags
(tools/kconfig_to_cargo.py --user-rustflags) and the std port layer's knobs
(--sdk-env: the ring-3 allocator and the default thread stack).

The binary is built through userspace/rustc_stable_metadata.py like every
ring-3 ELF, so its bytes depend on source and toolchain only: the kernel binds
an image's profile to its digest.
"""
import argparse
import hashlib
import os
import subprocess
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
TARGETS = {"riscv64": "riscv64imac-unknown-azos", "aarch64": "aarch64-unknown-azos", "x86_64": "x86_64-unknown-azos"}


def out(*cmd):
    return subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def toml_array(items):
    return "[" + ",".join('"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"' for s in items) + "]"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--isa", required=True, choices=sorted(TARGETS))
    ap.add_argument("--kconfig", required=True, help="the expanded .config the images are built from")
    ap.add_argument("--page-size", type=int, default=4096, help="aarch64 translation granule (4096, 16384, 65536)")
    ap.add_argument("--target-dir", help="cargo target dir (shared by SDK programs: std is built once)")
    ap.add_argument("--build-std", default="std,panic_abort",
                    help="the crates -Zbuild-std builds (`core` type-checks the std port layer alone, on the stock library)")
    ap.add_argument("cargo", nargs=argparse.REMAINDER, help="-- <cargo subcommand and arguments>")
    a = ap.parse_args()
    cargo_args = a.cargo[1:] if a.cargo[:1] == ["--"] else a.cargo
    if not cargo_args:
        ap.error("no cargo command")
    if a.page_size != 4096 and a.isa != "aarch64":
        ap.error("--page-size other than 4096 is an aarch64 granule")
    kconfig = os.path.realpath(os.path.join(ROOT, a.kconfig))
    if not os.path.isfile(kconfig):
        sys.exit(f"sdk_cargo: {a.kconfig}: no such file (make creates it)")
    target = TARGETS[a.isa]
    spec = os.path.join(ROOT, "sdk", "targets", target + ".json")

    env = dict(os.environ)
    if "std" in a.build_std.split(","):
        env["__CARGO_TESTS_ONLY_SRC_ROOT"] = out(sys.executable, "tools/sdk_std.py")
    for line in out(sys.executable, "tools/kconfig_to_cargo.py", "--sdk-env", kconfig).splitlines():
        k, v = line.split("=", 1)
        env[k] = v
    if a.page_size != 4096:
        env["AZOS_PAGE_SIZE"] = str(a.page_size)
    else:
        env.pop("AZOS_PAGE_SIZE", None)
    wrapper = os.path.join(ROOT, "userspace", "rustc_stable_metadata.py")
    with open(wrapper, "rb") as f:
        tag = hashlib.sha256(f.read()).hexdigest()[:12]
    env["RUSTC_WRAPPER"] = wrapper
    env.pop("RUSTFLAGS", None)
    env.pop("CARGO_BUILD_RUSTFLAGS", None)

    # The riscv64 target carries its level; the others pass it with the flags.
    isa_flags = out(sys.executable, "tools/kconfig_to_cargo.py", "--user-rustflags", "--toml",
                    *(["--skip-base"] if a.isa == "riscv64" else []), kconfig)
    flags = ["--cfg=azos_stable_metadata_" + tag, "-C", "link-arg=-T" + os.path.join(ROOT, "sdk", "ld", f"user_{a.isa}.ld")]
    if a.isa != "riscv64":
        flags += ["-C", f"link-arg=-zmax-page-size={a.page_size}", "-C", "link-arg=--no-eh-frame-hdr"]
    if a.isa == "x86_64":
        flags += ["-C", "link-arg=-znorelro"]
    rustflags = toml_array(flags)
    if isa_flags:
        rustflags = rustflags[:-1] + "," + isa_flags + "]"

    cmd = ["cargo", cargo_args[0], f"-Zbuild-std={a.build_std}", "-Zbuild-std-features=compiler-builtins-mem", "-Zjson-target-spec",
           "--config", f"target.{target}.rustflags={rustflags}", "--target", spec]
    if a.target_dir:
        cmd += ["--target-dir", a.target_dir]
    cmd += cargo_args[1:]
    os.execvpe("cargo", cmd, env)


main()

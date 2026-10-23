#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""sdk_cargo.py: run cargo for the native SDK target of one ISA.

    sdk_cargo.py --isa riscv64 --kconfig $AZOS_OUT/build/qemu-dev.config -- build --release --manifest-path userspace/services/why/Cargo.toml

builds a std program for `riscv64imac-unknown-azos` (aarch64, x86_64 likewise):
`-Zbuild-std` builds `std` from the tree tools/sdk_std.py assembles (the port
in sdk/std plus crates/core/stdrt), for the target in sdk/targets, which carries
the image layout too (no linker script). Everything configurable comes from the expanded Kconfig
named by `--kconfig` and nothing else: the ISA baseline flags
(tools/kconfig_to_cargo.py --user-rustflags) and the std port layer's knobs
(--sdk-env: the ring-3 allocator and the default thread stack).

A program with crates.io dependencies passes `--vendored`: crates.io is then
replaced by the directory source third_party/vendor, offline and locked, for that
invocation only (the kernel workspace's cargo config never sees it).

The binary is built through userspace/rustc_stable_metadata.py like every
ring-3 ELF, so its bytes depend on source and toolchain only: the kernel binds
an image's profile to its digest.
"""
import argparse
import hashlib
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import azos_tools  # noqa: E402

ROOT = os.path.realpath(azos_tools.ROOT)
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
    ap.add_argument("--vendored", action="store_true",
                    help="resolve crates.io through third_party/vendor, offline and locked (the programs with registry dependencies)")
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
    # -Zbuild-std takes std's path dependencies (azos_stdrt, and through it
    # azos_abi, azos_ualloc and libsys's pure.rs) as fixed sources: an edit to
    # one alone left the old rlib in the shared target dir, and a crate built
    # against it failed to find the new item. Their digest in the flags makes a
    # change rebuild std; an unchanged tree keeps it.
    src = hashlib.sha256()
    for d in ("crates/core/abi", "crates/core/stdrt", "userspace/lib/ualloc"):
        for dp, _, names in sorted(os.walk(os.path.join(ROOT, d))):
            for n in sorted(names):
                if n.endswith((".rs", ".toml")) and " " not in n:
                    q = os.path.join(dp, n)
                    src.update(q[len(ROOT):].encode())
                    with open(q, "rb") as f:
                        src.update(f.read())
    with open(os.path.join(ROOT, "crates", "core", "libsys", "src", "pure.rs"), "rb") as f:
        src.update(f.read())
    # `azos_std`: the program's entry is stdrt's `_azos_entry`, not libsys's
    # (crates/core/libsys/src/lib.rs), and ualloc leaves the engine to stdrt.
    flags = ["--cfg=azos_stable_metadata_" + tag, "--cfg=azos_std_src_" + src.hexdigest()[:12], "--cfg=azos_std"]
    if a.page_size != 4096:
        flags += ["-C", f"link-arg=-zmax-page-size={a.page_size}"]
    if a.vendored:
        # getrandom 0.4 (rand 0.10, quinn-proto) has no backend for target_os = "azos": the program provides one.
        flags += ["--cfg=getrandom_backend=\"custom\""]
    rustflags = toml_array(flags)
    if isa_flags:
        rustflags = rustflags[:-1] + "," + isa_flags + "]"

    cmd = ["cargo", cargo_args[0], f"-Zbuild-std={a.build_std}", "-Zbuild-std-features=compiler-builtins-mem", "-Zjson-target-spec",
           "--config", f"target.{target}.rustflags={rustflags}", "--target", spec]
    if a.vendored:
        # Scoped to this invocation: the kernel workspace's .cargo/config.toml never sees it. The vendor tree
        # also holds the std workspace's own dependencies (-Zbuild-std resolves them through the same
        # replacement); userspace/lib/tls-probe/vendor.py makes it.
        cmd += ["--config", "source.crates-io.replace-with=\"azos-vendor\"",
                "--config", f"source.azos-vendor.directory=\"{os.path.join(ROOT, 'third_party', 'vendor')}\"",
                "--locked", "--offline"]
    if a.target_dir:
        cmd += ["--target-dir", a.target_dir]
    cmd += cargo_args[1:]
    os.execvpe("cargo", cmd, env)


main()

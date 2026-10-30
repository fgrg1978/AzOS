#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""sdk_cargo.py: run cargo for the native SDK target of one ISA.

    sdk_cargo.py --isa riscv64 --kconfig $AZOS_OUT/build/qemu-dev.config -- build --release --manifest-path userspace/services/why/Cargo.toml

builds a std program for `riscv64imac-unknown-azos` (aarch64, x86_64 likewise):
`-Zbuild-std` builds `std` from the tree tools/build/sdk_std.py assembles (the port
in sdk/std plus crates/core/stdrt), for the target in sdk/targets, which carries
the image layout too (no linker script). Everything configurable comes from the expanded Kconfig
named by `--kconfig` and nothing else: the ISA baseline flags
(tools/build/kconfig_to_cargo.py --user-rustflags) and the std port layer's knobs
(--sdk-env: the ring-3 allocator and the default thread stack).

`--sdk <dir>` builds against the SDK `make sdk` made there (tools/build/sdk_build.py:
a sysroot with `std` already built) instead of building `std` with the program; it
refuses an SDK whose key is not the one the current sources, toolchain and Kconfig give.

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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = os.path.realpath(azos_tools.ROOT)
TARGETS = {"riscv64": "riscv64imac-unknown-azos", "aarch64": "aarch64-unknown-azos", "x86_64": "x86_64-unknown-azos"}


def out(*cmd):
    return subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def config_isa(path):
    """The ISA an expanded .config selects (riscv64 when no other ARCH_ symbol is on)."""
    with open(path, encoding="utf-8") as f:
        text = f.read().splitlines()
    for isa in ("aarch64", "x86_64"):
        if f"CONFIG_ARCH_{isa.upper()}=y" in text:
            return isa
    return "riscv64"


def toml_array(items):
    return "[" + ",".join('"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"' for s in items) + "]"


WRAPPER = os.path.join(ROOT, "userspace", "rustc_stable_metadata.py")


def file_digest(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def wrapper_tag():
    return file_digest(WRAPPER)[:12]


def tree_digest(h, paths):
    """Feed every .rs/.toml/.json/.py file under `paths` (a file or a directory, relative to the tree) to `h`."""
    for p in paths:
        full = os.path.join(ROOT, p)
        walk = [(os.path.dirname(full), [], [os.path.basename(full)])] if os.path.isfile(full) else sorted(os.walk(full))
        for dp, _, names in walk:
            for n in sorted(names):
                if n.endswith((".rs", ".toml", ".json", ".py")) and " " not in n:
                    q = os.path.join(dp, n)
                    h.update(q[len(ROOT):].encode())
                    with open(q, "rb") as f:
                        h.update(f.read())


def port_digest():
    """The sources -Zbuild-std takes as fixed: the port layer and what it calls."""
    h = hashlib.sha256()
    tree_digest(h, ["crates/core/abi", "crates/core/stdrt", "userspace/lib/ualloc", "crates/core/libsys/src/pure.rs"])
    return h.hexdigest()[:12]


def pinned_toolchain():
    with open(os.path.join(ROOT, "rust-toolchain.toml"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("channel"):
                return line.split("=", 1)[1].strip().strip('"')
    sys.exit("sdk_cargo: rust-toolchain.toml names no channel")


def sdk_env(kconfig):
    return out(sys.executable, "tools/build/kconfig_to_cargo.py", "--sdk-env", kconfig).splitlines()


def user_isa_flags(isa, kconfig):
    """The ISA baseline, as the inside of a TOML array; the riscv64 target carries its level, the others pass it."""
    return out(sys.executable, "tools/build/kconfig_to_cargo.py", "--user-rustflags", "--toml",
               *(["--skip-base"] if isa == "riscv64" else []), kconfig)


def sdk_key(isa, kconfig, page_size):
    """What the SDK's bytes follow: the toolchain, the port and its assembly, the target and
    the Kconfig values std is built with (the ISA baseline, the runtime knobs, the granule)."""
    h = hashlib.sha256()
    for part in (out("rustc", "-vV"), isa, str(page_size), user_isa_flags(isa, kconfig), "\n".join(sdk_env(kconfig)),
                 wrapper_tag(), port_digest(), file_digest(os.path.join(ROOT, "third_party", "VENDOR_PIN"))):
        h.update(part.encode() + b"\0")
    tree_digest(h, ["sdk/std", f"sdk/targets/{TARGETS[isa]}.json", "sdk/driver", "tools/build/sdk_std.py", "tools/build/sdk_cargo.py"])
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--isa", required=True, choices=sorted(TARGETS))
    ap.add_argument("--kconfig", required=True, help="the expanded .config the images are built from")
    ap.add_argument("--page-size", type=int, default=4096, help="aarch64 translation granule (4096, 16384, 65536)")
    ap.add_argument("--target-dir", help="cargo target dir (shared by SDK programs: std is built once)")
    ap.add_argument("--build-std", default="std,panic_abort",
                    help="the crates -Zbuild-std builds (`core` type-checks the std port layer alone, on the stock library)")
    ap.add_argument("--sdk", help="the SDK directory `make sdk` made (a sysroot with std built): build against it")
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
    if config_isa(kconfig) != a.isa:
        sys.exit(f"sdk_cargo: --isa {a.isa} but {a.kconfig} selects {config_isa(kconfig)}: its codegen flags are not {a.isa}'s")
    target = TARGETS[a.isa]
    spec = os.path.join(ROOT, "sdk", "targets", target + ".json")

    sdk = os.path.realpath(a.sdk) if a.sdk else None
    key = sdk_key(a.isa, kconfig, a.page_size)
    if sdk:
        try:
            with open(os.path.join(sdk, "key"), encoding="utf-8") as f:
                built = f.read().strip()
        except OSError:
            built = None
        if built != key:
            sys.exit(f"sdk_cargo: {a.sdk} is not the {a.isa} SDK of the current sources and configuration "
                     f"(its key {built and built[:12]}, now {key[:12]}): run make sdk")

    env = dict(os.environ)
    if not sdk and "std" in a.build_std.split(","):
        env["__CARGO_TESTS_ONLY_SRC_ROOT"] = out(sys.executable, "tools/build/sdk_std.py")
    for line in sdk_env(kconfig):
        k, v = line.split("=", 1)
        env[k] = v
    if a.page_size != 4096:
        env["AZOS_PAGE_SIZE"] = str(a.page_size)
    else:
        env.pop("AZOS_PAGE_SIZE", None)
    env["RUSTC_WRAPPER"] = WRAPPER
    env.pop("RUSTFLAGS", None)
    env.pop("CARGO_BUILD_RUSTFLAGS", None)

    # `azos_std`: the program's entry is stdrt's `_azos_entry`, not libsys's
    # (crates/core/libsys/src/lib.rs), and ualloc leaves the engine to stdrt.
    flags = ["--cfg=azos_stable_metadata_" + wrapper_tag()]
    if sdk:
        # The SDK's key in the flags rebuilds a program when the SDK changes.
        flags += ["--cfg=azos_sdk_" + key[:12], "--sysroot=" + os.path.join(sdk, "sysroot")]
    else:
        # -Zbuild-std takes std's path dependencies as fixed sources: an edit to one
        # alone left the old rlib in the shared target dir; their digest in the flags
        # makes a change rebuild std.
        flags += ["--cfg=azos_std_src_" + port_digest()]
    flags += ["--cfg=azos_std"]
    if a.page_size != 4096:
        flags += ["-C", f"link-arg=-zmax-page-size={a.page_size}"]
    if a.vendored:
        # getrandom 0.4 (rand 0.10, quinn-proto) has no backend for target_os = "azos": the program provides one.
        flags += ["--cfg=getrandom_backend=\"custom\""]
    rustflags = toml_array(flags)
    isa_flags = user_isa_flags(a.isa, kconfig)
    if isa_flags:
        rustflags = rustflags[:-1] + "," + isa_flags + "]"

    cmd = ["cargo", cargo_args[0]]
    if not sdk:
        cmd += [f"-Zbuild-std={a.build_std}", "-Zbuild-std-features=compiler-builtins-mem"]
    cmd += ["-Zjson-target-spec", "--config", f"target.{target}.rustflags={rustflags}", "--target", spec]
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
    if sdk:
        # The tree's cargo config (.cargo/config.toml) builds core and alloc for the no_std
        # programs, and cargo cannot be told to drop it: the SDK has them, so cargo runs
        # where that config is not found, with the tree's pinned toolchain.
        cmd.insert(1, "+" + pinned_toolchain())
        cmd = [os.path.join(ROOT, p) if i and cmd[i - 1] == "--manifest-path" else p for i, p in enumerate(cmd)]
        os.chdir(sdk)
    os.execvpe("cargo", cmd, env)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""sdk_std.py: assemble the Rust library source `-Zbuild-std` builds `std` from
for `*-unknown-azos`.

The toolchain pinned by rust-toolchain.toml ships its library source (the
`rust-src` component). `std` has no `azos` platform, so this tool copies that
source to `build/sdk/rust-src/library` and adds the port:

  * `sdk/std/sys/**` (the files of the port) is copied into
    `library/std/src/sys/`;
  * the dispatch sites (the `cfg_select!` blocks that choose a platform's
    module) get an `azos` arm: the EDITS table below, each an exact one-time
    replacement that fails loudly when the pinned library text moved;
  * `library/std/Cargo.toml` gets the dependency on `crates/core/stdrt`.

The result is handed to cargo with `__CARGO_TESTS_ONLY_SRC_ROOT=<printed
path>`, the environment variable cargo's own tests use to build `std` from a
source tree other than the sysroot's. It is an internal cargo hook, not a
supported interface: it is tied to the toolchain in rust-toolchain.toml, and a
toolchain bump is the moment to re-check the EDITS (the tool refuses rather
than guess). The path must be canonical (no `..`), which `os.path.realpath`
makes it.

    python3 tools/sdk_std.py            # assemble if stale, print the path
    python3 tools/sdk_std.py --check    # exit 1 if the edits do not apply

The assembled tree is a build product (`build/`), never committed.
"""
import hashlib
import os
import shutil
import subprocess
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
OVERLAY = os.path.join(ROOT, "sdk", "std", "sys")
DEST = os.path.join(ROOT, "build", "sdk", "rust-src", "library")
STDRT = os.path.join(ROOT, "crates", "core", "stdrt")

AZOS_ARM = "    target_os = \"azos\" => {\n        mod azos;\n        pub use azos::*;\n    }\n"

# (file under library/std, old text, new text); `old` must occur exactly once.
EDITS = [
    # std's build.rs lists the targets std is supported on; an unlisted one gets
    # the `restricted_std` gate.
    ("build.rs", "        || target_os == \"motor\"\n", "        || target_os == \"motor\"\n        || target_os == \"azos\"\n"),
    ("src/sys/pal/mod.rs", "    target_os = \"motor\" => {\n",
     "    target_os = \"azos\" => {\n        mod azos;\n        pub use self::azos::*;\n    }\n    target_os = \"motor\" => {\n"),
    ("src/sys/alloc/mod.rs", "    target_os = \"motor\" => {\n        mod motor;\n    }\n",
     "    target_os = \"azos\" => {\n        mod azos;\n    }\n    target_os = \"motor\" => {\n        mod motor;\n    }\n"),
    # args and env: the shared `common` module and the arm.
    ("src/sys/args/mod.rs", "    target_os = \"motor\",\n    target_os = \"uefi\",\n    target_os = \"wasi\",\n    target_os = \"xous\",\n))]\nmod common;",
     "    target_os = \"motor\",\n    target_os = \"azos\",\n    target_os = \"uefi\",\n    target_os = \"wasi\",\n    target_os = \"xous\",\n))]\nmod common;"),
    ("src/sys/args/mod.rs", "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::*;\n    }\n",
     AZOS_ARM + "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::*;\n    }\n"),
    ("src/sys/env/mod.rs", "    target_os = \"motor\",\n    all(target_vendor = \"fortanix\", target_env = \"sgx\"),\n    target_os = \"solid_asp3\",\n    target_os = \"uefi\",\n    target_os = \"wasi\",\n    target_os = \"xous\",\n))]\nmod common;",
     "    target_os = \"motor\",\n    target_os = \"azos\",\n    all(target_vendor = \"fortanix\", target_env = \"sgx\"),\n    target_os = \"solid_asp3\",\n    target_os = \"uefi\",\n    target_os = \"wasi\",\n    target_os = \"xous\",\n))]\nmod common;"),
    ("src/sys/env/mod.rs", "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::*;\n    }\n",
     AZOS_ARM + "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::*;\n    }\n"),
    ("src/sys/stdio/mod.rs", "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::*;\n    }\n",
     AZOS_ARM + "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::*;\n    }\n"),
    ("src/sys/thread/mod.rs", "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::*;\n    }\n",
     AZOS_ARM + "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::*;\n    }\n"),
    ("src/sys/time/mod.rs", "    target_os = \"motor\" => {\n        use moto_rt::time as imp;\n    }\n",
     "    target_os = \"azos\" => {\n        mod azos;\n        use azos as imp;\n    }\n    target_os = \"motor\" => {\n        use moto_rt::time as imp;\n    }\n"),
    ("src/sys/random/mod.rs", "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::fill_bytes;\n    }\n",
     "    target_os = \"azos\" => {\n        mod azos;\n        pub use azos::fill_bytes;\n    }\n    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::fill_bytes;\n    }\n"),
    # No errno: the generic error mapping (every code is "uncategorized").
    ("src/sys/io/error/mod.rs", "    any(\n        target_os = \"vexos\",\n", "    any(\n        target_os = \"azos\",\n        target_os = \"vexos\",\n"),
    # Thread-local keys, like motor's (racy lazy key over a platform key).
    ("src/sys/thread_local/mod.rs", "        target_os = \"motor\" => {\n            mod racy;\n",
     "        target_os = \"azos\" => {\n            mod racy;\n            mod azos;\n            pub(super) use racy::LazyKey;\n            pub(super) use azos::{Key, get, set};\n            use azos::{create, destroy};\n        }\n        target_os = \"motor\" => {\n            mod racy;\n"),
]
# The five futex-based locks list the platforms whose futex module they use.
for lock in ("mutex", "condvar", "once", "rwlock", "thread_parking"):
    EDITS.append((f"src/sys/sync/{lock}/mod.rs", "target_os = \"motor\",\n", "target_os = \"motor\",\n        target_os = \"azos\",\n"))

CARGO_ANCHOR = "[target.'cfg(target_os = \"motor\")'.dependencies]\n"


def sysroot_src():
    out = subprocess.run(["rustc", "--print", "sysroot"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    src = os.path.join(out, "lib", "rustlib", "src", "rust", "library")
    if not os.path.isdir(src):
        sys.exit("sdk_std: the pinned toolchain has no rust-src component (rustup component add rust-src)")
    ver = subprocess.run(["rustc", "-vV"], cwd=ROOT, check=True, capture_output=True, text=True).stdout
    return src, ver


def overlay_files():
    for d, _, names in sorted(os.walk(OVERLAY)):
        for n in sorted(names):
            yield os.path.join(d, n)


def stamp(ver):
    h = hashlib.sha256(ver.encode())
    for p in [__file__] + list(overlay_files()):
        h.update(p[len(ROOT):].encode())
        with open(p, "rb") as f:
            h.update(f.read())
    h.update(STDRT.encode())
    return h.hexdigest()


def apply_edits(dest):
    for rel, old, new in EDITS:
        p = os.path.join(dest, "std", rel)
        with open(p) as f:
            s = f.read()
        if s.count(old) != 1:
            sys.exit(f"sdk_std: {rel}: expected the dispatch text exactly once, found {s.count(old)} (toolchain moved?):\n{old}")
        with open(p, "w") as f:
            f.write(s.replace(old, new))
    p = os.path.join(dest, "std", "Cargo.toml")
    with open(p) as f:
        s = f.read()
    if s.count(CARGO_ANCHOR) != 1:
        sys.exit("sdk_std: std/Cargo.toml: the motor dependency block moved")
    dep = ("[target.'cfg(target_os = \"azos\")'.dependencies]\n"
           f"azos_stdrt = {{ path = \"{STDRT}\", features = ['rustc-dep-of-std'], public = true }}\n\n")
    with open(p, "w") as f:
        f.write(s.replace(CARGO_ANCHOR, dep + CARGO_ANCHOR))
    for src in overlay_files():
        rel = os.path.relpath(src, OVERLAY)
        out = os.path.join(dest, "std", "src", "sys", rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copyfile(src, out)


def main():
    src, ver = sysroot_src()
    want = stamp(ver)
    stampf = os.path.join(os.path.dirname(DEST), "stamp")
    if "--check" not in sys.argv[1:]:
        try:
            with open(stampf) as f:
                if f.read() == want and os.path.isdir(DEST):
                    print(DEST)
                    return
        except OSError:
            pass
    tmp = DEST + ".new"
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src, tmp)
    apply_edits(tmp)
    if "--check" in sys.argv[1:]:
        shutil.rmtree(tmp)
        print("sdk_std: the edits apply to the pinned library")
        return
    shutil.rmtree(DEST, ignore_errors=True)
    os.makedirs(os.path.dirname(DEST), exist_ok=True)
    os.rename(tmp, DEST)
    with open(stampf, "w") as f:
        f.write(want)
    print(DEST)


main()

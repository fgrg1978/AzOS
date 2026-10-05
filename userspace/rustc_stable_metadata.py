#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""rustc wrapper (`RUSTC_WRAPPER`) for the ring-3 userspace builds.

Every userspace ELF the disk image ships is bound by its SHA-256 to a seccomp
image profile (`crates/core/sched/src/seccomp.rs`, `build/image_hashes.rs`), so its
bytes must depend on source and toolchain only. Without this wrapper they also
depended on the directory the tree was checked out in.

Why: each userspace crate is its own cargo workspace, and `crates/core/libsys` (with
`crates/core/abi` behind it) is a path dependency outside that workspace. For such a
package cargo hashes the absolute source path into the `-C metadata` it passes
to rustc; rustc derives the crate disambiguator from it, which is part of every
mangled symbol, and items are ordered by names that carry it. The same
brain_client sources built in two directories differed in `.strtab`, and with
symbols stripped in 2975 bytes of `.text` (measured 2026-09-14, after gate 40
refused a brain_client rebuilt in its snapshot directory).

What: the `-C metadata=<hash>` value is replaced by one derived from the crate
name, its version (`CARGO_PKG_VERSION`, which cargo sets for every crate it
compiles, build-std's included; empty if unset), the crate type, the target and
the `--cfg` flags: the inputs that tell two units of one build apart, and never
anything that names a directory. The version is in the key so that two versions
of one crate in a build cannot collide. Every other argument is passed to rustc
unchanged.

It refuses, exiting non-zero and naming the crate, rather than fall back to
cargo's path-derived value: when a compilation (`--crate-name` given, not a
`--print` probe) carries no `-C metadata`, or carries more than one. An
invocation with neither a crate name nor a metadata argument (cargo's
`rustc -vV` probe) or a `--print` probe is passed through as is.
`tests/host/seccomp-tests` runs this script with a stand-in rustc and checks all of
the above.
"""
import hashlib
import os
import sys


def refuse(message):
    sys.stderr.write("rustc_stable_metadata.py: " + message + "\n")
    sys.exit(2)


def unit_facts(args):
    """(crate name, crate type, target, cfgs, is a --print probe) of one invocation."""
    name = ctype = target = ""
    cfgs = []
    printing = False
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a == "--crate-name":
            name = nxt
        elif a.startswith("--crate-name="):
            name = a.split("=", 1)[1]
        elif a == "--crate-type":
            ctype = nxt
        elif a.startswith("--crate-type="):
            ctype = a.split("=", 1)[1]
        elif a == "--target":
            target = nxt
        elif a.startswith("--target="):
            target = a.split("=", 1)[1]
        elif a == "--cfg":
            cfgs.append(nxt)
        elif a == "--print" or a.startswith("--print="):
            printing = True
        i += 1
    return name, ctype, target, cfgs, printing


def is_metadata(args, i):
    a = args[i]
    return (a == "-C" and i + 1 < len(args) and args[i + 1].startswith("metadata=")) or a.startswith(
        "-Cmetadata="
    )


def main():
    rustc, args = sys.argv[1], sys.argv[2:]
    name, ctype, target, cfgs, printing = unit_facts(args)
    count = sum(1 for i in range(len(args)) if is_metadata(args, i))
    if count > 1:
        refuse(f"cargo passed -C metadata {count} times for crate {name or '?'}: not guessing which one names the unit")
    if count == 0:
        if name and not printing:
            refuse(
                f"cargo compiles crate {name} without -C metadata, so its path-independent metadata "
                "cannot be applied and rustc would fall back to a value of its own"
            )
        os.execv(rustc, [rustc] + args)

    version = os.environ.get("CARGO_PKG_VERSION", "")
    key = "\n".join([name, version, ctype, target] + sorted(cfgs))
    value = hashlib.sha256(key.encode()).hexdigest()[:16]
    out = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-C" and i + 1 < len(args) and args[i + 1].startswith("metadata="):
            out += ["-C", "metadata=" + value]
            i += 2
            continue
        if a.startswith("-Cmetadata="):
            out.append("-Cmetadata=" + value)
            i += 1
            continue
        out.append(a)
        i += 1
    os.execv(rustc, [rustc] + out)


if __name__ == "__main__":
    main()

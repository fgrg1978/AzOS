#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The linker flags of a native user image, read from the ISA's target spec.

    user_link_args.py <riscv64|aarch64|x86_64>

A native image has no linker script: its layout (image base, page size, entry,
a static position-independent executable without RELRO) is what
`sdk/targets/<isa>-unknown-azos.json` tells rust-lld, and rustc passes it for
every Rust image. A link that rustc does not drive takes the same flags from
here, so the spec stays the one place that says them:

    user_link_args.py <isa>            for ld.lld (the hand-assembled `hello.S`)
    user_link_args.py --driver <isa>   for a compiler driver (`zig cc`, the C
                                       programs on relibc), as `-Wl,` flags

zig's driver refuses `-pie`, `--apply-dynamic-relocs`, `-z text` and
`--fix-cortex-a53-843419`, so `--driver` gives the layout of a static
executable (ET_EXEC): the same image base, page size, entry, no RELRO and no
`.eh_frame_hdr`, with nothing to relocate.
"""
import json
import os
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SPECS = {"riscv64": "riscv64imac-unknown-azos", "aarch64": "aarch64-unknown-azos", "x86_64": "x86_64-unknown-azos"}


def link_args(isa):
    with open(os.path.join(ROOT, "sdk", "targets", SPECS[isa] + ".json")) as f:
        spec = json.load(f)
    args = list(spec.get("pre-link-args", {}).get(spec["linker-flavor"], []))
    # What rustc adds for these spec fields (a static-pie executable, no RELRO).
    if spec.get("static-position-independent-executables") and spec.get("crt-static-default"):
        args += ["-static", "-pie", "--no-dynamic-linker", "-z", "text"]
    if spec.get("relro-level") == "off":
        args += ["-z", "norelro"]
    if spec.get("eh-frame-header") is False:
        args += ["--no-eh-frame-hdr"]
    return args


# What a compiler driver gets (see the module doc): the layout of a static,
# not position-independent executable.
DRIVER_DROP = {"--apply-dynamic-relocs", "--fix-cortex-a53-843419", "-static", "-pie", "--no-dynamic-linker"}


def driver_args(args):
    """`args` as `-Wl,` flags a driver accepts: two-word options (`-e NAME`,
    `-z KEY`) as one flag, `-zKEY` as `-z,KEY`, the PIE-only ones dropped."""
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a in ("-e", "-z") and i + 1 < len(args):
            if not (a == "-z" and args[i + 1] == "text"):
                out.append(f"-Wl,{a},{args[i + 1]}")
            i += 2
            continue
        if a.startswith("-z") and len(a) > 2:
            out.append(f"-Wl,-z,{a[2:]}")
        elif a not in DRIVER_DROP:
            out.append("-Wl," + a)
        i += 1
    return out


def main():
    argv = sys.argv[1:]
    driver = "--driver" in argv
    argv = [a for a in argv if a != "--driver"]
    if len(argv) != 1 or argv[0] not in SPECS:
        sys.exit("usage: user_link_args.py [--driver] <riscv64|aarch64|x86_64>")
    args = link_args(argv[0])
    print(" ".join(driver_args(args) if driver else args))


if __name__ == "__main__":
    main()

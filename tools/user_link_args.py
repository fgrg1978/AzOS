#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The linker flags of a native user image, read from the ISA's target spec.

    user_link_args.py <riscv64|aarch64|x86_64>

A native image has no linker script: its layout (image base, page size, entry,
a static position-independent executable without RELRO) is what
`sdk/targets/<isa>-unknown-azos.json` tells rust-lld, and rustc passes it for
every Rust image. A link that rustc does not drive (the hand-assembled
`hello.S`, a C program on relibc linked by zig) takes the same flags from
here, so the spec stays the one place that says them. Prints them on one line,
for `ld.lld`; `--wl` prefixes each with `-Wl,` for a compiler driver.
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


def main():
    argv = sys.argv[1:]
    wl = "--wl" in argv
    argv = [a for a in argv if a != "--wl"]
    if len(argv) != 1 or argv[0] not in SPECS:
        sys.exit("usage: user_link_args.py [--wl] <riscv64|aarch64|x86_64>")
    args = link_args(argv[0])
    if wl:
        # `-e NAME` is two words; a driver needs them as one `-Wl,` argument.
        out, i = [], 0
        while i < len(args):
            if args[i] in ("-e", "-z") and i + 1 < len(args):
                out.append(f"-Wl,{args[i]},{args[i + 1]}")
                i += 2
            else:
                out.append("-Wl," + args[i])
                i += 1
        args = out
    print(" ".join(args))


if __name__ == "__main__":
    main()

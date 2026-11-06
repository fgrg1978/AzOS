#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The stack scrub after HMAC and HKDF covers the calls it follows, in a kernel image.

    stack_scrub_check.py <kernel or monitor ELF> [--bytes N]

azos_crypto's HMAC/HKDF entries (crates/core/crypto/src/hkdf.rs, which the
resident monitor includes by path) run the
`hmac`/`hkdf` crates out of line (`*_inner`) and then `ct::scrub_stack`, which
zeroes STACK_SCRUB_BYTES below the entry's frame: the padded key, the PRK and
the T(i) blocks those crates leave there. That only holds if no chain under an
`*_inner` goes deeper than the scrub. This check measures each one with
tools/lint/stack_chain.py's dataflow (the same frames, the same call graph)
on the linked image, without the panic handler's charge: a panic stops the
CPU, and the scrub never runs after it either way. STACK_SCRUB_BYTES is read
from crates/core/crypto/src/ct.rs; `--bytes` replaces it (the canary: a
scrub of 256 bytes fails on every image).

Like stack_chain.py, a lower bound: an indirect call (the aarch64 SHA-2 hook)
is not followed; its own chain is small (`kernel::boot::seams::sha256_ce`).
Exit 1 when a chain is deeper than the scrub, 2 when the image or every entry is
missing.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack_chain  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
CT = os.path.join(ROOT, "crates/core/crypto/src/ct.rs")
# `azos_crypto::hkdf::...` in a kernel, `azos_hyp_mon::hkdf::...` in the
# resident monitor (it includes hkdf.rs by path and links only `hkdf`). An
# entry the image never calls is not in it; each one it does call is out of
# line (`#[inline(never)]`), so it is checked.
INNER = ("hmac_inner", "extract_inner", "expand_inner", "hkdf_inner")


def scrub_bytes() -> int:
    m = re.search(r"pub const STACK_SCRUB_BYTES: usize = ([0-9_]+);", open(CT).read())
    if not m:
        sys.stderr.write(f"no STACK_SCRUB_BYTES in {CT}\n")
        sys.exit(2)
    return int(m.group(1).replace("_", ""))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("elf")
    ap.add_argument("--bytes", type=int, default=0)
    a = ap.parse_args()
    limit = a.bytes or scrub_bytes()
    if not os.path.isfile(a.elf):
        sys.stderr.write(f"no image at {a.elf}\n")
        sys.exit(2)
    graph, an, names, _isa = stack_chain.load(a.elf, {})
    roots = [n for n in names if any(n.endswith(f"::hkdf::{f}") for f in INNER)]
    if not roots:
        sys.stderr.write(f"no symbol *::hkdf::{{{','.join(INNER)}}} in {a.elf}\n")
        sys.exit(2)
    over = False
    for r in roots:
        c = stack_chain.chain(graph, an.frames, r, an.unbounded)
        depth = sum(an.frames.get(f, 0) for f in c.path)
        mark = "OVER" if depth > limit else "ok"
        over |= depth > limit
        print(f"{mark:4} {depth:6d} <= {limit}: {r} ({' > '.join(c.path[1:4])})")
    sys.exit(1 if over else 0)


if __name__ == "__main__":
    main()

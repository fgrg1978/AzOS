#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""A kernel with no personality links no Linux code.

For each ISA the gate's defconfig is taken with Kconfig LINUX_ABI turned off
(LINUX_RUNTIME depends on it), and the kernel's dependency set for that cell
(`make check-deps`, a `cargo tree`, nothing is built) must not name
`azos_linux_abi`. `--self-test` runs the gate's defconfig as is, where the
crate must appear: the lint can see what it forbids.
"""

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ARCHES = ("riscv64", "aarch64", "x86_64")
FORBIDDEN = "azos_linux_abi"


def defconfig(arch):
    return os.path.join(ROOT, "config", "defconfigs", f"generic-sbc-{arch}-dev+qemu+linux+gui.config")


def without_linux(path, out):
    with open(path, encoding="utf-8") as fh:
        lines = [l for l in fh if "CONFIG_LINUX_ABI" not in l and "CONFIG_LINUX_RUNTIME" not in l]
    lines.append("# CONFIG_LINUX_ABI is not set\n")
    with open(out, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def deps(arch, cfg, work):
    kconfig = os.path.join(work, f"deps-{arch}.config")
    r = subprocess.run(
        ["make", "-s", "check-deps", f"ARCH={arch}", f"CHECK_DEFCONFIG_{arch}={cfg}", f"CHECK_KCONFIG={kconfig}"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if r.returncode != 0:
        sys.exit(f"no-personality lint: make check-deps ARCH={arch} failed:\n{r.stderr[-2000:]}")
    return {l.split()[0] for l in r.stdout.splitlines() if l.strip()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    out_root = os.environ.get("AZOS_OUT") or tempfile.gettempdir()
    work = tempfile.mkdtemp(prefix="nolx-", dir=out_root)
    bad = []
    for arch in ARCHES:
        if args.self_test:
            if FORBIDDEN not in deps(arch, defconfig(arch), work):
                bad.append(f"{arch}: the gate's defconfig does not link {FORBIDDEN}: the lint cannot see it")
            continue
        cfg = os.path.join(work, f"nolx-{arch}.defconfig")
        without_linux(defconfig(arch), cfg)
        if FORBIDDEN in deps(arch, cfg, work):
            bad.append(f"{arch}: a kernel without LINUX_ABI still depends on {FORBIDDEN}")
    for b in bad:
        print(b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

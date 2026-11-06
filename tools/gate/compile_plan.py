#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""What `make check-compile` (tools/gate/gate_tier.sh compile) type-checks for a diff.

  compile_plan.py [--base REV] [--files PATH...] [--explain]   one line per unit of work:
      cell <isa> <preset>     `make ARCH=<isa> CHECK_PRESET=<preset> check` (the kernel, no codegen)
      host <tests/host/dir>   `cargo check --tests` of the host suite
  compile_plan.py --self-test

The diff is the working tree against REV (default HEAD), as in rows_for_diff.py,
which also decides the host suites (the suites whose crate graph reaches a changed path).

Kernel cells. A path is in the kernel when its crate is in the kernel's
dependency closure (gate_rows.crate_closure), a file such a crate pulls in with
`#[path]`/`include!`, or one of BUILD_WIDE (the build graph, the Kconfig tree, the
toolchain pin). Then:
  * ISA: a path that names one ISA (riscv64, aarch64, x86_64 as a directory or a file
    name: arch/riscv/, kernel/src/entry/aarch64/, config/defconfigs/*-x86_64-*) is
    checked on that ISA; every other path, and BUILD_WIDE, on all three. The union of
    the changed paths decides.
  * preset: `generic` always; `robot` too when a changed path is under
    crates/domains/robot/ or names `robot` / mentions `use-robot` or `use_robot`
    (the cell that links the robot crates and the kernel's use-robot code);
    `microvm` too when a path is under config/, names `microvm`, or mentions a
    feature the microvm cell turns off that its default cells keep (the A/B
    slots, the package apply, the TPM, USB, the Linux personality,
    virtio-input and -sound, PS/2, the SBSA and BCM2835 watchdogs, the Raspberry
    Pi firmware).
A diff outside the kernel's closure (userspace/, tests/, tools/, docs) plans no cell.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402,F401
import gate_rows  # noqa: E402
import rows_for_diff  # noqa: E402

ROOT = gate_rows.ROOT
ISAS = {"riscv64": "riscv64", "aarch64": "aarch64", "x86_64": "x86_64"}
BUILD_WIDE = ["Cargo.toml", "Cargo.lock", "Kconfig", "config/**", ".cargo/**", "rust-toolchain.toml",
              "kernel/Cargo.toml", "kernel/build.rs", "kernel/linker-common.ld", "tools/build/kconfig_to_cargo.py"]
ROBOT_RE = re.compile(r"use[-_]robot|domains/robot")
MICROVM_RE = re.compile(r'microvm|boot[-_]slots|pkg[-_]boot[-_]apply|'
                        r'feature = "(tpm|usb-host|linux-abi|virtio-input|virtio-snd|ps2|wdt-sbsa|wdt-bcm2835-pm|rpi-firmware)"')


def isa_of(path):
    """The ISA a path names, or None."""
    if path.startswith("arch/riscv/"):
        return "riscv64"
    hits = {i for i in ISAS if re.search(r"(^|[/_.+-])%s([/_.+-]|$)" % i, path)}
    return hits.pop() if len(hits) == 1 else None


def wide(path):
    return rows_for_diff.match(path, BUILD_WIDE) and not (path.startswith("config/defconfigs/") and isa_of(path))


def in_kernel(path, closure):
    c = gate_rows.owning_crate(path)
    if c and c in closure:
        return True
    return path in {x[5:] for x in closure if x.startswith("file:")} or rows_for_diff.match(path, BUILD_WIDE)


def _text(path, text):
    if text is None:
        try:
            text = open(os.path.join(ROOT, path), errors="replace").read()
        except OSError:
            return ""
    return text


def wants_robot(path, text=None):
    if ROBOT_RE.search(path) or "robot" in os.path.basename(path):
        return True
    return bool(ROBOT_RE.search(_text(path, text)))


def wants_microvm(path, text=None):
    if path.startswith("config/") or MICROVM_RE.search(path):
        return True
    return bool(MICROVM_RE.search(_text(path, text)))


def plan(paths, closure=None, graph=None, read=None):
    """(cells [(isa, preset)], suites, why) for the changed paths."""
    closure = gate_rows.crate_closure("kernel") if closure is None else closure
    isas, robot, microvm, why = set(), False, False, []
    for p in paths:
        if not in_kernel(p, closure):
            continue
        i = None if wide(p) else isa_of(p)
        isas |= {i} if i else set(ISAS)
        r = wants_robot(p, read(p) if read else None)
        m = wants_microvm(p, read(p) if read else None)
        robot |= r
        microvm |= m
        why.append("%s: %s%s%s" % (p, i or "all ISAs", ", robot" if r else "", ", microvm" if m else ""))
    order = ["riscv64", "aarch64", "x86_64"]
    cells = [(i, "generic") for i in order if i in isas]
    if robot:
        cells += [(i, "robot") for i in order if i in isas]
    if microvm:
        cells += [(i, "microvm") for i in order if i in isas]
    return cells, rows_for_diff.host_suites(paths, graph), why


def self_test():
    bad = []
    clo = {"kernel", "arch/riscv", "arch/aarch64", "crates/core/ipc", "crates/domains/robot/nav", "file:crates/x/inc.rs"}
    rd = lambda p: {"kernel/src/robotish.rs": "use-robot", "crates/core/ipc/src/slots.rs": '#[cfg(feature = "boot-slots")]',
                    "crates/core/ipc/src/ps.rs": '#[cfg(not(feature = "ps2"))]'}.get(p, "")
    g = {}  # no suites in the toy graph

    def t(paths, want, what):
        cells, _, _ = plan(paths, clo, g, rd)
        if cells != want:
            bad.append("%s: %r != %r" % (what, cells, want))
    t(["arch/riscv/boot/entry.rs"], [("riscv64", "generic")], "one ISA's arch crate")
    t(["crates/core/ipc/src/lib.rs"], [(i, "generic") for i in ISAS], "shared crate: three ISAs")
    t(["crates/domains/robot/nav/src/lib.rs"], [(i, p) for p in ("generic", "robot") for i in ISAS], "robot crate: both presets")
    t(["kernel/src/robotish.rs"], [(i, p) for p in ("generic", "robot") for i in ISAS], "use-robot text: both presets")
    t(["docs/x.md", "userspace/services/a/src/main.rs", "tests/host/x/src/lib.rs"], [], "outside the kernel plans no cell")
    t(["crates/x/inc.rs"], [(i, "generic") for i in ISAS], "included file counts as the kernel's")
    t(["Cargo.lock"], [(i, "generic") for i in ISAS], "build-wide: three ISAs")
    t(["config/subsys/Kconfig.x"], [(i, p) for p in ("generic", "microvm") for i in ISAS], "Kconfig: the microvm cell too")
    t(["config/defconfigs/generic-sbc-x86_64-dev+qemu+linux+gui.config"], [("x86_64", "generic"), ("x86_64", "microvm")],
      "a defconfig names its ISA")
    t(["crates/core/ipc/src/slots.rs"], [(i, p) for p in ("generic", "microvm") for i in ISAS], "a microvm-off feature: both presets")
    t(["crates/core/ipc/src/ps.rs"], [(i, p) for p in ("generic", "microvm") for i in ISAS], "a driver microvm turns off: both presets")
    t(["arch/riscv/a.rs", "arch/aarch64/b.rs"], [("riscv64", "generic"), ("aarch64", "generic")], "union of two ISAs")
    for b in bad:
        print("compile_plan self-test: FAIL " + b)
    if not bad:
        print("compile_plan self-test: ok")
    return 1 if bad else 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    base = argv[argv.index("--base") + 1] if "--base" in argv else "HEAD"
    paths = rows_for_diff.changed(base)
    if "--files" in argv:
        i = argv.index("--files") + 1
        paths = []
        while i < len(argv) and not argv[i].startswith("--"):
            paths.append(argv[i])
            i += 1
    cells, suites, why = plan(paths)
    for c in cells:
        print("cell %s %s" % c)
    for s in suites:
        print("host " + s)
    if "--explain" in argv:
        for w in why:
            print("# " + w, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

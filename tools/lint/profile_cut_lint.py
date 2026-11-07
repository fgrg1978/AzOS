#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""A profile cut leaves its crates out of the kernel.

A symbol cut is a Kconfig symbol and the crates it alone brings in: for each
ISA the cut's defconfig is taken with the symbol turned off. A preset cut is a
preset's own defconfig, as is. Either way the kernel's dependency set for that
cell (`make check-deps`, a `cargo tree`, nothing is built) must name none of
those crates. `--self-test` runs the cut's on defconfig as is, where every
crate must appear: the lint can see what it forbids.

  linux     LINUX_ABI (LINUX_RUNTIME depends on it): azos_linux_abi
  board-io  BOARD_IO: the board's sensors, actuators, kill switch and the camera frame pool
  robot     USE_ROBOT: the robot extension's crates (core and kernel name none)
  microvm   PRESET_MICROVM: no Linux personality, no physical-hardware driver
            (TPM, USB and its storage), no board I/O, no extension
"""

import argparse
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = azos_tools.ROOT
ARCHES = ("riscv64", "aarch64", "x86_64")

# name: (preset of the defconfig with the symbol on, symbol, lines dropped, crates)
CUTS = {
    "linux": ("generic", "LINUX_ABI", ("CONFIG_LINUX_ABI", "CONFIG_LINUX_RUNTIME"), ("azos_linux_abi",)),
    "board-io": ("robot", "BOARD_IO", ("CONFIG_BOARD_IO", "CONFIG_USE_ROBOT", "CONFIG_PRESET_"),
                 ("azos_drv_sensor", "azos_cam_ring", "azos_drv_actuator", "azos_kill_switch")),
    "robot": ("robot", "USE_ROBOT", ("CONFIG_USE_ROBOT", "CONFIG_PRESET_"),
              ("azos_robot", "azos_behavior", "azos_safety_core", "azos_robot_drivers")),
}
# name: (the presets whose defconfigs have the crates between them, preset of the cut, crates)
PRESET_CUTS = {
    "microvm": (("robot", "generic"), "microvm",
                ("azos_linux_abi", "azos_tpm", "azos_usb", "azos_usb_hid", "azos_scsi",
                 "azos_drv_sensor", "azos_cam_ring", "azos_drv_actuator", "azos_kill_switch",
                 "azos_robot", "azos_behavior", "azos_safety_core", "azos_robot_drivers")),
}
# The overlays of a preset's gate cell (mk/lints.mk CHECK_OVERLAYS).
OVERLAYS = {"microvm": "qemu"}


def defconfig(preset, arch):
    return os.path.join(ROOT, "config", "defconfigs",
                        f"{preset}-sbc-{arch}-dev+{OVERLAYS.get(preset, 'qemu+linux+gui')}.config")


def without(path, drop, symbol, out):
    with open(path, encoding="utf-8") as fh:
        lines = [l for l in fh if not any(d in l for d in drop)]
    lines.append(f"# CONFIG_{symbol} is not set\n")
    with open(out, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def deps(arch, cfg, work):
    kconfig = os.path.join(work, f"deps-{arch}.config")
    r = subprocess.run(
        ["make", "-s", "check-deps", f"ARCH={arch}", f"CHECK_DEFCONFIG_{arch}={cfg}", f"CHECK_KCONFIG={kconfig}"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if r.returncode != 0:
        sys.exit(f"profile-cut lint: make check-deps ARCH={arch} failed:\n{r.stderr[-2000:]}")
    return {l.split()[0] for l in r.stdout.splitlines() if l.strip()}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--cut", choices=sorted({**CUTS, **PRESET_CUTS}), action="append")
    args = ap.parse_args()
    out_root = os.environ.get("AZOS_OUT") or tempfile.gettempdir()
    work = tempfile.mkdtemp(prefix="cut-", dir=out_root)
    bad = []
    for name in args.cut or sorted({**CUTS, **PRESET_CUTS}):
        if name in PRESET_CUTS:
            preset, cut, crates = PRESET_CUTS[name]
            what = f"the {cut} preset's kernel"
        else:
            preset, symbol, drop, crates = CUTS[name]
            what = f"a kernel without {symbol}"
        presets = preset if isinstance(preset, tuple) else (preset,)
        for arch in ARCHES:
            if args.self_test:
                linked = set().union(*(deps(arch, defconfig(p, arch), work) for p in presets))
                missing = [c for c in crates if c not in linked]
                if missing:
                    bad.append(f"{name} {arch}: the {'/'.join(presets)} defconfigs do not link "
                               f"{', '.join(missing)}: the lint cannot see it")
                continue
            on = defconfig(presets[0], arch)
            if name in PRESET_CUTS:
                cfg = defconfig(cut, arch)
            else:
                cfg = os.path.join(work, f"{name}-{arch}.defconfig")
                without(on, drop, symbol, cfg)
            found = [c for c in crates if c in deps(arch, cfg, work)]
            if found:
                bad.append(f"{what} on {arch} still depends on {', '.join(found)}")
    for b in bad:
        print(b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The one way a gate row starts qemu-system-aarch64: the accelerator is chosen here.

    qemu_a64.py [--tcg] <qemu-system-aarch64 arguments>
    qemu_a64.py --classify [--tcg] <arguments>     print "<hvf|tcg> <why>", start nothing

The process is replaced (exec), so the pid a row keeps and kills is QEMU's.

ACCEL=auto (default): HVF where tools/dev/qemu_hvf.sh says this host can run a
guest under it, TCG otherwise. ACCEL=tcg forces TCG; ACCEL=hvf asks for HVF and
refuses to start where there is none. AZOS_HVF_OK=0|1 carries one probe to the
processes below it.

TCG is forced, whatever ACCEL says, by what HVF cannot do:
  * `-icount`: virtual time exists only under TCG;
  * a machine that enters at EL2 (`virtualization=on`): HVF has no guest EL2;
  * a machine other than `virt` (`raspi3b`), a CPU model other than `max` or
    `host`, a counter frequency set on the CPU (`cntfrq=`);
  * `--tcg`, the tag of a row that needs CPU features the host lacks (the
    PAC/BTI/MTE/POE/GCS ktests, a 64 KiB granule) or asserts the ID registers.
An argument list that names `-accel` itself is passed on unchanged.
"""

import os
import subprocess
import sys

QEMU = "qemu-system-aarch64"
HERE = os.path.dirname(os.path.abspath(__file__))
HVF_PROBE = os.path.join(HERE, "..", "dev", "qemu_hvf.sh")


def hvf_host():
    """Can this host run a guest under HVF: asked once, remembered for the children."""
    known = os.environ.get("AZOS_HVF_OK")
    if known in ("0", "1"):
        return known == "1"
    ok = subprocess.run(["sh", HVF_PROBE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    os.environ["AZOS_HVF_OK"] = "1" if ok else "0"
    return ok


def option(args, names):
    """The value of the last `-name value` in args."""
    got = None
    for i, a in enumerate(args[:-1]):
        if a in names:
            got = args[i + 1]
    return got


def why_tcg(args, tagged):
    """What forces TCG for this argument list, or None."""
    if tagged:
        return "tagged --tcg"
    if "-icount" in args:
        return "-icount"
    machine = option(args, ("-M", "-machine"))
    if machine is not None:
        if machine.split(",")[0] != "virt":
            return f"machine {machine.split(',')[0]}"
        if "virtualization=on" in machine.split(","):
            return "virtualization=on"
    cpu = option(args, ("-cpu",))
    if cpu is not None:
        model, *props = cpu.split(",")
        if model not in ("max", "host"):
            return f"cpu {model}"
        if any(p.startswith("cntfrq=") for p in props):
            return "cntfrq="
    return None


def decide(args, tagged, accel, hvf):
    """(accelerator or None for 'the arguments name it', why)."""
    if any(a == "-accel" or a.startswith("-accel=") for a in args):
        return None, "the row names -accel"
    forced = why_tcg(args, tagged)
    if forced:
        return "tcg", forced
    if accel == "tcg":
        return "tcg", "ACCEL=tcg"
    if accel == "hvf":
        return ("hvf", "ACCEL=hvf") if hvf else ("error", "ACCEL=hvf but this host has no HVF")
    return ("hvf", "auto: HVF host") if hvf else ("tcg", "auto: no HVF here")


def main(argv):
    classify = bool(argv) and argv[0] == "--classify"
    if classify:
        argv = argv[1:]
    tagged = bool(argv) and argv[0] == "--tcg"
    if tagged:
        argv = argv[1:]
    accel = os.environ.get("ACCEL", "auto") or "auto"
    if accel not in ("auto", "hvf", "tcg"):
        sys.exit(f"qemu_a64: ACCEL={accel}: auto, hvf or tcg")
    # A forced TCG row does not ask the host.
    hvf = False if (tagged or why_tcg(argv, False) or accel == "tcg") else hvf_host()
    pick, why = decide(argv, tagged, accel, hvf)
    if classify:
        print(f"{pick or 'named'} {why}")
        return 0
    if pick == "error":
        sys.exit(f"qemu_a64: {why}")
    args = ([] if pick is None else ["-accel", pick]) + argv
    os.execvp(QEMU, [QEMU] + args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

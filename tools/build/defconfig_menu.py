#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""`make defconfig`: two questions (ISA, domain) and a defconfig name that boots in QEMU.

Usage: python3 tools/build/defconfig_menu.py [--arch ISA] [--preset NAME]
       python3 tools/build/defconfig_menu.py --after NAME
       python3 tools/build/defconfig_menu.py --self-test

The first form asks what --arch and --preset did not answer (on a terminal;
without one it takes the default of each) and prints the defconfig name on
stdout, for `make defconfig-<name>`; the menu goes to stderr. The name is
<preset>-<hwclass>-<arch>-dev+qemu[+gui]+linux-dev, assembled by
tools/build/gen_defconfigs.py:

  * the preset is the domain; its fragment name is the spelling (iot_hmi);
  * the hardware class is the one Kconfig gives that preset
    (config/axes/Kconfig.hwclass), read from Kconfig, not listed here;
  * the build is dev and the image is the QEMU one, so `make build && make
    qemu` boots it; +gui is added when the preset's USE is the desktop;
  * the Linux personality is on in a dev image, as +linux-dev has it: without the
    gate's pins (+linux), so BusyBox and, on x86_64, the ring-3 runtime that
    hosts it take their Kconfig defaults, which are on.

--after NAME prints what was chosen and what to run next; it marks the choice
green when tools/gate/preset_boot_green.tsv names a green boot row for the
(preset, ISA) and experimental otherwise.
"""

import os
import platform
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

REPO = azos_tools.ROOT
PRESETS_DIR = os.path.join(REPO, "config", "fragments", "presets")
GREEN_FILE = os.path.join(REPO, "tools/gate/preset_boot_green.tsv")
ISAS = ("riscv64", "aarch64", "x86_64")
HOST_ISA = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64", "riscv64": "riscv64"}
DEFAULT_PRESET = "generic"
OVERLAYS_BY_PRESET = {"desktop": ("gui",)}  # the preset whose USE gets the compositor's inputs
STATUSES = ("green", "experimental")


class Refused(Exception):
    pass


def presets():
    return sorted(f[:-len(".frag")] for f in os.listdir(PRESETS_DIR) if f.endswith(".frag"))


def host_isa():
    isa = HOST_ISA.get(platform.machine().lower())
    if isa is None:
        raise Refused(f"the host machine {platform.machine()!r} is not one of {', '.join(ISAS)}: name the ISA with ARCH=")
    return isa


def normalise_preset(name):
    n = name.strip().lower().replace("-", "_")
    if n not in presets():
        raise Refused(f"no domain {name!r}; the domains are {', '.join(presets())}")
    return n


def normalise_isa(name):
    n = HOST_ISA.get(name.strip().lower(), name.strip().lower())
    if n not in ISAS:
        raise Refused(f"no ISA {name!r}; the ISAs are {', '.join(ISAS)}")
    return n


def read_green(path=GREEN_FILE):
    """{(preset, isa): (status, evidence)} of the data file, or Refused if it is malformed."""
    out = {}
    for no, line in enumerate(open(path, encoding="utf-8").read().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) != 4:
            raise Refused(f"{path}:{no}: want preset, isa, status and evidence separated by tabs")
        preset, isa, status, evidence = f
        if preset not in presets() or isa not in ISAS or status not in STATUSES:
            raise Refused(f"{path}:{no}: {preset!r} {isa!r} {status!r}: not a preset, an ISA and green|experimental")
        if status == "green" and not evidence.strip():
            raise Refused(f"{path}:{no}: green without the row that proves it")
        if (preset, isa) in out:
            raise Refused(f"{path}:{no}: {preset} on {isa} is listed twice")
        out[(preset, isa)] = (status, evidence)
    missing = [(p, i) for p in presets() for i in ISAS if (p, i) not in out]
    if missing:
        raise Refused(f"{path}: no row for {', '.join(f'{p}/{i}' for p, i in missing)}")
    return out


def hwclass_of(preset):
    """The HWCLASS Kconfig defaults to under `preset` (config/axes/Kconfig.hwclass)."""
    import kconfiglib
    old = os.getcwd()
    os.chdir(REPO)
    try:
        k = kconfiglib.Kconfig("Kconfig", warn_to_stderr=False)
        k.syms["PRESET_" + preset.upper()].set_value(2)
        chosen = [s.name[len("HWCLASS_"):].lower() for s in k.syms.values()
                  if s.name.startswith("HWCLASS_") and s.str_value == "y"]
    finally:
        os.chdir(old)
    if len(chosen) != 1:
        raise Refused(f"preset {preset}: Kconfig selects {len(chosen)} hardware classes ({chosen})")
    return chosen[0]


def defconfig_name(preset, isa, hwclass):
    overlays = ("qemu",) + OVERLAYS_BY_PRESET.get(preset, ()) + ("linux-dev",)
    return f"{preset}-{hwclass}-{isa}-dev+" + "+".join(overlays)


def ask(question, options, default, labels, tty):
    """One question on stderr: the number or the name of an option; Enter takes the default."""
    if not tty:
        print(f"{question}: {default} (no terminal: the default)", file=sys.stderr)
        return default
    print(question, file=sys.stderr)
    w = max(len(o) for o in options) + 2
    for i, o in enumerate(options, 1):
        print(f"  {i:2d}) {o:<{w}s}{labels[o]}{'   [default]' if o == default else ''}", file=sys.stderr)
    while True:
        sys.stderr.write(f"choice [{default}]: ")
        sys.stderr.flush()
        a = sys.stdin.readline()
        if a == "":
            raise Refused("no answer (end of input)")
        a = a.strip()
        if not a:
            return default
        if a.isdigit() and 1 <= int(a) <= len(options):
            return options[int(a) - 1]
        for o in options:
            if a.lower().replace("-", "_") == o:
                return o
        print(f"  not one of the choices: {a!r}", file=sys.stderr)


def choose(arch, preset, tty):
    green = read_green()
    if arch is None:
        arch = ask("ISA (the host's is the default)", list(ISAS), host_isa(),
                   {i: ("the host's" if i == host_isa() else "") for i in ISAS}, tty)
    else:
        arch = normalise_isa(arch)
    if preset is None:
        labels = {p: green[(p, arch)][0] + ("" if green[(p, arch)][0] == "green" else " (no green boot row yet)")
                  for p in presets()}
        preset = ask(f"Domain, on {arch}", presets(), DEFAULT_PRESET, labels, tty)
    else:
        preset = normalise_preset(preset)
    return arch, preset


def after(name):
    parts = name.split("-")
    preset, hwclass, isa = parts[0], parts[1], parts[2]
    status, evidence = read_green()[(preset, isa)]
    print(f"Chosen: {preset} on {isa} (hardware class {hwclass}, dev build, QEMU image, Linux personality with BusyBox"
          f"{', GUI inputs' if '+gui' in name else ''}).")
    if status == "green":
        print(f"Boot row: green ({evidence}).")
    else:
        print("Boot row: experimental, no green preset boot row yet; it may not boot.")
    print("Next: make build && make qemu       (make config refines it; make defconfig-<name> picks a board or an advanced combination)")


def self_test():
    """Each rule on a scratch data file and the real fragments; the last two run Kconfig and
    gen_defconfigs on all presets x ISAs."""
    import tempfile
    import gen_defconfigs
    fails = []

    def refused(text, why):
        with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as t:
            t.write(text)
        try:
            read_green(t.name)
            fails.append(f"{why} was not refused")
        except Refused:
            pass
        finally:
            os.unlink(t.name)

    good = "".join(f"{p}\t{i}\texperimental\t-\n" for p in presets() for i in ISAS)
    with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as t:
        t.write(good)
    try:
        if len(read_green(t.name)) != len(presets()) * len(ISAS):
            fails.append("a complete green file did not read")
    finally:
        os.unlink(t.name)
    refused(good + "nosuch\triscv64\texperimental\t-\n", "a row for a preset that has no fragment")
    refused(good.replace("generic\triscv64\texperimental\t-", "generic\triscv64\tgreen\t"), "green without a row name")
    refused("".join(good.splitlines(True)[1:]), "a (preset, ISA) with no row")
    refused(good + good.splitlines()[0] + "\n", "a combination listed twice")
    refused(good.replace("experimental", "maybe", 1), "a status that is not green or experimental")

    import kconfiglib
    os.chdir(REPO)
    k = kconfiglib.Kconfig("Kconfig", warn_to_stderr=False)
    for p in presets():
        hw = hwclass_of(p)
        for isa in ISAS:
            name = defconfig_name(p, isa, hw)
            try:
                text = gen_defconfigs.assemble(name)
            except gen_defconfigs.Refused as e:
                fails.append(f"{name}: gen_defconfigs refuses it: {e}")
                continue
            with tempfile.NamedTemporaryFile("w", suffix=".config", delete=False) as t:
                t.write(text)
            try:
                warned = len(k.warnings)
                k.load_config(t.name)
            finally:
                os.unlink(t.name)
            for w in k.warnings[warned:]:
                fails.append(f"{name}: Kconfig drops an assignment: {w.strip()}")
            for sym in (f"PRESET_{p.upper()}", f"HWCLASS_{hw.upper()}", f"ARCH_{isa.upper()}",
                        "BUILD_TYPE_DEV", "LINUX_ABI", "USERSPACE_GPL"):
                if k.syms[sym].str_value != "y":
                    fails.append(f"{name}: expands without {sym}")
            unhosted = isa == "x86_64" and hw == "embedded"   # no ring-3 runtime there, so no BusyBox
            for sym in ("BUSYBOX",) + (("LINUX_RUNTIME",) if isa == "x86_64" else ()):
                want = "n" if unhosted else "y"
                if k.syms[sym].str_value != want:
                    fails.append(f"{name}: {sym} is {k.syms[sym].str_value}, want {want}")
            if (k.syms["INPUTD"].str_value == "y") != (p in OVERLAYS_BY_PRESET):
                fails.append(f"{name}: +gui is on exactly for the {', '.join(OVERLAYS_BY_PRESET)} preset")
    for f in fails:
        print("defconfig_menu self-test: FAIL", f)
    if not fails:
        print(f"defconfig_menu self-test: ok (6 data-file rules, {len(presets()) * len(ISAS)} presets x ISAs assemble)")
    return 1 if fails else 0


def main(argv):
    arch = preset = after_name = None
    i = 0
    try:
        if argv[:1] == ["--self-test"]:
            return self_test()
        while i < len(argv):
            if argv[i] == "--arch" and i + 1 < len(argv):
                arch = argv[i + 1]
            elif argv[i] == "--preset" and i + 1 < len(argv):
                preset = argv[i + 1]
            elif argv[i] == "--after" and i + 1 < len(argv):
                after_name = argv[i + 1]
            else:
                raise Refused(f"unknown argument {argv[i]!r}")
            i += 2
        if after_name is not None:
            after(after_name)
            return 0
        arch, preset = choose(arch, preset, sys.stdin.isatty())
        print(defconfig_name(preset, arch, hwclass_of(preset)))
        return 0
    except Refused as e:
        print("make defconfig:", e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

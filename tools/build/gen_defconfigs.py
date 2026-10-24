#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Assemble a defconfig from the fragments under config/fragments/.

Usage: python3 tools/build/gen_defconfigs.py [--check | --self-test | --print NAME | NAME...]

A defconfig's name says what it is made of:

    <preset>-<hwclass>-<arch>[-<build>][+<overlay>...]

e.g. `robot-sbc-riscv64-dev+qemu+linux+gui`. Each part is a fragment:
presets/<preset>.frag, hwclass/<hwclass>.frag, arch/<arch>.frag,
build/<build>.frag (no build part: the Kconfig default, release), then for each
overlay overlays/<overlay>.frag and overlays/<overlay>-<arch>.frag, whichever
exist (at least one must). Later fragments win; two axis fragments (preset,
hwclass, arch, build) that set one symbol differently, or two overlays that do,
are refused, so an overlay is the only thing that overrides an axis.

The committed config/defconfigs/<name>.config files are this script's output
for the cells something builds (the gate, the boards, `make build-fleet`, the
guest images). Any other cell is made the same way without a file:
`make defconfig-<name>` assembles it.

  (no argument)  rewrite every committed defconfig from its name
  NAME...        write config/defconfigs/NAME.config
  --print NAME   write NAME's defconfig to stdout
  --check        exit 1 if a committed defconfig is not what its name assembles,
                 or if one does not keep the axes its name gives once Kconfig has
                 expanded it; write nothing
  --self-test    the merge rules on a scratch fragment tree (each case is a canary
                 of one rule)
"""

import os
import re
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
FRAG = os.path.join(REPO, "config", "fragments")
DEFDIR = os.path.join(REPO, "config", "defconfigs")
LINE = re.compile(r"^(?:CONFIG_([A-Za-z0-9_]+)=(.*)|# CONFIG_([A-Za-z0-9_]+) is not set)$")
BUILDS = ("dev", "release", "certifiable")


class Refused(Exception):
    pass


def axis_values(kind):
    d = os.path.join(FRAG, kind)
    return sorted(f[:-5] for f in os.listdir(d) if f.endswith(".frag"))


def parse_name(name):
    """(preset, hwclass, arch, build or None, [overlays]) of a defconfig name."""
    cell, *overlays = name.split("+")
    parts = cell.split("-")
    if len(parts) not in (3, 4):
        raise Refused(f"{name}: not <preset>-<hwclass>-<arch>[-<build>][+<overlay>...]")
    preset, hwclass, arch = parts[:3]
    build = parts[3] if len(parts) == 4 else None
    for kind, v in (("presets", preset), ("hwclass", hwclass), ("arch", arch)):
        if v not in axis_values(kind):
            raise Refused(f"{name}: no config/fragments/{kind}/{v}.frag "
                          f"(there are: {', '.join(axis_values(kind))})")
    if build is not None and build not in BUILDS:
        raise Refused(f"{name}: build type {build!r} is not one of {', '.join(BUILDS)}")
    if len(set(overlays)) != len(overlays) or "" in overlays:
        raise Refused(f"{name}: an overlay is empty or named twice")
    return preset, hwclass, arch, build, overlays


def fragments(name):
    """[(path relative to config/fragments, is_overlay)] in merge order."""
    preset, hwclass, arch, build, overlays = parse_name(name)
    out = [(f"presets/{preset}.frag", False), (f"hwclass/{hwclass}.frag", False),
           (f"arch/{arch}.frag", False)]
    if build:
        out.append((f"build/{build}.frag", False))
    for o in overlays:
        found = [p for p in (f"overlays/{o}.frag", f"overlays/{o}-{arch}.frag")
                 if os.path.exists(os.path.join(FRAG, p))]
        if not found:
            raise Refused(f"{name}: no config/fragments/overlays/{o}.frag nor {o}-{arch}.frag")
        out += [(p, True) for p in found]
    return out


def read_fragment(rel):
    lines = open(os.path.join(FRAG, rel), encoding="utf-8").read().splitlines()
    sets = []
    for no, l in enumerate(lines, 1):
        if not l.strip() or (l.startswith("#") and not LINE.match(l)):
            continue
        m = LINE.match(l)
        if not m:
            raise Refused(f"config/fragments/{rel}:{no}: not a CONFIG_ line or a comment: {l!r}")
        sym, val = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), "n")
        sets.append((no - 1, sym, val))
    return lines, sets


def assemble(name):
    """The defconfig text of `name`."""
    frags = fragments(name)
    final = {}   # sym -> (value, fragment index, is_overlay)
    for i, (rel, ov) in enumerate(frags):
        for _, sym, val in read_fragment(rel)[1]:
            if sym in final and final[sym][0] != val:
                prev = frags[final[sym][1]]
                if prev[1] == ov:
                    raise Refused(f"{name}: config/fragments/{prev[0]} and config/fragments/{rel} "
                                  f"set {sym} to {final[sym][0]} and {val}")
            final[sym] = (val, i, ov)
    preset, hwclass, arch, build, overlays = parse_name(name)
    out = [f"# config/defconfigs/{name}.config — generated by tools/build/gen_defconfigs.py; do not edit",
           "#",
           f"# Preset {preset}, hardware class {hwclass}, {arch}, "
           f"{build or 'release (the default)'} build"
           + (f"; overlays: {', '.join(overlays)}." if overlays else "."),
           "# Edit the fragments under config/fragments/ and run `python3 tools/build/gen_defconfigs.py`.",
           f"# `make defconfig-{name}` loads it."]
    for i, (rel, _) in enumerate(frags):
        lines, sets = read_fragment(rel)
        drop = {no: sym for no, sym, _ in sets if final[sym][1] != i}
        out.append("")
        for no, l in enumerate(lines):
            if no in drop:
                out.append(f"# ({drop[no]}: set by config/fragments/{frags[final[drop[no]][1]][0]})")
            else:
                out.append(l)
    return "\n".join(out) + "\n"


def committed():
    return sorted(f[:-len(".config")] for f in os.listdir(DEFDIR) if f.endswith(".config"))


def expanded_axes_ok(names):
    """Each committed defconfig, expanded by Kconfig, keeps its name's axes and
    loads without a warning (an assignment Kconfig drops warns)."""
    import kconfiglib
    old = os.getcwd()
    os.chdir(REPO)
    try:
        k = kconfiglib.Kconfig("Kconfig", warn_to_stderr=False)
        bad = []
        for n in names:
            preset, hwclass, arch, build, _ = parse_name(n)
            nw = len(k.warnings)
            k.load_config(os.path.join(DEFDIR, n + ".config"))
            want = [f"PRESET_{preset.upper()}", f"HWCLASS_{hwclass.upper()}", f"ARCH_{arch.upper()}",
                    f"BUILD_TYPE_{(build or 'release').upper()}"]
            lost = [s for s in want if k.syms[s].str_value != "y"]
            if lost:
                bad.append(f"{n}: expands without {', '.join(lost)}")
            for w in k.warnings[nw:]:
                bad.append(f"{n}: {w.strip()}")
        return bad
    finally:
        os.chdir(old)


def self_test():
    """Each rule, on a scratch tree: an axis conflict is refused, an overlay
    overrides an axis and the overridden line becomes a note, a missing overlay
    is refused, and --check fails a hand-edited defconfig."""
    import tempfile
    global FRAG, DEFDIR
    keep = FRAG, DEFDIR
    fails = []
    with tempfile.TemporaryDirectory() as td:
        FRAG, DEFDIR = os.path.join(td, "fragments"), os.path.join(td, "defconfigs")
        try:
            for d in ("presets", "hwclass", "arch", "build", "overlays"):
                os.makedirs(os.path.join(FRAG, d))
            os.makedirs(DEFDIR)
            put = lambda rel, text: open(os.path.join(FRAG, rel), "w").write(text)
            put("presets/p.frag", "# p\nCONFIG_PRESET_P=y\nCONFIG_A=1\n")
            put("hwclass/h.frag", "# h\nCONFIG_HWCLASS_H=y\nCONFIG_A=2\n")
            put("hwclass/g.frag", "# g\nCONFIG_HWCLASS_G=y\n")
            put("arch/x.frag", "# x\nCONFIG_ARCH_X=y\n")
            put("overlays/o.frag", "# o\nCONFIG_A=3\n")
            put("overlays/q-x.frag", "# q on x\nCONFIG_A=4\n")
            try:
                assemble("p-h-x")
                fails.append("two axis fragments setting CONFIG_A differently were not refused")
            except Refused:
                pass
            t = assemble("p-g-x+o")
            if "CONFIG_A=3" not in t or "# (A: set by config/fragments/overlays/o.frag)" not in t:
                fails.append("an overlay did not override the axis value with a note")
            try:
                assemble("p-g-x+o+q")
                fails.append("two overlays setting CONFIG_A differently were not refused")
            except Refused:
                pass
            try:
                assemble("p-g-x+nope")
                fails.append("a missing overlay was not refused")
            except Refused:
                pass
            if "CONFIG_A=4" not in assemble("p-g-x+q"):
                fails.append("the <overlay>-<arch> fragment was not merged")
            open(os.path.join(DEFDIR, "p-g-x+o.config"), "w").write(t.replace("CONFIG_A=3", "CONFIG_A=5"))
            if assemble("p-g-x+o") == open(os.path.join(DEFDIR, "p-g-x+o.config")).read():
                fails.append("a hand-edited defconfig reads as generated")
        finally:
            FRAG, DEFDIR = keep
    for f in fails:
        print("gen_defconfigs self-test: FAIL", f)
    if not fails:
        print("gen_defconfigs self-test: ok (5 rules)")
    return 1 if fails else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    try:
        if argv[:1] == ["--print"]:
            sys.stdout.write(assemble(argv[1]))
            return 0
        if argv[:1] == ["--check"]:
            bad = []
            for n in committed():
                try:
                    text = assemble(n)
                except Refused as e:
                    bad.append(str(e))
                    continue
                if open(os.path.join(DEFDIR, n + ".config"), encoding="utf-8").read() != text:
                    bad.append(f"config/defconfigs/{n}.config is not what its fragments assemble: "
                               "run python3 tools/build/gen_defconfigs.py")
            if not bad:
                bad = expanded_axes_ok(committed())
            for b in bad:
                print("gen_defconfigs:", b)
            if not bad:
                print(f"gen_defconfigs: ok ({len(committed())} defconfigs)")
            return 1 if bad else 0
        for n in (argv or committed()):
            text = assemble(n)
            p = os.path.join(DEFDIR, n + ".config")
            if not os.path.exists(p) or open(p, encoding="utf-8").read() != text:
                open(p, "w", encoding="utf-8").write(text)
                print("wrote", os.path.relpath(p, REPO))
        return 0
    except Refused as e:
        print("gen_defconfigs:", e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

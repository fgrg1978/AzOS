#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host test of tools/gen_userspace_kconfig.py through kconfiglib, on a copy
of the Kconfig tree and of the program metadata under userspace/:

  1. the real tree: the images the board volume carries by default are the
     ones the topology declares (the 14 of `make board-elfs`), the console
     program is the native shell on edge and none on embedded;
  2. a program directory added under userspace/ appears in the menu
     (default n), and may be chosen as the console program;
  3. deleted again: olddefconfig drops its symbols, the console program
     falls back to the default (native sh on edge), and the configuration
     step warns that the chosen program is gone;
  4. a bad metadata line removes the generated file, so the next parse fails
     instead of reading a stale menu.

    python3 tools/test_gen_userspace_kconfig.py      (exit 0 = all pass)
"""

import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOARD_DEFAULT = {
    "BUZZDRV", "GPIODRV", "INADRV", "BRAINCLI", "FLIGHT", "BEHAVIOR", "CONFIG", "OTA",
    "MLSRV", "POWER", "REFLEX", "SH", "TOOLBOX", "TRACECTL",
}
FAILS = []


def check(cond, what):
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        FAILS.append(what)


def copy_tree(dst):
    shutil.copy(os.path.join(REPO, "Kconfig"), dst)
    shutil.copytree(os.path.join(REPO, "config"), os.path.join(dst, "config"),
                    ignore=shutil.ignore_patterns("Kconfig.userspace*"))
    os.makedirs(os.path.join(dst, "tools"))
    shutil.copy(os.path.join(REPO, "tools", "gen_userspace_kconfig.py"), os.path.join(dst, "tools"))
    src = os.path.join(REPO, "userspace")
    for cls in sorted(os.listdir(src)):
        cdir = os.path.join(src, cls)
        if not os.path.isdir(cdir):
            continue
        if cls == "thirdparty":
            os.makedirs(os.path.join(dst, "userspace", cls), exist_ok=True)
            for f in os.listdir(cdir):
                if f.endswith(".fragment"):
                    shutil.copy(os.path.join(cdir, f), os.path.join(dst, "userspace", cls))
            continue
        for prog in sorted(os.listdir(cdir)):
            pdir = os.path.join(cdir, prog)
            if not os.path.isdir(pdir):
                continue
            out = os.path.join(dst, "userspace", cls, prog)
            os.makedirs(out)
            for f in os.listdir(pdir):
                if f in ("Cargo.toml", "azos.toml") or f.endswith((".c", ".S")):
                    shutil.copy(os.path.join(pdir, f), out)


def olddefconfig(root, cfg):
    env = dict(os.environ, KCONFIG_CONFIG=cfg)
    r = subprocess.run([sys.executable, "-m", "olddefconfig", "Kconfig"], cwd=root, env=env,
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def values(cfg):
    out = {}
    with open(cfg, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("CONFIG_") and "=" in line:
                k, v = line.split("=", 1)
                out[k[7:]] = v
    return out


def defconfig(root, name, cfg):
    shutil.copy(os.path.join(root, "config", "defconfigs", name + ".config"), cfg)
    rc, log = olddefconfig(root, cfg)
    return rc, log, values(cfg)


def main():
    tmp = tempfile.mkdtemp(prefix="gen-uskc-")
    try:
        copy_tree(tmp)
        cfg = os.path.join(tmp, "t.config")

        # 1. The real tree.
        rc, log, v = defconfig(tmp, "edge", cfg)
        check(rc == 0, "edge defconfig expands")
        on = {k[len("USERSPACE_"):] for k, x in v.items()
              if k.startswith("USERSPACE_") and x == "y"} - {"GPL", "TOPOLOGY_ROWS"}
        check(on == BOARD_DEFAULT, f"edge: board images by default = topology rows ({sorted(on ^ BOARD_DEFAULT)} differ)")
        check(v.get("CONSOLE_PROGRAM_SH") == "y" and v.get("CONSOLE_PATH") == '"/fat/SH.ELF"'
              and v.get("USER_SHELL") == "y", "edge: console = native sh, USER_SHELL=y")
        rc, log, v = defconfig(tmp, "embedded", cfg)
        check(v.get("CONSOLE_PROGRAM_NONE") == "y" and "USER_SHELL" not in v
              and v.get("CONSOLE_PATH") == '""', "embedded: console = none, USER_SHELL=n")

        # 2. Add a program directory.
        dummy = os.path.join(tmp, "userspace", "tests", "dummyprg")
        os.makedirs(dummy)
        with open(os.path.join(dummy, "Cargo.toml"), "w") as f:
            f.write('[package]\nname = "dummyprg"\ndescription = "A test program."\n')
        rc, log, v = defconfig(tmp, "edge", cfg)
        gen = open(os.path.join(tmp, "config", "Kconfig.userspace")).read()
        check("config USERSPACE_DUMMYPRG" in gen and "config CONSOLE_PROGRAM_DUMMYPRG" in gen,
              "added dir: USERSPACE_DUMMYPRG and its console choice are generated")
        check("# CONFIG_USERSPACE_DUMMYPRG is not set" in open(cfg).read(), "added dir: default n")
        with open(cfg, "a") as f:
            f.write("CONFIG_USERSPACE_DUMMYPRG=y\nCONFIG_CONSOLE_PROGRAM_DUMMYPRG=y\n")
        rc, log = olddefconfig(tmp, cfg)
        v = values(cfg)
        check(rc == 0 and v.get("USERSPACE_DUMMYPRG") == "y" and v.get("CONSOLE_PROGRAM_DUMMYPRG") == "y"
              and v.get("CONSOLE_PATH") == '"/fat/DUMMYPRG.ELF"' and v.get("USER_SHELL") == "y",
              "added dir: selectable as the console program (CONSOLE_PATH=/fat/DUMMYPRG.ELF)")

        # 3. Delete it again.
        shutil.rmtree(dummy)
        rc, log = olddefconfig(tmp, cfg)
        v = values(cfg)
        gen = open(os.path.join(tmp, "config", "Kconfig.userspace")).read()
        text = open(cfg).read()
        check("DUMMYPRG" not in gen and "DUMMYPRG" not in text,
              "deleted dir: its symbols leave the menu and the .config")
        check(rc == 0 and v.get("CONSOLE_PROGRAM_SH") == "y" and v.get("CONSOLE_PATH") == '"/fat/SH.ELF"',
              "deleted dir: the console program falls back to native sh")
        check("CONSOLE_PROGRAM_DUMMYPRG names a program that is no longer under userspace/" in log,
              "deleted dir: olddefconfig warns about the console program")

        # 4. A bad metadata line: no stale menu.
        bad = os.path.join(tmp, "userspace", "tests", "badprg")
        os.makedirs(bad)
        with open(os.path.join(bad, "azos.toml"), "w") as f:
            f.write('[azos]\nimages = ["not-8.3-name.elf"]\n')
        rc, log = olddefconfig(tmp, cfg)
        check(rc != 0 and not os.path.exists(os.path.join(tmp, "config", "Kconfig.userspace")),
              "bad metadata: generated file removed, olddefconfig fails")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"{len(FAILS)} failed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

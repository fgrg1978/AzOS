#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_user_images.py: the ring-3 images follow the .config.

    python3 tools/image/test_user_images.py        (exit 0 = all pass)

Kconfig USERSPACE_<NAME> decides which programs the build makes, which the
digest tables bind and which the system volume carries (mk/vars.mk, mk/system.mk).
Each case writes a configuration, asks make what it would run (`make -n`: no
cargo, no QEMU) and compares the images on the command lines with the images
the configuration enables, taken from the configuration and from the program
metadata, not from the Makefile:

  1. an image off in the configuration is on no table (three ISAs) and no
     system volume (three ISAs); one on is on both;
  2. the table that lists nothing is written, not refused;
  3. the selection stamp keeps its mtime while the selection is the same and
     changes with it, so the tables and volumes follow Kconfig and not only the
     ELFs' timestamps.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = azos_tools.ROOT
FAILS = []
DEFCONFIG = "config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config"
TABLES = {
    "riscv64": "image_hashes.rs",
    "aarch64": "image_hashes_aarch64.rs",
    "x86_64": "image_hashes_x86_64.rs",
}
VOLUMES = {
    "riscv64": "disk-system.img",
    "aarch64": "disk-aarch64-system.img",
    "x86_64": "disk-x86_64-system.img",
}


def check(cond, what):
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        FAILS.append(what)


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def catalogue():
    """Every program image the tree builds, from the program metadata."""
    out = run([sys.executable, "tools/build/gen_userspace_kconfig.py", "--all-on"]).stdout
    return sorted(re.findall(r"CONFIG_USERSPACE_([A-Z0-9_]+)=y", out))


def write_config(path, on, off):
    """The development robot configuration, expanded, with `on` and `off` as asked."""
    shutil.copy(os.path.join(ROOT, DEFCONFIG), path)
    env = dict(os.environ, KCONFIG_CONFIG=path)
    r = subprocess.run([sys.executable, "-m", "olddefconfig"], cwd=ROOT, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"olddefconfig failed: {r.stderr}")
    names = set(on) | set(off)
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines()
                 if not any(re.fullmatch(rf"(# )?CONFIG_USERSPACE_{n}(=y| is not set)", ln) for n in names)]
    lines += [f"CONFIG_USERSPACE_{n}=y" for n in sorted(on)]
    lines += [f"# CONFIG_USERSPACE_{n} is not set" for n in sorted(off)]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def enabled(config, images):
    with open(config, encoding="utf-8") as f:
        on = set(re.findall(r"^CONFIG_USERSPACE_([A-Z0-9_]+)=y$", f.read(), re.M))
    return sorted(n for n in images if n in on)


def make_n(config, out, *goals):
    env = dict(os.environ, KCONFIG_CONFIG=config, AZOS_OUT=out)
    env.pop("MAKEFLAGS", None)
    r = subprocess.run(["make", "-n", *goals], cwd=ROOT, env=env, capture_output=True, text=True)
    return r.stdout, r.stderr, r.returncode


def table_images(out, goal):
    """The images the table recipe hashes: the NAME= of its image_hashes.py line."""
    names = None
    for ln in out.splitlines():
        m = re.search(r"userspace/image_hashes\.py (?!--)\S+ ?(.*)$", ln)
        if m and goal in ln:
            names = sorted(re.findall(r"([A-Z0-9_]+)\.ELF=", m.group(1)))
    return names


def volume_images(out):
    return sorted(set(re.findall(r"mcopy -i \S+ \S+ ::([A-Z0-9_]+)\.ELF", out)) - {"BUSYBOX"})


def main():
    images = catalogue()
    check(len(images) > 40 and "SH" in images and "HELLO" in images, f"the metadata lists the programs ({len(images)})")
    tmp = tempfile.mkdtemp(prefix="user-images-")
    try:
        out = os.path.join(tmp, "out")
        cfg = os.path.join(tmp, "dev.config")
        # SSHD: a service with a prompt, on in this profile; HELLO and ABITEST: test programs, off in it.
        write_config(cfg, on=["HELLO", "ABITEST"], off=["SSHD"])
        want = enabled(cfg, images)
        check("HELLO" in want and "SSHD" not in want, "the configuration enables HELLO and not SSHD")
        for isa, table in TABLES.items():
            goal = f"{out}/build/{table}"
            stdout, stderr, rc = make_n(cfg, out, goal)
            got = table_images(stdout, goal)
            check(rc == 0 and got is not None, f"{isa}: make -n {table} plans the table ({stderr.strip()[:80]})")
            check(got == want, f"{isa}: the table hashes exactly the enabled images (extra {sorted(set(got or []) - set(want))}, missing {sorted(set(want) - set(got or []))})")
            check("SSHD" not in (got or []) and "HELLO" in (got or []), f"{isa}: SSHD is off the table, HELLO is on it")
        for isa, vol in VOLUMES.items():
            stdout, stderr, rc = make_n(cfg, out, f"{out}/build/{vol}")
            got = volume_images(stdout)
            check(rc == 0, f"{isa}: make -n {vol} plans the volume ({stderr.strip()[:80]})")
            check(got == want, f"{isa}: the system volume carries exactly the enabled images (extra {sorted(set(got) - set(want))}, missing {sorted(set(want) - set(got))})")
            check("SSHD" not in got and "HELLO" in got, f"{isa}: SSHD is off the volume, HELLO is on it")

        # Nothing enabled but what the profile forces: the smallest table, written as it is.
        empty = os.path.join(tmp, "none.config")
        with open(empty, "w", encoding="utf-8") as f:
            f.write("CONFIG_ARCH_RISCV64=y\n")
        goal = f"{out}/build/image_hashes.rs"
        stdout, _, rc = make_n(empty, out, goal)
        check(rc == 0 and table_images(stdout, goal) == [], "a configuration that enables no image plans an empty table")
        stub = os.path.join(tmp, "table.rs")
        r = run([sys.executable, "userspace/image_hashes.py", stub])
        check(r.returncode == 0 and "IMAGE_SHA256: &[(&str, [u8; 32])] = &[\n];" in open(stub, encoding="utf-8").read(),
              "image_hashes.py writes an empty table for no image")

        # The stamp follows the selection.
        stamp = f"{out}/build/user-images.on"
        env = dict(os.environ, KCONFIG_CONFIG=cfg, AZOS_OUT=out)
        env.pop("MAKEFLAGS", None)
        mk = lambda: subprocess.run(["make", "-s", stamp], cwd=ROOT, env=env, capture_output=True, text=True)
        r1 = mk()
        m1 = os.stat(stamp).st_mtime_ns
        time.sleep(0.05)
        r2 = mk()
        m2 = os.stat(stamp).st_mtime_ns
        check(r1.returncode == 0 and r2.returncode == 0 and m1 == m2, "an unchanged selection leaves the stamp alone")
        write_config(cfg, on=["HELLO", "ABITEST", "SSHD"], off=[])
        mk()
        text = open(stamp, encoding="utf-8").read().split()
        check(os.stat(stamp).st_mtime_ns != m2 and "SSHD.ELF" in text, "a changed selection rewrites the stamp")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"{len(FAILS)} failed" if FAILS else "all pass")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

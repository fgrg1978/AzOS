#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Write config/Kconfig.userspace from the programs under userspace/.

    python3 tools/gen_userspace_kconfig.py [--root DIR] [--out FILE] [--config FILE]

The root `Kconfig` runs this script from a `$(shell,...)` line before it
sources the file, so every kconfiglib entry point (menuconfig, olddefconfig,
`make defconfig-*`, the build's own `.config` refresh, tools that load the
tree) sees the programs that exist now. `crates/core/limits/build.rs` runs it
too, before it reads the Kconfig tree. The output is not committed
(`.gitignore`): a program directory added under userspace/ appears in the
menu at the next configuration, and a deleted one disappears (olddefconfig
drops its symbol).

What it scans (one program directory = one directory below a class):

    userspace/{bench,drivers,services,tests}/<prog>/   Cargo.toml, or C sources
    userspace/thirdparty/busybox.fragment              BusyBox (BUSYBOX.ELF)

Each program directory names the FAT32 images it builds. A Cargo crate says so
in `[package.metadata.azos]`, a C program in `azos.toml` (`[azos]` table):

    images   = ["SH.ELF"]   # default: the directory name, upper-cased, 8.3
    topology = true         # the built-in topology has a row for it whenever
                            # the volume carries it (always, but on a small board)
    default  = "y"          # or a Kconfig expression; default n
    start    = "<expr>"     # the Kconfig condition under which the topology
                            # STARTS the image at boot (absent: never)

`images = []` marks a directory that builds no AzOS program (a Linux module,
a Linux baseline's init). A `topology = true` image defaults y and, outside a
small board, has no prompt: the board volume must carry every image the
topology declares (`tools/gen_board_manifest.py` fails otherwise), so it is
not a choice there.

A small board (HWCLASS_EMBEDDED) builds only what its topology names, so
there every image defaults n except the ones whose `start` condition holds
(the rows the kernel starts: `set_last_task_start` in
crates/core/topology/src/builder.rs). Every image has a prompt on a small
board, so the config can name the others (a defconfig line) and the
volume then carries them; `start` must not read a symbol that depends on
a USERSPACE_ symbol (the console choice does), which would be a cycle.

Output, in a menu "Userspace programs":

  * one bool per image, `USERSPACE_<STEM>` ("include in the board volume");
    BusyBox is not generated: its one symbol is `BUSYBOX` in
    config/Kconfig.linux, which the console choice below reads;
  * `choice` CONSOLE_PROGRAM: native sh, BusyBox sh, any other included
    image, a custom /fat path with arguments, or none;
  * the derived strings the kernel and the topology read: CONSOLE_PATH and
    CONSOLE_ARGS.

`--config FILE` (default `$KCONFIG_CONFIG`, else `.config`): an existing
configuration whose console program names an image that no longer exists
gets a warning on stderr; olddefconfig then drops that symbol and the
choice falls back to its default.

The output file is rewritten only when its contents change (it is a
`rerun-if-changed` input of `azos_limits`). On an error it is removed, so
the `source` line fails instead of reading a stale menu.
"""

import os
import re
import sys

CLASSES = ("bench", "drivers", "services", "tests")
OUT_REL = os.path.join("config", "Kconfig.userspace")

# Choice members that are not per-program.
FIXED_CHOICES = {"SH", "BUSYBOX_SH", "CUSTOM", "NONE"}
# The three images of the native shell session; CONSOLE_PROGRAM_SH names them
# all (the console program is the terminal server, which the shell is a client
# of, and the shell reaches it through the name server).
NATIVE_SHELL_IMAGES = {"SH.ELF", "TERMD.ELF", "NAMESD.ELF"}


class GenError(Exception):
    pass


def parse_value(raw, where):
    raw = raw.strip()
    if raw in ("true", "false"):
        return raw == "true"
    if raw.startswith('"'):
        m = re.fullmatch(r'"((?:[^"\\]|\\.)*)"', raw)
        if not m:
            raise GenError(f"{where}: bad string {raw!r}")
        return m.group(1).replace('\\"', '"').replace("\\\\", "\\")
    if raw.startswith("["):
        if not raw.endswith("]"):
            raise GenError(f"{where}: arrays must be on one line: {raw!r}")
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [parse_value(x, where) for x in re.findall(r'"(?:[^"\\]|\\.)*"', inner)]
    raise GenError(f"{where}: unsupported value {raw!r} (strings, booleans, string arrays)")


def read_table(path, table):
    """The `key = value` lines of `[table]` in a TOML file (the subset the
    program metadata uses: strings, booleans, one-line string arrays)."""
    out = {}
    cur = None
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            s = line.strip() if '"' in line else line.split("#", 1)[0].strip()
            if s.startswith("#"):
                continue
            if not s:
                continue
            if s.startswith("["):
                cur = s.strip("[]").strip()
                continue
            if cur != table or "=" not in s:
                continue
            k, v = s.split("=", 1)
            out[k.strip()] = parse_value(v, f"{path}:{n}")
    return out


def default_image(dirname):
    stem = re.sub(r"[^A-Z0-9]", "", dirname.upper())[:8] or "PROG"
    return stem + ".ELF"


def stem_of(image):
    return re.sub(r"[^A-Z0-9]", "_", image.rsplit(".", 1)[0].upper())


def scan(root):
    """[(class, dir, images, meta, description)] in a stable order."""
    progs = []
    for cls in CLASSES:
        base = os.path.join(root, "userspace", cls)
        if not os.path.isdir(base):
            continue
        for d in sorted(os.listdir(base)):
            p = os.path.join(base, d)
            if not os.path.isdir(p) or d.startswith(".") or re.search(r" \d+$", d):
                continue
            cargo = os.path.join(p, "Cargo.toml")
            sidecar = os.path.join(p, "azos.toml")
            if os.path.isfile(cargo):
                meta = read_table(cargo, "package.metadata.azos")
                pkg = read_table(cargo, "package")
                desc = pkg.get("description", "") if isinstance(pkg.get("description", ""), str) else ""
            elif os.path.isfile(sidecar) or any(f.endswith((".c", ".S")) for f in os.listdir(p)):
                meta = read_table(sidecar, "azos") if os.path.isfile(sidecar) else {}
                desc = meta.get("description", "")
            else:
                continue
            images = meta.get("images", [default_image(d)])
            if not isinstance(images, list) or not all(isinstance(i, str) for i in images):
                raise GenError(f"{p}: images must be a list of strings")
            for img in images:
                if not re.fullmatch(r"[A-Z0-9_]{1,8}\.ELF", img):
                    raise GenError(f"{p}: image {img!r} is not an 8.3 NAME.ELF")
            progs.append((cls, d, images, meta, desc))
    seen = {}
    for cls, d, images, _, _ in progs:
        for img in images:
            if img in seen:
                raise GenError(f"image {img} is built by both {seen[img]} and userspace/{cls}/{d}")
            seen[img] = f"userspace/{cls}/{d}"
    return progs


def busybox_present(root):
    return os.path.isfile(os.path.join(root, "userspace", "thirdparty", "busybox.fragment"))


def wrap(text, indent="      ", width=76):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width - len(indent):
            lines.append(indent + cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    if cur:
        lines.append(indent + cur)
    return lines


def kstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(root):
    progs = scan(root)
    bb = busybox_present(root)
    L = []
    a = L.append
    a("# GENERATED by tools/gen_userspace_kconfig.py from the directories under")
    a("# userspace/ at every configuration. Not committed; do not edit.")
    a("")
    a('menu "Userspace programs"')
    a("")
    a('comment "Images on the board volume (AZOS_OUT/build/disk-board*.img)"')
    images = []  # (image, stem, cls, dir)
    for cls in CLASSES:
        members = [p for p in progs if p[0] == cls]
        if not members:
            continue
        a("")
        a(f'menu "{cls}"')
        for _, d, imgs, meta, desc in members:
            for img in imgs:
                stem = stem_of(img)
                images.append((img, stem, cls, d))
                a("")
                a(f"config USERSPACE_{stem}")
                topo = bool(meta.get("topology"))
                if topo:
                    # No prompt outside a small board: the volume always carries it.
                    a(f'    bool "{img} (userspace/{cls}/{d})" if HWCLASS_EMBEDDED')
                else:
                    a(f'    bool "{img} (userspace/{cls}/{d})"')
                dflt = meta.get("default")
                start = meta.get("start")
                if start is not None and not (isinstance(start, str) and start.strip()):
                    raise GenError(f"userspace/{cls}/{d}: start must be a Kconfig expression")
                # Large boards: the program's own default. Small boards: only a
                # started row (the owner rule, tools/check_presets.py).
                if topo or dflt is True or dflt == "y":
                    a("    default y if !HWCLASS_EMBEDDED")
                elif isinstance(dflt, str) and dflt and dflt != "n":
                    a(f"    default y if !HWCLASS_EMBEDDED && ({dflt})")
                if start:
                    a(f"    default y if HWCLASS_EMBEDDED && ({start})")
                a("    default n")
                a("    help")
                for ln in wrap(desc or f"The program built from userspace/{cls}/{d}."):
                    a(ln)
                a("")
                if topo:
                    for ln in wrap(
                        f"The built-in topology has a row for {img}, so the board volume "
                        "carries it (not a choice). On a small board (HWCLASS_EMBEDDED) the "
                        "volume carries only what the topology starts"
                        + (f" ({start})" if start else " (this image it never starts)")
                        + " and what the config names, and the topology has the row only then."
                    ):
                        a(ln)
                else:
                    for ln in wrap(
                        f"y: the board volume carries /fat/{img}. A program the topology has "
                        "no row for is refused at spawn unless it is the console program "
                        "below, which gets a row of its own. Cost: the image's size on the volume."
                    ):
                        a(ln)
        a("")
        a("endmenu")
    # The console program.
    a("")
    a("choice CONSOLE_PROGRAM")
    a('    prompt "Console program (started on the console at boot)"')
    a("    default CONSOLE_PROGRAM_SH if !HWCLASS_EMBEDDED")
    a("    default CONSOLE_PROGRAM_NONE")
    a("    help")
    for ln in wrap(
        "The ring-3 program the kernel starts on the console when boot completes. "
        "Its topology row says start = true, so it is hash-bound, runs under its "
        "seccomp profile and its row's capabilities, and is started and supervised "
        "like any other row, by the component manager. The in-kernel shell stays "
        "the recovery console: it takes the "
        "console in safe mode, when the image is missing from the volume, when the "
        "program does not take console input within SH_START_TIMEOUT_S, or after "
        "it ended and its row does not restart it. With secure boot off, `init=/fat/NAME.ELF` "
        "on the kernel command line starts another image instead (its row must "
        "say start = true); with secure boot on it is ignored and the boot log says so."
    ):
        a(ln)
    a("")
    a("config CONSOLE_PROGRAM_SH")
    a('    bool "Native shell (SH.ELF, served by TERMD.ELF, named by NAMESD.ELF)"')
    a("    depends on USERSPACE_SH && USERSPACE_TERMD && USERSPACE_NAMESD && CAP_SLOT_EXT && MAX_FDS_PER_PROC >= 16 && MAX_MEMOBJS >= 8")
    a("    help")
    for ln in wrap(
        "userspace/services/sh runs programs with SYS_SPAWN_EX, each under its own "
        "row; it reads no console: its terminal is the Terminal object that "
        "userspace/services/termd (TERMD.ELF, the console program) serves over "
        "the endpoint.term endpoint, with the line editing, echo and history in "
        "the server and ^C as a typed event. The shell holds no grant on that "
        "endpoint: its row imports the name term, and the name server "
        "(userspace/services/namesd, NAMESD.ELF) lends it an attenuated "
        "capability, telling callers apart by the badge the kernel stamps from "
        "the signed row (CAP_SLOT_EXT). All three images start; the server takes "
        "console input. Needs MAX_FDS_PER_PROC >= 16 and MAX_MEMOBJS >= 8 (a "
        "pipe is a memory object; a pipeline with redirections holds several)."
    ):
        a(ln)
    if bb:
        a("")
        a("config CONSOLE_PROGRAM_BUSYBOX_SH")
        a('    bool "BusyBox sh (BUSYBOX.ELF, Linux personality, GPL-2.0-only)"')
        a("    depends on USERSPACE_GPL && LINUX_ABI && BUSYBOX")
        a("    help")
        for ln in wrap(
            "BusyBox's ash, run as `sh` under the Linux personality: the kernel "
            "starts BUSYBOX.ELF with argv `sh`, descriptors 0-2 on the console and "
            "console input lent to it (^C is SIGINT to it and its children). "
            "Needs USERSPACE_GPL (the volume is then distributed under GPL-2.0, "
            "see `make busybox-source-offer`), LINUX_ABI and BUSYBOX on. Needs zig and "
            "the pinned tarball to build (`make busybox`)."
        ):
            a(ln)
    for img, stem, cls, d in images:
        if stem in FIXED_CHOICES or img in NATIVE_SHELL_IMAGES:
            continue
        a("")
        a(f"config CONSOLE_PROGRAM_{stem}")
        a(f'    bool "{img} (userspace/{cls}/{d})"')
        a(f"    depends on USERSPACE_{stem}")
    a("")
    a("config CONSOLE_PROGRAM_CUSTOM")
    a('    bool "Custom image and arguments"')
    a("    help")
    for ln in wrap("CONSOLE_PROGRAM_CUSTOM_PATH with CONSOLE_PROGRAM_CUSTOM_ARGS."):
        a(ln)
    a("")
    a("config CONSOLE_PROGRAM_NONE")
    a('    bool "None (the in-kernel shell has the console)"')
    a("")
    a("endchoice")
    a("")
    a("config CONSOLE_PROGRAM_CUSTOM_PATH")
    a('    string "Custom console program: image path (/fat/NAME.ELF)"')
    a("    depends on CONSOLE_PROGRAM_CUSTOM")
    a('    default "/fat/SH.ELF"')
    a("    help")
    for ln in wrap(
        "An 8.3 image directly under /fat (the loader starts only those). If no "
        "topology row names it, one is added (no capabilities, best_effort). The "
        "board volume build fails if this tree does not build the image."
    ):
        a(ln)
    a("")
    a("config CONSOLE_PROGRAM_CUSTOM_ARGS")
    a('    string "Custom console program: argv (space-separated, argv[0] first)"')
    a("    depends on CONSOLE_PROGRAM_CUSTOM")
    a('    default ""')
    a("    help")
    for ln in wrap(
        "Passed to a Linux-ABI image (its row says abi = \"linux\") as its argv; "
        "empty: argv[0] is the image name. A native image takes no arguments from "
        "the kernel: the build refuses arguments for one."
    ):
        a(ln)
    a("")
    a("config CONSOLE_PATH")
    a("    string")
    a('    default "/fat/TERMD.ELF" if CONSOLE_PROGRAM_SH')
    if bb:
        a('    default "/fat/BUSYBOX.ELF" if CONSOLE_PROGRAM_BUSYBOX_SH')
    for img, stem, _, _ in images:
        if stem in FIXED_CHOICES or img in NATIVE_SHELL_IMAGES:
            continue
        a(f'    default "/fat/{img}" if CONSOLE_PROGRAM_{stem}')
    a("    default CONSOLE_PROGRAM_CUSTOM_PATH if CONSOLE_PROGRAM_CUSTOM")
    a('    default ""')
    a("    help")
    a("      Derived from CONSOLE_PROGRAM: the console program's image, \"\" for none.")
    a("")
    a("config CONSOLE_ARGS")
    a("    string")
    if bb:
        a('    default "sh" if CONSOLE_PROGRAM_BUSYBOX_SH')
    a("    default CONSOLE_PROGRAM_CUSTOM_ARGS if CONSOLE_PROGRAM_CUSTOM")
    a('    default ""')
    a("    help")
    a("      Derived from CONSOLE_PROGRAM: the console program's argv, \"\" for its name.")
    a("")
    a("endmenu")
    a("")
    return "\n".join(L), {s for (_, s, _, _) in images}


def warn_stale_console(config_path, stems, bb):
    if not config_path or not os.path.isfile(config_path):
        return
    with open(config_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"CONFIG_CONSOLE_PROGRAM_([A-Z0-9_]+)=y$", line.strip())
            if not m:
                continue
            s = m.group(1)
            if s in ("SH", "CUSTOM", "NONE") or s in stems or (s == "BUSYBOX_SH" and bb):
                continue
            sys.stderr.write(
                f"warning: {config_path}: CONSOLE_PROGRAM_{s} names a program that is no "
                f"longer under userspace/; the console program falls back to the default "
                f"(native sh where the profile has one)\n"
            )


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    out = None
    config = os.environ.get("KCONFIG_CONFIG") or ".config"
    it = iter(argv[1:])
    for arg in it:
        if arg == "--root":
            root = next(it)
        elif arg == "--out":
            out = next(it)
        elif arg == "--config":
            config = next(it)
        else:
            sys.stderr.write(f"gen_userspace_kconfig.py: unknown argument {arg!r}\n")
            return 2
    out = out or os.path.join(root, OUT_REL)
    try:
        text, stems = render(root)
    except (GenError, OSError) as e:
        try:
            os.remove(out)
        except OSError:
            pass
        sys.stderr.write(f"gen_userspace_kconfig.py: {e}\n")
        return 1
    warn_stale_console(config, stems, busybox_present(root))
    try:
        with open(out, encoding="utf-8") as f:
            if f.read() == text:
                return 0
    except OSError:
        pass
    tmp = f"{out}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

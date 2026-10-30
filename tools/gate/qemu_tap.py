#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Stand-in for qemu-system-* on the gate's PATH: note where the console goes, then become QEMU.

The gate (tools/gate/ci_check.sh) links this file as qemu-system-<arch> in a
directory it puts first on PATH. When CI_QTAP_REG names a file, one line per
console file is appended to it: the file the process' stdout is (a row writes
`>"$log"`) and every `-serial file:...` / `-chardev file,path=...` target.
The row's verdict then judges those files (tools/gate/console_judge.py).

The process is replaced (exec), so the pid a row keeps and kills is QEMU's.
"""

import fcntl
import os
import sys

F_GETPATH = 50  # macOS: the path of an open descriptor


def stdout_path():
    try:
        raw = fcntl.fcntl(1, F_GETPATH, b"\0" * 1024)
    except OSError:  # a pipe or a terminal: nothing to judge
        return None
    return raw.split(b"\0", 1)[0].decode(errors="replace") or None


def arg_paths(args):
    out = []
    for a in args:
        for part in a.split(","):
            for key in ("file:", "path="):
                if part.startswith(key):
                    out.append(part[len(key):])
    return out


def real_qemu(name):
    here = os.path.dirname(os.path.abspath(sys.argv[0]))
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and os.path.abspath(d) != here:
            cand = os.path.join(d, name)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    sys.exit(f"qemu_tap: no {name} on PATH outside {here}")


def main():
    name = os.path.basename(sys.argv[0])
    reg = os.environ.get("CI_QTAP_REG")
    if reg:
        paths = [p for p in [stdout_path()] + arg_paths(sys.argv[1:]) if p]
        if paths:
            with open(reg, "a", encoding="utf-8") as f:
                f.write("".join(p + "\n" for p in paths))
    real = real_qemu(name)
    os.execv(real, [real] + sys.argv[1:])


if __name__ == "__main__":
    main()

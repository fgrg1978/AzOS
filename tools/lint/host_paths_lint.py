#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""No tracked file names where one host installed its tools (they come from PATH
or from asking a package manager), or counts QEMU with `pgrep -x`, which matches
nothing on Linux: the tree builds and paces itself on any machine."""
import re
import subprocess
import sys

BAD = re.compile(r"/opt/homebrew|/usr/local/(?:opt|share/qemu)|/Users/[a-z]|pgrep\s[^|]*-x qemu-system|^\s*target = .[a-z0-9_]+-apple-darwin")
SELF = "tools/lint/host_paths_lint.py"


def hits(lines):
    return [(n, l) for n, l in enumerate(lines, 1) if BAD.search(l)]


def main(argv):
    if "--self-test" in argv:
        if not hits(["cc=/opt/homebrew/opt/llvm/bin/clang"]) or not hits(["# /Users/someone/x"]) \
                or not hits(["n=$(pgrep -g 1 -x qemu-system-x86_64 | wc -l)"]) \
                or not hits(['target = "aarch64-apple-darwin"']):
            print("host_paths_lint self-test: a fixed path passed")
            return 1
        if hits(["cc=$(brew --prefix llvm)/bin/clang", "/usr/local/bin is on PATH"]):
            print("host_paths_lint self-test: a detected path was refused")
            return 1
        return 0
    bad = 0
    files = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
    for f in files.decode().split("\0"):
        if not f or f == SELF or f.startswith("third_party/"):
            continue
        try:
            lines = open(f, encoding="utf-8").read().splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in hits(lines):
            print("%s:%d: host install path: %s" % (f, n, line.strip()[:90]))
            bad = 1
    return bad


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

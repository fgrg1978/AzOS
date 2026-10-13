#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Add SPDX license headers to every tracked source file that lacks one.

Usage: python3 tools/spdx_headers.py [--check] [--root DIR]

--check   list the files that would change and exit 1 if any; write nothing.

Idempotent: a file whose first lines already carry an SPDX-License-Identifier
is left alone. Files that cannot take a comment (docs, data, images, keys,
lock files) are covered by REUSE.toml instead.
"""
import os
import subprocess
import sys

LICENSE = "Apache-2.0 OR GPL-2.0-only"
HOLDER = "2026 Fernando Rodriguez"

# Comment style by file kind. Assembly that goes through the C preprocessor
# (.S) and linker scripts take block comments: a '#' line would be read as a
# preprocessor directive.
LINE_SLASH = ("// ", "")
LINE_HASH = ("# ", "")
BLOCK = ("/* ", " */")

BY_SUFFIX = {
    ".rs": LINE_SLASH,
    ".S": BLOCK,
    ".ld": BLOCK,
    ".py": LINE_HASH,
    ".sh": LINE_HASH,
}
BY_NAME = {"Makefile": LINE_HASH}

# Trees that carry their own license (Linux sources, and our glue that includes
# Linux headers, which is GPL-2.0-only): never stamped with the project header.
# The rest of lx/ (lx/emul, our own Rust) takes the project header.
SKIP_PREFIXES = ("third_party/", "lx/glue/")


def asm_style(text):
    """Assembly takes the comment syntax the file already uses: LLVM's
    AArch64 parser rejected a block comment at the start of the second
    `global_asm!` file, and `#` is a comment only on RISC-V."""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("//"):
            return LINE_SLASH
        if s.startswith("#") and not s.startswith("#include") and not s.startswith("#define"):
            return LINE_HASH
        if s:
            break
    return BLOCK


def style_for(path):
    name = os.path.basename(path)
    if name in BY_NAME:
        return BY_NAME[name]
    if name.startswith("Kconfig"):
        return LINE_HASH
    if name.endswith(".mk"):
        return LINE_HASH
    return BY_SUFFIX.get(os.path.splitext(name)[1])


def header(style):
    pre, post = style
    return (
        f"{pre}SPDX-License-Identifier: {LICENSE}{post}\n"
        f"{pre}SPDX-FileCopyrightText: {HOLDER}{post}\n"
    )


def has_header(text):
    return "SPDX-License-Identifier" in "\n".join(text.splitlines()[:6])


def with_header(text, style):
    lines = text.splitlines(keepends=True)
    keep = 0
    # A shebang must stay on line 1; a Python encoding cookie on line 1 or 2.
    # (Rust's `#![attr]` is not a shebang.)
    if lines and lines[0].startswith("#!") and not lines[0].startswith("#!["):
        keep = 1
    if style is LINE_HASH and len(lines) > keep and "coding" in lines[keep] and lines[keep].startswith("#"):
        keep += 1
    return "".join(lines[:keep]) + header(style) + "".join(lines[keep:])


def main():
    check = "--check" in sys.argv
    root = "."
    if "--root" in sys.argv:
        root = sys.argv[sys.argv.index("--root") + 1]
    files = subprocess.check_output(["git", "-C", root, "ls-files", "-z"]).decode().split("\0")
    changed = []
    for rel in files:
        if not rel:
            continue
        style = style_for(rel)
        if style is None or rel.startswith(SKIP_PREFIXES) or "/lx/glue/" in rel:
            continue
        path = os.path.join(root, rel)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if has_header(text):
            continue
        if rel.endswith(".S"):
            style = asm_style(text)
        changed.append(rel)
        if not check:
            with open(path, "w", encoding="utf-8") as f:
                f.write(with_header(text, style))
    for rel in changed:
        print(rel)
    print(f"{len(changed)} file(s) {'need a header' if check else 'given a header'}", file=sys.stderr)
    return 1 if (check and changed) else 0


if __name__ == "__main__":
    sys.exit(main())

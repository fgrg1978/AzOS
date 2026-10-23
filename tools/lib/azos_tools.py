# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""What the host tools share: where the checkout is, and how one tool reaches another.

A tool that needs the checkout root, or another tool's module, starts with

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
    import azos_tools  # noqa: E402

The quoted part is the way from the tool's own directory to tools/lib/;
tools/lint/tools_layout.py rewrites it when a tool moves. Importing this module
puts every directory of tools/ that holds Python modules on sys.path, ahead of
the installed packages, so a tool imports another by its file name wherever the
two live (file names are unique across tools/; the layout lint checks it).

    ROOT    the checkout (absolute, not resolved through symlinks)
    TOOLS   ROOT/tools
"""

import os
import sys

TOOLS = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ROOT = os.path.dirname(TOOLS)

# tools/keys/ holds key files only; __pycache__ is Python's own.
_SKIP = {"keys", "__pycache__"}


def module_dirs():
    """The directories under tools/ that hold a Python module, sorted."""
    dirs = []
    for d, subdirs, names in os.walk(TOOLS):
        subdirs[:] = sorted(s for s in subdirs if s not in _SKIP and not s.startswith("."))
        if any(n.endswith(".py") for n in names):
            dirs.append(d)
    return sorted(dirs)


for _d in reversed(module_dirs()):
    if _d not in sys.path:
        sys.path.insert(0, _d)

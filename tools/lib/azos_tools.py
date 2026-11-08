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


# The brain repo (a sibling checkout, `AzOSRobotBrain`) is an optional client of
# the OS: nothing here builds, runs or gates on it unless it is asked for.
BRAIN_REPO_NAME = "AzOSRobotBrain"


def _git_common_sibling():
    """The sibling of the MAIN checkout, for a worktree that has none of its own."""
    import subprocess
    try:
        common = subprocess.run(
            ["git", "-C", ROOT, "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return os.path.join(os.path.dirname(os.path.dirname(common)), BRAIN_REPO_NAME) if common else None


def brain_state():
    """(state, path): where the brain repo is and whether the run uses it.

    AZOS_BRAIN_DIR (or BRAIN_DIR) is taken verbatim, even when it names nothing,
    so a run can hide the repo. Unset, the sibling of the checkout, then of the
    main checkout. BRAIN=0 turns the brain off, BRAIN=1 requires it.

        "off"       BRAIN=0
        "found"     the repo is there and BRAIN is not 0
        "absent"    not there, BRAIN unset: the brain rows skip
        "required"  not there but BRAIN=1: the run fails
    """
    want = os.environ.get("BRAIN", "")
    explicit = os.environ.get("AZOS_BRAIN_DIR") or os.environ.get("BRAIN_DIR")
    cands = [explicit] if explicit else [os.path.join(os.path.dirname(ROOT), BRAIN_REPO_NAME), _git_common_sibling()]
    path = next((os.path.realpath(c) for c in cands if c and os.path.isdir(c)), None)
    if want == "0":
        return "off", path
    if path:
        return "found", path
    return ("required" if want == "1" else "absent"), (os.path.realpath(explicit) if explicit else None)


def brain_dir():
    """The brain repo's path when the run uses it, else None."""
    state, path = brain_state()
    return path if state == "found" else None


if __name__ == "__main__":
    # `python3 tools/lib/azos_tools.py brain` prints "<state> <path>".
    if sys.argv[1:] == ["brain"]:
        _s, _p = brain_state()
        print(_s, _p or "")
    else:
        sys.exit("usage: azos_tools.py brain")

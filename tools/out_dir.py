#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The one place the output root is computed (`AZOS_OUT`).

Every build output and every image QEMU loads lives under the root, never in
the checkout (the checkout may sit in a synced folder):

    $AZOS_OUT/build/    generated configs, hash tables, ELFs, disk images, kernels
    $AZOS_OUT/target/   the root cargo workspace's target dir
    $AZOS_OUT/tgt/<d>/  the target dir of the standalone crate at <d>

The default is `$HOME/azos-out/<checkout dir name>-<8 hex of its realpath>`: one
root per checkout, so two worktrees never share outputs, whatever they are named
or reached through. `AZOS_OUT` in the environment overrides it.

    python3 tools/out_dir.py            print the root
    from out_dir import out_root        use it from another tool
Makefile and the shell tools call the script; nothing else spells the default.
"""

import hashlib
import os
import sys


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def default_root(root=None):
    root = os.path.realpath(root or repo_root())
    key = "%s-%s" % (os.path.basename(root), hashlib.sha256(root.encode()).hexdigest()[:8])
    return os.path.join(os.path.expanduser("~"), "azos-out", key.replace(" ", "_"))


def out_root(root=None):
    return os.environ.get("AZOS_OUT") or default_root(root)


def target_dir(cwd=None, root=None):
    """The cargo target dir for a cargo run in `cwd`: the root workspace's, or the standalone crate's.

    Same scheme as the Makefile's OUT_TARGET / OUT_TGT: `$AZOS_OUT/target`
    for the repository root, `$AZOS_OUT/tgt/<repo-relative dir>` below it.
    None when `cwd` is outside the checkout.
    """
    root = os.path.realpath(root or repo_root())
    rel = os.path.relpath(os.path.realpath(cwd or os.getcwd()), root)
    if rel == ".":
        return os.path.join(out_root(root), "target")
    if rel.startswith(".."):
        return None
    return os.path.join(out_root(root), "tgt", rel)


if __name__ == "__main__":
    sys.stdout.write(out_root() + "\n")

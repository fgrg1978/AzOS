#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Seed a fresh worktree's cargo target dirs from another worktree (`make worktree-seed`).

A new worktree builds everything from zero: build-std (core, alloc,
compiler_builtins) once per target dir and profile, the crates.io
dependencies, both kernels, and every userspace crate, each of which has a
target dir of its own. This clones the other worktree's target dirs (APFS
`cp -c`: copy-on-write, no data copied) and keeps from them only what cannot
depend on where a worktree lives:

  * kept: the units of packages that are NOT path packages of either tree
    (build-std's sysroot crates, crates.io and git dependencies). Their
    sources sit outside both worktrees (the rustup sysroot, ~/.cargo), so
    cargo's own fingerprint check decides whether they are fresh, as it would
    in the tree that built them;
  * dropped: every unit of a path package (a package with no `source` in any
    Cargo.lock of either tree: the kernel, the crates, userspace, host tests).
    Those are what bakes the old worktree's absolute path into fingerprints,
    build-script binaries (`env!("CARGO_MANIFEST_DIR")`) and build-script
    outputs; reusing them is how a moved worktree once read the Kconfig of the
    old path. Cargo rebuilds them, here, from this tree's sources;
  * dropped: every file outside cargo's per-profile `.fingerprint`, `build`,
    `deps` and `incremental` dirs: uplifted binaries (target/<triple>/release/
    kernel), configs the gate writes under target/, images, logs. Nothing
    built from the other tree's sources survives to be read by mistake.

A target dir this tree already has is left alone. Prints, per target dir, the
units kept and dropped. `--dry-run` copies nothing.
"""

import os
import re
import shutil
import subprocess
import sys
import time

HASHED = re.compile(r"^(?:lib)?(.+?)-([0-9a-f]{16})(?:\..*)?$")
CARGO_SUBDIRS = (".fingerprint", "build", "deps", "incremental")
ROOT_KEEP = ("CACHEDIR.TAG", ".rustc_info.json")


def git(args, cwd):
    p = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


def target_dirs(tree):
    """Cargo target dirs (a CACHEDIR.TAG at their root) among the tree's ignored dirs."""
    out = git(["ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"], tree) or ""
    found = []
    for rel in sorted(p.rstrip("/") for p in out.split("\0") if p.endswith("/")):
        if os.path.isfile(os.path.join(tree, rel, "CACHEDIR.TAG")):
            found.append(rel)
    return found


def path_packages(tree, tdirs):
    """Normalised names of the packages with no `source` in the tree's Cargo.lock files."""
    locks = (git(["ls-files", "*Cargo.lock"], tree) or "").split()
    locks += [os.path.join(os.path.dirname(t), "Cargo.lock") for t in tdirs]
    names = set()
    for rel in set(locks):
        try:
            text = open(os.path.join(tree, rel)).read()
        except OSError:
            continue
        for block in text.split("[[package]]")[1:]:
            m = re.search(r'^name = "([^"]+)"', block, re.M)
            if m and not re.search(r"^source = ", block, re.M):
                names.add(m.group(1).replace("-", "_"))
    return names


def rebase(path, old, new):
    """Rewrite the source tree's absolute target path in a kept text file."""
    try:
        text = open(path, "rb").read()
    except OSError:
        return
    if old.encode() in text:
        open(path, "wb").write(text.replace(old.encode(), new.encode()))


def prune(tdir, path_pkgs, old, new):
    """Drop path-package units and every non-cargo file; return (kept, dropped).

    In what is kept, the old target path (`old`) becomes this tree's (`new`):
    the make-style `.d` files, and the build scripts' `root-output` and
    `output`, which cargo itself rebases from `root-output` when a target dir
    moves; rewritten here so no file of the seeded tree names the other one.
    """
    kept = dropped = 0
    for root, dirs, files in os.walk(tdir, topdown=True):
        if ".fingerprint" in dirs:  # a profile dir: <target>[/<triple>]/<profile>
            fp = os.path.join(root, ".fingerprint")
            gone = set()
            for unit in os.listdir(fp):
                m = HASHED.match(unit)
                if m and m.group(1).replace("-", "_") not in path_pkgs:
                    kept += 1
                    continue
                dropped += 1
                if m:
                    gone.add(m.group(2))
                shutil.rmtree(os.path.join(fp, unit), ignore_errors=True)
            for sub in ("build", "deps", "incremental"):
                d = os.path.join(root, sub)
                if not os.path.isdir(d):
                    continue
                for ent in os.listdir(d):
                    m = HASHED.match(ent)
                    p = os.path.join(d, ent)
                    if m and m.group(1).replace("-", "_") not in path_pkgs and m.group(2) not in gone:
                        if sub == "deps" and ent.endswith(".d"):
                            rebase(p, old, new)
                        elif sub == "build" and os.path.isdir(p):
                            for f in os.listdir(p):
                                if f in ("root-output", "output") or f.endswith(".d"):
                                    rebase(os.path.join(p, f), old, new)
                        continue
                    if os.path.isdir(p) and not os.path.islink(p):
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        os.unlink(p)
            for f in files:  # uplifted artifacts and their .d files
                os.unlink(os.path.join(root, f))
            dirs[:] = [d for d in dirs if d not in CARGO_SUBDIRS]
            continue
        for f in files:
            if root == tdir and f in ROOT_KEEP:
                continue
            os.unlink(os.path.join(root, f))
    return kept, dropped


def main():
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    dry = "--dry-run" in sys.argv[1:]
    here = (git(["rev-parse", "--show-toplevel"], os.getcwd()) or "").strip()
    if len(args) != 1 or not here:
        print("usage: tools/worktree_seed.py [--dry-run] <source-worktree>  (run inside the worktree to seed)")
        return 2
    src = os.path.realpath(os.path.expanduser(args[0]))
    if src == os.path.realpath(here):
        print("worktree_seed: the source is this worktree")
        return 2
    tdirs = target_dirs(src)
    if not tdirs:
        print("worktree_seed: %s has no cargo target dir to seed from" % src)
        return 1
    pkgs = path_packages(src, tdirs) | path_packages(here, tdirs)
    t0 = time.time()
    total_k = total_d = 0
    for rel in tdirs:
        dst = os.path.join(here, rel)
        if os.path.exists(dst):
            print("  %-48s kept as is (this tree has one)" % rel)
            continue
        if not os.path.isdir(os.path.dirname(dst)):
            print("  %-48s skipped (no such crate here)" % rel)
            continue
        if dry:
            print("  %-48s would seed" % rel)
            continue
        tmp = dst + ".seed.%d" % os.getpid()
        if subprocess.call(["cp", "-c", "-R", os.path.join(src, rel), tmp]) != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            print("worktree_seed: `cp -c` failed (not APFS?); nothing seeded for %s" % rel)
            return 1
        try:
            k, d = prune(tmp, pkgs, os.path.join(src, rel), dst)
            os.rename(tmp, dst)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        total_k += k; total_d += d
        print("  %-48s %5d units kept, %5d dropped" % (rel, k, d))
    print("worktree_seed: from %s, %d units kept, %d path-package units dropped, %.1f s"
          % (src, total_k, total_d, time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())

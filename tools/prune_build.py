#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Prune stale cargo artifacts so build directories do not grow without bound.

Usage: python3 tools/prune_build.py [--dry-run] [--quiet] [--keep N] [--days D] [DIR...]

Cargo never deletes an artifact: every feature set, profile and flag change
leaves another `lib<crate>-<hash>.{rlib,rmeta,d}` in `deps/` (one tree held
6,192 of them, 19 GiB). This removes, under every `deps/` directory below the
given target directories (default: this repository's target directories):

  * every artifact of a crate this repository no longer has, when its name
    carries one of the project's crate prefixes (a renamed or deleted crate);
  * for each crate, every build variant that is NOT among the newest `--keep`
    (default 8) AND was last written more than `--days` (default 7) days ago;
  * `incremental/` session directories not written for `--days` days.

The matching `.fingerprint/<crate>-<hash>` directory goes with an artifact, so
cargo sees the unit as missing and rebuilds it instead of trusting a stale
fingerprint. Only old variants are touched, so a cargo build running in the
same directory is never pulling from under its own feet.
"""
import os
import re
import shutil
import subprocess
import sys
import time

PREFIXES = ("azos_", "robot_os_", "kernos_")  # current and former crate prefixes
ART = re.compile(r"^(?:lib)?(?P<name>[A-Za-z0-9_]+)-(?P<hash>[0-9a-f]{16})(?:\..+)?$")


def repo_root():
    return subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()


def workspace_crates(root):
    """Package names of every Cargo.toml in the repository, as `_` identifiers."""
    names = set()
    files = subprocess.check_output(["git", "-C", root, "ls-files", "*Cargo.toml"], text=True).split()
    pat = re.compile(r'^\s*name\s*=\s*"([^"]+)"', re.M)
    for f in files:
        try:
            text = open(os.path.join(root, f), encoding="utf-8").read()
        except OSError:
            continue
        sect = text.split("[package]", 1)
        if len(sect) == 2:
            m = pat.search(sect[1])
            if m:
                names.add(m.group(1).replace("-", "_"))
    return names


def default_dirs(root):
    """Every `target` directory of the repository, symlinks resolved, once each."""
    seen, out = set(), []
    for dp, dn, fn in os.walk(root):
        if ".git" in dn:
            dn.remove(".git")
        for d in list(dn):
            if d == "target":
                real = os.path.realpath(os.path.join(dp, d))
                if real not in seen and os.path.isdir(real):
                    seen.add(real)
                    out.append(real)
                dn.remove(d)  # never descend into a target tree here
    return out


def size(path):
    if os.path.isfile(path) or os.path.islink(path):
        try:
            return os.lstat(path).st_size
        except OSError:
            return 0
    total = 0
    for dp, _, fn in os.walk(path):
        for f in fn:
            try:
                total += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
    return total


def remove(path, dry):
    n = size(path)
    if not dry:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            try:
                os.remove(path)
            except OSError:
                return 0
    return n


def prune_deps(deps, crates, keep, cutoff, dry):
    groups = {}  # (name, hash) -> [paths], newest mtime
    for f in os.listdir(deps):
        m = ART.match(f)
        if not m:
            continue
        p = os.path.join(deps, f)
        try:
            mt = os.lstat(p).st_mtime
        except OSError:
            continue
        g = groups.setdefault((m.group("name"), m.group("hash")), [[], 0.0])
        g[0].append(p)
        g[1] = max(g[1], mt)
    by_name = {}
    for (name, h), (paths, mt) in groups.items():
        by_name.setdefault(name, []).append((mt, h, paths))
    fp_dir = os.path.join(os.path.dirname(deps), ".fingerprint")
    freed = 0
    for name, variants in by_name.items():
        variants.sort(reverse=True)  # newest first
        gone_crate = name.startswith(PREFIXES) and name not in crates
        for i, (mt, h, paths) in enumerate(variants):
            if gone_crate or (i >= keep and mt < cutoff):
                for p in paths:
                    freed += remove(p, dry)
                fp = os.path.join(fp_dir, f"{name.replace('_', '-')}-{h}")
                for cand in (fp, os.path.join(fp_dir, f"{name}-{h}")):
                    if os.path.isdir(cand):
                        freed += remove(cand, dry)
    return freed


def prune_incremental(inc, cutoff, dry):
    freed = 0
    for d in os.listdir(inc):
        p = os.path.join(inc, d)
        try:
            if os.lstat(p).st_mtime < cutoff:
                freed += remove(p, dry)
        except OSError:
            pass
    return freed


def main(argv):
    dry = "--dry-run" in argv
    quiet = "--quiet" in argv
    keep, days, dirs = 8, 7.0, []
    it = iter(argv)
    for a in it:
        if a == "--keep":
            keep = int(next(it))
        elif a == "--days":
            days = float(next(it))
        elif not a.startswith("--"):
            dirs.append(os.path.realpath(a))
    root = repo_root()
    crates = workspace_crates(root)
    dirs = dirs or default_dirs(root)
    cutoff = time.time() - days * 86400
    freed = 0
    for top in dirs:
        for dp, dn, _ in os.walk(top):
            if os.path.basename(dp) == "deps":
                freed += prune_deps(dp, crates, keep, cutoff, dry)
                dn[:] = []
            elif os.path.basename(dp) == "incremental":
                freed += prune_incremental(dp, cutoff, dry)
                dn[:] = []
    if not quiet or freed:
        verb = "would free" if dry else "freed"
        print(f"prune_build: {verb} {freed / 2**30:.1f} GiB in {len(dirs)} target dir(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

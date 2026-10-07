#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Map a git diff to the gate rows and host suites it needs (the N1 tier).

  rows_for_diff.py [--base REV] [--files PATH...] --rows   gate row keys, one per line
  rows_for_diff.py [--base REV] [--files PATH...] --host   host suite dirs (tests/host/*)
  rows_for_diff.py ... --explain                           why each row was picked

The diff is the working tree (tracked changes and untracked files) against
REV (default HEAD), or the paths given with --files. A row is picked when:
  * a changed path matches one of its deps globs in tools/gate_rows.tsv;
  * the change is to tools/ci_check.sh and a changed line is in the row's call
    or in the body of the function it runs;
  * a changed path is CORE (build graph, config, boot, trap, the gate's own
    helpers): then the representative rows of CI_TIER=fast (FAST_ROWS).
Only tier n1 rows are printed; n2 rows a change maps to are named on stderr,
for `make ci`. The per-ISA smoke boots are always printed first. At most
GATE_N1_MAX_ROWS rows (default 16) are printed; the rest are named on stderr.

A host suite is picked when a changed path is in it, or in a crate it reaches
through `path =` dependencies (any Cargo.toml in the repository).
"""

import fnmatch
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_rows  # noqa: E402

ROOT = gate_rows.ROOT
SMOKES = ["boot + SMP scheduling", "aarch64 kernel boots (EL1, -smp 4)"]
CORE = ["Cargo.toml", "Cargo.lock", "kernel/Cargo.toml", "kernel/build.rs", "Kconfig",
        "config/**", "crates/core/limits/**", "crates/core/arch-api/**", "kernel/src/main.rs",
        "kernel/src/boot/**", "kernel/src/trap/**", "kernel/src/smokes/**",
        "kernel/linker*.ld", ".cargo/**", "rust-toolchain.toml", "Makefile",
        "tools/gate_pgroup.sh"]
# The gate's shared helpers: a change there can move any row.
GATE_HELPERS = ["qemu_run", "kq", "kbuild", "a64_kbuild", "a64_kbuild_out", "par",
                "par_ready", "job_disk", "make_disk", "fresh_disk", "ci_marker"]


def git(*args):
    return subprocess.run(["git"] + list(args), cwd=ROOT, capture_output=True,
                          text=True).stdout


def changed(base):
    names = set(git("diff", "--name-only", base).split())
    names |= set(git("ls-files", "-o", "--exclude-standard").split())
    return sorted(names)


def gate_lines(base):
    """New-side line numbers changed in tools/ci_check.sh."""
    out = set()
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", git(
            "diff", "-U0", base, "--", "tools/ci_check.sh"), re.M):
        start, n = int(m.group(1)), int(m.group(2) or "1")
        out.update(range(start, start + max(n, 1)))
    return out


def match(path, globs):
    for g in globs:
        if fnmatch.fnmatch(path, g) or (g.endswith("/**") and path.startswith(g[:-2])):
            return True
    return False


def fast_rows():
    text = open(gate_rows.GATE).read()
    m = re.search(r"^FAST_ROWS='\n(.*?)^'", text, re.S | re.M)
    return [l for l in (m.group(1).splitlines() if m else []) if l.strip()]


def pick_rows(paths, lines, explain):
    man = gate_rows.read_manifest()
    rows = gate_rows.rows()
    fns = gate_rows.functions(open(gate_rows.GATE).read())
    picked, why = [], {}

    def add(key, reason):
        if key not in why:
            picked.append(key)
            why[key] = reason

    for k in SMOKES:
        add(k, "smoke boot")
    core = [p for p in paths if match(p, CORE)]
    helper_hit = any(lines & set(range(fns[f][0], fns[f][1] + 1)) for f in GATE_HELPERS if f in fns)
    if core or helper_hit:
        for k in fast_rows():
            add(k, "core change: %s" % (core[0] if core else "gate helper"))
    for r in rows:
        tier, deps = man.get(r["key"], ("n2", ""))
        hit = [p for p in paths if match(p, deps.split())]
        if hit:
            add(r["key"], "deps: %s" % hit[0])
        a, b = r["range"]
        if lines and (r["line"] in lines or (a and lines & set(range(a, b + 1)))):
            add(r["key"], "gate row edited")
    n1, n2 = [], []
    for k in picked:
        (n1 if man.get(k, ("n1",))[0] == "n1" or k in SMOKES else n2).append(k)
    cap = int(os.environ.get("GATE_N1_MAX_ROWS", "16"))
    kept, dropped = n1[:cap], n1[cap:]
    if n2:
        sys.stderr.write("rows_for_diff: %d n2 row(s) also map to this diff (make ci): %s\n"
                         % (len(n2), " | ".join(n2)))
    if dropped:
        sys.stderr.write("rows_for_diff: %d n1 row(s) over GATE_N1_MAX_ROWS=%d (make ci): %s\n"
                         % (len(dropped), cap, " | ".join(dropped)))
    for k in kept:
        print("%s\t%s" % (k, why[k]) if explain else k)


def cargo_graph():
    """crate dir -> set of crate dirs it depends on through `path =`."""
    graph = {}
    for d, subdirs, files in os.walk(ROOT):
        rel = os.path.relpath(d, ROOT)
        subdirs[:] = [s for s in subdirs if s not in ("target", ".git", "build", "third_party")
                      and not s.startswith(".")]
        if "Cargo.toml" not in files:
            continue
        deps = set()
        for m in re.finditer(r'path\s*=\s*"([^"]+)"', open(os.path.join(d, "Cargo.toml")).read()):
            p = os.path.normpath(os.path.join(rel, m.group(1)))
            if not p.startswith(".."):
                deps.add(p)
        # Host suites pull kernel modules in with `#[path = "..."]` (and
        # `include!`): those files' crates are dependencies too.
        if rel.startswith("tests"):
            for sd, _, fs in os.walk(d):
                if "target" in sd:
                    continue
                for f in fs:
                    if not f.endswith(".rs"):
                        continue
                    try:
                        src = open(os.path.join(sd, f), errors="replace").read()
                    except OSError:
                        continue
                    for m in re.finditer(r'#\[path\s*=\s*"([^"]+)"\]|include(?:_str|_bytes)?!\(\s*"([^"]+)"', src):
                        q = os.path.normpath(os.path.join(os.path.relpath(sd, ROOT), m.group(1) or m.group(2)))
                        if not q.startswith(".."):
                            deps.add(os.path.dirname(q))
        graph[os.path.normpath(rel)] = deps
    return graph


def pick_host(paths):
    graph = cargo_graph()
    rev = {}
    for c, deps in graph.items():
        for dep in deps:
            rev.setdefault(dep, set()).add(c)
    touched = set()
    for p in paths:
        d = os.path.dirname(p)
        while d:
            if d in rev:
                touched.add(d)
            d = os.path.dirname(d)
        best = None
        for c in graph:
            if c != "." and (p == c or p.startswith(c + "/")) and (best is None or len(c) > len(best)):
                best = c
        if best:
            touched.add(best)
    seen, todo = set(touched), list(touched)
    while todo:
        for up in rev.get(todo.pop(), ()):
            if up not in seen:
                seen.add(up)
                todo.append(up)
    for s in sorted(c for c in seen if re.fullmatch(r"tests/host/[^/]+", c)):
        print(s)


def main(argv):
    base = "HEAD"
    files = None
    if "--base" in argv:
        base = argv[argv.index("--base") + 1]
    if "--files" in argv:
        i = argv.index("--files") + 1
        files = []
        while i < len(argv) and not argv[i].startswith("--"):
            files.append(argv[i])
            i += 1
    paths = files if files is not None else changed(base)
    lines = set() if files is not None else gate_lines(base)
    if files is not None and "tools/ci_check.sh" in files:
        lines = set(range(1, 10 ** 6))  # a named gate file: every row is edited
    if "--host" in argv:
        pick_host(paths)
    else:
        pick_rows(paths, lines, "--explain" in argv)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

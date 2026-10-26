#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Map a git diff to the gate rows and host suites it needs (the N1 tier).

  rows_for_diff.py [--base REV] [--files PATH...] --rows   gate row keys, one per line
  rows_for_diff.py [--base REV] [--files PATH...] --host   host suite dirs (tests/host/*)
  rows_for_diff.py ... --explain                           why each row was picked
  rows_for_diff.py --self-test                             canaries for the ranking and the suite graph

The diff is the working tree (tracked changes and untracked files) against
REV (default HEAD), or the paths given with --files. A row is picked when:
  * a changed path matches one of its deps globs in tools/gate/gate_rows.tsv;
  * the change is to tools/gate/ci_check.sh and a changed line is in the row's call
    or in the body of the function it runs;
  * a changed path is CORE (build graph, config, boot, trap, the gate's own
    helpers): then the representative rows of CI_TIER=fast (FAST_ROWS).
Only tier n1 rows are printed; n2 rows a change maps to are named on stderr,
for `make ci`. At most GATE_N1_MAX_ROWS rows (default 16) are printed, in this
order; the rest are named on stderr:
  1. the per-ISA smoke boots;
  2. rows that name a changed file itself (a glob with no wildcard: the
     marker, plant and script deps gate_rows.py writes) or whose gate call or
     function was edited, the row with the fewest deps globs first;
  3. the FAST_ROWS of a CORE change;
  4. the other deps hits, the row whose glob names the path most specifically
     first.
Within a step the gate's order holds. So a change to a smoke file runs the
rows that wait for its output before the CORE rows it also triggers.

A host suite is picked when a changed path is in it, or in a crate it reaches
through its dependencies (gate_rows.crate_graph: `path =` and `workspace = true`
dependencies of any Cargo.toml in the repository, and the files its sources
pull in with `#[path]` or `include!`, with the modules beside them).
"""

import fnmatch
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402,F401
import gate_rows  # noqa: E402

ROOT = gate_rows.ROOT
SMOKES = ["boot + SMP scheduling", "aarch64 kernel boots (EL1, -smp 4)"]
CORE = ["Cargo.toml", "Cargo.lock", "kernel/Cargo.toml", "kernel/build.rs", "Kconfig",
        "config/**", "crates/core/limits/**", "arch/api/**", "kernel/src/main.rs",
        "kernel/src/boot/**", "kernel/src/entry/riscv64/irq.rs", "kernel/src/entry/riscv64/trap.rs", "kernel/src/smokes/**",
        "kernel/src/entry/*/asm.rs", "kernel/src/tasks/create.rs",
        "kernel/linker*.ld", ".cargo/**", "rust-toolchain.toml", "Makefile",
        "tools/gate/gate_pgroup.sh"]
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
    """New-side line numbers changed in tools/gate/ci_check.sh."""
    out = set()
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", git(
            "diff", "-U0", base, "--", "tools/gate/ci_check.sh"), re.M):
        start, n = int(m.group(1)), int(m.group(2) or "1")
        out.update(range(start, start + max(n, 1)))
    return out


def specificity(path, globs):
    """Length of the literal prefix of the longest glob that matches `path`
    (0 when none does): a row that names the changed file outranks one that
    only names its directory tree."""
    return max((len(re.split(r"[*?\[]", g, maxsplit=1)[0]) for g in globs if match(path, [g])), default=0)


def match(path, globs):
    if path.startswith("mk/") and path.endswith(".mk"):
        path = "Makefile"  # the Makefile's included files trigger what the Makefile does
    for g in globs:
        if fnmatch.fnmatch(path, g) or (g.endswith("/**") and path.startswith(g[:-2])):
            return True
    return False


def fast_rows():
    text = open(gate_rows.GATE).read()
    m = re.search(r"^FAST_ROWS='\n(.*?)^'", text, re.S | re.M)
    return [l for l in (m.group(1).splitlines() if m else []) if l.strip()]


# Ranks (see the module docstring): every step outranks the ones after it.
SMOKE_RANK, DIRECT_RANK, CORE_RANK = 3 * 10 ** 6, 2 * 10 ** 6, 10 ** 6


def names_file(path, globs):
    """A glob with no wildcard that matches `path`: the row names the file."""
    return any(not re.search(r"[*?\[]", g) and match(path, [g]) for g in globs)


def rank_rows(paths, lines, man, rs, fns, fast):
    """(n1 keys in print order, n2 keys, key -> reason) for a diff."""
    picked, why, rank = [], {}, {}

    def add(key, reason, score):
        if key not in why:
            picked.append(key)
        if score > rank.get(key, -1):
            rank[key], why[key] = score, reason

    for k in SMOKES:
        add(k, "smoke boot", SMOKE_RANK)
    core = [p for p in paths if match(p, CORE)]
    helper_hit = any(lines & set(range(fns[f][0], fns[f][1] + 1)) for f in GATE_HELPERS if f in fns)
    if core or helper_hit:
        for k in fast:
            add(k, "core change: %s" % (core[0] if core else "gate helper"), CORE_RANK)
    for r in rs:
        tier, deps = man.get(r["key"], ("n2", ""))
        globs = deps.split()
        # Fewer globs, a narrower row: it breaks ties among the direct rows
        # (the 84 ktest rows name every file their hooks gate).
        direct = DIRECT_RANK - len(globs)
        hit = [p for p in paths if match(p, globs)]
        named = [p for p in hit if names_file(p, globs)]
        if named:
            add(r["key"], "names: %s" % named[0], direct)
        elif hit:
            add(r["key"], "deps: %s" % hit[0], max(specificity(p, globs) for p in hit))
        a, b = r["range"]
        if lines and (r["line"] in lines or (a and lines & set(range(a, b + 1)))):
            add(r["key"], "gate row edited", direct)
    n1, n2 = [], []
    for k in picked:
        (n1 if man.get(k, ("n1",))[0] == "n1" or k in SMOKES else n2).append(k)
    n1.sort(key=lambda k: -rank[k])  # stable: gate order within a rank
    return n1, n2, why


def pick_rows(paths, lines, explain):
    man = gate_rows.read_manifest()
    fns = gate_rows.functions(open(gate_rows.GATE).read())
    n1, n2, why = rank_rows(paths, lines, man, gate_rows.rows(), fns, fast_rows())
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


def host_suites(paths, graph=None):
    """The host suites (tests/host/*) a change to `paths` reaches."""
    graph = gate_rows.crate_graph() if graph is None else graph
    rev, pulled = {}, {}
    for c, deps in graph.items():
        for dep in deps:
            if dep.startswith("file:"):
                # A file pulled in with `#[path]` or `include!` counts by its
                # directory: the modules it declares (`mod x;`) sit there.
                # A separate table, so that `kernel/x.ld` does not make its
                # reader a dependent of the kernel crate.
                pulled.setdefault(os.path.dirname(dep[5:]) + "/", set()).add(c)
            else:
                rev.setdefault(dep, set()).add(c)
    touched = set()
    for p in paths:
        for d, users in pulled.items():
            if p.startswith(d):
                touched |= users
        c = gate_rows.owning_crate(p)
        if c:
            touched.add(c)
    seen, todo = set(touched), list(touched)
    while todo:
        for up in rev.get(todo.pop(), ()):
            if up not in seen:
                seen.add(up)
                todo.append(up)
    return sorted(c for c in seen if re.fullmatch(r"tests/host/[^/]+", c))


def self_test():
    bad = []

    def expect(what, ok):
        if not ok:
            bad.append(what)

    # Ranking: a smoke file is CORE, so its FAST_ROWS come with it; the row
    # that names the file must still make the cap, after the smoke boots.
    fast = ["fast %d" % i for i in range(20)]
    rs = [dict(key=k, line=0, range=(0, 0)) for k in SMOKES + fast + ["tree", "wide", "named"]]
    man = {k: ("n1", "kernel/**") for k in fast}
    man.update({k: ("n1", "") for k in SMOKES})
    man["tree"] = ("n1", "kernel/src/smokes/**")
    man["named"] = ("n1", "kernel/src/smokes/x.rs crates/core/x/**")
    man["wide"] = ("n1", "kernel/src/smokes/x.rs " + " ".join("crates/w%d/**" % i for i in range(9)))
    man["fast 3"] = ("n1", "kernel/** kernel/src/smokes/x.rs crates/a/**")  # core and direct
    n1, _, why = rank_rows(["kernel/src/smokes/x.rs"], set(), man, rs, {}, fast)
    expect("smoke boots not first: %r" % n1[:2], n1[:2] == SMOKES)
    expect("canary: the row naming the changed smoke file misses the cap of 16: %r" % n1[:16],
           "named" in n1[:16])
    expect("the narrower direct row does not rank first: %r" % n1[2:5], n1[2:5] == ["named", "fast 3", "wide"])
    expect("a core row ranks above a direct one", n1.index("fast 0") > n1.index("wide"))
    expect("canary: a core row that names the file explains itself as core: %r" % why.get("fast 3"),
           why.get("fast 3") == "names: kernel/src/smokes/x.rs")
    expect("canary: a dir glob counts as naming the file: %r" % n1, n1.index("tree") > n1.index("fast 19"))
    # On the real manifest: every n1 row that names a smoke file makes the
    # cap when there is room for it.
    gman = gate_rows.read_manifest()
    grs = gate_rows.rows()
    fns = gate_rows.functions(open(gate_rows.GATE).read())
    f = "kernel/src/smokes/drivers.rs"
    n1, _, _ = rank_rows([f], set(), gman, grs, fns, fast_rows())
    want = [r["key"] for r in grs if gman.get(r["key"], ("n2",))[0] == "n1"
            and names_file(f, gman[r["key"]][1].split())]
    expect("no n1 row names %s" % f, want)
    expect("canary: a row naming %s is past the cap: %r" % (f, [k for k in want if k not in n1[:16]]),
           all(k in n1[:16] for k in want))

    # Suites: an edge only `workspace = true` gives, and a module beside a
    # file a suite pulls in with `#[path]`.
    graph = gate_rows.crate_graph()
    expect("canary: crates/core/sync -> crates/core/limits (workspace = true) lost",
           "crates/core/limits" in graph.get("crates/core/sync", ()))
    # arch-api-tests reaches crates/core/limits only through `azos_limits =
    # { workspace = true }`, its own and arch/api's.
    lim = "crates/core/limits/src/lib.rs"
    expect("canary: %s does not reach arch-api-tests through a workspace dep" % lim,
           "tests/host/arch-api-tests" in host_suites([lim]))
    toy = {"tests/host/zz-tests": {"file:crates/core/sched/src/scheduler/wake.rs"},
           "tests/host/ld-tests": {"file:kernel/linker-x86_64-limine.ld"},
           "kernel": {"crates/core/limits"}}
    expect("canary: a module beside an included file reaches no suite",
           host_suites(["crates/core/sched/src/scheduler/wake/preempt.rs"], toy) == ["tests/host/zz-tests"])
    expect("canary: the reader of kernel/x.ld depends on the kernel crate",
           host_suites([lim], toy) == [])
    expect("canary: a path outside every crate reaches a suite",
           host_suites(["Documentation/building.md"], toy) == [])
    for b in bad:
        print("rows_for_diff self-test: FAIL " + b)
    if not bad:
        print("rows_for_diff self-test: ok (ranking, %d rows naming %s, suite graph)" % (len(want), f))
    return 1 if bad else 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
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
    if files is not None and "tools/gate/ci_check.sh" in files:
        lines = set(range(1, 10 ** 6))  # a named gate file: every row is edited
    if "--host" in argv:
        for s in host_suites(paths):
            print(s)
    else:
        pick_rows(paths, lines, "--explain" in argv)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

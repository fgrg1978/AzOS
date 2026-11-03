#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Resolve what a `git merge` leaves conflicted in the files that tools write.

Run it in a merge that stopped on conflicts; it settles the files below and
leaves every other conflict alone (exit 1 if any remains). It never commits.

  Documentation/config.md, Documentation/os-feature-matrix.md
        functions of the tree: regenerated (tools/build/gen_config_index.py,
        tools/build/gen_feature_matrix.py)
  tools/gate/gate_rows.tsv
        merged row by row (a row added, dropped or re-tiered on either side
        stays so; deps, which are globs, are the union), then normalised with
        tools/gate/gate_rows.py --write
  tools/lint/unsafe_budget.tsv, tools/lint/size_budget.tsv
        ratchet baselines, not functions of the tree: merged per row as
        ours + theirs - base on every number, then checked against the
        tree (unsafe_budget.py) or left for `make size-update REASON=..` to
        re-measure (size_budget.py): the numbers are a sum, not a measurement.
        A `reason` row keeps both sides' reasons.

  merge_generated.py [--selftest]
"""
import os
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
DOCS = {"Documentation/config.md": "tools/build/gen_config_index.py",
        "Documentation/os-feature-matrix.md": "tools/build/gen_feature_matrix.py"}
ROWS = "tools/gate/gate_rows.tsv"
BUDGETS = ("tools/lint/unsafe_budget.tsv", "tools/lint/size_budget.tsv")


def rows_of(text):
    """(comment lines, {key: fields}) of a tab-separated table; key = the first column,
    or the first two for the size budget (label, group)."""
    head, out = [], {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            head.append(line)
            continue
        f = line.split("\t")
        out[f[0] if len(f) < 3 or not f[1].startswith(".") and f[1] != "reason" else (f[0], f[1])] = f
    return head, out


def num(x):
    try:
        return int(x)
    except ValueError:
        return None


def merge3(base, ours, theirs, combine):
    """{key: fields} of a per-row three-way merge; a row dropped by a side that did not change it is dropped."""
    out = {}
    for k in list(ours) + [k for k in theirs if k not in ours]:
        o, t, b = ours.get(k), theirs.get(k), base.get(k)
        if o is None or t is None:
            gone = o is None
            kept = t if gone else o
            if b is not None and kept == b:
                continue
            out[k] = kept
        elif o == t or t == b:
            out[k] = o
        elif o == b:
            out[k] = t
        else:
            out[k] = combine(b, o, t)
    return out


def combine_rows(b, o, t):
    tier = o[1]
    deps = o[2].split()
    deps += [d for d in t[2].split() if d not in deps]
    return [o[0], tier, " ".join(deps)]


def combine_numbers(b, o, t):
    if o[1:2] == ["reason"] or (len(o) > 2 and o[1] == "reason"):
        return o if o == t else o[:-1] + [o[-1] + "; " + t[-1]]
    out = list(o)
    for i in range(1, len(o)):
        a, c = num(o[i]), num(t[i])
        d = num(b[i]) if b else 0
        if a is not None and c is not None and d is not None:
            out[i] = str(a + c - d)
    return out


def stage(path, n):
    r = subprocess.run(["git", "show", ":%d:%s" % (n, path)], cwd=ROOT, capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def render(head, rows):
    return "\n".join(head + ["\t".join(f) for f in rows.values()]) + "\n"


def resolve(path, combine):
    bh, base = rows_of(stage(path, 1))
    oh, ours = rows_of(stage(path, 2))
    _, theirs = rows_of(stage(path, 3))
    merged = merge3(base, ours, theirs, combine)
    keyed = sorted(merged.values(), key=lambda f: f[0]) if path == ROWS else list(merged.values())
    with open(os.path.join(ROOT, path), "w", encoding="utf-8") as fh:
        fh.write("\n".join(oh + ["\t".join(f) for f in keyed]) + "\n")


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT).returncode


def main():
    un = subprocess.run(["git", "diff", "--name-only", "--diff-filter=U"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    left = []
    for p in un:
        if p in DOCS:
            run(["git", "checkout", "--ours", p])
            ok = run([sys.executable, DOCS[p]]) == 0
        elif p == ROWS:
            resolve(p, combine_rows)
            ok = run([sys.executable, "tools/gate/gate_rows.py", "--write"]) == 0
        elif p in BUDGETS:
            resolve(p, combine_numbers)
            ok = True
        else:
            left.append(p)
            continue
        if ok:
            run(["git", "add", p])
        else:
            left.append(p)
    for p in BUDGETS:
        if p in un:
            print("%s: sums of both sides; %s" % (p, "run tools/lint/unsafe_budget.py to check it against the tree" if "unsafe" in p
                                                  else "re-measure with `make size-update REASON=..`"))
    if left:
        print("still conflicted: " + " ".join(left))
    return 1 if left else 0


def selftest():
    base = {"a": ["a", "1", "2"], "b": ["b", "5", "5"]}
    ours = {"a": ["a", "3", "2"], "b": ["b", "5", "5"], "n": ["n", "1", "1"]}
    theirs = {"a": ["a", "1", "4"], "m": ["m", "2", "2"]}
    got = merge3(base, ours, theirs, combine_numbers)
    assert got["a"] == ["a", "3", "4"], got
    assert "b" not in got and got["n"] == ["n", "1", "1"] and got["m"] == ["m", "2", "2"], got
    r = combine_rows(None, ["k", "n1", "x/** y"], ["k", "n2", "y z/**"])
    assert r == ["k", "n1", "x/** y z/**"], r
    print("merge_generated: self-test ok")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if sys.argv[1:] == ["--selftest"] else main())

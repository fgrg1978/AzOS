#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""feature_source_lint.py — no build names a kernel cargo feature by hand.

Kconfig is the only source of the kernel's features: a recipe or a script
builds the kernel with what `tools/build/kconfig_to_cargo.py` prints for its
configuration, and whatever it builds beyond that (a gate row's smoke, a
canary, a driver) is a build selection, `--select TOKENS`, which
kconfig_to_cargo.py applies to a copy of the configuration (`select`: Kconfig
lines, features a Kconfig symbol owns, test hooks). This lint fails on a
kernel `cargo build|check` in the Makefile, mk/*.mk, or a shell or Python
script under tools/ or tests/ that carries `--features` (or `-F`) of its own.

A kernel build is a `cargo build|check` of the workspace root (no `cd` into
another crate, no `--manifest-path`, no `-p` but `azos_kernel`), or a call of
the gate's `build`/`kbuild`-style helpers that forward to one. Comment lines
and the text of `echo`/`printf` are not commands.

  feature_source_lint.py             check; exit 1 and list every hand-written list
  feature_source_lint.py --fix       rewrite tools/gate/ci_check.sh in place: its cargo is
                                     tools/gate/ci_cargo.py, which takes `--select`, so
                                     each kernel `--features LIST` becomes
                                     `--select LIST` with the `qemu` board token
                                     dropped (the gate's cells are QEMU
                                     configurations; the board is theirs). The
                                     other files call cargo itself and are edited
                                     by hand. Re-run it on a newer tree: it is
                                     the replayable half of the F5 change.
  feature_source_lint.py --self-test the canaries
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# The files the rule covers, relative to the root: the Makefile, mk/*.mk, and
# every shell and Python script under tools/ and tests/.
def scanned(root=ROOT):
    out = ["Makefile"]
    out += sorted(os.path.join("mk", f) for f in os.listdir(os.path.join(root, "mk")) if f.endswith(".mk"))
    for top in ("tools", "tests"):
        for d, dirs, files in os.walk(os.path.join(root, top)):
            dirs[:] = sorted(x for x in dirs if x not in ("target", "__pycache__") and " " not in x)
            out += sorted(os.path.relpath(os.path.join(d, f), root) for f in files
                          if f.endswith((".sh", ".py")) and " " not in f)
    me = os.path.relpath(os.path.abspath(__file__), root)
    return [f for f in out if f != me]


# The one file `--fix` rewrites: the gate, whose `$CARGO` is tools/gate/ci_cargo.py.
FIX_FILE = os.path.join("tools", "ci_check.sh")

CARGO_RE = re.compile(r'(?:\bcargo|\$\(CARGO\)|"?\$\{?(?:CARGO|cargo)\}?"?)'
                      r'(?:\s+\+\S+)?\s+(build|check|rustc)\b')
# The gate's helpers whose arguments end in a kernel `cargo build`.
HELPER_RE = re.compile(r'^\s*(build|build_board)\s+"')
NOT_KERNEL_RE = re.compile(r'(\bcd\s+(?!"?\$\(?REPO_ROOT\)?"?\s*&&)(?!"?\$REPO"?\s*&&)\S|--manifest-path|'
                           r'\bsdk_cargo\.py|(?:-p|--package)[ =](?!azos_kernel\b)[\w$"{(]|'
                           r'\btests/host/|\bhost_cargo\b|--no-default-features)')
FEATURES_RE = re.compile(r'(?<![\w-])(--features|-F)(?=[ =])')
PY_LIST_RE = re.compile(r'\[\s*"cargo"\s*,\s*"(?:build|check)"[^\]]*"--features"')
MESSAGE_RE = re.compile(r'^\s*(?:echo|printf|die|log|warn)\b')
# A physical line whose `--features` is inside a message (`|| die "..."`).
IN_MESSAGE_RE = re.compile(r'(?:\b(?:die|echo|printf)\s+["\']).*--features')


def logical_lines(text):
    """[(first line number, [physical lines])]: shell continuations joined."""
    out, cur, start = [], [], 0
    for no, line in enumerate(text.split("\n"), 1):
        if not cur:
            start = no
        cur.append(line)
        if not line.rstrip().endswith("\\"):
            out.append((start, cur))
            cur = []
    if cur:
        out.append((start, cur))
    return out


def is_comment(line):
    return line.lstrip().startswith("#")


def kernel_build(joined):
    """A logical line that builds or checks the kernel."""
    if MESSAGE_RE.match(joined):
        return False
    if not (CARGO_RE.search(joined) or HELPER_RE.match(joined)):
        return False
    return not NOT_KERNEL_RE.search(joined)


def findings(path, text):
    """[(line, text)] of every kernel build that names --features."""
    bad = []
    if path.endswith(".py"):
        for no, line in enumerate(text.split("\n"), 1):
            if not is_comment(line) and PY_LIST_RE.search(line):
                bad.append((no, line.strip()))
        return bad
    for start, phys in logical_lines(text):
        if is_comment(phys[0]):
            continue
        code = [l for l in phys if not is_comment(l)]
        joined = " ".join(l.rstrip("\\") for l in code)
        if kernel_build(joined) and FEATURES_RE.search(joined):
            for i, l in enumerate(phys):
                if FEATURES_RE.search(l) and not is_comment(l) and not IN_MESSAGE_RE.search(l):
                    bad.append((start + i, l.strip()))
    return bad


# `--features LIST` -> `--select LIST` minus the `qemu` token; LIST is a word,
# a quoted word, or a quoted word with expansions.
_SEL_RE = re.compile(r'(\s*)(?<![\w-])--features([ =])("[^"]*"|[^\s"]+)(\s*)')


def _drop_qemu(arg):
    q = arg.startswith('"') and arg.endswith('"') and len(arg) >= 2
    body = arg[1:-1] if q else arg
    toks = body.split(",")
    kept = [t for t in toks if t != "qemu"]
    if kept == toks:
        return arg
    body = ",".join(kept)
    if not body:
        return None
    return f'"{body}"' if q else body


def fix_text(text):
    """The gate's text with every kernel `--features` turned into `--select`."""
    lines = text.split("\n")
    for start, phys in logical_lines(text):
        if is_comment(phys[0]):
            continue
        code = [l for l in phys if not is_comment(l)]
        joined = " ".join(l.rstrip("\\") for l in code)
        if not (kernel_build(joined) and FEATURES_RE.search(joined)):
            continue
        for i, l in enumerate(phys):
            if is_comment(l) or IN_MESSAGE_RE.search(l):
                continue

            def sub(m, l=l):
                arg = _drop_qemu(m.group(3))
                if arg is not None:
                    return f"{m.group(1)}--select{m.group(2)}{arg}{m.group(4)}"
                # A list of nothing but the board: the flag goes, and one run
                # of blanks with it (the indent, when it opens the line).
                return m.group(1) if not l[:m.start()].strip() else m.group(4)
            lines[start - 1 + i] = _SEL_RE.sub(sub, l)
    return "\n".join(lines)


def check(root=ROOT):
    bad = []
    for rel in scanned(root):
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            text = fh.read()
        bad += [(rel, no, l) for no, l in findings(rel, text)]
    return bad


def self_test():
    sh = (
        '# cargo build --release --features qemu   (a comment)\n'
        'echo "cargo build --release --features qemu"\n'
        '    "$CARGO" build --release --features qemu,net-smoke >/dev/null\n'
        '    out="$(env -u RUSTFLAGS "$CARGO" build --release --target t \\\n'
        '        -p azos_kernel --features "$feats" \\\n'
        '        --config x 2>&1)"\n'
        'build       "qemu"                --release --features qemu\n'
        '    (cd tests/host/x && "$CARGO" test --release --features a-canary)\n'
        '    (cd "${REPO_ROOT}/tests/host/energy-tests" && "$CARGO" build --features v)\n'
        '    "$CARGO" tree -e features -p azos_kernel --features "$f" -i azos_topology\n'
        '    "$CARGO" build --release --select "qemu,$feat"\n'
        '    out="$("$CARGO" build --release -p azos_kernel \\\n'
        '            --features qemu --config x\n'
    )
    got = [no for no, _ in findings("x.sh", sh)]
    want = [3, 5, 7, 13]
    if got != want:
        print(f"feature_source_lint self-test FAILED: findings on lines {got}, want {want}")
        return 1
    fixed = fix_text(sh).split("\n")
    expect = {
        3: '    "$CARGO" build --release --select net-smoke >/dev/null',
        5: '        -p azos_kernel --select "$feats" \\',
        7: 'build       "qemu"                --release',
        13: '            --config x',
        1: '# cargo build --release --features qemu   (a comment)',
        8: '    (cd tests/host/x && "$CARGO" test --release --features a-canary)',
    }
    for no, line in expect.items():
        if fixed[no - 1] != line:
            print(f"feature_source_lint self-test FAILED: --fix line {no}: {fixed[no - 1]!r}, want {line!r}")
            return 1
    if findings("x.sh", "\n".join(fixed)):
        print("feature_source_lint self-test FAILED: --fix leaves findings")
        return 1
    py = '        cmd = ["cargo", "build", "--release", "--features", "qemu"] + base\n'
    if [no for no, _ in findings("x.py", py)] != [1]:
        print("feature_source_lint self-test FAILED: a python cargo list with --features is not found")
        return 1
    print("feature_source_lint self-test ok")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if "--fix" in argv:
        p = os.path.join(ROOT, FIX_FILE)
        text = open(p, encoding="utf-8").read()
        new = fix_text(text)
        if new != text:
            open(p, "w", encoding="utf-8").write(new)
        n = sum(1 for a, b in zip(text.split("\n"), new.split("\n")) if a != b)
        print(f"feature_source_lint --fix: {n} lines of {FIX_FILE} rewritten")
    bad = check()
    for rel, no, l in bad:
        print(f"{rel}:{no}: a kernel build names --features by hand (Kconfig is the only "
              f"source: kconfig_to_cargo.py, or --select): {l}")
    if bad:
        return 1
    print("feature_source_lint: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

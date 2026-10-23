#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Nothing writes into the checkout: every output goes under $AZOS_OUT.

Build outputs and the images QEMU loads live under the output root
(tools/out_dir.py), never in the repository, which may sit in a synced folder.
This lint fails when the Makefile, a tool, a build script or a Rust
`include!` names a repository-relative `build/` or `target/`:

  * a path that starts at `build/` or `target/`, or at `$REPO_ROOT/build`,
    `$(CURDIR)/target`, `./build`, `../../build` and the like;
  * `mkdir/rm/cd/ls build` and `target` as a bare directory;
  * `--target-dir <relative path>`;
  * a Makefile recipe that runs cargo after a `cd` without naming its target dir;
  * Python `os.path.join(<anything but the output root>, "build"|"target", ...)`.

Comments and docstrings are not looked at. A line that is meant to name such a
path anyway (a canary, a test fixture) says `out-dir-lint: ok` in a comment.

    python3 tools/out_dir_lint.py              lint the tree (exit 1 on a finding)
    python3 tools/out_dir_lint.py --self-test  the canary: a synthetic violation of
                                               every rule must turn the lint red
    python3 tools/out_dir_lint.py FILE...      lint these files only
"""

import ast
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import azos_tools  # noqa: E402

ROOT = os.path.realpath(azos_tools.ROOT)
PRAGMA = "out-dir-lint: ok"
SKIP_PREFIXES = ("third_party/", "rfcs/", "docs/")
SKIP_FILES = {"tools/out_dir_lint.py"}

# The repository-rooted spellings of a relative build/target directory.
REPO_VAR = r"(?:\$\{?(?:REPO_ROOT|REPO|ROOT|OS_DIR|REPO_KERNEL|PWD)\}?|\$\((?:CURDIR|ROOT)\)|(?<![\w.])\.)"
RULES = [
    ("bare relative path", re.compile(r"(?<![\w.$/{}\)\-])(?:build|target)/(?=[\w$({.\"'*\[])")),
    ("repo-rooted path", re.compile(REPO_VAR + r"/(?:build|target)\b")),
    ("bare build/target directory", re.compile(
        r"\b(?:mkdir|rm|cd|ls|touch|cat)\b(?:\s+-\S+)*\s+[\"']?(?:build|target)[\"']?(?:/|\s|;|\)|$)")),
    ("relative --target-dir", re.compile(r"--target-dir[= ]+[\"']?[A-Za-z.]")),
    ("path climbing into build/target", re.compile(r"\.\./(?:\.\./)*(?:build|target)/")),
]
CARGO_CALL = re.compile(r"\$\(CARGO\)|\$\(USPACE_BUILD\)|\$\(MLSRV_(?:QEMU|BOARD)_BUILD\)|\bcargo\b")


def strip_comment(line, marker):
    """The line without a trailing `# ...` / `// ...` comment (outside quotes)."""
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif line.startswith(marker, i) and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
        i += 1
    return line


def scan_text(path, text, marker):
    """Findings in a Makefile, shell script, TOML or Rust file."""
    found = []
    lines = text.split("\n")
    for n, raw in enumerate(lines, 1):
        if PRAGMA in raw:
            continue
        code = strip_comment(raw, marker)
        if not code.strip():
            continue
        for what, rx in RULES:
            m = rx.search(code)
            if m:
                found.append((path, n, what, raw.strip()))
                break
    return found


def scan_makefile(path, text):
    found = scan_text(path, text, "#")
    # A recipe that enters another directory and runs cargo must say where its
    # outputs go; the logical line is the recipe line with its continuations.
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        start = i
        logical = lines[i]
        while logical.endswith("\\") and i + 1 < len(lines):
            i += 1
            logical = logical[:-1] + " " + lines[i].strip()
        i += 1
        if not logical.startswith("\t") or PRAGMA in logical:
            continue
        code = strip_comment(logical, "#")
        if re.search(r"\bcd\s+\S+\s*&&", code) and CARGO_CALL.search(code) \
                and "CARGO_TARGET_DIR" not in code and "--target-dir" not in code:
            found.append((path, start + 1, "cargo after cd without a target dir", logical.strip()[:160]))
    return found


def docstring_lines(tree):
    skip = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                v = body[0].value
                skip.update(range(v.lineno, (v.end_lineno or v.lineno) + 1))
    return skip


def scan_python(path, text):
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return [(path, e.lineno or 0, "does not parse", str(e))]
    src = text.split("\n")
    skip = docstring_lines(tree)
    found = []

    def pragma(lineno):
        return 0 < lineno <= len(src) and PRAGMA in src[lineno - 1]

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.lineno not in skip:
            if pragma(node.lineno):
                continue
            for line in node.value.split("\n"):
                for what, rx in RULES:
                    if rx.search(line):
                        found.append((path, node.lineno, what, line.strip()[:160]))
                        break
        elif isinstance(node, ast.Call):
            fn = ast.unparse(node.func)
            if fn in ("os.path.join", "path.join", "pathlib.Path", "Path", "posixpath.join") and len(node.args) >= 2:
                names = [a.value for a in node.args[1:] if isinstance(a, ast.Constant) and a.value in ("build", "target")]
                head = ast.unparse(node.args[0])
                if names and not re.search(r"OUT|out_root|\btd\b|tmp|tempfile", head) and not pragma(node.lineno):
                    found.append((path, node.lineno, "join(<not the output root>, build|target)", ast.unparse(node)[:160]))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) \
                and isinstance(node.right, ast.Constant) and node.right.value in ("build", "target"):
            head = ast.unparse(node.left)
            if not re.search(r"OUT|out_root|\btd\b|tmp", head) and not pragma(node.lineno):
                found.append((path, node.lineno, "<not the output root> / build|target", ast.unparse(node)[:160]))
    return found


def scan_file(rel, text):
    base = os.path.basename(rel)
    if base == "Makefile" or rel.endswith(".mk"):
        return scan_makefile(rel, text)
    if rel.endswith(".py"):
        return scan_python(rel, text)
    if rel.endswith(".sh"):
        return scan_text(rel, text, "#")
    if rel.endswith(".rs"):
        return scan_text(rel, text, "//")
    if rel.endswith(".toml") and ("/.cargo/" in "/" + rel or base == "config.toml"):
        return scan_text(rel, text, "#")
    return []


def candidates():
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    for rel in sorted(p for p in out.split("\0") if p):
        if rel in SKIP_FILES or rel.startswith(SKIP_PREFIXES):
            continue
        base = os.path.basename(rel)
        if base == "Makefile" or rel.endswith((".mk", ".py", ".sh", ".rs")) \
                or (rel.endswith(".toml") and "/.cargo/" in "/" + rel):
            yield rel


def lint(files, root=ROOT):
    found = []
    for rel in files:
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            continue
        found += scan_file(rel, text)
    return found


# One synthetic violation per rule (and per file kind). Each must be reported;
# each line of the allowed set must not.
VIOLATIONS = {
    "Makefile": [
        "x:\n\t@mkdir -p $(CURDIR)/build\n",
        "x:\n\tcp a build/disk.img\n",
        "x:\n\tcd foo && $(CARGO) build --release\n",
        "x:\n\t$(CARGO) build --target-dir target/x\n",
        "x:\n\t@mkdir -p build\n",
    ],
    "t.sh": [
        'KERNEL="target/riscv64imac-unknown-none-elf/release/kernel"\n',
        'DISK="$REPO_ROOT/build/disk.img"\n',
        'cd build && make\n',
        'cargo build --target-dir target/foo\n',
    ],
    "t.py": [
        'p = "build/disk.img"\n',
        'import os\nREPO = "."\np = os.path.join(REPO, "target", "x")\n',
        'from pathlib import Path\nq = Path(__file__).parent / "build"\n',
    ],
    "t.rs": [
        'static A: &[u8] = include_bytes!("../../../build/x.elf");\n',
        'const P: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../build/y");\n',
    ],
    "sub/.cargo/config.toml": [
        'KCONFIG_CONFIG = { value = "../../../build/micro.config", relative = true }\n',
    ],
}
ALLOWED = {
    "Makefile": [
        "x:\n\t@mkdir -p $(OUT_BUILD)\n\tcp a $(OUT_BUILD)/disk.img\n",
        "x:\n\tcd foo && CARGO_TARGET_DIR=\"$(OUT_TGT)/foo\" $(CARGO) build\n",
        "x:\n\t@echo build\n# mkdir -p build is only a comment\n",
        "x:\n\tcd foo && $(CARGO) build --target-dir $(OUT_TARGET)/foo\n",
    ],
    "t.sh": [
        'DISK="$AZOS_OUT/build/disk.img"\nKERNEL="${AZOS_OUT}/target/x/kernel"\n',
        '# cd build is a comment\nwork="$HOME/azos-tools/build/relibc"\n',
    ],
    "t.py": [
        'import os\nOUT = "/x"\np = os.path.join(OUT, "build", "disk.img")\n',
        '"""Docstring naming build/disk.img."""\nx = 1\n',
        'p = "build/fixture.elf"  # out-dir-lint: ok\n',
    ],
    "t.rs": [
        'static A: &[u8] = include_bytes!(concat!(env!("AZOS_OUT"), "/build/x.elf"));\n// include_bytes!("../../build/x")\n',
    ],
}


def self_test():
    failures = []
    with tempfile.TemporaryDirectory() as td:
        for kind, cases in VIOLATIONS.items():
            for i, text in enumerate(cases):
                rel = "v%d_%s" % (i, kind.replace("/", "_")) if kind != "Makefile" else "v%d/Makefile" % i
                if kind.endswith("config.toml"):
                    rel = "v%d/.cargo/config.toml" % i
                full = os.path.join(td, rel)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w") as f:
                    f.write(text)
                if not lint([rel], td):
                    failures.append("did not catch %s: %r" % (kind, text))
        for kind, cases in ALLOWED.items():
            for i, text in enumerate(cases):
                rel = "a%d_%s" % (i, kind) if kind != "Makefile" else "a%d/Makefile" % i
                full = os.path.join(td, rel)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w") as f:
                    f.write(text)
                got = lint([rel], td)
                if got:
                    failures.append("flagged an allowed %s %r: %s" % (kind, text, got))
    return failures


def main(argv):
    if "--self-test" in argv:
        failures = self_test()
        for f in failures:
            print("out_dir_lint --self-test:", f)
        if failures:
            print("out_dir_lint --self-test: FAIL")
            return 1
        print("out_dir_lint --self-test: every rule bites, nothing allowed is flagged")
        return 0
    files = [a for a in argv if not a.startswith("-")] or list(candidates())
    found = lint(files)
    for path, n, what, line in found:
        print("out_dir_lint: %s:%d: %s: %s" % (path, n, what, line))
    if found:
        print("out_dir_lint: %d finding(s). Outputs live under $AZOS_OUT (tools/out_dir.py), "
              "never in the checkout." % len(found))
        return 1
    print("out_dir_lint: ok (%d files)" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

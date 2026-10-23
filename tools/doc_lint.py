#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The public documentation names only paths that exist.

Checks, over `Documentation/**/*.md`, `ARCHITECTURE.md` and `README.md`:

  * every repo-relative path in an inline code span exists. A span counts as a
    path when it has a `/` and its first component is a top-level entry of the
    repository (`crates/core/abi/src/lib.rs`, `mk/host.mk`); a `:line` or
    `::item` suffix and a trailing `/` are dropped first. A span with a glob,
    a placeholder (`<x>`, `{x}`), an environment variable (`$X`) or a URL is not
    a path and is skipped, and so is everything inside a fenced code block;
  * every relative link target (`[text](target)`) exists, resolved from the
    file that holds the link; URLs and `#anchor`-only links are skipped;
  * no path names `rfcs/` or `docs/`, which are not part of the public tree;
  * `Documentation/README.md` exists and links every other file in
    `Documentation/` (a link target or a code span that names it).

"Exists" is judged on the tracked files and the untracked files git does not
ignore (a clean clone sees the same set); outside a git checkout, on the files
on disk.

    python3 tools/doc_lint.py              lint the tree (exit 1 on a finding)
    python3 tools/doc_lint.py --self-test  the canary: a synthetic violation of
                                           every rule must turn the lint red,
                                           and a clean tree must stay green
"""

import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import azos_tools  # noqa: E402

ROOT = os.path.realpath(azos_tools.ROOT)

DOC_DIR = "Documentation"
INDEX = "Documentation/README.md"
TOP_LEVEL_DOCS = ("ARCHITECTURE.md", "README.md")
PRIVATE_PREFIXES = ("rfcs/", "docs/")

CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")
LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REF_DEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
NOT_A_PATH = re.compile(r"[*?<>{}$|=\\]|\.\.\.|\u2026|://|@")
SUFFIX = re.compile(r"(::[A-Za-z_].*|:\d+(-\d+)?)$")


def list_tree(root):
    """Files that exist for the documentation: tracked + untracked-unignored,
    or the files on disk when `root` is not a git checkout."""
    files = None
    if os.path.exists(os.path.join(root, ".git")):
        try:
            out = subprocess.run(
                ["git", "-C", root, "ls-files", "--cached", "--others",
                 "--exclude-standard", "-z"],
                check=True, capture_output=True).stdout.decode("utf-8", "replace")
            files = [p for p in out.split("\0") if p and os.path.lexists(os.path.join(root, p))]
        except (OSError, subprocess.CalledProcessError):
            files = None
    if files is None:
        files = []
        for d, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if x != ".git"]
            for n in names:
                files.append(os.path.relpath(os.path.join(d, n), root))
    return set(files)


class Tree:
    def __init__(self, root):
        self.root = root
        self.files = list_tree(root)
        self.dirs = set()
        for f in self.files:
            parts = f.split("/")
            for i in range(1, len(parts)):
                self.dirs.add("/".join(parts[:i]))
        self.top = {f.split("/")[0] for f in self.files}

    def exists(self, rel):
        rel = os.path.normpath(rel).replace(os.sep, "/")
        return rel in self.files or rel in self.dirs


def doc_files(tree):
    out = [f for f in sorted(tree.files) if f.startswith(DOC_DIR + "/") and f.endswith(".md")]
    out += [f for f in TOP_LEVEL_DOCS if f in tree.files]
    return out


def scan(text):
    """Yield (lineno, kind, token) for code spans ('span') and link targets
    ('link') outside fenced code blocks."""
    fence = None
    for no, line in enumerate(text.splitlines(), 1):
        m = FENCE.match(line)
        if m:
            mark = m.group(1)
            if fence is None:
                fence = mark[0] * 3
            elif mark[0] * 3 == fence and line.strip().strip(mark[0]) == "":
                fence = None
            continue
        if fence is not None:
            continue
        # A code span may hold a `[x](y)`; links are looked for outside spans.
        bare = CODE_SPAN.sub(lambda s: " " * len(s.group(0)), line)
        for s in CODE_SPAN.finditer(line):
            yield no, "span", s.group(2).strip()
        for l in LINK.finditer(bare):
            yield no, "link", l.group(1)
        r = REF_DEF.match(bare)
        if r:
            yield no, "link", r.group(1)


def span_paths(token, tree):
    """The repo-relative path candidates of one code span."""
    for word in token.split():
        w = word.strip("\"'(),;:.[]")
        if w.startswith("./"):
            w = w[2:]
        if not w or w.startswith(("-", "~", "/", "#")) or NOT_A_PATH.search(w):
            continue
        w = SUFFIX.sub("", w).rstrip("/")
        if "/" not in w:
            continue
        yield w


def check_file(rel, tree, findings):
    with open(os.path.join(tree.root, rel), encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    here = os.path.dirname(rel)
    for no, kind, token in scan(text):
        if kind == "span":
            for p in span_paths(token, tree):
                if p.startswith(PRIVATE_PREFIXES):
                    findings.append("%s:%d: `%s` names a private path (not in the public tree)" % (rel, no, p))
                elif p.split("/")[0] in tree.top and not tree.exists(p):
                    findings.append("%s:%d: `%s` does not exist" % (rel, no, p))
        else:
            t = token.split("#", 1)[0].split("?", 1)[0]
            if not t or SCHEME.match(t) or NOT_A_PATH.search(t):
                continue
            if t.startswith("/"):
                target = t.lstrip("/")
            else:
                target = os.path.join(here, t)
            norm = os.path.normpath(target).replace(os.sep, "/")
            if norm.startswith(".."):
                findings.append("%s:%d: link (%s) leaves the repository" % (rel, no, token))
            elif norm.startswith(PRIVATE_PREFIXES):
                findings.append("%s:%d: link (%s) names a private path (not in the public tree)" % (rel, no, token))
            elif not tree.exists(norm):
                findings.append("%s:%d: link (%s) does not exist" % (rel, no, token))


def check_index(tree, findings):
    docs = sorted(f for f in tree.files if f.startswith(DOC_DIR + "/"))
    if not docs:
        return
    if INDEX not in tree.files:
        findings.append("%s: missing; it must list every file in %s/" % (INDEX, DOC_DIR))
        return
    with open(os.path.join(tree.root, INDEX), encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    named = set()
    for _, kind, token in scan(text):
        cands = [token.split("#", 1)[0]] if kind == "link" else list(span_paths(token, tree)) + [token]
        for c in cands:
            if c and not SCHEME.match(c):
                named.add(os.path.normpath(os.path.join(DOC_DIR, c)).replace(os.sep, "/"))
    for f in docs:
        if f != INDEX and f not in named:
            findings.append("%s: does not list %s" % (INDEX, f))


def lint(root):
    tree = Tree(root)
    findings = []
    for rel in doc_files(tree):
        check_file(rel, tree, findings)
    check_index(tree, findings)
    return findings


# ── the canary ───────────────────────────────────────────────────────────────

def _write(root, rel, text=""):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _clean_tree(root):
    _write(root, "crates/core/abi/src/lib.rs", "//! abi\n")
    _write(root, "mk/host.mk", "doc:\n")
    _write(root, "Documentation/README.md",
           "# Documentation\n\n* [API](api.md)\n* `guide/deep.md`\n")
    _write(root, "Documentation/api.md",
           "# API\n\nSee `crates/core/abi/src/lib.rs:12`, `crates/core/abi/src/lib.rs::item`,\n"
           "`crates/core/abi/`, `mk/host.mk`, [the index](README.md#top) and\n"
           "[rustdoc](https://doc.rust-lang.org/rustdoc/).\n"
           "Not paths: `$AZOS_OUT/doc/x/index.html`, `crates/*/src`, `<crate>/src/lib.rs`,\n"
           "`library/std/src/sys/azos.rs`, `a b`, `crates/core/abi`.\n\n"
           "```sh\ncd crates/core/missing && make nothing/here.mk\n```\n")
    _write(root, "Documentation/guide/deep.md", "# Deep\n\n[up](../api.md)\n")
    _write(root, "ARCHITECTURE.md", "# Architecture\n\n`mk/host.mk`\n")
    _write(root, "README.md", "# AzOS\n\n[docs](Documentation/README.md)\n")


def self_test():
    ok = True

    def expect(label, root, needle):
        nonlocal ok
        got = lint(root)
        hit = [g for g in got if needle in g]
        if needle is None:
            hit = [] if not got else got
            good = not got
        else:
            good = bool(hit)
        print("  %-52s %s" % (label, "ok" if good else "FAIL"))
        if not good:
            ok = False
            for g in (got or ["(no findings)"])[:4]:
                print("      " + g)

    def variant(label, edits, needle):
        with tempfile.TemporaryDirectory() as root:
            _clean_tree(root)
            for rel, text in edits.items():
                if text is None:
                    os.remove(os.path.join(root, rel))
                else:
                    with open(os.path.join(root, rel), "a", encoding="utf-8") as fh:
                        fh.write(text)
            expect(label, root, needle)

    with tempfile.TemporaryDirectory() as root:
        _clean_tree(root)
        expect("clean tree is green", root, None)
    variant("missing path in a code span",
            {"Documentation/api.md": "\n`crates/core/abi/src/gone.rs`\n"}, "gone.rs")
    variant("missing path with :line suffix",
            {"Documentation/api.md": "\n`mk/nothing.mk:7`\n"}, "nothing.mk")
    variant("missing path in a multi-word span",
            {"Documentation/api.md": "\n`cargo test --manifest-path mk/zzz/Cargo.toml`\n"}, "zzz/Cargo.toml")
    variant("missing relative link",
            {"Documentation/api.md": "\n[x](nowhere.md)\n"}, "nowhere.md")
    variant("link leaving the repository",
            {"Documentation/api.md": "\n[x](../../outside.md)\n"}, "leaves the repository")
    variant("missing path in ARCHITECTURE.md",
            {"ARCHITECTURE.md": "\n`mk/absent.mk`\n"}, "absent.mk")
    variant("missing path in README.md",
            {"README.md": "\n`crates/core/absent/src/lib.rs`\n"}, "absent/src/lib.rs")
    variant("private rfcs/ path",
            {"Documentation/api.md": "\n`rfcs/anything.md`\n"}, "private path")
    variant("private docs/ link",
            {"Documentation/api.md": "\n[x](/docs/anything.md)\n"}, "private path")
    variant("file the index does not list",
            {"Documentation/extra.md": "# Extra\n"}, "does not list Documentation/extra.md")
    variant("index missing", {"Documentation/README.md": None}, "missing")
    with tempfile.TemporaryDirectory() as root:
        _clean_tree(root)
        _write(root, "Documentation/api.md", "# API\n\n```\n`mk/ignored-in-a-fence.mk`\n```\n`mk/after.mk`\n")
        got = lint(root)
        good = len(got) == 1 and "after.mk" in got[0]
        print("  %-52s %s" % ("fenced block skipped, span after it checked", "ok" if good else "FAIL"))
        if not good:
            ok = False
            print("      " + "; ".join(got))
    return ok


def main(argv):
    if argv[1:] == ["--self-test"]:
        ok = self_test()
        print("doc_lint self-test: %s" % ("ok" if ok else "FAILED"))
        return 0 if ok else 1
    if len(argv) > 1:
        print(__doc__)
        return 2
    findings = lint(ROOT)
    for f in findings:
        print(f)
    if findings:
        print("doc_lint: %d finding(s)" % len(findings))
        return 1
    print("doc_lint: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

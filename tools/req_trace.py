#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Requirement tags in the code agree with the invariant ledger (SC-10).

`formal/INVARIANTS.md` is the trace from a safety property to the code that
maintains it and the test that checks it. Its ID cell carries two stable
names, `INV-n` and a requirement tag `REQ-nnn`. The code carries the tag too:

    // REQ-003
    #[test]
    fn missing_perms_rejected() { ... }

A `// REQ-nnn` comment line (several tags may share it, `// REQ-001 REQ-002`)
is attached to the next item below it: attributes and other comment lines may
sit between, a blank line may not. This lint reads the ledger and the
annotations and fails when:

  1. a ledger row has no tag, or two rows share a tag or an `INV-n`;
  2. an annotation names a tag no ledger row has, is not attached to an item
     (`fn`, `struct`, `enum`, `const`, `static`, `trait`, `type`, `mod`,
     `union`), or is spelled so that it is not recognised (a `REQ-nnn` in
     a `.rs` file anywhere else than in that comment form);
  3. a path a row names does not exist; a function, type or constant named in
     its "Enforced by" column is defined nowhere in the tree; a model
     identifier named in "Checked by" (CamelCase) is absent from
     `formal/tla/`; a quoted marker or gate-row name (the span has a space) is
     found in no source, script or gate table;
  4. a test or Kani harness named in "Checked by" does not exist, or no
     definition of that name carries the row's tag;
  5. an annotated item is named in neither column of its row (the ledger
     forgot it, or the tag was copied to the wrong place), or an enforcing
     item sits in a file other than the ones the row's "Enforced by" names;
  6. a row has no annotated item in its "Enforced by" column.

`--csv` prints the trace for an auditor: `req_id,inv_id,role,item,file`, one
line per annotated item (role `enforce` or `check`), plus one `check` line per
model identifier with the file `formal/tla/...`. The files looked at are the
tracked and untracked-unignored ones (a clean clone sees the same set);
`third_party/` and any `target/` or `build/` directory are not.

    python3 tools/req_trace.py              lint the tree (exit 1 on a finding)
    python3 tools/req_trace.py --csv        print the trace
    python3 tools/req_trace.py --self-test  the canary: a synthetic violation
                                            of every rule must turn the lint
                                            red, naming that rule, and a clean
                                            tree must stay green
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)

LEDGER = "formal/INVARIANTS.md"
SKIP_PREFIX = ("third_party/",)
SKIP_DIRS = ("target", "build", ".git")
TEXT_EXT = (".rs", ".sh", ".py", ".tsv", ".toml")

TAG = re.compile(r"REQ-\d{3}\b")
ANNOT = re.compile(r"^\s*//\s*((?:REQ-\d{3})(?:[\s,]+REQ-\d{3})*)\s*(?:[:—-].*)?$")
ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:unsafe\s+)?(?:async\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?(fn|struct|enum|const|static|trait|type|mod|union)\s+"
    r"(?:mut\s+)?([A-Za-z_]\w*)")
ATTR = re.compile(r"^\s*(#\[|#!\[|//)")
ROW_ID = re.compile(r"^INV-(\d+)\s*\((REQ-\d{3})\)\s*$")
SNAKE = re.compile(r"^[a-z_][a-z0-9_]*$")
CAMEL = re.compile(r"^[A-Z][A-Za-z0-9]*[a-z][A-Za-z0-9]*$")
IDENT = re.compile(r"^[A-Za-z_]\w*$")
BACKTICK = re.compile(r"`([^`]+)`")


def list_tree(root):
    """Tracked + untracked-unignored files, or the files on disk outside git."""
    files = None
    if os.path.exists(os.path.join(root, ".git")):
        try:
            out = subprocess.run(
                ["git", "-C", root, "ls-files", "--cached", "--others",
                 "--exclude-standard", "-z"],
                check=True, capture_output=True).stdout.decode("utf-8", "replace")
            files = [p for p in out.split("\0") if p and os.path.isfile(os.path.join(root, p))]
        except (OSError, subprocess.CalledProcessError):
            files = None
    if files is None:
        files = []
        for d, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if x != ".git"]
            for n in names:
                files.append(os.path.relpath(os.path.join(d, n), root))
    keep = []
    for f in files:
        if f.startswith(SKIP_PREFIX) or any(p in SKIP_DIRS for p in f.split("/")[:-1]):
            continue
        keep.append(f)
    return sorted(keep)


def read(root, rel):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def split_row(line):
    """Split a markdown table row on `|` that is outside backticks."""
    cells, cur, tick = [], [], False
    for ch in line.strip().strip("|"):
        if ch == "`":
            tick = not tick
        if ch == "|" and not tick:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    cells.append("".join(cur).strip())
    return cells


class Row:
    def __init__(self, inv, tag, enforced, checked, line):
        self.inv, self.tag, self.line = inv, tag, line
        self.enforced_raw, self.checked_raw = enforced, checked
        self.paths, self.enf_paths, self.markers, self.models = [], [], [], []
        self.enf_items, self.chk_tests = set(), set()
        self.enf_defs = []  # names that must be defined somewhere
        for tok in BACKTICK.findall(enforced):
            self.add_enforced(tok)
        for tok in BACKTICK.findall(checked):
            self.add_checked(tok)

    @staticmethod
    def is_path(tok):
        return " " not in tok and ("/" in tok or tok.endswith((".rs", ".tla", ".md", ".sh")))

    def add_enforced(self, tok):
        if self.is_path(tok):
            self.paths.append(tok)
            self.enf_paths.append(tok)
            return
        parts = re.split(r"[\s(]", tok, maxsplit=1)[0].split("::")
        name = parts[-1]
        if IDENT.match(name):
            self.enf_items.add(name)
            self.enf_defs.append((parts[-2] if len(parts) > 1 else "", name))

    def add_checked(self, tok):
        if self.is_path(tok):
            self.paths.append(tok)
        elif " " in tok or tok.startswith("["):
            self.markers.append(tok)
        elif SNAKE.match(tok):
            self.chk_tests.add(tok)
        elif CAMEL.match(tok):
            self.models.append(tok)


def parse_ledger(text):
    """Return (rows, findings). A row is a table line whose first cell begins INV-."""
    rows, findings = [], []
    for no, line in enumerate(text.splitlines(), 1):
        if not line.startswith("| INV-"):
            continue
        cells = split_row(line)
        if len(cells) < 4:
            findings.append((LEDGER, no, "bad-row", "a ledger row needs ID, invariant, enforced by, checked by"))
            continue
        m = ROW_ID.match(cells[0])
        if not m:
            findings.append((LEDGER, no, "no-tag", "ID cell `%s` is not `INV-n (REQ-nnn)`" % cells[0]))
            continue
        rows.append(Row(int(m.group(1)), m.group(2), cells[2], cells[3], no))
    return rows, findings


def annotations(root, rel):
    """Yield (lineno, tags, kind, name) for every annotation in a .rs file;
    kind is 'item' with the attached name, 'loose' or 'malformed'."""
    pending = []  # (lineno, tags) waiting for the item below
    tags_now = []
    first = 0

    def flush(item_name):
        nonlocal pending, tags_now, first
        out = None
        if tags_now:
            out = (first, tags_now, "item" if item_name else "loose", item_name or "")
        pending, tags_now, first = [], [], 0
        return out

    for no, line in enumerate(read(root, rel).splitlines(), 1):
        m = ANNOT.match(line)
        if m:
            if not tags_now:
                first = no
            tags_now = tags_now + TAG.findall(m.group(1))
            continue
        if TAG.search(line) and not line.lstrip().startswith("///"):
            yield no, [], "malformed", line.strip()
            continue
        if tags_now and ATTR.match(line):
            continue
        im = ITEM.match(line)
        res = flush(im.group(2) if im else None)
        if res:
            yield res
    res = flush(None)
    if res:
        yield res


def lint(root):
    """Return (findings, trace). findings: (file, line, code, message)."""
    findings = []
    trace = []  # (req, inv, role, item, file)
    files = list_tree(root)
    if LEDGER not in files:
        return [(LEDGER, 0, "no-ledger", "the invariant ledger is missing")], trace
    rows, f = parse_ledger(read(root, LEDGER))
    findings += f
    by_tag, seen_inv = {}, {}
    for r in rows:
        if r.tag in by_tag:
            findings.append((LEDGER, r.line, "dup-tag", "%s is also the tag of INV-%d" % (r.tag, by_tag[r.tag].inv)))
        by_tag.setdefault(r.tag, r)
        if r.inv in seen_inv:
            findings.append((LEDGER, r.line, "dup-tag", "INV-%d appears twice" % r.inv))
        seen_inv[r.inv] = r

    rs = [p for p in files if p.endswith(".rs")]
    defs = {}      # name -> set of files defining an item of that name
    annotated = {}  # (tag, name) -> [files]
    anns = []      # (file, line, tag, name)
    # A lookahead, so that `const fn name` yields `name` and not `fn`.
    item_def = re.compile(
        r"(?=\b(?:fn|struct|enum|const|static|trait|type|mod|union)\s+(?:mut\s+)?([A-Za-z_]\w*))")
    text_of = {}
    for p in rs:
        text = text_of[p] = read(root, p)
        for m in item_def.finditer(text):
            defs.setdefault(m.group(1), set()).add(p)
        for no, tags, kind, name in annotations(root, p):
            if kind == "malformed":
                findings.append((p, no, "bad-annotation", "`REQ-nnn` outside the `// REQ-nnn` comment form: " + name))
                continue
            if kind == "loose":
                findings.append((p, no, "loose-annotation", "annotation is not attached to an item"))
                continue
            for t in tags:
                if t not in by_tag:
                    findings.append((p, no, "dangling-req", "%s is not in %s" % (t, LEDGER)))
                    continue
                annotated.setdefault((t, name), []).append(p)
                anns.append((p, no, t, name))

    tla = "".join(read(root, p) for p in files if p.startswith("formal/tla/") and p.endswith(".tla"))
    tla_files = [p for p in files if p.startswith("formal/tla/") and p.endswith(".tla")]
    texts = None
    for r in rows:
        where = (LEDGER, r.line)
        for p in r.paths:
            if p not in files and not any(x.startswith(p.rstrip("/") + "/") for x in files):
                findings.append(where + ("missing-path", "%s names `%s`, which does not exist" % (r.tag, p)))
        for qual, name in r.enf_defs:
            # `Enum::Variant` is a definition of the variant when `Enum` is defined.
            variant = qual in defs and any(
                re.search(r"\b" + re.escape(name) + r"\b", text_of[q]) for q in defs[qual])
            if name not in defs and not variant:
                findings.append(where + ("missing-item", "%s: `%s` is defined nowhere" % (r.tag, name)))
        for name in sorted(r.chk_tests):
            if name not in defs:
                findings.append(where + ("missing-test", "%s: test `%s` does not exist" % (r.tag, name)))
            elif (r.tag, name) not in annotated:
                findings.append(where + ("untagged-test", "%s: no definition of `%s` carries `// %s`" % (r.tag, name, r.tag)))
        for m in r.models:
            if not re.search(r"\b" + re.escape(m) + r"\b", tla):
                findings.append(where + ("missing-model", "%s: `%s` is not in formal/tla/" % (r.tag, m)))
            else:
                src = next((p for p in tla_files if re.search(r"\b" + re.escape(m) + r"\b", read(root, p))), "formal/tla")
                trace.append((r.tag, "INV-%d" % r.inv, "check", m, src))
        for mk in r.markers:
            if texts is None:
                texts = "\n".join(read(root, p) for p in files if p.endswith(TEXT_EXT))
            if mk not in texts:
                findings.append(where + ("missing-marker", "%s: marker `%s` appears in no source, script or gate table" % (r.tag, mk)))
        if not any(t == r.tag and n in r.enf_items for (t, n) in annotated):
            findings.append(where + ("no-enforcer", "%s: no annotated item among its \"Enforced by\" names" % r.tag))

    for p, no, t, name in anns:
        r = by_tag[t]
        if name in r.chk_tests:
            role = "check"
        elif name in r.enf_items:
            role = "enforce"
            if r.enf_paths and not any(p == x or p.startswith(x.rstrip("/") + "/") for x in r.enf_paths):
                findings.append((p, no, "wrong-file", "`%s` carries %s but %s names its code in %s, not here"
                                 % (name, t, t, ", ".join(r.enf_paths))))
                continue
        else:
            findings.append((p, no, "not-in-ledger", "`%s` carries %s but %s names it in neither column" % (name, t, t)))
            continue
        trace.append((t, "INV-%d" % r.inv, role, name, p))
    trace.sort()
    return findings, trace


def report(findings):
    for f, no, code, msg in sorted(findings, key=lambda x: (x[0], x[1], x[2])):
        print("req_trace: %s:%d: [%s] %s" % (f, no, code, msg))


# ---- self-test -------------------------------------------------------------

LEDGER_OK = """# Invariants

| ID | Invariant | Enforced by | Checked by |
|---|---|---|---|
| INV-1 (REQ-001) | A thing holds. | `Table::resolve` in `src/lib.rs`, `LIMIT`, `Mode::Strict` | Kani `holds_always`; host test `a_thing_holds` in `tests/t.rs`; `SpecHolds` in `formal/tla/s.tla`; the gate's `thing ok` row |
| INV-2 (REQ-002) | Another holds. | `check_other` | host test `other_holds` |
"""
SRC_OK = """pub const LIMIT: u32 = 4;

pub enum Mode {
    Strict,
}

pub struct Table;

impl Table {
    // REQ-001
    pub fn resolve(&self) -> bool { true }
}

// REQ-002
pub const fn check_other() {}

#[cfg(kani)]
mod proofs {
    // REQ-001
    #[kani::proof]
    fn holds_always() {}
}
"""
TEST_OK = """// REQ-001
#[test]
fn a_thing_holds() {}

// REQ-002
// a note between
#[test]
fn other_holds() {}
"""
BASE = {
    LEDGER: LEDGER_OK,
    "src/lib.rs": SRC_OK,
    "tests/t.rs": TEST_OK,
    "formal/tla/s.tla": "SpecHolds == TRUE\n",
    "tools/gate.sh": "echo 'thing ok'\n",
}


def build(tree, files):
    for rel, text in files.items():
        path = os.path.join(tree, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


def self_test():
    ok = True

    def run(label, files, want):
        nonlocal ok
        with tempfile.TemporaryDirectory(prefix="req_trace.") as tree:
            build(tree, files)
            found, _ = lint(tree)
        codes = sorted({c for _, _, c, _ in found})
        good = (codes == []) if want is None else (want in codes)
        print("  %-34s %s%s" % (label, "ok" if good else "FAIL",
                                "" if good else "  (wanted %s, got %s)" % (want, codes)))
        ok &= good

    def with_(path, old, new):
        d = dict(BASE)
        assert old in d[path], (path, old)
        d[path] = d[path].replace(old, new)
        return d

    run("clean tree", BASE, None)
    run("ledger row without a tag", with_(LEDGER, "INV-2 (REQ-002)", "INV-2"), "no-tag")
    run("two rows, one tag", with_(LEDGER, "INV-2 (REQ-002)", "INV-2 (REQ-001)"), "dup-tag")
    run("dangling annotation", with_("src/lib.rs", "// REQ-002\npub const fn", "// REQ-009\npub const fn"), "dangling-req")
    run("annotation on nothing", with_("src/lib.rs", "// REQ-002\npub const fn check_other() {}",
                                        "// REQ-002\n\npub const fn check_other() {}"), "loose-annotation")
    run("misspelled annotation", with_("src/lib.rs", "// REQ-002\npub const fn", "// see REQ-002\npub const fn"), "bad-annotation")
    run("named path is gone", with_(LEDGER, "`tests/t.rs`", "`tests/gone.rs`"), "missing-path")
    run("enforcer not defined", with_(LEDGER, "`check_other`", "`check_gone`"), "missing-item")
    run("enum variant gone", with_("src/lib.rs", "    Strict,\n", ""), "missing-item")
    run("const fn enforcer renamed", with_("src/lib.rs", "pub const fn check_other", "pub const fn check_else"),
        "missing-item")
    run("enforcer in another file", dict(BASE, **{"src/other.rs": "// REQ-001\npub fn resolve() {}\n"},
                                         **{"src/lib.rs": SRC_OK.replace("// REQ-001\n    pub fn resolve", "    pub fn resolve")}),
        "wrong-file")
    run("test not defined", with_(LEDGER, "`a_thing_holds`", "`a_thing_gone`"), "missing-test")
    run("test without the tag", with_("tests/t.rs", "// REQ-001\n#[test]\nfn a_thing", "#[test]\nfn a_thing"),
        "untagged-test")
    run("test with the wrong tag", with_("tests/t.rs", "// REQ-001\n#[test]\nfn a_thing", "// REQ-002\n#[test]\nfn a_thing"),
        "untagged-test")
    run("model identifier missing", with_("formal/tla/s.tla", "SpecHolds", "SpecOther"), "missing-model")
    run("marker nowhere", with_("tools/gate.sh", "thing ok", "thing bad"), "missing-marker")
    run("annotated item not in ledger", with_("src/lib.rs", "// REQ-002\npub const fn check_other",
                                               "// REQ-002\npub const fn stray() {}\n\n// REQ-002\npub fn check_other"),
        "not-in-ledger")
    run("row with no annotated enforcer", with_("src/lib.rs", "// REQ-002\npub const fn check_other", "pub fn check_other"),
        "no-enforcer")
    run("tag on a skipped dir is ignored", dict(BASE, **{SKIP_DIRS[0] + "/x.rs": "// REQ-009\nfn z() {}\n"}), None)
    # --csv shape: every annotated item and the model identifier are listed.
    with tempfile.TemporaryDirectory(prefix="req_trace.") as tree:
        build(tree, BASE)
        found, trace = lint(tree)
    roles = sorted((t, r, n) for t, _, r, n, _ in trace)
    want = [("REQ-001", "check", "SpecHolds"), ("REQ-001", "check", "a_thing_holds"),
            ("REQ-001", "check", "holds_always"), ("REQ-001", "enforce", "resolve"),
            ("REQ-002", "check", "other_holds"), ("REQ-002", "enforce", "check_other")]
    good = roles == sorted(want)
    print("  %-34s %s" % ("trace lists every link", "ok" if good else "FAIL  " + repr(roles)))
    ok &= good
    print("req_trace self-test: %s" % ("ok" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv):
    if "--self-test" in argv:
        return self_test()
    findings, trace = lint(ROOT)
    if "--csv" in argv:
        print("req_id,inv_id,role,item,file")
        for row in trace:
            print(",".join(row))
        return 1 if findings else 0
    if findings:
        report(findings)
        print("req_trace: %d finding(s)" % len(findings))
        return 1
    print("req_trace: ok (%d requirements, %d links)" % (len({t[0] for t in trace}), len(trace)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

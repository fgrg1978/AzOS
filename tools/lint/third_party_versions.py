#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Version manifest of the third-party code in the tree.

third_party/MANIFEST.json names each source tree (busybox, limine, linux, relibc,
u-boot): upstream, tag, version, pinned commit and the date the pin was taken.
third_party/VENDOR_PIN names each vendored registry crate. This script

  * checks the manifest against .gitmodules (same trees, same upstream and tag),
    the index (the gitlink is the commit), the tag (the version is its number) and,
    when a tree is checked out, its HEAD;
  * checks VENDOR_PIN is well formed;
  * prints every pin;
  * reports each pin below the `fixed_in` version of a row of third_party/known_cves.tsv
    (a list kept by hand; nothing here reads the network). A reported CVE fails the check.

Usage: python3 tools/lint/third_party_versions.py [--quiet] [--cves FILE] | --self-test
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
SHA = re.compile(r"^[0-9a-f]{64}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def submodules(root):
    out = git(root, "config", "-f", ".gitmodules", "--get-regexp", r"^submodule\.") or ""
    mods = {}
    for line in out.splitlines():
        k, _, v = line.partition(" ")
        name, _, key = k[len("submodule."):].rpartition(".")
        mods.setdefault(name, {})[key] = v
    return mods


def gitlinks(root):
    out = git(root, "ls-files", "-s") or ""
    return {f[3]: f[1] for f in (ln.split(None, 3) for ln in out.splitlines()) if len(f) == 4 and f[0] == "160000"}


def vkey(v):
    """Numeric tuple of a version ('1_36_1', 'v7.2.9', '2025.07', '10.8.5-binary')."""
    m = re.match(r"^v?(\d+(?:[._]\d+)*)", v)
    return tuple(int(x) for x in re.split(r"[._]", m.group(1))) if m else None


def parse_vendor_pin(path):
    pins, errs = [], []
    for n, line in enumerate(open(path), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split()
        if len(f) not in (3, 4) or not SHA.match(f[2]) or (len(f) == 4 and f[3] != "pruned") or vkey(f[1]) is None:
            errs.append(f"VENDOR_PIN:{n}: not `name version sha256 [pruned]`: {line[:60]}")
            continue
        pins.append((f[0], f[1]))
    dup = {p for p in pins if pins.count(p) > 1}
    errs += [f"VENDOR_PIN: {n} {v} listed twice" for n, v in sorted(dup)]
    return pins, errs


def parse_cves(path):
    rows, errs = [], []
    if not os.path.exists(path):
        return rows, errs
    for n, line in enumerate(open(path), 1):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) != 4 or not f[1] or vkey(f[2]) is None:
            errs.append(f"{os.path.basename(path)}:{n}: need component<TAB>id<TAB>fixed_in<TAB>summary")
            continue
        rows.append(tuple(f))
    return rows, errs


def check_manifest(root, manifest):
    errs = []
    mods, links = submodules(root), gitlinks(root)
    trees = manifest.get("trees", [])
    names = [t.get("name") for t in trees]
    if len(set(names)) != len(names):
        errs.append("MANIFEST: a tree is listed twice")
    want = {n.split("/", 1)[1] for n in mods}
    if set(names) != want:
        errs.append(f"MANIFEST trees {sorted(names)} != .gitmodules {sorted(want)}")
    for t in trees:
        n, path = t.get("name"), f"third_party/{t.get('name')}"
        m = mods.get(path)
        if m is None:
            continue
        if t.get("upstream") != m.get("url"):
            errs.append(f"{n}: upstream {t.get('upstream')} != .gitmodules {m.get('url')}")
        if t.get("tag") != m.get("tag"):
            errs.append(f"{n}: tag {t.get('tag')} != .gitmodules {m.get('tag')}")
        if not COMMIT.match(t.get("commit") or "") or t.get("commit") != links.get(path):
            errs.append(f"{n}: commit {t.get('commit')} != gitlink {links.get(path)}")
        if not DATE.match(t.get("pinned") or ""):
            errs.append(f"{n}: pinned {t.get('pinned')!r} is not YYYY-MM-DD")
        v, tag = t.get("version"), t.get("tag")
        if tag:
            if v is None or vkey(v) != vkey(tag):
                errs.append(f"{n}: version {v} is not the number of tag {tag}")
        elif v is not None:
            errs.append(f"{n}: version {v} with no tag (a commit pin has version null)")
        sub = os.path.join(root, path)
        if os.path.exists(os.path.join(sub, ".git")):
            head = git(sub, "rev-parse", "HEAD")
            if head != t.get("commit"):
                errs.append(f"{n}: checkout HEAD {head} != manifest {t.get('commit')}")
    return errs


def report(root, manifest, vendor, cves, quiet=False):
    """Print every pin; return the CVE findings."""
    out = print if not quiet else (lambda *a: None)
    found = []
    comps = []
    for t in manifest.get("trees", []):
        sub = os.path.join(root, "third_party", t["name"])
        date = git(sub, "log", "-1", "--format=%cs") if os.path.exists(os.path.join(sub, ".git")) else None
        out(f"{t['name']:<10} {t['version'] or 'commit':<10} {t['commit'][:12]}  pinned {t['pinned']}"
            + (f"  upstream commit {date}" if date else "") + f"  {t['upstream']}")
        comps.append((t["name"], t["version"]))
    for n, v in vendor:
        comps.append((f"crate:{n}", v))
    out(f"vendored crates: {len(vendor)} (third_party/VENDOR_PIN)")
    for comp, ver in comps:
        for c, cid, fixed, summary in cves:
            if c == comp and ver is not None and vkey(ver) < vkey(fixed):
                found.append(f"{comp} {ver}: {cid} fixed in {fixed}: {summary}")
    return found


def run(root, cves_path, quiet=False):
    manifest = json.load(open(os.path.join(root, "third_party", "MANIFEST.json")))
    vendor, errs = parse_vendor_pin(os.path.join(root, "third_party", "VENDOR_PIN"))
    cves, e2 = parse_cves(cves_path)
    errs += e2 + check_manifest(root, manifest)
    errs += [f"CVE {x}" for x in report(root, manifest, vendor, cves, quiet)]
    return errs


def self_test():
    import tempfile
    assert vkey("1_36_1") == (1, 36, 1) and vkey("v10.8.5-binary") == (10, 8, 5) and vkey("2025.07") == (2025, 7)
    assert vkey("1.9") < vkey("1.10") and vkey("x") is None
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "pin")
        open(p, "w").write("a 1.0.0 " + "0" * 64 + "\nb 2.0 " + "1" * 64 + " pruned\nb 2.0 " + "1" * 64 + "\nc 1 zz\n")
        pins, errs = parse_vendor_pin(p)
        assert pins == [("a", "1.0.0"), ("b", "2.0"), ("b", "2.0")] and len(errs) == 2, (pins, errs)
        c = os.path.join(d, "cves")
        open(c, "w").write("busybox\tCVE-X\t1.37.0\tsample\ncrate:a\tCVE-Y\t1.0.0\tfixed here\nbad line\n")
        rows, errs = parse_cves(c)
        assert len(rows) == 2 and len(errs) == 1
        man = {"trees": [{"name": "busybox", "version": "1.36.1", "commit": "0" * 40, "pinned": "2026-01-01", "upstream": "u"}]}
        found = report(d, man, [("a", "1.0.0")], rows, quiet=True)
        assert found == ["busybox 1.36.1: CVE-X fixed in 1.37.0: sample"], found
    print("third_party_versions self-test ok")


def main(argv):
    if "--self-test" in argv:
        self_test()
        return 0
    cves = os.path.join(ROOT, "third_party", "known_cves.tsv")
    if "--cves" in argv:
        cves = argv[argv.index("--cves") + 1]
    errs = run(ROOT, cves, "--quiet" in argv)
    for e in errs:
        print(f"[PIN] {e}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

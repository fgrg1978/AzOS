#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The OS does not depend on the sibling brain repo.

The brain (`AzOSRobotBrain`) is an optional client: the dependency points from
the brain to the OS and never back. Two rules keep it so:

  * no tool, make file, build script or cargo config names the repo by a path
    (`../AzOSRobotBrain`) or builds one (`"AzOSRobotBrain"` in a path join).
    The one definition is tools/lib/azos_tools.py (BRAIN_REPO_NAME), which finds
    it for everyone else; comments are not looked at;
  * every gate scenario in tools/gate/ci_check.sh that boots against a brain
    peer (`run_brain_peer_boot` with a session, `link_peer.py --port`) starts
    with `brain_peer_required || return 0`, so a run without the repo skips
    it with a line instead of failing.

    python3 tools/lint/brain_dep_lint.py              lint the tree (exit 1 on a finding)
    python3 tools/lint/brain_dep_lint.py --self-test  the canary: a planted path and an
                                                 unguarded scenario must turn it red
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = os.path.realpath(azos_tools.ROOT)
SCAN = ("tools", "mk", "Makefile", ".cargo", "kernel", "crates", "userspace", "tests", "arch", "sdk", "micro")
EXT = (".sh", ".py", ".mk", ".toml", ".rs", ".tsv")
ALLOWED = {"tools/lib/azos_tools.py", "tools/lint/brain_dep_lint.py"}
PATH_RE = re.compile(r"\.\./+AzOSRobotBrain|\"AzOSRobotBrain\"|'AzOSRobotBrain'")
COMMENT_RE = re.compile(r"^\s*(#|//)")
GATE = "tools/gate/ci_check.sh"
FUNC_RE = re.compile(r"^(\s+)([a-z_0-9]+)\(\) \{")
PEER_RE = re.compile(r"run_brain_peer_boot \"|tools/gate/link_peer\.py --port")
GUARD = "brain_peer_required || return 0"


def files(root):
    for top in SCAN:
        p = os.path.join(root, top)
        if os.path.isfile(p):
            yield top
            continue
        for d, subs, names in os.walk(p):
            subs[:] = [s for s in subs if s not in ("target", ".git", "third_party", "__pycache__")]
            for n in names:
                if n.endswith(EXT) or n == "Makefile":
                    yield os.path.relpath(os.path.join(d, n), root)


def path_findings(root):
    out = []
    for rel in files(root):
        if rel in ALLOWED:
            continue
        try:
            lines = open(os.path.join(root, rel), encoding="utf-8").read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for n, ln in enumerate(lines, 1):
            if PATH_RE.search(ln) and not COMMENT_RE.match(ln):
                out.append(f"{rel}:{n}: names the brain repo by a path: {ln.strip()[:100]}")
    return out


def guard_findings(root):
    p = os.path.join(root, GATE)
    if not os.path.isfile(p):
        return []
    lines = open(p, encoding="utf-8").read().splitlines()
    out = []
    i = 0
    while i < len(lines):
        m = FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        indent, name = m.groups()
        j = i + 1
        while j < len(lines) and not lines[j].startswith(indent + "}"):
            j += 1
        body = [ln for ln in lines[i + 1:j] if not COMMENT_RE.match(ln) and ln.strip()]
        text = "\n".join(body)
        if name != "run_brain_peer_boot" and PEER_RE.search(text) and "--reconnect" not in text:
            if not body or GUARD not in body[0]:
                out.append(f"{GATE}:{i + 1}: {name} boots against a brain peer and does not start with `{GUARD}`")
        i = j + 1
    return out


def lint(root):
    return path_findings(root) + guard_findings(root)


def self_test():
    import tempfile
    fails = []
    with tempfile.TemporaryDirectory() as d:
        def put(rel, text):
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w", encoding="utf-8").write(text)
        good_gate = '    ring_scenario() {\n        brain_peer_required || return 0\n        run_brain_peer_boot "$log" "$blog" img 4\n    }\n' \
                    '    reconnect_scenario() {\n        run_brain_peer_boot "$log" "$blog" img 1 --reconnect\n    }\n'
        put(GATE, good_gate)
        put("tools/gate/x.sh", '# BRAIN_DIR="$OS/../AzOSRobotBrain"\necho "AzOSRobotBrain is optional"\n')
        if lint(d):
            fails.append(f"a clean tree is reported: {lint(d)}")
        put("tools/gate/x.sh", 'BRAIN_DIR="$OS_DIR/../AzOSRobotBrain"\n')
        if not any("x.sh:1" in f for f in path_findings(d)):
            fails.append("a hardcoded sibling path is not reported")
        put("tools/gate/x.sh", "")
        put("tools/gate/y.py", 'p = os.path.join(root, "AzOSRobotBrain")\n')
        if not any("y.py:1" in f for f in path_findings(d)):
            fails.append("a path join with the repo name is not reported")
        put("tools/gate/y.py", "")
        put(GATE, good_gate.replace("        brain_peer_required || return 0\n", ""))
        if not any("ring_scenario" in f for f in guard_findings(d)):
            fails.append("an unguarded peer scenario is not reported")
        put(GATE, good_gate.replace('run_brain_peer_boot "$log" "$blog" img 4', 'python3 tools/gate/link_peer.py --port 0'))
        if guard_findings(d):
            fails.append("a guarded link_peer scenario is reported")
    if fails:
        print("brain_dep_lint self-test FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("brain_dep_lint self-test ok")
    return 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    found = lint(ROOT)
    for f in found:
        print(f)
    print("brain_dep_lint: " + (f"{len(found)} finding(s)" if found else "ok"))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())

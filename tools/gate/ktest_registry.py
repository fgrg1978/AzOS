#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The in-kernel tests a kernel registers, read from the source.

`ktest!` / `ktest_late!` sites (crates/core/ktest) under kernel/src, with the
`#[cfg(..)]` of the site and of every module and block around it evaluated for
one ISA and one feature set. The gate expects the TAP plan of a ktest row to be
exactly this list: a test that the build lost, or one that the runner reports
twice, is a red row, and nobody keeps a count by hand.

The feature set is the kernel's, as the build derives it: the configuration with
the row's selection applied (tools/build/kconfig_to_cargo.py --select), closed
over kernel/Cargo.toml's [features]. A cfg this file cannot evaluate, a `mod`
it cannot find, or a ktest site outside the module tree is an error, never a
guess.

  ktest_registry.py count  --isa rv|arm|x86 --config CFG [--select TOKENS]
  ktest_registry.py names  (same)            one name per line
  ktest_registry.py verify (same) --log LOG  "" when the TAP lines of LOG name
                                             exactly these tests, else the diff
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
import kconfig_to_cargo  # noqa: E402
import out_dir  # noqa: E402

ROOT = azos_tools.ROOT
KSRC = os.path.join(ROOT, "kernel/src")
ARCH = {"rv": "riscv64", "arm": "aarch64", "x86": "x86_64"}
MACROS = {"ktest": "early", "ktest_late": "late"}


class Unsupported(Exception):
    pass


# ── tokens ────────────────────────────────────────────────────────────

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUM = re.compile(r"[0-9][0-9A-Za-z_.]*")


def tokenize(src):
    """(kind, text, line) with comments dropped. kind: i ident, s string (text is
    its content), p punctuation (one character), n number."""
    out, i, n, line = [], 0, len(src), 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    line += src[i] == "\n"
                    i += 1
        else:
            m = re.compile(r'(?:b?r(#*)")').match(src, i) if c in "rb" else None
            if m:
                end = '"' + m.group(1)
                j = src.find(end, m.end())
                if j < 0:
                    raise Unsupported("unterminated raw string at line %d" % line)
                out.append(("s", src[m.end():j], line))
                line += src.count("\n", i, j)
                i = j + len(end)
            elif c == '"' or (c == "b" and src.startswith('b"', i)):
                i += 1 if c == '"' else 2
                j = i
                while src[j] != '"':
                    j += 2 if src[j] == "\\" else 1
                out.append(("s", src[i:j], line))
                line += src.count("\n", i, j)
                i = j + 1
            elif c == "'" or (c == "b" and src.startswith("b'", i)):
                i += 1 if c == "'" else 2
                m = _IDENT.match(src, i)
                if m and not src.startswith("'", m.end()):
                    i = m.end()                 # a lifetime
                else:
                    j = i
                    while src[j] != "'":
                        j += 2 if src[j] == "\\" else 1
                    i = j + 1
            else:
                m = _IDENT.match(src, i)
                if m:
                    out.append(("i", m.group(), line))
                    i = m.end()
                    continue
                m = _NUM.match(src, i)
                if m:
                    out.append(("n", m.group(), line))
                    i = m.end()
                    continue
                out.append(("p", c, line))
                i += 1
    return out


# ── cfg predicates ────────────────────────────────────────────────────

def parse_pred(toks, i):
    """(predicate, next index) at toks[i]: a tree of ('all'|'any'|'not'|'kv'|'flag', ..)."""
    kind, text, line = toks[i]
    if kind != "i":
        raise Unsupported("cfg predicate at line %d" % line)
    if text in ("all", "any", "not"):
        assert toks[i + 1][1] == "("
        i += 2
        subs = []
        while toks[i][1] != ")":
            p, i = parse_pred(toks, i)
            subs.append(p)
            if toks[i][1] == ",":
                i += 1
        return (text, subs), i + 1
    if toks[i + 1][1] == "=":
        return ("kv", text, toks[i + 2][1]), i + 3
    return ("flag", text), i + 1


def evaluate(pred, env):
    op = pred[0]
    if op == "all":
        return all(evaluate(p, env) for p in pred[1])
    if op == "any":
        return any(evaluate(p, env) for p in pred[1])
    if op == "not":
        return not evaluate(pred[1][0], env)
    if op == "kv":
        key, val = pred[1], pred[2]
        if key == "feature":
            return val in env["features"]
        if key in env["kv"]:
            return env["kv"][key] == val
        raise Unsupported("cfg(%s = %r) has no value here" % (key, val))
    if pred[1] in env["flags"]:
        return env["flags"][pred[1]]
    raise Unsupported("cfg(%s) has no value here" % pred[1])


def environment(isa, features):
    return {
        "features": set(features),
        "kv": {"target_arch": ARCH[isa], "target_os": "none", "target_pointer_width": "64",
               "target_endian": "little", "target_vendor": "unknown", "target_env": "",
               "panic": "abort"},
        "flags": {"test": False, "debug_assertions": False, "unix": False, "windows": False,
                  "doc": False, "miri": False},
    }


# ── the module tree ───────────────────────────────────────────────────

class Walker:
    def __init__(self, env, root_file):
        self.env, self.root, self.found, self.declared = env, root_file, [], {os.path.realpath(root_file)}

    def file(self, path, active=True):
        path = os.path.realpath(path)
        with open(path, encoding="utf-8") as fh:
            toks = tokenize(fh.read())
        base = os.path.basename(path)
        mod_dir = os.path.dirname(path) if base in ("main.rs", "lib.rs", "mod.rs") else path[:-3]
        # `#![cfg(..)]` at the top of a file gates the whole file.
        i = 0
        while i + 2 < len(toks) and toks[i][1] == "#" and toks[i + 1][1] == "!":
            j = i + 3
            if toks[j][1] == "cfg":
                pred, _ = parse_pred(toks, j + 2)
                active = active and evaluate(pred, self.env)
            i = self.skip_brackets(toks, i + 2)
        self.scan(toks, i, path, mod_dir, active)

    @staticmethod
    def skip_brackets(toks, i):
        """Index after the bracket group that opens at toks[i]."""
        depth = 0
        while True:
            if toks[i][0] == "p":
                if toks[i][1] in "[({":
                    depth += 1
                elif toks[i][1] in "])}":
                    depth -= 1
                    if depth == 0:
                        return i + 1
            i += 1

    def scan(self, toks, i, path, mod_dir, active):
        stack = [(active, mod_dir)]     # (enabled, directory of the block's child modules)
        pending, pending_path = [], None
        n = len(toks)
        while i < n:
            kind, text, line = toks[i]
            if text == "#" and kind == "p" and toks[i + 1][1] in ("[", "!"):
                j = i + (3 if toks[i + 1][1] == "!" else 2)
                end = self.skip_brackets(toks, j - 1)
                if toks[j][1] == "cfg":
                    pred, _ = parse_pred(toks, j + 2)
                    pending.append(evaluate(pred, self.env))
                elif toks[j][1] == "cfg_attr":
                    if any(t[1] == "path" for t in toks[j:end]):
                        raise Unsupported("%s:%d: cfg_attr(.., path)" % (path, line))
                elif toks[j][1] == "path":
                    pending_path = toks[j + 2][1]
                i = end
                continue
            if kind == "i" and text == "mod" and toks[i + 1][0] == "i":
                name = toks[i + 1][1]
                on = stack[-1][0] and all(pending)
                if toks[i + 2][1] == ";":
                    target = self.mod_file(stack[-1][1], path, name, pending_path)
                    self.declared.add(target)
                    self.file(target, on)
                    pending, pending_path = [], None
                    i += 3
                    continue
                if toks[i + 2][1] == "{":
                    stack.append((on, os.path.join(stack[-1][1], name)))
                    pending, pending_path = [], None
                    i += 3
                    continue
            if kind == "i" and text in MACROS and toks[i + 1][1] == "!" and toks[i + 2][1] in "{(":
                self.site(toks, i, path, stack[-1][0] and all(pending), text)
                pending = []
                i = self.skip_brackets(toks, i + 2)
                continue
            if kind == "p" and text == "{":
                stack.append((stack[-1][0] and all(pending), stack[-1][1]))
                pending = []
            elif kind == "p" and text == "}":
                stack.pop()
            elif kind == "p" and text == ";":
                pending, pending_path = [], None
            i += 1
        assert len(stack) == 1, "%s: unbalanced braces" % path

    def mod_file(self, mod_dir, path, name, explicit):
        if explicit:
            cands = [os.path.join(os.path.dirname(path), explicit)]
        else:
            cands = [os.path.join(mod_dir, name + ".rs"), os.path.join(mod_dir, name, "mod.rs")]
        for c in cands:
            if os.path.isfile(c):
                return os.path.realpath(c)
        raise Unsupported("%s: no file for `mod %s;` (looked for %s)" % (path, name, ", ".join(cands)))

    def site(self, toks, i, path, on, macro):
        j = i + 3
        cfgs = []
        while toks[j][1] == "#":
            if toks[j + 2][1] != "cfg":
                raise Unsupported("%s:%d: only #[cfg] before a ktest fn" % (path, toks[j][2]))
            pred, _ = parse_pred(toks, j + 4)
            cfgs.append(evaluate(pred, self.env))
            j = self.skip_brackets(toks, j + 1)
        if toks[j][1] != "fn" or toks[j + 1][0] != "i" or toks[j + 2][1] != "(":
            raise Unsupported("%s:%d: a %s! that is not `fn name()`" % (path, toks[i][2], macro))
        if on and all(cfgs):
            self.found.append((toks[j + 1][1], MACROS[macro], os.path.relpath(path, ROOT), toks[i][2]))


def feature_closure(names):
    table = kconfig_to_cargo.cargo_features(os.path.join(ROOT, "kernel/Cargo.toml"))
    out, todo = set(), list(names)
    while todo:
        f = todo.pop()
        if f in out:
            continue
        out.add(f)
        todo += [x for x in table.get(f, []) if x in table]
    return out


def has_sites(path):
    with open(path, encoding="utf-8") as fh:
        return re.search(r"\bktest(_late)?!\s*[{(]", fh.read()) is not None


def registry(isa, features, ksrc=None, check_orphans=True):
    """[(name, phase, file, line)] of the kernel built for `isa` with `features`."""
    ksrc = ksrc or KSRC
    env = environment(isa, feature_closure(features))
    w = Walker(env, os.path.join(ksrc, "main.rs"))
    w.file(os.path.join(ksrc, "main.rs"))
    if check_orphans:
        for dp, _, fs in os.walk(ksrc):
            for f in fs:
                p = os.path.realpath(os.path.join(dp, f))
                if f.endswith(".rs") and p not in w.declared and has_sites(p):
                    raise Unsupported("%s has ktest sites but no `mod` reaches it" % os.path.relpath(p, ROOT))
    names = [s[0] for s in w.found]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        raise Unsupported("registered twice: %s" % " ".join(dup))
    return w.found


# ── the configuration's features ──────────────────────────────────────

def route_robot(config, tokens):
    """The robot cell for a selection that asks for a robot feature (tools/gate/ci_cargo.py)."""
    robot = {f for f in os.environ.get("CI_ROBOT_FEATS", "").split(",") if f}
    pairs = dict(p.split("=", 1) for p in os.environ.get("CI_ROBOT_KCONFIG", "").split(";") if "=" in p)
    return pairs[config] if robot and config in pairs and robot & set(tokens) else config


def kernel_features(config, select):
    tokens = [t for t in select.replace(",", " ").split() if t]
    config = route_robot(config, tokens)
    cache = os.path.join(out_dir.out_root(ROOT), "build", "ktest-registry")
    os.makedirs(cache, exist_ok=True)
    with open(config, "rb") as fh:
        key = hashlib.sha256(fh.read() + b"\0" + ",".join(tokens).encode()).hexdigest()[:20]
    hit = os.path.join(cache, key + ".json")
    if os.path.isfile(hit):
        with open(hit, encoding="utf-8") as fh:
            return json.load(fh)
    cmd = [sys.executable, os.path.join(ROOT, "tools/build/kconfig_to_cargo.py")]
    if tokens:
        cmd += ["--select", ",".join(tokens), "--out", os.path.join(cache, key + ".config")]
    r = subprocess.run(cmd + [config], capture_output=True, text=True)
    if r.returncode:
        raise Unsupported("kconfig_to_cargo %s: %s" % (config, r.stderr.strip()))
    out = r.stdout.split()
    feats = out[out.index("--features") + 1].split(",") if "--features" in out else []
    tmp = "%s.%d" % (hit, os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(feats, fh)
    os.replace(tmp, hit)
    return feats


# ── the log ───────────────────────────────────────────────────────────

def tap_names(log_text):
    return re.findall(r"^(?:not )?ok \d+ - ([A-Za-z0-9_]+)", log_text.replace("\r", ""), re.M)


def diff_against_log(names, log_text):
    """'' when the TAP lines name exactly `names`, each once; else what differs."""
    got = tap_names(log_text)
    missing, extra = sorted(set(names) - set(got)), sorted(set(got) - set(names))
    twice = sorted({n for n in got if got.count(n) > 1})
    parts = []
    if missing:
        parts.append("not run: " + " ".join(missing[:8]) + (" ..." if len(missing) > 8 else ""))
    if extra:
        parts.append("run but not in the source: " + " ".join(extra[:8]) + (" ..." if len(extra) > 8 else ""))
    if twice:
        parts.append("reported twice: " + " ".join(twice[:8]))
    return "; ".join(parts)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["count", "names", "verify"])
    ap.add_argument("--isa", required=True, choices=sorted(ARCH))
    ap.add_argument("--config", required=True)
    ap.add_argument("--select", default="")
    ap.add_argument("--log")
    a = ap.parse_args(argv)
    try:
        reg = registry(a.isa, kernel_features(a.config, a.select))
    except (Unsupported, OSError) as e:
        print("ktest_registry: %s" % e, file=sys.stderr)
        return 2
    names = [r[0] for r in reg]
    if a.cmd == "count":
        print(len(names))
    elif a.cmd == "names":
        print("\n".join(sorted(names)))
    else:
        with open(a.log, encoding="utf-8", errors="replace") as fh:
            print(diff_against_log(names, fh.read()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

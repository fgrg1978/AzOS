#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The gate's `cargo`: times every call, and builds each distinct kernel once.

`tools/ci_check.sh` points `$CARGO` here. Every call runs the real cargo
(`CI_REAL_CARGO`, default `cargo`) unless it is a kernel build this gate run has
already done with the same inputs, and appends one line to `CI_BUILD_ACC`
(`<seconds>\t<hit|miss|run>\t<argv>`): the row's build time, which the gate
subtracts from the row's wall time to split build from boot.

The kernel cache (`CI_KCACHE_DIR`; unset means off). A call is cacheable when it
is `cargo build --release` of the kernel package (no `-p`, or `-p azos_kernel`)
without `--keep-going`. Its KEY is the whole argv (features, target, flags), the
working directory, the toolchain (`rustc -vV`), the environment variables a
build can read (below), the content of the file `KCONFIG_CONFIG` names and of
the workspace `.config`, the content of `TOPOLOGY_PUBKEY_PATH` and
`PROD_PUBKEY_PATH`, and the source state: HEAD's tree, `git diff HEAD`, and the
names and content of untracked, non-ignored files. An entry also records every
file the kernel's dep-info names (`<artifact>.d`: every source rustc read, the
`include_bytes!` inputs such as build/*.elf that git ignores, and every
`rerun-if-changed` input of a build script, such as the .config and the key
files) with its content hash; a lookup is a hit only if the key matches AND
every one of those files still hashes the same.

The environment in the key is not all of it: the variables a session sets
(terminal, agent and ssh-agent ids) would make a cache kept between runs miss
for no reason. It is every variable whose name matches KEY_ENV_RE (cargo's,
rustc's, rustup's, the C toolchain's, python's, PATH, HOME) plus every name the
tree itself reads: `env!`, `option_env!`, `env::var[_os]` and
`rerun-if-env-changed=` with a literal name in any .rs file (git grep, per
source state). A build that reads a variable some other way is the gap; there
is none in the tree today.

A hit replays the exit status and the exact stdout/stderr of the build that
filled the entry (so a zero-warning row still sees that build's warnings) and
puts the stored ELF back at the path cargo writes it to, after unlinking that
path first: cargo hard-links it to `deps/kernel-<hash>`, and copying through
the link would rewrite cargo's own artifact for another feature set. Only
successful builds are stored, so a canary that must fail to build always runs
cargo. Every miss of a cacheable build appends to `<cache>/misses.log` what
differed from the last build with the same argv (a key part, or the deps
whose content changed). The gate (tools/ci_check.sh) keeps one run's cache by default, and
under CI_TIER=rows a cache in build/kcache that persists between runs, bounded
by CI_KCACHE_MAX_MB (least recently used entries go first).
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

REAL = os.environ.get("CI_REAL_CARGO", "cargo")
ACC = os.environ.get("CI_BUILD_ACC", "")
CACHE = os.environ.get("CI_KCACHE_DIR", "")
# The gate's own bookkeeping: per-row, per-job values that do not reach cargo.
# The variables a build can read whatever the tree says (see the docstring).
KEY_ENV_RE = re.compile(r"^(__CARGO|CARGO|RUST|PYTHON|CC|CXX|CFLAGS|CXXFLAGS|CPPFLAGS|"
                        r"LDFLAGS|AR|LD|NM|OBJCOPY|SDKROOT|MACOSX_|DEVELOPER_DIR|PATH$|HOME$)")
ENV_READ_RE = r'(env!|option_env!|env::var(_os)?)\("[A-Za-z_0-9]+"|rerun-if-env-changed=[A-Za-z_0-9]+'
BIN = "kernel"


def log(seconds, kind, argv):
    if not ACC:
        return
    try:
        with open(ACC, "a") as f:
            f.write("%.1f\t%s\t%s\n" % (seconds, kind, " ".join(argv)))
    except OSError:
        pass


def sha_file(path, h=None):
    h = h or hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        h.update(b"\0missing\0")
    return h


def git(args, cwd):
    try:
        return subprocess.run(["git"] + args, cwd=cwd, capture_output=True,
                              check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def source_state(cwd):
    top = git(["rev-parse", "--show-toplevel"], cwd)
    if top is None:
        return None
    top = top.decode().strip()
    h = hashlib.sha256()
    for part in (git(["rev-parse", "HEAD^{tree}"], top),
                 git(["diff", "HEAD", "--binary"], top)):
        if part is None:
            return None
        h.update(part)
    untracked = git(["ls-files", "-o", "--exclude-standard", "-z"], top)
    if untracked is None:
        return None
    for name in sorted(n for n in untracked.split(b"\0") if n):
        h.update(name)
        sha_file(os.path.join(top, name.decode()), h)
    return h.hexdigest()


def cacheable(argv):
    args = argv[1:] if argv and argv[0].startswith("+") else argv
    if not args or args[0] != "build" or "--release" not in args:
        return None
    if "--keep-going" in args:
        return None
    pkg = None
    triple = None
    tdir = os.environ.get("CARGO_TARGET_DIR")
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else None
        if a in ("-p", "--package"):
            pkg = nxt
        elif a.startswith("--package="):
            pkg = a.split("=", 1)[1]
        elif a == "--target":
            triple = nxt
        elif a.startswith("--target="):
            triple = a.split("=", 1)[1]
        elif a == "--target-dir":
            tdir = nxt
        elif a in ("--bin", "--example", "--lib", "--bins", "--all", "--workspace",
                   "--manifest-path"):
            return None
    if pkg not in (None, "azos_kernel"):
        return None
    top = git(["rev-parse", "--show-toplevel"], os.getcwd())
    if top is None:
        return None
    top = top.decode().strip()
    if os.path.realpath(os.getcwd()) != os.path.realpath(top):
        return None  # a host crate's own workspace: not the kernel
    triple = triple or "riscv64imac-unknown-none-elf"
    tdir = os.path.join(top, tdir or "target")
    return os.path.join(tdir, triple, "release", BIN)


def tree_env_names(top, state):
    """The variable names the tree's .rs files read, by literal (cached per state)."""
    memo = os.path.join(CACHE, "env-names.%s" % state) if CACHE else None
    if memo and os.path.exists(memo):
        return open(memo).read().split()
    out = git(["grep", "-hoE", ENV_READ_RE, "--", "*.rs"], top)
    if out is None:
        out = b""  # git grep exits 1 when nothing matches
    names = sorted(set(re.findall(r'[A-Za-z_0-9]+(?="?$)', l)[0]
                       for l in out.decode().splitlines() if l))
    if memo:
        try:
            for old in os.listdir(CACHE):
                if old.startswith("env-names."):
                    os.unlink(os.path.join(CACHE, old))
            open(memo, "w").write("\n".join(names) + "\n")
        except OSError:
            pass
    return names


def toolchain(argv):
    cmd = ["rustc"] + ([argv[0]] if argv and argv[0].startswith("+") else []) + ["-vV"]
    try:
        return subprocess.run(cmd, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def key_of(argv):
    """(key, parts): the key, and the hash of each thing in it (for misses.log)."""
    state = source_state(os.getcwd())
    tc = toolchain(argv)
    if state is None or tc is None:
        return None, None
    top = git(["rev-parse", "--show-toplevel"], os.getcwd()).decode().strip()
    parts = {"argv": json.dumps(argv), "cwd": os.getcwd(),
             "toolchain": hashlib.sha256(tc).hexdigest()}
    names = set(tree_env_names(top, state))
    for k in sorted(os.environ):
        if KEY_ENV_RE.match(k) or k in names:
            parts["env " + k] = hashlib.sha256(os.environ[k].encode()).hexdigest()
    for var in ("KCONFIG_CONFIG", "TOPOLOGY_PUBKEY_PATH", "PROD_PUBKEY_PATH"):
        p = os.environ.get(var)
        parts["file $" + var] = sha_file(p).hexdigest() if p else "unset"
    parts["file .config"] = sha_file(os.path.join(top, ".config")).hexdigest()
    parts["source state"] = state
    h = hashlib.sha256()
    for k in sorted(parts):
        h.update(("%s=%s\0" % (k, parts[k])).encode())
    return h.hexdigest(), parts


def note_miss(argv, parts, why):
    """CACHE/misses.log: why a cacheable build missed, against the last one."""
    last = os.path.join(CACHE, "last-%s.json" % hashlib.sha256(
        (parts["argv"] + parts["cwd"]).encode()).hexdigest()[:24])
    if not why:
        try:
            old = json.load(open(last))
            why = sorted(k for k in set(old) | set(parts) if old.get(k) != parts.get(k)) or ["?"]
        except (OSError, ValueError):
            why = ["first build of this argv"]
    log_path = os.path.join(CACHE, "misses.log")
    try:
        if os.path.exists(log_path) and os.path.getsize(log_path) > (1 << 20):
            os.replace(log_path, log_path + ".old")
        with open(log_path, "a") as f:
            f.write("%s\t%s\t%s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), " ".join(argv), "; ".join(why)))
        json.dump(parts, open(last, "w"))
    except OSError:
        pass


def deps_of(artifact):
    """Paths in cargo's dep-info for the artifact (`<artifact>.d`)."""
    try:
        text = open(artifact + ".d").read()
    except OSError:
        return None
    text = text.replace("\\\n", " ")
    out = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        rest = line.split(":", 1)[1]
        # dep-info escapes spaces as "\ "
        for p in rest.replace("\\ ", "\0").split():
            out.add(p.replace("\0", " "))
    return sorted(out)


def clone(src, dst):
    """APFS copy-on-write clone (`cp -c`); a plain copy where there is none."""
    if subprocess.call(["cp", "-c", src, dst], stderr=subprocess.DEVNULL) != 0:
        shutil.copy2(src, dst)


def evict(keep):
    """Drop the least recently used entries past CI_KCACHE_MAX_MB."""
    limit = int(os.environ.get("CI_KCACHE_MAX_MB", "16384")) << 20
    ents = []
    for e in os.listdir(CACHE):
        d = os.path.join(CACHE, e)
        m = os.path.join(d, "meta.json")
        if e == keep or not os.path.exists(m):
            continue
        size = sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d))
        ents.append((os.path.getmtime(m), size, d))
    total = sum(x[1] for x in ents)
    for _, size, d in sorted(ents):
        if total <= limit:
            break
        shutil.rmtree(d, ignore_errors=True)
        total -= size


def run_real(argv, capture):
    if not capture:
        return subprocess.call([REAL] + argv), b"", b""
    p = subprocess.run([REAL] + argv, capture_output=True)
    return p.returncode, p.stdout, p.stderr


def main():
    argv = sys.argv[1:]
    t0 = time.time()
    artifact = cacheable(argv) if CACHE else None
    key, parts = key_of(argv) if artifact else (None, None)
    why = None
    if key:
        ent = os.path.join(CACHE, key)
        meta = os.path.join(ent, "meta.json")
        if os.path.exists(meta):
            m = json.load(open(meta))
            dh = m.get("dep_hashes", {})
            changed = [p for p in m["deps"] if sha_file(p).hexdigest() != dh.get(p)]
            why = ["dep " + p for p in changed[:5]]
            if not changed:
                try:
                    os.unlink(artifact)
                except FileNotFoundError:
                    pass
                os.makedirs(os.path.dirname(artifact), exist_ok=True)
                clone(os.path.join(ent, "elf"), artifact)
                os.utime(meta)
                shutil.copy2(os.path.join(ent, "elf.d"), artifact + ".d")
                sys.stdout.buffer.write(open(os.path.join(ent, "out"), "rb").read())
                sys.stdout.flush()
                sys.stderr.buffer.write(open(os.path.join(ent, "err"), "rb").read())
                sys.stderr.flush()
                log(time.time() - t0, "hit", argv)
                return m["rc"]
    rc, out, err = run_real(argv, capture=bool(key))
    if key:
        note_miss(argv, parts, why)
        sys.stdout.buffer.write(out); sys.stdout.flush()
        sys.stderr.buffer.write(err); sys.stderr.flush()
        deps = deps_of(artifact) if rc == 0 else None
        if deps is not None and os.path.exists(artifact):
            tmp = os.path.join(CACHE, key + ".tmp.%d" % os.getpid())
            os.makedirs(tmp, exist_ok=True)
            clone(artifact, os.path.join(tmp, "elf"))
            shutil.copy2(artifact + ".d", os.path.join(tmp, "elf.d"))
            open(os.path.join(tmp, "out"), "wb").write(out)
            open(os.path.join(tmp, "err"), "wb").write(err)
            json.dump({"rc": rc, "deps": deps,
                       "dep_hashes": {p: sha_file(p).hexdigest() for p in deps}},
                      open(os.path.join(tmp, "meta.json"), "w"))
            ent = os.path.join(CACHE, key)
            shutil.rmtree(ent, ignore_errors=True)
            os.rename(tmp, ent)
            evict(key)
        log(time.time() - t0, "miss", argv)
    else:
        log(time.time() - t0, "run", argv)
    return rc


if __name__ == "__main__":
    sys.exit(main())

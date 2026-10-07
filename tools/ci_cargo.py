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
without `--keep-going`. Its KEY is the whole argv, the working directory, every
environment variable but the gate's own bookkeeping, the content of the file
`KCONFIG_CONFIG` names, the content of `TOPOLOGY_PUBKEY_PATH`, and the source
state (HEAD's tree, `git diff HEAD`, and the names and content of untracked,
non-ignored files). An entry also records every file rustc read for that kernel
(the `.d` dep-info cargo writes next to it, which lists `include_bytes!` inputs
such as build/*.elf that git ignores) with its content hash; a lookup is a hit
only if the key matches AND every one of those files still hashes the same.

A hit replays the exit status and the exact stdout/stderr of the build that
filled the entry (so a zero-warning row still sees that build's warnings) and
puts the stored ELF back at the path cargo writes it to, after unlinking that
path first: cargo hard-links it to `deps/kernel-<hash>`, and copying through
the link would rewrite cargo's own artifact for another feature set. Only
successful builds are stored, so a canary that must fail to build always runs
cargo. The cache lives for one gate run.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

REAL = os.environ.get("CI_REAL_CARGO", "cargo")
ACC = os.environ.get("CI_BUILD_ACC", "")
CACHE = os.environ.get("CI_KCACHE_DIR", "")
# The gate's own bookkeeping: per-row, per-job values that do not reach cargo.
ENV_SKIP = {"_", "SHLVL", "OLDPWD", "PWD", "CI_BUILD_ACC", "CI_KCACHE_DIR",
            "CI_REAL_CARGO", "TERM_SESSION_ID", "SECURITYSESSIONID"}
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


def key_of(argv):
    state = source_state(os.getcwd())
    if state is None:
        return None
    h = hashlib.sha256()
    h.update(json.dumps(argv).encode())
    h.update(os.getcwd().encode())
    for k in sorted(os.environ):
        if k not in ENV_SKIP:
            h.update(("%s=%s\0" % (k, os.environ[k])).encode())
    for var in ("KCONFIG_CONFIG", "TOPOLOGY_PUBKEY_PATH"):
        p = os.environ.get(var)
        if p:
            sha_file(p, h)
    h.update(state.encode())
    return h.hexdigest()


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


def deps_hash(paths):
    h = hashlib.sha256()
    for p in paths:
        h.update(p.encode())
        sha_file(p, h)
    return h.hexdigest()


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
    key = key_of(argv) if artifact else None
    if key:
        ent = os.path.join(CACHE, key)
        meta = os.path.join(ent, "meta.json")
        if os.path.exists(meta):
            m = json.load(open(meta))
            if deps_hash(m["deps"]) == m["deps_hash"]:
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
            json.dump({"rc": rc, "deps": deps, "deps_hash": deps_hash(deps)},
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

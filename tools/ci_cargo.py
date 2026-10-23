#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The gate's `cargo`: times every call, and builds each distinct kernel once.

`tools/ci_check.sh` points `$CARGO` here. Every call runs the real cargo
(`CI_REAL_CARGO`, default `cargo`) unless it is a kernel build this gate run has
already done with the same inputs, and appends one line to `CI_BUILD_ACC`
(`<seconds>\t<hit|miss|run>\t<argv>`): the row's build time, which the gate
subtracts from the row's wall time to split build from boot.

The kernel has no cargo `default` features: Kconfig is the only source. So a
`cargo build|check` of the kernel (the same predicate as the cache's, plus
`check`) gets `--features <the features of its configuration>` appended, from
`tools/kconfig_to_cargo.py` on `KCONFIG_CONFIG` (else the workspace `.config`).
What a row builds beyond its configuration is its selection, `--select
TOKENS` (this wrapper's flag, never cargo's): Kconfig lines, features a
Kconfig symbol owns (applied to a copy of the configuration, which
KCONFIG_CONFIG then names) and test hooks (tools/kconfig_to_cargo.py
`select`). A kernel call's own `--features` is refused unless every name
restates its configuration (a script passing kconfig_to_cargo.py's output on).
The rewritten argv is what the cache keys on and `CI_BUILD_ACC` logs.

A kernel whose selection names a feature that closes over `use-robot` builds from the
robot cell: when `CI_ROBOT_FEATS` (",f1,f2,...,", tools/gate_rows.py
--robot-features) names one of them and `KCONFIG_CONFIG` is a generic gate
config listed in `CI_ROBOT_KCONFIG` ("<generic>=<robot>;..."), the call reads
the robot one instead (tools/ci_check.sh sets both; the gate runs on the
generic image and a robot row on the robot cell).

The kernel cache (`CI_KCACHE_DIR`; unset means off). A call is cacheable when it
is `cargo build --release` of the kernel package (no `-p`, or `-p azos_kernel`)
without `--keep-going`. Its KEY is the whole argv (features, target, flags), the
working directory, the toolchain (`rustc -vV`), the environment variables a
build can read (below), the content of the file `KCONFIG_CONFIG` names and of
the workspace `.config`, the content of `TOPOLOGY_PUBKEY_PATH` and
`PROD_PUBKEY_PATH`, and the source state: HEAD's tree, `git diff HEAD`, and the
names and content of untracked, non-ignored files. An entry also records every
file the kernel's dep-info names (`<artifact>.d`: every source rustc read, the
`include_bytes!` inputs such as $AZOS_OUT/build/*.elf that git ignores, and every
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
under CI_TIER=rows a cache in $AZOS_OUT/build/kcache that persists between runs, bounded
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import out_dir  # noqa: E402

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
    tdir = os.path.join(top, tdir or out_dir.target_dir(os.getcwd()))
    return os.path.join(tdir, triple, "release", BIN)


def kernel_call(argv):
    """True for a `cargo build|check` of the kernel package from the
    workspace root: the calls whose features come from Kconfig."""
    i = 1 if argv and argv[0].startswith("+") else 0
    args = argv[i:]
    if not args or args[0] not in ("build", "check"):
        return False
    pkg = None
    for j, a in enumerate(args):
        if a in ("-p", "--package"):
            pkg = args[j + 1] if j + 1 < len(args) else None
        elif a.startswith("--package="):
            pkg = a.split("=", 1)[1]
        elif a in ("--bin", "--example", "--lib", "--bins", "--all", "--workspace",
                   "--manifest-path", "--no-default-features"):
            return False
    if pkg not in (None, "azos_kernel"):
        return False
    top = git(["rev-parse", "--show-toplevel"], os.getcwd())
    return top is not None and os.path.realpath(os.getcwd()) == os.path.realpath(top.decode().strip())


def take_selection(argv):
    """(argv without `--select TOKENS`, the tokens): the gate's own flag, the
    build selection of tools/kconfig_to_cargo.py `select`."""
    out, toks, j = [], [], 0
    while j < len(argv):
        a = argv[j]
        if a == "--select" and j + 1 < len(argv):
            toks += argv[j + 1].replace(",", " ").split()
            j += 2
            continue
        if a.startswith("--select="):
            toks += a.split("=", 1)[1].replace(",", " ").split()
        else:
            out.append(a)
        j += 1
    return out, toks


def take_features(argv):
    """(the names a `--features`/`-F` list gives, argv without it)."""
    out, names, j = [], [], 0
    while j < len(argv):
        a = argv[j]
        if a in ("--features", "-F") and j + 1 < len(argv):
            names += argv[j + 1].replace(",", " ").split()
            j += 2
            continue
        if a.startswith("--features="):
            names += a.split("=", 1)[1].replace(",", " ").split()
        else:
            out.append(a)
        j += 1
    return names, out


def route_robot(tokens):
    """KCONFIG_CONFIG -> the robot cell for a kernel that asks for a robot feature."""
    robot = set(f for f in os.environ.get("CI_ROBOT_FEATS", "").split(",") if f)
    pairs = dict(p.split("=", 1) for p in os.environ.get("CI_ROBOT_KCONFIG", "").split(";") if "=" in p)
    cfg = os.environ.get("KCONFIG_CONFIG")
    if robot and cfg in pairs and robot & set(tokens):
        os.environ["KCONFIG_CONFIG"] = pairs[cfg]


def with_kconfig_features(argv):
    """argv with the kernel's features: those of the configuration the build
    reads (KCONFIG_CONFIG, else the workspace .config), with the row's
    selection (`--select`) applied to it first (tools/kconfig_to_cargo.py
    `select`: a copy of the configuration under $AZOS_OUT/build/kselect/,
    which KCONFIG_CONFIG then names). A kernel call's own `--features` is
    refused unless each name is one the configuration gives: Kconfig is the
    only source of the kernel's features."""
    argv, toks = take_selection(argv)
    if not kernel_call(argv):
        if toks:
            sys.stderr.write("ci_cargo: --select is for a kernel build or check: %s\n" % " ".join(argv))
            sys.exit(2)
        return argv
    named, argv = take_features(argv)
    route_robot(toks)
    top = git(["rev-parse", "--show-toplevel"], os.getcwd()).decode().strip()
    cfg = os.environ.get("KCONFIG_CONFIG") or os.path.join(top, ".config")
    # A kernel built without its Kconfig features does not compile (or, worse,
    # compiles into something nobody asked for), and the row that follows boots
    # the previous binary. So a config that cannot be read is an error here.
    if not os.path.isfile(cfg):
        sys.stderr.write("ci_cargo: the kernel's config %s does not exist; no features can be derived\n" % cfg)
        sys.exit(2)
    k2c = [sys.executable, os.path.join(top, "tools", "kconfig_to_cargo.py")]
    if toks:
        h = sha_file(cfg)
        h.update(",".join(toks).encode())
        sel = os.path.join(out_dir.out_root(top), "build", "kselect", h.hexdigest()[:16] + ".config")
        os.makedirs(os.path.dirname(sel), exist_ok=True)
        k2c += ["--select", ",".join(toks), "--out", sel]
    try:
        r = subprocess.run(k2c + [cfg], capture_output=True, text=True)
    except OSError as e:
        sys.stderr.write("ci_cargo: tools/kconfig_to_cargo.py %s failed: %s\n" % (cfg, e))
        sys.exit(2)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        sys.exit(2)
    if toks:
        os.environ["KCONFIG_CONFIG"] = sel
    out = r.stdout.split()
    feats = out[out.index("--features"):][:2] if "--features" in out else []
    # `--features` of a caller that restates its configuration (a script that
    # passes `kconfig_to_cargo.py <its .config>` on): accepted only when every
    # name is one the configuration (with the selection) already gives.
    extra = sorted(set(named) - set(feats[1].split(",") if feats else []))
    if extra:
        sys.stderr.write("ci_cargo: a kernel build names its features through --select "
                         "(tools/kconfig_to_cargo.py), never --features; not in its configuration: %s\n"
                         % ",".join(extra))
        sys.exit(2)
    if "--" in argv:
        at = argv.index("--")
        return argv[:at] + feats + argv[at:]
    return argv + feats


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


def default_target_dir(argv):
    """No target dir named: the build goes to the output root, never into the checkout."""
    if os.environ.get("CARGO_TARGET_DIR") or any(a == "--target-dir" or a.startswith("--target-dir=") for a in argv):
        return
    td = out_dir.target_dir(os.getcwd())
    if td:
        os.environ["CARGO_TARGET_DIR"] = td


def main():
    default_target_dir(sys.argv[1:])
    argv = with_kconfig_features(sys.argv[1:])
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

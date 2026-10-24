#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""vendor.py: (re)generate and check third_party/vendor, the crates.io tree the
userspace std programs build from.

    python3 userspace/lib/tls-probe/vendor.py regen   # needs network: cargo vendor + prune + VENDOR_PIN
    python3 userspace/lib/tls-probe/vendor.py check   # offline: the tree is exactly VENDOR_PIN, cargo-deny passes on it
    python3 userspace/lib/tls-probe/vendor.py --self-test   # canary: corrupt a pin, a source, a checksum in a temp copy; each must fail
    python3 userspace/lib/tls-probe/vendor.py test    # offline: the probe's host tests (a TLS handshake over memory), on the stable host toolchain

What is vendored: everything in tls-probe's lockfile (rustls, the
rustls-rustcrypto provider, quinn-proto and their dependencies) plus the
dependencies of the toolchain's own std workspace (`cargo vendor --sync`),
because -Zbuild-std resolves them through the same source replacement
(tools/build/sdk_cargo.py --vendored). That second half moves with rust-toolchain.toml:
a toolchain bump is a `regen`.

Pruning: cargo vendors every platform, and the windows-* crates are most of the
bytes. They are never built for an azos or a unix host target, so the tree keeps
their manifest and licences and replaces the sources with a stub whose library
is a `compile_error!`: a build that does reach one fails loudly instead of
silently using a hollow crate. The `package` checksum in each
.cargo-checksum.json is the crates.io one, so Cargo.lock still matches; the
`files` map lists what is on disk.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
VENDOR = os.path.join(ROOT, "third_party", "vendor")
PIN = os.path.join(ROOT, "third_party", "VENDOR_PIN")
PROBE = os.path.join(ROOT, "userspace", "lib", "tls-probe")
VENDOR_CONFIG = ["--config", 'source.crates-io.replace-with="azos-vendor"', "--config", f'source.azos-vendor.directory="{VENDOR}"']
PRUNE = re.compile(r"^windows[-_]")
KEEP = re.compile(r"^(Cargo\.toml|Cargo\.toml\.orig|LICEN[CS]E.*|license.*|COPYING.*)$")

HEADER = """# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# The crates.io tree third_party/vendor holds, fixed on 2026-10-16 (owner-approved
# download): rustls 0.23 with the rustls-rustcrypto provider (no aws-lc-rs, no
# ring in any build for an azos or a unix host target), quinn-proto 0.11 (no
# crypto feature) and their dependencies, plus the dependencies of the pinned
# toolchain's std workspace (build-std resolves them through the same source
# replacement). One line per package: name, version, sha256 of the .crate file as
# crates.io publishes it (the Cargo.lock checksum), and `pruned` when the sources
# were replaced by a compile_error! stub (userspace/lib/tls-probe/vendor.py).
#
# Written by `vendor.py regen`, verified by `vendor.py check` (tools/gate/ci_check.sh).
# Cargo.lock of userspace/lib/tls-probe is the other half of the pin.
"""


def package_of(d):
    """name and version from the `[package]` table of a vendored (cargo-normalised) Cargo.toml."""
    with open(os.path.join(d, "Cargo.toml")) as f:
        text = f.read()
    sect = text.split("[package]", 1)[1].split("\n[", 1)[0]
    return (re.search(r'^name = "([^"]+)"', sect, re.M).group(1),
            re.search(r'^version = "([^"]+)"', sect, re.M).group(1))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def packages(vendor=VENDOR):
    """(dir, name, version, package checksum) for every directory of the tree."""
    out = []
    for d in sorted(os.listdir(vendor)):
        p = os.path.join(vendor, d)
        if not os.path.isdir(p):
            continue
        with open(os.path.join(p, ".cargo-checksum.json")) as f:
            ck = json.load(f)
        out.append((d,) + package_of(p) + (ck["package"],))
    return out


def prune():
    n = 0
    for d in sorted(os.listdir(VENDOR)):
        p = os.path.join(VENDOR, d)
        if not os.path.isdir(p):
            continue
        name, version = package_of(p)
        if not PRUNE.match(name):
            continue
        had_build = os.path.exists(os.path.join(p, "build.rs"))
        for e in os.listdir(p):
            if KEEP.match(e) or e == ".cargo-checksum.json":
                continue
            subprocess.run(["rm", "-rf", os.path.join(p, e)], check=True)
        os.makedirs(os.path.join(p, "src"))
        with open(os.path.join(p, "src", "lib.rs"), "w") as f:
            f.write(f'compile_error!("{name} {version} is pruned from third_party/vendor '
                    f'(windows crates are never built here; userspace/lib/tls-probe/vendor.py)");\n')
        if had_build:
            with open(os.path.join(p, "build.rs"), "w") as f:
                f.write("fn main() {}\n")
        files = {}
        for dp, _, fs in os.walk(p):
            for fn in fs:
                if fn == ".cargo-checksum.json":
                    continue
                full = os.path.join(dp, fn)
                files[os.path.relpath(full, p)] = sha256(full)
        with open(os.path.join(p, ".cargo-checksum.json")) as f:
            ck = json.load(f)
        ck["files"] = dict(sorted(files.items()))
        with open(os.path.join(p, ".cargo-checksum.json"), "w") as f:
            json.dump(ck, f, separators=(",", ":"))
        n += 1
    return n


def pin_text():
    lines = [HEADER]
    for d, name, ver, ck in packages():
        pruned = " pruned" if PRUNE.match(name) else ""
        lines.append(f"{name} {ver} {ck}{pruned}\n")
    return "".join(lines)


def regen():
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], check=True, capture_output=True, text=True).stdout.strip()
    std_ws = os.path.join(sysroot, "lib", "rustlib", "src", "rust", "library", "Cargo.toml")
    subprocess.run(["rm", "-rf", VENDOR], check=True)
    subprocess.run(["cargo", "vendor", "--locked", "--manifest-path", os.path.join(PROBE, "Cargo.toml"),
                    "--sync", std_ws, VENDOR], check=True, cwd=ROOT, stdout=subprocess.DEVNULL)
    print(f"vendor: pruned {prune()} windows crates")
    with open(PIN, "w") as f:
        f.write(pin_text())
    print(f"vendor: {len(packages())} packages pinned in third_party/VENDOR_PIN")


ADVISORY_DB = os.path.expanduser("~/.cargo/advisory-db")  # deny.toml [advisories] db-path


def advisory_db_present():
    """cargo-deny keeps the RustSec clone in a subdirectory of db-path; an empty directory or a lone db.lock is no database."""
    try:
        return any(e != "db.lock" for e in os.listdir(ADVISORY_DB))
    except OSError:
        return False


def deny(have_deny=None, have_db=None):
    """cargo-deny over tls-probe's graph read from the vendor tree, as deny.toml documents: licenses, bans and sources always,
    advisories when the RustSec database is on disk (the gate never fetches it). Returns (errors, notes): a missing
    cargo-deny is an error, a missing advisory database is a note the gate row prints, not a silent pass."""
    if have_deny is None:
        have_deny = shutil.which("cargo-deny") is not None
    if have_db is None:
        have_db = advisory_db_present()
    if not have_deny:
        return ["cargo-deny is not installed (cargo install cargo-deny): licences, bans and sources are unchecked"], []
    checks = ["licenses", "bans", "sources"] + (["advisories"] if have_db else [])
    notes = [] if have_db else [f"advisories NOT checked: no RustSec database at {ADVISORY_DB} (cargo deny fetch, once, with a network)"]
    with tempfile.TemporaryDirectory() as tmp:
        md = os.path.join(tmp, "metadata.json")
        manifest = os.path.join(PROBE, "Cargo.toml")
        with open(md, "w") as f:
            r = subprocess.run(["cargo", "metadata", "--offline", "--locked", "--format-version", "1", "--manifest-path", manifest]
                               + VENDOR_CONFIG, cwd=ROOT, stdout=f, stderr=subprocess.PIPE, text=True)
        if r.returncode:
            return ["cargo metadata: " + r.stderr.strip()], notes
        r = subprocess.run(["cargo", "deny", "--manifest-path", manifest, "check", "--config", os.path.join(ROOT, "deny.toml"),
                            "--metadata-path", md, "--disable-fetch"] + checks,
                           cwd=ROOT, capture_output=True, text=True)
        if r.returncode:
            return ["cargo deny: " + "\n".join(l for l in r.stderr.splitlines() if not l.startswith("warning"))[-1500:]], notes
    return [], notes


def tree_errors(vendor, pin):
    """Every way `vendor` differs from `pin`: the pin lines, each package's .cargo-checksum.json, the files on disk."""
    bad = []
    with open(pin) as f:
        pinned = [l.split() for l in f if l.strip() and not l.startswith("#")]
    pkgs = packages(vendor)
    have = {(n, v): (ck, bool(PRUNE.match(n))) for _, n, v, ck in pkgs}
    want = {(p[0], p[1]): (p[2], len(p) > 3) for p in pinned}
    for k in sorted(set(want) | set(have)):
        if want.get(k) != have.get(k):
            bad.append(f"{k[0]} {k[1]}: pin {want.get(k)} tree {have.get(k)}")
    for d, name, ver, _ in pkgs:
        p = os.path.join(vendor, d)
        with open(os.path.join(p, ".cargo-checksum.json")) as f:
            files = json.load(f)["files"]
        for rel, h in files.items():
            full = os.path.join(p, rel)
            if not os.path.isfile(full) or sha256(full) != h:
                bad.append(f"{name} {ver}: {rel} differs from its checksum")
        on_disk = {os.path.relpath(os.path.join(dp, fn), p) for dp, _, fs in os.walk(p) for fn in fs} - {".cargo-checksum.json"}
        for rel in sorted(on_disk - set(files)):
            bad.append(f"{name} {ver}: {rel} is not in the checksum file")
    return bad, len(want)


def check():
    bad, n = tree_errors(VENDOR, PIN)
    errs, notes = deny()
    bad += errs
    if bad:
        print("vendor check FAILED:\n  " + "\n  ".join(bad[:40]))
        return 1
    print(f"vendor check ok: {n} packages match third_party/VENDOR_PIN" + "".join(f"\n  note: {x}" for x in notes))
    return 0


def self_test():
    """Canary for `check`: a clean miniature copy of the tree passes, and each corruption below, applied alone, must fail it."""
    pkgs = packages()
    plain = [x for x in pkgs if not PRUNE.match(x[1])]
    pruned = [x for x in pkgs if PRUNE.match(x[1])]
    pick = plain[:3] + pruned[:1]
    pin_lines = {(x[1], x[2]): f"{x[1]} {x[2]} {x[3]}" + (" pruned" if PRUNE.match(x[1]) else "") + "\n" for x in pick}
    failures = []

    def fresh(tmp):
        v = os.path.join(tmp, "vendor")
        shutil.copytree(os.path.join(VENDOR), v, ignore=lambda d, names: [n for n in names if d == VENDOR and n not in {x[0] for x in pick}])
        pin = os.path.join(tmp, "pin")
        with open(pin, "w") as f:
            f.write("# header\n" + "".join(pin_lines.values()))
        return v, pin

    def source_of(v):
        d = pick[0][0]
        for dp, _, fs in os.walk(os.path.join(v, d)):
            for fn in sorted(fs):
                if fn.endswith(".rs"):
                    return os.path.join(dp, fn)
        raise SystemExit("self-test: no .rs file in " + d)

    def pin_checksum(v, pin):
        t = open(pin).read().replace(pick[0][3], "0" * 64)
        open(pin, "w").write(t)

    def pin_drop_line(v, pin):
        t = open(pin).read().replace(pin_lines[(pick[0][1], pick[0][2])], "")
        open(pin, "w").write(t)

    def pin_unprune(v, pin):
        k = (pruned[0][1], pruned[0][2])
        open(pin, "w").write(open(pin).read().replace(pin_lines[k], pin_lines[k].replace(" pruned", "")))

    def pin_extra_line(v, pin):
        open(pin, "a").write("phantom 1.0.0 " + "1" * 64 + "\n")

    def source_edit(v, pin):
        f = source_of(v)
        os.chmod(f, os.stat(f).st_mode | stat.S_IWUSR)
        open(f, "a").write("\n// tampered\n")

    def source_delete(v, pin):
        os.remove(source_of(v))

    def file_added(v, pin):
        open(os.path.join(v, pick[0][0], "extra.rs"), "w").write("fn main() {}\n")

    def package_checksum(v, pin):
        f = os.path.join(v, pick[0][0], ".cargo-checksum.json")
        ck = json.load(open(f))
        ck["package"] = "0" * 64
        json.dump(ck, open(f, "w"))

    with tempfile.TemporaryDirectory() as tmp:
        v, pin = fresh(tmp)
        bad, _ = tree_errors(v, pin)
        if bad:
            failures.append("clean copy does not pass: " + bad[0])
    for fn in (pin_checksum, pin_drop_line, pin_unprune, pin_extra_line, source_edit, source_delete, file_added, package_checksum):
        with tempfile.TemporaryDirectory() as tmp:
            v, pin = fresh(tmp)
            fn(v, pin)
            bad, _ = tree_errors(v, pin)
            print(f"  {fn.__name__:18} {'caught' if bad else 'NOT CAUGHT'}")
            if not bad:
                failures.append(fn.__name__ + " was not caught")
    errs, _ = deny(have_deny=False)
    print(f"  {'deny_missing':18} {'caught' if errs else 'NOT CAUGHT'}")
    if not errs:
        failures.append("a missing cargo-deny passes")
    if failures:
        print("vendor self-test FAILED:\n  " + "\n  ".join(failures))
        return 1
    print("vendor self-test ok: every corruption fails the check")
    return 0


def host_test():
    """The probe's own tests on the host: the same rustls + rustcrypto code the std program runs, with the host's
    entropy and clock. The stable toolchain (the pinned nightly would build the kernel's `build-std` into a host
    test), the host triple (the root cargo config sets a bare-metal target), the vendor tree and nothing else, offline
    and locked; the target directory is under $AZOS_OUT like every build output."""
    sys.path.insert(0, os.path.dirname(os.path.join(ROOT, "tools/lib/out_dir.py")))
    from out_dir import out_root  # noqa: E402
    host = next(l.split(": ", 1)[1] for l in subprocess.run(["rustc", "+stable", "-vV"], capture_output=True, text=True, check=True).stdout.splitlines() if l.startswith("host: "))
    cmd = ["cargo", "+stable", "test", "--release", "--offline", "--locked", "--manifest-path", os.path.join(PROBE, "Cargo.toml"),
           "--target", host, "--target-dir", os.path.join(out_root(), "build", "tls-probe-host")] + VENDOR_CONFIG
    return subprocess.run(cmd, cwd=ROOT).returncode


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("regen", "check", "--self-test", "test"):
        sys.exit(__doc__)
    if sys.argv[1] == "test":
        sys.exit(host_test())
    if sys.argv[1] == "regen":
        regen()
    elif sys.argv[1] == "check":
        sys.exit(check())
    else:
        sys.exit(self_test())

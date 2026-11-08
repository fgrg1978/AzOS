#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Everything the build needs from outside the checkout: fetch it, check it, move a pin.

    fetch.py fetch [--config-only [--config FILE]] [--brain]  (BRAIN_OPTIONAL=1 in the environment adds the optional brain packages) [--dry-run]
    fetch.py check [--offline]
    fetch.py update <tree> [<tag-or-commit>]
    fetch.py self-test

`make build` never downloads. `make fetch` is the one place that does (network
here only): every pinned third-party tree (tools/build/third_party_fetch.sh), the
pinned Rust toolchain with its components, the host tools the recipes call
(Homebrew on macOS; on Linux the apt/dnf line is printed and not run), the
pinned cargo tools, the Python packages in a venv under $AZOS_OUT, the RustSec
snapshot when it is stale and the container image of `make lx-kbuild`. What is
already present is skipped; the end is a table of what was fetched, installed or
already OK. `--config-only` fetches only the trees the .config consumes.

The inventory below is data: where each item is used, its pinned version, its source
and the checksum the tree records. `self-test` fails when a script under mk/ or
tools/ downloads or calls something the inventory does not name.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import datetime

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
HOME = os.path.expanduser("~")
sys.path.insert(0, os.path.join(ROOT, "tools/lint"))
import third_party_versions as tpv  # noqa: E402  (the pin/CVE parsing is its own)

# ── trees: the .config symbol that makes a tree needed, and where the build reads it ──
# u-boot has no symbol: only the netboot gate row (tools/gate/netboot/uboot_build.sh) builds it.
TREES = {
    "busybox": ("BUSYBOX", "mk/userspace.mk"),
    "limine": ("X86_BOOT_LIMINE", "mk/qemu.mk"),
    "linux": ("LINUX_DRIVERS", "mk/userspace.mk"),
    "relibc": ("RELIBC", "mk/userspace.mk"),
    "u-boot": (None, "tools/gate/netboot/uboot_build.sh"),
}
TAG_RE = {  # which upstream tags count as a stable release of each tree
    "busybox": r"^\d+_\d+_\d+$",
    "limine": r"^v\d+\.\d+\.\d+-binary$",
    "linux": r"^v\d+\.\d+(\.\d+)?$",
    "u-boot": r"^v\d{4}\.\d{2}$",
}
REBUILD = {
    "busybox": "make busybox; the BUSYBOX.ELF digest rows (seccomp table) and the sh/busybox QEMU rows on the three ISAs",
    "limine": "the x86_pc and netboot x86 rows (make x86-pc-esp, tools/gate/netboot/row.sh)",
    "linux": "an Lbump: make lx-kbuild lx-kbuild-repro, LX_LINUX_RELEASE (module vermagic), the sparse set in third_party_fetch.sh, every validated lx module row",
    "relibc": "make relibc on the three ISAs and the relibc patch (userspace/lib/relibc-azos) against the new tree",
    "u-boot": "tools/gate/netboot/row.sh riscv64-tftp (uboot_build.sh rebuilds on a new pin)",
}

# ── the rest of the inventory ────────────────────────────────────────────────────────
# cat: build (every recipe), gate (a gate row), dev (by hand / a board), optional (asked for by a flag), manual (not fetchable here).
# pkg: brew formula, apt, dnf. provides: the commands the item gives; the scan in self-test holds
# every command the scripts call to one of them.
def pkg(brew, apt=None, dnf=None, tap=None):
    return {"brew": brew, "apt": apt or brew, "dnf": dnf or apt or brew, "tap": tap}


INVENTORY = [
    dict(id="rust-pinned", cat="build", kind="rustup", toolchain="@rust-toolchain.toml",
         used="Everything (rust-toolchain.toml); -Zbuild-std from rust-src, so no prebuilt target std",
         pinned="@rust-toolchain.toml", source="https://static.rust-lang.org (rustup)", sum="-",
         provides=["cargo", "rustc", "llvm-objcopy", "llvm-objdump", "llvm-nm", "llvm-readelf", "llvm-readobj", "llvm-strip", "llvm-size", "llvm-cov", "llvm-profdata", "llvm-tools", "llvm-ar", "rust-lld", "ld.lld"]),
    dict(id="rust-nightly", cat="build", kind="rustup", toolchain="nightly", components=["rust-src"],
         used="`cargo +nightly` of USPACE_BUILD (mk/vars.mk), the ring-3 images",
         pinned="rolling (the newest nightly; not dated)", source="https://static.rust-lang.org (rustup)", sum="-", provides=[]),
    dict(id="zig", cat="build", kind="pkg", pkg=pkg("zig"), provides=["zig"],
         used="make busybox, make relibc (C compiler and linker: tools/build/busybox_cc.sh, relibc_cc.sh)",
         pinned="the formula's current release", source="https://ziglang.org (Homebrew zig)", sum="-"),
    dict(id="qemu", cat="build", kind="pkg", pkg=pkg("qemu", "qemu-system-misc qemu-system-arm qemu-system-x86 qemu-utils", "qemu-system-riscv qemu-system-aarch64 qemu-system-x86 qemu-img"),
         provides=["qemu-system-riscv64", "qemu-system-riscv32", "qemu-system-aarch64", "qemu-system-x86_64", "qemu-img"],
         used="make qemu*, the gate's QEMU scenarios (mk/vars.mk, mk/qemu.mk); the formula also carries the edk2 and OpenSBI firmware",
         pinned="the formula's current release", source="https://www.qemu.org (Homebrew qemu)", sum="-"),
    dict(id="qemu-firmware", cat="build", kind="qemu-fw", pkg=pkg("qemu"), provides=[],
         files=["edk2-x86_64-code.fd", "edk2-i386-vars.fd", "opensbi-riscv64-generic-fw_dynamic.bin"],
         used="OVMF/edk2 for the x86 q35 UEFI boot (mk/qemu.mk OVMF_CODE/OVMF_VARS, netboot rows); OpenSBI for riscv64 -M virt",
         pinned="the one QEMU ships", source="https://www.qemu.org (in the qemu package's share directory)", sum="-"),
    dict(id="dosfstools+mtools", cat="build", kind="pkg", pkg=pkg("dosfstools mtools", "dosfstools mtools", "dosfstools mtools"),
         provides=["mkfs.fat", "mcopy", "mmd", "mformat", "mdir", "mtype", "mdel"],
         used="every FAT volume and disk image (mk/images.mk, mk/system.mk, tools/image/make_parted_disk.py); the macOS sbin must be on PATH",
         pinned="the formulas' current releases", source="https://github.com/dosfstools/dosfstools, https://www.gnu.org/software/mtools", sum="-"),
    dict(id="llvm", cat="build", kind="pkg", pkg=pkg("llvm", "clang lld", "clang lld"), provides=["clang"],
         used="LX_CC (mk/userspace.mk): the Linux-targeting clang of the lx module fixtures and the static Linux test program",
         pinned="the formula's current release", source="https://llvm.org (Homebrew llvm)", sum="-"),
    dict(id="python-build", cat="build", kind="pip", venv="build", packages=["kconfiglib", "cryptography"],
         provides=["python3", "python3.14", "python3.13", "python3.12", "python3.11"],
         used="make config and every olddefconfig (kconfiglib), the signing and image tools (cryptography); mk/kernel.mk picks the interpreter",
         pinned="latest compatible (unpinned)", source="https://pypi.org", sum="-"),
    dict(id="cbindgen", cat="build", kind="cargo", crate="cbindgen", version="0.29.2", root="~/azos-tools/cbindgen", provides=["cbindgen"],
         used="make relibc (tools/build/relibc_build.sh headers)", pinned="0.29.2 (--locked)", source="https://crates.io/crates/cbindgen", sum="crates.io lockfile (--locked)"),
    dict(id="dtc+uboot-tools", cat="gate", kind="pkg", pkg=pkg("dtc u-boot-tools", "device-tree-compiler u-boot-tools", "dtc uboot-tools"),
         provides=["dtc", "mkimage"], used="the netboot rows (tools/gate/netboot), nvme_dma_mask_row.sh, the U-Boot boot script (mk/host.mk)",
         pinned="the formulas' current releases", source="https://git.kernel.org (dtc), https://source.denx.de (U-Boot tools)", sum="-"),
    dict(id="riscv-gcc", cat="gate", kind="pkg", pkg=pkg("riscv-gnu-toolchain", "gcc-riscv64-unknown-elf", "gcc-riscv64-linux-gnu", tap="riscv-software-src/riscv"),
         provides=["riscv64-unknown-elf-gcc"], used="the S-mode U-Boot of the riscv64 netboot row (tools/gate/netboot/uboot_build.sh); no other row needs a GCC",
         pinned="the tap's current release", source="https://github.com/riscv-software-src/homebrew-riscv", sum="-"),
    dict(id="podman", cat="gate", kind="pkg", pkg=pkg("podman"), provides=["podman"],
         used="make lx-kbuild (Linux's Kbuild in a pinned container); without it the target prints SKIP",
         pinned="the formula's current release", source="https://podman.io", sum="-"),
    dict(id="lx-kbuild-image", cat="gate", kind="container",
         used="make lx-kbuild (tools/build/lx_kbuild/run.sh image builds it; IMAGE records the tag, base digest and packages)",
         pinned="@tools/build/lx_kbuild/IMAGE", source="docker.io/library/debian (digest in IMAGE), apt", sum="@tools/build/lx_kbuild/IMAGE", provides=[]),
    dict(id="cargo-deny", cat="gate", kind="cargo", crate="cargo-deny", version=None, root=None, provides=["cargo-deny"],
         used="the supply-chain check of the N0 tier, tools/lint/advisories.sh", pinned="latest (unpinned)", source="https://crates.io/crates/cargo-deny", sum="-"),
    dict(id="cargo-fuzz", cat="dev", kind="cargo", crate="cargo-fuzz", version=None, root=None, provides=["cargo-fuzz"],
         used="tools/gate/fuzz.sh", pinned="latest (unpinned)", source="https://crates.io/crates/cargo-fuzz", sum="-"),
    dict(id="advisory-db", cat="gate", kind="advisory", provides=[],
         used="tools/lint/advisories.sh check (offline, against third_party/advisory-db); refreshed here when older than its own 45-day limit",
         pinned="@third_party/advisory-db/SNAPSHOT", source="https://github.com/RustSec/advisory-db", sum="@third_party/advisory-db/SNAPSHOT"),
    dict(id="brain-python", cat="optional", kind="pip", venv="brain", requirements="../AzOSRobotBrain/requirements.lock",
         optional_requirements="../AzOSRobotBrain/requirements-optional.lock", provides=[],
         used="the AzOSRobotBrain tests and protocol sync (make ci-full); only `make fetch BRAIN=1`; a venv under $AZOS_OUT, never the system pip; "
              "BRAIN_OPTIONAL=1 adds matplotlib, Pillow, scipy, opencv-python, astropy",
         pinned="the exact versions of AzOSRobotBrain/requirements.lock", source="https://pypi.org (hashes in the lock files)", sum="sha256 per file in the lock files"),
    dict(id="pyserial", cat="dev", kind="pip", venv="build", packages=["pyserial"], provides=[],
         used="the serial console tool of tools/dev (a board's UART)", pinned="latest (unpinned)", source="https://pypi.org", sum="-"),
    dict(id="gdb-lldb", cat="dev", kind="pkg", pkg=pkg("riscv64-elf-gdb", "gdb-multiarch", "gdb"), provides=["gdb", "lldb"],
         used="make qemu debug targets, tools/gate/debug_row.py, tools/dev/stall_attach.py (lldb ships with the Xcode tools)",
         pinned="the formula's current release", source="Homebrew riscv64-elf-gdb", sum="-"),
    dict(id="serial-and-dfu", cat="dev", kind="pkg", pkg=pkg("picocom dfu-util"), provides=["picocom", "minicom", "dfu-util"],
         used="a board's console (mk/kernel.mk k1-console) and the DFU recovery script of tools/dev",
         pinned="the formulas' current releases", source="Homebrew", sum="-"),
    dict(id="vsbench-linux", cat="gate", kind="vsbench", files=["Image-riscv64", "Image-aarch64", "bzImage-x86_64"], provides=[],
         used="the Linux column of vsbench (tools/bench/vsbench_*.sh, vsbench_linux.conf): built in the lx-kbuild container from the pinned Linux tree "
              "(tools/build/lx_kbuild/run.sh vsbench, options in tools/bench/vsbench_linux_in.sh) under $AZOS_OUT/build/vsbench-linux; VSBENCH_*_LINUX_IMAGE overrides",
         pinned="the third_party/linux pin", source="third_party/linux (the tree's source URL and commit)", sum="the pinned commit"),
    dict(id="x86-ucode", cat="manual", kind="manual",
         paths=["~/azos-dl/intel-ucode", "~/azos-dl/amd-fw"],
         used="make ucode (mk/firmware.mk): the vendors' microcode files, fetched with the owner's consent",
         pinned="the vendors' current files", source="https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files, linux-firmware (amd-ucode)", sum="-", provides=[]),
]
# Commands the scripts call that every host has, or that the build creates; the scan accepts them without an inventory item.
HOST_COMMANDS = {"openssl", "cpio", "xz", "rsync", "patch", "git", "make", "python3", "bash", "sed", "awk", "tar", "curl", "hdiutil", "jq", "mke2fs"}
# A download or install verb found in mk/ or tools/ is covered by the item named here (the file it sits in) or
# by an inventory name (pip package, cargo crate, rustup component, brew formula) it installs.
VERB_FILES = {
    "tools/build/third_party_fetch.sh": "trees",
    "tools/lint/advisories.sh": "advisory-db",
    "tools/build/fetch.py": "this tool",
    "tools/build/lx_kbuild/run.sh": "lx-kbuild-image",
    "tools/build/lx_kbuild/Containerfile": "lx-kbuild-image",
    "tools/build/lx_kbuild/kbuild-in.sh": "lx-kbuild-image",
    "tools/gate/netboot/row.sh": "local",   # http:// to the QEMU host's own server
    "tools/gate/ci_check.sh": "inventory",  # its install hints are checked by name
    "mk/userspace.mk": "inventory",
}
VERB_RE = re.compile(r"(?:\bcurl\s|\bwget\s|\bgit\s+clone\b|\bgit\s+fetch\b|\bgit\s+submodule\s+update\b|\bpip3?\s+install\s+(?:--[a-z-]+\s+)*([A-Za-z0-9_.-]+)"
                     r"|\bcargo\s+install\s+(?:--[a-z-]+(?:\s+=?[0-9.]+)?\s+)*([A-Za-z0-9_-]+)|\bbrew\s+install\s+([A-Za-z0-9@._-]+)"
                     r"|\brustup\s+(?:component|target|toolchain)\s+(?:add\s+|install\s+)?([A-Za-z0-9_.-]+)|https?://[A-Za-z0-9./_:~?=&%-]+)")
CMD_RE = re.compile(r"\b(qemu-system-[a-z0-9_]+|qemu-img|mkfs\.[a-z0-9]+|m(?:copy|format|mmd|dir|del|type)|llvm-(?:objcopy|objdump|nm|readelf|readobj|strip|size|cov|profdata|ar|tools|config|mc|lipo)|cargo-(?:deny|fuzz|nextest)"
                    r"|riscv64-[a-z-]*gcc|zig|cbindgen|dtc|mkimage|podman|docker(?![.\w/-])|gdb|lldb|picocom|minicom|dfu-util|openocd|esptool\.py)\b")


VSBENCH_SUBDIR = ("build", "vsbench-linux")  # where run.sh vsbench writes, under $AZOS_OUT
BUILD_VENV = "build"  # the venv of the build tools' Python packages, under $AZOS_OUT/venv


def today():
    return datetime.date.today().isoformat()


def out_dir():
    if os.environ.get("AZOS_OUT"):
        return os.environ["AZOS_OUT"]
    return subprocess.run([sys.executable, os.path.join(ROOT, "tools/lib/out_dir.py")], capture_output=True, text=True).stdout.strip()


def extra_path():
    return os.pathsep.join([os.environ.get("PATH", ""), "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin",
                            os.path.join(HOME, ".cargo/bin"), os.path.join(HOME, "azos-tools/cbindgen/bin")])


def which(cmd):
    return shutil.which(cmd, path=extra_path())


def run(argv, dry=False, **kw):
    print("  $ " + " ".join(argv))
    if dry:
        return 0
    return subprocess.run(argv, **kw).returncode


def sh(*argv, cwd=None):
    r = subprocess.run(argv, capture_output=True, text=True, cwd=cwd, env=dict(os.environ, PATH=extra_path()))
    return r.returncode, r.stdout.strip()


def is_mac():
    return sys.platform == "darwin"


# ── .gitmodules / .config ────────────────────────────────────────────────────────────
def config_symbols(text):
    return {m.group(1) for m in re.finditer(r"^CONFIG_([A-Z0-9_]+)=y\s*$", text, re.M)}


def trees_for_config(text):
    on = config_symbols(text)
    return sorted(t for t, (sym, _) in TREES.items() if sym and sym in on)


def tree_names(root):
    return sorted(n.split("/", 1)[1] for n in tpv.submodules(root))


def manifest(root):
    return json.load(open(os.path.join(root, "third_party", "MANIFEST.json")))


def tree_entry(root, name):
    return next(t for t in manifest(root)["trees"] if t["name"] == name)


def tree_state(root, name):
    t = tree_entry(root, name)
    d = os.path.join(root, "third_party", name)
    if not os.path.exists(os.path.join(d, ".git")):
        return "missing"
    rc, head = sh("git", "-C", d, "rev-parse", "HEAD")
    return "ok" if rc == 0 and head == t["commit"] else "wrong commit"


# ── rewriting a pin ──────────────────────────────────────────────────────────────────
def version_of(tag):
    m = re.match(r"^v?(\d+(?:[._]\d+)*)", tag or "")
    return re.sub("_", ".", m.group(1)) if m else None


def rewrite_pin(root, name, tag, commit, date):
    """Move the pin of one tree in .gitmodules, the index gitlink and MANIFEST.json (no network)."""
    key = f"submodule.third_party/{name}.tag"
    gm = os.path.join(root, ".gitmodules")
    if tag:
        rc, _ = sh("git", "config", "-f", gm, key, tag)
    else:
        rc = 0 if subprocess.run(["git", "config", "-f", gm, "--unset", key], capture_output=True).returncode in (0, 5) else 1
    if rc:
        raise RuntimeError(f"cannot rewrite {key} in .gitmodules")
    rc, err = sh("git", "-C", root, "update-index", "--add", "--cacheinfo", f"160000,{commit},third_party/{name}")
    if rc:
        raise RuntimeError(f"cannot move the gitlink of {name}: {err}")
    path = os.path.join(root, "third_party", "MANIFEST.json")
    data = json.load(open(path))
    for t in data["trees"]:
        if t["name"] == name:
            t.update(tag=tag, version=version_of(tag), commit=commit, pinned=date)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def ls_remote(url, *refs):
    opts = [r for r in refs if r.startswith("--")]
    rc, out = sh("git", "ls-remote", *opts, url, *[r for r in refs if not r.startswith("--")])
    return out.splitlines() if rc == 0 else None


def latest_release(name, url):
    """(tag, commit) of the newest stable tag, or (None, head commit) for a commit-pinned tree; None when unreachable."""
    if name not in TAG_RE:
        lines = ls_remote(url, "HEAD")
        return None if lines is None else (None, lines[0].split()[0] if lines else None)
    lines = ls_remote(url, "--tags", "--refs")
    if lines is None:
        return None
    best = None
    for ln in lines:
        sha, _, ref = ln.partition("\t")
        tag = ref.replace("refs/tags/", "")
        if re.match(TAG_RE[name], tag) and (best is None or tpv.vkey(tag) > tpv.vkey(best[0])):
            best = (tag, sha)
    return best


def resolve_tag(url, tag):
    lines = ls_remote(url, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
    if not lines:
        return None
    peeled = [ln.split()[0] for ln in lines if ln.endswith("^{}")]
    return (peeled or [lines[0].split()[0]])[0]


def cmd_update(root, name, target):
    if name not in TREES:
        if os.path.isdir(os.path.join(root, "third_party", "vendor", name)):
            print(f"fetch-update: {name} is a vendored crate: this tool moves tree pins only. Crates move with Cargo.lock "
                  f"and `python3 userspace/lib/tls-probe/vendor.py regen` (it regenerates the tree to the lockfiles; it has no per-crate bump).")
            return 2
        print(f"fetch-update: unknown tree {name!r}; trees: {' '.join(sorted(TREES))}")
        return 2
    t = tree_entry(root, name)
    url = t["upstream"]
    if name in TAG_RE:
        tag = target or (latest_release(name, url) or (None, None))[0]
        if not tag:
            print(f"fetch-update: no tag given and {url} is unreachable or has no stable tag")
            return 1
        commit = resolve_tag(url, tag)
        if not commit:
            print(f"fetch-update: {url} has no tag {tag}")
            return 1
    else:
        tag = None
        commit = target or (latest_release(name, url) or (None, None))[1]
        if not commit or not re.match(r"^[0-9a-f]{40}$", commit):
            print(f"fetch-update: {name} is a commit pin: give the full 40-hex commit, or reach {url} for its HEAD")
            return 1
    if (tag, commit) == (t["tag"], t["commit"]):
        print(f"fetch-update: {name} is already at {tag or commit}")
        return 0
    old = t["tag"] or t["commit"]
    rewrite_pin(root, name, tag, commit, today())
    print(f"fetch-update: {name}: {old} -> {tag or commit} ({commit})")
    rc = subprocess.run(["bash", os.path.join(root, "tools/build/third_party_fetch.sh"), name]).returncode
    if rc:
        print("fetch-update: the fetch failed; the pin files are already rewritten (git diff shows them)")
        return rc
    errs = tpv.run(root, os.path.join(root, "third_party", "known_cves.tsv"), quiet=True)
    for e in errs:
        print(f"[PIN] {e}")
    print("\nchanged, not committed (review with git diff):")
    subprocess.run(["git", "-C", root, "diff", "--stat", "--", ".gitmodules", "third_party/MANIFEST.json"])
    print(f"  gitlink third_party/{name}: {t['commit'][:12]} -> {commit[:12]} (git diff --cached --stat third_party/{name})")
    print(f"rebuild/test: {REBUILD[name]}")
    if t["tag"]:
        rc, refs = sh("git", "-C", root, "grep", "-n", "-F", t["tag"], "--", ".", ":!third_party", ":!.gitmodules")
        if refs:
            print(f"other places that still name {t['tag']} (check them):")
            print("\n".join("  " + ln for ln in refs.splitlines()[:12]))
    return 1 if errs else 0


# ── status of every inventory item ───────────────────────────────────────────────────
def toolchain_spec(root):
    text = open(os.path.join(root, "rust-toolchain.toml")).read()
    chan = re.search(r'^channel\s*=\s*"([^"]+)"', text, re.M).group(1)
    comps = re.search(r"^components\s*=\s*\[([^\]]*)\]", text, re.M)
    return chan, re.findall(r'"([^"]+)"', comps.group(1)) if comps else []


def qemu_dirs():
    rc, out = sh("qemu-system-x86_64", "-L", "help")
    return [d for d in out.splitlines() if os.path.isdir(d)] if rc == 0 else []


def venv_dir(it):
    return os.path.join(out_dir(), "venv", it["venv"])


def build_python_ok():
    for p in ("python3.14", "python3.13", "python3.12", "python3.11", "python3"):
        exe = which(p)
        if exe and subprocess.run([exe, "-c", "import kconfiglib, tomllib, cryptography"], capture_output=True).returncode == 0:
            return exe
    v = os.path.join(out_dir(), "venv", BUILD_VENV, "bin", "python")
    if os.path.exists(v) and subprocess.run([v, "-c", "import kconfiglib, tomllib, cryptography"], capture_output=True).returncode == 0:
        return v
    return None


def brain_locks(root, it, with_optional):
    keys = ["requirements"] + (["optional_requirements"] if with_optional else [])
    sibling = os.environ.get("BRAIN_DIR")
    paths = [it[k] if not sibling else os.path.join(sibling, os.path.basename(it[k])) for k in keys]
    return [os.path.normpath(os.path.join(root, p)) for p in paths]


def brain_stamp(locks):
    return "".join(f"== {os.path.basename(p)}\n{open(p).read()}" for p in locks)


def status(root, it):
    k = it["kind"]
    if k == "rustup":
        chan, comps = toolchain_spec(root)
        tc = chan if it["toolchain"].startswith("@") else it["toolchain"]
        comps = comps if it["toolchain"].startswith("@") else it["components"]
        rc, out = sh("rustup", "component", "list", "--installed", "--toolchain", tc)
        if rc:
            return "missing"
        absent = [c for c in comps if not any(ln.startswith(c.replace("-preview", "")) for ln in out.splitlines())]
        return "ok" if not absent else "missing " + ",".join(absent)
    if k == "pkg":
        gone = [c for c in it["provides"] if not which(c) and c not in ("lldb", "minicom", "mformat", "mdir", "mtype", "mdel", "python3")]
        return "ok" if not gone else "missing " + ",".join(gone)
    if k == "qemu-fw":
        dirs = qemu_dirs()
        gone = [f for f in it["files"] if not any(os.path.exists(os.path.join(d, f)) for d in dirs)]
        return "ok" if not gone else "missing " + ",".join(gone)
    if k == "cargo":
        exe = which(it["provides"][0])
        if not exe:
            return "missing"
        if it["version"]:
            rc, out = sh(exe, "--version")
            return "ok" if it["version"] in out else f"wrong version ({out})"
        return "ok"
    if k == "pip":
        if "requirements" in it:
            locks = brain_locks(root, it, os.environ.get("BRAIN_OPTIONAL") == "1")
            if not all(os.path.exists(p) for p in locks):
                return "absent (no sibling AzOSRobotBrain checkout with its lock files)"
            stamp = os.path.join(venv_dir(it), ".requirements")
            return "ok" if os.path.exists(stamp) and open(stamp).read() == brain_stamp(locks) else "missing"
        if it["venv"] == "build" and it["id"] == "python-build":
            return "ok" if build_python_ok() else "missing"
        py = os.path.join(venv_dir(it), "bin", "python")
        mods = [p.replace("-", "_") for p in it["packages"]]
        for exe in (py, which("python3")):
            if exe and os.path.exists(exe) and subprocess.run([exe, "-c", "import " + ",".join(m if m != "pyserial" else "serial" for m in mods)], capture_output=True).returncode == 0:
                return "ok"
        return "missing"
    if k == "advisory":
        snap = os.path.join(root, "third_party/advisory-db/SNAPSHOT")
        if not os.path.exists(snap):
            return "missing"
        m = re.search(r"^date = (\d{4}-\d{2}-\d{2})", open(snap).read(), re.M)
        age = (datetime.date.today() - datetime.date.fromisoformat(m.group(1))).days if m else 999
        return "ok" if age <= 45 else f"stale ({age} days)"
    if k == "container":
        if not which("podman"):
            return "needs podman"
        tag = re.search(r"^tag=(.*)$", open(os.path.join(root, "tools/build/lx_kbuild/IMAGE")).read(), re.M).group(1)
        rc, _ = sh("podman", "image", "exists", tag)
        return "ok" if rc == 0 else "missing"
    if k == "vsbench":
        d = os.path.join(out_dir(), *VSBENCH_SUBDIR)
        gone = [f for f in it["files"] if not os.path.exists(os.path.join(d, f))]
        return "ok" if not gone else "missing " + ",".join(gone)
    if k == "manual":
        gone = [p for p in it["paths"] if not os.path.exists(os.path.expanduser(p))]
        return "ok" if not gone else "absent (not fetchable here)"
    return "?"


def pinned_text(root, it):
    if it["kind"] == "rustup" and it["toolchain"].startswith("@"):
        chan, comps = toolchain_spec(root)
        return f"{chan} + {', '.join(comps)}"
    p = it["pinned"]
    if p.startswith("@"):
        f = os.path.join(root, p[1:])
        if f.endswith("SNAPSHOT") and os.path.exists(f):
            return "snapshot of " + re.search(r"^date = (\S+)", open(f).read(), re.M).group(1)
        first = [ln for ln in open(f).read().splitlines() if ln.strip() and not ln.startswith("#")] if os.path.exists(f) else []
        return first[0] if first else "-"
    return p


def pkg_manager_line(missing_items):
    """The install command for the host, per item list; (argv or None, text)."""
    names = []
    taps = []
    for it in missing_items:
        key = "brew" if is_mac() else ("apt" if shutil.which("apt-get") else "dnf")
        names += it["pkg"][key].split()
        if it["pkg"]["tap"]:
            taps.append(it["pkg"]["tap"])
    names = list(dict.fromkeys(names))
    if is_mac():
        return taps, ["brew", "install", *names]
    if shutil.which("apt-get"):
        return taps, ["sudo", "apt-get", "install", *names]
    return taps, ["sudo", "dnf", "install", *names]


# ── fetch ────────────────────────────────────────────────────────────────────────────
def cmd_fetch(root, config_only, config_file, dry, brain=False):
    rows = []  # (item, result)

    def note(name, res):
        rows.append((name, res))

    if config_only:
        if not os.path.exists(os.path.join(root, config_file)):
            print(f"fetch: no {config_file}: run `make defconfig` (or make config) first, or fetch everything with `make fetch`")
            return 1
        text = open(os.path.join(root, config_file)).read()
        wanted = trees_for_config(text)
        print(f"fetch: {config_file} needs: {' '.join(wanted) or 'no third-party tree'}")
    else:
        wanted = tree_names(root)
    for name in wanted:
        t = tree_entry(root, name)
        label = f"tree {name} {t['tag'] or t['commit'][:12]}"
        if tree_state(root, name) == "ok":
            note(label, "already OK")
            continue
        rc = run(["bash", os.path.join(root, "tools/build/third_party_fetch.sh"), name], dry)
        note(label, "FAILED" if rc else ("would fetch" if dry else "fetched"))
    if not config_only:
        todo_pkg = []
        for it in INVENTORY:
            if it["cat"] == "optional" and brain:
                note(it["id"], install(root, it, dry) if status(root, it) != "ok" else "already OK")
                continue
            if it["cat"] in ("dev", "optional") and it["kind"] != "manual":
                st = status(root, it)
                note(f"{it['id']} ({it['cat']})", "already OK" if st == "ok" else f"{st}; optional, not installed" + (" (make fetch BRAIN=1)" if it["cat"] == "optional" else ""))
                continue
            st = status(root, it)
            if it["kind"] == "manual":
                note(it["id"], "already OK" if st == "ok" else st)
            elif st == "ok":
                note(it["id"], "already OK")
            elif it["kind"] in ("pkg", "qemu-fw"):
                todo_pkg.append(it)
            else:
                note(it["id"], install(root, it, dry))
        if todo_pkg:
            taps, argv = pkg_manager_line(todo_pkg)
            print("host tools missing: " + " ".join(i["id"] for i in todo_pkg))
            if is_mac():
                res = "installed"
                for tap in dict.fromkeys(taps):
                    if run(["brew", "tap", tap], dry):
                        res = "FAILED"
                if res != "FAILED" and run(argv, dry):
                    res = "FAILED"
                for it in todo_pkg:
                    note(it["id"], "would install" if dry else res)
            else:
                print("  run (not run here): " + " ".join(argv))
                for it in todo_pkg:
                    note(it["id"], "printed the line, not run")
    w = max(len(r[0]) for r in rows)
    print("\nfetch summary:")
    for n, r in rows:
        print(f"  {n:<{w}}  {r}")
    return 1 if any(r == "FAILED" for _, r in rows) else 0


def install(root, it, dry):
    k = it["kind"]
    if k == "rustup":
        chan, comps = toolchain_spec(root)
        tc = chan if it["toolchain"].startswith("@") else it["toolchain"]
        comps = comps if it["toolchain"].startswith("@") else it["components"]
        argv = ["rustup", "toolchain", "install", tc, "--profile", "minimal"]
        for c in comps:
            argv += ["-c", c]
        rc = run(argv, dry)
    elif k == "cargo":
        argv = ["cargo", "install", it["crate"], "--locked"]
        if it["version"]:
            argv += ["--version", "=" + it["version"]]
        if it["root"]:
            argv += ["--root", os.path.expanduser(it["root"])]
        rc = run(argv, dry)
    elif k == "pip":
        rc = install_pip(root, it, dry)
    elif k == "advisory":
        rc = run(["bash", os.path.join(root, "tools/lint/advisories.sh"), "update"], dry)
    elif k == "vsbench":
        rc = run(["bash", os.path.join(root, "tools/build/lx_kbuild/run.sh"), "vsbench"], dry)
    elif k == "container":
        rc = run(["bash", os.path.join(root, "tools/build/lx_kbuild/run.sh"), "image"], dry) if which("podman") else 0
        if not which("podman"):
            return "skipped (needs podman)"
    else:
        rc = 1
    return "FAILED" if rc else ("would install" if dry else "installed")


def install_pip(root, it, dry):
    v = venv_dir(it)
    if "requirements" in it:
        locks = brain_locks(root, it, os.environ.get("BRAIN_OPTIONAL") == "1")
        gone = [p for p in locks if not os.path.exists(p)]
        if gone:
            print(f"  {gone[0]} is absent (the sibling AzOSRobotBrain checkout and its lock files): skipped")
            return 1
        pkgs = ["--require-hashes"] + [a for p in locks for a in ("-r", p)]
    else:
        pkgs = it["packages"]
    py = next((which(p) for p in ("python3.14", "python3.13", "python3.12", "python3.11") if which(p)), None) or which("python3")
    if run([py, "-m", "venv", v], dry or os.path.exists(os.path.join(v, "bin", "python"))):
        return 1
    rc = run([os.path.join(v, "bin", "python"), "-m", "pip", "install", *pkgs], dry)
    if rc == 0 and not dry and "requirements" in it:
        open(os.path.join(v, ".requirements"), "w").write(brain_stamp(brain_locks(root, it, os.environ.get("BRAIN_OPTIONAL") == "1")))
    if rc == 0 and it["id"] == "python-build":
        print(f"  make finds {v}/bin/python by itself (mk/kernel.mk), or pass PYTHON=<it>")
    return rc


# ── check ────────────────────────────────────────────────────────────────────────────
def cmd_check(root, offline):
    man = manifest(root)
    vendor, _ = tpv.parse_vendor_pin(os.path.join(root, "third_party", "VENDOR_PIN"))
    cves, _ = tpv.parse_cves(os.path.join(root, "third_party", "known_cves.tsv"))
    cve_hits = tpv.report(root, man, vendor, cves, quiet=True)
    print("third-party pins (latest = newest stable upstream tag; git ls-remote --tags, read-only):")
    print(f"  {'tree':<8} {'pinned':<16} {'checkout':<13} {'latest upstream':<18} {'CVEs':<5} update")
    updates = 0
    for t in man["trees"]:
        n = t["name"]
        pinned = t["tag"] or t["commit"][:12]
        ncve = sum(1 for h in cve_hits if h.startswith(n + " "))
        if offline:
            lat, upd = "(offline)", "?"
        else:
            r = latest_release(n, t["upstream"])
            if r is None:
                lat, upd = "(unreachable)", "?"
            elif n not in TAG_RE:
                lat = (r[1] or "?")[:12] + " HEAD"
                upd = "yes" if r[1] and r[1] != t["commit"] else "no"
            else:
                lat = r[0]
                upd = "yes" if r[0] and tpv.vkey(r[0]) > tpv.vkey(t["tag"]) else "no"
        updates += upd == "yes"
        print(f"  {n:<8} {pinned:<16} {tree_state(root, n):<13} {lat:<18} {ncve:<5} {upd}")
    for h in cve_hits:
        print(f"  CVE {h}")
    print(f"\nvendored crates: {len(vendor)} (third_party/VENDOR_PIN). A newer-version report needs the network and cargo; "
          f"`make advisories` (offline) reports the known advisories, `fetch-update` does not move crates.")
    rc, adv = sh("bash", os.path.join(root, "tools/lint/advisories.sh"), "check")
    print("RustSec advisories for the lockfiles (tools/lint/advisories.sh check, offline):")
    print("\n".join("  " + ln for ln in adv.splitlines()[-4:]) or "  (no output)")
    print("\nexternal inventory (cat: build = every recipe, gate = a gate row, dev = by hand, manual = not fetchable):")
    print(f"  {'item':<18} {'cat':<7} {'state':<30} pinned / source")
    for it in sorted(INVENTORY, key=lambda i: i["cat"] == "optional"):
        if it["cat"] == "optional" and it is next(i for i in INVENTORY if i["cat"] == "optional"):
            print("\noptional (not part of `make fetch`):")
        print(f"  {it['id']:<18} {it['cat']:<7} {status(root, it):<30} {pinned_text(root, it)}  <{it['source']}>"
              + (f"  sum: {pinned_sum(root, it)}" if it["sum"] != "-" else ""))
        print(f"  {'':<18} used: {it['used']}")
    print("\nnothing was changed.")
    return 0


def pinned_sum(root, it):
    s = it["sum"]
    if not s.startswith("@"):
        return s
    f = os.path.join(root, s[1:])
    if not os.path.exists(f):
        return "-"
    text = open(f).read()
    m = re.search(r"^base=(.*)$", text, re.M) or re.search(r"^commit = (.*)$", text, re.M)
    return m.group(1) if m else "-"


# ── self-test ────────────────────────────────────────────────────────────────────────
def scan_files(root):
    for top in ("mk", "tools"):
        for dp, dn, fn in os.walk(os.path.join(root, top)):
            dn[:] = [d for d in dn if d not in ("target", "__pycache__", "azos_sim", "vendor")]
            for f in fn:
                if f.endswith((".sh", ".py", ".mk", ".txt", ".conf")) or f in ("Containerfile",):
                    yield os.path.join(dp, f)


def inventory_words():
    names = {it["id"] for it in INVENTORY}
    cmds = {c for it in INVENTORY for c in it["provides"]}
    pips = {p for it in INVENTORY if it["kind"] == "pip" for p in it.get("packages", [])} | {"kconfiglib", "cryptography", "pyserial"}
    crates = {it["crate"] for it in INVENTORY if it["kind"] == "cargo"}
    brews = {n for it in INVENTORY if it["kind"] == "pkg" for n in it["pkg"]["brew"].split()}
    comps = {c for it in INVENTORY if it["kind"] == "rustup" for c in it.get("components", [])} | {"rust-src", "llvm-tools", "llvm-tools-preview", "rust-lld"}
    return names, cmds, pips, crates, brews, comps


def scan_findings(root, files=None):
    names, cmds, pips, crates, brews, comps = inventory_words()
    findings = []
    for path in (files if files is not None else scan_files(root)):
        rel = os.path.relpath(path, root)
        if rel == "tools/build/fetch.py":
            continue
        try:
            lines = open(path, errors="replace").read().splitlines()
        except OSError:
            continue
        for n, ln in enumerate(lines, 1):
            for m in VERB_RE.finditer(ln):
                hit = m.group(0).strip()
                if hit.startswith("http"):
                    if rel in VERB_FILES or re.search(r"(apache\.org|gnu\.org|spdx|azos\.invalid|10\.0\.2\.2|crates\.io-index|github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$)", hit):
                        continue
                    if any(it["source"].find(hit.split("/")[2]) >= 0 for it in INVENTORY):
                        continue
                    if rel.startswith("tools/lint/") or rel.endswith(".txt"):
                        continue
                    findings.append(f"{rel}:{n}: URL not in the inventory: {hit}")
                    continue
                pip, crate, brew, comp = m.group(1), m.group(2), m.group(3), m.group(4)
                if pip and pip not in pips:
                    findings.append(f"{rel}:{n}: pip package {pip} not in the inventory")
                elif crate and crate not in crates:
                    findings.append(f"{rel}:{n}: cargo crate {crate} not in the inventory")
                elif brew and brew not in brews:
                    findings.append(f"{rel}:{n}: brew formula {brew} not in the inventory")
                elif comp and not (comp in comps or comp in ("add", "install", "is", "list")):
                    findings.append(f"{rel}:{n}: rustup item {comp} not in the inventory")
                elif not (pip or crate or brew or comp) and rel not in VERB_FILES:
                    findings.append(f"{rel}:{n}: downloads ({hit}) and the file is not in VERB_FILES")
            if rel.startswith(("mk/", "tools/build/", "tools/gate/", "tools/image/", "tools/bench/")) and not ln.lstrip().startswith("#") and rel != "tools/build/fetch.py":
                for m in CMD_RE.finditer(ln):
                    c = m.group(1)
                    if c in cmds or c in HOST_COMMANDS or c.startswith(("llvm-", "qemu-system-")) and c in cmds:
                        continue
                    findings.append(f"{rel}:{n}: calls {c}, which no inventory item provides")
    return findings


def self_test():
    root = ROOT
    # 1. config -> trees, and the table names the trees of .gitmodules and where each is read
    assert tree_names(root) == sorted(TREES), (tree_names(root), sorted(TREES))
    for t, (sym, consumer) in TREES.items():
        src = open(os.path.join(root, consumer)).read()
        assert f"third_party/{t}" in src or f"third_party/{t.replace('-', '_')}" in src or t in src, f"{consumer} does not read {t}"
        if sym:
            kc = "".join(open(os.path.join(dp, f)).read() for dp, _, fs in os.walk(os.path.join(root, "config")) for f in fs if f.startswith("Kconfig"))
            assert re.search(rf"^\s*config {sym}\b", kc, re.M), f"no Kconfig symbol {sym}"
    cases = {"": [], "CONFIG_BUSYBOX=y\n": ["busybox"], "# CONFIG_BUSYBOX is not set\nCONFIG_RELIBC=y\n": ["relibc"],
             "CONFIG_X86_BOOT_LIMINE=y\nCONFIG_LINUX_DRIVERS=y\n": ["limine", "linux"],
             "CONFIG_BUSYBOX=m\nCONFIG_RELIBC=n\n": []}
    for text, want in cases.items():
        assert trees_for_config(text) == want, (text, trees_for_config(text), want)
    # canary: a table that maps a tree to the wrong symbol is caught by the cases
    saved = TREES["busybox"]
    TREES["busybox"] = ("RELIBC", saved[1])
    assert trees_for_config("CONFIG_BUSYBOX=y\n") != ["busybox"], "canary: the mapping test does not discriminate"
    TREES["busybox"] = saved
    # 2. rewriting a pin on a temp copy, no network
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "third_party"))
        shutil.copy(os.path.join(root, ".gitmodules"), d)
        shutil.copy(os.path.join(root, "third_party/MANIFEST.json"), os.path.join(d, "third_party"))
        open(os.path.join(d, "third_party/VENDOR_PIN"), "w").write("")
        subprocess.run(["git", "init", "-q", d], check=True)
        for t in manifest(d)["trees"]:
            subprocess.run(["git", "-C", d, "update-index", "--add", "--cacheinfo", f"160000,{t['commit']},third_party/{t['name']}"], check=True)
        assert tpv.check_manifest(d, manifest(d)) == [], tpv.check_manifest(d, manifest(d))
        before = open(os.path.join(d, "third_party/MANIFEST.json")).read()
        new = "ab" * 20
        rewrite_pin(d, "busybox", "1_37_0", new, "2030-01-02")
        errs = tpv.check_manifest(d, manifest(d))
        assert errs == [], errs
        t = tree_entry(d, "busybox")
        assert (t["tag"], t["version"], t["commit"], t["pinned"]) == ("1_37_0", "1.37.0", new, "2030-01-02"), t
        assert tpv.gitlinks(d)["third_party/busybox"] == new
        assert tpv.submodules(d)["third_party/busybox"]["tag"] == "1_37_0"
        assert open(os.path.join(d, "third_party/MANIFEST.json")).read().count("\n") == before.count("\n")
        rewrite_pin(d, "relibc", None, new, "2030-01-02")  # a commit pin: no tag, version null
        assert tpv.check_manifest(d, manifest(d)) == []
        assert tree_entry(d, "relibc")["version"] is None and "tag" not in tpv.submodules(d)["third_party/relibc"]
        # canary: a rewrite that leaves the gitlink behind is flagged by the same check
        subprocess.run(["git", "-C", d, "update-index", "--add", "--cacheinfo", f"160000,{'cd' * 20},third_party/busybox"], check=True)
        assert tpv.check_manifest(d, manifest(d)), "canary: the rewrite check does not discriminate"
        # canary: a rewrite that leaves the .gitmodules tag behind
        rewrite_pin(d, "limine", "v10.9.0-binary", new, "2030-01-02")
        subprocess.run(["git", "config", "-f", os.path.join(d, ".gitmodules"), "submodule.third_party/limine.tag", "v1.0.0-binary"], check=True)
        assert tpv.check_manifest(d, manifest(d)), "canary: a stale .gitmodules tag is not caught"
    assert version_of("1_36_1") == "1.36.1" and version_of("v10.8.5-binary") == "10.8.5" and version_of("v2025.07") == "2025.07"
    # 3. the inventory covers every download and every tool the scripts call
    found = scan_findings(root)
    assert not found, "not in the inventory:\n  " + "\n  ".join(found)
    with tempfile.TemporaryDirectory() as d:
        for text in ("curl -O https://example.org/x.tar\n", "pip install notinlist\n", "cargo install notacrate --locked\n",
                     "brew install notaformula\n", "git clone u d\n"):
            p = os.path.join(d, "mk.sh")
            open(p, "w").write(text)
            assert scan_findings(root, [p]), f"canary: the scan missed {text!r}"
        p = os.path.join(d, "mk.sh")
        open(p, "w").write("qemu-system-sparc64 -M x\n")
        os.makedirs(os.path.join(d, "mk"))
        q = os.path.join(d, "mk", "a.mk")
        open(q, "w").write("\tqemu-system-sparc64 -M x\n")
        assert scan_findings(d, [q]), "canary: a tool no item provides is not caught"
    # 4. the vsbench conf names exactly the images the inventory builds, under the output root
    vs = next(it for it in INVENTORY if it["kind"] == "vsbench")
    for isa in ("riscv64", "aarch64", "x86_64"):
        r = subprocess.run(["sh", os.path.join(root, "tools/bench/vsbench_linux_image.sh"), isa], capture_output=True, text=True,
                           env=dict(os.environ, AZOS_OUT="/o"))
        assert r.stdout.strip().startswith("/o/build/vsbench-linux/") and os.path.basename(r.stdout.strip()) in vs["files"], (isa, r.stdout)
    vs["files"].append("extra")  # canary: an image the conf does not name must not be accepted as the full set
    assert {os.path.basename(subprocess.run(["sh", os.path.join(root, "tools/bench/vsbench_linux_image.sh"), i], capture_output=True, text=True,
            env=dict(os.environ, AZOS_OUT="/o")).stdout.strip()) for i in ("riscv64", "aarch64", "x86_64")} != set(vs["files"]), "canary"
    vs["files"].pop()
    assert len({it["id"] for it in INVENTORY}) == len(INVENTORY)
    print("fetch self-test ok")
    return 0


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "self-test":
        return self_test()
    if cmd == "fetch":
        cfg = rest[rest.index("--config") + 1] if "--config" in rest else ".config"
        return cmd_fetch(ROOT, "--config-only" in rest, cfg, "--dry-run" in rest, "--brain" in rest)
    if cmd == "check":
        return cmd_check(ROOT, "--offline" in rest)
    if cmd == "update":
        if not rest:
            print("usage: fetch.py update <tree> [<tag-or-commit>]   (make fetch-update NAME=<tree> [VERSION=<tag>])")
            return 2
        return cmd_update(ROOT, rest[0], rest[1] if len(rest) > 1 else None)
    print(f"fetch.py: unknown command {cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

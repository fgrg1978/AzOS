#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Licence lint for the Linux driver layer (gate rows `lx: ...`).

The project is "Apache-2.0 OR GPL-2.0-only", and so is our own Rust in the
Linux layer (`lx/emul`, no Linux header; owner decision, round 47). The glue
that includes Linux headers (`lx/glue/`) and the pinned Linux tree
(`third_party/linux/`) are GPL-2.0-only. The rule this keeps: **no GPL-only
source, symbol or object outside `lx/glue/` and `third_party/`**, so nothing
GPL-only reaches the kernel or any image by accident.

    python3 tools/lint/lx_license_lint.py              # tree + build artefacts
    python3 tools/lint/lx_license_lint.py --pin        # every third_party/ gitlink == its checkout
    python3 tools/lint/lx_license_lint.py --self-test  # canary: every rule bites
    python3 tools/lint/lx_license_lint.py --ko DIR     # the Kbuild .ko set (L1)
    python3 tools/lint/lx_license_lint.py --ko DIR --self-test  # its canary

Tree rules (over `git ls-files`, so build output and untracked files are not
judged):

  T1  every SPDX line under lx/glue/ says exactly GPL-2.0-only, and every source
      file there (.rs .c .h .S .toml .py .sh) has one;
  T2  outside lx/glue/ and third_party/ (lx/emul included), every SPDX
      expression offers Apache-2.0
      (a GPL-only file there would make its crate GPL-only);
  T3  outside lx/glue/ and third_party/, no C/assembly source includes a Linux
      kernel header (`<linux/...>`, `<asm/...>`, `<asm-generic/...>`): a file
      compiled against Linux headers is GPL-2.0-only;
  T4  no Cargo.toml outside lx/glue/ depends on a path inside lx/glue/ (a dual-licensed
      crate linking a GPL one);
  T5  `third_party/linux` is named only by the files allowed to: the
      submodule record, this lint, the Kconfig help, the Kbuild runner and the
      device-id table that reads the tree as data (`tools/build/lx_device_table.py`
      and its list, `lx/DEVICE_SOURCES`).

  T6  MIT is accepted in exactly one place: userspace/lib/relibc-azos/patches/,
      the patch against relibc (Redox's libc, MIT, pinned in
      as third_party/relibc). A patch file carries lines of the MIT tree it
      patches, so it is MIT (every SPDX line there says exactly `MIT`, and
      every file has one); an MIT line anywhere else fails T2. The overlay
      beside it (our own platform code) stays Apache-2.0 OR GPL-2.0-only.

Artefact rules (over what is built; missing files are skipped, an empty set
is a failure so the row cannot pass by finding nothing):

  A1  no symbol of the GPL glue (`lx_glue`, Rust-mangled `7lx_glue`) in a
      kernel ELF, a userspace ELF ($AZOS_OUT/build/*.elf, $AZOS_OUT/build/aarch64/*.elf) or a
      module ($AZOS_OUT/build/lx/*.ko);
  A2  every module under $AZOS_OUT/build/lx/ carries this project's own licence tag
      (`Dual Apache/GPL`): until stage L1's sign-off no Linux module is built.

Module rules (`--ko DIR`, DIR = `make lx-kbuild`'s output: <isa>/*.ko for
riscv64, aarch64 and x86_64). The load order is lxbase.ko (the base,
lx/glue) and then every other module:

  K1  every .ko carries a GPL-compatible `license` (the Linux loader's list)
      and `vermagic` = "<the Linux tree's tag, no v> SMP preempt <riscv|aarch64|nothing>";
  K2  lxbase.ko imports only the host ABI (lx/HOST_ABI): no Linux symbol is
      expected from the server;
  K3  every other module imports only the host ABI and symbols EXPORTED
      (`__ksymtab`) by modules earlier in the order: the RFC 6.3 "nm -u"
      gate, so an unimplemented Linux symbol fails the build, not the boot;
  K4  no image (kernel ELFs, $AZOS_OUT/build/*.elf, $AZOS_OUT/build/aarch64/*.elf) has a symbol
      named like one a .ko defines: the GPL code lives in the .ko only;

The filesystem set (<isa>/fs/*.ko: crc16, mbcache, jbd2, ext4) is
held to K1 and K4. Its imports are not K3-gated, because the slice that
provides most of them does not exist yet: lx/FS_EXT4_UNRESOLVED records what
is missing and tests/host/lx-loader-tests fails when the built set differs.
  K0  an empty .ko set, or an empty image set, is a failure.

Pin rules (`--pin`), over every third-party tree (.gitmodules; the gitlink in
the index is the pin, tools/build/third_party_fetch.sh checks it out):
  P0  each entry lives under third_party/ at its own name, has a url, and is
      `shallow = true` and `update = none`; the Linux tree has a `tag`;
  P1  each entry has a gitlink in the index, and each gitlink an entry;
  P2  a checked-out tree's HEAD is its gitlink (an absent checkout is a note,
      or a failure with `--require-checkout`);
  P3  a checked-out tree has no local change (zero patches);
  P5  a checked-out tree with a `tag` has that tag, and it peels to the gitlink.
(No P4: the Linux tag is recorded in .gitmodules alone, with no Kconfig copy.)
relibc (MIT, the one MIT tree): its checkout's LICENSE is the MIT text (R2),
LICENSES/MIT.txt exists (R3) and NOTICE names relibc (R4).
"""

import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
ROOT = azos_tools.ROOT
from out_dir import out_root  # noqa: E402

# Built artefacts live under the output root, never in the checkout; the
# `BUILD`/`TARGET` names are the subdirectories of that root.
OUT = out_root()
BUILD = "build"
TARGET = "target"
GPL_ONLY_DIRS = ("lx/glue/", "third_party/")
MIT_DIRS = ("userspace/lib/relibc-azos/patches/",)
SOURCE_EXT = (".rs", ".c", ".h", ".S", ".s", ".toml", ".py", ".sh")
C_EXT = (".c", ".h", ".S", ".s", ".cc", ".cpp")
# A header line: a comment leader, then the tag. Only the first lines of a
# file are a header (REUSE convention); a later match is text ABOUT a tag
# (this file's own self-test fixtures), not the file's licence.
SPDX_RE = re.compile(r"^\s*(?://!?|#|/\*|\*|--|;|<!--)\s*SPDX-License-Identifier:\s*([^\n*]*?)\s*(?:\*/|-->)?\s*$", re.M)
HEADER_LINES = 12
LINUX_INC_RE = re.compile(r'^\s*#\s*include\s*[<"](linux|asm|asm-generic|uapi)/', re.M)
LX_DEP_RE = re.compile(r'path\s*=\s*"[^"]*(?:^|/)lx/glue(?:/|")')
T5_ALLOWED = {
    ".gitmodules",
    "tools/lint/lx_license_lint.py",
    "config/axes/Kconfig.personality",
    "tools/build/lx_kbuild/run.sh",
    "tools/build/lx_device_table.py",
    "lx/DEVICE_SOURCES",
}
LX_SYMBOL_RE = re.compile(rb"lx_glue|7lx_glue")
OUR_MODULE_TAG = b"Dual Apache/GPL"


def tracked(root):
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p]


def read(root, rel):
    try:
        with open(os.path.join(root, rel), "rb") as f:
            return f.read()
    except OSError:
        return b""


def check_tree(root, files):
    errs = []
    for rel in files:
        in_gpl = rel.startswith(GPL_ONLY_DIRS)
        if rel.startswith("third_party/"):
            continue  # Linux's own files (the gitlink); its licence is Linux's
        if rel.startswith("LICENSES/") or rel in ("LICENSE", "NOTICE", "REUSE.toml"):
            continue  # licence texts and the REUSE map name every licence
        data = read(root, rel)
        if b"\0" in data[:4096]:
            continue  # binary
        text = data.decode("utf-8", "replace")
        head = "\n".join(text.splitlines()[:HEADER_LINES])
        ids = [m.group(1).strip().strip('"') for m in SPDX_RE.finditer(head)]
        # The SPDX tool's own template line is not an identifier.
        ids = [i for i in ids if "{" not in i]
        if in_gpl:
            if rel.endswith(SOURCE_EXT) and not ids and not rel.endswith("Cargo.lock"):
                errs.append(f"T1 {rel}: no SPDX line (lx/glue/ is GPL-2.0-only)")
            for i in ids:
                if i != "GPL-2.0-only":
                    errs.append(f"T1 {rel}: SPDX '{i}' under lx/glue/ (must be GPL-2.0-only)")
            continue
        if rel.startswith(MIT_DIRS):
            if not ids:
                errs.append(f"T6 {rel}: no SPDX line (the relibc patch is MIT)")
            for i in ids:
                if i != "MIT":
                    errs.append(f"T6 {rel}: SPDX '{i}' in the relibc patch (must be MIT)")
            continue
        for i in ids:
            if "Apache-2.0" not in re.split(r"[\s()]+", i):
                errs.append(f"T2 {rel}: SPDX '{i}' outside lx/glue/ offers no Apache-2.0")
        if rel.endswith(C_EXT) and LINUX_INC_RE.search(text):
            errs.append(f"T3 {rel}: includes a Linux kernel header outside lx/glue/")
        if os.path.basename(rel) == "Cargo.toml" and LX_DEP_RE.search(text):
            errs.append(f"T4 {rel}: depends on a crate inside lx/glue/")
        if "third_party/linux" in text and rel not in T5_ALLOWED and not rel.endswith(".md"):
            errs.append(f"T5 {rel}: names third_party/linux (not an allowed user)")
    return errs


def artefacts(root):
    out = []
    for rel in (f"{TARGET}/riscv64imac-unknown-none-elf/release/kernel",
                f"{TARGET}/aarch64-unknown-none-softfloat/release/kernel"):
        out.append(rel)
    for d in (BUILD, f"{BUILD}/aarch64", f"{BUILD}/lx",
              f"{BUILD}/relibc/riscv64", f"{BUILD}/relibc/aarch64", f"{BUILD}/relibc/x86_64"):
        p = os.path.join(root, d)
        if os.path.isdir(p):
            out += [os.path.join(d, n) for n in sorted(os.listdir(p)) if n.endswith((".elf", ".ko"))]
    return [r for r in out if os.path.isfile(os.path.join(root, r))]


def strtab_names(data):
    """Every NUL-terminated name in the ELF's string tables (symbols and
    sections); a byte search over the whole file would also match string
    literals, which are not symbols."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return data  # not ELF64: search everything (conservative)
    shoff = int.from_bytes(data[40:48], "little")
    shnum = int.from_bytes(data[60:62], "little")
    chunks = []
    for i in range(shnum):
        o = shoff + i * 64
        kind = int.from_bytes(data[o + 4:o + 8], "little")
        if kind == 3:  # SHT_STRTAB
            off = int.from_bytes(data[o + 24:o + 32], "little")
            size = int.from_bytes(data[o + 32:o + 40], "little")
            chunks.append(data[off:off + size])
    return b"\0".join(chunks)


def modinfo(data, key):
    m = re.search(re.escape(key) + rb"=([^\0]*)", data)
    return m.group(1) if m else None


def check_artefacts(root, rels):
    errs = []
    if not rels:
        return ["A0 no built artefact found (build the kernels, `make userspace`, `make lx-modules`)"]
    for rel in rels:
        data = read(root, rel)
        if LX_SYMBOL_RE.search(strtab_names(data)):
            errs.append(f"A1 {rel}: carries a symbol of the GPL glue (lx/glue/)")
        if rel.startswith(f"{BUILD}/lx/") and rel.endswith(".ko"):
            tag = modinfo(data, b"license")
            if tag != OUR_MODULE_TAG:
                errs.append(f"A2 {rel}: module licence tag {tag!r}, not this project's "
                            f"({OUR_MODULE_TAG.decode()}): no Linux module before stage L1")
    return errs


# The Linux loader's GPL-compatible licence tags (`license_is_gpl_compatible`
# in kernel/module/main.c), the list crates/core/lx-loader also enforces.
GPL_COMPATIBLE = {b"GPL", b"GPL v2", b"GPL and additional rights", b"Dual BSD/GPL",
                  b"Dual MIT/GPL", b"Dual MPL/GPL", OUR_MODULE_TAG}
# The vermagic arch word per ISA: x86_64 defines none (arch/x86/include/asm/
# vermagic.h), so its vermagic ends in "preempt " with the trailing space.
KO_ISAS = {"riscv64": "riscv", "aarch64": "aarch64", "x86_64": ""}


def elf_symbols(data):
    """(name, defined, global, is_section) for every symbol of an ELF64
    little-endian object's .symtab."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return []
    u = lambda o, n: int.from_bytes(data[o:o + n], "little")
    shoff, shnum = u(40, 8), u(60, 2)
    secs = [(u(shoff + i * 64 + 4, 4), u(shoff + i * 64 + 24, 8), u(shoff + i * 64 + 32, 8),
             u(shoff + i * 64 + 40, 4)) for i in range(shnum)]
    out = []
    for kind, off, size, link in secs:
        if kind != 2:  # SHT_SYMTAB
            continue
        stroff = secs[link][1]
        for k in range(1, size // 24):
            o = off + k * 24
            name_off, info, shndx = u(o, 4), data[o + 4], u(o + 6, 2)
            end = data.index(b"\0", stroff + name_off)
            out.append((data[stroff + name_off:end], shndx != 0, info >> 4 != 0, info & 0xf == 3))
    return out


def ko_imports(data):
    return {n for n, d, g, _ in elf_symbols(data) if not d and g and n}


def ko_exports(data):
    """Names the module exports: its `__ksymtab_<name>` entry symbols."""
    return {n[len(b"__ksymtab_"):] for n, d, _, sec in elf_symbols(data)
            if d and not sec and n.startswith(b"__ksymtab_") and n != b"__ksymtab_strings"}


def ko_defined(data):
    return {n for n, d, g, sec in elf_symbols(data) if d and g and not sec and n}


def host_abi(root):
    with open(os.path.join(root, "lx", "HOST_ABI"), encoding="utf-8") as f:
        return {l.strip().encode() for l in f if l.strip() and not l.startswith("#")}


def check_ko(OUT, kodir, abi, images, release):
    """K rules over the .ko set in `kodir`; `images` are paths (relative to
    `root`) of the ELF images that must stay free of GPL symbols."""
    errs, defined, n_ko, n_fs = [], set(), 0, 0
    for isa, arch in KO_ISAS.items():
        d = os.path.join(kodir, isa)
        kos = sorted(f for f in os.listdir(d) if f.endswith(".ko")) if os.path.isdir(d) else []
        if "lxbase.ko" not in kos:
            errs.append(f"K0 {d}: no lxbase.ko (the base is loaded first)")
            continue
        kos.remove("lxbase.ko")
        exported = set()
        for i, ko in enumerate(["lxbase.ko"] + kos):
            data = open(os.path.join(d, ko), "rb").read()
            n_ko += 1
            tag, vm = modinfo(data, b"license"), modinfo(data, b"vermagic")
            want = f"{release} SMP preempt {arch}".encode()
            if tag not in GPL_COMPATIBLE:
                errs.append(f"K1 {isa}/{ko}: licence tag {tag!r} is not GPL-compatible")
            if vm != want:
                errs.append(f"K1 {isa}/{ko}: vermagic {vm!r}, the pin wants {want!r}")
            stray = ko_imports(data) - abi - (exported if i else set())
            for s in sorted(stray):
                rule = "K3" if i else "K2"
                errs.append(f"{rule} {isa}/{ko}: imports {s.decode()!r}, which neither the host ABI "
                            f"nor an earlier module exports")
            exported |= ko_exports(data)
            defined |= ko_defined(data)
        # The filesystem set (<isa>/fs/): same licence and
        # vermagic rules, and its symbols join K4. Its imports are not K3-gated:
        # the recorded list lx/FS_EXT4_UNRESOLVED is, by lx-loader-tests.
        fsd = os.path.join(d, "fs")
        for ko in sorted(f for f in os.listdir(fsd) if f.endswith(".ko")) if os.path.isdir(fsd) else []:
            data = open(os.path.join(fsd, ko), "rb").read()
            n_fs += 1
            tag, vm = modinfo(data, b"license"), modinfo(data, b"vermagic")
            if tag not in GPL_COMPATIBLE:
                errs.append(f"K1 {isa}/fs/{ko}: licence tag {tag!r} is not GPL-compatible")
            if vm != f"{release} SMP preempt {arch}".encode():
                errs.append(f"K1 {isa}/fs/{ko}: vermagic {vm!r}, the pin wants {release} SMP preempt {arch}")
            defined |= ko_defined(data)
    if not n_ko:
        errs.append(f"K0 {kodir}: no .ko built (make lx-kbuild)")
    if not images:
        errs.append("K0 no image to check (build the kernels and `make userspace`)")
    for rel in images:
        names = set(strtab_names(read(OUT, rel)).split(b"\0"))
        hit = sorted(names & defined)
        if hit:
            errs.append(f"K4 {rel}: names {len(hit)} symbol(s) a .ko defines, e.g. {hit[0].decode()!r}")
    return errs, n_ko, n_fs


def ko_self_test(root, kodir, release):
    """Canary for the K rules over the REAL .ko set: one mutation per rule,
    each must be reported; the unmutated set must pass."""
    import shutil
    failures, abi = [], host_abi(root)
    images = [r for r in artefacts(OUT) if not r.endswith(".ko")]
    errs, _, _ = check_ko(OUT, kodir, abi, images, release)
    if errs:
        return [f"the real .ko set does not pass: {errs}"]
    with tempfile.TemporaryDirectory() as td:
        k = os.path.join(td, "ko")
        shutil.copytree(kodir, k)
        p = os.path.join(k, "riscv64", "xz_dec.ko")
        clean = open(p, "rb").read()
        # K1: a proprietary-class tag (same length, so the ELF stays valid).
        open(p, "wb").write(clean.replace(b"license=Dual BSD/GPL\0", b"license=Proprietary!\0"))
        if not any(e.startswith("K1 riscv64/xz_dec.ko: licence") for e in check_ko(OUT, k, abi, images, release)[0]):
            failures.append("K1 (licence) did not bite")
        # K1: the set checked against another release (as if built from
        # another tree).
        open(p, "wb").write(clean)
        # K1 on the filesystem set (<isa>/fs/): the same mutation.
        fp = os.path.join(k, "aarch64", "fs", "ext4.ko")
        if os.path.exists(fp):
            fclean = open(fp, "rb").read()
            open(fp, "wb").write(fclean.replace(b"license=GPL\0", b"license=Prp\0"))
            if not any(e.startswith("K1 aarch64/fs/ext4.ko: licence") for e in check_ko(OUT, k, abi, images, release)[0]):
                failures.append("K1 (licence, fs set) did not bite")
            open(fp, "wb").write(fclean)
        if not any(e.startswith("K1 ") for e in check_ko(OUT, k, abi, images, release + "9")[0]):
            failures.append("K1 (vermagic) did not bite")
        # K2: the host ABI loses a symbol lxbase.ko imports.
        if not any(e.startswith("K2 ") for e in check_ko(OUT, k, abi - {b"memset"}, images, release)[0]):
            failures.append("K2 did not bite")
        # K3: xz_dec.ko needs crc32_le; the base stops exporting it.
        b = os.path.join(k, "riscv64", "lxbase.ko")
        base = open(b, "rb").read()
        open(b, "wb").write(base.replace(b"__ksymtab_crc32_le\0", b"__ksymtab_crc32_lX\0"))
        if not any(e.startswith("K3 riscv64/xz_dec.ko: imports 'crc32_le'") for e in check_ko(OUT, k, abi, images, release)[0]):
            failures.append("K3 did not bite")
        open(b, "wb").write(base)
        # K4: an image that carries a symbol the module defines.
        w = os.path.join(td, BUILD, "evil.elf")
        os.makedirs(os.path.dirname(w))
        evil = elf_append_strtab(open(os.path.join(OUT, images[0]), "rb").read(), b"xz_dec_run")
        open(w, "wb").write(evil)
        if not any(e.startswith("K4 ") for e in check_ko(td, k, abi, [f"{BUILD}/evil.elf"], release)[0]):
            failures.append("K4 did not bite")
    return failures


def elf_append_strtab(data, name):
    """`data` (an ELF64) with `name` appended to its first string table, the
    section grown in place at the end of the file (a copy for the canary)."""
    u = lambda o, n: int.from_bytes(data[o:o + n], "little")
    shoff, shnum = u(40, 8), u(60, 2)
    out = bytearray(data)
    for i in range(shnum):
        o = shoff + i * 64
        if u(o + 4, 4) == 3:
            off, size = u(o + 24, 8), u(o + 32, 8)
            blob = data[off:off + size] + b"\0" + name + b"\0"
            new_off = len(out)
            out += blob
            out[o + 24:o + 32] = new_off.to_bytes(8, "little")
            out[o + 32:o + 40] = len(blob).to_bytes(8, "little")
            return bytes(out)
    return data


def submodules(root):
    """The .gitmodules entries, {name: {key: value}} (keys as git reads them)."""
    out = subprocess.run(["git", "config", "-f", os.path.join(root, ".gitmodules"), "--get-regexp", r"^submodule\."],
                         capture_output=True, text=True).stdout
    mods = {}
    for line in out.splitlines():
        k, _, v = line.partition(" ")
        name, _, key = k[len("submodule."):].rpartition(".")
        mods.setdefault(name, {})[key] = v
    return mods


def gitlinks(root):
    """The gitlinks of the index, {path: commit}."""
    out = subprocess.run(["git", "-C", root, "ls-files", "-s"], capture_output=True, text=True).stdout
    return {f[3]: f[1] for f in (line.split(None, 3) for line in out.splitlines()) if len(f) == 4 and f[0] == "160000"}


def linux_release(root):
    """The pinned Linux tag without its `v` (the module vermagic release)."""
    return submodules(root).get("third_party/linux", {}).get("tag", "").lstrip("v")


def git_out(path, *args):
    r = subprocess.run(["git", "-C", path, *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def check_pin(root, require_checkout=False):
    """P and R rules (module docstring) over every third-party tree."""
    errs, notes = [], []
    mods, links = submodules(root), gitlinks(root)
    if not mods:
        return ["P0 .gitmodules lists no third-party tree"], notes
    for name, m in sorted(mods.items()):
        if m.get("path") != name or not name.startswith("third_party/") or not m.get("url"):
            errs.append(f"P0 {name}: path {m.get('path')!r} (must be its name, under third_party/) or no url")
        if m.get("shallow") != "true" or m.get("update") != "none":
            errs.append(f"P0 {name}: needs shallow = true and update = none")
        link = links.get(name)
        if not link:
            errs.append(f"P1 {name} has no gitlink in the index")
            continue
        sub = os.path.join(root, name)
        head = git_out(sub, "rev-parse", "HEAD") if os.path.exists(os.path.join(sub, ".git")) else None
        if head is None:
            # `update = none`, and the fetch script refuses iCloud checkouts:
            # absence is the normal state until a build consumes the tree.
            if require_checkout:
                errs.append(f"P2 {name} is not checked out: run tools/build/third_party_fetch.sh {name[len('third_party/'):]}")
            else:
                notes.append(name)
            continue
        if head != link:
            errs.append(f"P2 {name}: checkout HEAD {head} != gitlink {link}")
        st = git_out(sub, "status", "--porcelain", "--untracked-files=no")
        if st:
            errs.append(f"P3 {name} has local changes (a tree carries zero patches): {st.splitlines()[0]}")
        tag = m.get("tag")
        if tag:
            peeled = git_out(sub, "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}")
            if peeled != link:
                errs.append(f"P5 {name}: tag {tag} is {peeled or 'absent'} in the checkout, gitlink {link}"
                            f" (run tools/build/third_party_fetch.sh {name[len('third_party/'):]})")
        if name == "third_party/relibc" and not read(sub, "LICENSE").lstrip().startswith(b"MIT License"):
            errs.append("R2 the relibc checkout's LICENSE is not the MIT text")
    for path in sorted(set(links) - set(mods)):
        errs.append(f"P1 gitlink {path} has no .gitmodules entry")
    if "third_party/linux" in mods:
        tag = mods["third_party/linux"].get("tag")
        if not tag:
            errs.append("P0 third_party/linux has no tag (the module vermagic release)")
    if "third_party/relibc" in mods:
        if not os.path.isfile(os.path.join(root, "LICENSES", "MIT.txt")):
            errs.append("R3 LICENSES/MIT.txt is missing (the REUSE licence text for relibc)")
        if b"relibc" not in read(root, "NOTICE"):
            errs.append("R4 NOTICE does not name relibc (MIT asks for the notice to travel with the library)")
    return errs, notes


def self_test():
    """Canary: build a throwaway tree that breaks each rule once, and require
    each rule to report it; then require the clean variant to pass."""
    failures = []
    with tempfile.TemporaryDirectory() as td:
        def w(rel, text):
            p = os.path.join(td, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(text if isinstance(text, bytes) else text.encode())
        ok_hdr = "// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"
        gpl_hdr = "// SPDX-License-Identifier: GPL-2.0-only\n"
        mit_hdr = "# SPDX-License-Identifier: MIT\n"
        w("lx/glue/src/lib.rs", gpl_hdr)
        w("userspace/lib/relibc-azos/patches/0001.patch", mit_hdr)
        w("userspace/lib/relibc-azos/src/lib.rs", ok_hdr)
        w("lx/emul/src/lib.rs", ok_hdr)
        w("crates/x/src/lib.rs", ok_hdr)
        w("crates/z/Cargo.toml", "# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"
                                 "[dependencies]\nlx_emul = { path = \"../../lx/emul\" }\n")
        clean = ["lx/glue/src/lib.rs", "lx/emul/src/lib.rs", "crates/x/src/lib.rs", "crates/z/Cargo.toml",
                 "userspace/lib/relibc-azos/patches/0001.patch", "userspace/lib/relibc-azos/src/lib.rs"]
        if check_tree(td, clean):
            failures.append(f"clean tree flagged: {check_tree(td, clean)}")
        cases = {
            "T1": ("lx/glue/src/bad.rs", ok_hdr),
            "T1 ": ("lx/glue/src/none.rs", "fn main() {}\n"),
            "T2": ("crates/x/src/gpl.rs", gpl_hdr),
            "T2 ": ("lx/emul/src/gpl.rs", gpl_hdr),
            "T3": ("userspace/tests/x/a.c", ok_hdr + "#include <linux/module.h>\n"),
            "T3 ": ("lx/emul/src/shim.c", ok_hdr + "#include <linux/slab.h>\n"),
            "T4": ("crates/y/Cargo.toml", "# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"
                                          "[dependencies]\nlx_glue = { path = \"../../lx/glue\" }\n"),
            "T5": ("Makefile.x", "CFLAGS += -Ithird_party/linux/include\n"),
            # MIT is accepted in the relibc patch and nowhere else.
            "T2  ": ("crates/x/src/mit.rs", "// SPDX-License-Identifier: MIT\n"),
            "T2   ": ("userspace/lib/relibc-azos/src/mit.rs", "// SPDX-License-Identifier: MIT\n"),
            "T6": ("userspace/lib/relibc-azos/patches/0002.patch", "# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"),
            "T6 ": ("userspace/lib/relibc-azos/patches/0003.patch", "no header\n"),
        }
        for rule, (rel, text) in cases.items():
            w(rel, text)
            errs = check_tree(td, clean + [rel])
            if not any(e.startswith(rule.strip() + " ") for e in errs):
                failures.append(f"rule {rule.strip()} did not bite on {rel}: {errs}")
        # Artefacts: a fake ELF64 whose string table names an lx_emul symbol,
        # and a module whose licence tag is Linux's.
        def elf_with_strtab(names):
            strtab = b"\0" + b"\0".join(names) + b"\0"
            hdr = bytearray(64)
            hdr[0:4] = b"\x7fELF"; hdr[4] = 2; hdr[5] = 1
            shoff = 64 + len(strtab)
            hdr[40:48] = shoff.to_bytes(8, "little"); hdr[60:62] = (2).to_bytes(2, "little")
            sh = bytearray(128)
            sh[64 + 4:64 + 8] = (3).to_bytes(4, "little")
            sh[64 + 24:64 + 32] = (64).to_bytes(8, "little")
            sh[64 + 32:64 + 40] = len(strtab).to_bytes(8, "little")
            return bytes(hdr) + strtab + bytes(sh)
        w(f"{BUILD}/good.elf", elf_with_strtab([b"main", b"lx_test_mix", b"_ZN7lx_emul3mem7kmalloc17h0E"]))
        w(f"{BUILD}/bad.elf", elf_with_strtab([b"_ZN7lx_glue5probe17h0E"]))
        w(f"{BUILD}/lx/ours.ko", elf_with_strtab([b"x"]) + b"\0license=Dual Apache/GPL\0")
        w(f"{BUILD}/lx/linux.ko", elf_with_strtab([b"x"]) + b"\0license=GPL\0")
        errs = check_artefacts(td, [f"{BUILD}/good.elf", f"{BUILD}/lx/ours.ko"])
        if errs:
            failures.append(f"clean artefacts flagged: {errs}")
        errs = check_artefacts(td, [f"{BUILD}/bad.elf", f"{BUILD}/lx/linux.ko"])
        for rule in ("A1", "A2"):
            if not any(e.startswith(rule + " ") for e in errs):
                failures.append(f"rule {rule} did not bite: {errs}")
        if not check_artefacts(td, []):
            failures.append("an empty artefact set passed")
        failures += pin_self_test()
    return failures


def pin_self_test():
    """Canary for the P and R rules: a throwaway superproject with a Linux and
    a relibc gitlink, both checked out, passes; each mutation (one per rule)
    must be reported, and the clean tree must pass again after it."""
    failures = []
    with tempfile.TemporaryDirectory() as td:
        def w(rel, text):
            p = os.path.join(td, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        def git(path, *a):
            return subprocess.run(["git", "-C", path, "-c", "user.name=t", "-c", "user.email=t@t", *a],
                                  capture_output=True, text=True, check=True).stdout.strip()
        heads = {}
        for name, lic in (("linux", "GPL-2.0\n"), ("relibc", "MIT License\n")):
            sub = os.path.join(td, "third_party", name)
            os.makedirs(sub)
            git(sub, "init", "-q")
            w(f"third_party/{name}/LICENSE", lic)
            git(sub, "add", "LICENSE")
            git(sub, "commit", "-q", "-m", "x")
            heads[name] = git(sub, "rev-parse", "HEAD")
        git(os.path.join(td, "third_party", "linux"), "tag", "v1.0")
        git(td, "init", "-q")
        def gitmodules(linux_extra="\ttag = v1.0\n", relibc_update="none"):
            w(".gitmodules",
              '[submodule "third_party/linux"]\n\tpath = third_party/linux\n\turl = https://x/linux\n'
              f'\tshallow = true\n\tupdate = none\n{linux_extra}'
              '[submodule "third_party/relibc"]\n\tpath = third_party/relibc\n\turl = https://x/relibc\n'
              f'\tshallow = true\n\tupdate = {relibc_update}\n')
        def links(linux=None):
            for name in ("linux", "relibc"):
                git(td, "update-index", "--add", "--cacheinfo",
                    f"160000,{(linux if name == 'linux' and linux else heads[name])},third_party/{name}")
        def reset():
            gitmodules(); links()
            w("LICENSES/MIT.txt", "MIT License\n"); w("NOTICE", "relibc is MIT\n")
            w("third_party/relibc/LICENSE", "MIT License\n"); w("third_party/linux/LICENSE", "GPL-2.0\n")
            git(td, "update-index", "--force-remove", "third_party/extra")
        reset()
        errs, notes = check_pin(td)
        if errs or notes:
            failures.append(f"clean pin tree flagged: {errs} {notes}")
        other = "b" * 40
        for rule, mutate in (
            ("P0", lambda: gitmodules(relibc_update="checkout")),
            ("P0", lambda: gitmodules(linux_extra="")),
            ("P1", lambda: git(td, "update-index", "--force-remove", "third_party/relibc")),
            ("P1", lambda: git(td, "update-index", "--add", "--cacheinfo", f"160000,{other},third_party/extra")),
            ("P2", lambda: links(linux=other)),
            ("P3", lambda: w("third_party/linux/LICENSE", "patched\n")),
            ("P5", lambda: gitmodules(linux_extra="\ttag = v9.9\n")),
            ("R2", lambda: w("third_party/relibc/LICENSE", "GNU GENERAL PUBLIC LICENSE\n")),
            ("R3", lambda: os.remove(os.path.join(td, "LICENSES/MIT.txt"))),
            ("R4", lambda: w("NOTICE", "nothing here\n")),
        ):
            reset()
            mutate()
            if not any(e.startswith(rule + " ") for e in check_pin(td)[0]):
                failures.append(f"rule {rule} did not bite: {check_pin(td)[0]}")
        # An absent checkout is a note, and a failure when one is required.
        reset()
        git(os.path.join(td, "third_party", "linux"), "tag", "-d", "v1.0")
        import shutil
        shutil.rmtree(os.path.join(td, "third_party", "linux", ".git"))
        if check_pin(td)[0] or check_pin(td)[1] != ["third_party/linux"]:
            failures.append(f"an absent checkout is not a note: {check_pin(td)}")
        if not any(e.startswith("P2 ") for e in check_pin(td, require_checkout=True)[0]):
            failures.append("rule P2 (--require-checkout) did not bite")
    return failures


def main(argv):
    if "--ko" in argv:
        kodir = os.path.abspath(argv[argv.index("--ko") + 1])
        release = linux_release(ROOT)
        if "--self-test" in argv:
            f = ko_self_test(ROOT, kodir, release)
            for x in f:
                print("lx_license_lint --ko self-test:", x)
            print("lx_license_lint --ko self-test:", "FAIL" if f else "every rule bites (K1-K4)")
            return 1 if f else 0
        images = [r for r in artefacts(OUT) if not r.endswith(".ko")]
        errs, n, n_fs = check_ko(OUT, kodir, host_abi(ROOT), images, release)
        for e in errs:
            print("lx_license_lint:", e)
        if not errs:
            print(f"lx_license_lint: {n} validated Kbuild modules clean (GPL-compatible, vermagic {release}, "
                  f"imports resolved by host ABI + exports); {n_fs} filesystem-set modules checked for licence, "
                  f"vermagic and K4 only (their imports are gated by lx/FS_EXT4_UNRESOLVED, not resolved); "
                  f"{len(images)} images carry none of their symbols")
        return 1 if errs else 0
    if "--self-test" in argv:
        f = self_test()
        for x in f:
            print("lx_license_lint self-test:", x)
        print("lx_license_lint self-test:", "FAIL" if f else "every rule bites (T1-T6, A1, A2, P0-P3, P5, R2-R4)")
        return 1 if f else 0
    if "--pin" in argv:
        errs, notes = check_pin(ROOT, "--require-checkout" in argv)
        for e in errs:
            print("lx_license_lint:", e)
        if notes:
            print("lx_license_lint: note: not checked out (gitlink and .gitmodules checked only):", " ".join(notes))
        if not errs:
            links = gitlinks(ROOT)
            print("lx_license_lint: third_party clean:", ", ".join(
                f"{n[len('third_party/'):]} {m.get('tag') or links.get(n, '?')[:12]}" for n, m in sorted(submodules(ROOT).items())))
        return 1 if errs else 0
    errs = check_tree(ROOT, tracked(ROOT))
    arts = artefacts(OUT)
    errs += check_artefacts(OUT, arts)
    for e in errs:
        print("lx_license_lint:", e)
    if not errs:
        print(f"lx_license_lint: tree clean, {len(arts)} artefacts clean")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

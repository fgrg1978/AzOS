#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Licence lint for the Linux driver layer (RFC-0053 10.2; gate rows `lx: ...`).

The project is "Apache-2.0 OR GPL-2.0-only", and so is our own Rust in the
Linux layer (`lx/emul`, no Linux header; owner decision, round 47). The glue
that includes Linux headers (`lx/glue/`) and the pinned Linux tree
(`third_party/linux/`) are GPL-2.0-only. The rule this keeps: **no GPL-only
source, symbol or object outside `lx/glue/` and `third_party/`**, so nothing
GPL-only reaches the kernel or any image by accident.

    python3 tools/lx_license_lint.py              # tree + build artefacts
    python3 tools/lx_license_lint.py --pin        # submodule == lx/LINUX_PIN
    python3 tools/lx_license_lint.py --self-test  # canary: every rule bites
    python3 tools/lx_license_lint.py --ko DIR     # the Kbuild .ko set (L1)
    python3 tools/lx_license_lint.py --ko DIR --self-test  # its canary

Tree rules (over `git ls-files`, so build output and untracked files are not
judged):

  T1  every SPDX line under lx/glue/ says exactly GPL-2.0-only, and every source
      file there (.rs .c .h .S .toml .py .sh) has one;
  T2  outside lx/glue/ and third_party/ (lx/emul included), every SPDX
      expression offers Apache-2.0
      (a GPL-only file there would make its crate GPL-only);
  T3  outside lx/glue/ and third_party/, no C/assembly source includes a Linux
      kernel header (`<linux/...>`, `<asm/...>`, `<asm-generic/...>`): a file
      compiled against Linux headers is GPL-2.0-only by RFC-0053 10.2;
  T4  no Cargo.toml outside lx/glue/ depends on a path inside lx/glue/ (a dual-licensed
      crate linking a GPL one);
  T5  `third_party/linux` is named only by the files allowed to: the
      submodule record, the fetch script, this lint and the Kconfig help.

Artefact rules (over what is built; missing files are skipped, an empty set
is a failure so the row cannot pass by finding nothing):

  A1  no symbol of the GPL glue (`lx_glue`, Rust-mangled `7lx_glue`) in a
      kernel ELF, a userspace ELF (build/*.elf, build/aarch64/*.elf) or a
      module (build/lx/*.ko);
  A2  every module under build/lx/ carries this project's own licence tag
      (`Dual Apache/GPL`): until stage L1's sign-off no Linux module is built.

Module rules (`--ko DIR`, DIR = `make lx-kbuild`'s output: <isa>/*.ko for
riscv64 and aarch64; RFC-0053 L1). The load order is lxbase.ko (the base,
lx/glue) and then every other module:

  K1  every .ko carries a GPL-compatible `license` (the Linux loader's list)
      and `vermagic` = "<lx/LINUX_PIN release> SMP preempt <riscv|aarch64>";
  K2  lxbase.ko imports only the host ABI (lx/HOST_ABI): no Linux symbol is
      expected from the server;
  K3  every other module imports only the host ABI and symbols EXPORTED
      (`__ksymtab`) by modules earlier in the order: the RFC 6.3 "nm -u"
      gate, so an unimplemented Linux symbol fails the build, not the boot;
  K4  no image (kernel ELFs, build/*.elf, build/aarch64/*.elf) has a symbol
      named like one a .ko defines: the GPL code lives in the .ko only;
  K0  an empty .ko set, or an empty image set, is a failure.

Pin rules (`--pin`): lx/LINUX_PIN's commit equals the gitlink recorded for
third_party/linux, the checkout's HEAD, and the checkout has no local change;
config/Kconfig.linux's LX_LINUX_PIN default equals the pin's tag.
"""

import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GPL_ONLY_DIRS = ("lx/glue/", "third_party/")
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
    "tools/lx_fetch_linux.sh",
    "tools/lx_license_lint.py",
    "config/Kconfig.linux",
    "lx/LINUX_PIN",
    "tools/lx_kbuild/run.sh",
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
    for rel in ("target/riscv64imac-unknown-none-elf/release/kernel",
                "target/aarch64-unknown-none-softfloat/release/kernel"):
        out.append(rel)
    for d in ("build", "build/aarch64", "build/lx"):
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
        if rel.startswith("build/lx/") and rel.endswith(".ko"):
            tag = modinfo(data, b"license")
            if tag != OUR_MODULE_TAG:
                errs.append(f"A2 {rel}: module licence tag {tag!r}, not this project's "
                            f"({OUR_MODULE_TAG.decode()}): no Linux module before stage L1")
    return errs


# The Linux loader's GPL-compatible licence tags (`license_is_gpl_compatible`
# in kernel/module/main.c), the list crates/core/lx-loader also enforces.
GPL_COMPATIBLE = {b"GPL", b"GPL v2", b"GPL and additional rights", b"Dual BSD/GPL",
                  b"Dual MIT/GPL", b"Dual MPL/GPL", OUR_MODULE_TAG}
KO_ISAS = {"riscv64": "riscv", "aarch64": "aarch64"}


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


def check_ko(root, kodir, abi, images, release):
    """K rules over the .ko set in `kodir`; `images` are paths (relative to
    `root`) of the ELF images that must stay free of GPL symbols."""
    errs, defined, n_ko = [], set(), 0
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
    if not n_ko:
        errs.append(f"K0 {kodir}: no .ko built (make lx-kbuild)")
    if not images:
        errs.append("K0 no image to check (build the kernels and `make userspace`)")
    for rel in images:
        names = set(strtab_names(read(root, rel)).split(b"\0"))
        hit = sorted(names & defined)
        if hit:
            errs.append(f"K4 {rel}: names {len(hit)} symbol(s) a .ko defines, e.g. {hit[0].decode()!r}")
    return errs, n_ko


def ko_self_test(root, kodir, release):
    """Canary for the K rules over the REAL .ko set: one mutation per rule,
    each must be reported; the unmutated set must pass."""
    import shutil
    failures, abi = [], host_abi(root)
    images = [r for r in artefacts(root) if not r.endswith(".ko")]
    errs, _ = check_ko(root, kodir, abi, images, release)
    if errs:
        return [f"the real .ko set does not pass: {errs}"]
    with tempfile.TemporaryDirectory() as td:
        k = os.path.join(td, "ko")
        shutil.copytree(kodir, k)
        p = os.path.join(k, "riscv64", "xz_dec.ko")
        clean = open(p, "rb").read()
        # K1: a proprietary-class tag (same length, so the ELF stays valid).
        open(p, "wb").write(clean.replace(b"license=Dual BSD/GPL\0", b"license=Proprietary!\0"))
        if not any(e.startswith("K1 riscv64/xz_dec.ko: licence") for e in check_ko(root, k, abi, images, release)[0]):
            failures.append("K1 (licence) did not bite")
        # K1: the set checked against another release (as if built from
        # another tree).
        open(p, "wb").write(clean)
        if not any(e.startswith("K1 ") for e in check_ko(root, k, abi, images, release + "9")[0]):
            failures.append("K1 (vermagic) did not bite")
        # K2: the host ABI loses a symbol lxbase.ko imports.
        if not any(e.startswith("K2 ") for e in check_ko(root, k, abi - {b"memset"}, images, release)[0]):
            failures.append("K2 did not bite")
        # K3: xz_dec.ko needs crc32_le; the base stops exporting it.
        b = os.path.join(k, "riscv64", "lxbase.ko")
        base = open(b, "rb").read()
        open(b, "wb").write(base.replace(b"__ksymtab_crc32_le\0", b"__ksymtab_crc32_lX\0"))
        if not any(e.startswith("K3 riscv64/xz_dec.ko: imports 'crc32_le'") for e in check_ko(root, k, abi, images, release)[0]):
            failures.append("K3 did not bite")
        open(b, "wb").write(base)
        # K4: an image that carries a symbol the module defines.
        w = os.path.join(td, "build", "evil.elf")
        os.makedirs(os.path.dirname(w))
        evil = elf_append_strtab(open(os.path.join(root, images[0]), "rb").read(), b"xz_dec_run")
        open(w, "wb").write(evil)
        if not any(e.startswith("K4 ") for e in check_ko(td, k, abi, ["build/evil.elf"], release)[0]):
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


def pin_values(root):
    vals = {}
    for line in read(root, "lx/LINUX_PIN").decode().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    return vals


def check_pin(root):
    errs = []
    pin = pin_values(root)
    commit, tag = pin.get("commit"), pin.get("tag")
    if not commit or not tag:
        return ["P0 lx/LINUX_PIN has no commit= or tag="]
    ls = subprocess.run(["git", "-C", root, "ls-files", "-s", "third_party/linux"],
                        capture_output=True, text=True).stdout.split()
    if len(ls) < 2 or ls[0] != "160000":
        errs.append("P1 third_party/linux is not a submodule gitlink in the index")
    elif ls[1] != commit:
        errs.append(f"P1 gitlink {ls[1]} != pin {commit}")
    sub = os.path.join(root, "third_party/linux")
    head = subprocess.run(["git", "-C", sub, "rev-parse", "HEAD"], capture_output=True, text=True)
    if head.returncode != 0 or not os.path.exists(os.path.join(sub, ".git")):
        # `update = none` and a fetch script that refuses iCloud checkouts:
        # absence is the normal state until a build consumes Linux sources.
        # P1 and P4 still bind the pin; `--require-checkout` makes it P2.
        if "--require-checkout" in sys.argv:
            errs.append("P2 third_party/linux is not checked out: run tools/lx_fetch_linux.sh")
        else:
            print("lx_license_lint: note: third_party/linux not checked out; gitlink and Kconfig checked only")
    else:
        if head.stdout.strip() != commit:
            errs.append(f"P2 checkout HEAD {head.stdout.strip()} != pin {commit}")
        st = subprocess.run(["git", "-C", sub, "status", "--porcelain", "--untracked-files=no"],
                            capture_output=True, text=True).stdout
        if st.strip():
            errs.append("P3 third_party/linux has local changes (the submodule carries zero patches): "
                        + st.strip().splitlines()[0])
    kc = read(root, "config/Kconfig.linux").decode()
    m = re.search(r'config LX_LINUX_PIN\n(?:.*\n){0,3}?\s*default "([^"]+)"', kc)
    if not m or m.group(1) != tag:
        errs.append(f"P4 Kconfig LX_LINUX_PIN default {m.group(1) if m else None!r} != pin {tag!r}")
    return errs


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
        w("lx/glue/src/lib.rs", gpl_hdr)
        w("lx/emul/src/lib.rs", ok_hdr)
        w("crates/x/src/lib.rs", ok_hdr)
        w("crates/z/Cargo.toml", "# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"
                                 "[dependencies]\nlx_emul = { path = \"../../lx/emul\" }\n")
        clean = ["lx/glue/src/lib.rs", "lx/emul/src/lib.rs", "crates/x/src/lib.rs", "crates/z/Cargo.toml"]
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
        w("build/good.elf", elf_with_strtab([b"main", b"lx_test_mix", b"_ZN7lx_emul3mem7kmalloc17h0E"]))
        w("build/bad.elf", elf_with_strtab([b"_ZN7lx_glue5probe17h0E"]))
        w("build/lx/ours.ko", elf_with_strtab([b"x"]) + b"\0license=Dual Apache/GPL\0")
        w("build/lx/linux.ko", elf_with_strtab([b"x"]) + b"\0license=GPL\0")
        errs = check_artefacts(td, ["build/good.elf", "build/lx/ours.ko"])
        if errs:
            failures.append(f"clean artefacts flagged: {errs}")
        errs = check_artefacts(td, ["build/bad.elf", "build/lx/linux.ko"])
        for rule in ("A1", "A2"):
            if not any(e.startswith(rule + " ") for e in errs):
                failures.append(f"rule {rule} did not bite: {errs}")
        if not check_artefacts(td, []):
            failures.append("an empty artefact set passed")
    return failures


def main(argv):
    if "--ko" in argv:
        kodir = os.path.abspath(argv[argv.index("--ko") + 1])
        release = pin_values(ROOT).get("tag", "").lstrip("v")
        if "--self-test" in argv:
            f = ko_self_test(ROOT, kodir, release)
            for x in f:
                print("lx_license_lint --ko self-test:", x)
            print("lx_license_lint --ko self-test:", "FAIL" if f else "every rule bites (K1-K4)")
            return 1 if f else 0
        images = [r for r in artefacts(ROOT) if not r.endswith(".ko")]
        errs, n = check_ko(ROOT, kodir, host_abi(ROOT), images, release)
        for e in errs:
            print("lx_license_lint:", e)
        if not errs:
            print(f"lx_license_lint: {n} Kbuild modules clean (GPL-compatible, vermagic {release}, "
                  f"imports resolved by host ABI + exports); {len(images)} images carry none of their symbols")
        return 1 if errs else 0
    if "--self-test" in argv:
        f = self_test()
        for x in f:
            print("lx_license_lint self-test:", x)
        print("lx_license_lint self-test:", "FAIL" if f else "every rule bites (T1-T5, A1, A2)")
        return 1 if f else 0
    if "--pin" in argv:
        errs = check_pin(ROOT)
        pin = pin_values(ROOT)
        for e in errs:
            print("lx_license_lint:", e)
        if not errs:
            print(f"lx_license_lint: third_party/linux == {pin.get('tag')} ({pin.get('commit')}), clean")
        return 1 if errs else 0
    errs = check_tree(ROOT, tracked(ROOT))
    arts = artefacts(ROOT)
    errs += check_artefacts(ROOT, arts)
    for e in errs:
        print("lx_license_lint:", e)
    if not errs:
        print(f"lx_license_lint: tree clean, {len(arts)} artefacts clean")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

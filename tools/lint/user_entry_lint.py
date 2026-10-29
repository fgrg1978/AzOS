#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""A native user image has no linker script, and enters through `_azos_entry`.

The layout of every ring-3 image (image base, page size, entry, a static
position-independent executable) is its ISA's target spec, `sdk/targets/
<isa>-unknown-azos.json`, the one Rust target spec per ISA; a crate carries no
`.ld` and no `.cargo/config.toml` of its own (`userspace/.cargo/config.toml` is
the one configuration of them all). A per-crate script or config was how an
image drifted: `logd` and `mcpd` once had no config, linked with lld's defaults,
entered at `_start` one word off the stack alignment a Rust function expects,
and died with #GP on their first aligned SSE store, before `main`.

Checks:
  source   no `*.ld` and no `.cargo/config.toml` under userspace/ but
           `userspace/.cargo/config.toml`; no JSON target spec in the tree but
           the three in sdk/targets; each of them names `_azos_entry` as the
           entry (`-e`, libsys and stdrt define it)
  image    the first instruction of each x86_64 ELF named is `_azos_entry`'s
           (`[endbr64] xor ebp, ebp; and rsp, -16`), read from the bytes at
           `e_entry`, so it needs no symbol table

  user_entry_lint.py [--root DIR]    the source check
  user_entry_lint.py --image ELF...  the image check (not for the static Linux
                                     `lxhello`, which has its own `_start`)
  user_entry_lint.py --self-test     each check finds its crafted failure
"""
import json
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ONE_CONFIG = os.path.join("userspace", ".cargo", "config.toml")
SPEC_DIR = os.path.join("sdk", "targets")
SPECS = ("riscv64imac-unknown-azos.json", "aarch64-unknown-azos.json", "x86_64-unknown-azos.json")
# Not walked: build output, the vendored crates (their own `.cargo-checksum.json`
# and configs), version control, agent worktrees.
SKIP_DIRS = {"target", "third_party", "node_modules"}
ENDBR64 = b"\xf3\x0f\x1e\xfa"
# xor ebp, ebp; and rsp, -16
REALIGN = b"\x31\xed\x48\x83\xe4\xf0"


def is_target_spec(path):
    """Is the JSON file at `path` a rustc target spec?"""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return False
    return isinstance(d, dict) and "llvm-target" in d and "arch" in d


def source_findings(root):
    """[(path, what is wrong)] in the tree at `root`."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(("target-", "."))]
        rel = os.path.relpath(dirpath, root)
        in_user = rel == "userspace" or rel.startswith("userspace" + os.sep)
        for n in filenames:
            p = os.path.normpath(os.path.join(rel, n))
            if in_user and n.endswith(".ld"):
                out.append((p, "a linker script: the target spec carries the layout (sdk/targets)"))
            if in_user and os.path.basename(dirpath) == ".cargo" and n in ("config.toml", "config") \
                    and p != ONE_CONFIG:
                out.append((p, f"a cargo config of its own: {ONE_CONFIG} is the one for every image"))
            if n.endswith(".json") and os.path.dirname(p) != SPEC_DIR and is_target_spec(os.path.join(dirpath, n)):
                out.append((p, f"a target spec outside {SPEC_DIR}: one spec per ISA"))
    for n in SPECS:
        p = os.path.join(SPEC_DIR, n)
        try:
            with open(os.path.join(root, p), encoding="utf-8") as f:
                spec = json.load(f)
        except (OSError, ValueError) as e:
            out.append((p, f"unreadable ({e})"))
            continue
        args = spec.get("pre-link-args", {}).get(spec.get("linker-flavor", ""), [])
        if not any(a == "-e" and b == "_azos_entry" for a, b in zip(args, args[1:])):
            out.append((p, "the link arguments do not name `-e _azos_entry`"))
    return sorted(out)


def entry_bytes(data):
    """The bytes at `e_entry` of a 64-bit little-endian ELF (as many as the
    segment holds, at most 16); None when `data` is not one."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    entry, phoff = struct.unpack_from("<QQ", data, 24)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    for i in range(phnum):
        p_type, _fl, off, vaddr, _pa, filesz, _ms, _al = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * phentsize)
        if p_type == 1 and vaddr <= entry < vaddr + filesz:
            start = off + (entry - vaddr)
            return data[start:start + min(16, vaddr + filesz - entry)]
    return b""


def image_finding(data):
    """None when the image enters through `_azos_entry`, else why not."""
    head = entry_bytes(data)
    if head is None:
        return "not a 64-bit little-endian ELF"
    if head.startswith(ENDBR64):
        head = head[len(ENDBR64):]
    if not head.startswith(REALIGN):
        return "e_entry is not `_azos_entry` (xor ebp, ebp; and rsp, -16): linked without the target spec's `-e`?"
    return None


def crafted(entry_code):
    """A one-segment ELF whose entry holds `entry_code`."""
    hdr = bytearray(64 + 56)
    hdr[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", hdr, 24, 0x10000)
    struct.pack_into("<Q", hdr, 32, 64)
    struct.pack_into("<HH", hdr, 54, 56, 1)
    code = entry_code + b"\xcc" * 16
    struct.pack_into("<IIQQQQQQ", hdr, 64, 1, 5, 120, 0x10000, 0x10000, len(code), len(code), 4096)
    return bytes(hdr) + code


def self_test():
    ok = True

    def expect(cond, what):
        nonlocal ok
        if not cond:
            ok = False
            print(f"self-test FAIL: {what}")

    expect(image_finding(crafted(REALIGN + b"\xe8\0\0\0\0\x0f\x0b")) is None, "a realigning entry is refused")
    expect(image_finding(crafted(ENDBR64 + REALIGN)) is None, "an endbr64-prefixed realigning entry is refused")
    expect(image_finding(crafted(ENDBR64 + b"\x50\x48\x89\xf7")) is not None, "a bare `_start` (push rax) is accepted")
    expect(image_finding(b"MZ") is not None, "a non-ELF is accepted")
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, SPEC_DIR))
        for n in SPECS:
            with open(os.path.join(root, SPEC_DIR, n), "w", encoding="utf-8") as f:
                json.dump({"arch": "x", "llvm-target": "x", "linker-flavor": "gnu-lld",
                           "pre-link-args": {"gnu-lld": ["-e", "_azos_entry"]}}, f)
        crate = os.path.join(root, "userspace", "services", "x")
        os.makedirs(os.path.join(crate, ".cargo"))
        os.makedirs(os.path.join(root, "userspace", ".cargo"))
        open(os.path.join(root, ONE_CONFIG), "w").close()
        expect(not source_findings(root), "a clean tree is refused")
        open(os.path.join(crate, "user.ld"), "w").close()
        expect(any("linker script" in w for _d, w in source_findings(root)), "a crate's linker script is accepted")
        os.remove(os.path.join(crate, "user.ld"))
        open(os.path.join(crate, ".cargo", "config.toml"), "w").close()
        expect(any("cargo config" in w for _d, w in source_findings(root)), "a crate's cargo config is accepted")
        os.remove(os.path.join(crate, ".cargo", "config.toml"))
        with open(os.path.join(crate, "x86_64-user.json"), "w", encoding="utf-8") as f:
            json.dump({"arch": "x86_64", "llvm-target": "x86_64-unknown-none-elf"}, f)
        expect(any("target spec outside" in w for _d, w in source_findings(root)), "a second target spec is accepted")
        os.remove(os.path.join(crate, "x86_64-user.json"))
        with open(os.path.join(root, SPEC_DIR, SPECS[2]), "w", encoding="utf-8") as f:
            json.dump({"arch": "x", "llvm-target": "x", "linker-flavor": "gnu-lld",
                       "pre-link-args": {"gnu-lld": ["-e", "_start"]}}, f)
        expect(any("_azos_entry" in w for _d, w in source_findings(root)), "a spec entering at `_start` is accepted")
    print("self-test " + ("ok" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    if argv[:1] == ["--image"]:
        bad = 0
        for path in argv[1:]:
            with open(path, "rb") as f:
                why = image_finding(f.read())
            if why:
                bad += 1
                print(f"{path}: {why}")
        return 1 if bad else 0
    root = azos_tools.ROOT
    if argv[:1] == ["--root"] and len(argv) == 2:
        root = argv[1]
    found = source_findings(root)
    for d, why in found:
        print(f"{d}: {why}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

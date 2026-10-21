#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Every native x86_64 user image enters through `_azos_entry`.

The kernel starts a native image with rsp 16-byte aligned. A System V function
expects rsp + 8 aligned (a `call` pushed its return address), and a program's
`_start` is a Rust function, so the linker script names `_azos_entry`
(`ENTRY(_azos_entry)` in `user_x86_64.ld`, defined by libsys), which realigns
and calls `_start`. A crate whose build does not pick the script up links with
lld's defaults instead: the entry is `_start` itself, entered one word off, and
the first aligned SSE store in it (`movaps`, a startup block zeroed in
`startup_init`) is a #GP with error code 0, killing the task before `main`.
That is how `logd` and `mcpd` lost the script: no `.cargo/config.toml`.

Two checks:

  source   every userspace crate that ships a `user_x86_64.ld` has a
           `.cargo/config.toml` that links `user_x86_64.ld`, `user_aarch64.ld`
           and, where it builds for RISC-V, `user.ld` (the file `cargo` reads
           the script flags from)
  image    the first instruction of each x86_64 ELF named is `_azos_entry`'s
           (`[endbr64] xor ebp, ebp; and rsp, -16`), read from the bytes at
           `e_entry`, so it needs no symbol table

  user_entry_lint.py [--root DIR]    the source check
  user_entry_lint.py --image ELF...  the image check (not for the static Linux
                                     `lxhello`, which has its own `_start`)
  user_entry_lint.py --self-test     each check finds its crafted failure
"""
import os
import struct
import sys
import tempfile

SCRIPTS = ("user.ld", "user_aarch64.ld", "user_x86_64.ld")
ENDBR64 = b"\xf3\x0f\x1e\xfa"
# xor ebp, ebp; and rsp, -16
REALIGN = b"\x31\xed\x48\x83\xe4\xf0"


def source_findings(root):
    """[(crate dir, what is missing)] under `root`/userspace."""
    out = []
    base = os.path.join(root, "userspace")
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in ("target", "src", ".cargo")]
        if "user_x86_64.ld" not in filenames:
            continue
        rel = os.path.relpath(dirpath, root)
        cfg = os.path.join(dirpath, ".cargo", "config.toml")
        if not os.path.isfile(cfg):
            out.append((rel, "no .cargo/config.toml: the link scripts are never passed"))
            continue
        with open(cfg, encoding="utf-8") as f:
            text = f.read()
        # A crate that builds no RISC-V image (`hello`: assembly there) has no
        # riscv64 target section, so no `-Tuser.ld` to look for.
        for s in SCRIPTS:
            if s == "user.ld" and "riscv64imac-unknown-none-elf" not in text:
                continue
            if "-T" + s not in text:
                out.append((rel, f".cargo/config.toml does not link {s} (-T{s})"))
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
        return "e_entry is not `_azos_entry` (xor ebp, ebp; and rsp, -16): linked without user_x86_64.ld?"
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
        crate = os.path.join(root, "userspace", "services", "x")
        os.makedirs(os.path.join(crate, ".cargo"))
        for s in SCRIPTS:
            open(os.path.join(crate, s), "w").close()
        expect(any("no .cargo" in w for _d, w in source_findings(root)), "a crate with no cargo config is accepted")
        cfg = os.path.join(crate, ".cargo", "config.toml")
        with open(cfg, "w", encoding="utf-8") as f:
            f.write('riscv64imac-unknown-none-elf "-Tuser.ld" "-Tuser_aarch64.ld"\n')
        expect(any("user_x86_64.ld" in w for _d, w in source_findings(root)), "a config missing the x86_64 script is accepted")
        with open(cfg, "w", encoding="utf-8") as f:
            f.write('riscv64imac-unknown-none-elf "-Tuser.ld" "-Tuser_aarch64.ld" "-Tuser_x86_64.ld"\n')
        expect(not source_findings(root), "a complete crate is refused")
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
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if argv[:1] == ["--root"] and len(argv) == 2:
        root = argv[1]
    found = source_findings(root)
    for d, why in found:
        print(f"{d}: {why}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

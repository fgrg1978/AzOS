#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Live-update build hooks: the linker scripts and a linked kernel against
the Kconfig (config/Kconfig.development, "Live-update build hooks").

  check_livepatch_layout.py scripts
      every kernel linker script (kernel/linker*.ld, linker-efi.ld) defines
      `.text.patch_pool` with __patch_pool_start/_end and `.azos_patch` with
      __azos_patch_start/_end, and the pool lies before `_text_end` where
      the script has one (so the W^X and no-exec-outside-the-image checks
      cover it).

  check_livepatch_layout.py elf <kernel.elf> <.config> [llvm-nm]
      the four symbols exist, __patch_pool_end - __patch_pool_start is
      exactly LIVEPATCH_POOL_KIB KiB, the pool is inside [_text_start,
      _text_end], and a table the build filled holds whole 8-byte entries.

Exit 0 when everything holds, 1 with one line per failure otherwise.
"""
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE_BYTES = 8  # azos_arch_api::isa::PATCH_SITE_BYTES


def check_scripts() -> list[str]:
    bad: list[str] = []
    scripts = sorted(glob.glob(os.path.join(ROOT, "kernel", "linker*.ld")))
    scripts = [s for s in scripts if not s.endswith("linker-common.ld")]
    scripts.append(os.path.join(ROOT, "linker-efi.ld"))
    for path in scripts:
        name = os.path.relpath(path, ROOT)
        src = re.sub(r"/\*.*?\*/", "", open(path, encoding="utf-8").read(), flags=re.S)
        for needle in (".text.patch_pool", "__patch_pool_start = .", "__patch_pool_end = .",
                       ".azos_patch", "__azos_patch_start = .", "__azos_patch_end = .",
                       "__patch_pool_bytes", ".patch_pool_anchor"):
            if needle not in src:
                bad.append(f"{name}: missing `{needle}`")
        pool, text_end = src.find("__patch_pool_end = ."), src.find("_text_end = .")
        if text_end >= 0 and 0 <= pool and pool > text_end:
            bad.append(f"{name}: the patch pool is after _text_end (outside the text range)")
    # The list is derived (every kernel/linker*.ld but the common include,
    # plus linker-efi.ld), so a new script is checked, not counted.
    if len(scripts) < 2:
        bad.append(f"expected the kernel linker scripts, found {len(scripts)}")
    return bad


def config_int(path: str, key: str) -> int:
    for line in open(path, encoding="utf-8"):
        if line.startswith(f"{key}="):
            return int(line.split("=", 1)[1].strip(), 0)
    return 0


def check_elf(elf: str, config: str, nm: str) -> list[str]:
    out = subprocess.run([nm, elf], capture_output=True, text=True, check=True).stdout
    sym = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            sym[parts[2]] = int(parts[0], 16)
    bad: list[str] = []
    need = ["__patch_pool_start", "__patch_pool_end", "__azos_patch_start",
            "__azos_patch_end", "_text_start", "_text_end"]
    for n in need:
        if n not in sym:
            bad.append(f"{os.path.basename(elf)}: symbol {n} missing")
    if bad:
        return bad
    want = config_int(config, "CONFIG_LIVEPATCH_POOL_KIB") * 1024
    got = sym["__patch_pool_end"] - sym["__patch_pool_start"]
    if got != want:
        bad.append(f"pool is {got} bytes, LIVEPATCH_POOL_KIB wants {want}")
    if want and not (sym["_text_start"] <= sym["__patch_pool_start"]
                     and sym["__patch_pool_end"] <= sym["_text_end"]):
        bad.append("the pool is outside [_text_start, _text_end]")
    sites = sym["__azos_patch_end"] - sym["__azos_patch_start"]
    if sites % SITE_BYTES:
        bad.append(f".azos_patch is {sites} bytes, not whole {SITE_BYTES}-byte entries")
    if config_int(config, "CONFIG_LIVEPATCH_ENTRY_NOPS") == 0 and sites:
        bad.append(f"LIVEPATCH_ENTRY_NOPS=0 but .azos_patch holds {sites // SITE_BYTES} entries")
    print(f"[LIVEPATCH] {os.path.basename(elf)}: pool={got // 1024} KiB "
          f"sites={sites // SITE_BYTES}")
    return bad


def main() -> int:
    a = sys.argv[1:]
    if a[:1] == ["scripts"]:
        bad = check_scripts()
    elif a[:1] == ["elf"] and len(a) >= 3:
        nm = a[3] if len(a) > 3 else "llvm-nm"
        bad = check_elf(a[1], a[2], nm)
    else:
        print(__doc__)
        return 2
    for b in bad:
        print(f"check_livepatch_layout: {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

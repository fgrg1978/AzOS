#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""kconfig_to_cargo.py — Kconfig to cargo-feature bridge

Reads a kconfiglib-generated `.config` file and emits `cargo build` arguments
to stdout:

  --features vf2,qemu     (based on bool options that map to cargo features)
  --target riscv64imac-unknown-none-elf  (based on ARCH_* selection)

The existing crate-level `#[cfg(feature = "vf2")]` gates continue to work
because the bridge translates Kconfig choices into the correct `--features`
arguments.

Usage:
    cargo build --release $(python3 tools/kconfig_to_cargo.py)
    cargo build --release $(python3 tools/kconfig_to_cargo.py .config)
    KCONFIG_CONFIG=sel.config cargo build --release \
        $(python3 tools/kconfig_to_cargo.py --select pci,nvme-prp-canary --out sel.config .config)

`--select TOKENS --out PATH`: what a gate row or a make target builds beyond
its configuration (`select` below): Kconfig lines and the features a Kconfig
symbol owns go into a copy of the configuration at PATH, which the build then
reads; test hooks are added to its features. Nothing else names a kernel
feature: tools/feature_source_lint.py fails on a kernel build that carries
`--features` of its own.

If the .config file is absent the script emits nothing (allows existing manual
`--features` invocations to keep working untouched during the C1 phase).

Phase C4 changes vs C1:
  - Replaced the generic _ENABLED suffix path that produced phantom features
    (brain-l1, brain-l2, brain-l3) which do not exist in any Cargo.toml.
  - The Kconfig-to-feature map is read from the `# cargo-feature:` tags on the
    Kconfig symbols (see below), not written here. No nested crate feature is emitted any more:
    the last one, azos_mm/small-mem for the embedded tier, was dropped
    (2026-09-15) because it left the PMM without a free page; the PMM ceiling
    manages all the RAM the firmware reports on every profile. secure-boot-enforced used to be emitted as the
    nested token azos_ota/secure-boot-enforced; now that kernel/src/boot/ota.rs
    itself gates the boot-halt on `#[cfg(feature = "secure-boot-enforced")]`
    (F18 wiring), the bare kernel feature is emitted instead — it forwards to
    azos_ota/secure-boot-enforced via kernel/Cargo.toml's own
    `secure-boot-enforced = ["azos_ota/secure-boot-enforced"]` entry, so
    both crates still end up in lockstep from one --features token.
  - Added ISA-correct --target selection (riscv64 / aarch64 / x86_64).
  - `--rustflags` / `--user-rustflags`: the ISA baseline codegen flags of
    the kernel / the user images (the Kconfig level plus every extension
    set to `require`); `--toml` prints them as a TOML array's inside;
    `--target-features`: what crates/core/limits/build.rs checks the
    kernel build against.
"""

import sys
import os
import re
import subprocess
from typing import Optional

# ---------------------------------------------------------------------------
# Target triple mapping
# ---------------------------------------------------------------------------

# Maps CONFIG_ARCH_* key to cargo --target triple.
ARCH_TO_TARGET: dict[str, str] = {
    "CONFIG_ARCH_RISCV64": "riscv64imac-unknown-none-elf",
    # Soft-float KERNEL: it names no FP/SIMD register outside the lazy
    # user-FP save/restore (kernel/src/entry/aarch64/fp_lazy.rs, checked by
    # tools/aarch64_fp_free_check.sh). Userspace is still built for the
    # hard-float `aarch64-unknown-none` (Makefile TARGET_AARCH64); this map
    # is only used for kernel builds.
    "CONFIG_ARCH_AARCH64": "aarch64-unknown-none-softfloat",
    # The x86_64 port skeleton (config/arch/Kconfig.isa): type-checked only, with
    # `-Zbuild-std` (no installed target needed). The baseline level comes
    # from `--rustflags` below.
    "CONFIG_ARCH_X86_64": "x86_64-unknown-none",
}

# The compile-time BASELINE codegen may assume, per ISA (config/arch/Kconfig.isa,
# "Hardware support model"): the level plus every extension set to
# `require`. Every `probe` extension is detected at boot and emitted only
# inside gated asm, never as a global target-feature. One emitter for the
# kernel (`--rustflags`), the user images (`--user-rustflags`) and the
# build-time cross-check (`--target-features`, crates/core/limits/build.rs).
X86_64_LEVEL_TO_CPU: dict[str, str] = {
    "CONFIG_X86_64_LEVEL_V1": "x86-64",
    "CONFIG_X86_64_LEVEL_V2": "x86-64-v2",
    "CONFIG_X86_64_LEVEL_V3": "x86-64-v3",
    "CONFIG_X86_64_LEVEL_V4": "x86-64-v4",
}
# x86_64: what `-C target-cpu=<level>` enables on the soft-float kernel
# target (`rustc --print cfg --target x86_64-unknown-none -C target-cpu=...`;
# SIMD stays off, so v4 adds nothing over v3), and what it adds on the user
# images on top of that. Both lists are cumulative from their level.
X86_64_LEVEL_FEATURES: list[tuple[int, list[str], list[str]]] = [
    # (level, kernel, user-only)
    (2, ["cmpxchg16b", "lahfsahf", "popcnt"], ["sse3", "ssse3", "sse4.1", "sse4.2"]),
    (3, ["bmi1", "bmi2", "lzcnt", "movbe", "xsave"], ["avx", "avx2", "f16c", "fma"]),
    (4, [], ["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"]),
]
X86_64_LEVEL_NUM: dict[str, int] = {
    "CONFIG_X86_64_LEVEL_V1": 1, "CONFIG_X86_64_LEVEL_V2": 2,
    "CONFIG_X86_64_LEVEL_V3": 3, "CONFIG_X86_64_LEVEL_V4": 4,
}
# `require` → (kernel features, user-only features). Integer extensions
# reach both; SIMD ones only the user images. The system extensions (SMEP,
# SMAP, PCID, INVPCID, FSGSBASE, UMIP, PKU, LA57, CET, x2APIC, TSC-deadline,
# invariant TSC) change no codegen: `require` only refuses the CPU.
X86_64_REQUIRE_FEATURES: dict[str, tuple[list[str], list[str]]] = {
    "CONFIG_X86_SSE4_2_REQUIRE":    ([], ["sse4.2"]),
    "CONFIG_X86_POPCNT_REQUIRE":    (["popcnt"], []),
    "CONFIG_X86_XSAVE_REQUIRE":     (["xsave"], []),
    "CONFIG_X86_AVX_REQUIRE":       ([], ["avx"]),
    "CONFIG_X86_AVX2_REQUIRE":      ([], ["avx2"]),
    "CONFIG_X86_BMI1_REQUIRE":      (["bmi1"], []),
    "CONFIG_X86_BMI2_REQUIRE":      (["bmi2"], []),
    "CONFIG_X86_FMA_REQUIRE":       ([], ["fma"]),
    "CONFIG_X86_MOVBE_REQUIRE":     (["movbe"], []),
    "CONFIG_X86_AVX512F_REQUIRE":   ([], ["avx512f"]),
    "CONFIG_X86_AVX512BW_REQUIRE":  ([], ["avx512bw"]),
    "CONFIG_X86_AVX512CD_REQUIRE":  ([], ["avx512cd"]),
    "CONFIG_X86_AVX512DQ_REQUIRE":  ([], ["avx512dq"]),
    "CONFIG_X86_AVX512VL_REQUIRE":  ([], ["avx512vl"]),
    "CONFIG_X86_AES_REQUIRE":       ([], ["aes"]),
    "CONFIG_X86_PCLMULQDQ_REQUIRE": ([], ["pclmulqdq"]),
    "CONFIG_X86_SHA_NI_REQUIRE":    ([], ["sha"]),
    "CONFIG_X86_RDRAND_REQUIRE":    (["rdrand"], []),
    "CONFIG_X86_RDSEED_REQUIRE":    (["rdseed"], []),
    "CONFIG_X86_ADX_REQUIRE":       (["adx"], []),
    # XSAVEOPT/XSAVES imply XSAVE in rustc's feature graph.
    "CONFIG_X86_XSAVEOPT_REQUIRE":  (["xsave", "xsaveopt"], []),
    "CONFIG_X86_XSAVES_REQUIRE":    (["xsave", "xsaves"], []),
}

# riscv64: the level's codegen features. Zaamo/Zalrsc are the A extension
# (implied by the triple; spelled out as .cargo/config.toml always has).
# F, D and V never reach global codegen: the kernel and the user images are
# soft-float (`riscv64imac-unknown-none-elf`, `riscv64imac-unknown-azos`).
RISCV64_BASE_FEATURES: list[str] = ["zaamo", "zalrsc"]
# `require` on these compiles them in everywhere (the K1's old K1_ISA).
RISCV64_REQUIRE_FEATURES: dict[str, str] = {
    "CONFIG_RV_ZBA_REQUIRE": "zba",
    "CONFIG_RV_ZBB_REQUIRE": "zbb",
    "CONFIG_RV_ZBS_REQUIRE": "zbs",
}

# aarch64: each level's mandatory features as stable target features (never
# `+v8.Na`, which rustc flags as unstable). `kernel` ones need no FP/SIMD
# register (the kernel is `aarch64-unknown-none-softfloat`, where enabling
# NEON is an ABI warning); `user` ones only reach the hard-float user images.
AARCH64_LEVEL_FEATURES: list[tuple[int, list[str], list[str]]] = [
    # (minor, kernel, user-only)
    (1, ["lse", "crc", "pan", "lor", "vh"], ["rdm"]),
    (2, ["ras", "dpb"], []),
    (3, ["rcpc", "paca", "pacg"], ["jsconv", "fcma"]),
    (4, ["dit", "flagm", "rcpc2"], ["dotprod"]),
    (5, ["sb", "ssbs", "bti"], ["frintts"]),
]
AARCH64_LEVEL_MINOR: dict[str, int] = {
    "CONFIG_AARCH64_LEVEL_8_0": 0, "CONFIG_AARCH64_LEVEL_8_1": 1,
    "CONFIG_AARCH64_LEVEL_8_2": 2, "CONFIG_AARCH64_LEVEL_8_3": 3,
    "CONFIG_AARCH64_LEVEL_8_4": 4, "CONFIG_AARCH64_LEVEL_8_5": 5,
}
# `require` → (kernel features, user-only features).
AARCH64_REQUIRE_FEATURES: dict[str, tuple[list[str], list[str]]] = {
    "CONFIG_A64_LSE_REQUIRE":   (["lse"], []),
    "CONFIG_A64_CRC32_REQUIRE": (["crc"], []),
    "CONFIG_A64_PAUTH_REQUIRE": (["paca", "pacg"], []),
    "CONFIG_A64_BTI_REQUIRE":   (["bti"], []),
    "CONFIG_A64_MTE_REQUIRE":   (["mte"], []),
    "CONFIG_A64_SVE_REQUIRE":   ([], ["sve"]),
    "CONFIG_A64_AES_REQUIRE":   ([], ["aes"]),
    "CONFIG_A64_PMULL_REQUIRE": ([], ["aes"]),
    "CONFIG_A64_SHA2_REQUIRE":  ([], ["sha2"]),
}
# The features whose presence in a kernel build must match the Kconfig
# exactly (limits/build.rs): the ones that change codegen. A K1 flag in a
# VF2 build, or +lse in an Armv8.0 build, is a binary for another board.
CONTROLLED_FEATURES: dict[str, list[str]] = {
    "CONFIG_ARCH_RISCV64": ["zba", "zbb", "zbs"],
    "CONFIG_ARCH_AARCH64": ["lse", "rcpc"],
    "CONFIG_ARCH_X86_64": ["cmpxchg16b", "lahfsahf", "popcnt", "bmi1", "bmi2", "lzcnt", "movbe",
                           "xsave", "xsaveopt", "xsaves", "adx", "rdrand", "rdseed"],
}


def _dedup(xs: list[str]) -> list[str]:
    out: list[str] = []
    for x in xs:
        if x not in out:
            out.append(x)
    return out


def isa_features(cfg: dict[str, str], user: bool) -> list[str]:
    """The level's and every `require` extension's target features, for the
    kernel (`user=False`) or the user images (`user=True`)."""
    on = lambda k: cfg.get(k) == "y"
    feats: list[str] = []
    if on("CONFIG_ARCH_AARCH64"):
        minor = max((m for k, m in AARCH64_LEVEL_MINOR.items() if on(k)), default=0)
        for lvl, kern, uonly in AARCH64_LEVEL_FEATURES:
            if lvl <= minor:
                feats += kern + (uonly if user else [])
        for key, (kern, uonly) in AARCH64_REQUIRE_FEATURES.items():
            if on(key):
                feats += kern + (uonly if user else [])
    elif on("CONFIG_ARCH_X86_64"):
        level = max((n for k, n in X86_64_LEVEL_NUM.items() if on(k)), default=2)
        for lvl, kern, uonly in X86_64_LEVEL_FEATURES:
            if lvl <= level:
                feats += kern + (uonly if user else [])
        for key, (kern, uonly) in X86_64_REQUIRE_FEATURES.items():
            if on(key):
                feats += kern + (uonly if user else [])
    else:
        feats += RISCV64_BASE_FEATURES
        feats += [f for k, f in RISCV64_REQUIRE_FEATURES.items() if on(k)]
    return _dedup(feats)


def baseline_rustflags(cfg: dict[str, str], user: bool = False, skip_base: bool = False) -> str:
    """The baseline codegen flags: `-C target-cpu=...` for x86_64's level,
    `-C target-feature=+a,+b` for the others (empty for an Armv8.0 kernel
    with no `require`, which is what the target triple already means).
    `skip_base`: leave out riscv64's level features, which
    .cargo/config.toml and the riscv64 user target spec (sdk/targets)
    already carry (for a `--config` that merges with them)."""
    base = _baseline_isa_flags(cfg, user, skip_base)
    extra = cfi_rustflags(cfg) + ([] if user else livepatch_rustflags(cfg) + x86_mitigation_rustflags(cfg)
                                  + kaslr_rustflags(cfg))
    if cfg.get("CONFIG_PROFILER") == "y" and "force-frame-pointers=yes" not in extra:
        # The profiler walks frame-pointer chains, kernel and user.
        extra += ["-C", "force-frame-pointers=yes"]
    return " ".join(w for w in [base] + extra if w)


def cfi_policy(cfg: dict[str, str], symbol: str) -> str:
    """One extension choice's `n` / `probe` / `require` (config/arch/Kconfig.isa,
    CFI_* in config/kernel/Kconfig.hardening): a choice with no member set reads as
    `probe`, the way azos_arch_api::isa::ExtPolicy::from_kconfig does."""
    if cfg.get(f"CONFIG_{symbol}_NEVER") == "y":
        return "never"
    return "require" if cfg.get(f"CONFIG_{symbol}_REQUIRE") == "y" else "probe"


def cfi_rustflags(cfg: dict[str, str]) -> list[str]:
    """The hardware control-flow-integrity codegen (plan item I4), kernel and
    user images alike. The compiler half of each ISA's extension choice: any
    policy but `n` builds the landing pads, because they are architectural
    no-ops on a CPU without the extension (aarch64 `bti`/`paciasp` are HINT
    encodings, x86_64 `endbr64` is a multi-byte NOP, riscv64 `lpad` is
    `auipc x0`), so `probe` and `require` emit the same code; what differs
    is the boot (use it when found / refuse the CPU without it) and
    `n` leaves the code exactly as it was.

      aarch64: A64_BTI -> `bti`, A64_PAUTH -> `pac-ret` (key A, non-leaf
               functions), as `-Z branch-protection=bti,pac-ret`. Whether the
               pads are enforced is the page-table GP bit and SCTLR_EL1 (BT*),
               whether the signature is checked is SCTLR_EL1.EnIA
               (crates/core/arch-aarch64/src/cpu/cfi.rs).
      x86_64:  X86_CET_IBT -> `-Z cf-protection=branch` (`endbr64` at every
               function entry and indirect-jump target; CR4.CET and
               IA32_S_CET.ENDBR_EN enforce it, arch-x86_64/src/cpu/cfi.rs).
               The kernel shadow stack (X86_CET_SHSTK) is not a codegen mode.
      riscv64: nothing. Zicfilp (`lpad`) has no symbol until the boot can
               probe and refuse it; see "Not done" in config/kernel/Kconfig.hardening.
    """
    if cfg.get("CONFIG_ARCH_AARCH64") == "y":
        modes = [m for sym, m in (("A64_BTI", "bti"), ("A64_PAUTH", "pac-ret"))
                 if cfi_policy(cfg, sym) != "never"]
        return ["-Z", f"branch-protection={','.join(modes)}"] if modes else []
    if cfg.get("CONFIG_ARCH_X86_64") == "y":
        return ["-Z", "cf-protection=branch"] if cfi_policy(cfg, "X86_CET_IBT") != "never" else []
    return []


def x86_mitigation_rustflags(cfg: dict[str, str]) -> list[str]:
    """The x86_64 kernel's Spectre v2 build hook (config/axes/Kconfig.security):
    X86_MIT_SPECTRE_V2 = probe builds every indirect call and jump through
    the external thunk `__x86_indirect_thunk_r11`
    (crates/core/arch-x86_64/src/retpoline.rs), whose path the boot chooses
    by probe. `n` and `require` build without it (require demands the
    hardware modes, so the thunk would be dead weight)."""
    if cfg.get("CONFIG_ARCH_X86_64") == "y" and cfg.get("CONFIG_X86_MIT_SPECTRE_V2_PROBE") == "y":
        return ["-Z", "retpoline", "-Z", "retpoline-external-thunk"]
    return []


def kaslr_rustflags(cfg: dict[str, str]) -> list[str]:
    """Virtual KASLR (config/kernel/Kconfig.hardening, KASLR), kernel only: the CODEGEN
    half of the position-independent kernel, for any policy but `n` where the
    choice exists (KASLR_AVAILABLE). The LINK half (`-pie`,
    `--no-dynamic-linker`, `-z notext`, `-z norelro`) is kernel/build.rs's,
    read from the same configuration the kernel's policy constant is compiled
    from, so every command line that builds the kernel gets it: it lived here
    once, and the gate's and check-fast's builds, which pass only `--base`,
    linked `probe` kernels with an empty relocation table that the boot slid
    anyway (they hung after the W^X check).

    aarch64 and riscv64 keep `-C relocation-model=static`, and it matters. Code
    reaches every symbol with `adrp`+`add` / `auipc`+`addi`, PC-relative, so it
    runs at whatever address it is at; the `pie` model would load statics
    through the GOT instead, and the boot's pre-relocation Rust (the MMU
    bring-up, the relocation walk itself) would read GOT slots that hold zero
    or a not-yet-mapped address. Only the DATA changes: with `-pie` the linker
    turns each absolute pointer in data (vtables, tables of functions, the key
    and test registries) into one relocation entry.

    x86_64 needs `-C relocation-model=pie`: its `-mcmodel=kernel` code reaches
    statics, in a `static` model, with absolute sign-extended 32-bit operands
    (`R_X86_64_32S`, a table indexed `sym(,%rax,8)`) that no relative
    relocation can slide; `pie` makes the same code `lea sym(%rip)`, still
    resolved at link time, and the code model stays `kernel`. A build without
    it fails to link (an `R_X86_64_32S` in a `-pie` link), it does not boot
    wrong. It also needs `-Z relax-elf-relocations=yes`: `pie` code loads a
    symbol another codegen unit or crate defines through the GOT (`movq
    sym@GOTPCREL(%rip)`, also the callee of every call under the retpoline
    thunks), and only a relocation marked relaxable lets the linker turn that
    into `lea sym(%rip)`. Without it the boot's pre-relocation Rust
    (`x86_64_early_kaslr`) reads a GOT slot that holds zero until its own walk
    has run. `n` leaves the build exactly as it was."""
    if cfg.get("CONFIG_KASLR_AVAILABLE") != "y" or cfi_policy(cfg, "KASLR") == "never":
        return []
    x86 = cfg.get("CONFIG_ARCH_X86_64") == "y"
    return ["-C", f"relocation-model={'pie' if x86 else 'static'}"] \
        + (["-Z", "relax-elf-relocations=yes"] if x86 else [])


def livepatch_rustflags(cfg: dict[str, str]) -> list[str]:
    """The live-update build hooks (config/kernel/Kconfig.livepatch, "Live-update
    build hooks"), kernel only: LIVEPATCH_ENTRY_NOPS > 0 is
    `-Z patchable-function-entry=N,0`, LIVEPATCH_FP is
    `-C force-frame-pointers=yes`, and LIVEPATCH_POOL_KIB > 0 reaches the
    linker scripts as `--defsym=__patch_pool_bytes` (they read it with
    DEFINED(), so a build that never sets it gets 0). All off: no flag."""
    def num(key: str) -> int:
        try:
            return int(cfg.get(key, "0"), 0)
        except ValueError:
            return 0
    flags: list[str] = []
    if num("CONFIG_LIVEPATCH_ENTRY_NOPS") > 0:
        flags += ["-Z", f"patchable-function-entry={num('CONFIG_LIVEPATCH_ENTRY_NOPS')},0"]
    if cfg.get("CONFIG_LIVEPATCH_FP") == "y":
        flags += ["-C", "force-frame-pointers=yes"]
    if num("CONFIG_LIVEPATCH_POOL_KIB") > 0:
        flags += ["-C", f"link-arg=--defsym=__patch_pool_bytes={num('CONFIG_LIVEPATCH_POOL_KIB') * 1024}"]
    return flags


def _baseline_isa_flags(cfg: dict[str, str], user: bool, skip_base: bool) -> str:
    feats = isa_features(cfg, user)
    if cfg.get("CONFIG_ARCH_X86_64") == "y":
        # The level is `target-cpu`; only the `require` extras beyond it
        # are spelled out as target features.
        cpu = next((c for k, c in X86_64_LEVEL_TO_CPU.items() if cfg.get(k) == "y"), "x86-64-v2")
        level = max((n for k, n in X86_64_LEVEL_NUM.items() if cfg.get(k) == "y"), default=2)
        implied = [f for lvl, kern, uonly in X86_64_LEVEL_FEATURES if lvl <= level
                   for f in kern + uonly]
        extra = [f for f in feats if f not in implied]
        flags = f"-C target-cpu={cpu}"
        return flags + (f" -C target-feature={','.join('+' + f for f in extra)}" if extra else "")
    if skip_base:
        feats = [f for f in feats if f not in RISCV64_BASE_FEATURES]
    return f"-C target-feature={','.join('+' + f for f in feats)}" if feats else ""


def toml_rustflags(flags: str) -> str:
    """`-C a -C b` as the inside of a TOML array: `"-C","a","-C","b"` (for
    `--config 'target.<triple>.rustflags=[...]'`, which merges with the
    target's own rustflags instead of replacing them as RUSTFLAGS does)."""
    return ",".join(f'"{w}"' for w in flags.split())


# Default target when no ARCH_* is set (ARCH_RISCV64 is the Kconfig default).
DEFAULT_TARGET = "riscv64imac-unknown-none-elf"

# ---------------------------------------------------------------------------
# Kconfig symbol -> kernel cargo feature.
#
# Kconfig is the only source: a symbol that owns a cargo feature says so
# inside its own block, with
#
#     config FOO
#         # cargo-feature: foo            (FOO=y enables `foo`)
#         # cargo-feature: foo base          (also in `--base`, see below)
#
# The tags are read here, from the Kconfig files themselves, so there is no
# second table to keep in step. tools/kconfig_lint.py checks them against
# kernel/Cargo.toml. A symbol without a tag produces `pub const` entries in
# crates/core/limits, not a cargo feature.
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TAG_RE = re.compile(r"^\s*#\s*cargo-feature:\s*(\S+)((?:\s+[a-z]+)*)\s*$")
TAG_MODIFIERS = ("base",)
_BLOCK_START_RE = re.compile(r"^\s*(?:menu)?config\s+(\w+)\s*$")
_OTHER_KEYWORD_RE = re.compile(
    r"^\s*(?:choice|endchoice|menu|endmenu|if|endif|comment|source|mainmenu)\b")
_SOURCE_RE = re.compile(r'^\s*source\s+"([^"]+)"')


def kconfig_files(root: str = REPO_ROOT) -> list[str]:
    """The Kconfig files reachable from `<root>/Kconfig` through `source`."""
    out: list[str] = []
    todo = [os.path.join(root, "Kconfig")]
    while todo:
        path = todo.pop(0)
        if path in out:
            continue
        out.append(path)
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                m = _SOURCE_RE.match(line)
                if m:
                    todo.append(os.path.join(root, m.group(1)))
    return out


def parse_cargo_feature_tags(root: str = REPO_ROOT):
    """Read every `# cargo-feature:` tag.

    Returns `(tags, orphans)`: `tags` is a list of `(symbol, feature,
    modifiers, file)` in Kconfig source order (`modifiers` a tuple of
    TAG_MODIFIERS; an unknown word is an error, not ignored); `orphans` the `file:line` of
    tags that sit outside any `config` block (they would silently do nothing).
    """
    tags: list[tuple[str, str, tuple, str]] = []
    orphans: list[str] = []
    for path in kconfig_files(root):
        cur = None
        with open(path, encoding="utf-8") as fh:
            for no, line in enumerate(fh, 1):
                m = _TAG_RE.match(line)
                if m:
                    if cur is None:
                        orphans.append(f"{os.path.relpath(path, root)}:{no}")
                    else:
                        mods = tuple(m.group(2).split())
                        bad = [w for w in mods if w not in TAG_MODIFIERS]
                        if bad:
                            raise SystemExit(f"kconfig_to_cargo: {os.path.relpath(path, root)}:{no}: "
                                             f"unknown cargo-feature modifier {bad[0]!r}")
                        tags.append((cur, m.group(1), mods, os.path.relpath(path, root)))
                    continue
                m = _BLOCK_START_RE.match(line)
                if m:
                    cur = m.group(1)
                elif _OTHER_KEYWORD_RE.match(line):
                    cur = None
    return tags, orphans


def _load_tags():
    tags, orphans = parse_cargo_feature_tags()
    if orphans:
        raise SystemExit("kconfig_to_cargo: cargo-feature tag outside a config block: "
                         + ", ".join(orphans))
    direct = {"CONFIG_" + s: f for s, f, m, _ in tags}
    base = frozenset(f for _, f, m, _ in tags if "base" in m)
    return direct, base


# CONFIG_<symbol> -> cargo feature for FOO=y; and the
# `base` features: those that shape the image whatever board or test feature a
# build names by hand (the application domain, the scheduler options, driver
# placement). `--base` emits only these, for the Makefile and script recipes
# that name their board features themselves (`--features qemu`).
KCONFIG_TO_CARGO_FEATURE, BASE_FEATURES = _load_tags()

# Drivers a safety decision reads (the first placement rule; the list is
# written out in config/subsys/Kconfig.drivers): never placed in ring 3. None has a
# placement choice; a .config that places one there anyway (a choice added
# by mistake, or a hand-edited file) is refused rather than built.
SAFETY_READ_DRIVERS: frozenset[str] = frozenset({
    "CLINT", "PLIC", "WDT", "PWM", "GPIO", "MOTOR", "MOTOR_PID", "ESC", "RC",
    "I2C", "IMU", "RANGEFINDER", "ADS1115", "UART", "VIRTIO_BLK", "MMC",
})


def base_features(cfg: dict[str, str]) -> list[str]:
    """The `base` features whose symbol the .config sets y (the application
    domain, the scheduler options, the driver placement)."""
    return [f for k, f in KCONFIG_TO_CARGO_FEATURE.items()
            if f in BASE_FEATURES and cfg.get(k) == "y"]


def placement_violations(cfg: dict[str, str]) -> list[str]:
    """The `CONFIG_DRV_<NAME>_PLACEMENT_RING3=y` lines naming a driver that a
    safety decision reads."""
    return [k for k, v in cfg.items()
            if v == "y" and k.startswith("CONFIG_DRV_") and k.endswith("_PLACEMENT_RING3")
            and k[len("CONFIG_DRV_"):-len("_PLACEMENT_RING3")] in SAFETY_READ_DRIVERS]


KERNEL_CARGO_TOML = os.path.join(REPO_ROOT, "kernel", "Cargo.toml")


def cargo_features(cargo_toml: str) -> dict[str, list[str]]:
    """name -> list of entries, for the `[features]` table of a Cargo.toml."""
    text = open(cargo_toml, encoding="utf-8").read()
    sec = re.search(r"^\[features\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    out = {}
    for m in re.finditer(r"^([A-Za-z0-9_-]+)\s*=\s*\[(.*?)\]", sec.group(1), re.M | re.S):
        body = "\n".join(l.split("#", 1)[0] for l in m.group(2).splitlines())
        out[m.group(1)] = re.findall(r'"([^"]+)"', body)
    return out


# A test hook: a kernel cargo feature that only a gate row, a canary or a
# benchmark builds (a smoke, a canary, a probe, ...), never a product. The
# one kind of feature a build selection names directly (`--select`, below);
# every other feature is a Kconfig symbol's (its `# cargo-feature:` tag).
TEST_HOOK_RE = re.compile(r"(-smoke|-canary|-probe|-test|-row|-bench|-census|-sim|-freeze|"
                          r"-window|-spin|-safety|-skip|-keep|-census|-trace|-timing|-sync|"
                          r"-in-lock|-profile|-hooks)(-\w+)*$")


_SELECT_LINE_RE = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(\S+)$")


class SelectError(Exception):
    """A build selection that cannot be built from the configuration."""


def select(base: str, tokens: list[str], out: str) -> list[str]:
    """Write to `out` the configuration a build selection asks for, and return
    its test hooks.

    A selection is what a gate row or a make target builds beyond its
    configuration. A token `CONFIG_<SYM>=<value>` is a Kconfig line, for a
    symbol that owns no feature or one that another symbol derives (HV from
    VIRT_*, HAS_RVV from RV_V_*). Any other token is a cargo feature name. A feature a Kconfig
    symbol owns (its `# cargo-feature:` tag) is that symbol set to y in a copy
    of `base`, expanded by olddefconfig, so the dependencies decide as they do
    for a defconfig and the constants crates/core/limits generates agree with
    the features; a symbol the expansion cannot keep at y is an error, never a
    feature built against a configuration that says otherwise. A test hook
    (TEST_HOOK_RE) has no symbol: it is returned, for the caller to add to
    the configuration's own features. Any other name is an error: a policy
    feature without a Kconfig symbol, or no feature at all.
    """
    cfg = read_dot_config(base)
    if cfg is None:
        raise SelectError(f"{base}: no such configuration")
    feats = cargo_features(KERNEL_CARGO_TOML)
    sym_of = {f: k for k, f in KCONFIG_TO_CARGO_FEATURE.items()}
    hooks: list[str] = []
    lines: dict[str, str] = {}
    for t in tokens:
        m = _SELECT_LINE_RE.match(t)
        if m:
            if cfg.get(m.group(1), "n") != m.group(2):
                lines[m.group(1)] = m.group(2)
        elif t in sym_of:
            if cfg.get(sym_of[t]) != "y":
                lines[sym_of[t]] = "y"
        elif t in feats and TEST_HOOK_RE.search(t):
            if t not in hooks:
                hooks.append(t)
        elif t in feats:
            raise SelectError(f"`{t}` is a policy feature without a Kconfig symbol: "
                              f"give it one (a `# cargo-feature: {t}` tag), it is not named by hand")
        else:
            raise SelectError(f"`{t}` is not a feature of kernel/Cargo.toml")
    with open(base, encoding="utf-8") as fh:
        text = fh.read()
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        for k, v in lines.items():
            fh.write(f"{k}={v}\n" if v != "n" else f"# {k} is not set\n")
    if lines:
        env = dict(os.environ, KCONFIG_CONFIG=tmp)
        r = subprocess.run([sys.executable, "-m", "olddefconfig"], cwd=REPO_ROOT, env=env,
                           capture_output=True, text=True)
        if r.returncode != 0:
            os.unlink(tmp)
            raise SelectError(f"olddefconfig failed on {base} + {' '.join(lines)}: {r.stderr.strip()}")
        got = read_dot_config(tmp) or {}
        lost = [f"{k}={v}" for k, v in lines.items() if got.get(k, "n") != v]
        if lost:
            os.unlink(tmp)
            raise SelectError(f"{', '.join(lost)} does not hold on {base} (olddefconfig "
                              f"drops it: a dependency is not met, or another symbol derives it)")
    os.replace(tmp, out)
    return hooks

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DOT_CONFIG_DEFAULT = ".config"


def read_dot_config(path: str) -> Optional[dict[str, str]]:
    """Parse a kconfiglib .config file.

    Returns a dict of CONFIG_KEY → raw value string, or None if the file
    does not exist (silently; caller handles the missing-file case).
    """
    if not os.path.exists(path):
        return None

    result: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            # Skip blank lines and comment lines (including "# CONFIG_X is not set")
            if not line or line.startswith("#"):
                # Record "not set" patterns as "n".
                if line.startswith("# CONFIG_") and line.endswith(" is not set"):
                    key = line[2 : line.index(" is not set")]
                    result[key] = "n"
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            result[key.strip()] = val.strip()
    return result


def arch_target(cfg: dict[str, str]) -> str:
    """Return the --target triple for the selected ISA.

    Falls back to the riscv64 default if no ARCH_* key is set to "y"
    (ARCH_RISCV64 is the Kconfig default, so an all-defaults .config
    will not contain an explicit CONFIG_ARCH_RISCV64=y line).
    """
    for kconfig_key, triple in ARCH_TO_TARGET.items():
        if cfg.get(kconfig_key) == "y":
            return triple
    return DEFAULT_TARGET


def enabled_features(cfg: dict[str, str]) -> list[str]:
    """Return a deduplicated, ordered list of cargo features to enable.

    Only features that exist in kernel/Cargo.toml (bare names) or in a
    kernel-dependency crate (crate/feat notation) are produced.  The generic
    _ENABLED suffix path that existed in the C1 version has been removed to
    prevent phantom features like brain-l1/l2/l3.
    """
    features: list[str] = []
    seen: set[str] = set()

    def add(feat: Optional[str]) -> None:
        if feat and feat not in seen:
            features.append(feat)
            seen.add(feat)

    # --- Explicit forward mapping ---
    for kconfig_key, cargo_feat in KCONFIG_TO_CARGO_FEATURE.items():
        if cfg.get(kconfig_key) == "y":
            add(cargo_feat)

    return features


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# The Kconfig integers and bools the std port layer (crates/core/stdrt) reads
# at build time: `make sdk` exports each as AZOS_<SYMBOL> (a bool as 0 or 1).
SDK_ENV_SYMBOLS = (
    "USER_ALLOC_QUARANTINE_KB", "USER_ALLOC_QUARANTINE_SLOTS", "USER_ALLOC_BLOCK_KB",
    "USER_ALLOC_MAX_MAPS", "USER_ALLOC_RANDOMIZE", "USER_ALLOC_SEED_REQUIRED",
    "USER_ALLOC_POISON_FREED", "USER_ALLOC_GUARD_PAGES", "SDK_THREAD_STACK_KB",
)


def sdk_env(cfg: dict[str, str]) -> list[str]:
    """`AZOS_<SYMBOL>=<value>` lines for SDK_ENV_SYMBOLS: an int as its number,
    a bool as 0 or 1 (an unset bool is 0)."""
    out = []
    for sym in SDK_ENV_SYMBOLS:
        v = cfg.get("CONFIG_" + sym)
        if v in (None, "n"):
            v = "0"
        elif v == "y":
            v = "1"
        out.append(f"AZOS_{sym}={v}")
    return out


def main() -> int:
    args = sys.argv[1:]
    # `--base`: only the `base` features (BASE_FEATURES: the application
    # domain, the scheduler options, driver placement). For recipes that name
    # their own board and test features by hand (`make build` is `--features
    # qemu`), so the .config still decides the image.
    base_only = "--base" in args
    # `--rustflags`: only the kernel's baseline codegen flags
    # (baseline_rustflags); `--user-rustflags`: the user images' ones;
    # `--toml`: either as the inside of a TOML array; `--target-features`:
    # the kernel's required and controlled features (limits/build.rs).
    rustflags_only = "--rustflags" in args
    user_rustflags = "--user-rustflags" in args
    as_toml = "--toml" in args
    target_features = "--target-features" in args
    skip_base = "--skip-base" in args
    # `--sdk-env`: the AZOS_* variables of the std port layer, one per line.
    sdk_env_only = "--sdk-env" in args
    # `--select TOKENS --out PATH`: the build selection TOKENS (comma or space
    # separated feature names, see `select`) applied to the configuration;
    # PATH receives the configuration to build with (KCONFIG_CONFIG), and the
    # output is that configuration's cargo arguments plus the test hooks.
    sel_tokens: Optional[list[str]] = None
    sel_out: Optional[str] = None
    for flag in ("--select", "--out"):
        if flag in args:
            i = args.index(flag)
            if i + 1 >= len(args):
                print(f"kconfig_to_cargo: {flag} needs a value", file=sys.stderr)
                return 2
            val = args[i + 1]
            del args[i:i + 2]
            if flag == "--select":
                sel_tokens = val.replace(",", " ").split()
            else:
                sel_out = val
    if (sel_tokens is None) != (sel_out is None):
        print("kconfig_to_cargo: --select and --out go together", file=sys.stderr)
        return 2
    args = [a for a in args if a not in ("--base", "--rustflags", "--user-rustflags",
                                         "--toml", "--target-features", "--skip-base", "--sdk-env")]
    dot_config_path = args[0] if args else DOT_CONFIG_DEFAULT

    hooks: list[str] = []
    if sel_tokens is not None:
        try:
            hooks = select(dot_config_path, sel_tokens, sel_out)
        except SelectError as e:
            print(f"kconfig_to_cargo: --select {','.join(sel_tokens)}: {e}", file=sys.stderr)
            return 1
        dot_config_path = sel_out

    cfg = read_dot_config(dot_config_path)
    if cfg is None:
        # .config absent — emit nothing.  Existing `--features X` invocations
        # in the Makefile continue to work untouched.
        return 0

    bad = placement_violations(cfg)
    if bad:
        for k in bad:
            print(f"kconfig_to_cargo: {k}: a driver a safety decision reads is never "
                  f"placed in ring 3 (config/subsys/Kconfig.drivers)", file=sys.stderr)
        return 1

    if sdk_env_only:
        print("\n".join(sdk_env(cfg)))
        return 0

    if rustflags_only or user_rustflags:
        flags = baseline_rustflags(cfg, user=user_rustflags, skip_base=skip_base)
        if flags:
            print(toml_rustflags(flags) if as_toml else flags)
        return 0

    if target_features:
        arch = next((k for k in CONTROLLED_FEATURES if cfg.get(k) == "y"), "CONFIG_ARCH_RISCV64")
        print("require=" + ",".join(isa_features(cfg, user=False)))
        print("control=" + ",".join(CONTROLLED_FEATURES.get(arch, [])))
        return 0

    if base_only:
        feats = base_features(cfg)
        if feats:
            print(f"--features {','.join(feats)}")
        return 0

    parts: list[str] = []

    # --target (always emitted; defaults to riscv64 if not set)
    target = arch_target(cfg)
    parts.append(f"--target {target}")

    # --features: the kernel has no `default` list, so this is every feature
    # (and a selection's test hooks after them)
    feats = enabled_features(cfg)
    feats += [h for h in hooks if h not in feats]
    if feats:
        parts.append(f"--features {','.join(feats)}")

    if parts:
        print(" ".join(parts))

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""kconfig_to_cargo.py — RFC-0026 Phase C4 (updated from C1)

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

If the .config file is absent the script emits nothing (allows existing manual
`--features` invocations to keep working untouched during the C1 phase).

Phase C4 changes vs C1:
  - Replaced the generic _ENABLED suffix path that produced phantom features
    (brain-l1, brain-l2, brain-l3) which do not exist in any Cargo.toml.
  - The Kconfig-to-feature map is read from the `# cargo-feature:` tags on the
    Kconfig symbols (see below), not written here. No nested crate feature is emitted any more:
    the last one, azos_mm/small-mem for PROFILE_EMBEDDED, was dropped
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
    # The x86_64 port skeleton (config/Kconfig.arch): type-checked only, with
    # `-Zbuild-std` (no installed target needed). The baseline level comes
    # from `--rustflags` below.
    "CONFIG_ARCH_X86_64": "x86_64-unknown-none",
}

# The compile-time BASELINE codegen may assume, per ISA (config/Kconfig.arch,
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
# soft-float (`riscv64imac-unknown-none-elf`).
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
    .cargo/config.toml and every riscv64 user crate's target already carry
    (for a `--config` that merges with them)."""
    base = _baseline_isa_flags(cfg, user, skip_base)
    extra = [] if user else livepatch_rustflags(cfg) + x86_mitigation_rustflags(cfg)
    return " ".join(w for w in [base] + extra if w)


def x86_mitigation_rustflags(cfg: dict[str, str]) -> list[str]:
    """The x86_64 kernel's Spectre v2 build hook (config/Kconfig.mitigations):
    X86_MIT_SPECTRE_V2 = probe builds every indirect call and jump through
    the external thunk `__x86_indirect_thunk_r11`
    (crates/core/arch-x86_64/src/retpoline.rs), whose path the boot chooses
    by probe. `n` and `require` build without it (require demands the
    hardware modes, so the thunk would be dead weight)."""
    if cfg.get("CONFIG_ARCH_X86_64") == "y" and cfg.get("CONFIG_X86_MIT_SPECTRE_V2_PROBE") == "y":
        return ["-Z", "retpoline", "-Z", "retpoline-external-thunk"]
    return []


def livepatch_rustflags(cfg: dict[str, str]) -> list[str]:
    """The live-update build hooks (config/Kconfig.development, "Live-update
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

# Drivers a safety decision reads (RFC-0040's table, rule 1; the list is
# written out in config/Kconfig.drivers): never placed in ring 3. None has a
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
    args = [a for a in args if a not in ("--base", "--rustflags", "--user-rustflags",
                                         "--toml", "--target-features", "--skip-base", "--sdk-env")]
    dot_config_path = args[0] if args else DOT_CONFIG_DEFAULT

    cfg = read_dot_config(dot_config_path)
    if cfg is None:
        # .config absent — emit nothing.  Existing `--features X` invocations
        # in the Makefile continue to work untouched.
        return 0

    bad = placement_violations(cfg)
    if bad:
        for k in bad:
            print(f"kconfig_to_cargo: {k}: a driver a safety decision reads is never "
                  f"placed in ring 3 (config/Kconfig.drivers)", file=sys.stderr)
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
    feats = enabled_features(cfg)
    if feats:
        parts.append(f"--features {','.join(feats)}")

    if parts:
        print(" ".join(parts))

    return 0


if __name__ == "__main__":
    sys.exit(main())

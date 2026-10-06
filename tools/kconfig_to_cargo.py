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
  - Built an explicit KCONFIG_TO_CARGO_FEATURE table that covers every cargo
    feature in kernel/Cargo.toml. No nested crate feature is emitted any more:
    the last one, azos_mm/small-mem for PROFILE_EMBEDDED, was dropped
    (2026-09-15) because it left the PMM without a free page; the PMM ceiling
    comes from RAM_SIZE on every profile. secure-boot-enforced used to be emitted as the
    nested token azos_ota/secure-boot-enforced; now that kernel/src/boot/ota.rs
    itself gates the boot-halt on `#[cfg(feature = "secure-boot-enforced")]`
    (F18 wiring), the bare kernel feature is emitted instead — it forwards to
    azos_ota/secure-boot-enforced via kernel/Cargo.toml's own
    `secure-boot-enforced = ["azos_ota/secure-boot-enforced"]` entry, so
    both crates still end up in lockstep from one --features token.
  - Added INVERTED_FEATURES set for documentation: features whose Kconfig
    option is absent/n when the cargo feature is enabled.
  - Added ISA-correct --target selection (riscv64 / aarch64 / x86_64).
"""

import sys
import os
from typing import Optional

# ---------------------------------------------------------------------------
# Target triple mapping
# ---------------------------------------------------------------------------

# Maps CONFIG_ARCH_* key to cargo --target triple.
#
# CONFIG_ARCH_X86_64 removed 2026-09-25 (Q4.1, owner decision): the Kconfig
# choice mapped to this "x86_64-unknown-none" triple with no real port
# behind it in this tree (see config/Kconfig.arch's note at the same date). Re-add
# once a port exists.
ARCH_TO_TARGET: dict[str, str] = {
    "CONFIG_ARCH_RISCV64": "riscv64imac-unknown-none-elf",
    # Soft-float KERNEL: it names no FP/SIMD register outside the lazy
    # user-FP save/restore (kernel/src/entry/aarch64/fp_lazy.rs, checked by
    # tools/aarch64_fp_free_check.sh). Userspace is still built for the
    # hard-float `aarch64-unknown-none` (Makefile TARGET_AARCH64); this map
    # is only used for kernel builds.
    "CONFIG_ARCH_AARCH64": "aarch64-unknown-none-softfloat",
}

# Default target when no ARCH_* is set (ARCH_RISCV64 is the Kconfig default).
DEFAULT_TARGET = "riscv64imac-unknown-none-elf"

# ---------------------------------------------------------------------------
# Kconfig option → kernel cargo feature.
#
# Rules:
#   - Bare feature names (e.g. "vf2") must appear in kernel/Cargo.toml
#     [features] block.
#   - "crate/feat" tokens (e.g. "azos_ota/secure-boot-enforced") must
#     appear in the named crate's [features] block AND the crate must be a
#     kernel dependency.
#   - Kconfig options not listed here produce pub const entries in
#     crates/core/limits, NOT cargo features.
#   - Options marked None have no direct feature; they affect generated
#     constants only.
#
# Kernel features this table can emit (as of wave 11):
#   vf2, k1, rvv, qemu, tftp-smoke, no-ml, no-mmu, secure-boot-enforced,
#   link-auth-enforced, link-encrypt-enforced, sched-aps, lat-trace,
#   pci, hdmi, ramfb, page-16k, page-64k, camera, domain-robot, energy,
#   switch-census
#
# `no-opensbi` and `uefi` were removed 2026-09-21 (B2-02/B2-03): neither was
# wired to a real boot path (see kernel/Cargo.toml's [features] comment), so
# CONFIG_BOOT_NO_OPENSBI / CONFIG_BOOT_UEFI never had anything to map to.
#
# Nested crate features used as kernel --features tokens: none.
# ---------------------------------------------------------------------------

KCONFIG_TO_CARGO_FEATURE: dict[str, Optional[str]] = {
    # Board / platform → bare kernel feature
    "CONFIG_BOARD_VF2":     "vf2",
    "CONFIG_BOARD_K1":      "k1",
    "CONFIG_BOARD_QEMU":    "qemu",

    # ISA extensions
    "CONFIG_HAS_RVV":       "rvv",

    # MMU mode: NO_MMU=y → enable no-mmu feature (direct, NOT inverted)
    "CONFIG_NO_MMU":        "no-mmu",

    # aarch64 translation granule (config/Kconfig.arch). 4 KiB has no feature:
    # it is the absence of both. The kernel asserts these against
    # azos_limits::PAGE_SHIFT, so a build without them on a 16/64 KiB
    # .config does not compile.
    "CONFIG_AARCH64_PAGE_4K":  None,
    "CONFIG_AARCH64_PAGE_16K": "page-16k",
    "CONFIG_AARCH64_PAGE_64K": "page-64k",

    # Boot path options.
    # NOTE: TFTP_SMOKE_BOOT is not yet defined in any Kconfig.* fragment (C1
    # scope; pending C4/C5 author work). Listed here so the mapping is
    # complete and documented; it will never fire until the matching Kconfig
    # option is added. (BOOT_NO_OPENSBI / BOOT_UEFI rows removed 2026-09-21,
    # B2-02/B2-03 — see the [features] block comment above.)
    "CONFIG_TFTP_SMOKE_BOOT":  "tftp-smoke",

    # Security: bare kernel feature (gates the F18 boot-halt in
    # kernel/src/boot/ota.rs directly), which itself forwards to
    # azos_ota/secure-boot-enforced — see kernel/Cargo.toml.
    "CONFIG_SECURE_BOOT_ENFORCED": "secure-boot-enforced",
    # Same compile-time-policy pattern as secure boot: see kernel/Cargo.toml.
    "CONFIG_LINK_AUTH_ENFORCED": "link-auth-enforced",
    # K-C5 — kernel/Cargo.toml forwards to azos_behavior →
    # azos_encrypt_link, same pattern as secure-boot-enforced.
    "CONFIG_LINK_ENCRYPT_ENFORCED": "link-encrypt-enforced",

    # Scheduler backend (config/Kconfig.timing). The choice already surfaces as the
    # const azos_limits::SCHED_BACKEND_APS, which is what kernel/src/main.rs
    # reads to call use_aps_dispatch(). The const alone is not enough: with
    # `lto = false` the APS policies, per-CPU runqueues and typed registry are
    # linked into every kernel whether or not the const is true — 8.1 KB of
    # .text and 41,536 bytes of .data on a Legacy build. The feature is what
    # keeps them out, and it forwards to azos_sched/sched-aps via
    # kernel/Cargo.toml, exactly like secure-boot-enforced.
    # LEGACY has no feature: it is the absence of this one.
    "CONFIG_SCHED_BACKEND_APS":    "sched-aps",
    "CONFIG_SCHED_BACKEND_LEGACY": None,

    # RFC-0051 E0-E2 (config/Kconfig.timing). The seams are in every build
    # with today's behaviour; the feature adds utilisation tracking and the
    # boot-time energy model. ENERGY_UTIL_* and the two time constants are
    # plain consts in crates/core/limits.
    "CONFIG_ENERGY": "energy",

    # config/Kconfig.development's masked-window tracer. The hooks live in the ISA
    # crates and in crates/core/sync behind cargo features (kernel `lat-trace`
    # forwards to both), so off means not compiled, not merely not called.
    "CONFIG_LAT_TRACE": "lat-trace",
    "CONFIG_SWITCH_CENSUS": "switch-census",

    # Optional buses and display drivers (config/Kconfig.drivers, wave 11).
    # Each is a kernel feature that already existed with no Kconfig symbol;
    # the symbols depend on the board the feature is for. `iommu` is not
    # mapped: it adds only `pci` plus a crate nothing in the kernel calls.
    "CONFIG_DRV_PCI":            "pci",
    "CONFIG_DRV_DISPLAY_HDMI":   "hdmi",
    "CONFIG_DRV_DISPLAY_RAMFB":  "ramfb",
    # Wave 11 (DOMAIN): CSI camera bring-up in a non-robot image.
    "CONFIG_DRV_CAMERA":         "camera",

    # Per-driver placement (config/Kconfig.drivers, wave 11 DRVPLACE). The
    # ring-3 placement has no feature: it is the absence of the kernel one,
    # as SCHED_BACKEND_LEGACY is, so a build naming its features by hand gets
    # the same default as the Kconfig choice.
    "CONFIG_DRV_INA219_PLACEMENT_KERNEL": "ina219-kernel",
    "CONFIG_DRV_INA219_PLACEMENT_RING3":  None,
    "CONFIG_DRV_BUZZER_PLACEMENT_KERNEL": "buzzer-kernel",
    "CONFIG_DRV_BUZZER_PLACEMENT_RING3":  None,

    # The application domain (config/Kconfig.domain, wave 11 DOMAIN).
    # DOMAIN_ROBOT links the robot crates through the kernel feature
    # `domain-robot`, which is in the kernel's `default` list so that builds
    # naming their features by hand keep the robot image. Every other domain
    # therefore needs `--no-default-features` plus the rest of `default`:
    # see `domain_args` below. The other domains have no feature of their
    # own: they set defaults with `imply` / conditional defaults.
    "CONFIG_DOMAIN_ROBOT":       "domain-robot",
    # RFC-0053 L0/L0b: the module loader and the empty Linux driver server.
    # crates/core/limits/build.rs refuses LINUX_DRIVERS without it.
    "CONFIG_LX_SERVER_SKELETON": "lx-server",
    # The threat-model profile (config/Kconfig.mitigations) only sets
    # defaults with `imply`, and the robot type reaches the safety layer as
    # the const azos_limits::ROBOT_TYPE_ID: no feature for either.

    # BOARD_GENERIC and every PROFILE_* have no direct cargo feature.
    # Their effect is entirely through pub const values in crates/core/limits.
    # PROFILE_EMBEDDED used to emit `azos_mm/small-mem`, which capped the
    # PMM at 128 pages (512 KiB) whatever the RAM: `pmm::init` then reserved
    # the image inside those 128 pages and was left with no free page on any
    # real layout. The PMM ceiling now comes from `RAM_SIZE` on every profile.
    "CONFIG_BOARD_GENERIC":     None,
    "CONFIG_PROFILE_EMBEDDED":  None,
    "CONFIG_PROFILE_EDGE":      None,
    "CONFIG_PROFILE_FLEET":     None,
}

# Options that produce a cargo feature by their ABSENCE (inverted booleans).
# When CONFIG_FOO is absent or =n, the corresponding cargo feature is enabled.
# This set is intentionally small — most options are direct (presence = enable).
INVERTED_FEATURE_MAP: dict[str, str] = {
    # DRV_ML_INFERENCE=n (or not set) → enable no-ml feature.
    "CONFIG_DRV_ML_INFERENCE": "no-ml",
}

# Documentation-only set: cargo feature names whose Kconfig option is inverted.
# Used to label the semantics; the logic lives in INVERTED_FEATURE_MAP above.
INVERTED_FEATURES: frozenset[str] = frozenset({"no-ml", "no-mmu"})

# Drivers a safety decision reads (RFC-0040's table, rule 1; the list is
# written out in config/Kconfig.drivers): never placed in ring 3. None has a
# placement choice; a .config that places one there anyway (a choice added
# by mistake, or a hand-edited file) is refused rather than built.
SAFETY_READ_DRIVERS: frozenset[str] = frozenset({
    "CLINT", "PLIC", "WDT", "PWM", "GPIO", "MOTOR", "MOTOR_PID", "ESC", "RC",
    "I2C", "IMU", "RANGEFINDER", "ADS1115", "UART", "VIRTIO_BLK", "MMC",
})


def placement_features(cfg: dict[str, str]) -> list[str]:
    """The kernel features the .config's driver placement choices map to."""
    return [f for k, f in KCONFIG_TO_CARGO_FEATURE.items()
            if f and k.startswith("CONFIG_DRV_") and "_PLACEMENT_" in k and cfg.get(k) == "y"]


def placement_violations(cfg: dict[str, str]) -> list[str]:
    """The `CONFIG_DRV_<NAME>_PLACEMENT_RING3=y` lines naming a driver that a
    safety decision reads."""
    return [k for k, v in cfg.items()
            if v == "y" and k.startswith("CONFIG_DRV_") and k.endswith("_PLACEMENT_RING3")
            and k[len("CONFIG_DRV_"):-len("_PLACEMENT_RING3")] in SAFETY_READ_DRIVERS]


# The kernel feature a DOMAIN_ROBOT .config needs, and that every other
# domain must leave out of the kernel's `default` list.
DOMAIN_FEATURE = "domain-robot"

KERNEL_CARGO_TOML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kernel", "Cargo.toml")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DOT_CONFIG_DEFAULT = ".config"


def kernel_default_features(cargo_toml: str = KERNEL_CARGO_TOML) -> list[str]:
    """The kernel's `[features] default` list, read from kernel/Cargo.toml.

    Read, not copied: a second copy of the list here would drift from the
    one cargo uses (it has before, for other lists in this tree).
    """
    # No `tomllib`: the gate runs this under /usr/bin/python3 (3.9 on macOS).
    # The `default = [...]` entry of `[features]`, possibly over several
    # lines; comments and the other entries are skipped.
    import re
    text = open(cargo_toml, encoding="utf-8").read()
    sec = re.search(r"^\[features\]\s*$(.*?)(?=^\[)", text, re.M | re.S)
    if sec is None:
        raise SystemExit(f"kconfig_to_cargo: no [features] in {cargo_toml}")
    body = "\n".join(l.split("#", 1)[0] for l in sec.group(1).splitlines())
    m = re.search(r"^default\s*=\s*\[(.*?)\]", body, re.M | re.S)
    if m is None:
        raise SystemExit(f"kconfig_to_cargo: no `default` feature list in {cargo_toml}")
    return re.findall(r'"([^"]+)"', m.group(1))


def domain_args(cfg: dict[str, str], feats: list[str],
                cargo_toml: str = KERNEL_CARGO_TOML) -> tuple[bool, list[str]]:
    """Apply the application domain to the feature list.

    Returns `(no_default_features, features)`. A DOMAIN_ROBOT .config keeps
    the kernel's defaults (which include `domain-robot`). Any other domain
    turns the defaults off and adds them back without `domain-robot`, ahead
    of the features the .config maps to.
    """
    if cfg.get("CONFIG_DOMAIN_ROBOT") == "y":
        return False, feats
    defaults = [f for f in kernel_default_features(cargo_toml) if f != DOMAIN_FEATURE]
    out = defaults + [f for f in feats if f not in defaults and f != DOMAIN_FEATURE]
    return True, out


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
                # Record "not set" patterns as "n" so INVERTED_FEATURE_MAP can see them.
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

    # --- Explicit inverted mapping ---
    # Fire only when the option is explicitly disabled in the defconfig
    # ("# CONFIG_FOO is not set" → stored as "n").  We do NOT fire on absent
    # keys because minimal defconfigs omit options that are at their defaults,
    # and the default for DRV_ML_INFERENCE is y (ML enabled).  Only an explicit
    # disable line means "turn this feature off".
    for kconfig_key, cargo_feat in INVERTED_FEATURE_MAP.items():
        val = cfg.get(kconfig_key)
        if val == "n":
            add(cargo_feat)

    return features


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = sys.argv[1:]
    # `--domain-only`: only the domain's effect on the cargo defaults
    # (`--no-default-features --features <rest of default>` outside
    # DOMAIN_ROBOT, nothing for it), plus the driver placement features. For Makefile targets that name their own
    # board features by hand (`make build` is `--features qemu`), so the
    # application domain chosen in `make config` still decides the crates.
    domain_only = "--domain-only" in args
    args = [a for a in args if a != "--domain-only"]
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

    if domain_only:
        # Driver placement is not a board feature either: `make build`
        # (`--features qemu` by hand) honours DRV_<NAME>_PLACEMENT too.
        no_default, feats = domain_args(cfg, placement_features(cfg))
        if no_default:
            print(f"--no-default-features --features {','.join(feats)}")
        elif feats:
            print(f"--features {','.join(feats)}")
        return 0

    parts: list[str] = []

    # --target (always emitted; defaults to riscv64 if not set)
    target = arch_target(cfg)
    parts.append(f"--target {target}")

    # --features (and --no-default-features outside DOMAIN_ROBOT)
    no_default, feats = domain_args(cfg, enabled_features(cfg))
    if no_default:
        parts.append("--no-default-features")
    if feats:
        parts.append(f"--features {','.join(feats)}")

    if parts:
        print(" ".join(parts))

    return 0


if __name__ == "__main__":
    sys.exit(main())

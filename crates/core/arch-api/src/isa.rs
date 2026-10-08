// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hardware-support model every ISA shares (config/Kconfig.arch):
//! a baseline level per ISA, then each optional extension a three-way
//! `make config` choice — [`ExtPolicy`] — resolved at boot against what
//! the CPU reports into an [`ExtState`]. The boot prints one `[ISA]` line
//! ([`write_report`]) and refuses a CPU that lacks a `require`d extension.
//!
//! The per-ISA policy tables ([`riscv64`], [`aarch64`], [`x86_64`]) come
//! from the generated `azos_limits` consts, so every ISA's table compiles
//! on every build (a choice hidden by `if ARCH_*` reads as all-`n`
//! members, i.e. [`ExtPolicy::Probe`]; nothing reads another ISA's table).

use core::fmt;

/// One extension's `make config` choice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExtPolicy {
    /// `n`: never used, even when the CPU has it.
    Never,
    /// `probe`: compiled in, used only when the boot probe finds it.
    Probe,
    /// `require`: baseline; the boot refuses a CPU without it.
    Require,
}

impl ExtPolicy {
    /// From the choice's `_NEVER` and `_REQUIRE` members (`_PROBE` is the
    /// remaining case, and what an unset choice reads as).
    pub const fn from_kconfig(never: bool, require: bool) -> Self {
        if never {
            ExtPolicy::Never
        } else if require {
            ExtPolicy::Require
        } else {
            ExtPolicy::Probe
        }
    }

    /// May the boot select the extension's path at all?
    pub const fn allowed(self) -> bool {
        !matches!(self, ExtPolicy::Never)
    }

    /// The selection input for a path: the hardware's answer, unless the
    /// policy is `n`.
    pub const fn gate(self, present: bool) -> bool {
        self.allowed() && present
    }

    /// What `present` means under this policy.
    pub const fn resolve(self, present: bool) -> ExtState {
        match (self, present) {
            (ExtPolicy::Never, _) => ExtState::Off,
            (ExtPolicy::Probe, true) => ExtState::Present,
            (ExtPolicy::Probe, false) => ExtState::Absent,
            (ExtPolicy::Require, true) => ExtState::Required,
            (ExtPolicy::Require, false) => ExtState::Missing,
        }
    }
}

/// An extension after the boot probe.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExtState {
    /// `n`: not used, whatever the CPU has.
    Off,
    /// `probe`, and the CPU has it: in use.
    Present,
    /// `probe`, and the CPU lacks it: the fallback.
    Absent,
    /// `require`, and the CPU has it.
    Required,
    /// `require`, and the CPU lacks it: the boot refuses.
    Missing,
}

impl ExtState {
    /// The word the `[ISA]` boot line prints.
    pub const fn label(self) -> &'static str {
        match self {
            ExtState::Off => "n",
            ExtState::Present => "probed-present",
            ExtState::Absent => "probed-absent",
            ExtState::Required => "required",
            ExtState::Missing => "MISSING",
        }
    }

    /// In use on this boot.
    pub const fn in_use(self) -> bool {
        matches!(self, ExtState::Present | ExtState::Required)
    }
}

/// One row of an ISA's report: the name the boot line prints, the Kconfig
/// choice it comes from (named in the refusal), the policy, and what the
/// probe found.
#[derive(Clone, Copy, Debug)]
pub struct Ext {
    pub name: &'static str,
    pub symbol: &'static str,
    pub policy: ExtPolicy,
    pub present: bool,
}

impl Ext {
    pub const fn state(&self) -> ExtState {
        self.policy.resolve(self.present)
    }
}

/// The first `require`d extension the CPU lacks.
pub fn first_missing(exts: &[Ext]) -> Option<&Ext> {
    exts.iter().find(|e| e.state() == ExtState::Missing)
}

/// `[ISA] baseline=<level> <name>=<state> ...` — one line, no newline.
pub fn write_report<W: fmt::Write>(w: &mut W, baseline: &str, exts: &[Ext]) -> fmt::Result {
    write!(w, "[ISA] baseline={}", baseline)?;
    for e in exts {
        write!(w, " {}={}", e.name, e.state().label())?;
    }
    Ok(())
}

/// The refusal line for a `require`d extension the CPU lacks, no newline.
pub fn write_refusal<W: fmt::Write>(w: &mut W, e: &Ext) -> fmt::Result {
    write!(w, "[ISA] FATAL: {} is `require` (Kconfig {}_REQUIRE) but this CPU does not \
               implement it; refusing to boot. Choose probe or n in make config, or \
               boot a CPU that has it.", e.name, e.symbol)
}

/// The refusal line for a CPU below the baseline level, no newline.
pub fn write_level_refusal<W: fmt::Write>(w: &mut W, level: &str, missing: &str) -> fmt::Result {
    write!(w, "[ISA] FATAL: the baseline is {} but this CPU lacks {}; refusing to boot. \
               Lower the level in make config, or boot a CPU that implements it.", level, missing)
}

/// `ExtPolicy` of a Kconfig choice from its generated `_NEVER`/`_REQUIRE` members.
macro_rules! ext_policy {
    ($never:ident, $require:ident) => {
        $crate::isa::ExtPolicy::from_kconfig(azos_limits::$never, azos_limits::$require)
    };
}

/// riscv64 (config/Kconfig.arch `RISCV64_LEVEL`, `RV_*`).
pub mod riscv64 {
    use super::ExtPolicy;

    /// The baseline's name, as the boot line prints it.
    pub const LEVEL: &str = if azos_limits::RISCV64_LEVEL_RV64GCV {
        "rv64gcv"
    } else if azos_limits::RISCV64_LEVEL_RV64GC {
        "rv64gc"
    } else {
        "rv64imac"
    };
    /// The level's single-letter extensions beyond `imac` the boot checks
    /// in cpu@0's `riscv,isa`.
    pub const LEVEL_NEEDS_FD: bool = azos_limits::RISCV64_LEVEL_RV64GC || azos_limits::RISCV64_LEVEL_RV64GCV;
    pub const LEVEL_NEEDS_V: bool = azos_limits::RISCV64_LEVEL_RV64GCV;

    pub const ZICBOZ: ExtPolicy = ext_policy!(RV_ZICBOZ_NEVER, RV_ZICBOZ_REQUIRE);
    pub const SSTC: ExtPolicy = ext_policy!(RV_SSTC_NEVER, RV_SSTC_REQUIRE);
    pub const SVPBMT: ExtPolicy = ext_policy!(RV_SVPBMT_NEVER, RV_SVPBMT_REQUIRE);
    pub const ZBA: ExtPolicy = ext_policy!(RV_ZBA_NEVER, RV_ZBA_REQUIRE);
    pub const ZBB: ExtPolicy = ext_policy!(RV_ZBB_NEVER, RV_ZBB_REQUIRE);
    pub const ZBS: ExtPolicy = ext_policy!(RV_ZBS_NEVER, RV_ZBS_REQUIRE);
    pub const V: ExtPolicy = ext_policy!(RV_V_NEVER, RV_V_REQUIRE);
    pub const AIA: ExtPolicy = ext_policy!(RV_AIA_NEVER, RV_AIA_REQUIRE);
}

/// aarch64 (config/Kconfig.arch `AARCH64_LEVEL`, `A64_*`).
pub mod aarch64 {
    use super::ExtPolicy;

    /// The baseline as a minor version of Armv8 (0..=5).
    pub const LEVEL_MINOR: u8 = if azos_limits::AARCH64_LEVEL_8_5 {
        5
    } else if azos_limits::AARCH64_LEVEL_8_4 {
        4
    } else if azos_limits::AARCH64_LEVEL_8_3 {
        3
    } else if azos_limits::AARCH64_LEVEL_8_2 {
        2
    } else if azos_limits::AARCH64_LEVEL_8_1 {
        1
    } else {
        0
    };
    /// The baseline's name, as the boot line prints it.
    pub const LEVEL: &str = ["armv8.0", "armv8.1", "armv8.2", "armv8.3", "armv8.4", "armv8.5"]
        [LEVEL_MINOR as usize];

    pub const LSE: ExtPolicy = ext_policy!(A64_LSE_NEVER, A64_LSE_REQUIRE);
    pub const CRC32: ExtPolicy = ext_policy!(A64_CRC32_NEVER, A64_CRC32_REQUIRE);
    pub const PAUTH: ExtPolicy = ext_policy!(A64_PAUTH_NEVER, A64_PAUTH_REQUIRE);
    pub const BTI: ExtPolicy = ext_policy!(A64_BTI_NEVER, A64_BTI_REQUIRE);
    pub const MTE: ExtPolicy = ext_policy!(A64_MTE_NEVER, A64_MTE_REQUIRE);
    pub const SVE: ExtPolicy = ext_policy!(A64_SVE_NEVER, A64_SVE_REQUIRE);
    pub const AES: ExtPolicy = ext_policy!(A64_AES_NEVER, A64_AES_REQUIRE);
    pub const PMULL: ExtPolicy = ext_policy!(A64_PMULL_NEVER, A64_PMULL_REQUIRE);
    pub const SHA2: ExtPolicy = ext_policy!(A64_SHA2_NEVER, A64_SHA2_REQUIRE);
}

/// x86_64 (config/Kconfig.arch `X86_64_LEVEL`, `X86_*`).
pub mod x86_64 {
    use super::ExtPolicy;

    /// The baseline's name, as the boot line prints it.
    pub const LEVEL: &str = if azos_limits::X86_64_LEVEL_V3 {
        "x86-64-v3"
    } else if azos_limits::X86_64_LEVEL_V1 {
        "x86-64"
    } else {
        "x86-64-v2"
    };

    pub const SMEP: ExtPolicy = ext_policy!(X86_SMEP_NEVER, X86_SMEP_REQUIRE);
    pub const SMAP: ExtPolicy = ext_policy!(X86_SMAP_NEVER, X86_SMAP_REQUIRE);
    pub const PCID: ExtPolicy = ext_policy!(X86_PCID_NEVER, X86_PCID_REQUIRE);
    pub const FSGSBASE: ExtPolicy = ext_policy!(X86_FSGSBASE_NEVER, X86_FSGSBASE_REQUIRE);
    pub const TSC_DEADLINE: ExtPolicy = ext_policy!(X86_TSC_DEADLINE_NEVER, X86_TSC_DEADLINE_REQUIRE);
    pub const X2APIC: ExtPolicy = ext_policy!(X86_X2APIC_NEVER, X86_X2APIC_REQUIRE);
    pub const XSAVEOPT: ExtPolicy = ext_policy!(X86_XSAVEOPT_NEVER, X86_XSAVEOPT_REQUIRE);
    pub const AVX2: ExtPolicy = ext_policy!(X86_AVX2_NEVER, X86_AVX2_REQUIRE);
    pub const SHA_NI: ExtPolicy = ext_policy!(X86_SHA_NI_NEVER, X86_SHA_NI_REQUIRE);
}

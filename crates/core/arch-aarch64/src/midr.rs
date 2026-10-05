// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! MIDR_EL1 — Main ID Register — implementer / part-number /
//! revision decoder. Mirror of `arch-x86_64::cpuid`.
//!
//! Used by boot log + procfs to identify the CPU model and gate
//! per-core errata workarounds.

#![allow(dead_code)]

/// Decoded MIDR_EL1.
#[derive(Clone, Copy, Debug)]
pub struct Midr {
    pub raw:         u64,
    pub implementer: u8,
    pub variant:     u8,
    pub architecture:u8,
    pub part_num:    u16,
    pub revision:    u8,
}

impl Midr {
    /// JEP106 implementer codes — the common ones a robotics
    /// kernel will actually see. Codes are 7-bit; bit 7 is the
    /// continuation flag (ignored here).
    pub const IMPL_ARM:       u8 = 0x41; // 'A'
    pub const IMPL_BROADCOM:  u8 = 0x42;
    pub const IMPL_CAVIUM:    u8 = 0x43;
    pub const IMPL_DEC:       u8 = 0x44;
    pub const IMPL_FUJITSU:   u8 = 0x46;
    pub const IMPL_INFINEON:  u8 = 0x49;
    pub const IMPL_MOTOROLA:  u8 = 0x4D;
    pub const IMPL_NVIDIA:    u8 = 0x4E;
    pub const IMPL_APM:       u8 = 0x50;
    pub const IMPL_QUALCOMM:  u8 = 0x51;
    pub const IMPL_MARVELL:   u8 = 0x56;
    pub const IMPL_INTEL:     u8 = 0x69;
    pub const IMPL_AMPERE:    u8 = 0xC0;
    pub const IMPL_APPLE:     u8 = 0x61;

    /// ARM Limited part numbers. The kernel uses these to gate
    /// per-µarch quirks (e.g. cortex-a72 erratum 832075).
    pub const PART_CORTEX_A53:    u16 = 0xD03;
    pub const PART_CORTEX_A57:    u16 = 0xD07;
    pub const PART_CORTEX_A72:    u16 = 0xD08; // QEMU virt default
    pub const PART_CORTEX_A73:    u16 = 0xD09;
    pub const PART_CORTEX_A55:    u16 = 0xD05;
    pub const PART_CORTEX_A75:    u16 = 0xD0A;
    pub const PART_CORTEX_A76:    u16 = 0xD0B;
    pub const PART_CORTEX_A78:    u16 = 0xD41;
    pub const PART_NEOVERSE_N1:   u16 = 0xD0C;
    pub const PART_NEOVERSE_V1:   u16 = 0xD40;
    pub const PART_NEOVERSE_N2:   u16 = 0xD49;

    pub fn implementer_name(&self) -> &'static str {
        match self.implementer {
            Self::IMPL_ARM      => "ARM",
            Self::IMPL_BROADCOM => "Broadcom",
            Self::IMPL_CAVIUM   => "Cavium",
            Self::IMPL_FUJITSU  => "Fujitsu",
            Self::IMPL_NVIDIA   => "NVIDIA",
            Self::IMPL_APM      => "Applied Micro",
            Self::IMPL_QUALCOMM => "Qualcomm",
            Self::IMPL_MARVELL  => "Marvell",
            Self::IMPL_INTEL    => "Intel",
            Self::IMPL_AMPERE   => "Ampere",
            Self::IMPL_APPLE    => "Apple",
            _                   => "Unknown",
        }
    }

    /// Best-effort part-name lookup for ARM-implemented cores.
    /// Non-ARM implementers reuse the part-num field for their
    /// own product lines so this only resolves names when
    /// `implementer == IMPL_ARM`.
    pub fn part_name(&self) -> &'static str {
        if self.implementer != Self::IMPL_ARM {
            return "non-ARM impl";
        }
        match self.part_num {
            Self::PART_CORTEX_A53    => "Cortex-A53",
            Self::PART_CORTEX_A55    => "Cortex-A55",
            Self::PART_CORTEX_A57    => "Cortex-A57",
            Self::PART_CORTEX_A72    => "Cortex-A72",
            Self::PART_CORTEX_A73    => "Cortex-A73",
            Self::PART_CORTEX_A75    => "Cortex-A75",
            Self::PART_CORTEX_A76    => "Cortex-A76",
            Self::PART_CORTEX_A78    => "Cortex-A78",
            Self::PART_NEOVERSE_N1   => "Neoverse-N1",
            Self::PART_NEOVERSE_V1   => "Neoverse-V1",
            Self::PART_NEOVERSE_N2   => "Neoverse-N2",
            _                        => "Unknown ARM core",
        }
    }
}

/// Read MIDR_EL1 and decode.
#[cfg(target_arch = "aarch64")]
pub fn read_midr() -> Midr {
    let raw: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, MIDR_EL1",
            out(reg) raw,
            options(nomem, nostack, preserves_flags),
        );
    }
    Midr {
        raw,
        implementer:  ((raw >> 24) & 0xFF) as u8,
        variant:      ((raw >> 20) & 0xF)  as u8,
        architecture: ((raw >> 16) & 0xF)  as u8,
        part_num:     ((raw >> 4)  & 0xFFF) as u16,
        revision:     ( raw        & 0xF)  as u8,
    }
}

/// Read REVIDR_EL1 — implementer-defined revision details. The
/// kernel uses it as part of erratum-matching tuples (impl, part,
/// variant, revision, revidr) for per-silicon-revision quirks.
#[cfg(target_arch = "aarch64")]
pub fn read_revidr() -> u64 {
    let raw: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, REVIDR_EL1",
            out(reg) raw,
            options(nomem, nostack, preserves_flags),
        );
    }
    raw
}

// ── Host-build stubs ────────────────────────────────────────

#[cfg(not(target_arch = "aarch64"))]
pub fn read_midr() -> Midr {
    Midr { raw: 0, implementer: 0, variant: 0, architecture: 0,
           part_num: 0, revision: 0 }
}
#[cfg(not(target_arch = "aarch64"))]
pub fn read_revidr() -> u64 { 0 }

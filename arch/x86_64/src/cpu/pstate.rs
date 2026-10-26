// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What this x86_64 PC can do about its own clock and energy: the probe behind
//! the thermal framework's level request and meter (`azos_thermal::x86`,
//! `kernel/src/entry/x86_64/ext/thermal_hw.rs`). The temperature sensor is not
//! here: `azos_thermal::x86_sensor::probe` decides that one.
//!
//! * **Performance level.** Intel HWP (`CPUID.6:EAX[7]`) and AMD CPPC
//!   (`CPUID.80000008:EBX[27]`) take a minimum and a maximum level per logical
//!   CPU.
//! * **Energy.** RAPL's package counter: Intel parts since Sandy Bridge, AMD
//!   Zen (`CPUID.80000007:EDX[14]`).
//!
//! # No fixup, so no guessing
//!
//! A `rdmsr` of an MSR the CPU lacks raises #GP, and the kernel has no
//! exception-table fixup for it. So nothing here is ever "tried": every MSR
//! the board touches is behind a bit this probe read first, and where the
//! architecture publishes no bit (RAPL on Intel) the gate is the vendor, the
//! family and the model, from the list Linux keeps for the same reason.
//!
//! A hypervisor (`CPUID.1:ECX[31]`) is treated as a machine with none of it:
//! QEMU's TCG implements no HWP, CPPC or RAPL, and a guest that sees one of
//! those MSRs through a hypervisor gets the hypervisor's stub, not the
//! part's. The result is the fallback every consumer already has (no
//! actuator, no meter: nothing is touched, invariant I4). Real-hardware
//! confirmation of the model gate is the testing week's.
//!
//! The whole module is pure arithmetic over a [`PstateCpuid`] snapshot, so the
//! host suite (`tests/host/arch-tests/src/pstate_x86.rs`) runs it; only
//! [`read`] executes `cpuid`. The MSR layouts live with their one user,
//! `azos_thermal::x86`.

use super::features::{decode_ident, CpuIdent, CpuidLeaves, Vendor};

/// CPUID.1:ECX[31]: running under a hypervisor.
const L1_ECX_HYPERVISOR: u32 = 1 << 31;
/// CPUID.6:EAX[7]: hardware-controlled performance states.
const L6_EAX_HWP: u32 = 1 << 7;
/// CPUID.80000007:EDX[14]: AMD's RAPL.
const E7_EDX_RAPL: u32 = 1 << 14;
/// CPUID.80000008:EBX[27]: AMD's collaborative performance control.
const E8_EBX_CPPC: u32 = 1 << 27;

/// First AMD family with CPPC and RAPL (Zen 1 is 0x17).
pub const AMD_ZEN_FAMILY: u16 = 0x17;
/// First Intel display model of the family-6 parts whose RAPL package energy
/// counter has no quirk (Haswell). Below it only the four Sandy and Ivy
/// Bridge models in [`intel_rapl`] qualify.
const INTEL_HASWELL: u16 = 0x3C;

/// The CPUID words this probe reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PstateCpuid {
    /// The words `features` already reads (vendor, family and model, the
    /// hypervisor bit, `CPUID.80000007:EDX`, `CPUID.80000008:EBX`).
    pub base: CpuidLeaves,
    /// CPUID.6:EAX — thermal and power management.
    pub l6_eax: u32,
}

/// How a performance level is requested.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Perf {
    /// The CPU takes no level request: the actuator refuses every one.
    None,
    /// Intel HWP.
    Hwp,
    /// AMD CPPC.
    Cppc,
}

/// How energy is measured.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Meter {
    /// No counter.
    None,
    /// Intel RAPL.
    Intel,
    /// AMD RAPL.
    Amd,
}

/// What the probe found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Caps {
    /// The level request.
    pub perf: Perf,
    /// The energy counter.
    pub meter: Meter,
}

impl Caps {
    /// Nothing: a hypervisor, an unknown vendor, a CPU without the bits.
    pub const NONE: Self = Self { perf: Perf::None, meter: Meter::None };

    /// Whether the machine has either.
    pub const fn any(&self) -> bool {
        !matches!(self.perf, Perf::None) || !matches!(self.meter, Meter::None)
    }
}

/// Whether an Intel family-6 part has RAPL's package energy counter in the
/// layout the board reads (MSR_RAPL_POWER_UNIT, MSR_PKG_ENERGY_STATUS): Sandy
/// and Ivy Bridge, then Haswell and every later core. Not the Silvermont and
/// Airmont Atoms (their energy unit is a different field) nor Xeon Phi.
const fn intel_rapl(model: u16) -> bool {
    match model {
        0x2A | 0x2D | 0x3A | 0x3E => true,
        0x4A | 0x4C | 0x4D | 0x57 | 0x5A | 0x5D | 0x85 => false,
        m => m >= INTEL_HASWELL,
    }
}

/// Decode what this CPU offers. Pure.
pub const fn probe(c: &PstateCpuid) -> Caps {
    let id: CpuIdent = decode_ident(&c.base);
    if c.base.l1_ecx & L1_ECX_HYPERVISOR != 0 {
        return Caps::NONE;
    }
    match id.vendor {
        Vendor::Intel if id.family == 6 => Caps {
            perf: if c.l6_eax & L6_EAX_HWP != 0 { Perf::Hwp } else { Perf::None },
            meter: if intel_rapl(id.model) { Meter::Intel } else { Meter::None },
        },
        Vendor::Amd if id.family >= AMD_ZEN_FAMILY => Caps {
            perf: if c.base.e8_ebx & E8_EBX_CPPC != 0 { Perf::Cppc } else { Perf::None },
            meter: if c.base.e7_edx & E7_EDX_RAPL != 0 { Meter::Amd } else { Meter::None },
        },
        _ => Caps::NONE,
    }
}

/// Execute `cpuid` for the words [`PstateCpuid`] holds. Zero off bare-metal
/// x86_64 (the same rule as [`super::features::read_cpuid`]).
pub fn read() -> PstateCpuid {
    #[allow(unused_mut)]
    let mut r = PstateCpuid { base: super::features::read_cpuid(), ..PstateCpuid::default() };
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        use core::arch::x86_64::__cpuid_count;
        if __cpuid_count(0, 0).eax >= 6 {
            r.l6_eax = __cpuid_count(6, 0).eax;
        }
    }
    r
}

/// The caps of the CPU that runs this.
pub fn detect() -> Caps {
    probe(&read())
}

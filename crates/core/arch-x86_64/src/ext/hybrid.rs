// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Core types of an x86 hybrid CPU: what each logical processor says about
//! itself, for the energy model's capacity classes
//! (`azos_energy::model::CoreClass`, Kconfig `ENERGY`).
//!
//! * **Intel.** `CPUID.(7,0):EDX[15]` says the part is hybrid; leaf 0x1A
//!   `EAX[31:24]` is the core type of the logical processor that executes it:
//!   0x40 Core (P), 0x20 Atom (E).
//! * **AMD.** `CPUID.0x80000026:EAX[30]` says the part has heterogeneous
//!   cores; `EBX[31:28]` is the core type: 0 performance (Zen 5), 1
//!   efficiency (Zen 5c). The encodings are the ones Linux reads
//!   (`arch/x86/kernel/cpu/topology_common.c`); no AMD hybrid part has run
//!   this decode yet.
//!
//! **The answer is per logical processor**: CPUID reports the CPU that runs
//! it, and nothing lets one CPU ask another. Each CPU therefore records its
//! own kind as it comes up ([`record_this_cpu`], the boot CPU from the energy
//! install, an AP from its entry), and whoever builds the model reads the
//! records once every CPU is up ([`recorded`]).
//!
//! Everything but [`read_this_cpu`] is pure, and the host suite
//! (`tests/host/energy-tests/src/cpuid.rs`) runs it on synthetic CPUID words.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::cpu::features::Vendor;

/// What one logical processor says about its core type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreKind {
    /// The CPU is not hybrid, or reports no core type.
    Uniform,
    /// A performance core (Intel Core, AMD Zen 5).
    Performance,
    /// An efficiency core (Intel Atom, AMD Zen 5c).
    Efficiency,
    /// The CPU says it is hybrid and reports a type this decode does not know.
    Unrecognised,
}

/// The CPUID words the decode reads, as the executing CPU reports them. A
/// leaf above the CPU's maximum reads as zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HybridLeaves {
    /// Vendor, from CPUID.0.
    pub vendor: Vendor,
    /// CPUID.(7,0):EDX — bit 15 is "hybrid" on Intel.
    pub l7_edx: u32,
    /// CPUID.0x1A:EAX — the core type in bits 31:24 (Intel).
    pub l1a_eax: u32,
    /// CPUID.0x80000026:EAX — bit 30 is "heterogeneous cores" (AMD).
    pub e26_eax: u32,
    /// CPUID.0x80000026:EBX — the core type in bits 31:28 (AMD).
    pub e26_ebx: u32,
}

/// `CPUID.(7,0):EDX`: the part is hybrid.
const L7_EDX_HYBRID: u32 = 1 << 15;
/// `CPUID.0x1A:EAX[31:24]`: Intel Atom (E) and Core (P).
const INTEL_ATOM: u32 = 0x20;
const INTEL_CORE: u32 = 0x40;
/// `CPUID.0x80000026:EAX`: heterogeneous cores.
const E26_EAX_HETERO: u32 = 1 << 30;

/// The kind of the CPU that read `l`.
pub const fn decode(l: &HybridLeaves) -> CoreKind {
    match l.vendor {
        Vendor::Intel => {
            if l.l7_edx & L7_EDX_HYBRID == 0 {
                return CoreKind::Uniform;
            }
            match l.l1a_eax >> 24 {
                INTEL_CORE => CoreKind::Performance,
                INTEL_ATOM => CoreKind::Efficiency,
                _ => CoreKind::Unrecognised,
            }
        }
        Vendor::Amd => {
            if l.e26_eax & E26_EAX_HETERO == 0 {
                return CoreKind::Uniform;
            }
            match l.e26_ebx >> 28 {
                0 => CoreKind::Performance,
                1 => CoreKind::Efficiency,
                _ => CoreKind::Unrecognised,
            }
        }
        // Hygon's Zen derivative has no hybrid part; an unknown vendor's
        // leaves mean nothing.
        _ => CoreKind::Uniform,
    }
}

/// Execute `cpuid` for the words [`HybridLeaves`] holds, each guarded by the
/// CPU's maximum leaf. All zero off the target (a host x86_64 test process
/// must not mistake its own CPU for the target's).
pub fn read_this_cpu() -> HybridLeaves {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        use crate::cpu::features::{decode_ident, CpuidLeaves};
        use core::arch::x86_64::__cpuid_count;
        let l0 = __cpuid_count(0, 0);
        let max = l0.eax;
        let max_ext = __cpuid_count(0x8000_0000, 0).eax;
        let ident = CpuidLeaves { l0_vendor: [l0.ebx, l0.edx, l0.ecx], ..CpuidLeaves::ZERO };
        let mut r = HybridLeaves { vendor: decode_ident(&ident).vendor, ..HybridLeaves::default() };
        if max >= 7 {
            r.l7_edx = __cpuid_count(7, 0).edx;
        }
        if max >= 0x1A {
            r.l1a_eax = __cpuid_count(0x1A, 0).eax;
        }
        if max_ext >= 0x8000_0026 {
            let e26 = __cpuid_count(0x8000_0026, 0);
            (r.e26_eax, r.e26_ebx) = (e26.eax, e26.ebx);
        }
        r
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    {
        HybridLeaves::default()
    }
}

/// CPUs whose kind can be recorded: the energy model names at most 32
/// (`azos_energy::model::MAX_MODEL_CPUS`).
pub const MAX_RECORDED: usize = 32;

/// Per CPU: 0 not recorded, else `kind + 1`.
static RECORDED: [AtomicU8; MAX_RECORDED] = [const { AtomicU8::new(0) }; MAX_RECORDED];

const fn code(k: CoreKind) -> u8 {
    match k {
        CoreKind::Uniform => 1,
        CoreKind::Performance => 2,
        CoreKind::Efficiency => 3,
        CoreKind::Unrecognised => 4,
    }
}

/// Record `kind` as CPU `cpu`'s. A CPU past [`MAX_RECORDED`] is not recorded.
pub fn record(cpu: usize, kind: CoreKind) {
    if let Some(slot) = RECORDED.get(cpu) {
        slot.store(code(kind), Ordering::Release);
    }
}

/// Read the calling CPU's kind and record it as CPU `cpu`'s; returns it.
pub fn record_this_cpu(cpu: usize) -> CoreKind {
    let kind = decode(&read_this_cpu());
    record(cpu, kind);
    kind
}

/// The kind CPU `cpu` recorded; `None` if it has not (it never came up, or it
/// is past [`MAX_RECORDED`]).
pub fn recorded(cpu: usize) -> Option<CoreKind> {
    match RECORDED.get(cpu)?.load(Ordering::Acquire) {
        1 => Some(CoreKind::Uniform),
        2 => Some(CoreKind::Performance),
        3 => Some(CoreKind::Efficiency),
        4 => Some(CoreKind::Unrecognised),
        _ => None,
    }
}

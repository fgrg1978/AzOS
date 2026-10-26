// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 PC power probe (`arch/x86_64/src/cpu/pstate.rs`): which
//! of the level request (HWP, CPPC) and the energy counter (RAPL) a CPU is
//! allowed to be asked for. The temperature sensor is `azos_thermal::x86_sensor`'s.
//!
//! The mistake that matters is silent until a real machine: the kernel has no
//! fixup for a `rdmsr` of an MSR the CPU lacks, so a gate that lets one
//! through is a #GP in the thermal task. Every gate has a test that flips only
//! that gate, and the machine QEMU's TCG presents (hypervisor bit set, none of
//! the bits) is asserted to be the empty answer.
//!
//! Canaries (by hand, each must turn the named test red): drop the
//! hypervisor test in `probe` -> `a_hypervisor_has_none_of_it`; make
//! `intel_rapl` accept every model -> `intel_rapl_is_for_the_models_that_have_it`;
//! read `E8_EBX_CPPC` from bit 26 -> `cppc_is_its_own_cpuid_bit_on_amd_only`.

use crate::cpu::features::CpuidLeaves;
use crate::cpu::pstate::*;

const GENUINE_INTEL: [u32; 3] = [u32::from_le_bytes(*b"Genu"), u32::from_le_bytes(*b"ineI"), u32::from_le_bytes(*b"ntel")];
const AUTHENTIC_AMD: [u32; 3] = [u32::from_le_bytes(*b"Auth"), u32::from_le_bytes(*b"enti"), u32::from_le_bytes(*b"cAMD")];
const HYGON: [u32; 3] = [u32::from_le_bytes(*b"Hygo"), u32::from_le_bytes(*b"nGen"), u32::from_le_bytes(*b"uine")];

const HWP: u32 = 1 << 7;
const HYPERVISOR: u32 = 1 << 31;

/// CPUID.1:EAX of a family-6 part with this display model.
fn eax_intel(model: u16) -> u32 {
    let (ext, base) = ((model >> 4) as u32, (model & 0xF) as u32);
    ext << 16 | 6 << 8 | base << 4 | 1
}

/// CPUID.1:EAX of an AMD part of display family `fam` (>= 0x10).
fn eax_amd(fam: u32) -> u32 {
    (fam - 0xF) << 20 | 0xF << 8 | 1
}

fn intel(model: u16, l6_eax: u32) -> PstateCpuid {
    PstateCpuid {
        base: CpuidLeaves { l0_vendor: GENUINE_INTEL, l1_eax: eax_intel(model), ..CpuidLeaves::ZERO },
        l6_eax,
    }
}

fn amd(fam: u32, e7_edx: u32, e8_ebx: u32) -> PstateCpuid {
    PstateCpuid {
        base: CpuidLeaves { l0_vendor: AUTHENTIC_AMD, l1_eax: eax_amd(fam), e7_edx, e8_ebx, ..CpuidLeaves::ZERO },
        l6_eax: 0,
    }
}

#[test]
fn off_bare_metal_cpuid_reads_as_nothing() {
    assert_eq!(read(), PstateCpuid::default());
    assert_eq!(detect(), Caps::NONE);
    assert!(!Caps::NONE.any());
}

#[test]
fn a_hypervisor_has_none_of_it() {
    // QEMU TCG: the hypervisor bit, and not one of the power bits. KVM may
    // pass some through; its MSRs are the hypervisor's stubs, not the part's.
    let mut tcg = intel(0x6A, HWP);
    tcg.base.l1_ecx = HYPERVISOR;
    assert_eq!(probe(&tcg), Caps::NONE);
    let mut zen = amd(0x19, 1 << 14, 1 << 27);
    zen.base.l1_ecx = HYPERVISOR;
    assert_eq!(probe(&zen), Caps::NONE);
    // The same CPUs bare.
    assert!(probe(&intel(0x6A, HWP)).any());
    assert!(probe(&amd(0x19, 1 << 14, 1 << 27)).any());
}

#[test]
fn hwp_is_its_own_cpuid_bit_on_intel_only() {
    assert_eq!(probe(&intel(0x8E, HWP)).perf, Perf::Hwp);
    assert_eq!(probe(&intel(0x8E, 0)).perf, Perf::None);
    // The bit means nothing on the other vendors (leaf 6 is not read for them).
    let mut a = amd(0x19, 0, 0);
    a.l6_eax = HWP;
    assert_eq!(probe(&a).perf, Perf::None);
}

#[test]
fn cppc_is_its_own_cpuid_bit_on_amd_only() {
    assert_eq!(probe(&amd(0x19, 0, 1 << 27)).perf, Perf::Cppc);
    assert_eq!(probe(&amd(0x19, 0, 1 << 26)).perf, Perf::None);
    assert_eq!(probe(&amd(0x19, 0, 0)).perf, Perf::None);
    let mut i = intel(0x8E, 0);
    i.base.e8_ebx = 1 << 27;
    assert_eq!(probe(&i).perf, Perf::None);
}

#[test]
fn intel_rapl_is_for_the_models_that_have_it() {
    let rapl = |m| probe(&intel(m, 0)).meter;
    for m in [0x2A, 0x2D, 0x3A, 0x3E, 0x3C, 0x45, 0x3F, 0x4E, 0x5E, 0x8E, 0x6A, 0x97, 0xB7, 0xAD, 0xCF, 0xC6] {
        assert_eq!(rapl(m), Meter::Intel, "model {m:#x}");
    }
    // Nehalem and earlier have none; the Atoms and Xeon Phi named in the list
    // have it in another layout.
    for m in [0x0F, 0x17, 0x1A, 0x1E, 0x25, 0x2C, 0x2F, 0x37, 0x4A, 0x4C, 0x4D, 0x57, 0x5A, 0x5D, 0x85] {
        assert_eq!(rapl(m), Meter::None, "model {m:#x}");
    }
}

#[test]
fn amd_rapl_is_cpuid_bit_14_of_the_power_leaf() {
    assert_eq!(probe(&amd(0x17, 1 << 14, 0)).meter, Meter::Amd);
    assert_eq!(probe(&amd(0x17, 1 << 13, 0)).meter, Meter::None);
    assert_eq!(probe(&amd(0x17, 0, 0)).meter, Meter::None);
}

#[test]
fn amd_before_zen_and_other_vendors_have_nothing() {
    // Family 0x15 (Bulldozer): no SMN thermal register, no CPPC.
    assert_eq!(probe(&amd(0x15, 1 << 14, 1 << 27)), Caps::NONE);
    assert_eq!(probe(&amd(0x16, 1 << 14, 1 << 27)), Caps::NONE);
    // Zen from family 0x17 on.
    for f in [0x17, 0x19, 0x1A] {
        assert_eq!(probe(&amd(f, 1 << 14, 1 << 27)), Caps { perf: Perf::Cppc, meter: Meter::Amd }, "family {f:#x}");
    }
    // Hygon is a Zen derivative whose CPPC and RAPL this board has not been checked on.
    let mut h = amd(0x18, 1 << 14, 1 << 27);
    h.base.l0_vendor = HYGON;
    assert_eq!(probe(&h), Caps::NONE);
    // Unknown vendor; an Intel part outside family 6 (Pentium 4 era).
    let mut u = intel(0x8E, HWP);
    u.base.l0_vendor = [0; 3];
    assert_eq!(probe(&u), Caps::NONE);
    let mut p4 = intel(0x8E, HWP);
    p4.base.l1_eax = 0xF << 8 | 1;
    assert_eq!(probe(&p4), Caps::NONE);
}

#[test]
fn a_full_part_has_both() {
    let c = probe(&intel(0xB7, HWP));
    assert_eq!(c, Caps { perf: Perf::Hwp, meter: Meter::Intel });
    let c = probe(&amd(0x1A, 1 << 14, 1 << 27));
    assert_eq!(c, Caps { perf: Perf::Cppc, meter: Meter::Amd });
}

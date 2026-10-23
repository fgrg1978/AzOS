// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_arch_api::pmu`: the performance-counter seam's pure half, driven
//! with fake identification words and register images: the CPUID / SBI /
//! `ID_AA64DFR0` decode, the plans built from them, the register values the
//! ISA crates write, the counter-width math and the boot line.
//!
//! Canaries (three buckets: discriminates / does not / did not compile):
//! every decode test below feeds a word whose NEIGHBOURING fields are set,
//! so a decoder reading the wrong bit range fails; the `delta` cases cross
//! the wrap, so a plain subtraction fails; `advanced` is fed a stuck and a
//! backwards counter, so a check that only compares `!=` fails. The
//! overflow-sampling cases load a counter with `sample_init` and count it
//! forward `period` events: an initial value off by one wraps one event early
//! or late and fails, and a period at the half-range edge is checked on both
//! sides.

use azos_arch_api::pmu::*;


#[test]
fn delta_survives_a_wrap_of_a_narrow_counter() {
    assert_eq!(delta(48, 10, 25), 15);
    assert_eq!(delta(48, mask(48) - 3, 4), 8, "wrapped through 2^48");
    assert_eq!(delta(32, 0xFFFF_FFF0, 0x10), 0x20);
    assert_eq!(delta(64, u64::MAX, 4), 5);
    assert_eq!(delta(64, 7, 7), 0);
}

#[test]
fn the_liveness_check_wants_movement_that_is_not_garbage() {
    assert!(advanced(48, 100, 200));
    assert!(!advanced(48, 100, 100), "a stuck counter");
    assert!(!advanced(48, 200, 100), "a counter that went backwards is a huge forward step");
    assert!(advanced(32, 0xFFFF_FFFE, 5), "movement across the wrap counts");
}

#[test]
fn rate_is_never_zero() {
    assert_eq!(rate_per_us(1_000_000, 1000), 1000);
    assert_eq!(rate_per_us(0, 1000), 1, "no cycles counted: raw counts");
    assert_eq!(rate_per_us(5, 1000), 1, "less than one per us: still 1");
    assert_eq!(rate_per_us(1000, 0), 1, "no interval: raw counts");
}

#[test]
fn intel_leaf_a_decodes_each_field_from_its_own_bits() {
    // Skylake: version 4, 4 GP counters of 48 bits, 3 fixed of 48 bits.
    let eax = 4 | (4 << 8) | (48 << 16) | (7 << 24);
    let edx = 3 | (48 << 5);
    let p = intel_decode(eax, edx);
    assert_eq!(p, IntelPmu { version: 4, gp: 4, gp_bits: 48, fixed: 3, fixed_bits: 48 });
    // A hypervisor with no PMU reports version 0 and nothing else.
    assert_eq!(intel_decode(0, 0), IntelPmu { version: 0, gp: 0, gp_bits: 0, fixed: 0, fixed_bits: 0 });
    // Version 1 has general counters only: EDX is reserved there.
    let v1 = intel_decode(1 | (2 << 8) | (40 << 16), !0);
    assert_eq!((v1.fixed, v1.fixed_bits, v1.gp), (0, 0, 2), "fixed counters need version 2");
    // Neighbouring fields do not bleed: all-ones EAX/EDX.
    let ones = intel_decode(!0, !0);
    assert_eq!((ones.version, ones.gp, ones.gp_bits, ones.fixed, ones.fixed_bits), (255, 255, 255, 31, 255));
}

#[test]
fn the_intel_plan_uses_fixed_counters_and_one_pmc() {
    let full = x86_plan_intel(intel_decode(4 | (4 << 8) | (48 << 16), 3 | (48 << 5)));
    assert_eq!(full.instr_idx, Some(X86_RDPMC_FIXED));
    assert_eq!(full.cycle_idx, Some(X86_RDPMC_FIXED | 1));
    assert_eq!((full.cycle_bits, full.instr_bits, full.event_bits), (48, 48, 48));
    assert_eq!((full.fixed_mask, full.pmc_mask, full.event_idx), (0b11, 0b11, Some(0)));
    assert_eq!((full.sample_idx, full.sample_bits), (Some(1), 48), "PMC1 samples");
    assert!(full.fixed && full.amd.is_none() && full.global);
    // One fixed counter: instructions only, the cycle counter is the TSC.
    let one = x86_plan_intel(intel_decode(2 | (2 << 8) | (48 << 16), 1 | (40 << 5)));
    assert_eq!((one.instr_idx.is_some(), one.cycle_idx), (true, None));
    assert_eq!(one.instr_bits, 40);
    // Version 1: no fixed counters.
    let v1 = x86_plan_intel(intel_decode(1 | (2 << 8) | (40 << 16), 0));
    assert_eq!((v1.instr_idx, v1.cycle_idx, v1.event_idx), (None, None, Some(0)));
    assert!(!v1.global, "version 1 has no global control register");
    // None at all.
    let none = x86_plan_intel(intel_decode(0, 0));
    assert_eq!((none.instr_idx, none.cycle_idx, none.event_idx), (None, None, None));
    // One general counter: Pmu::event keeps it, nothing samples.
    let gp1 = x86_plan_intel(intel_decode(2 | (1 << 8) | (48 << 16), 3 | (48 << 5)));
    assert_eq!((gp1.event_idx, gp1.sample_idx, gp1.sample_bits, gp1.pmc_mask), (Some(0), None, 0, 1));
    assert_eq!(none.sample_idx, None);
}

#[test]
fn amd_counters_follow_extcore_perfmonv2_and_the_hypervisor() {
    let ext = amd_decode(true, 0, 0, false, 0x17);
    assert_eq!((ext.counters, ext.evtsel0, ext.ctr0, ext.stride, ext.global_ctl), (6, 0xC001_0200, 0xC001_0201, 2, false));
    assert_eq!((ext.evtsel(0), ext.ctr(0), ext.evtsel(2), ext.ctr(2)), (0xC001_0200, 0xC001_0201, 0xC001_0204, 0xC001_0205));
    let v2 = amd_decode(true, 1, 6, false, 0x19);
    assert!(v2.global_ctl);
    assert_eq!(v2.counters, 6);
    assert_eq!(amd_decode(true, 1, 4, false, 0x19).counters, 4, "PerfMonV2 reports the real count");
    assert_eq!(amd_decode(true, 0, 3, false, 0x17).counters, 6, "EBX counts only with PerfMonV2");
    let legacy = amd_decode(false, 0, 0, false, 0x10);
    assert_eq!((legacy.counters, legacy.evtsel(1), legacy.ctr(1)), (4, 0xC001_0001, 0xC001_0005));
    assert_eq!(amd_decode(false, 0, 0, true, 0x10), AmdPmu::NONE, "no legacy MSRs behind a hypervisor");
    // Bulldozer and later have ExtCore: one without it (an emulator with
    // the hypervisor bit hidden) is assumed to have nothing. Canary: drop
    // the family gate and this is 4 legacy counters, whose `rdpmc` is #UD
    // under TCG.
    assert_eq!(amd_decode(false, 0, 0, false, 0x17), AmdPmu::NONE, "a Zen part without ExtCore");
    assert_eq!(amd_decode(false, 0, 0, false, 0x15), AmdPmu::NONE, "the first ExtCore family");
    assert_eq!(amd_decode(false, 0, 0, false, 0x14).counters, 4, "Bobcat: the legacy four");
    assert_eq!(amd_decode(true, 0, 0, true, 0x17).counters, 6, "a hypervisor that enumerates ExtCore has a PMU");
}

#[test]
fn the_amd_plan_puts_cycles_on_0_and_instructions_on_1() {
    let p = x86_plan_amd(amd_decode(true, 0, 0, false, 0x17));
    assert_eq!((p.cycle_idx, p.instr_idx, p.event_idx), (Some(0), Some(1), Some(2)));
    assert_eq!((p.cycle_bits, p.pmc_mask, p.fixed, p.global), (48, 0b1111, false, false));
    assert_eq!((p.sample_idx, p.sample_bits), (Some(3), 48), "counter 3 samples");
    let two = x86_plan_amd(AmdPmu { counters: 2, ..amd_decode(true, 0, 0, false, 0x17) });
    assert_eq!((two.event_idx, two.pmc_mask, two.sample_idx), (None, 0b11, None));
    let three = x86_plan_amd(AmdPmu { counters: 3, ..amd_decode(true, 0, 0, false, 0x17) });
    assert_eq!((three.event_idx, three.sample_idx, three.pmc_mask), (Some(2), None, 0b111));
    let none = x86_plan_amd(AmdPmu::NONE);
    assert_eq!((none.cycle_idx, none.instr_idx, none.event_idx), (None, None, None));
}

#[test]
fn x86_register_images() {
    // Event 0xC0 (AMD retired instructions), umask 0: USR | OS | EN.
    assert_eq!(x86_evtsel(0xC0), 0xC0 | (1 << 16) | (1 << 17) | (1 << 22));
    // The unit mask and AMD's high event bits survive; stray control bits do not.
    assert_eq!(x86_evtsel(0x12_34 | (0x1 << 32)) & !(7 << 16 | 1 << 22), 0x1234 | (1 << 32));
    assert_eq!(x86_evtsel(1 << 22 | 1 << 40) & (1 << 40), 0, "bits above the image are dropped");
    // Fixed counter control: counters 0 and 1 in both rings, 2 untouched.
    assert_eq!(x86_fixed_ctrl(0, 0b11), 0x33);
    assert_eq!(x86_fixed_ctrl(0xFFF, 0b01), 0xFF3, "only the asked counter's field changes");
    assert_eq!(x86_fixed_ctrl(0xFFF, 0b100), 0x3FF);
    assert_eq!(x86_global_ctrl(0, 0b11, 0b1), (0b11 << 32) | 1);
    assert_eq!(x86_global_ctrl(0b100, 0b100, 0), (0b100 << 32) | 0b100, "bits already set stay");
}

#[test]
fn sbi_counter_info_tells_hardware_from_firmware() {
    // hpmcounter3, 48 bits (width-1 = 47).
    let hw = 0xC03 | (47 << 12);
    assert_eq!(rv_counter_info(hw, 64), Some(RvCounter { csr: 0xC03, bits: 48 }));
    assert_eq!(rv_counter_info(hw | (1 << 63), 64), None, "firmware counter");
    assert_eq!(rv_counter_info(0xC02 | (63 << 12), 64), None, "instret is not programmable");
    assert_eq!(rv_counter_info(0xC20 | (63 << 12), 64), None, "past hpmcounter31");
    assert_eq!(rv_counter_info(0xC1F | (63 << 12), 64), Some(RvCounter { csr: 0xC1F, bits: 64 }));
}

#[test]
fn the_sbi_programmable_mask_skips_cycle_time_instret() {
    assert_eq!(rv_programmable_mask(0), 0);
    assert_eq!(rv_programmable_mask(3), 0);
    assert_eq!(rv_programmable_mask(4), 0b1000);
    assert_eq!(rv_programmable_mask(8), 0b1111_1000);
    assert_eq!(rv_programmable_mask(64), 0xFFFF_FFF8, "capped at 32 counters");
}

#[test]
fn scounteren_gives_ring_3_the_clock_and_what_is_allowed() {
    assert_eq!(rv_scounteren(false, false), 0b010);
    assert_eq!(rv_scounteren(true, false), 0b011);
    assert_eq!(rv_scounteren(false, true), 0b110);
    assert_eq!(rv_scounteren(true, true), 0b111);
}

#[test]
fn aarch64_pmcr_and_user_access() {
    assert_eq!(a64_pmcr(0, 3), A64_PMCR_E);
    assert_eq!(a64_pmcr(A64_PMCR_D, 3), A64_PMCR_E, "a divided cycle counter is made undivided");
    assert_eq!(a64_pmcr(0, 5), A64_PMCR_E, "PMUv3p4 has no LP bit: not set");
    assert_eq!(a64_pmcr(0, 6), A64_PMCR_E | A64_PMCR_LP, "PMUv3p5: 64-bit event counters");
    let n6 = (6 << 11) | (1 << 6) | (0x41 << 24);
    assert_eq!(a64_pmcr(n6, 3), n6 | A64_PMCR_E, "N, LC and the rest are kept");
    assert_eq!(a64_pmcr_n(n6), 6);
    assert_eq!((a64_event_bits(5), a64_event_bits(6)), (32, 64));
    assert_eq!(a64_cnten(0), 1 << 31);
    assert_eq!(a64_cnten(1), (1 << 31) | 1);
    assert_eq!(a64_cnten(6), (1 << 31) | 3, "counters 0 and 1 only");
    assert_eq!(a64_pmuserenr(false, false), 0, "no read allowed: EL0 stays trapped");
    assert_eq!(a64_pmuserenr(true, false), A64_PMUSERENR_CR);
    assert_eq!(a64_pmuserenr(false, true), A64_PMUSERENR_ER);
    assert_eq!(a64_pmuserenr(true, true), 0b1100);
    // EN (bit 0) and SW (bit 1) would give EL0 write access to the control
    // registers: the kernel's own counters would be at the mercy of any task.
    for (c, i) in [(false, false), (true, false), (false, true), (true, true)] {
        assert_eq!(a64_pmuserenr(c, i) & 0b11, 0, "no EL0 write access to the PMU");
    }
}

#[test]
fn the_boot_line_names_what_was_found() {
    assert_eq!(format!("{}", PmuCaps::NONE), "cycles=none instret=none events=0 user=none sample=none");
    let c = PmuCaps {
        cycles: Source::Pmu, instructions: Source::Pmu, cycle_bits: 48, instr_bits: 48,
        events: 1, event_bits: 48, user_cycles: true, user_instructions: true, sample_bits: 48,
    };
    assert_eq!(format!("{c}"), "cycles=pmu/48 instret=pmu/48 events=1/48 user=cycles,instret sample=48");
    let tsc = PmuCaps { cycles: Source::Timebase, instructions: Source::None, events: 0, user_cycles: false, user_instructions: true, sample_bits: 0, ..c };
    assert_eq!(format!("{tsc}"), "cycles=tsc/48 instret=none events=0 user=instret sample=none");
    assert!(c.core_cycles() && !tsc.core_cycles() && !PmuCaps::NONE.core_cycles());
    assert!(PmuCaps { cycles: Source::Isa, ..c }.core_cycles());
}

/// A CPUID model: the leaves it answers, everything else all zeros.
fn cpuid_of(table: &'static [(u32, u32, [u32; 4])]) -> impl Fn(u32, u32) -> (u32, u32, u32, u32) {
    move |leaf, sub| {
        for &(l, s, r) in table {
            if l == leaf && s == sub {
                return (r[0], r[1], r[2], r[3]);
            }
        }
        (0, 0, 0, 0)
    }
}

const GENUINE_INTEL: [u32; 3] = [0x756E_6547, 0x6C65_746E, 0x4965_6E69]; // ebx, ecx, edx
const AUTHENTIC_AMD: [u32; 3] = [0x6874_7541, 0x444D_4163, 0x6974_6E65];

#[test]
fn the_vendor_comes_from_all_three_string_registers() {
    let [b, c, d] = GENUINE_INTEL;
    assert_eq!(x86_vendor(b, c, d), X86Vendor::Intel);
    let [b, c, d] = AUTHENTIC_AMD;
    assert_eq!(x86_vendor(b, c, d), X86Vendor::Amd);
    assert_eq!(x86_vendor(0x6F67_7948, 0x656E_6975, 0x6E65_476E), X86Vendor::Amd, "HygonGenuine");
    assert_eq!(x86_vendor(b, GENUINE_INTEL[1], d), X86Vendor::Other, "a mixed string is nobody");
    assert_eq!(x86_vendor(0, 0, 0), X86Vendor::Other);
}

#[test]
fn a_skylake_gets_fixed_counters_and_a_zen_gets_core_counters() {
    static SKYLAKE: [(u32, u32, [u32; 4]); 3] = [
        (0, 0, [0x16, GENUINE_INTEL[0], GENUINE_INTEL[1], GENUINE_INTEL[2]]),
        (1, 0, [0, 0, 0, 0]),
        (0xA, 0, [4 | (4 << 8) | (48 << 16) | (7 << 24), 0, 0, 3 | (48 << 5)]),
    ];
    let p = x86_plan(cpuid_of(&SKYLAKE));
    assert_eq!((p.cycle_idx, p.instr_idx), (Some(X86_RDPMC_FIXED | 1), Some(X86_RDPMC_FIXED)));
    assert!(p.fixed && p.amd.is_none());

    // Zen 3 on bare metal: ExtCore, no PerfMonV2.
    static ZEN3: [(u32, u32, [u32; 4]); 4] = [
        (0, 0, [0x10, AUTHENTIC_AMD[0], AUTHENTIC_AMD[1], AUTHENTIC_AMD[2]]),
        (1, 0, [0, 0, 0, 0]),
        (0x8000_0000, 0, [0x8000_0021, 0, 0, 0]),
        (0x8000_0001, 0, [0, 0, 1 << 23, 0]),
    ];
    let p = x86_plan(cpuid_of(&ZEN3));
    assert_eq!((p.cycle_idx, p.instr_idx, p.event_idx), (Some(0), Some(1), Some(2)));
    assert!(!p.fixed && p.amd.unwrap().counters == 6 && !p.amd.unwrap().global_ctl);

    // Zen 4: PerfMonV2 with six counters.
    static ZEN4: [(u32, u32, [u32; 4]); 5] = [
        (0, 0, [0x10, AUTHENTIC_AMD[0], AUTHENTIC_AMD[1], AUTHENTIC_AMD[2]]),
        (1, 0, [0, 0, 0, 0]),
        (0x8000_0000, 0, [0x8000_0023, 0, 0, 0]),
        (0x8000_0001, 0, [0, 0, 1 << 23, 0]),
        (0x8000_0022, 0, [1, 6, 0, 0]),
    ];
    let p = x86_plan(cpuid_of(&ZEN4));
    assert!(p.amd.unwrap().global_ctl && p.amd.unwrap().counters == 6);
}

#[test]
fn an_emulator_or_a_hypervisor_without_a_pmu_gets_nothing() {
    // QEMU TCG qemu64: an AMD string, the hypervisor bit, no ExtCore.
    static QEMU64: [(u32, u32, [u32; 4]); 4] = [
        (0, 0, [0xD, AUTHENTIC_AMD[0], AUTHENTIC_AMD[1], AUTHENTIC_AMD[2]]),
        (1, 0, [0, 0, 1 << 31, 0]),
        (0x8000_0000, 0, [0x8000_000A, 0, 0, 0]),
        (0x8000_0001, 0, [0, 0, 0, 0]),
    ];
    assert_eq!(x86_plan(cpuid_of(&QEMU64)), X86Plan { amd: Some(AmdPmu::NONE), ..X86Plan::NONE },
               "no legacy MSRs behind a hypervisor");
    // A K10 (family 0x10) on bare metal does have the legacy four.
    static OLD_AMD: [(u32, u32, [u32; 4]); 4] = [
        (0, 0, [0xD, AUTHENTIC_AMD[0], AUTHENTIC_AMD[1], AUTHENTIC_AMD[2]]),
        (1, 0, [(0x1 << 20) | (0xF << 8), 0, 0, 0]),
        (0x8000_0000, 0, [0x8000_000A, 0, 0, 0]),
        (0x8000_0001, 0, [0, 0, 0, 0]),
    ];
    assert_eq!(x86_plan(cpuid_of(&OLD_AMD)).amd.unwrap().counters, 4);
    // QEMU TCG `-cpu EPYC,-hypervisor`: family 0x17, the hypervisor bit
    // hidden, no ExtCore. Nothing is named (the boot trapped on `rdpmc` when
    // the legacy four were assumed here).
    static EPYC_NO_HV: [(u32, u32, [u32; 4]); 4] = [
        (0, 0, [0xD, AUTHENTIC_AMD[0], AUTHENTIC_AMD[1], AUTHENTIC_AMD[2]]),
        (1, 0, [(0x8 << 20) | (0xF << 8) | 0x12, 0, 0, 0]),
        (0x8000_0000, 0, [0x8000_001F, 0, 0, 0]),
        (0x8000_0001, 0, [0, 0, 0, 0]),
    ];
    assert_eq!(x86_plan(cpuid_of(&EPYC_NO_HV)), X86Plan { amd: Some(AmdPmu::NONE), ..X86Plan::NONE });
    // Intel TCG-style: leaf 0xA says version 0.
    static NO_PMU: [(u32, u32, [u32; 4]); 3] = [
        (0, 0, [0xD, GENUINE_INTEL[0], GENUINE_INTEL[1], GENUINE_INTEL[2]]),
        (1, 0, [0, 0, 1 << 31, 0]),
        (0xA, 0, [0, 0, 0, 0]),
    ];
    assert_eq!(x86_plan(cpuid_of(&NO_PMU)), X86Plan { fixed: true, ..X86Plan::NONE });
    // A max leaf below 0xA never asks for it.
    static OLD_INTEL: [(u32, u32, [u32; 4]); 2] = [
        (0, 0, [0x5, GENUINE_INTEL[0], GENUINE_INTEL[1], GENUINE_INTEL[2]]),
        (0xA, 0, [4 | (4 << 8), 0, 0, 3 | (48 << 5)]),
    ];
    assert_eq!(x86_plan(cpuid_of(&OLD_INTEL)), X86Plan::NONE, "leaf 0xA is past the max leaf: not read");
    // Not an x86 vendor we know.
    static OTHER: [(u32, u32, [u32; 4]); 2] = [(0, 0, [0xD, 1, 2, 3]), (0xA, 0, [4, 0, 0, 3])];
    assert_eq!(x86_plan(cpuid_of(&OTHER)), X86Plan::NONE);
}

#[test]
fn the_first_sbi_hardware_counter_skips_firmware_ones() {
    // 8 counters: 0..=2 are cycle, time, instret; 3 is a firmware counter;
    // 4 is hpmcounter4 (40 bits).
    let info = |idx: usize| -> u64 {
        match idx {
            3 => 1 << 63,
            4 => 0xC04 | (39 << 12),
            _ => 0xC00 + idx as u64,
        }
    };
    let (idx, c) = rv_first_hw_counter(8, info).unwrap();
    assert_eq!((idx, c), (4, RvCounter { csr: 0xC04, bits: 40 }));
    assert_eq!(rv_first_hw_counter(3, info), None, "cycle, time and instret only");
    assert_eq!(rv_first_hw_counter(4, info), None, "the one extra counter is firmware");
    assert_eq!(rv_first_hw_counter(8, |_| 1 << 63), None);
}

/// Count a `bits`-wide counter `n` events forward.
fn tick(bits: u8, v: u64, n: u64) -> u64 {
    v.wrapping_add(n) & mask(bits)
}

#[test]
fn a_sampling_counter_wraps_after_exactly_its_period() {
    for (bits, period) in [(32u8, 1_000_000u64), (48, 1_000_000), (64, 1_000_000), (32, (1 << 31) - 1), (48, 3)] {
        let init = sample_init(bits, period);
        assert!(!sample_overflowed(bits, init), "{bits}/{period}: armed, not wrapped");
        assert!(!sample_overflowed(bits, tick(bits, init, period - 1)), "{bits}/{period}: one event short");
        assert_eq!(tick(bits, init, period), 0, "{bits}/{period}: the wrap is the period's last event");
        assert!(sample_overflowed(bits, tick(bits, init, period)), "{bits}/{period}: wrapped");
        assert!(sample_overflowed(bits, tick(bits, init, period + 7)), "{bits}/{period}: read a little late");
    }
}

#[test]
fn a_period_fits_below_half_the_counter() {
    assert!(sample_period_fits(32, (1 << 31) - 1));
    assert!(!sample_period_fits(32, 1 << 31), "the top bit would start clear");
    assert!(!sample_period_fits(48, 0), "a zero period never arms");
    assert!(sample_period_fits(48, 1 << 46) && sample_period_fits(64, u64::MAX / 2));
    assert!(!sample_period_fits(0, 1) && !sample_period_fits(1, 1), "a counter too narrow to mark");
    // Every Kconfig PROFILER_PMU_PERIOD (1000..=2^31-1) fits every counter
    // this kernel samples on (32, 48, 64 bits).
    for bits in [32u8, 48, 64] {
        assert!(sample_period_fits(bits, 1000) && sample_period_fits(bits, (1 << 31) - 1));
    }
}

#[test]
fn intel_legacy_counter_writes_keep_the_initial_value() {
    // IA32_PMCn keeps the low 32 bits and sign-extends bit 31.
    for period in [1000u64, 1_000_000, (1 << 31) - 1] {
        let init = sample_init(48, period);
        assert_eq!(x86_legacy_write(48, init), init, "period {period}");
    }
    // 2^31 is the last period bit 31 still carries; one more loads a
    // positive counter that would not wrap for 2^47 events: refused.
    let edge = sample_init(48, 1 << 31);
    assert_eq!(x86_legacy_write(48, edge), edge);
    let init = sample_init(48, (1 << 31) + 1);
    assert_ne!(x86_legacy_write(48, init), init);
    assert_eq!(x86_legacy_write(48, 0x7FFF_FFFF), 0x7FFF_FFFF, "bit 31 clear: zero-extended");
}

#[test]
fn x86_sampling_event_select_interrupts() {
    let v = x86_sample_evtsel(INTEL_EV_CYCLES);
    assert_eq!(v, 0x3C | X86_EVTSEL_USR | X86_EVTSEL_OS | X86_EVTSEL_INT | X86_EVTSEL_EN);
    assert_eq!(X86_EVTSEL_INT, 1 << 20);
    assert_eq!(x86_evtsel(AMD_EV_CYCLES) & X86_EVTSEL_INT, 0, "Pmu::event's counter never interrupts");
    assert_eq!((X86_MSR_PERF_GLOBAL_STATUS, X86_MSR_PERF_GLOBAL_OVF_CTRL, AMD_MSR_PERF_GLOBAL_STATUS_CLR),
               (0x38E, 0x390, 0xC000_0302));
}

#[test]
fn aarch64_samples_on_the_last_counter_when_three_exist() {
    assert_eq!(a64_sample_counter(6), Some(5));
    assert_eq!(a64_sample_counter(3), Some(2));
    assert_eq!(a64_sample_counter(2), None, "counters 0 and 1 are taken");
    assert_eq!(a64_sample_counter(0), None);
    // The sampling counter is never one `a64_cnten` starts for the readers.
    for n in 3..=31u8 {
        assert_eq!(a64_cnten(n) & (1 << a64_sample_counter(n).unwrap()), 0, "N={n}");
    }
    assert_eq!(A64_EV_CPU_CYCLES, 0x11);
}

#[test]
fn riscv64_sampling_flags() {
    assert_eq!(SBI_HW_CPU_CYCLES, 1);
    // counter_config_matching: CLEAR_VALUE and SET_MINH, never AUTO_START
    // (the start loads the initial value) nor SKIP_MATCH.
    assert_eq!(SBI_PMU_CFG_SAMPLE & (1 << 1), 1 << 1);
    assert_eq!(SBI_PMU_CFG_SAMPLE & (1 << 7), 1 << 7);
    assert_eq!(SBI_PMU_CFG_SAMPLE & ((1 << 0) | (1 << 2)), 0);
    assert_eq!((SBI_PMU_START_SET_INIT_VALUE, SBI_PMU_STOP_RESET), (1, 1));
    assert_eq!(RV_SIE_LCOFIE, 1 << 13, "LCOFI is interrupt 13");
}

#[test]
fn the_family_and_the_counter_msrs() {
    assert_eq!(x86_family((0x8 << 20) | (0xF << 8)), 0x17, "Zen: 0xF + 8");
    assert_eq!(x86_family((0xA << 20) | (0xF << 8)), 0x19);
    assert_eq!(x86_family(6 << 8 | 0xFF << 20), 6, "the extended family counts only under 0xF");
    // Intel: fixed counter 1 and PMC1; AMD ExtCore counter 3 and legacy 1.
    assert_eq!(x86_counter_msr(X86_RDPMC_FIXED | 1, None), 0x30A);
    assert_eq!(x86_counter_msr(1, None), 0xC2);
    let ext = amd_decode(true, 0, 0, false, 0x17);
    assert_eq!(x86_counter_msr(3, Some(ext)), 0xC001_0207);
    assert_eq!(x86_counter_msr(1, Some(amd_decode(false, 0, 0, false, 0x10))), 0xC001_0005);
}

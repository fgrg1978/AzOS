// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 deep idle (`crates/core/arch-x86_64/src/cpu/idle.rs`): the C-state
//! ladder per CPU model, what CPUID must say before a state is on it, and the
//! depth `cpu_idle` enters for a depth asked.
//!
//! The mistake that matters is silent: a state whose exit latency is smaller
//! than the real one, or a state that stops the APIC timer on a CPU that
//! cannot say it keeps running, passes every functional test and then sleeps
//! through a real-time deadline or never wakes. So each gate has a test that
//! flips only that gate. The CPU is "bare" (no mwait) until a test says
//! otherwise.
//!
//! Canaries (by hand, each must turn the named test red): drop the ARAT/TSC
//! test in `build` -> `without_arat_or_invariant_tsc_only_the_c1_family_stays`;
//! make `pick` clamp upward -> `a_depth_is_never_entered_deeper_than_asked`;
//! drop the `l5_edx` test -> `a_hint_with_no_listed_substate_is_off_the_ladder`.

use crate::cpu::features::CpuidLeaves;
use crate::cpu::idle::*;

const GENUINE_INTEL: [u32; 3] = [u32::from_le_bytes(*b"Genu"), u32::from_le_bytes(*b"ineI"), u32::from_le_bytes(*b"ntel")];
const AUTHENTIC_AMD: [u32; 3] = [u32::from_le_bytes(*b"Auth"), u32::from_le_bytes(*b"enti"), u32::from_le_bytes(*b"cAMD")];
const HYGON: [u32; 3] = [u32::from_le_bytes(*b"Hygo"), u32::from_le_bytes(*b"nGen"), u32::from_le_bytes(*b"uine")];

/// CPUID.1:EAX of a family-6 part with this display model (stepping 1).
fn eax_intel(model: u16) -> u32 {
    let (ext, base) = ((model >> 4) as u32, (model & 0xF) as u32);
    ext << 16 | 6 << 8 | base << 4 | 1
}

/// A fully capable Intel: MONITOR, the MWAIT extensions, every C-state with
/// two sub-states, ARAT and an invariant TSC.
fn intel(model: u16) -> IdleCpuid {
    IdleCpuid {
        base: CpuidLeaves {
            l0_vendor: GENUINE_INTEL,
            l1_eax: eax_intel(model),
            l1_ecx: 1 << 3,
            e7_edx: 1 << 8,
            ..CpuidLeaves::default()
        },
        l5_ecx: 0b11,
        l5_edx: 0x2222_2222,
        l6_eax: 1 << 2,
    }
}

/// A Zen part: family 0x17 (base 0xF + extended 0x08), MONITORX.
fn amd(vendor: [u32; 3], monitorx: bool) -> IdleCpuid {
    IdleCpuid {
        base: CpuidLeaves {
            l0_vendor: vendor,
            l1_eax: 0x00_8_F_1_1,
            e1_ecx: if monitorx { 1 << 29 } else { 0 },
            ..CpuidLeaves::default()
        },
        ..IdleCpuid::default()
    }
}

fn rows(l: &Ladder) -> Vec<(&'static str, u8, u32, u32)> {
    l.states().iter().map(|s| (s.name, s.hint, s.exit_latency_us, s.target_residency_us)).collect()
}

#[test]
fn state_table_of_each_targeted_model() {
    let skl = [("C1E", 0x01, 10, 20), ("C6", 0x20, 85, 200), ("C10", 0x60, 890, 5000)];
    let hsw = [("C1E", 0x01, 10, 20), ("C6", 0x20, 133, 400), ("C10", 0x60, 2600, 7700)];
    let adl = [("C1E", 0x01, 2, 4), ("C6", 0x20, 220, 600), ("C10", 0x60, 680, 2000)];
    let cases: [(u16, &[(&str, u8, u32, u32)]); 9] = [
        (0x3C, &hsw),
        (0x9E, &skl),
        (0x55, &[("C1E", 0x01, 10, 20), ("C6", 0x20, 133, 600)]),
        (0x6A, &[("C1E", 0x01, 4, 4), ("C6", 0x20, 170, 600)]),
        (0x8C, &[("C1E", 0x01, 4, 4), ("C6", 0x20, 170, 600)]),
        (0x8F, &[("C1E", 0x01, 2, 4), ("C6", 0x20, 290, 800)]),
        (0x97, &adl),
        (0xB7, &adl),
        (0xCF, &[("C1E", 0x01, 2, 4), ("C6", 0x20, 290, 800)]),
    ];
    for (model, want) in cases {
        let l = build(&intel(model));
        assert_eq!(rows(&l), want, "model {model:#x}");
        assert_eq!(l.wait(), Wait::Mwait);
    }
}

#[test]
fn every_table_rises_with_depth_and_pays_back_its_exit() {
    let models = [0x3C, 0x45, 0x46, 0x3D, 0x47, 0x4E, 0x5E, 0x8E, 0x9E, 0xA5, 0xA6, 0x7E, 0x8C, 0x8D, 0xA7]
        .into_iter()
        .chain([0x55, 0x6A, 0x6C, 0x8F, 0xCF, 0x97, 0x9A, 0xB7, 0xBA, 0xBF]);
    for model in models {
        let l = build(&intel(model));
        assert!(!l.states().is_empty() && l.states().len() <= MAX_STATES, "model {model:#x}");
        for w in l.states().windows(2) {
            assert!(w[0].exit_latency_us < w[1].exit_latency_us, "{model:#x}: latency must rise: {w:?}");
            assert!(w[0].target_residency_us < w[1].target_residency_us, "{model:#x}: residency must rise: {w:?}");
            assert!(w[0].hint < w[1].hint, "{model:#x}: hints ascend: {w:?}");
        }
        for s in l.states() {
            assert!(s.target_residency_us >= s.exit_latency_us, "{model:#x}: {s:?} cannot pay back");
        }
    }
}

#[test]
fn a_model_with_no_table_gets_no_deep_state() {
    // QEMU's default (family 6 model 6), a pre-Haswell and a future model.
    for model in [0x06, 0x2A, 0x3A, 0xFF] {
        assert_eq!(build(&intel(model)), Ladder::EMPTY, "model {model:#x}");
    }
    // Intel but not family 6 (Pentium 4's family 0xF, model 0x3C-alike).
    let mut c = intel(0x3C);
    c.base.l1_eax = 0x0F << 8 | 0x3 << 4;
    assert_eq!(build(&c), Ladder::EMPTY);
    // An unknown vendor string.
    let mut c = intel(0x3C);
    c.base.l0_vendor = [1, 2, 3];
    assert_eq!(build(&c), Ladder::EMPTY);
}

#[test]
fn amd_and_hygon_have_one_mwaitx_state_where_monitorx_exists() {
    for v in [AUTHENTIC_AMD, HYGON] {
        let l = build(&amd(v, true));
        assert_eq!(rows(&l), [("C1", 0x00, 1, 2)]);
        assert_eq!(l.wait(), Wait::Mwaitx);
        assert_eq!(build(&amd(v, false)), Ladder::EMPTY, "no MONITORX: hlt only");
    }
}

#[test]
fn mwait_needs_monitor_and_both_extensions() {
    let mut c = intel(0x9E);
    c.base.l1_ecx = 0;
    assert_eq!(build(&c), Ladder::EMPTY, "CPUID.1:ECX.MONITOR clear (a hypervisor hides it)");
    for missing in [0b01u32, 0b10, 0b00] {
        let mut c = intel(0x9E);
        c.l5_ecx = missing;
        assert_eq!(build(&c), Ladder::EMPTY, "CPUID.5:ECX = {missing:#b}");
    }
}

#[test]
fn without_arat_or_invariant_tsc_only_the_c1_family_stays() {
    let mut c = intel(0x9E);
    c.l6_eax = 0;
    assert_eq!(rows(&build(&c)), [("C1E", 0x01, 10, 20)], "no ARAT: the APIC timer stops in C6");
    let mut c = intel(0x9E);
    c.base.e7_edx = 0;
    assert_eq!(rows(&build(&c)), [("C1E", 0x01, 10, 20)], "no invariant TSC: the clock stops in C6");
    assert!(build(&c).states().iter().all(|s| !s.may_stop_timer()));
}

#[test]
fn a_hint_with_no_listed_substate_is_off_the_ladder() {
    // EDX nibble c+1 counts the sub-states of the hint's C-state c. Clear the
    // C6 nibble (hint 0x20: c = 2, nibble 3) and C6 goes, C10 and C1E stay.
    let mut c = intel(0x9E);
    c.l5_edx &= !(0xF << 12);
    assert_eq!(rows(&build(&c)).iter().map(|r| r.0).collect::<Vec<_>>(), ["C1E", "C10"]);
    // No C1 sub-state (nibble 1) removes C1E.
    let mut c = intel(0x9E);
    c.l5_edx &= !(0xF << 4);
    assert_eq!(rows(&build(&c)).iter().map(|r| r.0).collect::<Vec<_>>(), ["C6", "C10"]);
    c.l5_edx = 0;
    assert_eq!(build(&c), Ladder::EMPTY);
}

#[test]
fn a_depth_is_never_entered_deeper_than_asked() {
    let l = build(&intel(0x9E));
    assert_eq!(l.pick(0), None, "depth 0 is hlt");
    assert_eq!(l.pick(1).map(|s| s.name), Some("C1E"));
    assert_eq!(l.pick(2).map(|s| s.name), Some("C6"));
    assert_eq!(l.pick(3).map(|s| s.name), Some("C10"));
    // Past the ladder: the deepest there is, which is shallower than asked.
    assert_eq!(l.pick(4).map(|s| s.name), Some("C10"));
    assert_eq!(l.pick(255).map(|s| s.name), Some("C10"));
    for depth in 0..=255u8 {
        let entered = l.pick(depth).map_or(0, |s| l.states().iter().position(|x| x == s).unwrap() as u32 + 1);
        assert!(entered <= depth as u32, "depth {depth} entered state {entered}");
    }
    // No ladder: every depth is hlt.
    assert!((0..=255u8).all(|d| Ladder::EMPTY.pick(d).is_none()));
}

#[test]
fn a_model_that_claims_less_latency_than_the_state_has_is_caught() {
    let l = build(&intel(0x9E));
    assert!(!l.understates(0, 0), "hlt is not checked");
    assert!(!l.understates(1, 10) && l.understates(1, 9));
    assert!(!l.understates(2, 85) && l.understates(2, 84));
    // A depth past the ladder is entered as the deepest state, and checked as it.
    assert!(l.understates(7, 889) && !l.understates(7, 890));
    assert!(!Ladder::EMPTY.understates(1, 0));
}

#[test]
fn the_depth_is_capped_at_the_first_claim_the_ladder_breaks() {
    let l = build(&intel(0x9E)); // exits 10, 85, 890
    assert_eq!(l.depth_within_claims(&[10, 85, 890]), 3, "a model that tells the truth keeps the ladder");
    assert_eq!(l.depth_within_claims(&[10, 85]), 2);
    assert_eq!(l.depth_within_claims(&[10, 84, 890]), 1, "depth 2 claims too little: stop before it");
    assert_eq!(l.depth_within_claims(&[10, 85, 889]), 2);
    assert_eq!(l.depth_within_claims(&[9, 85, 890]), 0, "depth 1 claims too little: hlt only");
    // A deeper claim that is right does not rescue a shallower one that is wrong.
    assert_eq!(l.depth_within_claims(&[1, 1000, 1000]), 0);
    assert_eq!(l.depth_within_claims(&[]), 0);
    assert_eq!(Ladder::EMPTY.depth_within_claims(&[1, 1]), 2, "no ladder: every depth is hlt, nothing to break");
}

#[test]
fn the_cap_only_ever_lowers() {
    assert_eq!(depth_cap(), u8::MAX);
    cap_depth(2);
    cap_depth(3);
    assert_eq!(depth_cap(), 2);
    cap_depth(0);
    assert_eq!(depth_cap(), 0);
}

#[test]
fn the_models_idle_list_is_hlt_then_the_ladder_exactly() {
    // The kernel seeds a domain's idle list from `model_state(0..=n)`: depth d
    // in the model must be the state `pick(d)` enters, with its real numbers.
    let l = build(&intel(0x9E));
    assert_eq!(l.model_state(0), ("hlt", 0, 0));
    let listed: Vec<_> = (1..=l.states().len() as u8).map(|d| l.model_state(d)).collect();
    assert_eq!(listed, [("C1E", 10, 20), ("C6", 85, 200), ("C10", 890, 5000)]);
    for d in 1..=3u8 {
        let (_, exit, _) = l.model_state(d);
        assert!(!l.understates(d, exit), "a list built from the ladder never trips the I3 check");
    }
    // The list is what the model validates: exit non-decreasing from hlt, residency >= exit.
    let all: Vec<_> = (0..=3u8).map(|d| l.model_state(d)).collect();
    assert!(all.windows(2).all(|w| w[0].1 <= w[1].1) && all.iter().all(|s| s.2 >= s.1));
    // No ladder: only hlt, at every depth.
    assert_eq!(Ladder::EMPTY.model_state(0), ("hlt", 0, 0));
    assert_eq!(Ladder::EMPTY.model_state(2), ("hlt", 0, 0));
}

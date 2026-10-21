// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the aarch64 half of the superpage break-before-make gate:
//! `IdRegs::bbm_level2` (ID_AA64MMFR2_EL1.BBM [55:52] >= 2), the weakest-CPU
//! survey `Mmu::block_change_needs_bbm` reads (`BbmSurvey`), and the word a
//! level-1 slot holds between the break and the make. The sequence itself
//! (`vmm::promote_user_block`, `split_user_mega`) is
//! `tests/host/syscall-tests/src/thp_bbm.rs`, over an arch that answers
//! `true` on demand; riscv64 and x86_64 state `false` explicitly and no host
//! row can reach their impl.
//!
//! Canaries: `--features a64-id-canary` turns the test into `>= 1`; the
//! `level_1_is_not_enough` row goes red and no other. `BbmSurvey::note`
//! forgetting a CPU that lacks level 2 (the `lacking` store removed):
//! `one_weak_cpu_among_strong_ones_decides` goes red. `needs_bbm` ignoring
//! `expected` (answering from `lacking` alone):
//! `before_boot_says_how_many_cpus_the_answer_is_yes` and
//! `a_cpu_that_has_not_noted_itself_yet_keeps_the_break` go red. `noted`
//! stepped by 1 instead of by the CPU's bit: `a_cpu_that_has_not_noted_itself_yet_keeps_the_break`
//! and `every_cpu_with_level_2_means_no_break` go red.

use crate::aarch64_cpu::features::{BbmSurvey, IdRegs};
use azos_arch_api::PTE_BBM_PARK;

fn mmfr2(v: u64) -> IdRegs {
    IdRegs { mmfr2: v, ..IdRegs::default() }
}

#[test]
fn level_2_lets_a_block_change_without_bbm() {
    assert!(mmfr2(2 << 52).bbm_level2());
}

#[test]
fn a_larger_level_still_counts() {
    assert!(mmfr2(3 << 52).bbm_level2());
    assert!(mmfr2(0xF << 52).bbm_level2());
}

#[test]
fn level_0_needs_bbm() {
    // Cortex-A53, A72 and A76 (Raspberry Pi 3 and 5) report 0.
    assert!(!mmfr2(0).bbm_level2());
}

/// Level 1 allows a block-size change without BBM but a TLB conflict abort
/// may still be raised, which is what the gate exists to avoid.
#[test]
fn level_1_is_not_enough() {
    assert!(!mmfr2(1 << 52).bbm_level2());
}

#[test]
fn neighbouring_fields_do_not_leak_into_bbm() {
    // EVT [59:56] and E0PD [63:60] above, ST [31:28] and below, set alone.
    assert!(!mmfr2(!(0xF << 52)).bbm_level2());
    assert!(!mmfr2(0xF << 56).bbm_level2());
    assert!(!mmfr2(0xF << 60).bbm_level2());
    assert!(!mmfr2(0x0000_0000_FFFF_FFFF).bbm_level2());
    assert!(!mmfr2(0x000F_FFFF_FFFF_FFFF).bbm_level2(), "bits 51:0 leaked into BBM");
}

#[test]
fn another_register_does_not_leak_into_bbm() {
    let all_but = IdRegs { isar0: u64::MAX, isar1: u64::MAX, pfr0: u64::MAX, pfr1: u64::MAX,
                           mmfr1: u64::MAX, mmfr2: 0, isar2: u64::MAX, dfr0: u64::MAX };
    assert!(!all_but.bbm_level2());
}

#[test]
fn the_probe_does_not_move_its_neighbours() {
    let r = mmfr2(2 << 52);
    assert!(!r.e0pd() && !r.pan() && !r.sve() && !r.tlbirange() && !r.wfxt() && !r.pmuv3());
}

#[test]
fn before_boot_says_how_many_cpus_the_answer_is_yes() {
    // A level-2 CPU has noted itself; nobody has said how many to expect.
    let s = BbmSurvey::new();
    assert!(s.needs_bbm());
    s.note(0, true);
    assert!(s.needs_bbm());
}

#[test]
fn every_cpu_with_level_2_means_no_break() {
    let s = BbmSurvey::new();
    s.note(0, true);
    s.note(1, true);
    s.expect(2);
    assert!(!s.needs_bbm());
}

#[test]
fn a_cpu_that_has_not_noted_itself_yet_keeps_the_break() {
    // Tasks already run on CPU 1 while CPU 2 is still starting: a block made
    // now would meet whatever CPU 2 turns out to be.
    let s = BbmSurvey::new();
    s.note(0, true);
    s.expect(3);
    s.note(1, true);
    assert!(s.needs_bbm());
    s.note(2, true);
    assert!(!s.needs_bbm());
}

#[test]
fn a_cpu_noting_itself_twice_is_one_cpu() {
    let s = BbmSurvey::new();
    s.expect(2);
    s.note(0, true);
    s.note(0, true);
    assert!(s.needs_bbm());
}

#[test]
fn one_weak_cpu_among_strong_ones_decides() {
    // big.LITTLE: the boot CPU has level 2, a secondary does not, in either
    // order; a block made on the strong CPU is seen by the weak one.
    let a = BbmSurvey::new();
    a.expect(3);
    a.note(0, true);
    a.note(1, false);
    a.note(2, true);
    assert!(a.needs_bbm());
    let b = BbmSurvey::new();
    b.expect(2);
    b.note(0, false);
    b.note(1, true);
    assert!(b.needs_bbm());
}

#[test]
fn the_park_word_is_not_valid_not_empty_and_not_a_demand_marker() {
    use crate::aarch64_mmu as m;
    assert!(!m::is_valid(PTE_BBM_PARK), "the hardware must fault on it");
    assert_ne!(PTE_BBM_PARK, m::empty(), "a walker that builds over empty must not take it");
    assert!(!m::is_demand(PTE_BBM_PARK), "not a demand marker");
}

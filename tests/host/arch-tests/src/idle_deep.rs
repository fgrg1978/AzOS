// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Deep idle on riscv64: which `riscv,sbi-suspend-param` the idle seam may
//! hand to SBI HSM `hart_suspend`, and what it does with the answer.
//!
//! The one mistake that matters here is silent in the bad direction: a
//! non-retentive suspend type entered by a kernel with no resume path wakes the
//! hart at a firmware-chosen address with its context gone, and every other
//! test still passes. So the retentive test is pinned from both sides (bit 31
//! set is refused, bit 31 clear is not), and the refusal is checked at the
//! firmware wrapper too, not only at the ladder in front of it.

#[allow(dead_code)]
#[path = "../../../../arch/riscv64/src/firmware.rs"]
mod firmware;

use firmware::*;
use std::cell::Cell;

const DEFAULT_RETENTIVE: u32 = 0;
const PLATFORM_RETENTIVE: u32 = 0x1000_0001;
const DEFAULT_NON_RETENTIVE: u32 = 0x8000_0000;
const PLATFORM_NON_RETENTIVE: u32 = 0x9000_0002;

fn st(param: Option<u32>) -> SuspendState {
    SuspendState { param, local_timer_stop: false }
}

#[test]
fn bit_31_alone_decides_retentive() {
    for t in [0, 1, 0x1000_0000, PLATFORM_RETENTIVE, 0x7fff_ffff] {
        assert!(suspend_is_retentive(t), "{t:#x}");
    }
    for t in [DEFAULT_NON_RETENTIVE, 0x8000_0001, PLATFORM_NON_RETENTIVE, 0xffff_ffff] {
        assert!(!suspend_is_retentive(t), "{t:#x}");
    }
}

#[test]
fn only_a_retentive_timer_keeping_state_with_a_parameter_is_enterable() {
    assert_eq!(st(None).enterable(), None, "no riscv,sbi-suspend-param");
    assert_eq!(st(Some(DEFAULT_NON_RETENTIVE)).enterable(), None);
    assert_eq!(st(Some(PLATFORM_NON_RETENTIVE)).enterable(), None);
    assert_eq!(st(Some(DEFAULT_RETENTIVE)).enterable(), Some(0), "0 is a real type, not 'absent'");
    assert_eq!(st(Some(PLATFORM_RETENTIVE)).enterable(), Some(PLATFORM_RETENTIVE));
    let stops = SuspendState { param: Some(PLATFORM_RETENTIVE), local_timer_stop: true };
    assert_eq!(stops.enterable(), None, "local-timer-stop: the wake-up timer would be lost");
}

#[test]
fn the_wrapper_never_calls_for_a_non_retentive_type() {
    // Off riscv64 every ecall answers NOT_SUPPORTED. A non-retentive type
    // must come back INVALID_PARAM instead: refused before any call.
    assert_eq!(hart_suspend_retentive(DEFAULT_NON_RETENTIVE), ERR_INVALID_PARAM);
    assert_eq!(hart_suspend_retentive(PLATFORM_NON_RETENTIVE), ERR_INVALID_PARAM);
    assert_eq!(hart_suspend_retentive(DEFAULT_RETENTIVE), ERR_NOT_SUPPORTED, "went to the (absent) firmware");
}

#[test]
fn hart_suspend_needs_sbi_0_3_and_hsm() {
    assert!(!spec_has_hart_suspend(0x0000_0002), "0.2 has HSM but no hart_suspend");
    assert!(spec_has_hart_suspend(0x0000_0003));
    assert!(spec_has_hart_suspend(0x0100_0000), "major 1");
    assert!(!hart_suspend_available(), "no firmware on the host");
}

#[test]
fn return_codes_classify() {
    assert_eq!(classify_suspend(0), SuspendOutcome::Slept);
    assert_eq!(classify_suspend(ERR_NOT_SUPPORTED), SuspendOutcome::Unusable);
    assert_eq!(classify_suspend(ERR_INVALID_PARAM), SuspendOutcome::Unusable);
    assert_eq!(classify_suspend(ERR_DENIED), SuspendOutcome::Transient);
    assert_eq!(classify_suspend(ERR_FAILED), SuspendOutcome::Transient);
}

#[test]
fn depth_selection_falls_to_the_deepest_enterable_state_below() {
    let l = IdleLadder::EMPTY;
    // depth 1 retentive (0), depth 2 non-retentive, depth 3 retentive platform type.
    let mask = l.install(&[st(Some(DEFAULT_RETENTIVE)), st(Some(DEFAULT_NON_RETENTIVE)), st(Some(PLATFORM_RETENTIVE))]);
    assert_eq!(mask, 0b101);
    assert_eq!(l.entry(0), None, "depth 0 is wfi");
    assert_eq!(l.entry(1), Some(0), "parameter 0 is honoured");
    assert_eq!(l.entry(2), Some(0), "non-retentive depth 2 enters depth 1's state");
    assert_eq!(l.entry(3), Some(PLATFORM_RETENTIVE));
    assert_eq!(l.entry(4), Some(PLATFORM_RETENTIVE), "past the listed states: the deepest");
    assert_eq!(l.entry(255), Some(PLATFORM_RETENTIVE));
}

#[test]
fn no_enterable_state_below_means_wfi() {
    let l = IdleLadder::EMPTY;
    assert_eq!(l.install(&[st(Some(PLATFORM_NON_RETENTIVE)), st(None), st(Some(5))]), 0b100);
    assert_eq!(l.entry(1), None);
    assert_eq!(l.entry(2), None, "a missing parameter is not an entry");
    assert_eq!(l.entry(3), Some(5));
    assert_eq!(IdleLadder::EMPTY.entry(1), None, "nothing installed");
}

#[test]
fn more_states_than_the_ladder_holds_are_ignored() {
    let l = IdleLadder::EMPTY;
    let many = [st(Some(1)); IDLE_DEPTHS + 3];
    assert_eq!(l.install(&many), (1u8 << IDLE_DEPTHS) - 1);
}

#[test]
fn a_reinstall_replaces_the_whole_ladder() {
    let l = IdleLadder::EMPTY;
    l.install(&[st(Some(1)), st(Some(2))]);
    l.install(&[st(Some(3))]);
    assert_eq!(l.entry(1), Some(3));
    assert_eq!(l.entry(2), Some(3), "depth 2 is gone, the deepest left answers");
}

#[test]
fn enter_reports_sleep_and_falls_back_on_refusal() {
    let l = IdleLadder::EMPTY;
    l.install(&[st(Some(7)), st(Some(9))]);
    let seen = Cell::new(0u32);
    assert!(l.enter(2, |t| { seen.set(t); 0 }), "a sleep that returned 0 is a sleep");
    assert_eq!(seen.get(), 9);
    assert!(!l.enter(0, |_| panic!("depth 0 never calls the firmware")));
    // A transient refusal waits with wfi this time and tries again next time.
    assert!(!l.enter(2, |_| ERR_DENIED));
    assert_eq!(l.entry(2), Some(9), "DENIED does not retire the state");
}

#[test]
fn a_refused_type_is_retired_for_every_depth_and_the_shallower_state_takes_over() {
    let l = IdleLadder::EMPTY;
    l.install(&[st(Some(7)), st(Some(9)), st(Some(9))]);
    assert!(!l.enter(3, |t| { assert_eq!(t, 9); ERR_INVALID_PARAM }));
    assert_eq!(l.entry(3), Some(7), "both depths holding 9 are gone, depth 1 remains");
    assert_eq!(l.entry(2), Some(7));
    assert!(l.enter(3, |t| { assert_eq!(t, 7, "the retired type is not asked again"); 0 }));
    assert!(!l.enter(1, |_| ERR_NOT_SUPPORTED));
    assert_eq!(l.entry(3), None, "nothing left: wfi");
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Deep idle on aarch64: which `arm,psci-suspend-param` the idle seam may hand
//! to PSCI `CPU_SUSPEND`, and what it does with the answer.
//!
//! The mistake that matters is silent in the bad direction: a power-down state
//! entered by a kernel with no resume path wakes the CPU at the entry point
//! with the MMU off and its context gone, and every other test still passes.
//! StateType is bit 16 in the original `power_state` format and bit 30 in the
//! extended one, so the decode is pinned on a value that is a power-down in one
//! format and a standby in the other.

use crate::aarch64_firmware::*;
use std::cell::Cell;

const STANDBY: u32 = 0x0000_0000;
const RETENTION_ORIG: u32 = 0x0000_0001;
const POWERDOWN_ORIG: u32 = 0x0001_0033;
const RETENTION_EXT: u32 = 0x0000_1001;
const POWERDOWN_EXT: u32 = 0x4000_1033;

fn st(param: Option<u32>) -> SuspendState {
    SuspendState { param, local_timer_stop: false }
}

const O: PowerStateFormat = PowerStateFormat::Original;
const X: PowerStateFormat = PowerStateFormat::Extended;

#[test]
fn function_ids() {
    assert_eq!(PSCI_CPU_SUSPEND_64, 0xC400_0001);
    assert_eq!(PSCI_FEATURES, 0x8400_000A);
}

#[test]
fn state_type_is_bit_16_originally_and_bit_30_extended() {
    assert_eq!(O.type_bit(), 1 << 16);
    assert_eq!(X.type_bit(), 1 << 30);
    assert!(power_state_loses_context(POWERDOWN_ORIG, O));
    assert!(!power_state_loses_context(RETENTION_ORIG, O));
    assert!(power_state_loses_context(POWERDOWN_EXT, X));
    assert!(!power_state_loses_context(RETENTION_EXT, X));
    // The same words, read in the other format.
    assert!(!power_state_loses_context(POWERDOWN_EXT, O), "bit 30 is a StateID bit originally");
    assert!(power_state_loses_context(0x0001_0000, O));
    assert!(!power_state_loses_context(0x0001_0000, X), "bit 16 is a StateID bit when extended");
}

#[test]
fn the_format_comes_from_version_and_features() {
    let never = || -> i32 { panic!("PSCI_FEATURES does not exist before 1.0") };
    assert_eq!(suspend_format(-1, never), None, "PSCI_VERSION not implemented");
    assert_eq!(suspend_format(0x0000_0001, never), None, "0.1 has other function ids");
    assert_eq!(suspend_format(0x0000_0002, never), Some(O), "0.2: CPU_SUSPEND, original format");
    assert_eq!(suspend_format(0x0001_0000, || -1), None, "1.0 and CPU_SUSPEND_64 not implemented");
    assert_eq!(suspend_format(0x0001_0001, || 0), Some(O));
    assert_eq!(suspend_format(0x0001_0001, || 1), Some(O), "bit 0 is the mode, not the format");
    assert_eq!(suspend_format(0x0001_0001, || 2), Some(X));
    assert_eq!(suspend_format(0x0001_0001, || 3), Some(X));
}

#[test]
fn only_a_standby_timer_keeping_state_with_a_parameter_is_enterable() {
    assert_eq!(st(None).enterable(O), None, "no arm,psci-suspend-param");
    assert_eq!(st(Some(POWERDOWN_ORIG)).enterable(O), None);
    assert_eq!(st(Some(POWERDOWN_EXT)).enterable(X), None);
    assert_eq!(st(Some(STANDBY)).enterable(O), Some(0), "0 is a real power_state, not 'absent'");
    assert_eq!(st(Some(RETENTION_ORIG)).enterable(O), Some(RETENTION_ORIG));
    assert_eq!(st(Some(RETENTION_EXT)).enterable(X), Some(RETENTION_EXT));
    // A power-down word in the format the firmware does not use is a standby here.
    assert_eq!(st(Some(POWERDOWN_EXT)).enterable(O), Some(POWERDOWN_EXT));
    let stops = SuspendState { param: Some(RETENTION_ORIG), local_timer_stop: true };
    assert_eq!(stops.enterable(O), None, "local-timer-stop: the wake-up timer would be lost");
}

#[test]
fn return_codes_classify() {
    assert_eq!(classify_suspend(PSCI_OK), SuspendOutcome::Slept);
    assert_eq!(classify_suspend(PSCI_NOT_SUPPORTED), SuspendOutcome::Unusable);
    assert_eq!(classify_suspend(PSCI_INVALID_PARAMS), SuspendOutcome::Unusable);
    assert_eq!(classify_suspend(PSCI_DENIED), SuspendOutcome::Transient);
    assert_eq!(classify_suspend(PSCI_INTERNAL_FAILURE), SuspendOutcome::Transient);
}

#[test]
fn depth_selection_falls_to_the_deepest_enterable_state_below() {
    let l = IdleLadder::EMPTY;
    // depth 1 standby (0), depth 2 power-down, depth 3 retention.
    let mask = l.install(&[st(Some(STANDBY)), st(Some(POWERDOWN_ORIG)), st(Some(RETENTION_ORIG))], O);
    assert_eq!(mask, 0b101);
    assert_eq!(l.entry(0), None, "depth 0 is wfi");
    assert_eq!(l.entry(1), Some(0), "power_state 0 is honoured");
    assert_eq!(l.entry(2), Some(0), "power-down depth 2 enters depth 1's state");
    assert_eq!(l.entry(3), Some(RETENTION_ORIG));
    assert_eq!(l.entry(4), Some(RETENTION_ORIG), "past the listed states: the deepest");
    assert_eq!(l.entry(255), Some(RETENTION_ORIG));
}

#[test]
fn the_format_changes_what_is_a_power_down() {
    let words = [st(Some(0x0001_0000)), st(Some(0x4000_0000))];
    assert_eq!(IdleLadder::EMPTY.install(&words, O), 0b10);
    assert_eq!(IdleLadder::EMPTY.install(&words, X), 0b01);
}

#[test]
fn no_enterable_state_below_means_wfi() {
    let l = IdleLadder::EMPTY;
    assert_eq!(l.install(&[st(Some(POWERDOWN_ORIG)), st(None), st(Some(5))], O), 0b100);
    assert_eq!(l.entry(1), None);
    assert_eq!(l.entry(2), None, "a missing parameter is not an entry");
    assert_eq!(l.entry(3), Some(5));
    assert_eq!(IdleLadder::EMPTY.entry(1), None, "nothing installed");
}

#[test]
fn more_states_than_the_ladder_holds_are_ignored() {
    let l = IdleLadder::EMPTY;
    let many = [st(Some(1)); IDLE_DEPTHS + 3];
    assert_eq!(l.install(&many, O), (1u8 << IDLE_DEPTHS) - 1);
}

#[test]
fn a_reinstall_replaces_the_whole_ladder() {
    let l = IdleLadder::EMPTY;
    l.install(&[st(Some(1)), st(Some(2))], O);
    l.install(&[st(Some(3))], O);
    assert_eq!(l.entry(1), Some(3));
    assert_eq!(l.entry(2), Some(3), "depth 2 is gone, the deepest left answers");
}

#[test]
fn enter_reports_sleep_and_falls_back_on_refusal() {
    let l = IdleLadder::EMPTY;
    l.install(&[st(Some(7)), st(Some(9))], O);
    let seen = Cell::new(0u32);
    assert!(l.enter(2, |p| { seen.set(p); PSCI_OK }));
    assert_eq!(seen.get(), 9);
    assert!(!l.enter(0, |_| panic!("depth 0 never calls the firmware")));
    // A transient refusal waits with wfi this time and tries again next time.
    assert!(!l.enter(2, |_| PSCI_DENIED));
    assert_eq!(l.entry(2), Some(9), "DENIED does not retire the state");
}

#[test]
fn a_refused_state_is_retired_for_every_depth_and_the_shallower_state_takes_over() {
    let l = IdleLadder::EMPTY;
    l.install(&[st(Some(7)), st(Some(9)), st(Some(9))], O);
    assert!(!l.enter(3, |p| { assert_eq!(p, 9); PSCI_INVALID_PARAMS }));
    assert_eq!(l.entry(3), Some(7), "both depths holding 9 are gone, depth 1 remains");
    assert_eq!(l.entry(2), Some(7));
    assert!(l.enter(3, |p| { assert_eq!(p, 7, "the retired state is not asked again"); PSCI_OK }));
    assert!(!l.enter(1, |_| PSCI_NOT_SUPPORTED));
    assert_eq!(l.entry(3), None, "nothing left: wfi");
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the receipt index (innovation B3) as the effect gate
//! feeds it: an effect that reached its device left a receipt, one the gate
//! refused did not, and a stop contradicts the drive before it. The index
//! itself (cells, bounds, ages) is tested in `logger.rs`
//! (`receipt_index_tests`); the capability side in `tests/host/cap-tests`.
//!
//! Each test uses a wheel of its own: the index is process state.

use crate::effect_gate::{self, Class, Effect, Timing, KIND_MOTOR};
use crate::logger::*;
use crate::tests::fresh;

const DRIVE: u8 = 1;
const STOP: u8 = 0;

fn wheel(subject: u16, class: Class) -> Effect {
    Effect { kind: KIND_MOTOR, class, subject, tid: 7, a0: 1, a1: 50 }
}

fn device(subject: u16) -> u16 {
    (KIND_MOTOR as u16) << 8 | subject
}

fn issue(e: &Effect) -> Result<(), effect_gate::Refusal> {
    effect_gate::issue(e, &Timing::NONE, || ((), true))
}

/// The clock `ms` milliseconds after boot.
fn at(ms: u64) {
    azos_drv_sys::clint::set_test_time(ms * (azos_drv_sys::timebase::TIMER_FREQ / 1000));
}

/// An effect the gate let through left a receipt of its class on its device;
/// the stop that follows is younger than the drive and contradicts it; the
/// drive after that contradicts the stop; another wheel has none.
/// **Canary.** Skip `receipt_note` in `commit_effect_record`: every row below
/// finds no receipt, red.
#[test]
fn an_issued_effect_leaves_a_receipt_and_a_stop_contradicts_a_drive() {
    let _g = fresh();
    at(1_000);
    issue(&wheel(25, Class::Reversible)).expect("issued");
    at(1_300);
    assert_eq!(receipt_ages(device(25), DRIVE), (300, NO_RECEIPT_AGE), "driven 300 ms ago, no stop since");
    assert_eq!(receipt_ages(device(25), STOP), (NO_RECEIPT_AGE, 300));
    assert_eq!(receipt_ages(device(26), DRIVE), (NO_RECEIPT_AGE, NO_RECEIPT_AGE), "another wheel");

    issue(&wheel(25, Class::Safe)).expect("a stop is never refused");
    at(1_400);
    assert_eq!(receipt_ages(device(25), STOP), (100, 400), "stopped 100 ms ago, after the drive");
    let (drive_age, stop_age) = receipt_ages(device(25), DRIVE);
    assert!(stop_age < drive_age, "the stop contradicts the drive: {stop_age} < {drive_age}");

    issue(&wheel(25, Class::Reversible)).expect("issued");
    at(1_450);
    let (drive_age, stop_age) = receipt_ages(device(25), DRIVE);
    assert!(drive_age < stop_age, "driven again after the stop");
    azos_drv_sys::clint::clear_test_time();
}

/// An effect the ring refuses never reached its device and left no receipt:
/// a warrant conditioned on it stays refused. **Canary.** Note the receipt
/// before the ring's verdict in `commit_effect_record`: the refused effect
/// leaves one, red.
#[test]
fn a_refused_effect_leaves_no_receipt() {
    let _g = fresh();
    at(2_000);
    let limit = LOG_RING_CAPACITY - RING_SAFETY_RESERVE;
    for _ in 0..limit {
        issue(&wheel(27, Class::Reversible)).expect("under the limit");
    }
    assert!(issue(&wheel(28, Class::Reversible)).is_err(), "the ring is at its effect limit");
    assert_eq!(receipt_ages(device(28), DRIVE), (NO_RECEIPT_AGE, NO_RECEIPT_AGE));
    assert_eq!(receipt_ages(device(27), DRIVE).0, 0, "the wheel that did reach its device has one");
    azos_drv_sys::clint::clear_test_time();
}

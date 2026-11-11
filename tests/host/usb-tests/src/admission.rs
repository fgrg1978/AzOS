// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which interfaces of a plugged device reach a class driver: the signed
//! topology's `[usb.*]` rows, and what a build does with none.

use azos_usb::admit::{Admission, Reason, Row};
use azos_usb::class::Match;

use crate::devices::{keyboard, stick};
use crate::harness::Rig;

fn row(vid: Option<u16>, pid: Option<u16>, class: Option<u8>, allow: bool) -> Row {
    Row { vid, pid, class, allow }
}

fn admission(open: bool, rows: &[Row]) -> Admission {
    let mut a = Admission::with_default(open);
    for r in rows {
        a.push(*r);
    }
    a
}

/// A rig with the rows set, a driver for mass storage (0), one for vendor
/// interfaces (1) and one for HID (2), and `dev` plugged in.
fn plugged(a: Admission, dev: crate::devices::DevRef) -> Rig {
    let mut rig = Rig::new();
    rig.usb.set_admission(a);
    rig.add_driver(Match::interface_class(8), true);
    rig.add_driver(Match::interface_class(0xff), true);
    rig.add_driver(Match::interface_class(3), true);
    rig.hw.attach_root(1, dev);
    rig.settle();
    rig
}

fn bound(rig: &Rig) -> [usize; 3] {
    [0, 1, 2].map(|i| rig.driver(i).attached.len())
}

#[test]
fn a_device_no_row_matches_binds_nothing_once_rows_exist() {
    let a = admission(true, &[row(Some(0x046d), None, Some(3), true)]);
    let rig = plugged(a, stick());
    assert_eq!(bound(&rig), [0, 0, 0]);
    assert_eq!(rig.usb.stats().refused, 2, "both interfaces");
    assert_eq!(rig.usb.devices().count(), 1, "the device itself is still enumerated");
}

#[test]
fn a_row_admits_the_interfaces_it_names_and_only_those() {
    let a = admission(false, &[row(Some(0x0781), Some(0x5567), Some(8), true)]);
    let rig = plugged(a, stick());
    assert_eq!(bound(&rig), [1, 0, 0]);
    assert_eq!(rig.usb.stats().refused, 1);
}

#[test]
fn a_keyboard_binds_only_when_a_row_admits_it() {
    let rig = plugged(admission(false, &[]), keyboard());
    assert_eq!(bound(&rig), [0, 0, 0], "no rows, closed build");
    let rig = plugged(admission(true, &[row(None, None, Some(8), true)]), keyboard());
    assert_eq!(bound(&rig), [0, 0, 0], "a row for storage does not admit a keyboard");
    let rig = plugged(admission(false, &[row(Some(0x046d), Some(0xc31c), None, true)]), keyboard());
    assert_eq!(bound(&rig), [0, 0, 1]);
}

#[test]
fn the_first_matching_row_decides() {
    let a = admission(true, &[row(None, None, Some(8), false), row(None, None, None, true)]);
    let rig = plugged(a, stick());
    assert_eq!(bound(&rig), [0, 1, 0], "storage refused, the catch-all admits the rest");
    let a = admission(true, &[row(Some(0x0781), None, None, true), row(None, None, Some(8), false)]);
    let rig = plugged(a, stick());
    assert_eq!(bound(&rig), [1, 1, 0]);
}

#[test]
fn with_no_rows_the_build_decides() {
    assert_eq!(bound(&plugged(admission(true, &[]), stick())), [1, 1, 0]);
    let rig = plugged(admission(false, &[]), stick());
    assert_eq!(bound(&rig), [0, 0, 0]);
    assert_eq!(rig.usb.stats().refused, 2);
}

#[test]
fn more_rows_than_fit_admit_nothing() {
    let mut a = Admission::with_default(true);
    for _ in 0..=azos_usb::admit::MAX_ROWS {
        a.push(row(None, None, None, true));
    }
    assert_eq!(a.decide(1, 2, 3), Reason::NoRow);
}

#[test]
fn the_reasons_say_why() {
    let a = admission(false, &[row(Some(1), None, None, true), row(Some(2), None, None, false)]);
    assert_eq!(a.decide(1, 9, 3), Reason::Row);
    assert_eq!(a.decide(2, 9, 3), Reason::RowRefuses);
    assert_eq!(a.decide(3, 9, 3), Reason::NoRow);
    assert_eq!(admission(false, &[]).decide(1, 1, 1), Reason::NoRows);
    assert_eq!(admission(true, &[]).decide(1, 1, 1), Reason::OpenWithoutRows);
}

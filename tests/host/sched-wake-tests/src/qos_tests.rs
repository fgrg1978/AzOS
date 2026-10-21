// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/core/sched/src/qos.rs`, the real file: the switch
//! path's per-hart tag cache (write only on change) and the fit rule of a
//! row's partition against what the hardware can tag. The hardware write is a
//! counting closure, the same seam `asid::qos_retag` fills with
//! `Cpu::set_qos_tag`.

use crate::qos::{fit, HartTags, HARTS};
use std::cell::RefCell;

/// A fake hart: records every tag written, accepts ids up to `max`.
struct Fake {
    max: u16,
    writes: RefCell<Vec<u16>>,
}

impl Fake {
    fn new(max: u16) -> Self {
        Self { max, writes: RefCell::new(Vec::new()) }
    }
    fn write(&self, p: u16) -> bool {
        if p > self.max {
            return false;
        }
        self.writes.borrow_mut().push(p);
        true
    }
}

#[test]
fn the_first_switch_in_writes_even_partition_zero() {
    let tags = HartTags::new();
    let hw = Fake::new(15);
    assert_eq!(tags.held(0), None, "nothing is known of the hart's reset value");
    assert!(tags.retag(0, 0, |p| hw.write(p)), "the hart is made to hold 0, not assumed to");
    assert_eq!(*hw.writes.borrow(), vec![0]);
    assert_eq!(tags.held(0), Some(0));
}

#[test]
fn a_switch_to_the_same_partition_writes_nothing() {
    let tags = HartTags::new();
    let hw = Fake::new(15);
    for _ in 0..5 {
        tags.retag(0, 3, |p| hw.write(p));
    }
    assert_eq!(*hw.writes.borrow(), vec![3], "one write for five switches into partition 3");
}

#[test]
fn a_change_writes_once_and_back_writes_again() {
    let tags = HartTags::new();
    let hw = Fake::new(15);
    for p in [0, 0, 7, 7, 0, 7] {
        tags.retag(0, p, |p| hw.write(p));
    }
    assert_eq!(*hw.writes.borrow(), vec![0, 7, 0, 7]);
}

#[test]
fn each_hart_has_its_own_cache() {
    let tags = HartTags::new();
    let hw = Fake::new(15);
    assert!(HARTS >= 2, "the test needs two CPUs");
    tags.retag(0, 5, |p| hw.write(p));
    // CPU 1 still holds whatever the hardware reset it to: it must write.
    assert!(tags.retag(1, 5, |p| hw.write(p)));
    assert!(!tags.retag(1, 5, |p| hw.write(p)));
    assert!(!tags.retag(0, 5, |p| hw.write(p)));
    assert_eq!(*hw.writes.borrow(), vec![5, 5]);
    assert_eq!((tags.held(0), tags.held(1)), (Some(5), Some(5)));
}

#[test]
fn a_refused_write_is_not_remembered() {
    let tags = HartTags::new();
    let hw = Fake::new(3);
    assert!(!tags.retag(0, 9, |p| hw.write(p)), "the hardware cannot tag 9");
    assert_eq!(tags.held(0), None, "the cache does not claim a write that did not happen");
    assert!(!tags.retag(0, 9, |p| hw.write(p)), "so the next switch asks again");
    assert!(hw.writes.borrow().is_empty());
    assert!(tags.retag(0, 3, |p| hw.write(p)));
}

#[test]
fn a_cpu_past_the_table_writes_every_time() {
    let tags = HartTags::new();
    let hw = Fake::new(3);
    assert!(tags.retag(HARTS, 1, |p| hw.write(p)));
    assert!(tags.retag(HARTS, 1, |p| hw.write(p)));
    assert_eq!(hw.writes.borrow().len(), 2);
}

#[test]
fn fit_keeps_a_partition_the_hardware_can_tag_and_refuses_one_it_cannot() {
    // A machine that tags up to 15.
    assert_eq!(fit(1, 15), 1);
    assert_eq!(fit(15, 15), 15, "the last RCID fits");
    assert_eq!(fit(16, 15), 0, "one past it would alias: the default partition");
    assert_eq!(fit(65535, 15), 0);
    assert_eq!(fit(0, 15), 0);
    // A machine that does not tag (ISA without it, Kconfig n, probe failed):
    // nothing to alias, the row's id is kept for introspection.
    assert_eq!(fit(7, 0), 7);
    assert_eq!(fit(65535, 0), 65535);
}

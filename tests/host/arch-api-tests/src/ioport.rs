// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_arch_api::ioport`: a thread's open port ranges and the key that
//! names each set (the TSS bitmap cache of x86_64 trusts it).

use azos_arch_api::ioport::{GrantFull, PortGrant, RANGES};
use azos_arch_api::IoPorts;

#[test]
fn a_new_grant_is_empty() {
    let g = PortGrant::new();
    let mut out = [(0, 0); RANGES];
    assert_eq!(g.key(), 0);
    assert_eq!(g.ranges(&mut out), 0);
}

/// Every change of the set takes a key no other set had: a CPU that holds
/// key K's bitmap never mistakes another set for it.
#[test]
fn each_change_takes_a_fresh_key() {
    let a = PortGrant::new();
    let b = PortGrant::new();
    assert_eq!(a.add(0x42, 0x43), Ok(true));
    let k1 = a.key();
    assert_ne!(k1, 0);
    assert_eq!(b.add(0x42, 0x43), Ok(true));
    assert_ne!(b.key(), k1, "the same ranges in another thread: another key");
    if RANGES > 1 {
        assert_eq!(a.add(0x61, 0x61), Ok(true));
        assert_ne!(a.key(), k1);
    }
    let k2 = a.key();
    a.clear();
    assert_eq!(a.key(), 0);
    assert_eq!(a.add(0x42, 0x43), Ok(true));
    assert!(a.key() != k1 && a.key() != k2, "a cleared slot never reuses a key");
}

/// A range an open one already holds changes nothing, the key included.
#[test]
fn a_covered_range_keeps_the_key() {
    let g = PortGrant::new();
    assert_eq!(g.add(0x40, 0x43), Ok(true));
    let k = g.key();
    assert_eq!(g.add(0x42, 0x43), Ok(false));
    assert_eq!(g.add(0x40, 0x43), Ok(false));
    assert_eq!(g.key(), k);
    let mut out = [(0, 0); RANGES];
    assert_eq!(g.ranges(&mut out), 1);
    assert_eq!(out[0], (0x40, 0x43));
}

#[test]
fn full_at_ranges() {
    let g = PortGrant::new();
    for i in 0..RANGES as u16 {
        assert_eq!(g.add(i * 8, i * 8), Ok(true));
    }
    let k = g.key();
    assert_eq!(g.add(0x400, 0x400), Err(GrantFull::Full));
    assert_eq!(g.key(), k, "a refused add changes nothing");
    let mut out = [(0, 0); RANGES];
    assert_eq!(g.ranges(&mut out), RANGES);
}

/// The trait's defaults are the ISAs without a port space: nothing loads.
#[test]
fn the_default_loads_nothing() {
    struct NoPorts;
    impl IoPorts for NoPorts {}
    let g = PortGrant::new();
    g.add(1, 2).unwrap();
    NoPorts.io_ports_load(0, &g);
}

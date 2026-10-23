// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_arch_api::ioport`: a thread's open port ranges and the key that
//! names each set (the TSS bitmap cache of x86_64 trusts it).

use azos_arch_api::ioport::{GrantFull, PortGrant, PortSet, RANGES};
use azos_arch_api::IoPorts;

/// The capability table the tests' ranges are opened through.
const T: u32 = 7;

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
    assert_eq!(a.add(0x42, 0x43, T), Ok(true));
    let k1 = a.key();
    assert_ne!(k1, 0);
    assert_eq!(b.add(0x42, 0x43, T), Ok(true));
    assert_ne!(b.key(), k1, "the same ranges in another thread: another key");
    if RANGES > 1 {
        assert_eq!(a.add(0x61, 0x61, T), Ok(true));
        assert_ne!(a.key(), k1);
    }
    let k2 = a.key();
    a.clear();
    assert_eq!(a.key(), 0);
    assert_eq!(a.add(0x42, 0x43, T), Ok(true));
    assert!(a.key() != k1 && a.key() != k2, "a cleared slot never reuses a key");
}

/// A range an open one already holds changes nothing, the key included.
#[test]
fn a_covered_range_keeps_the_key() {
    let g = PortGrant::new();
    assert_eq!(g.add(0x40, 0x43, T), Ok(true));
    let k = g.key();
    assert_eq!(g.add(0x42, 0x43, T), Ok(false));
    assert_eq!(g.add(0x40, 0x43, T), Ok(false));
    assert_eq!(g.key(), k);
    let mut out = [(0, 0); RANGES];
    assert_eq!(g.ranges(&mut out), 1);
    assert_eq!(out[0], (0x40, 0x43));
}

#[test]
fn full_at_ranges() {
    let g = PortGrant::new();
    for i in 0..RANGES as u16 {
        assert_eq!(g.add(i * 8, i * 8, T), Ok(true));
    }
    let k = g.key();
    assert_eq!(g.add(0x400, 0x400, T), Err(GrantFull::Full));
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
    g.add(1, 2, T).unwrap();
    NoPorts.io_ports_load(0, &g);
}

/// A capability that leaves the table closes the ranges inside its range,
/// and only those, under a new key; the last one closed is key 0.
///
/// **Canary.** Keep the key in `remove_within`: the key after the first
/// close equals the key before it (a CPU holding that bitmap would keep
/// showing the closed range).
#[test]
fn a_revoked_range_closes_under_a_new_key() {
    let g = PortGrant::new();
    assert_eq!(g.add(0x42, 0x43, T), Ok(true));
    if RANGES > 1 {
        assert_eq!(g.add(0x61, 0x61, T), Ok(true));
    }
    let k = g.key();
    assert!(!g.remove_within(T, 0x44, 0x60), "nothing inside: nothing closes");
    assert!(!g.remove_within(T, 0x42, 0x42), "a range only partly inside stays");
    assert_eq!(g.key(), k, "nothing closed, the key stays");
    if RANGES > 1 {
        assert!(g.remove_within(T, 0x61, 0x61));
        assert!(g.key() != k && g.key() != 0, "a smaller set, a fresh key");
        let mut out = [(0, 0); RANGES];
        assert_eq!(g.ranges(&mut out), 1);
        assert_eq!(out[0], (0x42, 0x43), "the range outside stays");
    }
    assert!(g.remove_within(T, 0x40, 0x43), "a range inside a wider revoked one closes");
    assert_eq!(g.key(), 0, "nothing open: key 0, the CPU shows no port");
    let mut out = [(0, 0); RANGES];
    assert_eq!(g.ranges(&mut out), 0);
}

/// Only the table the set was opened through closes it: another domain's
/// capability over the same ports is not this thread's.
#[test]
fn another_tables_revocation_closes_nothing() {
    let g = PortGrant::new();
    assert_eq!(g.add(0x80, 0x80, T), Ok(true));
    let k = g.key();
    assert!(!g.remove_within(T + 1, 0, 0xFFFF));
    assert_eq!(g.key(), k);
    assert!(g.remove_within(T, 0, 0xFFFF), "positive control");
    g.clear();
    assert!(!g.remove_within(T, 0, 0xFFFF), "a cleared set belongs to no table");
}

/// The kernel's ports: a range holds one when any of its ports is in the
/// set; a port past the set's reach is never in it.
///
/// **Canary.** Test only the first port of the range in `first_in`: COM1's
/// range found from 0x3F0 goes unseen.
#[test]
fn the_port_set_finds_the_first_kernel_port_of_a_range() {
    let k: PortSet<32> = PortSet::new();
    k.insert(0x3F8, 0x3FF);
    k.insert(0x40, 0x40);
    assert_eq!(k.first_in(0x3F0, 0x3FF), Some(0x3F8));
    assert_eq!(k.first_in(0x3FC, 0x3FC), Some(0x3FC));
    assert_eq!(k.first_in(0x40, 0x43), Some(0x40));
    assert_eq!(k.first_in(0x42, 0x43), None, "the speaker's channel and the mode register");
    assert_eq!(k.first_in(0x61, 0x61), None);
    k.insert(0xCF8, 0xCFF);
    assert_eq!(k.first_in(0, 0xFFFF), Some(0x40));
    assert_eq!(k.first_in(0x400, 0xFFFF), None, "past 1024 ports: not kept, never granted either");
}

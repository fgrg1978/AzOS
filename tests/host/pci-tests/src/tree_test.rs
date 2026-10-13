// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `enumerate_tree`: bus 0 and the buses behind PCI-to-PCI bridges, against a
//! fake config space with several buses.

use azos_pci::*;
use std::collections::HashMap;

/// Config space of a machine: 64 dwords per function is enough for the header.
struct Tree {
    f: HashMap<(u8, u8, u8), [u32; 64]>,
}

impl Tree {
    fn new() -> Self {
        Tree { f: HashMap::new() }
    }

    fn endpoint(&mut self, bus: u8, dev: u8, func: u8, vendor: u16, device: u16, class: u32, multifunction: bool) {
        let mut d = [0u32; 64];
        d[0] = (device as u32) << 16 | vendor as u32;
        d[2] = class << 8;
        d[3] = (if multifunction { 0x80 } else { 0 }) << 16;
        self.f.insert((bus, dev, func), d);
    }

    /// A bridge on `bus` whose secondary bus is `secondary`.
    fn bridge(&mut self, bus: u8, dev: u8, secondary: u8) {
        let mut d = [0u32; 64];
        d[0] = 0x1b36 | 0x000c << 16;
        d[2] = 0x0006_0400 << 8;
        d[3] = 1 << 16; // header type 1
        d[6] = (secondary as u32) << 8 | bus as u32; // primary | secondary << 8
        self.f.insert((bus, dev, 0), d);
    }
}

impl ConfigSpace for Tree {
    fn read32(&self, bdf: Bdf, offset: u16) -> u32 {
        match self.f.get(&(bdf.bus, bdf.device, bdf.function)) {
            Some(d) => d[(offset / 4) as usize],
            None => 0xffff_ffff,
        }
    }
    fn write32(&mut self, _bdf: Bdf, _offset: u16, _val: u32) {}
}

fn ids(funcs: &[Option<FunctionInfo>], n: usize) -> Vec<(u8, u8, u8, u16, u16)> {
    funcs[..n].iter().flatten().map(|f| (f.bdf.bus, f.bdf.device, f.bdf.function, f.vendor, f.device)).collect()
}

#[test]
fn a_function_carries_its_class_code() {
    let mut t = Tree::new();
    t.endpoint(0, 4, 0, 0x8086, 0x5845, 0x010802, false);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| false);
    assert_eq!(n, 1);
    assert_eq!(f[0].unwrap().class, 0x010802);
}

#[test]
fn buses_behind_bridges_are_walked_in_discovery_order() {
    let mut t = Tree::new();
    t.endpoint(0, 1, 0, 0x1af4, 0x1041, 0x020000, false);
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    t.bridge(1, 1, 2);
    t.endpoint(2, 0, 0, 0x10ec, 0x8168, 0x020000, false);
    t.bridge(0, 3, 3);
    t.endpoint(3, 0, 0, 0x1b36, 0x000d, 0x0c0330, false);
    let mut asked = Vec::new();
    let (f, n) = enumerate_tree::<Tree, 16>(&mut t, &mut |b| { asked.push(b); true });
    // Bus 0 first (its bridges included), then buses in the order found: 1, 3, then 2 behind 1.
    assert_eq!(ids(&f, n), [
        (0, 1, 0, 0x1af4, 0x1041), (0, 2, 0, 0x1b36, 0x000c), (0, 3, 0, 0x1b36, 0x000c),
        (1, 0, 0, 0x8086, 0x5845), (1, 1, 0, 0x1b36, 0x000c),
        (3, 0, 0, 0x1b36, 0x000d),
        (2, 0, 0, 0x10ec, 0x8168),
    ]);
    assert_eq!(asked, [1, 3, 2], "each bus beyond 0 is asked for once, before it is read");
}

#[test]
fn a_bus_the_caller_cannot_reach_is_skipped() {
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| false);
    assert_eq!(ids(&f, n), [(0, 2, 0, 0x1b36, 0x000c)]);
}

#[test]
fn a_bridge_that_leads_nowhere_or_back_adds_no_bus() {
    let mut t = Tree::new();
    t.bridge(0, 1, 0); // no secondary bus assigned
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    t.bridge(1, 1, 1); // points at its own bus
    t.bridge(1, 2, 0); // points back at the root
    t.bridge(0, 3, 1); // a second bridge to a bus already queued
    let mut asked = Vec::new();
    let (f, n) = enumerate_tree::<Tree, 16>(&mut t, &mut |b| { asked.push(b); true });
    assert_eq!(asked, [1]);
    assert_eq!(n, 3 + 1 + 2, "the root's three bridges, the endpoint and two bridges on bus 1");
    let _ = f;
}

#[test]
fn only_function_0_of_a_single_function_device_is_probed() {
    let mut t = Tree::new();
    t.endpoint(0, 5, 0, 0x1af4, 0x1041, 0x020000, false);
    t.endpoint(0, 5, 1, 0x1af4, 0x1042, 0x010000, false); // would be a ghost
    t.endpoint(0, 6, 0, 0x8086, 0x1234, 0x020000, true);
    t.endpoint(0, 6, 3, 0x8086, 0x1235, 0x020000, false);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    assert_eq!(ids(&f, n), [(0, 5, 0, 0x1af4, 0x1041), (0, 6, 0, 0x8086, 0x1234), (0, 6, 3, 0x8086, 0x1235)]);
}

#[test]
fn the_output_capacity_is_a_bound_not_a_panic() {
    let mut t = Tree::new();
    for d in 0..10 {
        t.endpoint(0, d, 0, 0x1af4, 0x1041, 0x020000, false);
    }
    let (_, n) = enumerate_tree::<Tree, 4>(&mut t, &mut |_| true);
    assert_eq!(n, 4);
}

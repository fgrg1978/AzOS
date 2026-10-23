// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `enumerate_tree`: bus 0 and the buses behind PCI-to-PCI bridges, against a
//! fake config space with several buses.

use azos_pci::*;
use std::collections::{HashMap, HashSet};

/// How one BAR slot answers a size probe.
#[derive(Clone, Copy)]
enum Slot {
    None,
    /// Low (or only) dword of a memory BAR: `size`, the fixed type bits.
    Lo { size: u64, fixed: u32 },
    /// High dword of a 64-bit BAR of `size` bytes.
    Hi { size: u64 },
}

struct Func {
    d: [u32; 64],
    slots: [Slot; 6],
}

/// Config space of a machine with several buses: 64 dwords per function is
/// enough for a type-0 or type-1 header. A write lands in the register file
/// (a BAR slot answers a size probe like hardware, Command/Status keep it
/// simple); a function in `ignoring` drops every write (hardware that
/// ignores bus numbers). A bus is readable only while a bridge's current
/// secondary/subordinate numbers lead to it, so a walk that reads a bus
/// before numbering its bridge sees an empty bus.
pub(crate) struct Tree {
    f: HashMap<(u8, u8, u8), Func>,
    pub(crate) ignoring: HashSet<(u8, u8, u8)>,
    /// Every write, in order.
    pub(crate) writes: Vec<(Bdf, u16, u32)>,
}

impl Tree {
    pub(crate) fn new() -> Self {
        Tree { f: HashMap::new(), ignoring: HashSet::new(), writes: Vec::new() }
    }

    pub(crate) fn endpoint(&mut self, bus: u8, dev: u8, func: u8, vendor: u16, device: u16, class: u32, multifunction: bool) {
        let mut d = [0u32; 64];
        d[0] = (device as u32) << 16 | vendor as u32;
        d[2] = class << 8;
        d[3] = (if multifunction { 0x80 } else { 0 }) << 16;
        self.f.insert((bus, dev, func), Func { d, slots: [Slot::None; 6] });
    }

    /// A bridge on `bus` whose secondary (and subordinate) bus is `secondary`.
    pub(crate) fn bridge(&mut self, bus: u8, dev: u8, secondary: u8) {
        self.bridge_range(bus, dev, secondary, secondary);
    }

    pub(crate) fn bridge_range(&mut self, bus: u8, dev: u8, secondary: u8, subordinate: u8) {
        let mut d = [0u32; 64];
        d[0] = 0x1b36 | 0x000c << 16;
        d[2] = 0x0006_0400 << 8;
        d[3] = 1 << 16; // header type 1
        d[6] = (subordinate as u32) << 16 | (secondary as u32) << 8 | bus as u32;
        // 64-bit prefetchable window capable, as every PCIe bridge.
        d[9] = 0x0001_0001;
        self.f.insert((bus, dev, 0), Func { d, slots: [Slot::None; 6] });
    }

    /// The bridge at `bus:dev.0` decodes only 32 bits of prefetchable
    /// memory (the low nibble of its prefetchable base reads 0).
    pub(crate) fn pref_32bit_only(&mut self, bus: u8, dev: u8) {
        self.f.get_mut(&(bus, dev, 0)).unwrap().d[9] = 0;
    }

    /// Give BAR slot `index` of the function a memory BAR of `size` bytes.
    pub(crate) fn bar(&mut self, bus: u8, dev: u8, func: u8, index: usize, is64: bool, prefetchable: bool, size: u64) {
        let fixed = if is64 { 0x4 } else { 0 } | if prefetchable { 0x8 } else { 0 };
        let f = self.f.get_mut(&(bus, dev, func)).unwrap();
        f.slots[index] = Slot::Lo { size, fixed };
        f.d[4 + index] = fixed;
        if is64 {
            f.slots[index + 1] = Slot::Hi { size };
        }
    }

    /// The function at `bus:dev.0`'s register at byte `offset`.
    pub(crate) fn reg(&self, bus: u8, dev: u8, offset: u16) -> u32 {
        self.f[&(bus, dev, 0)].d[(offset / 4) as usize]
    }

    fn reachable(&self, bus: u8) -> bool {
        bus == 0
            || self.f.iter().any(|(&(b, _, _), f)| {
                f.d[3] >> 16 & 0x7f == 1 && {
                    let (sec, sub) = ((f.d[6] >> 8 & 0xff) as u8, (f.d[6] >> 16 & 0xff) as u8);
                    b < bus && sec != 0 && sec <= bus && bus <= sub && self.reachable(b)
                }
            })
    }
}

impl ConfigSpace for Tree {
    fn read32(&self, bdf: Bdf, offset: u16) -> u32 {
        match self.f.get(&(bdf.bus, bdf.device, bdf.function)) {
            Some(f) if self.reachable(bdf.bus) => f.d[(offset / 4) as usize],
            _ => 0xffff_ffff,
        }
    }

    fn write32(&mut self, bdf: Bdf, offset: u16, val: u32) {
        self.writes.push((bdf, offset, val));
        let key = (bdf.bus, bdf.device, bdf.function);
        if self.ignoring.contains(&key) || !self.reachable(bdf.bus) {
            return;
        }
        let Some(f) = self.f.get_mut(&key) else { return };
        let i = (offset / 4) as usize;
        if offset == OFF_COMMAND {
            f.d[i] = f.d[i] & 0xffff_0000 | val & 0xffff;
            return;
        }
        let bar_end = if f.d[3] >> 16 & 0x7f == 1 { OFF_BAR0 + 8 } else { OFF_BAR0 + 24 };
        if (OFF_BAR0..bar_end).contains(&offset) {
            let slot = f.slots[((offset - OFF_BAR0) / 4) as usize];
            f.d[i] = match slot {
                Slot::None => 0,
                Slot::Lo { size, fixed } => (val & !((size - 1) as u32) & !0xf) | fixed,
                Slot::Hi { size } => val & ((!(size - 1)) >> 32) as u32,
            };
            return;
        }
        f.d[i] = val;
    }
}

fn ids(funcs: &[Option<FunctionInfo>], n: usize) -> Vec<(u8, u8, u8, u16, u16)> {
    funcs[..n].iter().flatten().map(|f| (f.bdf.bus, f.bdf.device, f.bdf.function, f.vendor, f.device)).collect()
}

#[test]
fn a_function_carries_its_class_code() {
    let mut t = Tree::new();
    t.endpoint(0, 4, 0, 0x8086, 0x5845, 0x010802, false);
    let Found { funcs: f, n, .. } = enumerate_tree::<Tree, 8>(&mut t, &mut |_| false);
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
    let Found { funcs: f, n, .. } = enumerate_tree::<Tree, 16>(&mut t, &mut |b| { asked.push(b); true });
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
    let Found { funcs: f, n, .. } = enumerate_tree::<Tree, 8>(&mut t, &mut |_| false);
    assert_eq!(ids(&f, n), [(0, 2, 0, 0x1b36, 0x000c)]);
}

#[test]
fn a_bridge_that_leads_nowhere_or_back_adds_no_bus_when_it_cannot_be_numbered() {
    let mut t = Tree::new();
    t.bridge(0, 1, 0); // no secondary bus assigned...
    t.ignoring.insert((0, 1, 0)); // ...and hardware that will not take one
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    t.bridge(1, 1, 1); // points at its own bus
    t.bridge(1, 2, 0); // points back at the root
    t.bridge(0, 3, 1); // a second bridge to a bus already queued
    let mut asked = Vec::new();
    let Found { funcs: f, n, .. } = enumerate_tree::<Tree, 16>(&mut t, &mut |b| { asked.push(b); true });
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
    let Found { funcs: f, n, .. } = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    assert_eq!(ids(&f, n), [(0, 5, 0, 0x1af4, 0x1041), (0, 6, 0, 0x8086, 0x1234), (0, 6, 3, 0x8086, 0x1235)]);
}

/// The capacity (Kconfig `PCI_MAX_FUNCTIONS` in the kernel) is a bound, not
/// a panic, and what it drops is counted: the boot says "dropped N".
/// **Canary:** `push` without the `dropped += 1`: the count stays 0.
#[test]
fn the_output_capacity_is_a_bound_not_a_panic() {
    let mut t = Tree::new();
    for d in 0..10 {
        t.endpoint(0, d, 0, 0x1af4, 0x1041, 0x020000, false);
    }
    let Found { n, dropped, .. } = enumerate_tree::<Tree, 4>(&mut t, &mut |_| true);
    assert_eq!((n, dropped), (4, 6));
    let Found { n, dropped, .. } = enumerate_tree::<Tree, 10>(&mut t, &mut |_| true);
    assert_eq!((n, dropped), (10, 0), "exactly full drops nothing");
}

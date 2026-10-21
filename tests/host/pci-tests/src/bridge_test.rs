// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Bridges: bus numbering for the ones firmware left dark (inside
//! `enumerate_tree`) and the forwarding windows `place_behind_bridges`
//! programs, against `tree_test::Tree`, a multi-bus fake in which a bus is
//! readable only while a bridge's registers lead to it.

use crate::tree_test::Tree;
use azos_pci::*;

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

fn ids(funcs: &[Option<FunctionInfo>], n: usize) -> Vec<(u8, u8, u8)> {
    funcs[..n].iter().flatten().map(|f| (f.bdf.bus, f.bdf.device, f.bdf.function)).collect()
}

/// Bus numbers of the bridge at `bus:dev.0`: (primary, secondary, subordinate).
fn buses(t: &Tree, bus: u8, dev: u8) -> (u8, u8, u8) {
    let r = t.reg(bus, dev, OFF_PRIMARY_BUS);
    (r as u8, (r >> 8) as u8, (r >> 16) as u8)
}

// ---------------------------------------------------------------------
// Numbering
// ---------------------------------------------------------------------

#[test]
fn a_bridge_the_firmware_left_dark_gets_a_bus_and_its_devices_are_found() {
    let mut t = Tree::new();
    t.endpoint(0, 1, 0, 0x1af4, 0x1041, 0x020000, false);
    t.bridge(0, 2, 0); // secondary 0: dark
    t.endpoint(1, 0, 0, 0x1af4, 0x1041, 0x020000, false);
    let mut asked = Vec::new();
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |b| { asked.push(b); true });
    assert_eq!(buses(&t, 0, 2), (0, 1, 1));
    assert_eq!(ids(&f, n), [(0, 1, 0), (0, 2, 0), (1, 0, 0)]);
    assert_eq!(asked, [1], "the new bus is asked for once, before it is read");
}

#[test]
fn numbering_is_depth_first_so_a_bridges_range_holds_exactly_the_buses_behind_it() {
    // A (00:01.0) has a bridge C behind it; B (00:02.0) is a sibling. Depth
    // first: A=1, C=2, B=3. Breadth first would give B=2, C=3 and the
    // endpoints below (placed where the DFS numbering puts them) would not
    // be found.
    let mut t = Tree::new();
    t.bridge(0, 1, 0);
    t.bridge(0, 2, 0);
    t.bridge(1, 0, 0); // C, on A's bus
    t.endpoint(2, 0, 0, 0x8086, 0x5845, 0x010802, false); // behind C
    t.endpoint(3, 0, 0, 0x10ec, 0x8168, 0x020000, false); // behind B
    let (f, n) = enumerate_tree::<Tree, 16>(&mut t, &mut |_| true);
    assert_eq!(buses(&t, 0, 1), (0, 1, 2), "A: its own bus and C's");
    assert_eq!(buses(&t, 1, 0), (1, 2, 2), "C");
    assert_eq!(buses(&t, 0, 2), (0, 3, 3), "B comes after A's whole range");
    let found = ids(&f, n);
    assert!(found.contains(&(2, 0, 0)) && found.contains(&(3, 0, 0)), "{found:?}");
}

#[test]
fn numbering_starts_above_every_bus_the_firmware_used() {
    let mut t = Tree::new();
    t.bridge_range(0, 1, 1, 3); // firmware: buses 1..=3 behind it
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    t.bridge(0, 2, 0); // dark
    t.endpoint(4, 0, 0, 0x10ec, 0x8168, 0x020000, false);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    assert_eq!(buses(&t, 0, 1), (0, 1, 3), "the firmware's bridge is untouched");
    assert_eq!(buses(&t, 0, 2), (0, 4, 4));
    assert!(ids(&f, n).contains(&(4, 0, 0)));
}

/// Bus numbers are 8 bits. When the firmware already used bus 255 there is no
/// bus left to hand out: the dark bridge is left as found, not given a number
/// that wrapped to one the walk numbered before (bus 0 or 1).
#[test]
fn no_bus_number_is_handed_out_past_255() {
    let mut t = Tree::new();
    t.bridge_range(0, 1, 255, 255); // firmware: bus 255 behind it
    t.bridge(0, 2, 0); // dark
    let before = t.reg(0, 2, OFF_PRIMARY_BUS);
    let (_f, _n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    assert_eq!(buses(&t, 0, 1), (0, 255, 255), "the firmware's bridge is untouched");
    assert_eq!(t.reg(0, 2, OFF_PRIMARY_BUS), before, "the dark bridge was not numbered");
}

#[test]
fn a_tree_the_firmware_numbered_is_not_written_to() {
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    let (_, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    assert_eq!(n, 2);
    assert!(
        t.writes.iter().all(|(bdf, off, _)| !(bdf.device == 2 && bdf.bus == 0 && *off == OFF_PRIMARY_BUS)),
        "{:?}", t.writes
    );
}

#[test]
fn hardware_that_ignores_the_numbers_leaves_the_bridge_as_found() {
    let mut t = Tree::new();
    t.bridge(0, 2, 0);
    t.ignoring.insert((0, 2, 0));
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    let before = t.reg(0, 2, OFF_PRIMARY_BUS);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    assert_eq!(ids(&f, n), [(0, 2, 0)]);
    assert_eq!(t.reg(0, 2, OFF_PRIMARY_BUS), before);
    // It asked, was refused, and put back what it had read.
    assert_eq!(t.writes.last().unwrap().2, before);
}

#[test]
fn a_bus_the_caller_cannot_reach_ends_the_numbering_below_that_bridge() {
    let mut t = Tree::new();
    t.bridge(0, 2, 0);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| false);
    assert_eq!(ids(&f, n), [(0, 2, 0)]);
    assert_eq!(buses(&t, 0, 2), (0, 1, 1), "numbered, but nothing behind it is read");
}

#[test]
fn only_a_bridges_two_bars_are_sized_and_nothing_else_of_its_header_is_written() {
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.bar(0, 2, 0, 0, false, false, 0x1000);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    let (f, _) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let bridge = f[0].unwrap();
    assert_eq!((bridge.bar_count, bridge.bars[0].map(|b| b.size)), (1, Some(0x1000)));
    for (bdf, off, _) in &t.writes {
        if bdf.bus == 0 && bdf.device == 2 {
            assert!(*off == 0x10 || *off == 0x14, "sizing wrote bridge header offset {off:#x}");
        }
    }
    assert_eq!(buses(&t, 0, 2), (0, 1, 1), "bus numbers survive the sizing");
}

// ---------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------

fn window() -> BarWindow {
    BarWindow::new(0x4000_0000, GIB).with_pref64(0x4_0000_0000, 4 * GIB)
}

fn func(f: &[Option<FunctionInfo>], bus: u8, dev: u8) -> FunctionInfo {
    f.iter().flatten().find(|x| x.bdf.bus == bus && x.bdf.device == dev && x.bdf.function == 0).copied().unwrap()
}

#[test]
fn a_64bit_prefetchable_bar_behind_a_bridge_gets_a_window_that_covers_it() {
    let mut t = Tree::new();
    t.bridge(0, 2, 0); // dark: numbered and then windowed
    t.endpoint(1, 0, 0, 0x1af4, 0x1041, 0x020000, false);
    t.bar(1, 0, 0, 0, true, true, 0x4000); // 64-bit prefetchable: slots 0-1
    t.bar(1, 0, 0, 2, false, false, 0x1000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = window();
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);

    assert_eq!(plan.left_alone, 0);
    assert_eq!(plan.unplaced, 0);
    let b = plan.iter().next().copied().unwrap();
    assert_eq!((b.bdf, b.secondary, b.subordinate), (Bdf::new(0, 2, 0), 1, 1));
    assert_eq!(b.mem, Some((0x4000_0000, MIB)));
    assert_eq!(b.pref, Some((0x4_0000_0000, MIB)));
    // Non-prefetchable window 0x4000_0000..=0x400f_ffff: address bits 31:20
    // of the base (0x400) and of the limit (0x400) in bits 15:4 of each half.
    assert_eq!(t.reg(0, 2, 0x20), 0x4000_4000);
    // Prefetchable: low halves keep the 64-bit-capable nibbles, the high
    // dwords carry address bits 63:32.
    assert_eq!(t.reg(0, 2, 0x24), 0x0001_0001);
    assert_eq!((t.reg(0, 2, 0x28), t.reg(0, 2, 0x2c)), (4, 4));
    assert_eq!(t.reg(0, 2, OFF_COMMAND) & 0x6, 0x6, "memory decode and bus master on the bridge");

    // The driver that asks later gets the address inside the window.
    let ep = func(&f, 1, 0);
    let (bar0, bar2) = (ep.bars[0].unwrap(), ep.bars[1].unwrap());
    assert_eq!((bar0.index, bar0.kind, bar0.prefetchable), (0, BarKind::Mem64, true));
    assert_eq!(w.alloc_bar(ep.bdf, &bar0), Some(0x4_0000_0000));
    assert_eq!(w.alloc_bar(ep.bdf, &bar2), Some(0x4000_0000));
    assert_eq!(w.alloc_bar(ep.bdf, &bar2), Some(0x4000_0000), "the same address every time");
}

#[test]
fn a_bar_on_bus_0_is_placed_on_demand_after_the_bridge_windows() {
    let mut t = Tree::new();
    t.endpoint(0, 1, 0, 0x1af4, 0x1041, 0x020000, false);
    t.bar(0, 1, 0, 0, false, false, 0x1000);
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    t.bar(1, 0, 0, 0, false, false, 0x4000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = window();
    place_behind_bridges(&mut t, &f[..n], &mut w);
    let on_bus0 = func(&f, 0, 1).bars[0].unwrap();
    assert_eq!(w.alloc_bar(Bdf::new(0, 1, 0), &on_bus0), Some(0x4010_0000), "the bridge's 1 MiB window came first");
    assert_eq!(w.alloc_bar(Bdf::new(1, 0, 0), &func(&f, 1, 0).bars[0].unwrap()), Some(0x4000_0000));
}

#[test]
fn a_nonprefetchable_64bit_bar_and_a_32bit_prefetchable_one_use_the_memory_window() {
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    t.bar(1, 0, 0, 0, true, false, 0x4000); // NVMe-style BAR0
    t.bar(1, 0, 0, 2, false, true, 0x2000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = window();
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    let b = plan.iter().next().copied().unwrap();
    assert_eq!(b.mem, Some((0x4000_0000, MIB)));
    assert_eq!(b.pref, None, "nothing for the prefetchable window to hold");
    assert_eq!(t.reg(0, 2, 0x28), 0);
    let ep = func(&f, 1, 0);
    assert_eq!(w.alloc_bar(ep.bdf, &ep.bars[0].unwrap()), Some(0x4000_0000));
    assert_eq!(w.alloc_bar(ep.bdf, &ep.bars[1].unwrap()), Some(0x4000_4000));
}

#[test]
fn with_no_64bit_window_a_prefetchable_bar_behind_a_bridge_goes_in_the_memory_window() {
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x1af4, 0x1041, 0x020000, false);
    t.bar(1, 0, 0, 0, true, true, 0x4000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = BarWindow::new(0x4000_0000, GIB);
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    let b = plan.iter().next().copied().unwrap();
    assert_eq!((b.mem.is_some(), b.pref), (true, None));
    let ep = func(&f, 1, 0);
    assert_eq!(w.alloc_bar(ep.bdf, &ep.bars[0].unwrap()), Some(0x4000_0000));
}

#[test]
fn nested_bridges_sum_into_their_parents_window() {
    // A (bus 1) holds a 4 KiB endpoint and bridge B; B (bus 2) holds a 2 MiB BAR.
    let mut t = Tree::new();
    t.bridge_range(0, 1, 1, 2);
    t.endpoint(1, 0, 0, 0x8086, 0x1111, 0x020000, false);
    t.bar(1, 0, 0, 0, false, false, 0x1000);
    t.bridge(1, 1, 2);
    t.endpoint(2, 0, 0, 0x8086, 0x2222, 0x020000, false);
    t.bar(2, 0, 0, 0, false, false, 2 * MIB);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = window();
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    assert_eq!(plan.unplaced, 0);
    let by_bdf = |bus, dev| plan.iter().find(|b| b.bdf == Bdf::new(bus, dev, 0)).copied().unwrap();
    let (a, b) = (by_bdf(0, 1), by_bdf(1, 1));
    // B: 2 MiB. A: 2 MiB (B) + 4 KiB -> rounded up to 4 MiB.
    assert_eq!(b.mem.unwrap().1, 2 * MIB);
    assert_eq!(a.mem.unwrap().1, 4 * MIB);
    let (a_base, a_size) = a.mem.unwrap();
    let (b_base, b_size) = b.mem.unwrap();
    assert!(b_base >= a_base && b_base + b_size <= a_base + a_size, "B's window sits inside A's");
    assert_eq!(b_base, a_base, "largest first: B takes the bottom of A's window");
    // The endpoints' BARs are inside their own bridge's window.
    let deep = func(&f, 2, 0).bars[0].unwrap();
    let near = func(&f, 1, 0).bars[0].unwrap();
    let d = w.alloc_bar(Bdf::new(2, 0, 0), &deep).unwrap();
    let s = w.alloc_bar(Bdf::new(1, 0, 0), &near).unwrap();
    assert!(d >= b_base && d + deep.size <= b_base + b_size);
    assert!(s >= a_base && s + near.size <= a_base + a_size && !(s >= b_base && s < b_base + b_size));
}

#[test]
fn siblings_get_disjoint_windows() {
    let mut t = Tree::new();
    t.bridge(0, 1, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x1111, 0x020000, false);
    t.bar(1, 0, 0, 0, true, true, 0x10_0000);
    t.bridge(0, 2, 2);
    t.endpoint(2, 0, 0, 0x8086, 0x2222, 0x020000, false);
    t.bar(2, 0, 0, 0, true, true, 0x10_0000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = window();
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    let v: Vec<_> = plan.iter().map(|b| b.pref.unwrap()).collect();
    assert_eq!(v.len(), 2);
    assert!(v[0].0 + v[0].1 <= v[1].0 || v[1].0 + v[1].1 <= v[0].0, "{v:x?}");
}

#[test]
fn a_bridge_the_firmware_opened_a_window_on_is_left_as_found_with_what_is_behind_it() {
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    t.bar(1, 0, 0, 0, false, false, 0x4000);
    // The firmware's window: 0x5000_0000..=0x500f_ffff.
    let mut w = window();
    {
        let mut raw = |off: u16, v: u32| t.write32(Bdf::new(0, 2, 0), off, v);
        raw(0x20, 0x500f_5000);
    }
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    assert_eq!((plan.iter().count(), plan.left_alone), (0, 1));
    assert_eq!(t.reg(0, 2, 0x20), 0x500f_5000, "not rewritten");
    // Its endpoint's BAR is on demand, like a bus-0 one.
    let ep = func(&f, 1, 0);
    assert_eq!(w.alloc_bar(ep.bdf, &ep.bars[0].unwrap()), Some(0x4000_0000));
}

#[test]
fn a_window_that_does_not_fit_is_counted_not_programmed() {
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    t.bar(1, 0, 0, 0, false, false, 4 * MIB);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = BarWindow::new(0x4000_0000, 2 * MIB);
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    assert_eq!((plan.iter().count(), plan.unplaced), (0, 1));
    assert_eq!(t.reg(0, 2, 0x20), 0, "still closed");
}

#[test]
fn the_plan_reads_like_one_console_line() {
    let mut t = Tree::new();
    t.bridge(0, 2, 0);
    t.endpoint(1, 0, 0, 0x1af4, 0x1041, 0x020000, false);
    t.bar(1, 0, 0, 0, true, true, 0x4000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let plan = place_behind_bridges(&mut t, &f[..n], &mut window());
    assert_eq!(plan.to_string(), "bridge 00:02.0 buses 1-1 pref 0x400000000+0x100000");
}

#[test]
fn a_bridge_that_decodes_only_32_bits_never_gets_a_pref64_reservation() {
    // The pref64 pool lies above 4 GiB; a bridge whose prefetchable base
    // nibble is 0 cannot forward there, so its 64-bit prefetchable BAR takes
    // the memory window instead.
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.pref_32bit_only(0, 2);
    t.endpoint(1, 0, 0, 0x1af4, 0x1041, 0x020000, false);
    t.bar(1, 0, 0, 0, true, true, 0x4000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = window();
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    assert_eq!(plan.unplaced, 0);
    let b = plan.iter().next().copied().unwrap();
    assert_eq!((b.mem, b.pref), (Some((0x4000_0000, MIB)), None));
    assert_eq!(t.reg(0, 2, 0x24), 0, "the prefetchable window stays closed");
    assert_eq!((t.reg(0, 2, 0x28), t.reg(0, 2, 0x2c)), (0, 0));
    let ep = func(&f, 1, 0);
    assert_eq!(w.alloc_bar(ep.bdf, &ep.bars[0].unwrap()), Some(0x4000_0000), "inside the programmed window");
}

#[test]
fn a_bridge_below_a_32bit_only_bridge_gets_no_pref64_window_either() {
    let mut t = Tree::new();
    t.bridge_range(0, 1, 1, 2);
    t.pref_32bit_only(0, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x1111, 0x020000, false);
    t.bridge(1, 1, 2); // decodes 64 bits itself, but its parent does not
    t.endpoint(2, 0, 0, 0x8086, 0x2222, 0x020000, false);
    t.bar(2, 0, 0, 0, true, true, 0x4000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = window();
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    assert_eq!(plan.unplaced, 0);
    assert!(plan.iter().all(|b| b.pref.is_none() && b.mem.is_some()), "{plan}");
    let ep = func(&f, 2, 0);
    let a = w.alloc_bar(ep.bdf, &ep.bars[0].unwrap()).unwrap();
    assert!(a < 1 << 32);
}

#[test]
fn a_window_the_bridge_cannot_hold_drops_the_bars_reserved_behind_it() {
    // The memory pool sits above 4 GiB: the non-prefetchable window cannot be
    // programmed, so the BAR behind it must not keep the address reserved
    // inside it.
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x8086, 0x5845, 0x010802, false);
    t.bar(1, 0, 0, 0, false, false, 0x4000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = BarWindow::new(0x1_0000_0000, GIB);
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    assert_eq!((plan.iter().count(), plan.unplaced), (0, 1));
    assert_eq!(t.reg(0, 2, 0x20), 0, "still closed");
    let ep = func(&f, 1, 0);
    assert_ne!(w.alloc_bar(ep.bdf, &ep.bars[0].unwrap()), Some(0x1_0000_0000), "the reservation is gone");
}

#[test]
fn device_sizes_that_overflow_leave_the_bridge_unplaced_not_wrapped() {
    // Two BARs of 2^63 behind one bridge: their sum does not fit in u64.
    let mut t = Tree::new();
    t.bridge(0, 2, 1);
    t.endpoint(1, 0, 0, 0x1af4, 0x1041, 0x020000, false);
    t.bar(1, 0, 0, 0, true, true, 1 << 63);
    t.bar(1, 0, 0, 2, true, true, 1 << 63);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let mut w = window();
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    assert_eq!(plan.iter().count(), 0);
    assert!(plan.unplaced >= 1, "{plan}");
    assert_eq!(t.reg(0, 2, 0x24), 0x0001_0001, "no window programmed");

    // The same through the non-prefetchable class and a nested bridge.
    let mut t = Tree::new();
    t.bridge_range(0, 1, 1, 2);
    t.bridge(1, 1, 2);
    t.endpoint(2, 0, 0, 0x8086, 0x2222, 0x020000, false);
    t.bar(2, 0, 0, 0, true, false, 1 << 63);
    t.bar(2, 0, 0, 2, true, false, 1 << 63);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let plan = place_behind_bridges(&mut t, &f[..n], &mut window());
    assert_eq!(plan.iter().count(), 0);
    assert!(plan.unplaced >= 1, "{plan}");
}

#[test]
fn bridge_windows_and_bars_behind_a_translating_host_bridge_are_bus_addresses() {
    // The host bridge shows bus 0x4000_0000.. at CPU 0x6000_0000.. and the
    // 64-bit bus window 0x40_0000_0000.. at CPU 0x20_0000_0000..
    let mut t = Tree::new();
    t.bridge(0, 2, 0);
    t.endpoint(1, 0, 0, 0x1af4, 0x1041, 0x020000, false);
    t.bar(1, 0, 0, 0, true, true, 0x4000);
    t.bar(1, 0, 0, 2, false, false, 0x1000);
    let (f, n) = enumerate_tree::<Tree, 8>(&mut t, &mut |_| true);
    let fw = FirmwareWindows {
        mem32: Some(HostWindow { cpu_base: 0x6000_0000, bus_base: 0x4000_0000, size: GIB }),
        mem64: Some(HostWindow { cpu_base: 0x20_0000_0000, bus_base: 0x40_0000_0000, size: 4 * GIB }),
    };
    let (mut w, _) = resolve_bar_window(Some(fw), "dtb", (0, 0), None, 1 << 38);
    let plan = place_behind_bridges(&mut t, &f[..n], &mut w);
    assert_eq!((plan.left_alone, plan.unplaced), (0, 0));

    // The bridge forwards BUS addresses: that is what its registers hold.
    let b = plan.iter().next().copied().unwrap();
    assert_eq!(b.mem, Some((0x4000_0000, MIB)));
    assert_eq!(b.pref, Some((0x40_0000_0000, MIB)));
    assert_eq!(t.reg(0, 2, 0x20), 0x4000_4000);
    assert_eq!((t.reg(0, 2, 0x28), t.reg(0, 2, 0x2c)), (0x40, 0x40));

    // The driver's BARs are inside them, and the CPU reaches them translated.
    let ep = func(&f, 1, 0);
    let (bar0, bar2) = (ep.bars[0].unwrap(), ep.bars[1].unwrap());
    let a0 = w.alloc_bar(ep.bdf, &bar0).unwrap();
    let a2 = w.alloc_bar(ep.bdf, &bar2).unwrap();
    assert_eq!((a0, a2), (0x40_0000_0000, 0x4000_0000));
    assert_eq!(w.bar_cpu_addr(a0, bar0.size), Some(0x20_0000_0000));
    assert_eq!(w.bar_cpu_addr(a2, bar2.size), Some(0x6000_0000));
}

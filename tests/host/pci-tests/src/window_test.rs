// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `resolve_bar_window` and `BarWindow::alloc_bar`: which window a BAR is
//! placed in, and what firmware's windows become.

use azos_pci::*;

const GIB: u64 = 1 << 30;
const MEM32: (u64, u64) = (0x4000_0000, GIB);
const REACH: u64 = 1 << 38;

fn bar(index: u8, kind: BarKind, prefetchable: bool, size: u64) -> Bar {
    Bar { index, kind, prefetchable, address: 0, size }
}

fn hw(cpu: u64, bus: u64, size: u64) -> HostWindow {
    HostWindow { cpu_base: cpu, bus_base: bus, size }
}

/// QEMU riscv64 `virt`: a 32-bit window at 1 GiB and a 64-bit one at 16 GiB,
/// both with bus == CPU addresses.
fn virt() -> FirmwareWindows {
    FirmwareWindows { mem32: Some(hw(0x4000_0000, 0x4000_0000, GIB)), mem64: Some(hw(0x4_0000_0000, 0x4_0000_0000, 4 * GIB)) }
}

const BDF: Bdf = Bdf::new(0, 3, 0);

#[test]
fn a_64bit_prefetchable_bar_is_placed_in_the_64bit_window() {
    let (mut w, rep) = resolve_bar_window(Some(virt()), "dtb", MEM32, None, REACH);
    assert!(w.has_pref64());
    assert_eq!(w.alloc_bar(BDF, &bar(4, BarKind::Mem64, true, 0x4000)), Some(0x4_0000_0000));
    // The next one follows, aligned to its own size.
    assert_eq!(w.alloc_bar(BDF, &bar(2, BarKind::Mem64, true, 0x10_0000)), Some(0x4_0010_0000));
    assert_eq!(rep.pref64.unwrap().source, WindowSource::Firmware);
}

#[test]
fn everything_else_is_placed_in_the_32bit_window() {
    let (mut w, _) = resolve_bar_window(Some(virt()), "dtb", MEM32, None, REACH);
    // Non-prefetchable 64-bit (an NVMe BAR0): below 4 GiB, where a bridge's
    // non-prefetchable window can hold it.
    assert_eq!(w.alloc_bar(BDF, &bar(0, BarKind::Mem64, false, 0x4000)), Some(0x4000_0000));
    // Prefetchable 32-bit cannot go above 4 GiB.
    assert_eq!(w.alloc_bar(BDF, &bar(1, BarKind::Mem32, true, 0x1000)), Some(0x4000_4000));
    assert_eq!(w.alloc_bar(BDF, &bar(2, BarKind::Mem32, false, 0x1000)), Some(0x4000_5000));
    // I/O BARs are not assigned.
    assert_eq!(w.alloc_bar(BDF, &bar(3, BarKind::Io, false, 0x20)), None);
}

#[test]
fn an_exhausted_64bit_window_overflows_into_the_32bit_one() {
    let fw = FirmwareWindows { mem32: Some(hw(0x4000_0000, 0x4000_0000, GIB)), mem64: Some(hw(0x4_0000_0000, 0x4_0000_0000, 0x2000)) };
    let (mut w, _) = resolve_bar_window(Some(fw), "dtb", MEM32, None, REACH);
    assert_eq!(w.alloc_bar(BDF, &bar(0, BarKind::Mem64, true, 0x2000)), Some(0x4_0000_0000));
    assert_eq!(w.alloc_bar(BDF, &bar(2, BarKind::Mem64, true, 0x2000)), Some(0x4000_0000));
}

#[test]
fn with_no_64bit_window_a_prefetchable_64bit_bar_uses_the_32bit_one() {
    let fw = FirmwareWindows { mem32: Some(hw(0x4000_0000, 0x4000_0000, GIB)), mem64: None };
    let (mut w, rep) = resolve_bar_window(Some(fw), "dtb", MEM32, None, REACH);
    assert!(!w.has_pref64());
    assert_eq!(rep.pref64, None);
    assert_eq!(w.alloc_bar(BDF, &bar(4, BarKind::Mem64, true, 0x4000)), Some(0x4000_0000));
}

/// A host bridge that translates in both directions: the 32-bit window's bus
/// addresses sit BELOW their CPU addresses, the 64-bit one's ABOVE.
fn translated() -> FirmwareWindows {
    FirmwareWindows {
        mem32: Some(hw(0x6000_0000, 0x4000_0000, GIB)),
        mem64: Some(hw(0x20_0000_0000, 0x40_0000_0000, 4 * GIB)),
    }
}

#[test]
fn a_translated_window_hands_out_bus_addresses_and_maps_them_to_cpu_ones() {
    let (mut w, rep) = resolve_bar_window(Some(translated()), "dtb", MEM32, None, REACH);
    assert_eq!(rep.mem32.source, WindowSource::Translated);
    assert_eq!((rep.mem32.base, rep.mem32.cpu_base, rep.mem32.size), (0x4000_0000, 0x6000_0000, GIB));
    assert!(w.has_pref64());

    // The BAR gets the BUS address ...
    let b32 = w.alloc_bar(BDF, &bar(0, BarKind::Mem32, false, 0x1000)).unwrap();
    assert_eq!(b32, 0x4000_0000);
    // ... the CPU maps the translated one (bus below cpu: +0x2000_0000).
    assert_eq!(w.bar_cpu_addr(b32, 0x1000), Some(0x6000_0000));
    let b32b = w.alloc_bar(BDF, &bar(1, BarKind::Mem32, false, 0x2000)).unwrap();
    assert_eq!(w.bar_cpu_addr(b32b, 0x2000), Some(b32b + 0x2000_0000));

    // 64-bit window: bus above cpu (wrapping offset).
    let b64 = w.alloc_bar(BDF, &bar(4, BarKind::Mem64, true, 0x4000)).unwrap();
    assert_eq!(b64, 0x40_0000_0000);
    assert_eq!(w.bar_cpu_addr(b64, 0x4000), Some(0x20_0000_0000));
    assert_eq!(w.bar_cpu_addr(b64 + 0x10_0000, 0x1000), Some(0x20_0010_0000));
}

#[test]
fn an_identity_window_maps_every_address_to_itself() {
    let (mut w, rep) = resolve_bar_window(Some(virt()), "dtb", MEM32, None, REACH);
    assert_eq!(rep.mem32.source, WindowSource::Firmware);
    let a = w.alloc_bar(BDF, &bar(0, BarKind::Mem32, false, 0x1000)).unwrap();
    assert_eq!(w.bar_cpu_addr(a, 0x1000), Some(a));
    let a = w.alloc_bar(BDF, &bar(4, BarKind::Mem64, true, 0x4000)).unwrap();
    assert_eq!(w.bar_cpu_addr(a, 0x4000), Some(a));
    // A BAR firmware put outside the windows we know is reached where it is.
    assert_eq!(w.bar_cpu_addr(0x1000_0000, 0x1000), Some(0x1000_0000));
    // Built-in windows are identity as well.
    let (mut w, _) = resolve_bar_window(None, "dtb", MEM32, Some((0x8_0000_0000, GIB)), REACH);
    let a = w.alloc_bar(BDF, &bar(4, BarKind::Mem64, true, 0x4000)).unwrap();
    assert_eq!(w.bar_cpu_addr(a, 0x4000), Some(0x8_0000_0000));
}

#[test]
fn a_bar_nothing_forwards_has_no_cpu_address_when_the_bridge_translates() {
    let (w, _) = resolve_bar_window(Some(translated()), "dtb", MEM32, None, REACH);
    // Outside both windows.
    assert_eq!(w.bar_cpu_addr(0x1000_0000, 0x1000), None);
    // Starts inside the window, runs past its end.
    assert_eq!(w.bar_cpu_addr(0x4000_0000 + GIB - 0x800, 0x1000), None);
    // The CPU address of a window is not a bus address of it.
    assert_eq!(w.bar_cpu_addr(0x20_0000_0000, 0x1000), None);
}

#[test]
fn translation_is_clipped_by_the_cpu_reach_and_the_bus_stays_in_step() {
    // The CPU side ends 256 MiB into the window: so does the bus side.
    let fw = FirmwareWindows { mem32: Some(hw(0x6000_0000, 0x4000_0000, GIB)), mem64: None };
    let (mut w, rep) = resolve_bar_window(Some(fw), "dtb", MEM32, None, 0x7000_0000);
    assert_eq!((rep.mem32.base, rep.mem32.cpu_base, rep.mem32.size), (0x4000_0000, 0x6000_0000, 0x1000_0000));
    assert_eq!(w.alloc_bar(BDF, &bar(0, BarKind::Mem32, false, 0x1000_0000)), Some(0x4000_0000));
    assert_eq!(w.alloc_bar(BDF, &bar(1, BarKind::Mem32, false, 0x1000)), None);
    // CPU window wholly out of reach: nothing is handed out.
    let fw = FirmwareWindows { mem32: Some(hw(0x80_0000_0000, 0x4000_0000, GIB)), mem64: Some(hw(0x90_0000_0000, 0x4_0000_0000, GIB)) };
    let (mut w, rep) = resolve_bar_window(Some(fw), "dtb", MEM32, None, REACH);
    assert_eq!((rep.mem32.source, rep.pref64.unwrap().source), (WindowSource::BeyondReach, WindowSource::BeyondReach));
    assert_eq!(w.alloc_bar(BDF, &bar(0, BarKind::Mem32, false, 0x1000)), None);
}

#[test]
fn the_32bit_window_is_cut_at_4_gib_of_bus_address() {
    let fw = FirmwareWindows { mem32: Some(hw(0x1_0000_0000, 0xc000_0000, 2 * GIB)), mem64: None };
    let (mut w, rep) = resolve_bar_window(Some(fw), "dtb", MEM32, None, REACH);
    assert_eq!((rep.mem32.base, rep.mem32.size), (0xc000_0000, GIB));
    let a = w.alloc_bar(BDF, &bar(0, BarKind::Mem32, false, 0x1000)).unwrap();
    assert!(a + 0x1000 <= 1 << 32);
    assert_eq!(w.bar_cpu_addr(a, 0x1000), Some(0x1_0000_0000));
    let fw = FirmwareWindows { mem32: Some(hw(0x1_0000_0000, 0x1_0000_0000, GIB)), mem64: None };
    let (_, rep) = resolve_bar_window(Some(fw), "dtb", MEM32, None, REACH);
    assert_eq!(rep.mem32.source, WindowSource::Above4G);
}

#[test]
fn a_64bit_window_beyond_the_kernels_reach_is_dropped_and_one_that_straddles_it_is_cut() {
    // aarch64 `virt`: the high window starts at 512 GiB, a 39-bit address space ends there.
    let fw = FirmwareWindows { mem32: Some(hw(0x1000_0000, 0x1000_0000, 0x2eff_0000)), mem64: Some(hw(0x80_0000_0000, 0x80_0000_0000, 0x80_0000_0000)) };
    let (mut w, rep) = resolve_bar_window(Some(fw), "dtb", MEM32, None, 1 << 39);
    assert_eq!(rep.pref64.unwrap().source, WindowSource::BeyondReach);
    assert!(!w.has_pref64());
    assert_eq!(w.alloc_bar(BDF, &bar(4, BarKind::Mem64, true, 0x4000)), Some(0x1000_0000), "falls back to the 32-bit window");

    let fw = FirmwareWindows { mem32: None, mem64: Some(hw(0x4_0000_0000, 0x4_0000_0000, 0x10_0000_0000)) };
    let (w, rep) = resolve_bar_window(Some(fw), "dtb", MEM32, None, 0x5_0000_0000);
    assert!(w.has_pref64());
    assert_eq!(rep.pref64.map(|p| (p.base, p.size)), Some((0x4_0000_0000, 0x1_0000_0000)));
}

#[test]
fn without_firmware_the_built_in_windows_apply() {
    let (mut w, rep) = resolve_bar_window(None, "dtb", MEM32, Some((0x8_0000_0000, GIB)), REACH);
    assert_eq!(rep.mem32.source, WindowSource::BuiltIn);
    assert_eq!(rep.pref64.unwrap().source, WindowSource::BuiltIn);
    assert_eq!(w.alloc_bar(BDF, &bar(4, BarKind::Mem64, true, 0x4000)), Some(0x8_0000_0000));
    let (w, rep) = resolve_bar_window(None, "dtb", MEM32, None, REACH);
    assert!(!w.has_pref64());
    assert_eq!(rep.pref64, None);
}

#[test]
fn the_report_reads_like_the_line_the_gate_greps() {
    let fw = FirmwareWindows { mem32: Some(hw(0x1000_0000, 0x1000_0000, 0x2eff_0000)), mem64: None };
    let (_, rep) = resolve_bar_window(Some(fw), "dtb", MEM32, None, 1 << 39);
    assert_eq!(rep.to_string(), "mem32 0x10000000+0x2eff0000 (dtb), no pref64 window");
    let (_, rep) = resolve_bar_window(Some(virt()), "dtb", MEM32, None, REACH);
    assert_eq!(rep.to_string(), "mem32 0x40000000+0x40000000 (dtb), pref64 0x400000000+0x100000000 (dtb)");
    let (_, rep) = resolve_bar_window(None, "dtb", MEM32, None, REACH);
    assert_eq!(rep.to_string(), "mem32 0x40000000+0x40000000 (built-in), no pref64 window");
    let (_, rep) = resolve_bar_window(Some(translated()), "dtb", MEM32, None, REACH);
    assert_eq!(rep.to_string(), "mem32 0x40000000+0x40000000 -> cpu 0x60000000 (dtb), pref64 0x4000000000+0x100000000 -> cpu 0x2000000000 (dtb)");
}

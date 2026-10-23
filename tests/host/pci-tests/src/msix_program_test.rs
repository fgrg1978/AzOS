// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the MSI-X table/PBA arithmetic and programming added to
//! `azos_pci` for AIA/IMSIC interrupt delivery (A1). Reuses
//! `FakeBus`/`FakeFunction` from `lib.rs` for the capability-level enable
//! bit; adds a small fake BAR-memory stand-in for the table/PBA side,
//! mirroring the shape `virtio_pci_test.rs` uses for its own `Mmio` fake.

#![cfg(test)]

use crate::{FakeBus, FakeFunction};
use azos_pci::*;

/// A fake PCI BAR's byte-addressed memory, big enough for a handful of
/// MSI-X table entries plus a PBA dword.
struct FakeBar {
    /// 16 KiB — enough headroom for table offsets like `0x1000`/`0x2000`
    /// (this fake's tests place the table and PBA at BAR-realistic
    /// offsets, not packed at 0, to catch an implementation that ignores
    /// `table_offset`/`pba_offset` and always writes at BAR-relative 0).
    words: [u32; 4096],
}

impl FakeBar {
    fn new() -> Self {
        FakeBar { words: [0; 4096] }
    }
}

impl BarMem for FakeBar {
    fn read32(&self, offset: usize) -> u32 {
        self.words[offset / 4]
    }
    fn write32(&mut self, offset: usize, val: u32) {
        self.words[offset / 4] = val;
    }
}

/// An MSI-X capability's parse: `n` vectors, the table at `table_offset` and
/// the PBA at `pba_offset`, both in BAR 0.
fn msix_info(n: u16, table_offset: u32, pba_offset: u32) -> MsixInfo {
    MsixInfo { cap_offset: 0x40, table_size: n, table_bar: 0, table_offset, pba_bar: 0, pba_offset }
}

// -----------------------------------------------------------------------
// Pure arithmetic
// -----------------------------------------------------------------------

#[test]
fn table_entry_offset_is_16_bytes_per_vector() {
    assert_eq!(msix_table_entry_offset(0), 0);
    assert_eq!(msix_table_entry_offset(1), 16);
    assert_eq!(msix_table_entry_offset(7), 112);
}

#[test]
fn pba_word_and_bit_pack_32_vectors_per_dword() {
    assert_eq!(msix_pba_word_and_bit(0), (0, 0));
    assert_eq!(msix_pba_word_and_bit(31), (0, 31));
    assert_eq!(msix_pba_word_and_bit(32), (1, 0));
    assert_eq!(msix_pba_word_and_bit(65), (2, 1));
}

// -----------------------------------------------------------------------
// Table programming — (a) the entry lands correctly, (b) masked=true is
// the canary's negation bucket: the mask bit must be the ONLY thing that
// differs, not the address/data (a real device would still see a fully
// programmed vector, just muted).
// -----------------------------------------------------------------------

#[test]
fn program_msix_entry_writes_all_four_dwords() {
    let mut bar = FakeBar::new();
    let table_offset = 0x1000u32;
    let addr: u64 = 0x2800_2000; // an IMSIC hart file address, e.g. hart 2
    let data: u32 = 42; // the interrupt identity

    assert!(program_msix_entry(&mut bar, &msix_info(4, table_offset, 0x2000), 3, addr, data, false));

    let base = (table_offset + msix_table_entry_offset(3)) as usize;
    assert_eq!(bar.read32(base), addr as u32);
    assert_eq!(bar.read32(base + 4), (addr >> 32) as u32);
    assert_eq!(bar.read32(base + 8), data);
    assert_eq!(bar.read32(base + 12), 0, "unmasked entry must have vector_control == 0");
}

#[test]
fn program_msix_entry_masked_sets_only_the_mask_bit() {
    let mut bar = FakeBar::new();
    let table_offset = 0u32;
    let addr: u64 = 0x2800_1000;
    let data: u32 = 7;

    assert!(program_msix_entry(&mut bar, &msix_info(1, table_offset, 0x2000), 0, addr, data, true));

    assert_eq!(bar.read32(0), addr as u32, "masking must not corrupt the address");
    assert_eq!(bar.read32(4), (addr >> 32) as u32);
    assert_eq!(bar.read32(8), data, "masking must not corrupt the data/identity");
    assert_eq!(bar.read32(12), MSIX_VECTOR_CTRL_MASK, "mask bit must be set, nothing else");
}

#[test]
fn program_msix_entry_addresses_do_not_overlap_between_vectors() {
    let mut bar = FakeBar::new();
    let m = msix_info(2, 0, 0x2000);
    assert!(program_msix_entry(&mut bar, &m, 0, 0x1111, 1, false));
    assert!(program_msix_entry(&mut bar, &m, 1, 0x2222, 2, false));

    assert_eq!(bar.read32(0), 0x1111);
    assert_eq!(bar.read32(4 * 4), 0x2222, "vector 1's entry must start at byte 16, not overwrite vector 0");
}

// -----------------------------------------------------------------------
// PBA readback
// -----------------------------------------------------------------------

#[test]
fn msix_pba_pending_reads_the_right_bit() {
    let mut bar = FakeBar::new();
    let pba_offset = 0x2000u32;
    // Set bit 5 of PBA dword 0 (vector 5 pending) and bit 3 of dword 1
    // (vector 32+3 = 35 pending).
    bar.write32(pba_offset as usize, 1 << 5);
    bar.write32(pba_offset as usize + 4, 1 << 3);

    let m = msix_info(64, 0x1000, pba_offset);
    assert_eq!(msix_pba_pending(&bar, &m, 5), Some(true));
    assert_eq!(msix_pba_pending(&bar, &m, 4), Some(false), "adjacent bit must not read as set");
    assert_eq!(msix_pba_pending(&bar, &m, 35), Some(true));
    assert_eq!(msix_pba_pending(&bar, &m, 0), Some(false));
    assert_eq!(msix_pba_pending(&bar, &m, 64), None, "past the table");
}

// -----------------------------------------------------------------------
// Bounds: the table ends where the capability says, inside its BAR
// -----------------------------------------------------------------------

/// A vector past `table_size` is refused and nothing is written: what
/// follows the table (here the PBA) is not a table entry.
/// **Canary:** drop the `index >= table_size` check: the PBA is overwritten.
#[test]
fn program_msix_entry_refuses_a_vector_past_the_table() {
    let mut bar = FakeBar::new();
    // Two vectors at 0x1000, the PBA right after the table.
    let m = msix_info(2, 0x1000, 0x1020);
    bar.write32(0x1020, 0x5a5a_5a5a);
    assert!(program_msix_entry(&mut bar, &m, 1, 0x2800_0000, 1, false));
    assert!(!program_msix_entry(&mut bar, &m, 2, 0x2800_0000, 2, false));
    assert_eq!(bar.read32(0x1020), 0x5a5a_5a5a, "the PBA after the table is untouched");
}

/// The table and the PBA must lie inside the memory BAR the BIR names: an
/// offset (or a table size) the device reports past its BAR, an I/O BAR, an
/// absent one or a reserved BIR is no MSI-X table, and the function is
/// probed without MSI-X.
/// **Canary:** `probe_function` without the `msix_fits` filter: the line
/// says msix=y for the table that runs past BAR 0.
#[test]
fn an_msix_table_outside_its_bar_is_no_msix() {
    let bar0 = Bar { index: 0, kind: BarKind::Mem32, prefetchable: false, address: 0, size: 0x1000 };
    let io2 = Bar { index: 2, kind: BarKind::Io, prefetchable: false, address: 0xc000, size: 0x100 };
    let bars = [Some(bar0), Some(io2), None, None, None, None];
    assert!(msix_fits(&msix_info(64, 0, 0x800), &bars), "64 vectors fill 0x400, the PBA 8 bytes");
    assert!(msix_fits(&msix_info(256, 0, 0xfe0), &bars), "a table that ends at the BAR's end");
    assert!(!msix_fits(&msix_info(257, 0, 0x800), &bars), "a table one entry past the BAR");
    assert!(msix_fits(&msix_info(4, 0, 0xffc), &bars), "a one-dword PBA in the last dword");
    assert!(!msix_fits(&msix_info(33, 0, 0xffc), &bars), "a second PBA dword past the BAR's end");
    assert!(!msix_fits(&msix_info(4, 0xff8, 0x800), &bars), "a table that starts in and runs out");
    assert!(!msix_fits(&msix_info(4, 0, 0x1000), &bars), "a PBA past the BAR");
    let mut m = msix_info(4, 0, 0x800);
    m.table_bar = 2;
    assert!(!msix_fits(&m, &bars), "an I/O BAR");
    m.table_bar = 1;
    assert!(!msix_fits(&m, &bars), "an absent BAR");
    m.table_bar = 6;
    assert!(!msix_fits(&m, &bars), "a reserved BIR");

    // Through the probe: one function whose capability names a table at
    // 0x2000 in a 4 KiB BAR 0.
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    f.configure_mem_bar(0, false, false, 0x4000_0000, 0x1000);
    f.write_u8(0x40, CAP_ID_MSIX);
    f.write_u8(0x41, 0);
    f.write_u16(0x42, 3);
    f.write_u32(0x44, 0x2000);
    f.write_u32(0x48, 0x800);
    f.set_cap_list(0x40);
    bus.put(0, f);
    let info = probe_function(&mut bus, Bdf::new(0, 0, 0)).unwrap();
    assert!(info.msix.is_none(), "the table past BAR 0 is not used");
    bus.funcs[0].as_mut().unwrap().write_u32(0x44, 0x0);
    assert!(probe_function(&mut bus, Bdf::new(0, 0, 0)).unwrap().msix.is_some(), "the same table at 0 is");
}

// -----------------------------------------------------------------------
// Capability-level enable bit — THE canary: disabling it is the negation
// the brief's acceptance criteria anchors on ("disable the MSI-X enable
// bit -> the count stays 0 and the row fails").
// -----------------------------------------------------------------------

/// Also: INTx Disable follows MSI-X Enable (set with it, cleared after it).
/// **Canary:** `msix_set_enable` without the Command writes: INTx stays on.
#[test]
fn msix_set_enable_round_trips_through_config_space() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    f.write_u8(0x40, CAP_ID_MSIX);
    f.write_u8(0x41, 0);
    f.write_u16(0x42, 3); // table_size encoded as N-1 -> 4 vectors
    f.write_u32(0x44, 0x1000);
    f.write_u32(0x48, 0x2000);
    f.set_cap_list(0x40);
    bus.put(0, f);

    let bdf = Bdf::new(0, 0, 0);
    let caps = walk_capabilities(&bus, bdf);
    let msix_cap = caps.find(CAP_ID_MSIX).expect("MSI-X cap must be found");
    let msix = parse_msix(&bus, bdf, msix_cap);

    assert!(!msix_is_enabled(&bus, bdf, &msix), "reset default must be disabled");

    msix_set_enable(&mut bus, bdf, &msix, true);
    assert!(msix_is_enabled(&bus, bdf, &msix));
    assert_ne!(bus.read16(bdf, OFF_COMMAND) & CMD_INTX_DISABLE, 0, "INTx off while MSI-X is on");

    // (b) — the canary's negation: flip it back off, count-side effects
    // (an actual delivered-interrupt counter) are exercised at the
    // integration/boot level, not here; this proves the ENABLE BIT ITSELF
    // toggles cleanly and does not stick.
    msix_set_enable(&mut bus, bdf, &msix, false);
    assert!(!msix_is_enabled(&bus, bdf, &msix), "must be possible to re-disable — the canary's negation path");
    assert_eq!(bus.read16(bdf, OFF_COMMAND) & CMD_INTX_DISABLE, 0, "INTx back once MSI-X is off");
}

#[test]
fn msix_set_enable_does_not_disturb_function_mask_or_table_size() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    f.write_u8(0x40, CAP_ID_MSIX);
    f.write_u8(0x41, 0);
    // table_size field (bits 10:0) = 3 (4 vectors) AND function mask (bit
    // 14) pre-set, to prove set_enable only ever touches bit 15.
    f.write_u16(0x42, 3 | MSGCTRL_FUNCTION_MASK);
    f.write_u32(0x44, 0x1000);
    f.write_u32(0x48, 0x2000);
    f.set_cap_list(0x40);
    bus.put(0, f);

    let bdf = Bdf::new(0, 0, 0);
    let caps = walk_capabilities(&bus, bdf);
    let msix_cap = caps.find(CAP_ID_MSIX).unwrap();
    let msix = parse_msix(&bus, bdf, msix_cap);
    assert_eq!(msix.table_size, 4);

    msix_set_enable(&mut bus, bdf, &msix, true);

    let msg_ctrl = bus.read16(bdf, msix.cap_offset + 2);
    assert_ne!(msg_ctrl & MSGCTRL_FUNCTION_MASK, 0, "function mask must survive");
    assert_ne!(msg_ctrl & MSGCTRL_MSIX_ENABLE, 0);
    let msix_after = parse_msix(&bus, bdf, msix_cap);
    assert_eq!(msix_after.table_size, 4, "table_size field must survive");
}

// -----------------------------------------------------------------------
// Command register — Bus Master / Memory Space (mandatory for MSI-X DMA)
// -----------------------------------------------------------------------

#[test]
fn set_command_bits_sets_requested_bits_without_clearing_others() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    bus.put(0, f);
    let bdf = Bdf::new(0, 0, 0);

    set_command_bits(&mut bus, bdf, CMD_MEM_SPACE);
    assert_eq!(bus.read16(bdf, OFF_COMMAND) & CMD_MEM_SPACE, CMD_MEM_SPACE);
    assert_eq!(bus.read16(bdf, OFF_COMMAND) & CMD_BUS_MASTER, 0);

    set_command_bits(&mut bus, bdf, CMD_BUS_MASTER);
    let cmd = bus.read16(bdf, OFF_COMMAND);
    assert_eq!(cmd & CMD_MEM_SPACE, CMD_MEM_SPACE, "second call must not clear the first bit");
    assert_eq!(cmd & CMD_BUS_MASTER, CMD_BUS_MASTER);
}

#[test]
fn clear_command_bits_clears_only_the_named_bits() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    bus.put(0, f);
    let bdf = Bdf::new(0, 0, 0);

    set_command_bits(&mut bus, bdf, CMD_MEM_SPACE | CMD_BUS_MASTER);
    clear_command_bits(&mut bus, bdf, CMD_MEM_SPACE);
    let cmd = bus.read16(bdf, OFF_COMMAND);
    assert_eq!(cmd & CMD_MEM_SPACE, 0, "the named bit must be cleared");
    assert_eq!(cmd & CMD_BUS_MASTER, CMD_BUS_MASTER, "an unnamed bit must survive");
}

#[test]
fn clear_command_bits_never_clears_a_rw1c_status_bit() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    f.write_u16(OFF_STATUS, 1 << 15);
    bus.put(0, f);
    let bdf = Bdf::new(0, 0, 0);

    clear_command_bits(&mut bus, bdf, CMD_MEM_SPACE | CMD_BUS_MASTER);
    assert_eq!(bus.read16(bdf, OFF_STATUS) & (1 << 15), 1 << 15,
        "a Command write must not clear a pending Status error bit");
}

#[test]
fn set_command_bits_never_clears_a_rw1c_status_bit() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    // Simulate a device that already has a Status RW1C bit set (bit 15,
    // "Detected Parity Error" in real hardware) before we ever touch
    // Command — set_command_bits must not clear it as a side effect.
    f.write_u16(OFF_STATUS, 1 << 15);
    bus.put(0, f);
    let bdf = Bdf::new(0, 0, 0);

    set_command_bits(&mut bus, bdf, CMD_MEM_SPACE);
    assert_ne!(bus.read16(bdf, OFF_STATUS) & (1 << 15), 0, "an unrelated RW1C status bit must survive a Command write");
}

// -----------------------------------------------------------------------
// BAR assignment — Pool alignment/exhaustion and assign_bar's writes
// -----------------------------------------------------------------------

#[test]
fn pool_aligns_each_bar_to_its_size() {
    let mut w = Pool::new(0x4000_0000, 0x4000_0000);
    assert_eq!(w.alloc(0x1000), Some(0x4000_0000));
    // A 16 KiB BAR after a 4 KiB one must skip to the next 16 KiB boundary.
    assert_eq!(w.alloc(0x4000), Some(0x4000_4000));
    assert_eq!(w.alloc(0x1000), Some(0x4000_8000));
}

#[test]
fn pool_refuses_non_power_of_two_and_exhaustion() {
    let mut w = Pool::new(0x1000, 0x2000);
    assert_eq!(w.alloc(0x3000), None, "not a power of two");
    assert_eq!(w.alloc(0), None);
    assert_eq!(w.alloc(0x1000), Some(0x1000));
    assert_eq!(w.alloc(0x1000), Some(0x2000));
    assert_eq!(w.alloc(0x1000), None, "window [0x1000, 0x3000) is used up");
}

#[test]
fn assign_bar_programs_mem32_and_keeps_type_bits() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    f.configure_mem_bar(1, false, false, 0, 0x1000);
    bus.put(0, f);
    let bdf = Bdf::new(0, 0, 0);
    let (bars, _) = decode_bars(&mut bus, bdf);
    let bar = bars[0].unwrap();
    assert_eq!(bar.address, 0, "unassigned after reset");

    let out = assign_bar(&mut bus, bdf, &bar, 0x4000_0000).expect("mem32 below 4 GiB");
    assert_eq!(out.address, 0x4000_0000);
    let (again, _) = decode_bars(&mut bus, bdf);
    assert_eq!(again[0].unwrap().address, 0x4000_0000, "config space must hold the new address");
    assert_eq!(again[0].unwrap().kind, BarKind::Mem32);
    assert_eq!(assign_bar(&mut bus, bdf, &bar, 0x1_0000_0000), None, "mem32 cannot take a >4 GiB address");
}

#[test]
fn assign_bar_writes_both_halves_of_a_mem64_bar() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    f.configure_mem_bar(4, true, true, 0, 0x4000);
    bus.put(0, f);
    let bdf = Bdf::new(0, 0, 0);
    let (bars, _) = decode_bars(&mut bus, bdf);
    let bar = bars[0].unwrap();
    assert_eq!(bar.kind, BarKind::Mem64);

    assign_bar(&mut bus, bdf, &bar, 0x10_4000_4000).unwrap();
    let (again, _) = decode_bars(&mut bus, bdf);
    let b = again[0].unwrap();
    assert_eq!(b.address, 0x10_4000_4000, "high dword must be written too");
    assert!(b.prefetchable, "type bits must survive the address write");
}

// -----------------------------------------------------------------------
// Canary hook: with `msix-enable-canary` the enable request is ignored.
// `msix_set_enable_round_trips_through_config_space` above FAILS under
// `cargo test --features msix-enable-canary` — that is the host-side proof
// the feature really breaks the property the boot row checks.
// -----------------------------------------------------------------------

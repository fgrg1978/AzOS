// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_pci` against a fake config space that models
//! real BAR hardware behaviour (type bits fixed, size mask on an all-1s
//! write) closely enough to catch sizing/decode bugs, plus a
//! deliberately hostile capability list to prove the walk terminates.

#![cfg(test)]

mod virtio_pci_test;
mod msix_program_test;

use azos_pci::*;

/// One function's 4 KiB config space, dword-addressed. BAR registers
/// (0x10..0x28) get hardware-like behaviour in `write32`; everything
/// else is a plain byte-array-backed register file.
struct FakeFunction {
    dwords: [u32; 1024],
    /// Fixed low bits per BAR slot (type + prefetchable + io flag) that
    /// survive an all-1s write, exactly like real BAR decode-bit hardware.
    bar_fixed_bits: [u32; 6],
    /// True size (bytes) of each BAR slot, used to compute what an
    /// all-1s probe reads back. 0 = BAR not implemented (reads back 0).
    bar_size: [u64; 6],
}

impl FakeFunction {
    fn new() -> Self {
        FakeFunction { dwords: [0; 1024], bar_fixed_bits: [0; 6], bar_size: [0; 6] }
    }

    fn set_header(&mut self, vendor: u16, device: u16) {
        self.dwords[0] = (device as u32) << 16 | vendor as u32;
    }

    fn set_cap_list(&mut self, first_cap: u8) {
        // Status.CAP_LIST (bit 4 of the high 16 bits of dword at 0x04).
        self.dwords[1] |= (STATUS_CAP_LIST as u32) << 16;
        // Capability Pointer lives at 0x34 -> dword index 13, low byte.
        self.dwords[13] = (self.dwords[13] & !0xff) | first_cap as u32;
    }

    fn write_u8(&mut self, offset: u16, val: u8) {
        let idx = (offset / 4) as usize;
        let shift = (offset % 4) * 8;
        self.dwords[idx] = (self.dwords[idx] & !(0xffu32 << shift)) | ((val as u32) << shift);
    }

    fn write_u16(&mut self, offset: u16, val: u16) {
        self.write_u8(offset, (val & 0xff) as u8);
        self.write_u8(offset + 1, (val >> 8) as u8);
    }

    fn write_u32(&mut self, offset: u16, val: u32) {
        let idx = (offset / 4) as usize;
        self.dwords[idx] = val;
    }

    fn configure_mem_bar(&mut self, index: usize, is64: bool, prefetchable: bool, address: u64, size: u64) {
        let mut fixed = if is64 { 0x4 } else { 0x0 };
        if prefetchable {
            fixed |= 0x8;
        }
        self.bar_fixed_bits[index] = fixed;
        self.bar_size[index] = size;

        let off = OFF_BAR0 + (index as u16) * 4;
        self.write_u32(off, ((address as u32) & !0xf) | fixed);
        if is64 {
            self.write_u32(off + 4, (address >> 32) as u32);
        }
    }
}

/// A tiny "bus" holding one function per device slot 0..32 (the full
/// range `enumerate_bus0` walks), function 0 only — multifunction is not
/// exercised here since the real BDF math is covered by the `ecam_*`
/// unit tests independently of this fake.
struct FakeBus {
    funcs: [Option<FakeFunction>; 32],
}

impl FakeBus {
    fn new() -> Self {
        FakeBus { funcs: core::array::from_fn(|_| None) }
    }

    fn put(&mut self, device: u8, f: FakeFunction) {
        self.funcs[device as usize] = Some(f);
    }
}

impl ConfigSpace for FakeBus {
    fn read32(&self, bdf: Bdf, offset: u16) -> u32 {
        match &self.funcs[bdf.device as usize] {
            Some(f) => {
                let idx = (offset / 4) as usize;
                let raw = f.dwords[idx];
                // BAR slots need the "type bits survive, but only report
                // the fixed bits (never a stray write) unless the caller
                // last did the all-1s size probe" behaviour: modelled by
                // just returning what's stored — `write32` below is what
                // encodes the hardware trick, so `read32` stays dumb.
                raw
            }
            None => 0xffff_ffff, // absent device: everything reads all-ones
        }
    }

    fn write32(&mut self, bdf: Bdf, offset: u16, val: u32) {
        let Some(f) = &mut self.funcs[bdf.device as usize] else { return };

        // Command/Status dword: Status's upper 16 bits are RW1C on real
        // hardware (PCI spec) — writing 1 to a Status bit clears it,
        // writing 0 leaves it alone. `azos_pci::set_command_bits`'s
        // whole safety argument (a Command write must never clear an
        // unrelated Status error bit) depends on that; a plain
        // register-file fake that just stores `val` verbatim would
        // silently "disprove" a correct implementation by clobbering
        // Status on every Command write, so this models it explicitly.
        if offset == OFF_COMMAND {
            let idx = (offset / 4) as usize;
            let cur_status = f.dwords[idx] & 0xffff_0000;
            let write_status = val & 0xffff_0000;
            let remaining_status = cur_status & !write_status; // 1-bits in the write clear that bit.
            f.dwords[idx] = remaining_status | (val & 0xffff);
            return;
        }

        // BAR hardware emulation: an all-1s write yields the size mask
        // (fixed bits preserved) on the next read; any other write yields
        // the fixed bits ORed into the caller's address bits, exactly like
        // real BAR decode logic ignoring the low fixed bits on write.
        if (OFF_BAR0..OFF_BAR0 + 24).contains(&offset) && offset % 4 == 0 {
            let index = ((offset - OFF_BAR0) / 4) as usize;

            if val == 0xffff_ffff {
                let size = f.bar_size[index.min(5)];
                if size == 0 {
                    f.dwords[(offset / 4) as usize] = f.bar_fixed_bits[index.min(5)];
                } else {
                    let mask32 = if size > 0xffff_ffff { 0u32 } else { (!(size - 1)) as u32 };
                    f.dwords[(offset / 4) as usize] = mask32 | f.bar_fixed_bits[index.min(5)];
                }
                return;
            }
            f.dwords[(offset / 4) as usize] = (val & !0xf) | f.bar_fixed_bits[index.min(5)];
            return;
        }

        f.dwords[(offset / 4) as usize] = val;
    }
}

// -----------------------------------------------------------------------
// ECAM address math
// -----------------------------------------------------------------------

#[test]
fn ecam_offset_matches_spec_layout() {
    let bdf = Bdf::new(1, 2, 3);
    // bus<<20 | dev<<15 | func<<12
    let expect = (1usize << 20) | (2usize << 15) | (3usize << 12);
    assert_eq!(ecam_function_offset(bdf), expect);
    assert_eq!(ecam_address(0x3000_0000, bdf, 0x10), 0x3000_0000 + expect + 0x10);
}

#[test]
fn bdf_masks_out_of_range_device_and_function() {
    let bdf = Bdf::new(0, 0xff, 0xff);
    assert_eq!(bdf.device, 0x1f);
    assert_eq!(bdf.function, 0x07);
}

// -----------------------------------------------------------------------
// function_exists
// -----------------------------------------------------------------------

#[test]
fn absent_function_reads_all_ones_vendor() {
    let bus = FakeBus::new();
    assert!(!function_exists(&bus, Bdf::new(0, 0, 0)));
}

#[test]
fn present_function_is_detected() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    bus.put(0, f);
    assert!(function_exists(&bus, Bdf::new(0, 0, 0)));
}

// -----------------------------------------------------------------------
// BAR sizing — this is the canary: RED before the fix, GREEN after.
// -----------------------------------------------------------------------

#[test]
fn mem32_bar_size_and_address_roundtrip() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    f.configure_mem_bar(0, false, false, 0x4000_0000, 0x1000);
    bus.put(0, f);

    let (bars, n) = decode_bars(&mut bus, Bdf::new(0, 0, 0));
    assert_eq!(n, 1);
    let bar = bars[0].unwrap();
    assert_eq!(bar.kind, BarKind::Mem32);
    assert_eq!(bar.address, 0x4000_0000);
    assert_eq!(bar.size, 0x1000);

    // The probe must restore the original value — a second decode must
    // see the same address, not the all-1s size-probe value leaking.
    let (bars2, _) = decode_bars(&mut bus, Bdf::new(0, 0, 0));
    assert_eq!(bars2[0].unwrap().address, 0x4000_0000);
}

#[test]
fn mem64_bar_consumes_two_slots_and_reports_one_bar() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1042);
    // 64-bit BAR at index 0 (consumes slots 0 and 1), a plain 32-bit BAR
    // at index 2 right after it — proves the walker skips the high half
    // instead of misreading it as its own BAR.
    f.configure_mem_bar(0, true, false, 0x1_0000_1000, 0x4000);
    f.configure_mem_bar(2, false, false, 0x5000_0000, 0x2000);
    bus.put(0, f);

    let (bars, n) = decode_bars(&mut bus, Bdf::new(0, 0, 0));
    assert_eq!(n, 2, "64-bit BAR pair must yield exactly one Bar, plus the real bar2");
    let b0 = bars[0].unwrap();
    assert_eq!(b0.index, 0);
    assert_eq!(b0.kind, BarKind::Mem64);
    assert_eq!(b0.address, 0x1_0000_1000);
    assert_eq!(b0.size, 0x4000);

    let b1 = bars[1].unwrap();
    assert_eq!(b1.index, 2, "must resume numbering at slot 2, not slot 1");
    assert_eq!(b1.kind, BarKind::Mem32);
    assert_eq!(b1.address, 0x5000_0000);
    assert_eq!(b1.size, 0x2000);
}

#[test]
fn unimplemented_bar_slots_are_skipped_entirely() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);
    // Only BAR0 configured; BARs 1..6 stay all-zero (never sized, size 0
    // on probe) and must NOT show up as entries — that is what makes the
    // gate's one-line-per-function output free of `bar1=...+0x0` noise.
    f.configure_mem_bar(0, false, false, 0x4000_0000, 0x1000);
    bus.put(0, f);

    let (bars, n) = decode_bars(&mut bus, Bdf::new(0, 0, 0));
    assert_eq!(n, 1, "unimplemented BAR slots must not produce entries");
    assert_eq!(bars[0].unwrap().size, 0x1000);
}

// -----------------------------------------------------------------------
// Capability walk — including the hostile / corrupt cases
// -----------------------------------------------------------------------

#[test]
fn capability_walk_finds_msi_and_msix() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);

    // MSI at 0x40: id, next=0x50, msg_ctrl with 64-bit + per-vector mask,
    // 4 vectors capable (MMC=2).
    f.write_u8(0x40, CAP_ID_MSI);
    f.write_u8(0x41, 0x50);
    f.write_u16(0x42, (1 << 7) | (1 << 8) | (2 << 1));

    // MSI-X at 0x50: id, next=0, table size 4 (encoded 3), table BIR=0
    // offset=0x1000, PBA BIR=0 offset=0x2000.
    f.write_u8(0x50, CAP_ID_MSIX);
    f.write_u8(0x51, 0x00);
    f.write_u16(0x52, 3);
    f.write_u32(0x54, 0x1000 | 0);
    f.write_u32(0x58, 0x2000 | 0);

    f.set_cap_list(0x40);
    bus.put(0, f);

    let bdf = Bdf::new(0, 0, 0);
    let caps = walk_capabilities(&bus, bdf);
    assert_eq!(caps.len(), 2);

    let msi_cap = caps.find(CAP_ID_MSI).expect("MSI cap must be found");
    let msi = parse_msi(&bus, bdf, msi_cap);
    assert!(msi.addr64_capable);
    assert!(msi.per_vector_masking);
    assert_eq!(msi.max_vectors, 4);

    let msix_cap = caps.find(CAP_ID_MSIX).expect("MSI-X cap must be found");
    let msix = parse_msix(&bus, bdf, msix_cap);
    assert_eq!(msix.table_size, 4);
    assert_eq!(msix.table_bar, 0);
    assert_eq!(msix.table_offset, 0x1000);
    assert_eq!(msix.pba_offset, 0x2000);
}

#[test]
fn capability_walk_terminates_on_a_self_pointing_loop() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);

    // A hostile/corrupt device: cap at 0x40 whose `next` points back at
    // itself. Without CAP_WALK_MAX_HOPS this spins forever.
    f.write_u8(0x40, CAP_ID_VENDOR);
    f.write_u8(0x41, 0x40);
    f.set_cap_list(0x40);
    bus.put(0, f);

    let bdf = Bdf::new(0, 0, 0);
    let caps = walk_capabilities(&bus, bdf);
    // Must stop — capacity-bounded, not hop-bounded in this particular
    // case (every hop lands on the same real capability, which the
    // fixed-size list accepts until it's full), but it MUST terminate.
    assert!(caps.len() <= MAX_CAPS_PER_FUNCTION);
}

#[test]
fn capability_walk_rejects_unaligned_next_pointer() {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x1af4, 0x1041);

    f.write_u8(0x40, CAP_ID_VENDOR);
    f.write_u8(0x41, 0x41); // unaligned (not a multiple of 4) -> must stop
    f.set_cap_list(0x40);
    bus.put(0, f);

    let caps = walk_capabilities(&bus, Bdf::new(0, 0, 0));
    assert_eq!(caps.len(), 1, "the unaligned next pointer must not be followed");
}

// -----------------------------------------------------------------------
// Enumeration + one-line format (what the stage-1 gate row greps for)
// -----------------------------------------------------------------------

#[test]
fn enumerate_and_format_one_line_per_function() {
    let mut bus = FakeBus::new();

    let mut f0 = FakeFunction::new();
    f0.set_header(0x1af4, 0x1041); // virtio-net
    f0.configure_mem_bar(0, true, false, 0x4000_0000, 0x4000);
    f0.write_u8(0x40, CAP_ID_MSIX);
    f0.write_u8(0x41, 0);
    f0.write_u16(0x42, 3);
    f0.write_u32(0x44, 0x0);
    f0.write_u32(0x48, 0x0);
    f0.set_cap_list(0x40);
    bus.put(0, f0);

    let (funcs, n) = enumerate_bus0::<FakeBus, 8>(&mut bus);
    assert_eq!(n, 1);

    let mut line = String::new();
    format_function_line(&funcs[0].unwrap(), &mut line).unwrap();
    assert!(line.starts_with("pci 00:00.0 1af4:1041"), "got: {line}");
    assert!(line.contains("bar0=mem64:0x40000000+0x4000"), "got: {line}");
    assert!(line.contains("msix=y"), "got: {line}");
    assert!(line.contains("msi=n"), "got: {line}");
}

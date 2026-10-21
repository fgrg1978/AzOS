// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_pci::program_msi`: the single-vector MSI capability
//! the Intel e1000e family uses (no MSI-X table). Reuses `FakeBus` from
//! `lib.rs`; each test builds the capability in one of the three layouts
//! (32-bit address, 64-bit address, 64-bit with per-vector masking) and
//! reads the registers back from config space.

#![cfg(test)]

use crate::{FakeBus, FakeFunction};
use azos_pci::*;

const CAP: u16 = 0x50;

/// A function with an MSI capability at `CAP`; `ctrl` is the Message Control
/// the device resets to (capability bits: 7 = 64-bit, 8 = per-vector masking).
fn bus_with_msi(ctrl: u16) -> (FakeBus, Bdf, MsiInfo) {
    let mut bus = FakeBus::new();
    let mut f = FakeFunction::new();
    f.set_header(0x8086, 0x10d3);
    f.write_u8(CAP, CAP_ID_MSI);
    f.write_u8(CAP + 1, 0);
    f.write_u16(CAP + 2, ctrl);
    // Poison every register the programming must overwrite.
    for off in (CAP + 4..CAP + 0x18).step_by(4) {
        f.write_u32(off, 0xdead_beef);
    }
    f.set_cap_list(CAP as u8);
    bus.put(0, f);
    let bdf = Bdf::new(0, 0, 0);
    let cap = walk_capabilities(&bus, bdf).find(CAP_ID_MSI).expect("MSI cap");
    let msi = parse_msi(&bus, bdf, cap);
    (bus, bdf, msi)
}

/// **Discriminates.** 64-bit layout: address low at +4, high at +8, data at
/// +12, and MSI Enable set with Multiple Message Enable forced to one vector
/// even if the device came up asking for four. A driver that writes the
/// 32-bit layout's data offset (+8) leaves +12 poisoned and clobbers the
/// address's high half; one that forgets to clear MME asks for 4 vectors.
#[test]
fn msi_64bit_layout_lands_and_enables_one_vector() {
    let (mut bus, bdf, msi) = bus_with_msi(1 << 7 | 2 << 4); // 64-bit, MME = 4 vectors
    assert!(msi.addr64_capable && !msi.per_vector_masking);
    assert!(program_msi(&mut bus, bdf, &msi, 0x0000_0012_3456_7000, 0x2a));
    assert_eq!(bus.read32(bdf, CAP + 4), 0x3456_7000);
    assert_eq!(bus.read32(bdf, CAP + 8), 0x12);
    assert_eq!(bus.read32(bdf, CAP + 12) & 0xffff, 0x2a);
    let ctrl = bus.read16(bdf, CAP + 2);
    assert_eq!(ctrl & MSGCTRL_MSI_ENABLE, 1);
    assert_eq!(ctrl & MSGCTRL_MSI_MME_MASK, 0, "one vector");
    assert_eq!(ctrl & 1 << 7, 1 << 7, "capability bits survive");
    assert!(msi_is_enabled(&bus, bdf, &msi));
}

/// **Discriminates.** 32-bit layout: data at +8, no high half. The same
/// function that wrote +12 for a 64-bit capability must not touch +12 here.
#[test]
fn msi_32bit_layout_puts_data_at_offset_8() {
    let (mut bus, bdf, msi) = bus_with_msi(0);
    assert!(!msi.addr64_capable);
    assert!(program_msi(&mut bus, bdf, &msi, 0xfee0_1000, 0x41));
    assert_eq!(bus.read32(bdf, CAP + 4), 0xfee0_1000);
    assert_eq!(bus.read32(bdf, CAP + 8) & 0xffff, 0x41);
    assert_eq!(bus.read32(bdf, CAP + 12), 0xdead_beef, "+12 is not ours in this layout");
    assert!(msi_is_enabled(&bus, bdf, &msi));
}

/// **Discriminates.** Per-vector masking: the mask register (+16 in the
/// 64-bit layout) is cleared, or the one vector would stay masked forever.
#[test]
fn msi_per_vector_mask_is_cleared() {
    let (mut bus, bdf, msi) = bus_with_msi(1 << 7 | 1 << 8);
    assert!(msi.per_vector_masking);
    assert!(program_msi(&mut bus, bdf, &msi, 0xfee0_0000, 0x30));
    assert_eq!(bus.read32(bdf, CAP + 16), 0);
}

/// **Discriminates.** A message that does not fit is refused and nothing is
/// written: data above 16 bits, or an address above 4 GiB on a function with
/// only the low half. A version that truncates writes a wrong doorbell.
#[test]
fn msi_message_that_does_not_fit_is_refused_untouched() {
    let (mut bus, bdf, msi) = bus_with_msi(0);
    assert!(!program_msi(&mut bus, bdf, &msi, 1 << 32, 1));
    assert!(!program_msi(&mut bus, bdf, &msi, 0xfee0_0000, 0x1_0000));
    assert_eq!(bus.read32(bdf, CAP + 4), 0xdead_beef);
    assert!(!msi_is_enabled(&bus, bdf, &msi));
}

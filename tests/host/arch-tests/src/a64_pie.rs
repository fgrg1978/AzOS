// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Stage-1 indirect permissions on aarch64 (Kconfig `A64_S1PIE`): the pure half
//! of `arch/aarch64/src/mmu/pie.rs` and the leaf encoding of `mmu/mod.rs` that
//! it depends on. The encodings are literals from Linux's headers (cited per
//! assert), so a constant moved by one bit fails; the scheme is checked by
//! enumerating every leaf the page-table code builds, in the `A64_S1PIE`
//! encoding whatever this host's Kconfig, against the direct permissions.

use crate::aarch64_mmu::pie::*;
use crate::aarch64_mmu::pte_fmt::{AF, AP_EL0, AP_RO, CONT, DBM, PXN, UXN, VALID, TYPE_TABLE_OR_PAGE};
use crate::aarch64_mmu::{attr_bits_with, break_cow_with, guarded, make_table, perms_of, ptwin, share_cow_with, tcr_with_ha};
use azos_arch_api::{MemType, PagePerms};

/// Every `PagePerms` `attr_bits` accepts (read is always set on aarch64).
fn all_perms() -> Vec<PagePerms> {
    let mut v = Vec::new();
    for bits in 0..32u32 {
        for mem in [MemType::WB, MemType::WC, MemType::NC, MemType::Device] {
            let (write, exec, user) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
            v.push(PagePerms { read: true, write, exec, user, mem, accessed: bits & 8 != 0, dirty: bits & 16 != 0 });
        }
    }
    v
}

/// Every word the page-table code builds or rewrites a leaf into, in the
/// `A64_S1PIE` encoding: each `make_leaf` (page and block type), its
/// copy-on-write share and break, the BTI guard, the POE pool tag and the
/// contiguous hint.
fn produced_words() -> Vec<u64> {
    let mut v = Vec::new();
    for p in all_perms() {
        let attrs = attr_bits_with(p, DBM).unwrap();
        for leaf in [0x4000_1000 | VALID | TYPE_TABLE_OR_PAGE | attrs, 0x4020_0000 | VALID | attrs] {
            let shared = share_cow_with(leaf, DBM);
            v.extend([leaf, shared, break_cow_with(shared, DBM), guarded(leaf), ptwin::tag(leaf), leaf | CONT]);
        }
    }
    v
}

/// The index is UXN, PXN, DBM, AP[1] from high to low bit (Linux
/// pgtable-hwdef.h `PTE_PI_IDX_0` 6 /* AP[1] */, `_1` 51 /* DBM */, `_2` 53
/// /* PXN */, `_3` 54 /* UXN */); the nibbles are Linux sysreg.h's `PIE_*`;
/// `TCR2_EL1.PIE` is bit 1 and nPIR_EL1 / nPIRE0_EL1 bits 58 / 57 of
/// HFGRTR_EL2 and HFGWTR_EL2 (arch/arm64/tools/sysreg). Canary: swap two
/// entries of `PI_BITS` and the first assert fails; nPIR at 59 (nPOR_EL0) the
/// third.
#[test]
fn the_pie_encodings_are_linuxs() {
    assert_eq!(PI_BITS, [6, 51, 53, 54]);
    assert_eq!(
        [PIE_NONE_O, PIE_R_O, PIE_X_O, PIE_RX_O, PIE_RW_O, PIE_RWX_O, PIE_R, PIE_GCS, PIE_RX, PIE_RW, PIE_RWX],
        [0x0, 0x1, 0x2, 0x3, 0x5, 0x7, 0x8, 0x9, 0xa, 0xc, 0xe]
    );
    assert_eq!((TCR2_EL1_PIE, HFGXTR_NPIR_EL1, HFGXTR_NPIRE0_EL1), (1 << 1, 1 << 58, 1 << 57));
    assert_eq!(HFGXTR_NPIR_EL1 & !(0xFFFF << 48), 0, "the trampoline ORs it in as a 64-bit logical immediate");
    // Linux's own page types land where its table says (pgtable-prot.h,
    // `/* e: PAGE_KERNEL PTE_UXN | PTE_PXN | PTE_WRITE */` and the rest).
    assert_eq!(pi_index(UXN | PXN | DBM), 0xe);
    assert_eq!(pi_index(UXN), 0x8);
    assert_eq!(pi_index(PXN | AP_EL0), 0x5);
    assert_eq!(pi_index(UXN | PXN | DBM | AP_EL0), 0xf);
    assert_eq!(pi_index(UXN | DBM | AP_EL0), 0xb, "Linux's user GCS page");
    assert_eq!(pi_index(AP_RO | AF | (1 << 50) | (7 << 60) | 0xFFFF_F000), 0, "no other bit is part of the index");
}

/// The two registers, written out: EL1 RX/RWX/R/RW for the kernel indices 8, a,
/// c, e and R/RW for the user ones 5, 7, d, f, the GCS permission at 4; EL0 the
/// user indices only. Canary: give `GCS_INDEX` 0xb (Linux's user GCS) and the
/// first assert fails.
#[test]
fn the_registers_hold_the_scheme() {
    assert_eq!(GCS_INDEX, 4);
    assert_eq!(PIR_EL1_VALUE, 0x5511_0703_5019_0000);
    assert_eq!(PIRE0_EL1_VALUE, 0x5010_0000_7030_0000);
    let mut seen = Vec::new();
    for i in 0..16 {
        if produced(i) {
            seen.push(i);
        }
    }
    assert_eq!(seen, [0x5, 0x7, 0x8, 0xa, 0xc, 0xd, 0xe, 0xf]);
}

/// **Every leaf keeps its exact permissions with PIE on.** Each word the
/// page-table code builds has a produced index, AP[2] set exactly when DBM is
/// clear, and grants with `PIR_EL1`/`PIRE0_EL1` what the direct bits grant,
/// whether or not bit 7 removes write under PIE. Canaries: `attr_bits` not
/// setting the write bit (`write_dbm` ignored) fails the index check of a
/// writable page; `share_cow` keeping DBM fails the AP[2]/DBM check.
#[test]
fn every_produced_leaf_has_the_same_permissions_with_and_without_pie() {
    let words = produced_words();
    assert!(words.len() > 1000);
    for w in words {
        let i = pi_index(w);
        assert!(produced(i), "{w:#x}: index {i:#x} is not one the registers give the direct meaning");
        assert_eq!(w & AP_RO != 0, w & DBM == 0, "{w:#x}: AP[2] and the write bit disagree");
        for ndirty in [false, true] {
            assert_eq!(indirect(w, PIR_EL1_VALUE, PIRE0_EL1_VALUE, ndirty), Some(direct(w)), "{w:#x} (index {i:#x}, nDirty {ndirty})");
        }
    }
}

/// All 16 indices: a produced one means under PIE what its leaf means under
/// the direct bits; every other grants nothing at either level, but the GCS
/// index, which EL1 reads and the GCS instructions read and write (no plain
/// store) and EL0 cannot touch.
#[test]
fn every_index_is_the_direct_meaning_nothing_or_the_gcs_page() {
    for i in 0..16 {
        let (el1, gcs, _) = decode(nibble(PIR_EL1_VALUE, i)).unwrap();
        let (el0, gcs0, _) = decode(nibble(PIRE0_EL1_VALUE, i)).unwrap();
        let none = Rwx { r: false, w: false, x: false };
        assert!(!gcs0, "index {i:#x}: EL0 has a GCS permission");
        if produced(i) {
            assert_eq!(pi_index(index_leaf(i)), i);
            assert_eq!(Access { el1, el0 }, direct(index_leaf(i)), "index {i:#x}");
            assert!(!gcs);
        } else if i == GCS_INDEX {
            assert_eq!((el1, gcs, el0), (Rwx { r: true, w: false, x: false }, true, none));
        } else {
            assert_eq!((el1, gcs, el0), (none, false, none), "index {i:#x} grants something");
        }
    }
}

/// The overlay applies to every produced index at EL1 (the `_O` encodings), so
/// `A64_POE`'s write-deny on the pool (index 1 of `POR_EL1`) still holds with
/// PIE on. Canary: build the kernel indices with Linux's `PIE_RW` (0xc, no
/// overlay) and this fails while the permission checks above still pass.
#[test]
fn the_overlay_still_applies_to_every_produced_index() {
    for i in (0..16).filter(|&i| produced(i)) {
        let (_, _, overlay) = decode(nibble(PIR_EL1_VALUE, i)).unwrap();
        assert!(overlay, "index {i:#x}: POR_EL1 would not apply");
    }
}

/// A GCS leaf is a kernel read-write leaf with the GCS index and nothing else
/// changed: PXN set; UXN, DBM, AP[1] and AP[2] clear; frame, AF, shareability,
/// memory type and the software bits as they were.
#[test]
fn a_gcs_leaf_changes_only_the_index_bits() {
    let rw = 0x4000_3000 | VALID | TYPE_TABLE_OR_PAGE | attr_bits_with(PagePerms::KERNEL_RW, DBM).unwrap();
    let g = gcs_leaf(rw);
    assert_eq!(pi_index(g), GCS_INDEX);
    assert_eq!(g & AP_RO, 0, "a GCS write would meet nDirty");
    let index_bits = UXN | PXN | DBM | AP_EL0 | AP_RO;
    assert_eq!(g & !index_bits, rw & !index_bits);
    assert_eq!(gcs_leaf(rw | AP_EL0 | AP_RO), g, "a user or read-only source still makes the kernel GCS page");
}

/// Outside an `A64_S1PIE` build the encoding is what it was: no leaf carries
/// DBM (the split monitor refuses one), a share sets AP[2] and the COW mark, a
/// break clears both and sets the software dirty bit.
#[test]
fn without_s1pie_no_leaf_carries_dbm() {
    for p in all_perms() {
        let w = 0x4000_1000 | VALID | TYPE_TABLE_OR_PAGE | attr_bits_with(p, 0).unwrap();
        assert_eq!(w & DBM, 0, "{p:?}");
        assert_eq!(w & AP_RO == 0, p.write);
        let s = share_cow_with(w, 0);
        assert_eq!(s, w | AP_RO | 1 << 55);
        assert_eq!(break_cow_with(s, 0), (w & !AP_RO) | 1 << 56);
    }
}

/// One `TCR2_EL1` value for both features, every other field 0; the POE
/// readback still sees the pool locked with PIE on; and `TCR_EL1.HD` (bit 40)
/// is never what `tcr_with_ha` sets, so DBM stays inert under the direct
/// permissions.
#[test]
fn tcr2_is_composed_and_hd_stays_off() {
    assert_eq!(tcr2_value(false, false), 0);
    assert_eq!(tcr2_value(true, false), ptwin::TCR2_EL1_POE);
    assert_eq!(tcr2_value(false, true), TCR2_EL1_PIE);
    assert_eq!(tcr2_value(true, true), 0b1010);
    assert!(ptwin::denies_writes(tcr2_value(true, true), ptwin::POR_LOCKED));
    assert_eq!(tcr_with_ha(0), 1 << 39);
}

/// No table descriptor carries hierarchical permissions (APTable 62:61,
/// UXNTable 60, PXNTable 59, NSTable 63), so the indirect scheme's handling of
/// them cannot change what a leaf grants. Canary: OR APTable into `make_table`
/// and this fails.
#[test]
fn table_descriptors_carry_no_hierarchical_permissions() {
    for pa in [0usize, 0x4000_0000, 0x0000_FFFF_FFFF_F000, 0x1234_5000] {
        assert_eq!(make_table(pa) & (0x1F << 59), 0, "{pa:#x}");
    }
}

/// The generic decoder reads a kernel GCS leaf read-only (and not executable,
/// not user), so rebuilding a leaf from its decoded permissions turns a GCS
/// page into a read-only one, never a writable one; and no leaf the
/// page-table code builds is mistaken for one. Canary: drop `is_gcs_leaf`
/// from `perms_from_attr_bits` and the first assert fails.
#[test]
fn a_gcs_leaf_decodes_read_only_and_never_rebuilds_writable() {
    let rw = 0x4000_3000 | VALID | TYPE_TABLE_OR_PAGE | attr_bits_with(PagePerms::KERNEL_RW, DBM).unwrap();
    let g = gcs_leaf(rw);
    assert!(is_gcs_leaf(g));
    let p = perms_of(g);
    assert!(!p.write && !p.exec && !p.user, "{p:?}");
    let rebuilt = attr_bits_with(p, DBM).unwrap();
    assert_eq!((rebuilt & AP_RO, rebuilt & DBM), (AP_RO, 0), "a rebuilt GCS leaf is writable");
    assert!(produced_words().iter().all(|&w| !is_gcs_leaf(w)), "a built leaf carries the GCS index");
}

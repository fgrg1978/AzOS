// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The stage-1 descriptor layout the page-table code and the resident monitor
//! agree on (Arm ARM D8.3): bit positions and the predicates that read a word
//! at a level. Numbers only, no dependency: `mmu/mod.rs` builds and decodes
//! leaves with them, and the monitor, which checks every kernel-half write,
//! includes the same file.

/// Levels in the walk: three on every granule this crate builds.
pub const LEVELS: usize = 3;

pub const VALID: u64 = 1 << 0;
/// Bit [1]: at a non-leaf level (level > 0), 1 = table descriptor, 0 = block
/// (leaf). At the last level (level 0), must be 1 for a page descriptor.
pub const TYPE_TABLE_OR_PAGE: u64 = 1 << 1;
/// AP\[1\] (bit 6): 0 = EL1-only, 1 = EL0+EL1 (user-accessible).
pub const AP_EL0: u64 = 1 << 6;
/// AP\[2\] (bit 7): 0 = R/W, 1 = R/O.
pub const AP_RO: u64 = 1 << 7;
/// AF (bit 10): the Access Flag.
pub const AF: u64 = 1 << 10;
/// Output-address bits `[47:12]`: a table pointer or a leaf frame base.
pub const OA_MASK: u64 = 0x0000_FFFF_FFFF_F000;
/// DBM (bit 51): the hardware dirty state writes the descriptor.
pub const DBM: u64 = 1 << 51;
/// Contiguous hint (bit 52): the TLB may cache a run of descriptors as one.
pub const CONT: u64 = 1 << 52;
pub const PXN: u64 = 1 << 53;
pub const UXN: u64 = 1 << 54;

/// The empty (all-zero) word: an unmapped slot.
#[inline]
pub const fn empty() -> u64 { 0 }

/// Is `word`'s valid bit set? True for both table and leaf entries.
#[inline]
pub const fn is_valid(word: u64) -> bool { word & VALID != 0 }

/// Is `word`, read AT `level` (0 = last), a pointer to the next-level table?
#[inline]
pub const fn is_table(word: u64, level: usize) -> bool {
    level > 0 && is_valid(word) && (word & TYPE_TABLE_OR_PAGE != 0)
}

/// Is `word`, read AT `level` (0 = last), a leaf (page or block)?
#[inline]
pub const fn is_leaf(word: u64, level: usize) -> bool {
    if !is_valid(word) { return false; }
    if level == 0 {
        word & TYPE_TABLE_OR_PAGE != 0
    } else {
        word & TYPE_TABLE_OR_PAGE == 0
    }
}

/// The physical address `word` encodes: the next-level table's base for a
/// table entry, or the mapped frame's base for a leaf.
#[inline]
pub const fn phys_addr(word: u64) -> usize {
    (word & OA_MASK) as usize
}

/// Build a non-leaf descriptor pointing at the table based at `pa`.
#[inline]
pub const fn make_table(pa: usize) -> u64 {
    ((pa as u64) & OA_MASK) | VALID | TYPE_TABLE_OR_PAGE
}

/// Can EL1 write through the leaf `word` (AP\[2\] clear)?
#[inline]
pub const fn el1_writable(word: u64) -> bool { word & AP_RO == 0 }

/// Can EL1 fetch from the leaf `word` (PXN clear)?
#[inline]
pub const fn el1_executable(word: u64) -> bool { word & PXN == 0 }

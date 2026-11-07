// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PT_PROTECTION on aarch64 (Kconfig `A64_POE`): the pure half of
//! `arch/aarch64/src/mmu/ptwin.rs`. The register accesses are `msr` and cannot
//! run on the host; the encodings are written here as literals from the Arm ARM,
//! so a constant moved by one bit fails.

use crate::aarch64_mmu::ptwin::*;

/// POIndex is leaf bits 62:60, `TCR2_EL1.POE` is bit 3, the overlay encodings are
/// R=1, X=2, W=4 per index, and the EL2 grants are `HCRX_EL2` bit 14 and
/// `nPOR_EL1` at bit 60 (bit 59 is `nPOR_EL0`, EL0's, which does not grant EL1
/// the register). Canary: POIndex shift 60→59 fails the first line, nPOR 60→59
/// the second.
#[test]
fn the_poe_encoding_is_the_architectures() {
    assert_eq!((PTE_POINDEX_SHIFT, PTE_POINDEX_MASK), (60, 0x7000_0000_0000_0000));
    assert_eq!((TCR2_EL1_POE, HCRX_TCR2EN, HFGXTR_NPOR_EL1), (1 << 3, 1 << 14, 1 << 60));
    assert_ne!(HFGXTR_NPOR_EL1, 1 << 59, "that is nPOR_EL0");
    assert_eq!((OVL_R, OVL_X, OVL_W), (1, 2, 4));
    assert_eq!(POR_LOCKED, 0x17, "index 0 RWX (7), index 1 R (1)");
}

/// Tagging sets the pool's index and nothing else, and retags another index.
#[test]
fn tagging_a_leaf_changes_only_the_overlay_index() {
    for w in [0x0060_0000_4000_0743u64, 1 << 63, 0x7000_0000_0000_0003, 0] {
        let t = tag(w);
        assert_eq!((t >> 60) & 7, 1);
        assert_eq!(t & !PTE_POINDEX_MASK, w & !PTE_POINDEX_MASK, "{w:#x}: a bit outside the index moved");
    }
}

/// The window gives write back to the pool's index only; the token carries
/// `POR_EL1` and `DAIF` whole; the readback says locked only for the locked pair.
/// Canary: `opened` setting W on index 0 fails the first assert.
#[test]
fn the_window_lifts_the_pool_indexs_write_only() {
    assert_eq!(opened(POR_LOCKED), 0x57);
    assert_eq!(opened(opened(POR_LOCKED)), 0x57, "an open window stays open (nesting)");
    for (por, daif) in [(POR_LOCKED, 0x3C0u64), (0x57, 0), (0xFFFF_FFFF, 0x3C0)] {
        assert_eq!(unpack(pack(por, daif)), (por, daif));
    }
    assert!(denies_writes(TCR2_EL1_POE, POR_LOCKED));
    assert!(!denies_writes(0, POR_LOCKED), "POE off: the overlay is not applied");
    assert!(!denies_writes(TCR2_EL1_POE, 0x57), "a window is open");
    assert!(!denies_writes(TCR2_EL1_POE, 0x07), "index 1 has no permissions at all");
}

/// A by-VA TLBI operand is the page number in bits 43:0 and nothing else: a kernel
/// VA (bits 63:48 all ones) must give TTL = 0 and no ASID bits. Canary: drop the
/// mask in `tlbi_va_operand` and the kernel-VA asserts fail.
#[test]
fn a_tlbi_operand_for_a_kernel_va_has_no_ttl_and_no_asid() {
    use crate::sysregs::tlbi_va_operand;
    let op = tlbi_va_operand(0xffff_8000_1234_5000);
    assert_eq!(op, 0xff8_0001_2345, "VA[55:12]");
    assert_eq!(op >> 44, 0, "bits 63:44 (TTL, ASID) must be clear");
    assert_eq!(tlbi_va_operand(0x0000_0000_4000_1000), 0x4_0001, "a user VA is unchanged");
    assert_eq!(tlbi_va_operand(u64::MAX) >> 44, 0);
}

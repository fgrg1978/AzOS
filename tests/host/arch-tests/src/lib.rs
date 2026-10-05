// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the pure parts of `crates/core/arch-riscv64`.
//!
//! **WHY.** 1375 lines with no test of any kind, and it is where the bug of
//! 2026-08-31 lived: `sie.SSIE` was never enabled on secondary harts, so the
//! K-C15 wake doorbell had never once worked on a hart other than 0 since it
//! was added. Nothing caught it for months because nothing looks at this crate.
//!
//! Most of it is inline assembly and cannot run on the host. What can is the
//! arithmetic — Sv39 address decomposition and PMP region encoding — and that
//! is the half whose mistakes are **silent**: a wrong VPN field maps a
//! different page, a wrong PMP encoding leaves memory unprotected while every
//! test still passes.

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/mmu.rs"]
mod mmu;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/pmp.rs"]
mod pmp;

// Wave 8 TLB shootdown: which harts a revoke must interrupt. A wrong mask is
// silent in the direction that matters — a hart left out keeps a stale
// translation and nothing faults — so the selection rule is pinned here.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/tlb.rs"]
mod tlb;

/// The shootdown's scan bound: one past the highest hart ever noted, never
/// lowered, blind to ids it cannot index. Canary: `--features
/// tlb-bound-canary` (the note records nothing) fails the first assertion.
#[cfg(test)]
mod tlb_bound {
    use super::tlb::{hart_bound, note_hart_online, remote_mask, TLB_MAX_HARTS};

    #[test]
    fn the_bound_covers_every_noted_hart_and_the_mask_needs_it() {
        note_hart_online(3);
        assert!(hart_bound() >= 4, "hart 3 noted, bound {}", hart_bound());
        note_hart_online(1);
        assert!(hart_bound() >= 4, "a lower id lowered the bound to {}", hart_bound());
        note_hart_online(TLB_MAX_HARTS);
        assert!(hart_bound() <= TLB_MAX_HARTS, "an out-of-range id raised the bound past the table");
        // Hart 3 running root R is found under the bound, and missed under a
        // bound that leaves it out -- the failure the bound must never cause.
        let root = 0x8123_4000usize;
        let published = |h: usize| if h == 3 { (8usize << 60) | (root >> 12) } else { 0 };
        assert_eq!(remote_mask(published, hart_bound(), 0, root), 1 << 3);
        assert_eq!(remote_mask(published, 3, 0, root), 0);
    }
}

#[cfg(test)]
mod tlb_mask {
    use super::tlb::{publish, remote_mask, AZOS_HART_SATP, TLB_MAX_HARTS};
    use core::sync::atomic::Ordering;

    const MODE_SV39: usize = 8 << 60;
    fn satp(root: usize, asid: usize) -> usize { MODE_SV39 | (asid << 44) | (root >> 12) }

    #[test]
    fn only_harts_running_the_root_are_selected_and_never_self() {
        let root = 0x8123_4000;
        let other = 0x8765_4000;
        let pubd = [satp(root, 0), satp(other, 0), satp(root, 0), 0, satp(root, 0), 0, 0, 0];
        // From hart 0: harts 2 and 4 hold it; hart 0 is self, hart 1 runs another root.
        assert_eq!(remote_mask(|h| pubd[h], 8, 0, root), 0b1_0100);
        // From hart 1 (not running it): harts 0, 2 and 4.
        assert_eq!(remote_mask(|h| pubd[h], 8, 1, root), 0b1_0101);
    }

    #[test]
    fn a_single_hart_address_space_needs_no_ipi() {
        // Today's shape: the caller runs the address space, nobody else does.
        let root = 0x8020_0000;
        let pubd = [satp(root, 0), satp(0x8030_0000, 0), 0, 0, 0, 0, 0, 0];
        assert_eq!(remote_mask(|h| pubd[h], 8, 0, root), 0);
    }

    #[test]
    fn mode_and_asid_bits_do_not_hide_a_hart() {
        let root = 0x9000_0000;
        let pubd = [0, satp(root, 7), satp(root, 0xffff), 0, 0, 0, 0, 0];
        assert_eq!(remote_mask(|h| pubd[h], 8, 0, root), 0b110);
    }

    #[test]
    fn unpublished_slots_and_a_zero_root_select_nothing() {
        let pubd = [0usize; 8];
        assert_eq!(remote_mask(|h| pubd[h], 8, 0, 0x8000_0000), 0);
        // Root 0 must never match the zero ("never published") slots.
        assert_eq!(remote_mask(|h| pubd[h], 8, 3, 0), 0);
    }

    #[test]
    fn hart_count_is_clamped_to_the_table() {
        let root = 0x8123_4000;
        let pubd = [satp(root, 0); 8];
        assert_eq!(remote_mask(|h| pubd[h], 64, 0, root), 0b1111_1110);
    }

    /// The page-table free check (`holders`) is the shootdown's selection
    /// with nobody excluded: the hart that asks is the one most likely to
    /// still be on the table (an exit that frees before it leaves), so it
    /// must count. Canary: pass the caller's own id as `self_hart` in
    /// `holders` and the first assertion fails.
    #[test]
    fn a_free_counts_the_hart_that_asks() {
        use super::tlb::{holders, note_hart_online};
        let root = 0x8abc_d000;
        note_hart_online(6);
        publish(6, satp(root, 3));
        assert_eq!(holders(root) & (1 << 6), 1 << 6, "a hart publishing the root is a holder");
        publish(6, satp(0x8abc_e000, 0));
        assert_eq!(holders(root) & (1 << 6), 0, "a hart that moved off it is not");
        publish(6, 0);
        // The same rule through the pure selection: excluding nobody includes
        // the would-be self.
        let pubd = [satp(root, 0), 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(remote_mask(|h| pubd[h], 8, usize::MAX, root), 1);
        assert_eq!(remote_mask(|h| pubd[h], 8, 0, root), 0);
    }

    #[test]
    fn publish_stores_the_value_and_ignores_out_of_range_harts() {
        publish(5, 0x1234);
        assert_eq!(AZOS_HART_SATP[5].load(Ordering::SeqCst), 0x1234);
        publish(TLB_MAX_HARTS, 0x5678); // must not panic or write anywhere
        publish(5, 0);
    }
}

// The aarch64 side's ID-register decoding, for the same reason: it is pure
// arithmetic whose mistakes are silent. A field shift off by four reads a
// NEIGHBOURING feature's bits and reports that one instead — a kernel that
// believes it has MTE when the CPU said BTI is a kernel that has disabled its
// own memory tagging and does not know. The `#[cfg(target_arch)]` guards inside
// keep the register reads out of a host build; `detect()` answers `NONE` here,
// which is itself asserted.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/features.rs"]
mod aarch64_features;

// M38/U10-3: VMSAv8-64 PTE attribute encode/decode is the aarch64-side twin
// of `mmu` above — pure bit arithmetic, no `cfg(target_arch)` gate anywhere
// in the file, and exactly the kind of mistake that is silent: the ret2usr
// fix landed here (`attr_bits` now sets PXN unconditionally whenever
// `perms.user`) needed a matching fix to `perms_from_attr_bits`'s decode
// side (UXN, not PXN, now carries "software asked for exec" once `user` is
// true) — getting THAT wrong would silently strip `exec` off every user
// page on a COW/permission-widening round trip, passing every existing
// check because nothing else in the tree decodes a PTE and compares it
// against the `PagePerms` that built it. See `mod aarch64_mmu` below.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/mmu.rs"]
mod aarch64_mmu;

#[cfg(test)]
mod sv39 {
    use super::mmu::*;

    /// Sv39 splits a 39-bit VA into three 9-bit page-table indices and a
    /// 12-bit offset. The test address gives each field a **distinct** value,
    /// so a copy-paste shift error cannot pass by coincidence — which is
    /// exactly what a test using 0 or an all-ones address would allow.
    #[test]
    fn vpn_fields_are_the_bits_the_spec_names() {
        //   VPN[2]=0x123 (bits 38:30), VPN[1]=0x0AB (29:21),
        //   VPN[0]=0x1C4 (20:12), offset=0xDEF (11:0)
        let va = (0x123usize << 30) | (0x0AB << 21) | (0x1C4 << 12) | 0xDEF;
        assert_eq!(vpn2(va), 0x123, "VPN[2] is bits 38:30");
        assert_eq!(vpn1(va), 0x0AB, "VPN[1] is bits 29:21");
        assert_eq!(vpn0(va), 0x1C4, "VPN[0] is bits 20:12");
    }

    /// Each field is 9 bits and must not bleed into its neighbours. Bits above
    /// 38 belong to the sign extension, not to VPN[2]: an unmasked shift would
    /// return them and index past a 512-entry table.
    #[test]
    fn vpn_fields_mask_to_nine_bits() {
        let all = usize::MAX;
        assert_eq!(vpn2(all), 0x1FF);
        assert_eq!(vpn1(all), 0x1FF);
        assert_eq!(vpn0(all), 0x1FF);
        assert!(vpn2(all) < PT_ENTRIES, "VPN[2] must index a 512-entry table");
    }

    /// `satp` for Sv39: MODE=8 in bits [63:60], ASID in [59:44], PPN in
    /// [43:0]. Wrong placement does not fail loudly — the MMU either stays off
    /// (MODE=0) or walks from the wrong root, and both look like "the kernel
    /// hangs early".
    #[test]
    fn satp_places_mode_asid_and_ppn_where_the_spec_says() {
        let root = 0x8020_1000usize;      // page-aligned physical root
        let satp = make_satp(root, 0xBEEF);
        assert_eq!(satp >> 60, 8, "MODE must be 8 (Sv39)");
        assert_eq!((satp >> 44) & 0xFFFF, 0xBEEF, "ASID is bits 59:44");
        assert_eq!(satp & 0xFFF_FFFF_FFFF, root >> 12, "PPN is the root >> 12");
        // ASID 0 is the common case and must not disturb the other fields.
        let s0 = make_satp(root, 0);
        assert_eq!(s0 >> 60, 8);
        assert_eq!((s0 >> 44) & 0xFFFF, 0);
    }

    /// Page rounding, including the two cases that are always wrong when this
    /// is written from memory: an already-aligned address must not be pushed
    /// to the next page, and 0 must stay 0.
    #[test]
    fn page_rounding_is_idempotent_on_aligned_addresses() {
        assert_eq!(page_align_up(0), 0);
        assert_eq!(page_align_up(0x1000), 0x1000, "aligned must not advance");
        assert_eq!(page_align_up(0x1001), 0x2000);
        assert_eq!(page_align_up(0xFFF), 0x1000);
        assert_eq!(page_align_down(0x1FFF), 0x1000);
        assert_eq!(page_align_down(0x1000), 0x1000);
        assert!(is_page_aligned(0x2000));
        assert!(!is_page_aligned(0x2001));
    }
}

#[cfg(test)]
mod pmp_encoding {
    use super::pmp::*;

    /// TOR entries encode the **exclusive upper bound**, shifted right by 2
    /// because `pmpaddr` addresses 4-byte units. Forgetting the shift makes
    /// every region four times too large — which protects nothing and fails
    /// nowhere.
    #[test]
    fn tor_encodes_the_exclusive_end_over_four() {
        let r = PmpRegion { name: "t", base: 0x8000_0000, size: 0x1000,
                            perm: PmpPerm::RW, mode: PmpMode::Tor, locked: false };
        assert_eq!(r.tor_addr(), (0x8000_0000usize + 0x1000) >> 2);
    }

    /// NAPOT packs the size into the trailing ones of the address:
    /// `(base >> 2) | (size/8 - 1)`. The classic error is `size/4` or
    /// `size/8` without the `-1`, either of which encodes the wrong power of
    /// two — silently, and in the direction of a larger region.
    #[test]
    fn napot_packs_the_size_into_trailing_ones() {
        for shift in 3..20u32 {                 // 8 B .. 512 KiB
            let size = 1usize << shift;
            let base = 0x8000_0000usize;        // aligned to anything in range
            let r = PmpRegion { name: "n", base, size,
                                perm: PmpPerm::RW, mode: PmpMode::Napot, locked: false };
            let a = r.napot_addr();
            assert_eq!(a, (base >> 2) | ((size / 8) - 1), "size {size}");
            // The encoded region must be exactly `size` bytes: the number of
            // trailing ones determines it, so count them and check.
            let ones = (!a).trailing_zeros();
            assert_eq!(1usize << (ones + 3), size,
                       "NAPOT for {size} decodes to a different size");
        }
    }

    /// The regions are TOR, and **TOR takes its lower bound from the previous
    /// entry's `pmpaddr`**. A gap between one region's end and the next one's
    /// base is therefore not an unmapped hole — it is silently absorbed into
    /// the next region, with the next region's permissions. This is the
    /// property that makes the table correct, and nothing else checks it.
    #[test]
    fn tor_regions_are_contiguous_with_no_gaps() {
        let rs = pmp_regions(0x8000_0000, 0x8020_0000, 0x8040_0000, 0x0020_0000);
        for w in rs.windows(2) {
            let end = w[0].base + w[0].size;
            // The MMIO entry deliberately restarts at a lower base; every
            // other boundary must join exactly.
            if w[1].base < end { continue; }
            assert_eq!(w[1].base, end,
                       "gap between {:?} and {:?}: {:#x}..{:#x}",
                       w[0].name, w[1].name, end, w[1].base);
        }
    }

    /// Every region must be non-empty. A zero-size TOR entry encodes an upper
    /// bound equal to the previous one, which the hardware reads as a region
    /// covering nothing — so the range it was meant to protect falls through
    /// to the next entry.
    #[test]
    fn no_region_is_empty() {
        let rs = pmp_regions(0x8000_0000, 0x8020_0000, 0x8040_0000, 0x0020_0000);
        for r in rs.iter() {
            assert!(r.size > 0, "region {:?} has zero size", r.name);
        }
    }
}

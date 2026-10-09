// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 paging (`crates/core/arch-x86_64/src/{mmu,tlb}.rs`): PTE encode and
//! decode, the CR3 word, the table walker, the shootdown's target mask and
//! local-flush choice. A wrong bit here is silent until real hardware walks
//! it (a PAT bit read as PS maps 2 MiB where 4 KiB was meant; a missing NX
//! makes data executable), so each property has an assertion that goes red
//! when that one bit is dropped.

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/mmu.rs"]
pub mod mmu;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/tlb.rs"]
pub mod tlb;

#[cfg(test)]
mod tests {
    use super::mmu::*;
    use super::tlb;
    use azos_arch_api::{MmuError, PagePerms};
    use std::collections::HashMap;

    const ALL_PERMS: [PagePerms; 10] = [
        PagePerms::KERNEL_RW, PagePerms::KERNEL_RX, PagePerms::KERNEL_RO, PagePerms::KERNEL_RWX,
        PagePerms::USER_RW, PagePerms::USER_RX, PagePerms::USER_RO,
        PagePerms::USER_MMIO_RW, PagePerms::USER_MMIO_RO, PagePerms::MMIO,
    ];

    #[test]
    fn every_perms_constant_round_trips_at_every_leaf_level() {
        for p in ALL_PERMS {
            for (level, pa) in [(0usize, 0x1234_5000usize), (1, 0x4060_0000), (2, 0x8000_0000)] {
                let w = make_leaf_with(pa, p, level, true).unwrap();
                assert_eq!(perms_of(w), p, "level {level}");
                assert_eq!(phys_addr(w), pa);
                assert!(is_leaf(w, level) && is_valid(w));
                assert!(!is_table(w, level) || level == 0);
            }
        }
    }

    #[test]
    fn each_permission_bit_sits_where_the_sdm_says() {
        let k = |p| attr_bits_with(p, true).unwrap();
        assert_eq!(k(PagePerms::USER_RW) & (RW | US | NX | G), RW | US | NX);
        assert_eq!(k(PagePerms::USER_RX) & (RW | US | NX), US);
        assert_eq!(k(PagePerms::KERNEL_RX) & (RW | US | NX | G), G);
        assert_eq!(k(PagePerms::KERNEL_RW) & (RW | NX | A | D), RW | NX | A | D);
        // Bit positions, not just names: P0 RW1 US2 PWT3 PCD4 A5 D6 PS7 G8 NX63.
        assert_eq!([P, RW, US, PWT, PCD, A, D, PS, G, NX],
                   [1, 2, 4, 8, 16, 32, 64, 128, 256, 1 << 63]);
        // G only with the policy on, and never on a user leaf.
        assert_eq!(attr_bits_with(PagePerms::KERNEL_RW, false).unwrap() & G, 0);
        assert_eq!(attr_bits_with(PagePerms::USER_RW, true).unwrap() & G, 0);
    }

    #[test]
    fn device_memory_is_uc_through_pcd_pwt_and_never_the_pat_bit() {
        let w = make_leaf_with(0xFEE0_0000, PagePerms::MMIO, 0, false).unwrap();
        assert_eq!(w & (PCD | PWT), PCD | PWT);
        assert_eq!(w & PAT_4K, 0, "bit 7 at level 0 is PAT, not PS");
        assert_eq!(memory_type(w), PAT_UC);
        let n = make_leaf_with(0x20_0000, PagePerms::KERNEL_RW, 1, false).unwrap();
        assert_eq!(memory_type(n), PAT_WB);
        assert_eq!(n & PAT_HUGE, 0);
        assert!(!perms_of(w).cache && perms_of(n).cache);
        // Linux's PAT layout.
        assert_eq!(PAT_VALUE, 0x0407_0506_0007_0106);
    }

    #[test]
    fn ps_means_leaf_only_at_levels_one_and_two() {
        let pt = make_leaf_with(0x5000, PagePerms::KERNEL_RW, 0, false).unwrap();
        assert_eq!(pt & PS, 0);
        let pd = make_leaf_with(0x20_0000, PagePerms::KERNEL_RW, 1, false).unwrap();
        assert_ne!(pd & PS, 0);
        // A level-0 word with bit 7 (PAT) is still a 4 KiB leaf, and a
        // level-0 word is never a table pointer, PS or not.
        assert!(is_leaf(pt | PAT_4K, 0));
        assert!(!is_table(pt, 0) && !is_table(pt | PAT_4K, 0));
        // A table pointer is never a leaf above level 0, and a PS word is
        // never a table.
        let t = make_table(0x9000);
        for l in 1..=4 { assert!(is_table(t, l) && !is_leaf(t, l)); }
        assert!(!is_table(pd, 1));
        // No leaf at PML4 / PML5, even with PS set.
        assert!(!is_leaf(t | PS, 3) && !is_leaf(t | PS, 4));
        assert_eq!(make_leaf_with(0, PagePerms::KERNEL_RW, 3, true), Err(MmuError::UnrepresentablePerms));
    }

    #[test]
    fn huge_leaves_need_alignment_and_gb_pages_need_the_cpu() {
        assert_eq!(make_leaf_with(0x1000, PagePerms::KERNEL_RW, 1, true), Err(MmuError::NotAligned));
        assert_eq!(make_leaf_with(0x20_0000, PagePerms::KERNEL_RW, 2, true), Err(MmuError::NotAligned));
        assert_eq!(make_leaf_with(0x4000_0000, PagePerms::KERNEL_RW, 2, false), Err(MmuError::UnrepresentablePerms));
        assert!(make_leaf_with(0x4000_0000, PagePerms::KERNEL_RW, 2, true).is_ok());
        assert_eq!(make_leaf_with(1 << 52, PagePerms::KERNEL_RW, 0, false), Err(MmuError::BadPhys));
    }

    #[test]
    fn no_read_has_no_encoding() {
        let p = PagePerms { read: false, ..PagePerms::USER_RX };
        assert_eq!(attr_bits(p), Err(MmuError::UnrepresentablePerms));
        assert_eq!(make_demand(p), 0);
    }

    #[test]
    fn cow_share_and_break() {
        let w = make_leaf_with(0x7000, PagePerms { accessed: true, ..PagePerms::USER_RW }, 0, false).unwrap();
        let s = share_cow(w);
        assert!(is_cow(s) && s & RW == 0 && phys_addr(s) == 0x7000 && is_valid(s));
        let b = break_cow(s);
        assert!(!is_cow(b) && b & RW != 0 && b & D != 0 && phys_addr(b) == 0x7000);
        assert_eq!(b & NX, NX, "exec state survives the round trip");
    }

    #[test]
    fn demand_marker_is_not_present_and_carries_its_perms() {
        for p in ALL_PERMS {
            let w = make_demand(p);
            assert!(!is_valid(w) && is_demand(w));
            assert_eq!(demand_perms(w), PagePerms { ..p });
            assert!(!is_leaf(w, 0) && !is_table(w, 1));
        }
        // A present COW leaf is not a demand marker even with bit 10 set.
        assert!(!is_demand(P | SW_DEMAND));
        assert_eq!([SW_COW, SW_DEMAND], [1 << 9, 1 << 10]);
    }

    #[test]
    fn vpn_and_canonical_form_for_four_and_five_levels() {
        let va = 0xFFFF_8123_4567_8000usize;
        assert_eq!(vpn(va, 0), (va >> 12) & 0x1FF);
        assert_eq!(vpn(va, 1), (va >> 21) & 0x1FF);
        assert_eq!(vpn(va, 2), (va >> 30) & 0x1FF);
        assert_eq!(vpn(va, 3), 0x102);
        assert!(is_canonical(va, 4) && is_canonical(va, 5));
        assert!(!is_canonical(0x0000_8000_0000_0000, 4));
        assert!(is_canonical(0x0000_8000_0000_0000, 5));
        assert!(!is_canonical(0x0100_0000_0000_0000, 5));
        assert_eq!(user_top(4), 0x0000_8000_0000_0000);
        assert_eq!(user_top(5), 0x0100_0000_0000_0000);
        assert_eq!(vpn(KERNEL_VA_OFFSET as usize, 3), KERNEL_HALF_FIRST_SLOT);
        assert!(is_user_va(0x7FFF_FFFF_F000, 4) && !is_user_va(KERNEL_VA_OFFSET as usize, 4));
    }

    #[test]
    fn cr3_word_carries_the_pcid_only_with_pcide() {
        assert_eq!(make_cr3(0x1000, 0x1ABC, true), 0x1000 | 0xABC);
        assert_eq!(make_cr3(0x1000, 0x1ABC, false), 0x1000);
        assert_eq!(cr3_root(0x1000 | 0xABC), 0x1000);
        assert_eq!(cr3_pcid(0x1000 | 0xABC), 0xABC);
        // The switch never asks to keep the incoming PCID's entries.
        assert_eq!(make_cr3(0x1000, 0xFFFF, true) & CR3_NOFLUSH, 0);
    }

    /// Table memory: frames by PA.
    struct Mem { tables: HashMap<usize, [u64; 512]>, next: usize, limit: usize }
    impl Mem {
        fn new(limit: usize) -> (Self, usize) {
            let mut m = Mem { tables: HashMap::new(), next: 0x10_0000, limit };
            let root = m.alloc_table().unwrap();
            (m, root)
        }
    }
    impl TableMem for Mem {
        fn read(&self, t: usize, i: usize) -> u64 { self.tables[&t][i] }
        fn write(&mut self, t: usize, i: usize, w: u64) { self.tables.get_mut(&t).unwrap()[i] = w; }
        fn alloc_table(&mut self) -> Option<usize> {
            if self.tables.len() >= self.limit { return None; }
            let pa = self.next;
            self.next += 0x1000;
            self.tables.insert(pa, [0; 512]);
            Some(pa)
        }
    }

    #[test]
    fn walker_maps_translates_protects_and_unmaps_4k() {
        for levels in [4, 5] {
            let (mut m, root) = Mem::new(64);
            let va = 0x0000_7F12_3456_7000usize;
            map(&mut m, root, levels, va, 0xABC_D000, 0, PagePerms::USER_RW, false).unwrap();
            assert_eq!(m.tables.len(), levels, "one table per level");
            let l = translate(&m, root, levels, va + 0x123).unwrap();
            assert_eq!((l.phys, l.level), (0xABC_D123, 0));
            assert_eq!(map(&mut m, root, levels, va, 0x1000, 0, PagePerms::USER_RW, false),
                       Err(WalkError::AlreadyMapped));
            let old = protect(&mut m, root, levels, va, PagePerms::USER_RO).unwrap();
            assert_ne!(old & RW, 0);
            let l = translate(&m, root, levels, va).unwrap();
            assert_eq!(l.word & RW, 0);
            assert_eq!(phys_addr(l.word), 0xABC_D000, "protect keeps the frame");
            let gone = unmap(&mut m, root, levels, va).unwrap();
            assert_eq!(phys_addr(gone.word), 0xABC_D000);
            assert!(translate(&m, root, levels, va).is_none());
            assert_eq!(unmap(&mut m, root, levels, va), Err(WalkError::NotMapped));
        }
    }

    #[test]
    fn walker_huge_leaves_and_their_conflicts() {
        let (mut m, root) = Mem::new(64);
        let va = 0x4000_0000usize;
        map(&mut m, root, 4, va, 0x8000_0000, 1, PagePerms::KERNEL_RW, false).unwrap();
        let l = translate(&m, root, 4, va + 0x1_2345).unwrap();
        assert_eq!((l.level, l.phys), (1, 0x8001_2345));
        assert_eq!(map(&mut m, root, 4, va + 0x1000, 0x1000, 0, PagePerms::KERNEL_RW, false),
                   Err(WalkError::HugeLeafInTheWay));
        assert_eq!(map(&mut m, root, 4, va + 0x1000, 0x20_0000, 1, PagePerms::KERNEL_RW, false),
                   Err(WalkError::Misaligned));
        assert_eq!(map(&mut m, root, 4, 0x8000_0000, 0x4000_0000, 2, PagePerms::KERNEL_RW, false),
                   Err(WalkError::Mmu(MmuError::UnrepresentablePerms)));
        map(&mut m, root, 4, 0x8000_0000, 0x4000_0000, 2, PagePerms::KERNEL_RW, true).unwrap();
        assert_eq!(translate(&m, root, 4, 0xBFFF_FFFF).unwrap().phys, 0x7FFF_FFFF);
        assert_eq!(unmap(&mut m, root, 4, 0x8000_1000).unwrap().level, 2);
    }

    #[test]
    fn walker_refuses_non_canonical_and_reports_oom() {
        let (mut m, root) = Mem::new(2);
        assert_eq!(map(&mut m, root, 4, 0x0000_8000_0000_0000, 0, 0, PagePerms::USER_RW, false),
                   Err(WalkError::NotCanonical));
        assert_eq!(map(&mut m, root, 4, 0x1000, 0x1000, 0, PagePerms::USER_RW, false),
                   Err(WalkError::NoMemory));
    }

    #[test]
    fn user_roots_share_the_kernel_half_and_nothing_below_it() {
        let (mut m, kroot) = Mem::new(64);
        map(&mut m, kroot, 4, KERNEL_VA_OFFSET as usize, 0, 1, PagePerms::KERNEL_RW, false).unwrap();
        map(&mut m, kroot, 4, 0x1000, 0x1000, 0, PagePerms::KERNEL_RW, false).unwrap();
        let uroot = m.alloc_table().unwrap();
        share_kernel_half(&mut m, kroot, uroot);
        assert_eq!(m.read(uroot, KERNEL_HALF_FIRST_SLOT), m.read(kroot, KERNEL_HALF_FIRST_SLOT));
        assert!(translate(&m, uroot, 4, KERNEL_VA_OFFSET as usize).is_some());
        assert!(translate(&m, uroot, 4, 0x1000).is_none(), "the low half is the user's");
    }

    #[test]
    fn shootdown_targets_cpus_on_the_root_whatever_their_pcid() {
        let published = |c: usize| [0x5000 | 7, 0x6000, 0x5000 | 9, 0, 0x5000][c];
        assert_eq!(tlb::remote_mask(published, 5, 0, 0x5000), 0b10100);
        assert_eq!(tlb::remote_mask(published, 5, 4, 0x5000), 0b00101);
        assert_eq!(tlb::remote_mask(published, 3, 0, 0x5000), 0b00100, "scan bound");
        assert_eq!(tlb::remote_mask(published, 5, 0, 0), 0, "root 0 is nobody");
        // Kernel-wide: every other CPU that has published a root.
        assert_eq!(tlb::remote_mask(published, 5, 0, usize::MAX), 0b10110);
    }

    #[test]
    fn local_flush_choice_respects_the_ceiling_and_globals() {
        use tlb::{local_flush_for as f, LocalFlush::*, ALL};
        assert_eq!(f(0x1234, 1, false, 33), Pages { start: 0x1000, pages: 1 });
        assert_eq!(f(0x1FFF, 2, false, 33), Pages { start: 0x1000, pages: 2 });
        assert_eq!(f(0, 33 * 4096, false, 33), Pages { start: 0, pages: 33 });
        assert_eq!(f(0, 34 * 4096, false, 33), Context);
        assert_eq!(f(0, 34 * 4096, true, 33), Everything);
        assert_eq!(f(0, ALL, false, 33), Context);
        assert_eq!(f(0, ALL, true, 33), Everything);
    }
}

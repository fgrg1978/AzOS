// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Variable page size: the encoders of the aarch64 contiguous hint and the
//! riscv64 Svnapot 64 KiB leaf, the alignment rule, and what breaking a run
//! leaves behind (the words `ARCH.pte_contig_member` hands `vmm::break_contig_run`).
//! The page-table half (`vmm::map_contig_range`,
//! `vmm::break_contig_run`) needs a live MMU and runs in the boot gate; this
//! file pins the words both write and the rule that picks the runs.
//!
//! Canaries (each by hand, red then green):
//! * `Pte::phys_addr` not masking PPN[3:0] when N is set:
//!   `a_napot_word_names_the_run_base_and_a_plain_one_keeps_its_low_bits` goes red.
//! * `aarch64_mmu::clear_contig` returning its argument:
//!   `a_member_is_its_own_page_plus_bit_52` and `one_page_taken_from_a_run_leaves_the_rest_plain_and_mapped` go red.
//! * `napot::member` not clearing N: `a_break_leaves_plain_words_naming_the_frames_the_run_did`
//!   and `one_page_taken_from_a_run_leaves_the_rest_plain_and_mapped` go red.
//!
//! x86_64 has no counterpart below a 2 MiB leaf: its `Mmu::contig_run_pages`
//! is the trait default 0 (see `x86_none`).

use azos_arch_api::contig;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/ext/napot.rs"]
mod napot;

mod rv {
    use super::napot::*;
    use crate::mmu::{Pte, PteFlags, PTE_N};

    const RW: PteFlags = PteFlags::from_bits_truncate(
        PteFlags::VALID.bits() | PteFlags::READ.bits() | PteFlags::WRITE.bits()
            | PteFlags::USER.bits() | PteFlags::ACCESSED.bits() | PteFlags::DIRTY.bits(),
    );
    const RUN: usize = 0x8001_0000;

    #[test]
    fn a_napot_run_is_sixteen_pages_of_64_kib() {
        assert_eq!(NAPOT_PAGES, 16);
        assert_eq!(NAPOT_SIZE, 64 * 1024);
    }

    #[test]
    fn the_word_has_n_and_the_size_marker_and_the_flags() {
        let w = make_64k(RUN, RW);
        assert_ne!(w & PTE_N, 0, "N, bit 63");
        assert_eq!(PTE_N, 1 << 63);
        // PPN[3:0] = 0b1000: word bits 13:10.
        assert_eq!((w >> 10) & 0xF, 0b1000);
        assert_eq!(w & 0x3FF, RW.bits() & 0x3FF, "V R W U A D in place");
        assert!(is_napot(w));
        let p = Pte(w);
        assert!(p.is_valid() && p.is_leaf());
    }

    #[test]
    fn a_napot_word_names_the_run_base_and_a_plain_one_keeps_its_low_bits() {
        let w = Pte(make_64k(RUN, RW));
        // The marker is size, not address: the run's base comes back.
        assert_eq!(w.phys_addr(), RUN);
        // A plain 4 KiB leaf at a frame whose PPN[3:0] happens to be 0b1000
        // is NOT masked: only N makes the field a marker.
        let plain = Pte::new(RUN + 0x8000, RW);
        assert_eq!(plain.0 & PTE_N, 0);
        assert_eq!(plain.phys_addr(), RUN + 0x8000);
        assert!(!is_napot(plain.0), "marker bits without N are an address");
    }

    #[test]
    fn only_the_size_marker_with_n_is_a_run() {
        let w = make_64k(RUN, RW);
        assert!(is_napot(w));
        assert!(!is_napot(w & !PTE_N), "no N: a plain page");
        // N with another PPN[3:0] is a reserved encoding on this size (the
        // hart faults on it); it is not a run to break either.
        assert!(!is_napot((w & !(0xF << 10)) | (0b0100 << 10)));
        assert!(!is_napot(0));
    }

    #[test]
    fn a_break_leaves_plain_words_naming_the_frames_the_run_did() {
        let flags = RW | PteFlags::PBMT_NC;
        let w = make_64k(RUN, flags);
        for i in 0..NAPOT_PAGES {
            let m = member(w, i);
            assert_eq!(m, Pte::new(RUN + i * 4096, flags).0, "member {i}: the word a lone page would hold");
            assert!(!is_napot(m) && m & PTE_N == 0, "no hint left");
            assert_eq!(Pte(m).phys_addr(), RUN + i * 4096);
            assert!(Pte(m).flags().contains(PteFlags::PBMT_NC), "the memory type is carried");
        }
        // Not a run: unchanged.
        let lone = Pte::new(RUN, RW).0;
        assert_eq!(member(lone, 3), lone);
    }

    #[test]
    fn select_is_the_policy_and_the_device_tree() {
        assert!(!select(true, false), "the DT lacks it");
        assert!(!on());
        assert!(!select(false, true), "Kconfig says never");
        assert!(!on());
        assert!(select(true, true));
        assert!(on());
        select(false, false);
    }
}

mod a64 {
    use crate::aarch64_mmu::*;
    use azos_arch_api::{MmuError, PagePerms};

    const RUN: usize = 0x4001_0000;

    #[test]
    fn the_run_per_granule_is_what_the_architecture_says() {
        // Arm ARM D8.6: 16 level-3 pages at 4 KiB, 128 at 16 KiB, 32 at 64 KiB.
        assert_eq!(GRANULE_4K.contig_pages(), 16);
        assert_eq!(GRANULE_16K.contig_pages(), 128);
        assert_eq!(GRANULE_64K.contig_pages(), 32);
        assert_eq!(GRANULE_4K.contig_size(), 64 * 1024);
        assert_eq!(GRANULE_16K.contig_size(), 2 * 1024 * 1024);
        assert_eq!(GRANULE_64K.contig_size(), 2 * 1024 * 1024);
        for g in [GRANULE_4K, GRANULE_16K, GRANULE_64K] {
            assert!(g.contig_pages().is_power_of_two());
            assert_eq!(g.entries() % g.contig_pages(), 0, "a run stays inside one level-3 table");
            assert!(g.contig_pages() <= azos_arch_api::contig::MAX_RUN_PAGES);
        }
        assert_eq!(CONT_PAGES, GRANULE.contig_pages());
        assert_eq!(CONT_SIZE, CONT_PAGES * PAGE_SIZE);
    }

    #[test]
    fn a_member_is_its_own_page_plus_bit_52() {
        let p = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
        for i in 0..CONT_PAGES {
            let w = make_contig_leaf(RUN, i, p).unwrap();
            let lone = make_leaf(RUN + i * PAGE_SIZE, p, 0).unwrap();
            assert_eq!(w, lone | (1 << 52), "member {i}");
            assert!(is_contig(w) && !is_contig(lone));
            // Bit 52 is outside the output address.
            assert_eq!(phys_addr(w), RUN + i * PAGE_SIZE);
            assert_eq!(clear_contig(w), lone);
            assert_eq!(perms_of(w), perms_of(lone));
        }
    }

    #[test]
    fn a_run_must_start_on_its_size_and_have_a_member_index() {
        let p = PagePerms::USER_RW;
        assert_eq!(make_contig_leaf(RUN + PAGE_SIZE, 0, p), Err(MmuError::NotAligned));
        assert_eq!(make_contig_leaf(RUN, CONT_PAGES, p), Err(MmuError::NotAligned));
        assert!(make_contig_leaf(RUN, CONT_PAGES - 1, p).is_ok());
        // An unrepresentable permission is refused, as for any leaf.
        let no_read = PagePerms { read: false, ..p };
        assert!(make_contig_leaf(RUN, 0, no_read).is_err());
    }

    #[test]
    fn a_dropped_hint_is_idempotent_and_leaves_an_invalid_word_alone() {
        let w = make_contig_leaf(RUN, 5, PagePerms::USER_RO).unwrap();
        assert_eq!(clear_contig(clear_contig(w)), clear_contig(w));
        assert!(!is_contig(0));
        assert!(!is_contig(1 << 52), "the hint on an invalid word is nothing");
    }
}

/// The break before a per-page change, both ISAs, with the member encoders
/// `vmm::break_contig_run` applies to every slot of the run (the run is always
/// broken whole, whatever the range that reached it): each slot rewritten as
/// a plain word, then the page goes. What is left must be plain leaves for the
/// right frames, the page gone, no word with a hint.
mod partial_unmap {
    use super::contig::MAX_RUN_PAGES;
    use super::napot;
    use crate::aarch64_mmu as a64;
    use crate::mmu::{Pte, PteFlags};
    use azos_arch_api::PagePerms;

    const PAGE: usize = 4096;

    /// The sixteen words of a 64 KiB run at `pa` on each ISA, and the break.
    fn rv_run(pa: usize) -> ([u64; 16], fn(u64, usize) -> u64) {
        let f = PteFlags::VALID | PteFlags::READ | PteFlags::USER | PteFlags::ACCESSED;
        ([napot::make_64k(pa, f); 16], napot::member)
    }

    fn a64_run(pa: usize) -> ([u64; 16], fn(u64, usize) -> u64) {
        let p = PagePerms { accessed: true, ..PagePerms::USER_RO };
        let mut w = [0u64; 16];
        for (i, s) in w.iter_mut().enumerate() {
            *s = a64::make_contig_leaf(pa, i, p).unwrap();
        }
        (w, |w, _| a64::clear_contig(w))
    }

    #[test]
    fn one_page_taken_from_a_run_leaves_the_rest_plain_and_mapped() {
        if a64::CONT_PAGES != 16 {
            return; // the 4 KiB granule's 64 KiB run is what both ISAs share
        }
        let pa = 0x8004_0000usize;
        let hint = |w: u64, rv: bool| if rv { napot::is_napot(w) } else { a64::is_contig(w) };
        for (rv, (words, brk)) in [(true, rv_run(pa)), (false, a64_run(pa))] {
            for victim in [0usize, 7, 15] {
                let mut slots = words;
                for (k, s) in slots.iter_mut().enumerate() {
                    *s = brk(*s, k);
                }
                slots[victim] = 0;
                for (k, &s) in slots.iter().enumerate() {
                    if k == victim {
                        assert_eq!(s, 0);
                        continue;
                    }
                    assert!(!hint(s, rv), "rv={rv} victim={victim} slot {k}: hint still set");
                    let frame = if rv { Pte(s).phys_addr() } else { a64::phys_addr(s) };
                    assert_eq!(frame, pa + k * PAGE, "rv={rv} slot {k}: the frame the run named");
                }
            }
        }
    }

    #[test]
    fn the_largest_run_any_isa_writes_fits_the_scratch_of_a_break() {
        assert!(a64::GRANULE_16K.contig_pages() <= MAX_RUN_PAGES);
    }
}

/// x86_64: a 4 KiB leaf has no neighbour hint; its next size is the 2 MiB
/// leaf one level up, which is `MEGA_SIZE`'s business (locked rows, promoted
/// blocks), not a run of level-0 leaves. The trait default says 0 and
/// `map_contig_range` maps page by page.
mod x86_none {
    use azos_arch_api::contig::{is_run, step_pages};

    #[test]
    fn zero_pages_means_no_run_whatever_the_alignment() {
        let phys = [0x10_0000usize, 0x10_1000, 0x10_2000, 0x10_3000];
        assert!(!is_run(4096, 0, 0x4000_0000, &phys));
        assert_eq!(step_pages(4096, 0, 0x4000_0000, &phys), 1);
        assert_eq!(step_pages(4096, 1, 0x4000_0000, &phys), 1, "a run of one page is a page");
    }
}

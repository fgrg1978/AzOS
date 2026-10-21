// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! FEAT_TLBIRANGE (Kconfig `A64_TLBIRANGE`): the pure half. `tlb_shootdown`
//! (`api_impl.rs`) asks [`use_range`] whether a run of pages takes the range
//! form, walks [`Plan`] for the operations that cover it, and builds each
//! operand with [`operand`]; no instruction is here, so the host tests
//! (`tests/host/arch-tests`) run all of it.
//!
//! `TLBI RVAE1IS` / `RVAAE1IS` invalidate `(NUM + 1) * 2^(5 * SCALE + 1)`
//! translation-granule pages from a base address: operand `[63:48]` ASID,
//! `[47:46]` TG, `[45:44]` SCALE, `[43:39]` NUM, `[38:37]` TTL (0: no
//! hint), `[36:0]` BaseADDR (the address shifted down by the granule).
//! Any number of pages below 2^21 is covered exactly by at most one
//! single-page operation (an odd count) and one range per scale, the
//! decomposition Linux's `__flush_tlb_range_op` uses.

use azos_arch_api::isa::{aarch64 as policy, ExtPolicy};
use core::sync::atomic::{AtomicBool, Ordering};

/// The probe's verdict (`probe` only; `n`/`require` never read it).
static ON: AtomicBool = AtomicBool::new(false);

/// The range form is in use on this boot: a constant under `n`/`require`.
#[inline(always)]
pub fn range_on() -> bool {
    match policy::TLBIRANGE {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => ON.load(Ordering::Relaxed),
    }
}

/// Boot, the boot CPU, before the secondaries: `present` is the ID
/// register's answer. Returns what the shootdown uses.
pub fn select(present: bool) -> bool {
    ON.store(policy::TLBIRANGE.gate(present), Ordering::Relaxed);
    range_on()
}

/// Pages a range shootdown covers: strictly below 2^21 (SCALE 3, NUM 31).
pub const MAX_RANGE_PAGES: usize = 1 << 21;

/// Does a shootdown of `pages` granule pages use the range form? `hw`: the
/// probe kept FEAT_TLBIRANGE. Below `min_pages` the per-page form issues
/// as few operations; at or above `MAX_RANGE_PAGES` one operation cannot
/// name the count (per-page, as before).
pub const fn use_range(hw: bool, pages: usize, min_pages: usize) -> bool {
    hw && pages >= min_pages && pages >= 2 && pages < MAX_RANGE_PAGES
}

/// One invalidation of a [`Plan`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// One page (`TLBI VAE1IS` / `VAAE1IS`).
    Page,
    /// `(num + 1) << (5 * scale + 1)` pages (`TLBI RVAE1IS` / `RVAAE1IS`).
    Range { scale: u8, num: u8 },
}

impl Step {
    /// Pages this step invalidates.
    pub const fn pages(self) -> usize {
        match self {
            Step::Page => 1,
            Step::Range { scale, num } => (num as usize + 1) << (5 * scale as usize + 1),
        }
    }
}

/// The steps covering `pages` pages from a base, in address order.
#[derive(Clone, Copy, Debug)]
pub struct Plan {
    pages: usize,
}

impl Plan {
    /// `pages` must be below [`MAX_RANGE_PAGES`] (see [`use_range`]).
    pub const fn new(pages: usize) -> Self {
        Plan { pages }
    }
}

impl Iterator for Plan {
    type Item = Step;

    fn next(&mut self) -> Option<Step> {
        if self.pages == 0 {
            return None;
        }
        // A range covers a multiple of two pages: an odd count peels one off.
        if self.pages & 1 == 1 {
            self.pages -= 1;
            return Some(Step::Page);
        }
        let mut scale = 0u8;
        while scale <= 3 {
            let n = (self.pages >> (5 * scale as usize + 1)) & 31;
            if n != 0 {
                // Canary (`a64-tlbi-canary`): NUM one too large.
                let num = if cfg!(feature = "a64-tlbi-canary") { n } else { n - 1 } as u8;
                let step = Step::Range { scale, num };
                // Saturating: under the canary the step overshoots.
                self.pages = self.pages.saturating_sub(step.pages());
                return Some(step);
            }
            scale += 1;
        }
        // Unreachable below MAX_RANGE_PAGES; end rather than loop.
        self.pages = 0;
        None
    }
}

/// The translation granule field of a range operand (`[47:46]`) for a page
/// of `1 << page_shift` bytes: 4 KiB 1, 16 KiB 2, 64 KiB 3.
pub const fn granule_tg(page_shift: u32) -> u64 {
    ((page_shift - 10) / 2) as u64
}

/// The `RVAE1IS` operand: `asid_tag` is the ASID already shifted to `[63:48]`
/// (0 for `RVAAE1IS`, whose ASID field is RES0), `va` the first page's
/// address.
pub const fn operand(asid_tag: u64, va: usize, page_shift: u32, scale: u8, num: u8) -> u64 {
    asid_tag
        | granule_tg(page_shift) << 46
        | (scale as u64 & 3) << 44
        | (num as u64 & 31) << 39
        | ((va as u64) >> page_shift) & ((1 << 37) - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every count below the limit is covered exactly, in at most five
    /// steps (one page and four scales), and no step is empty.
    #[test]
    fn a_plan_covers_every_count_exactly() {
        let check = |pages: usize| {
            let mut covered = 0usize;
            let mut steps = 0usize;
            for s in Plan::new(pages) {
                assert!(s.pages() >= 1);
                covered += s.pages();
                steps += 1;
            }
            assert_eq!(covered, pages, "pages={pages}");
            assert!(steps <= 5, "pages={pages} took {steps} steps");
        };
        for pages in 0..70_000 {
            check(pages);
        }
        for pages in [(1 << 21) - 1, (1 << 20) + 2, (31 << 16) + (31 << 11) + (31 << 6) + (31 << 1) + 1, 1 << 16, 1 << 11] {
            check(pages);
        }
    }

    /// The decomposition's shape: a lone odd page first, ranges after, the
    /// small scales before the large, and NUM never past 31.
    #[test]
    fn a_plan_peels_the_odd_page_then_goes_by_scale() {
        assert!(Plan::new(5).eq([Step::Page, Step::Range { scale: 0, num: 1 }]));
        assert!(Plan::new(2).eq([Step::Range { scale: 0, num: 0 }]));
        assert!(Plan::new(64).eq([Step::Range { scale: 1, num: 0 }]), "64 = (0+1) << 6");
        assert!(Plan::new(64 + 2).eq([Step::Range { scale: 0, num: 0 }, Step::Range { scale: 1, num: 0 }]));
        assert!(Plan::new((1 << 21) - 2).all(|s| matches!(s, Step::Range { num, .. } if num <= 31)));
        assert_eq!(Plan::new(0).count(), 0);
    }

    #[test]
    fn the_operand_puts_each_field_in_its_own_bits() {
        let asid = 0xABCDu64 << 48;
        // 4 KiB granule, scale 2, num 17, base = page 0x1234_5678.
        let op = operand(asid, 0x1234_5678 << 12, 12, 2, 17);
        assert_eq!(op >> 48, 0xABCD);
        assert_eq!((op >> 46) & 3, 1, "TG: 4 KiB");
        assert_eq!((op >> 44) & 3, 2, "SCALE");
        assert_eq!((op >> 39) & 31, 17, "NUM");
        assert_eq!((op >> 37) & 3, 0, "TTL: no hint");
        assert_eq!(op & ((1 << 37) - 1), 0x1234_5678, "BaseADDR");
        assert_eq!(granule_tg(12), 1);
        assert_eq!(granule_tg(14), 2);
        assert_eq!(granule_tg(16), 3);
        // 64 KiB granule: BaseADDR is the address >> 16.
        assert_eq!(operand(0, 0x7_0000, 16, 0, 0) & ((1 << 37) - 1), 7);
        // A kernel (TTBR1) address: bits 63:49 are dropped, 48:12 kept.
        let kva = 0xFFFF_8000_0020_3000usize;
        let op = operand(0, kva, 12, 0, 3);
        assert_eq!(op & ((1 << 37) - 1), (kva as u64 >> 12) & ((1 << 37) - 1));
        assert_eq!(op >> 46, 1, "no ASID, no stray bits above TG");
        // Oversized scale/num are masked, not smeared into a neighbour.
        let op = operand(0, 0, 12, 7, 63);
        assert_eq!((op >> 44) & 3, 3);
        assert_eq!((op >> 39) & 31, 31);
        assert_eq!(op >> 48, 0);
    }

    #[test]
    fn select_follows_the_probe_under_probe_policy() {
        if !matches!(policy::TLBIRANGE, ExtPolicy::Probe) {
            return;
        }
        assert!(select(true) && range_on());
        assert!(!select(false) && !range_on());
    }

    #[test]
    fn the_range_form_is_for_hardware_that_has_it_and_runs_of_min_pages() {
        assert!(use_range(true, 4, 4));
        assert!(!use_range(true, 3, 4), "below the minimum stays per-page");
        assert!(!use_range(false, 4096, 4), "no FEAT_TLBIRANGE, no range form");
        assert!(!use_range(true, MAX_RANGE_PAGES, 4), "one operation cannot name 2^21 pages");
        assert!(use_range(true, MAX_RANGE_PAGES - 1, 4));
        assert!(!use_range(true, 1, 1), "a single page is never a range");
        assert!(!use_range(true, 0, 0));
    }
}

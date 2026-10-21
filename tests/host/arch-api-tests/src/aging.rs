// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Accessed-bit seam (`Mmu::harvest_accessed`, `Mmu::resolve_accessed_fault`,
//! `azos_arch_api::aging`): the one walker all three ISAs share, driven over
//! real tables in host memory through the test stub's made-up word layout
//! (A = bit 4, D = bit 5, run member = bit 6). The per-ISA bit positions have
//! their rows next to each encoding (`tests/host/arch-tests`, `aarch64_encoding_tests`).
//!
//! Canaries (by hand; each goes red where the row says, discriminates):
//! * `rmw_unit` touching only the faulting member of a run:
//!   `a_run_is_read_and_cleared_whole`, `resolve_sets_every_member_of_a_run`.
//! * `rmw_leaf` without the user-leaf test: `kernel_leaves_read_as_idle`,
//!   `resolve_leaves_an_empty_slot_empty`.
//! * `harvest` stepping one page instead of the leaf's span:
//!   `a_block_reports_every_page_it_covers`, `a_run_is_read_and_cleared_whole`.
//! `d_survives_the_clear` pins that the clear writes the A bit off and nothing
//! else; the lost-update race a plain store would have needs two threads
//! and a hardware walker, and is a boot row (open_issues of the front).

use crate::tests::{Stub, AGING_BIT, AGING_FLUSHES, AGING_RUN, STUB_A, STUB_CONTIG, STUB_D};
use azos_arch_api::{Mmu, PagePerms};
use core::sync::atomic::{AtomicU64, Ordering};

const PAGE: usize = 4096;
const L1_SPAN: usize = 2 << 20;

#[repr(align(4096))]
#[allow(dead_code)] // owns the table memory, which is read through raw addresses
struct Page([AtomicU64; 512]);

/// Page tables in host memory. A table's "physical address" is the address of
/// its page, which is what the default `Mmu::table_word` dereferences.
struct Tables {
    pages: Vec<Box<Page>>,
}

impl Tables {
    fn new() -> Self {
        let mut t = Tables { pages: Vec::new() };
        t.table(); // the root
        t
    }

    fn table(&mut self) -> usize {
        let p = Box::new(Page(core::array::from_fn(|_| AtomicU64::new(0))));
        let pa = &*p as *const Page as usize;
        self.pages.push(p);
        pa
    }

    fn root(&self) -> usize {
        &*self.pages[0] as *const Page as usize
    }

    fn slot(pa: usize, idx: usize) -> &'static AtomicU64 {
        // SAFETY: `pa` is a page of `self.pages`, which outlives the test.
        unsafe { &*((pa + idx * 8) as *const AtomicU64) }
    }

    /// Link a level-0 table for the 2 MiB span `span_idx` (index 0..512 of the
    /// level-1 table) and return its address.
    fn l0(&mut self, span_idx: usize) -> usize {
        let root = self.root();
        let l1 = match Stub.pte_is_valid(Self::slot(root, 0).load(Ordering::Relaxed)) {
            true => Stub.pte_phys(Self::slot(root, 0).load(Ordering::Relaxed)),
            false => {
                let l1 = self.table();
                Self::slot(root, 0).store(Stub.pte_make_table(l1), Ordering::Relaxed);
                l1
            }
        };
        let l0 = self.table();
        Self::slot(l1, span_idx).store(Stub.pte_make_table(l0), Ordering::Relaxed);
        l0
    }

    /// The level-1 table (made on the first call).
    fn l1(&mut self) -> usize {
        let root = self.root();
        let w = Self::slot(root, 0).load(Ordering::Relaxed);
        if Stub.pte_is_valid(w) {
            return Stub.pte_phys(w);
        }
        let l1 = self.table();
        Self::slot(root, 0).store(Stub.pte_make_table(l1), Ordering::Relaxed);
        l1
    }
}

fn leaf(user: bool, extra: u64) -> u64 {
    let perms = PagePerms { user, ..PagePerms::USER_RW };
    Stub.pte_make_leaf(0x8000_0000, perms, 0).unwrap() | extra
}

fn aging_on(run: usize) {
    AGING_BIT.with(|c| c.set(STUB_A));
    AGING_RUN.with(|c| c.set(run));
    AGING_FLUSHES.with(|c| c.set(0));
}

#[test]
fn harvest_reports_and_clears_accessed_pages() {
    aging_on(0);
    let mut t = Tables::new();
    let l0 = t.l0(0);
    for i in 0..8 {
        let a = if matches!(i, 1 | 3 | 6) { STUB_A } else { 0 };
        Tables::slot(l0, i).store(leaf(true, a), Ordering::Relaxed);
    }
    assert_eq!(Stub.harvest_accessed(t.root(), 0, 8), 0b0100_1010);
    for i in 0..8 {
        assert_eq!(Tables::slot(l0, i).load(Ordering::Relaxed) & STUB_A, 0, "page {i} keeps A");
    }
    assert_eq!(Stub.harvest_accessed(t.root(), 0, 8), 0, "a second harvest has nothing left");
}

#[test]
fn d_survives_the_clear() {
    aging_on(0);
    let mut t = Tables::new();
    let l0 = t.l0(0);
    Tables::slot(l0, 0).store(leaf(true, STUB_A | STUB_D), Ordering::Relaxed);
    assert_eq!(Stub.harvest_accessed(t.root(), 0, 1), 1);
    assert_eq!(Tables::slot(l0, 0).load(Ordering::Relaxed), leaf(true, STUB_D), "only A went");
}

#[test]
fn kernel_leaves_read_as_idle() {
    aging_on(0);
    let mut t = Tables::new();
    let l0 = t.l0(0);
    Tables::slot(l0, 0).store(leaf(true, STUB_A), Ordering::Relaxed);
    Tables::slot(l0, 1).store(leaf(false, STUB_A), Ordering::Relaxed);
    assert_eq!(Stub.harvest_accessed(t.root(), 0, 4), 0b01);
    assert_ne!(Tables::slot(l0, 1).load(Ordering::Relaxed) & STUB_A, 0, "a kernel leaf is not aged through a user root");
}

#[test]
fn a_hole_is_skipped_by_its_span() {
    aging_on(0);
    let mut t = Tables::new();
    let l0 = t.l0(1); // 0x20_0000..0x40_0000
    Tables::slot(l0, 0).store(leaf(true, STUB_A), Ordering::Relaxed);
    // Four pages of the empty span below, then the first page of the mapped one.
    assert_eq!(Stub.harvest_accessed(t.root(), L1_SPAN - 4 * PAGE, 8), 1 << 4);
    // An address space with nothing in it.
    let empty = Tables::new();
    assert_eq!(Stub.harvest_accessed(empty.root(), 0, 64), 0);
}

#[test]
fn a_block_reports_every_page_it_covers() {
    aging_on(0);
    let mut t = Tables::new();
    let l1 = t.l1();
    let block = Stub.pte_make_leaf(0x8000_0000, PagePerms::USER_RW, 1).unwrap() | STUB_A;
    Tables::slot(l1, 0).store(block, Ordering::Relaxed);
    assert_eq!(Stub.harvest_accessed(t.root(), 3 * PAGE, 4), 0b1111);
    assert_eq!(Tables::slot(l1, 0).load(Ordering::Relaxed) & STUB_A, 0);
    assert_eq!(Stub.harvest_accessed(t.root(), 0, 64), 0);
    Tables::slot(l1, 0).store(block, Ordering::Relaxed);
    assert_eq!(Stub.harvest_accessed(t.root(), 0, 64), u64::MAX, "all sixty-four bits of a full chunk");
}

#[test]
fn a_run_is_read_and_cleared_whole() {
    aging_on(4);
    let mut t = Tables::new();
    let l0 = t.l0(0);
    for i in 0..8 {
        let a = if i == 2 { STUB_A } else { 0 };
        Tables::slot(l0, i).store(leaf(true, STUB_CONTIG | a), Ordering::Relaxed);
    }
    // Only member 2 of the first run was touched: the run reads as touched.
    assert_eq!(Stub.harvest_accessed(t.root(), 0, 8), 0x0F);
    for i in 0..8 {
        assert_eq!(Tables::slot(l0, i).load(Ordering::Relaxed), leaf(true, STUB_CONTIG), "word {i}");
    }
    // A range that starts inside a run still ages the run whole.
    Tables::slot(l0, 1).store(leaf(true, STUB_CONTIG | STUB_A), Ordering::Relaxed);
    assert_eq!(Stub.harvest_accessed(t.root(), 2 * PAGE, 2), 0b11);
    assert_eq!(Tables::slot(l0, 1).load(Ordering::Relaxed) & STUB_A, 0, "the member outside the range is cleared too");
}

#[test]
fn no_accessed_bit_means_no_model() {
    // A model that keeps no A bit (the default): nothing is read or written.
    AGING_BIT.with(|c| c.set(0));
    let mut t = Tables::new();
    let l0 = t.l0(0);
    Tables::slot(l0, 0).store(leaf(true, STUB_A), Ordering::Relaxed);
    assert_eq!(Stub.harvest_accessed(t.root(), 0, 1), 0);
    assert_ne!(Tables::slot(l0, 0).load(Ordering::Relaxed) & STUB_A, 0);
    assert!(!Stub.resolve_accessed_fault(t.root(), 0));
}

#[test]
fn resolve_sets_a_once_and_flushes_the_page() {
    aging_on(0);
    let mut t = Tables::new();
    let l0 = t.l0(0);
    Tables::slot(l0, 3).store(leaf(true, 0), Ordering::Relaxed);
    assert!(Stub.resolve_accessed_fault(t.root(), 3 * PAGE));
    assert_eq!(Tables::slot(l0, 3).load(Ordering::Relaxed), leaf(true, STUB_A));
    assert_eq!(AGING_FLUSHES.with(|c| c.get()), 1);
    // The fault was an A fault: with A set, a fault on the same page is not.
    assert!(!Stub.resolve_accessed_fault(t.root(), 3 * PAGE));
    assert_eq!(AGING_FLUSHES.with(|c| c.get()), 1, "nothing changed, nothing flushed");
}

#[test]
fn resolve_leaves_an_empty_slot_empty() {
    aging_on(0);
    let mut t = Tables::new();
    let l0 = t.l0(0);
    assert!(!Stub.resolve_accessed_fault(t.root(), 5 * PAGE));
    assert_eq!(Tables::slot(l0, 5).load(Ordering::Relaxed), 0, "no stray A bit in an empty slot");
    assert!(!Stub.resolve_accessed_fault(t.root(), 3 * L1_SPAN), "no table at all");
    Tables::slot(l0, 6).store(leaf(false, 0), Ordering::Relaxed);
    assert!(!Stub.resolve_accessed_fault(t.root(), 6 * PAGE), "a kernel leaf is not resolved through a user fault");
    assert_eq!(Tables::slot(l0, 6).load(Ordering::Relaxed), leaf(false, 0));
}

#[test]
fn resolve_sets_every_member_of_a_run() {
    aging_on(4);
    let mut t = Tables::new();
    let l0 = t.l0(0);
    for i in 0..4 {
        Tables::slot(l0, i).store(leaf(true, STUB_CONTIG), Ordering::Relaxed);
    }
    assert!(Stub.resolve_accessed_fault(t.root(), 2 * PAGE));
    for i in 0..4 {
        assert_eq!(Tables::slot(l0, i).load(Ordering::Relaxed), leaf(true, STUB_CONTIG | STUB_A), "member {i}");
    }
}

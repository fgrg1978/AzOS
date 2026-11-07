// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The page-table funnel (crates/core/mm/src/pt.rs) and the kernel-half pool
//! behind it (ptpool.rs, feature `pt-pool`) and the write window that guards it
//! (ptprot.rs, feature `pt-protection`).
//!
//! WHY. Every stage-1 word the kernel writes goes through one of three
//! functions, so the monitor that makes the kernel half's tables read-only can
//! take over from them alone. A word of the pool that is stored directly after
//! the lock faults at stage 2 (the kernel stops); a word outside it that is sent
//! to the monitor is refused (it is not the monitor's); a refused race loop that
//! gives up loses a table entry. The plain functions are the stores they replace.

use super::pt::{pt_cas, pt_set, pt_store};
use core::sync::atomic::{AtomicU64, Ordering};

#[test]
fn the_plain_funnel_is_the_store_and_the_swap() {
    let w = AtomicU64::new(0);
    pt_store(&w, 7, Ordering::Release);
    assert_eq!(w.load(Ordering::Acquire), 7);
    assert_eq!(pt_cas(&w, 7, 9), Ok(7));
    assert_eq!(pt_cas(&w, 7, 11), Err(9));
    // SAFETY: an aligned, live word.
    unsafe { pt_set(&w as *const AtomicU64 as *mut u64, 13) };
    assert_eq!(w.load(Ordering::Acquire), 13);
}

#[cfg(feature = "pt-pool")]
mod pool {
    use super::*;
    use crate::ptpool;
    use azos_arch_api::PAGE_SIZE;
    use std::sync::Mutex;

    /// (entry pa, expected, new, level) of every word the hook was asked for.
    static CALLS: Mutex<Vec<(usize, u64, u64, usize)>> = Mutex::new(Vec::new());
    /// Words the hook answers `Err` to before it takes one (a lost race).
    static LOSE: Mutex<Vec<u64>> = Mutex::new(Vec::new());

    fn hook(pa: usize, expected: u64, new: u64, level: usize) -> Result<(), u64> {
        CALLS.lock().unwrap().push((pa, expected, new, level));
        match LOSE.lock().unwrap().pop() {
            Some(cur) => Err(cur),
            None => Ok(()),
        }
    }

    fn calls() -> Vec<(usize, u64, u64, usize)> {
        std::mem::take(&mut *CALLS.lock().unwrap())
    }

    #[test]
    fn the_pool_is_sized_from_the_ram_the_stack_window_and_the_margin() {
        let (gib, entries) = (1usize << 30, PAGE_SIZE / 8);
        // The root, a level-1 table per GiB (and one for the misalignment), then the window and the margin.
        assert_eq!(ptpool::pages_for(gib, 3, entries, 10, 64), Some(1 + 2 + 10 + 64));
        assert_eq!(ptpool::pages_for(64 * gib, 3, entries, 10, 64), Some(1 + 65 + 10 + 64));
        // A fourth level adds a table per span of the level above.
        assert_eq!(ptpool::pages_for(gib, 4, entries, 10, 64), Some(1 + 2 + 2 + 10 + 64));
        // More than the bound is a refusal, not a smaller pool.
        assert_eq!(ptpool::pages_for(1024 * 1024 * gib, 3, entries, 10, 64), None);
    }

    /// One scenario, in order: the pool is global state.
    #[test]
    fn words_in_the_armed_pool_go_to_the_monitor_and_nothing_else_does() {
        let layout = std::alloc::Layout::from_size_align(ptpool::MAX_PAGES * PAGE_SIZE, PAGE_SIZE).unwrap();
        // SAFETY: a zeroed allocation of the pool's size, kept for the process.
        let base = unsafe { std::alloc::alloc_zeroed(layout) } as usize;
        ptpool::init(crate::addr::PhysAddr::new(base), ptpool::MAX_PAGES);
        ptpool::set_writer_hook(hook);

        let root = ptpool::take(2).unwrap();
        let mid = ptpool::take(1).unwrap();
        assert_eq!((root.as_usize(), mid.as_usize()), (base, base + PAGE_SIZE));
        assert!(ptpool::contains(mid) && !ptpool::contains(crate::addr::PhysAddr::new(base + ptpool::MAX_PAGES * PAGE_SIZE)));
        let slot = unsafe { &*((base + PAGE_SIZE + 8) as *const AtomicU64) };

        // Before the lock a pool word is an ordinary word.
        pt_store(slot, 5, Ordering::Release);
        assert_eq!(slot.load(Ordering::Acquire), 5);
        assert!(calls().is_empty());

        ptpool::arm();
        let outside = AtomicU64::new(0);
        pt_store(&outside, 3, Ordering::Release);
        assert_eq!(pt_cas(&outside, 3, 4), Ok(3));
        assert!(calls().is_empty(), "a word outside the pool went to the monitor");

        // A compare-and-swap is one call, with the level of the page it lies in.
        assert_eq!(pt_cas(slot, 5, 6), Ok(5));
        assert_eq!(calls(), vec![(base + PAGE_SIZE + 8, 5, 6, 1)]);
        assert_eq!(slot.load(Ordering::Acquire), 5, "the funnel stored a pool word itself");

        // A lost race comes back as the word found, not as a store.
        LOSE.lock().unwrap().push(8);
        assert_eq!(pt_cas(slot, 5, 6), Err(8));
        calls();

        // A store is a swap from the word read, repeated until it takes.
        LOSE.lock().unwrap().push(9);
        pt_store(slot, 10, Ordering::Release);
        let c = calls();
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].2, c[1].1, c[1].2), (10, 9, 10));

        // A page given back serves the next table of its level, and only that level.
        let spare = ptpool::take(0).unwrap();
        ptpool::give_back(spare);
        assert_eq!(ptpool::take(1).unwrap().as_usize(), base + 2 * PAGE_SIZE + PAGE_SIZE);
        assert_eq!(ptpool::take(0).unwrap(), spare);

        // A page of the pool never reaches the page allocator.
        assert_eq!(crate::pmm::free_page(root), Err(azos_common::error::KernelError::PermissionDenied));

        // Nor does a run or a block that overlaps it, from any side.
        let pfn = crate::frame::Pfn::from_phys(base);
        assert_eq!(crate::pmm::free(pfn, 0), Err(azos_common::error::KernelError::PermissionDenied));
        assert_eq!(crate::pmm::free(pfn, 3), Err(azos_common::error::KernelError::PermissionDenied));
        assert_eq!(crate::pmm::free_run(crate::addr::PhysAddr::new(base), 1), Err(azos_common::error::KernelError::PermissionDenied));
        assert_eq!(crate::pmm::free_run(crate::addr::PhysAddr::new(base - 4 * PAGE_SIZE), 5), Err(azos_common::error::KernelError::PermissionDenied));
        assert_eq!(crate::pmm::free_run(crate::addr::PhysAddr::new(base + (ptpool::MAX_PAGES - 1) * PAGE_SIZE), 4), Err(azos_common::error::KernelError::PermissionDenied));
        assert!(!ptpool::overlaps(base + ptpool::MAX_PAGES * PAGE_SIZE, PAGE_SIZE) && !ptpool::overlaps(base - PAGE_SIZE, PAGE_SIZE));

        // The pool is finite.
        while ptpool::take(0).is_ok() {}
        assert_eq!(ptpool::take(0), Err(azos_common::error::KernelError::OutOfMemory));
        assert_eq!(ptpool::extent().1, ptpool::MAX_PAGES);
    }
}

#[cfg(feature = "pt-protection")]
mod window {
    use super::*;
    use crate::ptprot::{write, Window};
    use std::cell::RefCell;

    /// A window over one word that checks, from inside `open` and `close`, where the store is.
    struct Probe<'a> {
        slot: &'a AtomicU64,
        before: u64,
        after: u64,
        token: u64,
        log: RefCell<Vec<(&'static str, u64)>>,
    }

    impl Window for Probe<'_> {
        fn open(&self) -> u64 {
            assert_eq!(self.slot.load(Ordering::Acquire), self.before, "the store came before the window opened");
            self.log.borrow_mut().push(("open", 0));
            self.token
        }
        fn close(&self, saved: u64) {
            assert_eq!(self.slot.load(Ordering::Acquire), self.after, "the window closed before the store");
            self.log.borrow_mut().push(("close", saved));
        }
    }

    /// The store is made between an open and a close, and the close gets back
    /// what the open returned.
    /// Canary: `--features ptprot-store-outside-canary` makes the store after the
    /// close, and `close` sees the old word.
    #[test]
    fn the_store_is_made_inside_the_window_and_the_token_comes_back() {
        let slot = AtomicU64::new(5);
        let w = Probe { slot: &slot, before: 5, after: 6, token: 0xA5, log: RefCell::new(Vec::new()) };
        assert_eq!(write(&w, &slot, 5, 6), Ok(5));
        assert_eq!(slot.load(Ordering::Acquire), 6);
        assert_eq!(*w.log.borrow(), vec![("open", 0), ("close", 0xA5)]);
    }

    /// A lost race is the word found, the word is untouched, and the window is closed all the same.
    #[test]
    fn a_lost_race_closes_the_window_and_reports_the_word_found() {
        let slot = AtomicU64::new(9);
        let w = Probe { slot: &slot, before: 9, after: 9, token: 3, log: RefCell::new(Vec::new()) };
        assert_eq!(write(&w, &slot, 5, 6), Err(9));
        assert_eq!(slot.load(Ordering::Acquire), 9);
        assert_eq!(*w.log.borrow(), vec![("open", 0), ("close", 3)]);
    }

    /// A window inside a window closes to the outer one's state.
    #[test]
    fn windows_nest_and_each_restores_what_it_found() {
        let (a, b) = (AtomicU64::new(1), AtomicU64::new(1));
        let outer = Probe { slot: &a, before: 1, after: 2, token: 10, log: RefCell::new(Vec::new()) };
        let inner = Probe { slot: &b, before: 1, after: 2, token: 20, log: RefCell::new(Vec::new()) };
        let saved = outer.open();
        assert_eq!(write(&inner, &b, 1, 2), Ok(1));
        assert_eq!(a.compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire), Ok(1));
        outer.close(saved);
        assert_eq!(*inner.log.borrow(), vec![("open", 0), ("close", 20)]);
        assert_eq!(*outer.log.borrow(), vec![("open", 0), ("close", 10)]);
    }
}

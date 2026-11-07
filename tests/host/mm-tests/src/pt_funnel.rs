// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The page-table funnel (crates/core/mm/src/pt.rs) and the kernel-half pool
//! behind it (ptpool.rs, feature `hyp-monitor`).
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

#[cfg(feature = "hyp-monitor")]
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

    /// One scenario, in order: the pool is global state.
    #[test]
    fn words_in_the_armed_pool_go_to_the_monitor_and_nothing_else_does() {
        let layout = std::alloc::Layout::from_size_align(ptpool::PAGES * PAGE_SIZE, PAGE_SIZE).unwrap();
        // SAFETY: a zeroed allocation of the pool's size, kept for the process.
        let base = unsafe { std::alloc::alloc_zeroed(layout) } as usize;
        ptpool::init(crate::addr::PhysAddr::new(base));
        ptpool::set_monitor_hook(hook);

        let root = ptpool::take(2).unwrap();
        let mid = ptpool::take(1).unwrap();
        assert_eq!((root.as_usize(), mid.as_usize()), (base, base + PAGE_SIZE));
        assert!(ptpool::contains(mid) && !ptpool::contains(crate::addr::PhysAddr::new(base + ptpool::PAGES * PAGE_SIZE)));
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

        // The pool is finite.
        while ptpool::take(0).is_ok() {}
        assert_eq!(ptpool::take(0), Err(azos_common::error::KernelError::OutOfMemory));
        assert_eq!(ptpool::extent().1, ptpool::PAGES);
    }
}

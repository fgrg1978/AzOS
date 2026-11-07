// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PT_PROTECTION: the kernel half's page-table pool, write-protected from the
//! kernel itself (feature `pt-protection`).
//!
//! The pool's pages carry the ISA's supervisor protection key and every CPU
//! denies writes to that key. The pool's writer ([`crate::ptpool`]) is the one
//! place that lifts the denial: [`write`] opens a window, makes the
//! compare-and-swap and closes it, so a stray kernel store anywhere else
//! faults. `tools/lint/pt_writes_lint.py` already holds every page-table word
//! to [`crate::pt`]; this makes the hardware hold the kernel to it.
//!
//! [`Window`] is what an ISA gives (`ArchPlatform::pt_window_*`); the writer is
//! generic over it so the order open, store, close is a host row.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A write window on the pool's pages: open lifts the write denial and returns
/// what close restores.
pub trait Window {
    fn open(&self) -> u64;
    fn close(&self, saved: u64);
}

/// `expected` to `new` in `slot`, the denial lifted for that one compare-and-swap.
/// The result is the word found, as `AtomicU64::compare_exchange`'s.
#[inline(always)]
pub fn write<W: Window>(w: &W, slot: &AtomicU64, expected: u64, new: u64) -> Result<u64, u64> {
    let saved = w.open();
    // Canary (`ptprot-store-outside-canary`): the store is made once the window is closed.
    if cfg!(feature = "ptprot-store-outside-canary") {
        w.close(saved);
        return slot.compare_exchange(expected, new, Ordering::AcqRel, Ordering::Acquire);
    }
    let r = slot.compare_exchange(expected, new, Ordering::AcqRel, Ordering::Acquire);
    w.close(saved);
    r
}

/// What the boot did with the pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Engaged {
    /// The pool is tagged and this CPU denies writes to it: `pages` of the
    /// run are in use.
    Locked { pages: usize },
    /// The CPU has no key or Kconfig says n: the pool is in use and writable.
    NoKey,
    /// The pool's pages could not all be tagged (a block mapping that would
    /// not split): nothing was locked.
    Untaggable,
}

static ENGAGED: AtomicBool = AtomicBool::new(false);

/// Did [`engage`] lock the pool? Every CPU that comes up later runs
/// `ArchPlatform::pt_lock_this_cpu` when it did.
pub fn engaged() -> bool {
    ENGAGED.load(Ordering::Acquire)
}

pub(crate) fn mark_engaged() {
    ENGAGED.store(true, Ordering::Release);
}

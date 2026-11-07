// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PT_PROTECTION: the kernel root's page tables, write-protected from the
//! kernel itself (feature `pt-protection`). A user root keeps its own copies of
//! the kernel's top-level entries in ordinary pages, so a stray store there is
//! not caught; neither is a device's DMA (the IOMMU's job).
//!
//! The pool's pages carry the ISA's supervisor protection key and every CPU
//! denies writes to that key. The pool's writer ([`crate::ptpool`]) is the one
//! place that lifts the denial: [`write`] opens a window, makes the
//! compare-and-swap and closes it, so a stray kernel store anywhere else
//! faults. `tools/lint/pt_writes_lint.py` already holds every page-table word
//! to [`crate::pt`]; this makes the hardware hold the kernel to it.
//!
//! [`Window`] is what lifts the denial for one word: an ISA's key register
//! (`ArchPlatform::pt_window_*`), or, on an ISA without one, the word's page
//! flipped writable in the direct map (Kconfig `PT_PROTECTION_SOFT`). The writer
//! is generic over it so the order open, store, close is a host row.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A write window on the pool word at address `va`: open lifts the write
/// denial and returns what close restores.
pub trait Window {
    fn open(&self, va: usize) -> u64;
    fn close(&self, va: usize, saved: u64);
}

/// `expected` to `new` in `slot`, the denial lifted for that one compare-and-swap.
/// The result is the word found, as `AtomicU64::compare_exchange`'s.
#[inline(always)]
pub fn write<W: Window>(w: &W, slot: &AtomicU64, expected: u64, new: u64) -> Result<u64, u64> {
    let va = slot as *const AtomicU64 as usize;
    let saved = w.open(if cfg!(feature = "ptprot-wrong-word-canary") { 0 } else { va });
    // Canary (`ptprot-store-outside-canary`): the store is made once the window is closed.
    if cfg!(feature = "ptprot-store-outside-canary") {
        w.close(va, saved);
        return slot.compare_exchange(expected, new, Ordering::AcqRel, Ordering::Acquire);
    }
    let r = slot.compare_exchange(expected, new, Ordering::AcqRel, Ordering::Acquire);
    w.close(va, saved);
    r
}

/// What the boot did with the pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Engaged {
    /// The pool is tagged and this CPU denies writes to it: `pages` of the
    /// run are in use.
    Locked { pages: usize },
    /// The pool is read-only in the direct map and a word is written with its
    /// page flipped writable for the one store (no key hardware).
    SoftLocked { pages: usize },
    /// The CPU has no key and the software window is off: the pool is in use and writable.
    NoKey,
    /// The CPU has the key, but denying writes to it did not take on this
    /// CPU: the pool stays unarmed and writable.
    LockFailed,
    /// The pool's pages could not all be tagged (a block mapping that would
    /// not split): nothing was locked.
    Untaggable,
}

static ENGAGED: AtomicBool = AtomicBool::new(false);
static KEYED: AtomicBool = AtomicBool::new(false);

/// Is the pool locked, by a key or by the software window?
pub fn engaged() -> bool {
    ENGAGED.load(Ordering::Acquire)
}

/// Is it locked by the ISA's key? Every CPU that comes up later runs
/// `ArchPlatform::pt_lock_this_cpu` when it is.
pub fn keyed() -> bool {
    KEYED.load(Ordering::Acquire)
}

pub(crate) fn mark_engaged(keyed: bool) {
    KEYED.store(keyed, Ordering::Release);
    ENGAGED.store(true, Ordering::Release);
}

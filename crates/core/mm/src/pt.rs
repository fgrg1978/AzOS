// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The funnel every stage-1 page-table word the kernel changes goes through.
//!
//! One place writes a PTE, so a monitor that protects the kernel half's tables
//! (VIRT_SPLIT, feature `hyp-monitor`) or the kernel itself (PT_PROTECTION,
//! feature `pt-protection`: a write window opened for the one store) has one
//! place to take over: a word in the kernel-half pool ([`crate::ptpool`]) is
//! changed by the pool's writer, any other by the store or swap it always was.
//! With neither feature the check is a constant false and each function is
//! the bare store.
//! `tools/lint/pt_writes_lint.py` fails a page-table write that bypasses it.

use core::sync::atomic::{AtomicU64, Ordering};

/// Compare-and-swap `slot` from `seen` to `new`, like `compare_exchange` with
/// `AcqRel`/`Acquire`: `Err` carries the word found. A writer refusal is not
/// a lost race: the kernel stops (see `ptpool::through_writer`).
#[inline(always)]
pub fn pt_cas(slot: &AtomicU64, seen: u64, new: u64) -> Result<u64, u64> {
    #[cfg(feature = "pt-pool")]
    if let Some(r) = crate::ptpool::route(slot as *const AtomicU64 as usize, seen, new) {
        return r;
    }
    slot.compare_exchange(seen, new, Ordering::AcqRel, Ordering::Acquire)
}

/// Store `word` into `slot` with `order`.
#[inline(always)]
pub fn pt_store(slot: &AtomicU64, word: u64, order: Ordering) {
    #[cfg(feature = "pt-pool")]
    if crate::ptpool::owns(slot as *const AtomicU64 as usize) {
        crate::ptpool::replace(slot, word);
        return;
    }
    slot.store(word, order)
}

/// Volatile store of `word` at the entry `slot` points to.
///
/// # Safety
/// `slot` is an aligned entry of a live table page.
#[inline(always)]
pub unsafe fn pt_set(slot: *mut u64, word: u64) {
    #[cfg(feature = "pt-pool")]
    if crate::ptpool::owns(slot as usize) {
        // SAFETY: as the caller's.
        crate::ptpool::replace(unsafe { &*(slot as *const AtomicU64) }, word);
        return;
    }
    // SAFETY: as the caller's.
    unsafe { core::ptr::write_volatile(slot, word) }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Child module of `scheduler.rs` (pulled in with `#[path]`), moved out of it unchanged.

use super::{reap_one, Reap, MAX_TASKS, SLOT_WORDS};
use core::sync::atomic::{AtomicU64, Ordering};

static PENDING: [AtomicU64; SLOT_WORDS] = [const { AtomicU64::new(0) }; SLOT_WORDS];

#[inline]
pub(super) fn mark(idx: usize) {
    if let Some(w) = PENDING.get(idx / 64) {
        w.fetch_or(1u64 << (idx % 64), Ordering::Release);
    }
}

/// Whether `idx` is marked (census cross-check only).
#[cfg(feature = "ipc-census")]
fn marked(idx: usize) -> bool {
    PENDING.get(idx / 64).is_some_and(|w| w.load(Ordering::Acquire) & (1u64 << (idx % 64)) != 0)
}

/// Whether any slot is still marked (a stamp `reap_one` said to retry).
pub(super) fn any() -> bool {
    PENDING.iter().any(|w| w.load(Ordering::Acquire) != 0)
}

pub(super) fn reap_marked() {
    for (wi, word) in PENDING.iter().enumerate() {
        let mut bits = word.swap(0, Ordering::Acquire);
        while bits != 0 {
            let i = wi * 64 + bits.trailing_zeros() as usize;
            bits &= bits - 1;
            if i >= MAX_TASKS {
                continue;
            }
            // SAFETY: the tick ISR, as for the sweep.
            match unsafe { reap_one(i) } {
                Reap::Again => mark(i),
                Reap::Done => {}
                Reap::Reaped => {
                    #[cfg(feature = "ipc-census")]
                    MARKED_REAPED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    #[cfg(feature = "ipc-census")]
    census_sweep();
}

#[cfg(feature = "ipc-census")]
pub static UNMARKED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ipc-census")]
pub static MARKED_REAPED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ipc-census")]
static PASSES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// What the sweep would still do after the marked pass: a slot it reaps
/// here that carried no mark is a stamp site `note_unsaved_stamp` missed.
#[cfg(feature = "ipc-census")]
fn census_sweep() {
    use crate::task::sched_word::{state_of, WAKE_STAMP};
    let n = PASSES.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if n >= 1024 && n.is_power_of_two() {
        azos_drv_sys::kprintln!(
            "[SCHED] reap-check ticks={} marked_reaped={} unmarked={}",
            n, MARKED_REAPED.load(Ordering::Relaxed), UNMARKED.load(Ordering::Relaxed),
        );
    }
    for i in 0..MAX_TASKS {
        let reapable = unsafe {
            let t = &*core::ptr::addr_of!(super::TASKS[i]);
            let w = t.state_word.load(Ordering::Acquire);
            super::TASK_VALID[i].load(Ordering::Relaxed)
                && w & WAKE_STAMP != 0
                && state_of(w) == super::TaskState::Blocked
        };
        if !reapable || marked(i) {
            continue;
        }
        // SAFETY: the tick ISR.
        match unsafe { reap_one(i) } {
            // Unmarked but not reapable yet: most likely a waker between
            // its stamp CAS and its mark. Leave it to that mark.
            Reap::Again | Reap::Done => {}
            Reap::Reaped => {
                if UNMARKED.fetch_add(1, Ordering::Relaxed) == 0 {
                    azos_drv_sys::kprintln!("[SCHED] REAP_UNMARKED first: slot={}", i);
                }
            }
        }
    }
}

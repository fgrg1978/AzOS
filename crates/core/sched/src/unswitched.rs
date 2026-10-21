// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Child module of `scheduler.rs` (pulled in with `#[path]`), moved out of it unchanged.

use core::sync::atomic::{AtomicU32, Ordering};

/// `block_current` returned **without blocking**: the commit CAS reported
/// a consumed wake stamp.
/// How many times `do_schedule` is ENTERED, and how many times it gets as
/// far as switching. Without these two, zeroed "returned without
/// switching" counters are ambiguous: it may always switch, or it may
/// never be entered at all.
pub static CALLS: AtomicU32 = AtomicU32::new(0);
pub static SWITCHED: AtomicU32 = AtomicU32::new(0);
pub static BLOCK_SKIPPED: AtomicU32 = AtomicU32::new(0);
/// `block_current` committed to `Blocked` and called `do_schedule`, which
/// eventually returned — i.e. the task really did yield the hart and came
/// back.
pub static BLOCK_SLEPT: AtomicU32 = AtomicU32::new(0);

/// Priority-queue path with an empty per-CPU ready queue.
pub static QUEUE_EMPTY_BLOCKED: AtomicU32 = AtomicU32::new(0);
/// Picked ourselves (`next_idx == old_idx`).
pub static SELF_PICK_BLOCKED: AtomicU32 = AtomicU32::new(0);
/// Same three, with the current task still `Running` — the benign case,
/// kept so the ratio is visible rather than assumed.
pub static QUEUE_EMPTY_OK: AtomicU32 = AtomicU32::new(0);
pub static SELF_PICK_OK: AtomicU32 = AtomicU32::new(0);

/// Canary: this module is only compiled when the feature reaches THIS
/// crate. If `kernel/Cargo.toml` stops forwarding
/// `azos_sched/ipc-census`, the counters vanish and `read()` answers
/// zeros for code that does not exist — which already invalidated two
/// measurements in this investigation. `CANARY` is checked by the caller
/// so that failure is loud instead of a convincing row of zeros.
pub static CANARY: u32 = 0xC0FFEE;

/// `(skipped, slept)` — the fundamental fork in `block_current`, which
/// every other counter here is downstream of. Measured last, which was a
/// mistake: two hypotheses died before this one was even instrumented.
/// `(calls, switched)`
pub fn call_split() -> (u32, u32) {
    (CALLS.load(Ordering::Relaxed), SWITCHED.load(Ordering::Relaxed))
}

pub fn block_split() -> (u32, u32) {
    (BLOCK_SKIPPED.load(Ordering::Relaxed), BLOCK_SLEPT.load(Ordering::Relaxed))
}

/// `(q_blk, self_blk, q_ok, self_ok)`
pub fn read() -> (u32, u32, u32, u32) {
    (QUEUE_EMPTY_BLOCKED.load(Ordering::Relaxed),
     SELF_PICK_BLOCKED.load(Ordering::Relaxed),
     QUEUE_EMPTY_OK.load(Ordering::Relaxed),
     SELF_PICK_OK.load(Ordering::Relaxed))
}

#[inline(always)]
pub fn bump(c: &AtomicU32) { c.fetch_add(1, Ordering::Relaxed); }

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Child module of `scheduler.rs` (pulled in with `#[path]`), moved out of it unchanged.

use core::sync::atomic::{AtomicU32, Ordering};

/// `task_yield()` calls refused because a critical section was open.
pub static YIELD_WHILE_ATOMIC: AtomicU32 = AtomicU32::new(0);
/// `block_current()` calls refused because a critical section was open.
/// Any non-zero value names a caller that would sleep holding a spinlock.
pub static BLOCK_WHILE_ATOMIC: AtomicU32 = AtomicU32::new(0);
/// `task_exit_with_code()` calls that had to force the depth to 0.
pub static EXIT_WHILE_ATOMIC: AtomicU32 = AtomicU32::new(0);
/// Context switches reached with depth != 0. **Must stay zero**: every
/// path into `context_switch` is supposed to be gated by one of the checks
/// above. This one is the proof, not the assumption.
pub static SWITCH_WHILE_ATOMIC: AtomicU32 = AtomicU32::new(0);

/// Last `block_current` offender: `(tid, depth, wait-reason discriminant)`.
/// Packed into one word so it can be read without a lock: tid in the low
/// 16 bits, depth in the next 8, reason tag in the top 8.
pub static LAST_BLOCK_OFFENDER: AtomicU32 = AtomicU32::new(0);

/// How many `block_current` refusals still get a console line. After this
/// many the counter keeps rising silently — a hart that is refusing on
/// every IPC must not turn the UART into the bottleneck.
pub const BLOCK_LOG_BUDGET: u32 = 8;

/// Saturating bump: a diagnostic counter that wraps to zero reads as
/// "clean" on a board that is anything but.
#[inline]
pub(crate) fn bump(c: &AtomicU32) {
    let _ = c.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(1))
    });
}

#[inline]
pub(crate) fn record_block_offender(tid: u32, depth: u32, reason_tag: u8) {
    let packed = (tid & 0xFFFF)
        | ((depth.min(0xFF)) << 16)
        | ((reason_tag as u32) << 24);
    LAST_BLOCK_OFFENDER.store(packed, Ordering::Relaxed);
}

/// `(deferred, fired, yield_atomic, block_atomic, exit_atomic,
///   switch_atomic, last_block_offender_packed)`.
///
/// `deferred` and `fired` are read straight from `azos_sync::preempt`,
/// which is the single owner of both. This module briefly kept a shadow
/// `RESCHED_DEFERRED` that nothing read; it is gone. See
/// `azos_sync::preempt::FIRED`'s doc for what the pair does and does
/// NOT tell you about outstanding debt. `underflow`/`hart_oor` stay a separate call
/// (`azos_sync::preempt::audit_counters()`) rather than folding into
/// this tuple: those two are must-stay-zero invariants about this
/// mechanism's own bookkeeping, and `deferred`/`fired` are expected to
/// grow — mixing the two kinds defeats eyeballing either one.
pub fn read() -> (u32, u32, u32, u32, u32, u32, u32) {
    (
        azos_sync::preempt::deferred(),
        azos_sync::preempt::fired(),
        YIELD_WHILE_ATOMIC.load(Ordering::Relaxed),
        BLOCK_WHILE_ATOMIC.load(Ordering::Relaxed),
        EXIT_WHILE_ATOMIC.load(Ordering::Relaxed),
        SWITCH_WHILE_ATOMIC.load(Ordering::Relaxed),
        LAST_BLOCK_OFFENDER.load(Ordering::Relaxed),
    )
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Removal from a per-priority ready ring, in place.
//!
//! Split out of `scheduler::cpu_remove` so it can be tested on the host: the
//! scheduler itself cannot be (static task pool, CSRs, assembly context
//! switch). See `tests/host/sched-wake-tests`.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Remove the first occurrence of `value` from the ring `buf`, which holds
/// `count` entries starting at `head`. The gap is closed by moving every later
/// entry back one slot, so the order of the rest is kept and `head` does not
/// move; the new tail is `(head + new_count) % buf.len()`.
///
/// Returns the new count, or `None` when `value` is not among the entries, in
/// which case nothing was written. A `count` above `buf.len()` is read as
/// `buf.len()`.
///
/// No scratch copy of the ring is made: one would be `buf.len()` words on the
/// caller's stack, which is `MAX_TASKS` words — 32 KiB on the fleet profile,
/// against a 16 KiB kernel stack.
pub fn remove_in_place(buf: &[AtomicUsize], head: usize, count: usize, value: usize) -> Option<usize> {
    let cap = buf.len();
    let n = count.min(cap);
    let pos = (0..n).find(|&j| buf[(head + j) % cap].load(Ordering::Relaxed) == value)?;
    for j in pos..n - 1 {
        let next = buf[(head + j + 1) % cap].load(Ordering::Relaxed);
        buf[(head + j) % cap].store(next, Ordering::Relaxed);
    }
    Some(n - 1)
}

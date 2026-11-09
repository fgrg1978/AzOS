// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A safety verdict with its age: a value an enforcer publishes and a reader
//! takes only while it is fresh. A verdict nobody refreshed is no verdict, and
//! the reader falls back to the safe one, so a stalled enforcer stops what it
//! guards instead of leaving its last word standing.

use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// One published value and the timebase tick it was published at (0: never).
pub struct Stamped {
    value: AtomicI32,
    at: AtomicU64,
}

impl Stamped {
    pub const fn new() -> Self {
        Stamped { value: AtomicI32::new(0), at: AtomicU64::new(0) }
    }

    /// Publish `value` as of tick `now`.
    pub fn publish(&self, value: i32, now: u64) {
        self.value.store(value, Ordering::Release);
        self.at.store(now.max(1), Ordering::Release);
    }

    /// Withdraw the value: readers see none until the next publish.
    pub fn withdraw(&self) {
        self.at.store(0, Ordering::Release);
    }

    /// The value, if it was published at most `max_age` ticks before `now`.
    pub fn fresh(&self, now: u64, max_age: u64) -> Option<i32> {
        let at = self.at.load(Ordering::Acquire);
        (at != 0 && now.saturating_sub(at) <= max_age).then(|| self.value.load(Ordering::Acquire))
    }
}

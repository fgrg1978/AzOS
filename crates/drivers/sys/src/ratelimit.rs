// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Rate limit for a console report: a burst, then silence until the
//! interval ends, then a count of what was not printed. The shape of Linux's
//! `printk_ratelimit` (`___ratelimit`, lib/ratelimit.c).
//!
//! Only the console line is limited. A caller that also records the event
//! (flight recorder, exit statistics) records it every time, before asking.
//!
//! No hardware in it: the caller passes the time and the tick rate, so the
//! arithmetic is host-tested (`tests/host/drivers-tests`).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// `burst` reports per `interval_s` seconds. Shared by every hart: a lost
/// race on the window or the count costs at most one report printed or
/// dropped, never a missed count of suppressed ones.
pub struct RateLimit {
    burst: u32,
    interval_s: u64,
    /// Tick the current window opened at; 0 = no window yet.
    window_start: AtomicU64,
    /// Reports printed in the current window.
    printed: AtomicU32,
    /// Reports suppressed since the last one printed.
    missed: AtomicU32,
}

impl RateLimit {
    /// `burst` reports per `interval_s` seconds.
    pub const fn new(burst: u32, interval_s: u64) -> Self {
        Self {
            burst,
            interval_s,
            window_start: AtomicU64::new(0),
            printed: AtomicU32::new(0),
            missed: AtomicU32::new(0),
        }
    }

    /// One report at tick `now` (`ticks_per_s` ticks a second): `Some(k)`
    /// when it may print, `k` being how many were suppressed before it (the
    /// caller prints that count first when `k > 0`); `None` when it is
    /// suppressed (and counted).
    pub fn check_at(&self, now: u64, ticks_per_s: u64) -> Option<u32> {
        let start = self.window_start.load(Ordering::Relaxed);
        let len = self.interval_s.saturating_mul(ticks_per_s);
        if start == 0 || now.wrapping_sub(start) >= len {
            // A new window. 0 is "no window yet", so a window opened at tick
            // 0 is stamped 1.
            if self
                .window_start
                .compare_exchange(start, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.printed.store(0, Ordering::Relaxed);
            }
        }
        let burst = self.burst;
        if self
            .printed
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| (n < burst).then_some(n + 1))
            .is_ok()
        {
            Some(self.missed.swap(0, Ordering::Relaxed))
        } else {
            let _ = self
                .missed
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |m| Some(m.saturating_add(1)));
            None
        }
    }
}

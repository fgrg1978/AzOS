// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Two decisions of the daemon that are not I/O, kept apart so the host
//! tests can drive them: how often a refused connection is allowed to write a
//! record, and whether the Domain is short of memory.

use core::sync::atomic::{AtomicU8, Ordering};

/// Refused connections are counted and written as one record per window, so a
/// flood of them costs one append per window and not one per connection.
pub struct Refusals {
    /// Refused since the last record.
    pending: u32,
    /// When the last record was written, ms (`None` before the first).
    last: Option<u64>,
    window_ms: u64,
}

impl Refusals {
    pub const fn new(window_ms: u64) -> Self {
        Self { pending: 0, last: None, window_ms }
    }

    /// A connection was refused at `now`. `Some(n)` is the number to record
    /// now (this one and those held back); `None` means it is only counted.
    pub fn refused(&mut self, now: u64) -> Option<u32> {
        self.pending = self.pending.saturating_add(1);
        if self.last.is_some_and(|t| now.saturating_sub(t) < self.window_ms) {
            return None;
        }
        self.last = Some(now);
        Some(core::mem::take(&mut self.pending))
    }

    /// Held back and not yet recorded: written when the connection ends.
    pub fn take_pending(&mut self, now: u64) -> Option<u32> {
        if self.pending == 0 {
            return None;
        }
        self.last = Some(now);
        Some(core::mem::take(&mut self.pending))
    }
}

/// The level of a Domain's pressure event from which memory is short: 1,
/// warning (reclaim is due), and 2, critical (`azos_libsys::pressure_level`).
const PRESSURE_WARNING: u8 = 1;

/// The last level the Domain's pressure port reported, which the allocator asks
/// for where it is about to take a block (`UserAlloc::watch_pressure`). The
/// kernel sends an event on a CHANGE of level, so the level has to be kept
/// between asks: no event since the last one means the level is the same, not
/// that it is back to normal. It is a static the allocator's probe (a plain
/// `fn`) reads, hence the atomic.
pub struct Pressure {
    level: AtomicU8,
}

impl Pressure {
    pub const fn new() -> Self {
        Self { level: AtomicU8::new(0) }
    }

    /// Is memory short now? `next` yields the level of each event the port
    /// holds, oldest first, and `None` when it is drained; the last one is the
    /// level the Domain is at.
    pub fn short(&self, mut next: impl FnMut() -> Option<u8>) -> bool {
        while let Some(level) = next() {
            self.level.store(level, Ordering::Relaxed);
        }
        self.level.load(Ordering::Relaxed) >= PRESSURE_WARNING
    }
}

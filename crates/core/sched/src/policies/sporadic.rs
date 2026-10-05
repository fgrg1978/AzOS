// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Sporadic server scheduler.
//!
//! Used by `Idle` to give very-low-priority opportunistic tasks a
//! capped, replenishing budget. The "sporadic server" idea is
//! Sprunt-Sha-Lehoczky: a server with capacity `C` and replenishment
//! period `T`. While the server has capacity it runs at a configured
//! priority level; consumed capacity is replenished one period after
//! it was used, not at fixed intervals.
//!
//! For AZOS purposes (idle / opportunistic work) we keep this very
//! simple: a single shared bucket per CPU, drained as the idle class
//! consumes time.

use super::{Policy, TaskMeta};

/// Maximum tasks queued in the sporadic server.
pub const SPORADIC_CAPACITY: usize = 8;

/// Sporadic server runqueue.
pub struct Sporadic {
    queue: [Option<TaskMeta>; SPORADIC_CAPACITY],
    len: usize,
    /// Capacity remaining in the current replenishment period, μs.
    remaining_us: u32,
    /// Total capacity (refill amount), μs.
    capacity_us: u32,
}

impl Sporadic {
    /// Default capacity = 1 ms per period; tune via [`set_capacity`].
    pub const fn new() -> Self {
        const DEFAULT_CAPACITY_US: u32 = 1_000;
        Self {
            queue: [None; SPORADIC_CAPACITY],
            len: 0,
            remaining_us: DEFAULT_CAPACITY_US,
            capacity_us: DEFAULT_CAPACITY_US,
        }
    }

    /// Configure the server's per-period capacity in microseconds.
    pub fn set_capacity(&mut self, cap_us: u32) {
        self.capacity_us = cap_us;
        if self.remaining_us > cap_us {
            self.remaining_us = cap_us;
        }
    }

    /// Refill the bucket (called by the replenishment scheduler at
    /// the period boundary).
    pub fn replenish(&mut self) {
        self.remaining_us = self.capacity_us;
    }

    /// Microseconds of capacity remaining this period.
    pub fn remaining_us(&self) -> u32 {
        self.remaining_us
    }

    /// `true` iff the server has nothing left to give this period.
    pub fn exhausted(&self) -> bool {
        self.remaining_us == 0
    }
}

impl Default for Sporadic {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy for Sporadic {
    const CAPACITY: usize = SPORADIC_CAPACITY;

    fn enqueue(&mut self, meta: TaskMeta) -> Result<(), TaskMeta> {
        if self.len >= SPORADIC_CAPACITY {
            return Err(meta);
        }
        self.queue[self.len] = Some(meta);
        self.len += 1;
        Ok(())
    }

    fn dequeue(&mut self, tid: u32) -> Option<TaskMeta> {
        let idx = self.queue[..self.len]
            .iter()
            .position(|s| matches!(s, Some(m) if m.tid == tid))?;
        let removed = self.queue[idx].take();
        for i in idx..self.len - 1 {
            self.queue[i] = self.queue[i + 1].take();
        }
        self.len -= 1;
        removed
    }

    fn pick_next(&mut self, _now_us: u64) -> Option<TaskMeta> {
        if self.len == 0 || self.exhausted() {
            return None;
        }
        // Highest static priority wins (lower numeric = higher).
        self.queue[..self.len]
            .iter()
            .flatten()
            .min_by_key(|m| m.priority)
            .cloned()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn tick(&mut self, _tid_running: u32, dt_us: u32) {
        // Drain capacity regardless of which task ran (sporadic class
        // shares one bucket).
        if dt_us >= self.remaining_us {
            self.remaining_us = 0;
        } else {
            self.remaining_us -= dt_us;
        }
    }
}

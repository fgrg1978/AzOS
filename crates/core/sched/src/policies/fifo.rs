// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fixed-priority FIFO scheduler.
//!
//! Tasks are popped highest-priority-first, FIFO within the same
//! priority. Used by `SafetyCritical` when a deterministic, no-frills
//! ordering is wanted (every safety task is its own deadline; there
//! is no fairness goal).
//!
//! Capacity is bounded; runqueue is a fixed array. No allocation.

use super::{Policy, TaskMeta};

/// Maximum tasks queued in this policy at once.
pub const FIFO_CAPACITY: usize = 32;

/// Fixed-priority FIFO runqueue.
pub struct Fifo {
    queue: [Option<TaskMeta>; FIFO_CAPACITY],
    /// Number of valid entries.
    len: usize,
}

impl Fifo {
    /// Construct an empty runqueue.
    pub const fn new() -> Self {
        Self {
            queue: [None; FIFO_CAPACITY],
            len: 0,
        }
    }
}

impl Default for Fifo {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy for Fifo {
    const CAPACITY: usize = FIFO_CAPACITY;

    fn enqueue(&mut self, meta: TaskMeta) -> Result<(), TaskMeta> {
        if self.len >= FIFO_CAPACITY {
            return Err(meta);
        }
        // Append to the tail.
        self.queue[self.len] = Some(meta);
        self.len += 1;
        Ok(())
    }

    fn dequeue(&mut self, tid: u32) -> Option<TaskMeta> {
        let idx = self.queue[..self.len]
            .iter()
            .position(|s| matches!(s, Some(m) if m.tid == tid))?;
        let removed = self.queue[idx].take();
        // Shift left by one to keep entries dense.
        for i in idx..self.len - 1 {
            self.queue[i] = self.queue[i + 1].take();
        }
        self.len -= 1;
        removed
    }

    fn pick_next(&mut self, _now_us: u64) -> Option<TaskMeta> {
        if self.len == 0 {
            return None;
        }
        // Find highest-priority entry. Lower numeric value = higher.
        let (idx, _) = self
            .queue
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|m| (i, m.priority)))
            .min_by_key(|&(_, p)| p)?;
        self.queue[idx].clone()
    }

    fn len(&self) -> usize {
        self.len
    }
}

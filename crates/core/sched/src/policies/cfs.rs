// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Completely-Fair-Scheduler-style policy (simplified).
//!
//! Each task carries a `vruntime_us` accumulator. The runqueue picks
//! the task with the smallest `vruntime`, runs it, and accumulates
//! the elapsed time onto its `vruntime` weighted by an inverse
//! priority factor (Nice-equivalent).
//!
//! Used by `BestEffort`. We deliberately keep this much simpler than
//! Linux's full CFS — no red-black tree, no group scheduling, no
//! load weights beyond a discrete priority shift — because the
//! cert-relevant scheduler classes are EDF / FIFO.

use super::{Policy, TaskMeta};

/// Maximum tasks in the CFS runqueue.
pub const CFS_CAPACITY: usize = 32;

/// CFS-like fair-share runqueue.
pub struct Cfs {
    queue: [Option<TaskMeta>; CFS_CAPACITY],
    len: usize,
}

impl Cfs {
    /// Construct an empty runqueue.
    pub const fn new() -> Self {
        Self {
            queue: [None; CFS_CAPACITY],
            len: 0,
        }
    }

    /// Compute the priority weight: lower-priority tasks accumulate
    /// vruntime faster (Linux nice ≈ 1.25^nice; we use 2^priority for
    /// simplicity and integer math).
    #[inline]
    fn weight(priority: u8) -> u64 {
        // Cap the shift so we never overflow.
        let shift = priority.min(20);
        1u64 << shift
    }

    /// Charge `dt_us` of runtime to `tid`'s vruntime.
    pub fn charge(&mut self, tid: u32, dt_us: u32) {
        for slot in self.queue[..self.len].iter_mut() {
            if let Some(m) = slot {
                if m.tid == tid {
                    let w = Self::weight(m.priority);
                    let increment = (dt_us as u64).saturating_mul(w);
                    m.vruntime_us = m.vruntime_us.saturating_add(increment);
                    return;
                }
            }
        }
    }
}

impl Default for Cfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy for Cfs {
    const CAPACITY: usize = CFS_CAPACITY;

    fn enqueue(&mut self, mut meta: TaskMeta) -> Result<(), TaskMeta> {
        if self.len >= CFS_CAPACITY {
            return Err(meta);
        }
        // New tasks join with the minimum vruntime currently in the
        // runqueue, so they're not unfairly favoured.
        let baseline = self.queue[..self.len]
            .iter()
            .filter_map(|s| s.as_ref().map(|m| m.vruntime_us))
            .min()
            .unwrap_or(0);
        if meta.vruntime_us < baseline {
            meta.vruntime_us = baseline;
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
        if self.len == 0 {
            return None;
        }
        self.queue[..self.len]
            .iter()
            .filter_map(|s| s.as_ref())
            .min_by_key(|m| m.vruntime_us)
            .cloned()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn tick(&mut self, tid_running: u32, dt_us: u32) {
        self.charge(tid_running, dt_us);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Round-robin scheduler with per-task quantum.
//!
//! Used by `SoftRT`. Each task carries its own `time_slice_us`. The
//! ISR drives [`tick`] which decrements the running task's remaining
//! slice; when it hits zero the task moves to the tail of the queue.

use super::{Policy, TaskMeta};

/// Maximum tasks in the round-robin queue.
pub const RR_CAPACITY: usize = 32;

/// Default quantum if a task has `time_slice_us == 0`.
pub const DEFAULT_QUANTUM_US: u32 = 10_000;

/// Round-robin runqueue.
pub struct RoundRobin {
    queue: [Option<TaskMeta>; RR_CAPACITY],
    /// Index of the head (next to run). Wraps modulo `RR_CAPACITY`.
    head: usize,
    /// Number of valid entries.
    len: usize,
    /// Microseconds remaining in the current quantum for the task at
    /// `head`. Decremented by `tick`.
    remaining_us: u32,
}

impl RoundRobin {
    /// Construct an empty runqueue.
    pub const fn new() -> Self {
        Self {
            queue: [None; RR_CAPACITY],
            head: 0,
            len: 0,
            remaining_us: 0,
        }
    }

    /// Microseconds left in the current task's quantum. Used by the
    /// integration tests; the kernel timer ISR uses [`tick`].
    pub fn remaining_us(&self) -> u32 {
        self.remaining_us
    }

    fn tail(&self) -> usize {
        (self.head + self.len) % RR_CAPACITY
    }
}

impl Default for RoundRobin {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy for RoundRobin {
    const CAPACITY: usize = RR_CAPACITY;

    fn enqueue(&mut self, meta: TaskMeta) -> Result<(), TaskMeta> {
        if self.len >= RR_CAPACITY {
            return Err(meta);
        }
        let idx = self.tail();
        self.queue[idx] = Some(meta);
        if self.len == 0 {
            // Newly arrived task is also the head; start its quantum.
            let q = if meta.time_slice_us == 0 {
                DEFAULT_QUANTUM_US
            } else {
                meta.time_slice_us
            };
            self.remaining_us = q;
        }
        self.len += 1;
        Ok(())
    }

    fn dequeue(&mut self, tid: u32) -> Option<TaskMeta> {
        if self.len == 0 {
            return None;
        }
        // Find the slot.
        let mut found_at: Option<usize> = None;
        for off in 0..self.len {
            let idx = (self.head + off) % RR_CAPACITY;
            if matches!(self.queue[idx], Some(m) if m.tid == tid) {
                found_at = Some(off);
                break;
            }
        }
        let off = found_at?;
        let idx = (self.head + off) % RR_CAPACITY;
        let removed = self.queue[idx].take();
        // Shift the entries that came after to keep the ring dense.
        for shift in off..self.len - 1 {
            let from = (self.head + shift + 1) % RR_CAPACITY;
            let to = (self.head + shift) % RR_CAPACITY;
            self.queue[to] = self.queue[from].take();
        }
        self.len -= 1;
        if self.len == 0 {
            self.remaining_us = 0;
            self.head = 0;
        } else if off == 0 {
            // We removed the head — start a fresh quantum for the
            // new head.
            let new_head = self.queue[self.head].as_ref();
            self.remaining_us = match new_head {
                Some(m) if m.time_slice_us != 0 => m.time_slice_us,
                _ => DEFAULT_QUANTUM_US,
            };
        }
        removed
    }

    fn pick_next(&mut self, _now_us: u64) -> Option<TaskMeta> {
        if self.len == 0 {
            return None;
        }
        self.queue[self.head].clone()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn tick(&mut self, tid_running: u32, dt_us: u32) {
        if self.len == 0 {
            return;
        }
        let head_meta = match &self.queue[self.head] {
            Some(m) => m,
            None => return,
        };
        if head_meta.tid != tid_running {
            return;
        }
        if dt_us >= self.remaining_us {
            // Quantum exhausted — rotate head to tail.
            self.rotate();
        } else {
            self.remaining_us -= dt_us;
        }
    }
}

impl RoundRobin {
    fn rotate(&mut self) {
        if self.len < 2 {
            // One task — nothing to rotate; just refill the quantum.
            if let Some(m) = &self.queue[self.head] {
                self.remaining_us = if m.time_slice_us != 0 {
                    m.time_slice_us
                } else {
                    DEFAULT_QUANTUM_US
                };
            }
            return;
        }
        let tail_idx = self.tail();
        // Move head into the slot after the current tail.
        self.queue[tail_idx] = self.queue[self.head].take();
        self.head = (self.head + 1) % RR_CAPACITY;
        // Start fresh quantum for new head.
        if let Some(m) = &self.queue[self.head] {
            self.remaining_us = if m.time_slice_us != 0 {
                m.time_slice_us
            } else {
                DEFAULT_QUANTUM_US
            };
        }
    }
}

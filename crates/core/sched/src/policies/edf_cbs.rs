// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Earliest-Deadline-First with Constant Bandwidth Server.
//!
//! Used by `SafetyCritical` and `HardRT`. EDF picks the runnable task
//! whose `deadline_us` is soonest. CBS adds a per-class budget cap so
//! a runaway task (e.g. one whose actual WCET overshoots its declared
//! reservation) cannot hog the CPU and starve the other classes.
//!
//! ### CBS in one paragraph
//!
//! Each EDF task is given a *server* with two parameters: a budget
//! `Q_s` (microseconds it may consume per period) and a period
//! `T_s`. While the task runs we decrement `budget_remaining`. When
//! it hits zero, the task's deadline is pushed forward by `T_s` and
//! the budget refilled IN THE SAME STEP (`CbsState::tick`) — so the
//! enforcement a caller outside `tick` ever sees is the pushed
//! deadline, never a budget actually sitting at zero
//! (`CbsState::exhausted`'s doc has the detail). Effectively the task
//! acts as if it had a soft-RT class behaviour — it loses priority
//! instead of stealing CPU. (Buttazzo, *Hard Real-Time Computing
//! Systems*, ch. 6.)
//!
//! ### Liu-Layland admission test (RFC-0004)
//!
//! For `n` periodic tasks with WCET `C_i` and period `T_i`, EDF can
//! meet all deadlines iff `Σ C_i / T_i ≤ 1.0`. We approximate with
//! integer math at promille granularity (per-mille = 1/1000) to
//! avoid floats: `Σ (C_i × 1000 / T_i) ≤ 1000`.

use super::{Policy, TaskMeta};

/// Maximum tasks in the EDF runqueue per CPU.
pub const EDF_CAPACITY: usize = 16;

/// CBS state for one server (one EDF task).
#[derive(Clone, Copy, Debug)]
pub struct CbsState {
    /// Budget `Q_s`, in microseconds.
    pub budget_us: u32,
    /// Period `T_s`, in microseconds.
    pub period_us: u32,
    /// Runtime remaining in the current period, microseconds.
    pub remaining_us: u32,
}

impl CbsState {
    /// Construct a fresh CBS server.
    pub const fn new(budget_us: u32, period_us: u32) -> Self {
        Self {
            budget_us,
            period_us,
            remaining_us: budget_us,
        }
    }

    /// `true` iff the server has exhausted its budget.
    ///
    /// **Never observed `true` outside `tick` itself.** `tick` (below)
    /// sets `remaining_us = 0` and calls `refill()` in the same call, so
    /// by the time any OTHER caller — `pick_next`'s
    /// `.filter(|e| !e.cbs.exhausted())`, or a test — reads this, the
    /// budget is already full again. The doc used to say the task "has
    /// to wait for the next deadline period"; it does not wait for
    /// anything from this flag's perspective. What actually throttles it
    /// is `tick`'s deadline push, which lowers its EDF priority (a later
    /// deadline sorts worse in `pick_next`'s `min_by_key`) regardless of
    /// this flag. Kept rather than removed: a future caller between
    /// `tick` calls (there is none today) could still observe it
    /// meaningfully, and `pick_next`'s two-tier fallback is harmless
    /// dead weight, not a bug, while it is.
    #[inline]
    pub fn exhausted(&self) -> bool {
        self.remaining_us == 0
    }

    /// Refill the budget at the start of a new period.
    #[inline]
    pub fn refill(&mut self) {
        self.remaining_us = self.budget_us;
    }
}

/// One EDF entry: scheduling metadata + CBS state.
#[derive(Clone, Copy, Debug)]
pub struct EdfEntry {
    pub meta: TaskMeta,
    pub cbs: CbsState,
}

/// EDF + CBS runqueue.
pub struct EdfCbs {
    queue: [Option<EdfEntry>; EDF_CAPACITY],
    len: usize,
}

impl EdfCbs {
    /// Construct an empty runqueue.
    pub const fn new() -> Self {
        Self {
            queue: [None; EDF_CAPACITY],
            len: 0,
        }
    }

    /// Insert with explicit CBS parameters. Failing returns the input
    /// echo so the caller can react.
    pub fn enqueue_with_cbs(
        &mut self,
        meta: TaskMeta,
        cbs: CbsState,
    ) -> Result<(), (TaskMeta, CbsState)> {
        if self.len >= EDF_CAPACITY {
            return Err((meta, cbs));
        }
        self.queue[self.len] = Some(EdfEntry { meta, cbs });
        self.len += 1;
        Ok(())
    }

    /// Liu-Layland admission test for the *current* set of tasks plus
    /// a hypothetical new admission. Returns `true` if the resulting
    /// utilisation is ≤ 1.0.
    pub fn admission_check(
        &self,
        new_budget_us: u32,
        new_period_us: u32,
    ) -> bool {
        if new_period_us == 0 {
            return false;
        }
        // Per-mille utilisation Σ (C × 1000 / T) ≤ 1000.
        let mut sum_permille: u64 = 0;
        for entry in self.queue[..self.len].iter().flatten() {
            if entry.cbs.period_us == 0 {
                return false;
            }
            sum_permille += (entry.cbs.budget_us as u64 * 1000)
                / entry.cbs.period_us as u64;
        }
        sum_permille +=
            (new_budget_us as u64 * 1000) / new_period_us as u64;
        sum_permille <= 1000
    }

    /// Borrow the entry for `tid` (read-only).
    pub fn entry(&self, tid: u32) -> Option<&EdfEntry> {
        self.queue[..self.len]
            .iter()
            .flatten()
            .find(|e| e.meta.tid == tid)
    }
}

impl Default for EdfCbs {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy for EdfCbs {
    const CAPACITY: usize = EDF_CAPACITY;

    fn enqueue(&mut self, meta: TaskMeta) -> Result<(), TaskMeta> {
        // Default CBS: budget = period = 10 ms (caller must override
        // via `enqueue_with_cbs` for real workloads).
        const DEFAULT_BUDGET_US: u32 = 10_000;
        const DEFAULT_PERIOD_US: u32 = 10_000;
        self.enqueue_with_cbs(
            meta,
            CbsState::new(DEFAULT_BUDGET_US, DEFAULT_PERIOD_US),
        )
        .map_err(|(m, _)| m)
    }

    fn dequeue(&mut self, tid: u32) -> Option<TaskMeta> {
        let idx = self.queue[..self.len]
            .iter()
            .position(|s| matches!(s, Some(e) if e.meta.tid == tid))?;
        let removed = self.queue[idx].take().map(|e| e.meta);
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
        // Prefer non-exhausted servers; among those, smallest deadline.
        // Tasks with `deadline_us == None` get u64::MAX (treated as
        // last-resort).
        self.queue[..self.len]
            .iter()
            .flatten()
            .filter(|e| !e.cbs.exhausted())
            .min_by_key(|e| e.meta.deadline_us.unwrap_or(u64::MAX))
            .map(|e| e.meta)
            .or_else(|| {
                // All servers exhausted — fall back to first non-empty
                // (degraded mode; caller should bump the deadline +
                // refill at next period boundary).
                self.queue[..self.len]
                    .iter()
                    .flatten()
                    .min_by_key(|e| e.meta.deadline_us.unwrap_or(u64::MAX))
                    .map(|e| e.meta)
            })
    }

    fn len(&self) -> usize {
        self.len
    }

    fn tick(&mut self, tid_running: u32, dt_us: u32) {
        for slot in self.queue[..self.len].iter_mut() {
            if let Some(entry) = slot {
                if entry.meta.tid == tid_running {
                    if dt_us >= entry.cbs.remaining_us {
                        entry.cbs.remaining_us = 0;
                        // Push deadline forward by one period.
                        if let Some(d) = entry.meta.deadline_us.as_mut() {
                            *d = d.saturating_add(entry.cbs.period_us as u64);
                        }
                        entry.cbs.refill();
                    } else {
                        entry.cbs.remaining_us -= dt_us;
                    }
                    return;
                }
            }
        }
    }
}

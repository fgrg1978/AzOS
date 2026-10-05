// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Adaptive Partitioning Scheduler — RFC-0004.
//!
//! Splits the CPU among the five [`SchedClass`] groups, guaranteeing
//! each its `min_pct` budget per partition window while letting
//! under-served classes opportunistically borrow surplus.
//!
//! ## Algorithm
//!
//! At each scheduling tick:
//!
//! 1. **Time accounting** — the running task's class is debited the
//!    elapsed `dt_us`.
//! 2. **Window roll-over** — if `now_us - window_start ≥ window_us`,
//!    every class's `consumed_us` is reset and `window_start` shifts
//!    to the next boundary.
//! 3. **Class selection** — iterate classes in urgency order
//!    (SafetyCritical → Idle):
//!    - If a class has tasks runnable AND `under_min(window_us)`
//!      → pick that class (must serve guaranteed minimum first).
//!    - Otherwise, among classes whose budget isn't exhausted,
//!      pick the most-urgent runnable one.
//! 4. The selected class's [`Policy::pick_next`] returns the task.
//!
//! ## Properties (verified in `formal/tla/sched_aps.tla`)
//!
//! - **Guaranteed minimum**: as long as a class has runnable tasks,
//!   it receives at least `min_pct` of the window.
//! - **Bounded interference**: a misbehaving lower-class task cannot
//!   starve a higher-class task by more than one window.
//! - **No deadlock**: the combinator always picks a runnable task if
//!   any exists.
//!
//! **What "verified" covers, precisely.** The TLA+ model's state is a
//! per-class `runnable` flag (`sched_aps.tla`) — it does not model the
//! legacy per-CPU ring `aps_state`/`scheduler::do_schedule` also
//! maintain, or the fact that a class's `runnable` flag going true (a
//! wake) used to never feed a policy's runqueue at all (U02-1, fixed:
//! `scheduler::wake_enqueue_locked`). These three properties hold for
//! the combinator `Aps::pick_class` implements; they say nothing about
//! whether a policy's runqueue actually contains the tasks it should.

use crate::class::{ClassBudget, SchedClass};

/// Per-CPU APS state.
pub struct Aps {
    budgets: [ClassBudget; SchedClass::COUNT],
    /// Window length in microseconds.
    window_us: u32,
    /// Monotonic time at which the current window started.
    window_start_us: u64,
    /// Class of the currently-running task (used by [`tick`] to
    /// charge runtime). `None` ⇒ idle.
    current_class: Option<SchedClass>,
    /// `tid` of the currently-running task (for diagnostics +
    /// accounting completeness).
    current_tid: u32,
}

impl Aps {
    /// Construct with the RFC-0004 default per-class budgets and a
    /// 10 ms partition window.
    pub const fn default_config() -> Self {
        let budgets: [ClassBudget; SchedClass::COUNT] = [
            ClassBudget::default_for(SchedClass::SafetyCritical),
            ClassBudget::default_for(SchedClass::HardRT),
            ClassBudget::default_for(SchedClass::SoftRT),
            ClassBudget::default_for(SchedClass::BestEffort),
            ClassBudget::default_for(SchedClass::Idle),
        ];
        Self {
            budgets,
            window_us: 10_000,
            window_start_us: 0,
            current_class: None,
            current_tid: 0,
        }
    }

    /// Construct with explicit per-class budgets and window.
    pub const fn new(
        budgets: [ClassBudget; SchedClass::COUNT],
        window_us: u32,
    ) -> Self {
        Self {
            budgets,
            window_us,
            window_start_us: 0,
            current_class: None,
            current_tid: 0,
        }
    }

    /// Window length in microseconds.
    #[inline]
    pub fn window_us(&self) -> u32 {
        self.window_us
    }

    /// Borrow a class's budget bookkeeping.
    #[inline]
    pub fn budget(&self, class: SchedClass) -> &ClassBudget {
        &self.budgets[class.slot()]
    }

    /// Note that `tid` of class `class` is now running. Subsequent
    /// [`tick`] calls will charge `class`'s budget.
    pub fn set_current(&mut self, class: SchedClass, tid: u32) {
        self.current_class = Some(class);
        self.current_tid = tid;
    }

    /// Mark the CPU idle (between tasks). [`tick`] will not charge
    /// any class while idle.
    pub fn set_idle(&mut self) {
        self.current_class = None;
        self.current_tid = 0;
    }

    /// Currently-running class, if any.
    #[inline]
    pub fn current_class(&self) -> Option<SchedClass> {
        self.current_class
    }

    /// Currently-running tid (or `0` if idle).
    #[inline]
    pub fn current_tid(&self) -> u32 {
        self.current_tid
    }

    /// Advance the partition state by `dt_us` microseconds at
    /// monotonic time `now_us`.
    ///
    /// If `now_us` is more than one window past the current window
    /// start (e.g. the kernel just booted with the window anchored
    /// at 0 and `rdtime` is already in the millions), we
    /// **catch up in one step** — advance the window start by as
    /// many full windows as needed and reset the budgets once. A
    /// naive single-window advance would burn the consumption
    /// counter on every subsequent tick until caught up.
    ///
    /// Returns `true` iff a window roll-over happened during this
    /// call. U02-1 fix: `aps_state::account` uses this to drive
    /// [`crate::policies::sporadic::Sporadic::replenish`], which
    /// otherwise has no caller in the tree — the Idle bucket drained
    /// its capacity once and stayed at zero forever, since nothing
    /// ever refilled it. The window roll-over is the natural
    /// replenishment period boundary: every class's budget is reset
    /// here too, in the same `if`.
    pub fn tick(&mut self, now_us: u64, dt_us: u32) -> bool {
        let elapsed = now_us.saturating_sub(self.window_start_us);
        let window = self.window_us as u64;
        let rolled_over = window > 0 && elapsed >= window;
        if rolled_over {
            for b in &self.budgets {
                b.reset_window();
            }
            // How many full windows have elapsed since the last anchor.
            let windows = elapsed / window;
            self.window_start_us =
                self.window_start_us.saturating_add(windows * window);
        }
        if let Some(c) = self.current_class {
            self.budgets[c.slot()].consume(dt_us);
        }
        rolled_over
    }

    /// Pick the next class to run.
    ///
    /// Caller passes a function `is_runnable: SchedClass -> bool`
    /// that the APS uses to skip empty runqueues.
    pub fn pick_class<F>(&self, is_runnable: F) -> Option<SchedClass>
    where
        F: Fn(SchedClass) -> bool,
    {
        // Phase 1: any class under its guaranteed minimum.
        for &cls in &SchedClass::ALL {
            if !is_runnable(cls) {
                continue;
            }
            if self.budgets[cls.slot()].under_min(self.window_us) {
                return Some(cls);
            }
        }
        // Phase 2: any non-exhausted runnable class, urgency-first.
        for &cls in &SchedClass::ALL {
            if !is_runnable(cls) {
                continue;
            }
            if !self.budgets[cls.slot()].over_quota(self.window_us) {
                return Some(cls);
            }
        }
        // Phase 3 (degraded): every class is over-quota. Hand the CPU
        // to the most-urgent runnable class anyway — better than an
        // unscheduled CPU.
        SchedClass::ALL
            .iter()
            .copied()
            .find(|&c| is_runnable(c))
    }

    /// Force the window to start at `now_us` (typically called once
    /// from `init` so the first tick's reference is sane).
    pub fn anchor_window(&mut self, now_us: u64) {
        self.window_start_us = now_us;
        for b in &self.budgets {
            b.reset_window();
        }
    }
}

impl Default for Aps {
    fn default() -> Self {
        Self::default_config()
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The micro kernel's dispatch: three classes in the main kernel's precedence
//! (`sc::Class::PRECEDENCE`, deadline over real time over idle; there is no
//! fair class and no stop class on one hart), over the scheduling context
//! and the CBS arithmetic the main kernel shares (`sc.rs`, `rt_core.rs`).
//!
//! * Deadline: a topology row with a `profile` holds a CBS reservation. The
//!   earliest absolute deadline among the eligible runs; a hard server whose
//!   budget ran out is throttled until its deadline.
//! * Real time: fixed priority, lower number first, round robin inside a
//!   level with a slice of `MICRO_TIMESLICE_TICKS`. A server working under
//!   an endpoint's ceiling runs at the ceiling's level (`ceiling.rs`).
//! * Idle: the rows at `MICRO_IDLE_PRIO` or above, run when nothing else is.
//!
//! Pure: it decides, the kernel (`kernel.rs`) switches. Time is `mtime`
//! ticks.

use core::sync::atomic::Ordering::Relaxed;

use crate::ceiling;
use crate::pi_attr::PiAttr;
use crate::rt_core::{edf_before, Cbs};
use crate::sc::{Class, SchedContext};

/// One schedulable task.
pub struct Entity {
    /// Class, level and times (`sc.rs`).
    pub sc: SchedContext,
    /// The CBS reservation; `Cbs::NONE` outside the deadline class.
    pub cbs: Cbs,
    /// Ready to run (not blocked, sleeping, dead or unborn).
    pub runnable: bool,
    /// The ceiling it serves under, while it holds a request.
    pub ceiling: Option<PiAttr>,
    /// Ticks left of the current round-robin slice.
    pub slice_left: u32,
    /// Dispatch stamp: the lower, the longer ago it last ran.
    pub last_run: u64,
}

impl Entity {
    /// An entity that is not schedulable yet.
    pub const fn unborn() -> Self {
        Self {
            sc: SchedContext::new(Class::Idle),
            cbs: Cbs::NONE,
            runnable: false,
            ceiling: None,
            slice_left: 0,
            last_run: 0,
        }
    }

    /// The level it competes at: its own, or the ceiling's while it serves.
    fn level(&self) -> u32 {
        let base = self.sc.prio_or_weight.load(Relaxed);
        let attr = ceiling::base_attr(self.sc.class(), base.min(255) as u8);
        match ceiling::effective(attr, self.ceiling) {
            PiAttr::Rt { prio } => prio as u32,
            _ => base,
        }
    }

    /// It became runnable: a reservation applies the CBS release rule at
    /// its next pick.
    pub fn wake(&mut self) {
        self.runnable = true;
        if self.cbs.active() {
            self.cbs.release_due = true;
        }
    }

    /// The task starts its slice anew: it is being dispatched.
    pub fn dispatched(&mut self, stamp: u64, slice: u32) {
        self.last_run = stamp;
        self.slice_left = slice;
    }
}

/// The task to run next, or `None` when nothing is runnable (the idle row
/// is missing). `cur` is the task that was running: it keeps the processor
/// against a peer of its own level until its slice is spent.
pub fn pick(ents: &mut [Entity], cur: Option<usize>, now: u64) -> Option<usize> {
    // Deadline class. First the reservations' own bookkeeping (a woken one
    // is released, a throttled one whose deadline came is refilled), then
    // the earliest deadline among the eligible.
    for e in ents.iter_mut() {
        if e.runnable && e.sc.class() == Class::Dl && e.cbs.active() {
            if e.cbs.release_due {
                e.cbs.release(now);
            }
            e.cbs.replenish_if_due(now);
        }
    }
    let mut best: Option<usize> = None;
    for (i, e) in ents.iter().enumerate() {
        if !e.runnable || e.sc.class() != Class::Dl || !e.cbs.active() || !e.cbs.eligible() {
            continue;
        }
        if best.map_or(true, |b| edf_before(0, e.cbs.deadline, 0, ents[b].cbs.deadline)) {
            best = Some(i);
        }
    }
    if best.is_some() {
        return best;
    }
    // Real time: the lowest level; inside it, the task that ran longest ago
    // unless the running task still has slice.
    let mut best: Option<usize> = None;
    for (i, e) in ents.iter().enumerate() {
        if !e.runnable || e.sc.class() != Class::Rt {
            continue;
        }
        best = match best {
            Some(b) if (ents[b].level(), ents[b].last_run) <= (e.level(), e.last_run) => Some(b),
            _ => Some(i),
        };
    }
    if let (Some(b), Some(c)) = (best, cur) {
        let ce = &ents[c];
        if c != b && ce.runnable && ce.sc.class() == Class::Rt && ce.level() == ents[b].level() && ce.slice_left > 0 {
            return Some(c);
        }
    }
    if best.is_some() {
        return best;
    }
    ents.iter().position(|e| e.runnable && e.sc.class() == Class::Idle)
}

/// One scheduler tick passed with `e` running: spend a tick of its slice.
/// When the slice is spent the task is stamped `stamp` (newer than any
/// peer's), so the peers of its level go before it.
pub fn slice_tick(e: &mut Entity, stamp: u64) {
    if e.slice_left > 0 {
        e.slice_left -= 1;
        if e.slice_left == 0 {
            e.last_run = stamp;
        }
    }
}

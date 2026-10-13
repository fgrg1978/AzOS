// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Stage E4: a TEO-like idle governor (RFC-0051 §4.5), after Linux's
//! `teo` ("timer events oriented") cpuidle governor.
//!
//! The next armed timer bounds how long a CPU can sleep; the governor
//! starts from the deepest state whose target residency fits that bound and
//! whose exit latency fits the real-time slack (invariant I3), then moves
//! shallower while the CPU's recent history says it is usually woken early
//! by something other than the timer (an "intercept": an IPI, a device
//! interrupt). History can only make the choice shallower, never deeper, so
//! it cannot break I3.
//!
//! Per CPU, each state `i` keeps two decaying counters for the wake-ups whose
//! measured idle time fell in its bin `[residency(i), residency(i+1))`:
//! `hits` (the CPU slept until its timer bound) and `intercepts` (woken
//! earlier). Each wake-up decays every bin by 1/8 and adds [`STEP`] to one,
//! so a counter stays below `8 × STEP + 8` (the decay rounds down).
//!
//! State 0 is the shallowest the model lists (`wfi` on every board and fake
//! model so far); it is what an idle CPU does with no choice to make, so I3
//! constrains states 1 and up.

use crate::model::{IdleState, MAX_IDLE_STATES};

/// What one wake-up adds to its bin.
pub const STEP: u16 = 64;
/// A wake-up within this fraction (1/`TIMER_SLOP_DIV`) of the timer bound
/// counts as woken by the timer.
pub const TIMER_SLOP_DIV: u64 = 16;

/// One CPU's wake-up history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TeoCpu {
    /// Woken by the timer, per bin.
    pub hits: [u16; MAX_IDLE_STATES],
    /// Woken early, per bin.
    pub intercepts: [u16; MAX_IDLE_STATES],
}

impl TeoCpu {
    /// No history.
    pub const NEW: Self = Self { hits: [0; MAX_IDLE_STATES], intercepts: [0; MAX_IDLE_STATES] };
}

/// Why the choice is shallower than the deepest state the timer bound allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    /// Nothing: the timer bound picked it.
    Timer,
    /// I3: a deeper state's exit latency exceeds the real-time slack.
    RtSlack,
    /// Early wake-ups dominate the history below the candidate.
    History,
}

/// The deepest state in `states` whose residency fits `sleep_us` and, for
/// states past 0, whose exit latency fits `rt_slack_us`. Also whether the
/// slack (not the timer) stopped it.
pub fn timer_candidate(states: &[IdleState], sleep_us: u64, rt_slack_us: u64) -> (usize, bool) {
    let mut c = 0;
    let mut by_slack = false;
    for (i, s) in states.iter().enumerate().skip(1) {
        if s.target_residency_us as u64 > sleep_us {
            break;
        }
        if s.exit_latency_us as u64 > rt_slack_us && !cfg!(feature = "i3-canary") {
            by_slack = true;
            break;
        }
        c = i;
    }
    (c, by_slack)
}

/// The state to enter (an index into `states`), and what limited it.
/// `sleep_us`: time to the next armed timer; `rt_slack_us`: time to the
/// nearest real-time deadline on this CPU (`u64::MAX`: none).
pub fn select(states: &[IdleState], sleep_us: u64, rt_slack_us: u64, h: &TeoCpu) -> (usize, Limit) {
    let (mut c, by_slack) = timer_candidate(states, sleep_us, rt_slack_us);
    let mut limit = if by_slack { Limit::RtSlack } else { Limit::Timer };
    let n = states.len().min(MAX_IDLE_STATES);
    let total: u32 = (0..n).map(|i| h.hits[i] as u32 + h.intercepts[i] as u32).sum();
    while c > 0 {
        // Early wake-ups that landed below the candidate's residency.
        let early: u32 = (0..c).map(|i| h.intercepts[i] as u32).sum();
        if 2 * early > total {
            c -= 1;
            limit = Limit::History;
        } else {
            break;
        }
    }
    (c, limit)
}

/// The bin of an idle time of `us`: the deepest state whose residency it
/// reaches (0 if none).
pub fn bin_of(states: &[IdleState], us: u64) -> usize {
    let mut b = 0;
    for (i, s) in states.iter().enumerate() {
        if (s.target_residency_us as u64) <= us {
            b = i;
        }
    }
    b.min(MAX_IDLE_STATES - 1)
}

/// Record a wake-up after `slept_us` of a sleep the timer bounded at
/// `sleep_us`. Returns whether it counted as an intercept.
pub fn reflect(states: &[IdleState], h: &mut TeoCpu, slept_us: u64, sleep_us: u64) -> bool {
    for i in 0..MAX_IDLE_STATES {
        h.hits[i] -= h.hits[i] >> 3;
        h.intercepts[i] -= h.intercepts[i] >> 3;
    }
    let by_timer = slept_us.saturating_add(sleep_us / TIMER_SLOP_DIV) >= sleep_us;
    if by_timer {
        let b = bin_of(states, sleep_us);
        h.hits[b] = h.hits[b].saturating_add(STEP);
    } else {
        let b = bin_of(states, slept_us);
        h.intercepts[b] = h.intercepts[b].saturating_add(STEP);
    }
    !by_timer
}

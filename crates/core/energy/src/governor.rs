// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Stage E3: which OPP a performance domain should run at (RFC-0051 §4.4, §5).
//!
//! Three floors are computed separately and the answer is their maximum:
//!
//! * **schedutil** ([`schedutil_opp`]): the lowest OPP whose capacity covers
//!   the domain's busiest CPU with 25 % headroom, Linux's `map_util_freq`
//!   rule. The utilisation signal is the fraction of time a CPU was busy at
//!   the OPP it ran at (it is not frequency-invariant), so the demand is
//!   `util × capacity(current OPP)`; a CPU that stays saturated climbs one
//!   step per evaluation.
//! * **deadline floor** ([`deadline_floor_opp`]): the lowest OPP whose
//!   capacity covers the admitted real-time reservations of the domain's
//!   most loaded hart (cycle-conserving EDF, Pillai & Shin 2001), plus
//!   [`DEADLINE_MARGIN_PCT`]. The admitted figure is the SCHED-RT ledger's
//!   **density** `Σ q/d`, not the utilisation `Σ q/t`: it is what admission
//!   books, and it is never smaller, so the floor errs high. A reservation's
//!   `runtime_us` is taken as measured at the domain's fastest OPP (the RFC
//!   leaves the reference frequency open, §5(a)); a runtime measured slower
//!   would only lower the floor this computes.
//! * **safety floor** ([`safety_floor_opp`], invariant I6): the lowest OPP
//!   at or above the domain's declared WCET reference frequency
//!   (`wcet_ref_khz`); with none declared, or one above every OPP, the
//!   fastest OPP. So a model that does not say at which clock its safety
//!   bounds hold never lets any governor lower the clock.
//!
//! `Governor::Schedutil` answers `max(schedutil, safety)`;
//! `Governor::DeadlineFloor` answers `max(schedutil, deadline, safety)`
//! (invariant I1). Nothing here touches a clock or a timer: the kernel
//! records the answer (there is no clock driver on any board yet).

use crate::model::PerfDomain;
use crate::util::SCALE;

/// Headroom over the deadline floor, percent.
pub const DEADLINE_MARGIN_PCT: u64 = 20;
/// Shortest interval between two evaluations of one domain, microseconds
/// (Linux `schedutil` `rate_limit_us` order of magnitude).
pub const RATE_LIMIT_US: u64 = 4_000;
/// Parts per million (the SCHED-RT ledger's unit).
pub const PPM: u64 = 1_000_000;

/// Which floor set the answer (the largest; ties go to the safety floor,
/// then the deadline floor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// Utilisation.
    Schedutil,
    /// Admitted real-time reservations (I1).
    DeadlineFloor,
    /// The WCET reference frequency (I6).
    SafetyFloor,
}

/// What the governor saw and decided for one domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The OPP index to run at.
    pub opp: usize,
    /// Which floor set it.
    pub why: Why,
    /// Each floor, for the log.
    pub schedutil: usize,
    /// Deadline floor (0 when the governor ignores reservations).
    pub deadline: usize,
    /// Safety floor.
    pub safety: usize,
}

/// The lowest OPP of `d` whose capacity is at least `cap`; the fastest if
/// none is. A domain with no OPP answers 0.
pub fn lowest_opp_with_capacity(d: &PerfDomain, cap: u64) -> usize {
    let opps = d.opps();
    for (i, o) in opps.iter().enumerate() {
        if o.capacity as u64 >= cap {
            return i;
        }
    }
    opps.len().saturating_sub(1)
}

/// schedutil: `util` (on [`SCALE`]) is the busy fraction of the domain's
/// busiest CPU at OPP `cur`.
pub fn schedutil_opp(d: &PerfDomain, util: u32, cur: usize) -> usize {
    let opps = d.opps();
    if opps.is_empty() {
        return 0;
    }
    let cur_cap = opps[cur.min(opps.len() - 1)].capacity as u64;
    let util = (util as u64).min(SCALE as u64);
    // demand × 1.25, rounded up.
    let need = (util * cur_cap * 5).div_ceil(SCALE as u64 * 4);
    lowest_opp_with_capacity(d, need)
}

/// The deadline floor for a hart with `admitted_ppm` of reservations.
pub fn deadline_floor_opp(d: &PerfDomain, admitted_ppm: u32) -> usize {
    if admitted_ppm == 0 || cfg!(feature = "i1-canary") {
        return 0;
    }
    let top = d.max_capacity() as u64;
    let need = (admitted_ppm as u64 * top * (100 + DEADLINE_MARGIN_PCT)).div_ceil(PPM * 100);
    lowest_opp_with_capacity(d, need)
}

/// I6: the lowest OPP at or above the domain's WCET reference frequency.
pub fn safety_floor_opp(d: &PerfDomain) -> usize {
    let opps = d.opps();
    let top = opps.len().saturating_sub(1);
    if cfg!(feature = "i6-canary") {
        return 0;
    }
    if d.wcet_ref_khz == 0 {
        return top;
    }
    for (i, o) in opps.iter().enumerate() {
        if o.freq_khz >= d.wcet_ref_khz {
            return i;
        }
    }
    top
}

/// `max` of the floors, with the reason. `deadline` is `None` for a
/// governor that does not read reservations.
pub fn combine(schedutil: usize, deadline: Option<usize>, safety: usize) -> Decision {
    let dl = deadline.unwrap_or(0);
    let (opp, why) = if safety >= schedutil && safety >= dl {
        (safety, Why::SafetyFloor)
    } else if deadline.is_some() && dl >= schedutil {
        (dl, Why::DeadlineFloor)
    } else {
        (schedutil, Why::Schedutil)
    };
    Decision { opp, why, schedutil, deadline: dl, safety }
}

/// Is a domain last evaluated at `last` due again at `now` (both in ticks of
/// a `freq` Hz counter)? `last == 0` is "never".
#[inline]
pub fn due(last: u64, now: u64, freq: u64) -> bool {
    last == 0 || now.saturating_sub(last) >= RATE_LIMIT_US * freq / 1_000_000
}

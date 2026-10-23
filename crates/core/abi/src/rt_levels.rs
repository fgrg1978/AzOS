// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The cross-level admission rule for EDF + CBS reservations, shared by the
//! two places that admit them: the topology's boot check
//! (`azos_topology::deadline::admit`) and the scheduler's run-time
//! `reserve` (`azos_sched::rt_core`, which re-exports it). It lives here
//! because this is the lowest crate both depend on; one copy means a set the
//! board admits at boot is a set `reserve` admits at run time.
//!
//! The rule binds only under fixed priority between levels
//! ([`LevelOrder::Fixed`]). Every caller passes the order the dispatch runs
//! in (`azos_sched::classes::level_order`), so admission and dispatch read
//! one switch and cannot disagree.
//!
//! Pure, allocation-free, unit-agnostic (`q` and `d` in any one time unit).

/// How one hart's dispatch orders reservations at different priority levels.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LevelOrder {
    /// EDF across levels: every reservation competes at one rank, by its
    /// absolute deadline (`azos_sched::rt_core::dl_rank`). The default. The
    /// density sum is the whole test, and [`levels_check`] admits every set.
    Edf,
    /// Fixed priority between levels, EDF inside one: a level above runs
    /// first whatever its deadlines (the `sched-dl-in-level` canary).
    /// [`levels_check`] applies.
    Fixed,
}

/// One CPU is this many parts per million.
pub const PPM: u64 = 1_000_000;

/// One reservation of a hart, as [`levels_check`] reads it: its level, budget
/// and relative deadline (any one time unit), and density.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Booked {
    /// Priority level the reservation's task runs at (lower = more urgent).
    pub level: u32,
    /// Budget per period.
    pub q: u64,
    /// Relative deadline, same unit as `q`.
    pub d: u64,
    /// Density, parts per million (`ceil(q * PPM / min(d, t))`).
    pub density_ppm: u32,
}

/// Can every reservation of one hart keep its deadlines when they sit at
/// different priority levels and the dispatch runs them in `order`? `Err`
/// names the level whose deadlines it cannot guarantee (the first one found,
/// in `booked` order) for a refusal line.
///
/// Under [`LevelOrder::Edf`] always `Ok`: EDF over all of a hart's
/// reservations meets every deadline the density sum admits, whatever their
/// levels, so a test by level would only refuse sets that fit.
///
/// Under [`LevelOrder::Fixed`] the dispatch orders reservations by deadline
/// inside a level only; a level above runs first whatever its deadlines, so
/// the density sum is not enough: two reservations at 75 % in all, the lower
/// one with a 2 ms deadline behind 5 ms of the upper one, miss every job
/// (wave 15, `sched-rt-util` `mixed`). The test, for each level `l` present,
/// with `dmin` its shortest relative deadline:
///
/// `sum(density, levels <= l) + sum(q, levels < l) / dmin <= 1`
///
/// Why it is enough (sufficient, not necessary). A hard CBS server above `l`
/// takes at most `density * L + q` of any window of length `L`: the wake
/// rule (`azos_sched::rt_core::Cbs::release`) keeps its work between a
/// release and the deadline it holds within its density of that span, and
/// `q` covers the budget it carries into the window (the end of one server
/// period and the start of the next can be back to back). Level `l`'s own
/// demand in a window of length `L >= dmin` is at most `sum(density, l) * L`
/// (a constrained sporadic task's demand bound), and none below `dmin`. EDF
/// meets level `l`'s deadlines when, for every `L >= dmin`, that demand fits
/// in what the levels above leave; the carried budgets weigh most at
/// `L = dmin`, which is the test. Same-level sets reduce to the density sum.
///
/// Monotone: a subset of a set that fits also fits (removing a reservation
/// lowers both sums and can only raise a level's `dmin`), so a hart's set
/// admitted whole at boot is admitted in any arrival order at run time.
///
/// Outside the model: tasks above `l` that hold no reservation (the kernel's
/// own loops, a band task without a profile), priority donation that moves a
/// reservation's task to another level while it holds a lock, and
/// non-preemptible kernel sections.
pub fn levels_check(order: LevelOrder, booked: &[Booked]) -> Result<(), u32> {
    if !binds(order) {
        return Ok(());
    }
    for b in booked {
        let l = b.level;
        let mut dmin = u64::MAX;
        let (mut dens, mut carry) = (0u64, 0u128);
        for o in booked {
            if o.level == l {
                dmin = dmin.min(o.d);
            }
            if o.level <= l {
                dens += o.density_ppm as u64;
            }
            if o.level < l {
                carry += o.q as u128;
            }
        }
        if dmin == 0 {
            return Err(l);
        }
        let carry_ppm = (carry * PPM as u128).div_ceil(dmin as u128);
        if dens as u128 + carry_ppm > PPM as u128 {
            return Err(l);
        }
    }
    Ok(())
}

/// Does the rule bind under `order`? Canaries, never in a build:
/// `rt-levels-always-canary` binds it under EDF too (the rule before the
/// order decided it), `rt-levels-never-canary` never binds it.
const fn binds(order: LevelOrder) -> bool {
    if cfg!(feature = "rt-levels-always-canary") {
        true
    } else if cfg!(feature = "rt-levels-never-canary") {
        false
    } else {
        matches!(order, LevelOrder::Fixed)
    }
}

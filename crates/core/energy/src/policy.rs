// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The run-time energy policy: what user space may change and the limits the
//! kernel keeps (owner plan, Energy section 8).
//!
//! The seams in [`crate::seams`] are fixed at boot. This module is the live
//! part: a [`Policy`] of atomics the governor and the idle governor read, and
//! limit-checked setters. User space owns the *policy* (`userspace/services/
//! power` applies a profile through `PowerPolicy`); the kernel only enforces
//! *limits*, and a setter outside them is refused and recorded:
//!
//! | Setter | Refused when |
//! |---|---|
//! | [`Policy::set_governor`] | no model; anything but `Fixed` or `DeadlineFloor` (bare schedutil cannot honour I1) |
//! | [`Policy::set_opp_range`] | unknown domain; `min > max`; `max` past the last OPP; `max` below the WCET reference OPP (I6) or below the admitted real-time floor (I1) |
//! | [`Policy::set_headroom`] | outside [`HEADROOM_MIN_PCT`]`..=`[`HEADROOM_MAX_PCT`] |
//! | [`Policy::set_rate_limit`] | outside [`RATE_LIMIT_MIN_US`]`..=`[`RATE_LIMIT_MAX_US`] |
//! | [`Policy::set_idle_depth`] | deeper than the deepest state any domain lists |
//!
//! A cap that was legal when set can become illegal later (reservations are
//! admitted at run time), so the limits are enforced again at every governor
//! evaluation: [`Policy::clamp`] applies the user's range to the governor's
//! request and then lets the deadline and safety floors win. The idle depth
//! only ever shortens the list of states the idle governor chooses from, so
//! the real-time slack (I3) still applies on top.
//!
//! Every refusal bumps a counter and leaves a record in a small ring
//! ([`Policy::refusal`]); an application bumps `applied`.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering::Relaxed};

use azos_abi::power::*;

use crate::governor::{self, Decision, HEADROOM_PCT, RATE_LIMIT_US};
use crate::model::{EnergyModel, MAX_DOMAINS};
use crate::seams::Governor;

/// Why a setter refused (the `POLICY_REFUSED_*` code it travels as).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Refusal {
    /// The machine has no energy model.
    NoModel = POLICY_REFUSED_NO_MODEL as u8,
    /// Not a governor user space may choose.
    Governor = POLICY_REFUSED_GOVERNOR as u8,
    /// No such domain.
    Domain = POLICY_REFUSED_DOMAIN as u8,
    /// Empty or out-of-table OPP range.
    Range = POLICY_REFUSED_RANGE as u8,
    /// Cap below the WCET reference OPP (I6).
    SafetyFloor = POLICY_REFUSED_SAFETY_FLOOR as u8,
    /// Cap below the admitted real-time floor (I1).
    DeadlineFloor = POLICY_REFUSED_DEADLINE_FLOOR as u8,
    /// Headroom outside its limits.
    Headroom = POLICY_REFUSED_HEADROOM as u8,
    /// Rate limit outside its limits.
    RateLimit = POLICY_REFUSED_RATE_LIMIT as u8,
    /// Deeper than any idle state.
    IdleDepth = POLICY_REFUSED_IDLE_DEPTH as u8,
}

impl Refusal {
    /// The wire code.
    pub const fn code(self) -> u32 {
        self as u8 as u32
    }
}

/// Which setter a record is about, as its `POWER_OP_POLICY_*` number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    /// [`Policy::set_governor`].
    Governor = POWER_OP_POLICY_GOVERNOR as u8,
    /// [`Policy::set_opp_range`].
    OppRange = POWER_OP_POLICY_OPP_RANGE as u8,
    /// [`Policy::set_headroom`].
    Headroom = POWER_OP_POLICY_HEADROOM as u8,
    /// [`Policy::set_rate_limit`].
    RateLimit = POWER_OP_POLICY_RATE_LIMIT as u8,
    /// [`Policy::set_idle_depth`].
    IdleDepth = POWER_OP_POLICY_IDLE_DEPTH as u8,
}

/// Refusal records kept (the most recent).
pub const LOG_LEN: usize = 8;
/// Governor value as stored.
const GOV_FIXED: u8 = 0;
const GOV_SCHEDUTIL: u8 = 1;
const GOV_DEADLINE: u8 = 2;
/// "No cap" / "no limit" in the 8-bit fields.
pub const NONE_U8: u8 = u8::MAX;

/// The live policy. All reads and writes are relaxed atomics: a setter races
/// with a governor evaluation harmlessly (either sees the old or the new
/// value, and [`Policy::clamp`] re-checks the floors at each evaluation).
pub struct Policy {
    governor: AtomicU8,
    opp_min: [AtomicU8; MAX_DOMAINS],
    opp_max: [AtomicU8; MAX_DOMAINS],
    headroom_pct: AtomicU32,
    rate_limit_us: AtomicU32,
    idle_depth: AtomicU8,
    applied: AtomicU32,
    refused: AtomicU32,
    floor_wins: AtomicU32,
    by_reason: [AtomicU32; POLICY_REFUSED_COUNT],
    log: [AtomicU64; LOG_LEN],
}

impl Policy {
    /// Boot state: the governor `g` the seams chose, no OPP cap, today's
    /// headroom and rate limit, no idle limit.
    pub const fn new(g: Governor) -> Self {
        Self {
            governor: AtomicU8::new(gov_code(g)),
            opp_min: [const { AtomicU8::new(0) }; MAX_DOMAINS],
            opp_max: [const { AtomicU8::new(NONE_U8) }; MAX_DOMAINS],
            headroom_pct: AtomicU32::new(HEADROOM_PCT),
            rate_limit_us: AtomicU32::new(RATE_LIMIT_US as u32),
            idle_depth: AtomicU8::new(NONE_U8),
            applied: AtomicU32::new(0),
            refused: AtomicU32::new(0),
            floor_wins: AtomicU32::new(0),
            by_reason: [const { AtomicU32::new(0) }; POLICY_REFUSED_COUNT],
            log: [const { AtomicU64::new(0) }; LOG_LEN],
        }
    }

    /// Set the boot governor (the seams' choice), before the scheduler runs.
    pub fn init(&self, g: Governor) {
        self.governor.store(gov_code(g), Relaxed);
    }

    // ── readers ──────────────────────────────────────────────────────────

    /// The governor in force.
    pub fn governor(&self) -> Governor {
        match self.governor.load(Relaxed) {
            GOV_DEADLINE => Governor::DeadlineFloor,
            GOV_SCHEDUTIL => Governor::Schedutil,
            _ => Governor::Fixed,
        }
    }
    /// Schedutil headroom, percent.
    pub fn headroom_pct(&self) -> u32 {
        self.headroom_pct.load(Relaxed)
    }
    /// Shortest interval between evaluations of a domain, microseconds.
    pub fn rate_limit_us(&self) -> u32 {
        self.rate_limit_us.load(Relaxed)
    }
    /// Deepest idle state the idle governor may pick ([`NONE_U8`] = no limit).
    pub fn idle_depth(&self) -> u8 {
        self.idle_depth.load(Relaxed)
    }
    /// Domain `d`'s user range, `(min, max)` ([`NONE_U8`] max = no cap).
    pub fn opp_range(&self, d: usize) -> (u8, u8) {
        match (self.opp_min.get(d), self.opp_max.get(d)) {
            (Some(lo), Some(hi)) => (lo.load(Relaxed), hi.load(Relaxed)),
            _ => (0, NONE_U8),
        }
    }
    /// Setter calls applied.
    pub fn applied(&self) -> u32 {
        self.applied.load(Relaxed)
    }
    /// Setter calls refused.
    pub fn refused(&self) -> u32 {
        self.refused.load(Relaxed)
    }
    /// Refusals with reason code `r`.
    pub fn refused_by(&self, r: usize) -> u32 {
        self.by_reason.get(r).map_or(0, |c| c.load(Relaxed))
    }
    /// Evaluations where a floor overrode the user's cap.
    pub fn floor_wins(&self) -> u32 {
        self.floor_wins.load(Relaxed)
    }
    /// The `i`-th most recent refusal record (0 = newest), packed
    /// `op << 56 | reason << 48 | seq << 32 | arg`: `op` is the
    /// `POWER_OP_POLICY_*` number, `arg` the call's argument as it travels;
    /// 0 = none.
    pub fn refusal(&self, i: usize) -> u64 {
        let n = self.refused.load(Relaxed) as usize;
        if i >= n.min(LOG_LEN) {
            return 0;
        }
        self.log[(n - 1 - i) % LOG_LEN].load(Relaxed)
    }

    // ── setters ──────────────────────────────────────────────────────────

    fn done(&self, op: Op, arg: u32, r: Result<(), Refusal>) -> Result<(), Refusal> {
        match r {
            Ok(()) => {
                self.applied.fetch_add(1, Relaxed);
            }
            Err(why) => {
                let n = self.refused.fetch_add(1, Relaxed);
                self.by_reason[why as usize].fetch_add(1, Relaxed);
                if !cfg!(feature = "pl-record-canary") {
                    let rec = (op as u64) << 56
                        | (why as u64) << 48
                        | ((n as u64) & 0xFFFF) << 32
                        | arg as u64;
                    self.log[n as usize % LOG_LEN].store(rec, Relaxed);
                }
            }
        }
        r
    }

    /// Choose the frequency governor (`POLICY_GOV_*`).
    pub fn set_governor(&self, model: &EnergyModel, gov: u32) -> Result<(), Refusal> {
        let r = if !model.is_present() {
            Err(Refusal::NoModel)
        } else {
            match gov as u64 {
                POLICY_GOV_FIXED => {
                    self.governor.store(GOV_FIXED, Relaxed);
                    Ok(())
                }
                POLICY_GOV_DEADLINE_FLOOR => {
                    self.governor.store(GOV_DEADLINE, Relaxed);
                    Ok(())
                }
                _ => Err(Refusal::Governor),
            }
        };
        self.done(Op::Governor, gov, r)
    }

    /// Restrict domain `domain` to OPPs `min..=max`. `admitted_ppm` is the
    /// real-time density admitted on the domain's most loaded hart (the
    /// caller reads it from the ledger).
    pub fn set_opp_range(
        &self,
        model: &EnergyModel,
        domain: u32,
        min: u32,
        max: u32,
        admitted_ppm: u32,
    ) -> Result<(), Refusal> {
        // The wire form of the argument (`POWER_OP_POLICY_OPP_RANGE`).
        let arg = (domain & 0xFF) | (min & 0xFF) << 8 | (max & 0xFF) << 16;
        let r = (|| {
            if !model.is_present() {
                return Err(Refusal::NoModel);
            }
            let Some(d) = model.domains().get(domain as usize) else {
                return Err(Refusal::Domain);
            };
            if min > max || max as usize >= d.opps().len() {
                return Err(Refusal::Range);
            }
            if (max as usize) < governor::safety_floor_opp(d) && !cfg!(feature = "pl-floor-canary") {
                return Err(Refusal::SafetyFloor);
            }
            if (max as usize) < governor::deadline_floor_opp(d, admitted_ppm) && !cfg!(feature = "pl-floor-canary") {
                return Err(Refusal::DeadlineFloor);
            }
            self.opp_min[domain as usize].store(min as u8, Relaxed);
            self.opp_max[domain as usize].store(max as u8, Relaxed);
            Ok(())
        })();
        self.done(Op::OppRange, arg, r)
    }

    /// Set the schedutil headroom, percent.
    pub fn set_headroom(&self, pct: u32) -> Result<(), Refusal> {
        let r = if (POLICY_HEADROOM_MIN_PCT..=POLICY_HEADROOM_MAX_PCT).contains(&pct) {
            self.headroom_pct.store(pct, Relaxed);
            Ok(())
        } else {
            Err(Refusal::Headroom)
        };
        self.done(Op::Headroom, pct, r)
    }

    /// Set the shortest interval between governor evaluations, microseconds.
    pub fn set_rate_limit(&self, us: u32) -> Result<(), Refusal> {
        let r = if (POLICY_RATE_LIMIT_MIN_US..=POLICY_RATE_LIMIT_MAX_US).contains(&us) {
            self.rate_limit_us.store(us, Relaxed);
            Ok(())
        } else {
            Err(Refusal::RateLimit)
        };
        self.done(Op::RateLimit, us, r)
    }

    /// Limit the idle governor to states `0..=depth` ([`POLICY_IDLE_UNLIMITED`]
    /// lifts the limit). Refused deeper than any state the model lists.
    pub fn set_idle_depth(&self, model: &EnergyModel, depth: u32) -> Result<(), Refusal> {
        let deepest = model.domains().iter().map(|d| d.idle_states().len()).max().unwrap_or(0).saturating_sub(1);
        let r = if !model.is_present() {
            Err(Refusal::NoModel)
        } else if depth == POLICY_IDLE_UNLIMITED {
            self.idle_depth.store(NONE_U8, Relaxed);
            Ok(())
        } else if depth as usize > deepest {
            Err(Refusal::IdleDepth)
        } else {
            self.idle_depth.store(depth as u8, Relaxed);
            Ok(())
        };
        self.done(Op::IdleDepth, depth, r)
    }

    // ── enforcement at evaluation ────────────────────────────────────────

    /// Apply domain `d`'s user range to the governor's decision `dec`, then
    /// let the floors win again: the cap bounds the schedutil request and the
    /// range's floor raises it, but the deadline floor (I1) and the safety
    /// floor (I6) are never lowered. Counts a cap the floors overrode.
    pub fn clamp(&self, d: usize, dec: Decision) -> Decision {
        let (lo, hi) = self.opp_range(d);
        let lo = lo as usize;
        let hi = (hi as usize).max(lo);
        let su = dec.schedutil.max(lo).min(hi);
        if cfg!(feature = "pl-clamp-canary") {
            // Canary: the cap applies to the whole decision, floors included.
            return Decision { opp: dec.opp.max(lo).min(hi), ..dec };
        }
        let out = governor::combine(su, Some(dec.deadline), dec.safety);
        if out.opp > hi {
            self.floor_wins.fetch_add(1, Relaxed);
        }
        out
    }
}

const fn gov_code(g: Governor) -> u8 {
    match g {
        Governor::Fixed => GOV_FIXED,
        Governor::Schedutil => GOV_SCHEDUTIL,
        Governor::DeadlineFloor => GOV_DEADLINE,
    }
}

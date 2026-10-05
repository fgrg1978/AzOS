// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the behavior loop does with the ring-3 ML service's answer — or with
//! its absence.
//!
//! The MLP no longer runs in the kernel. Each cycle the loop asks the ML
//! service (`userspace/services/mlsrv`, `DRV_KIND_ML`) for a class and waits for it
//! with a bounded timeout. This module is the policy for every way that ask
//! can end; the transport lives in the kernel.
//!
//! # The fallback is STOP, and why
//!
//! L1 (`layers::layer_avoid_obstacle`) is the only layer that reacts to an
//! obstacle ahead, and it acts only on a verdict. With no verdict it passes,
//! and L2 (remote VLA) or L3 (explore/patrol) drives — blind to the obstacle
//! the MLP exists to see. Holding the last verdict is the same blindness,
//! delayed: a stale `go_forward` keeps the wheels turning towards whatever
//! appeared since. So when a verdict was expected and did not come, L1 gets
//! the MLP's own obstacle answer, `stop`, and the robot holds still until the
//! service answers again. That costs motion, never safety, and it is what the
//! MLP itself answers for an obstacle, so arbitration needs no new case.
//!
//! # A service that never started is a missing verdict too
//!
//! A verdict is expected whenever ML is enabled (`ml_enabled=1`, a build
//! without `no-ml`), whether or not the kernel managed to start the service.
//! Owner decision 2026-09-28, fail closed: a boot that never started it — no
//! disk, no `MLSRV.ELF`, an image refused by its digest, a `no-mmu` build —
//! holds STOP through L1 exactly as a service that died does. Only an
//! explicit `ml_enabled=0` (or a `no-ml` build) runs with no ML and L1
//! passing: that is configuration, not absence.
//!
//! # Absence is recorded
//!
//! [`MlAbsence`] turns a run of [`ABSENT_RECORD_CYCLES`] cycles in which L1
//! was handed the fallback into one `SAFETY_ML_ABSENT` record per episode.
//! The run length keeps the ordinary start-up gap out of the recorder: every
//! boot's first cycle finds the service not yet registered.

use crate::types::MlpResult;

/// The MLP's `stop` class (`azos_abi::ml_srv::CLASS_STOP`).
pub const CLASS_STOP: u8 = 2;
/// Number of classes; anything at or above is malformed.
pub const CLASSES: u8 = 3;

/// How one cycle's request to the ML service ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MlOutcome {
    /// The service answered with this class.
    Verdict(u8),
    /// It did not answer within the loop's ML budget.
    Late,
    /// The request could not be queued: no task is registered for the kind
    /// (the service died, or never registered), or its queue is full.
    Unavailable,
    /// It answered, but not with a class (short reply, class out of range).
    Malformed,
    /// The kernel never started the service on this boot.
    NotLaunched,
}

/// The verdict L1 acts on for `outcome`.
pub fn mlp_result_for(outcome: MlOutcome) -> MlpResult {
    match outcome {
        MlOutcome::Verdict(c) if c < CLASSES => MlpResult { class: c, valid: true },
        MlOutcome::NotLaunched => never_launched(),
        MlOutcome::Verdict(_) | MlOutcome::Late | MlOutcome::Unavailable | MlOutcome::Malformed => {
            fallback()
        }
    }
}

/// A service that never started is a missing verdict. `ml-absent-canary`
/// restores the answer before owner decision 2026-09-28, "no verdict" (L1
/// passes), which the ML service absent row must catch.
#[cfg(not(feature = "ml-absent-canary"))]
fn never_launched() -> MlpResult {
    fallback()
}

#[cfg(feature = "ml-absent-canary")]
fn never_launched() -> MlpResult {
    MlpResult::none()
}

/// The missing-verdict answer. `ml-fallback-canary` replaces it with "no
/// verdict" — the loop's behaviour before this module, and what the ML
/// service kill row must catch.
#[cfg(not(feature = "ml-fallback-canary"))]
fn fallback() -> MlpResult {
    MlpResult { class: CLASS_STOP, valid: true }
}

#[cfg(feature = "ml-fallback-canary")]
fn fallback() -> MlpResult {
    MlpResult::none()
}

/// Per-outcome counts since boot, for the loop's periodic report.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct MlLinkStats {
    pub verdicts: u64,
    pub late: u64,
    pub unavailable: u64,
    pub malformed: u64,
    pub not_launched: u64,
}

impl MlLinkStats {
    pub const fn new() -> Self {
        MlLinkStats { verdicts: 0, late: 0, unavailable: 0, malformed: 0, not_launched: 0 }
    }

    pub fn note(&mut self, outcome: MlOutcome) {
        match outcome {
            MlOutcome::Verdict(c) if c < CLASSES => self.verdicts += 1,
            MlOutcome::Verdict(_) | MlOutcome::Malformed => self.malformed += 1,
            MlOutcome::Late => self.late += 1,
            MlOutcome::Unavailable => self.unavailable += 1,
            MlOutcome::NotLaunched => self.not_launched += 1,
        }
    }

    /// Cycles L1 was handed the fallback.
    pub fn fallbacks(&self) -> u64 {
        self.late + self.unavailable + self.malformed + self.not_launched
    }
}

/// Consecutive cycles of fallback before the absence is recorded: one second
/// of the loop's 100 ms period.
pub const ABSENT_RECORD_CYCLES: u32 = 10;

/// `SAFETY_ML_ABSENT`'s action codes: the outcome of the cycle it was
/// written on.
pub const ABSENT_NOT_LAUNCHED: u8 = 1;
pub const ABSENT_UNAVAILABLE: u8 = 2;
pub const ABSENT_LATE: u8 = 3;
pub const ABSENT_MALFORMED: u8 = 4;

/// The `SAFETY_ML_ABSENT` action code for a missing-verdict `outcome`; `None`
/// for a verdict.
pub fn absent_action(outcome: MlOutcome) -> Option<u8> {
    match outcome {
        MlOutcome::Verdict(c) if c < CLASSES => None,
        MlOutcome::NotLaunched => Some(ABSENT_NOT_LAUNCHED),
        MlOutcome::Unavailable => Some(ABSENT_UNAVAILABLE),
        MlOutcome::Late => Some(ABSENT_LATE),
        MlOutcome::Verdict(_) | MlOutcome::Malformed => Some(ABSENT_MALFORMED),
    }
}

/// When a run of missing verdicts is to be recorded.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct MlAbsence {
    run: u32,
}

impl MlAbsence {
    pub const fn new() -> Self {
        MlAbsence { run: 0 }
    }

    /// One cycle: its outcome and the verdict L1 was handed for it. Returns
    /// the action code on the one cycle of an episode that must write the
    /// record — the [`ABSENT_RECORD_CYCLES`]-th consecutive cycle whose
    /// missing verdict L1 answered with the STOP fallback. A verdict ends the
    /// episode. A cycle that did not hold STOP (a canary build) neither
    /// records nor counts: the record says STOP was held.
    pub fn note(&mut self, outcome: MlOutcome, handed: &MlpResult) -> Option<u8> {
        let action = match absent_action(outcome) {
            None => {
                self.run = 0;
                return None;
            }
            Some(a) => a,
        };
        if !(handed.valid && handed.class == CLASS_STOP) {
            return None;
        }
        self.run = self.run.saturating_add(1);
        if self.run == ABSENT_RECORD_CYCLES { Some(action) } else { None }
    }
}

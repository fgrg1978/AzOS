// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! OPP actuation: the one seam through which an operating point reaches a
//! clock (and, where the SoC needs it, a regulator).
//!
//! The governor ([`crate::governor`]) and the thermal framework
//! ([`crate::thermal`]) only ever *decide* an OPP index; they touch no
//! hardware. [`OppActuator`] is what applies one. A board implements it with
//! whatever moves its clock: the Raspberry Pi through the VideoCore mailbox
//! (`set-clock-rate`), the JH7110 through the clock and regulator framework.
//! A board with no way to change its clock uses [`NoActuator`], which refuses
//! every request, so the decision is still recorded and the thermal
//! framework still degrades instead of capping.
//!
//! [`Dvfs`] keeps the one piece of state every caller needs: which OPP each
//! domain runs at now. It skips a request that changes nothing (a mailbox
//! round trip or a regulator ramp is not free) and counts what the actuator
//! refused. It does not own the actuator: on a Pi the same firmware mailbox
//! that sets the clock also reads the temperature, so the board passes one
//! hardware object to each call.

use crate::model::{EnergyModel, Opp, MAX_DOMAINS};

/// Why an actuator did not apply an OPP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActuateError {
    /// This board has no way to change the domain's clock.
    Unsupported,
    /// The clock or the firmware refused the rate (out of its range, busy).
    Refused,
    /// The transport failed (a mailbox that never answered, a bus error);
    /// the code is the transport's own.
    Fault(i32),
}

/// Something that can put a performance domain at an operating point.
pub trait OppActuator {
    /// Run `domain` at `opp`. On `Ok` the clock has been requested at
    /// `opp.freq_khz` (and the supply, if the board has one, is at the
    /// matching voltage); a failure leaves the domain where it was.
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError>;
}

/// The actuator of a board that cannot change its clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoActuator;

impl OppActuator for NoActuator {
    fn set_opp(&mut self, _domain: usize, _opp: &Opp) -> Result<(), ActuateError> {
        Err(ActuateError::Unsupported)
    }
}

/// What a [`Dvfs::set`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The domain already ran at this OPP: nothing was sent.
    Unchanged,
    /// The actuator moved the domain.
    Changed,
}

/// "Not known yet" in the per-domain current-OPP table.
const UNKNOWN: u8 = u8::MAX;

/// The current OPP of each domain, and what the actuator did.
pub struct Dvfs {
    cur: [u8; MAX_DOMAINS],
    changed: u32,
    refused: u32,
}

impl Dvfs {
    /// No domain's OPP is known: the first [`Dvfs::set`] of each always goes
    /// to the actuator, unless [`Dvfs::assume`] says where firmware left it.
    pub const fn new() -> Self {
        Self { cur: [UNKNOWN; MAX_DOMAINS], changed: 0, refused: 0 }
    }

    /// Record that `domain` boots at OPP `idx` (read back from firmware).
    pub fn assume(&mut self, domain: usize, idx: usize) {
        if let Some(c) = self.cur.get_mut(domain) {
            *c = idx.min(UNKNOWN as usize - 1) as u8;
        }
    }

    /// The OPP `domain` runs at, if known.
    pub fn current(&self, domain: usize) -> Option<usize> {
        match self.cur.get(domain) {
            Some(&c) if c != UNKNOWN => Some(c as usize),
            _ => None,
        }
    }

    /// Put `domain` at its OPP number `idx` through `act`. `Err(Refused)`
    /// for a domain or index the model does not have; otherwise the
    /// actuator's answer.
    pub fn set<A: OppActuator>(
        &mut self,
        act: &mut A,
        model: &EnergyModel,
        domain: usize,
        idx: usize,
    ) -> Result<Applied, ActuateError> {
        let opp = *model
            .domains()
            .get(domain)
            .and_then(|d| d.opps().get(idx))
            .ok_or(ActuateError::Refused)?;
        if self.current(domain) == Some(idx) {
            return Ok(Applied::Unchanged);
        }
        match act.set_opp(domain, &opp) {
            Ok(()) => {
                self.cur[domain] = idx as u8;
                self.changed += 1;
                Ok(Applied::Changed)
            }
            Err(e) => {
                self.refused += 1;
                Err(e)
            }
        }
    }

    /// Requests the actuator applied.
    pub fn changed(&self) -> u32 {
        self.changed
    }

    /// Requests the actuator refused.
    pub fn refused(&self) -> u32 {
        self.refused
    }
}

impl Default for Dvfs {
    fn default() -> Self {
        Self::new()
    }
}

// ── The governor's assertion: its choice reached the clock ──────────────────
//
// The governor decides in the tick (`azos_sched::energy::gov_maybe`), where no
// clock may be moved (a mailbox round trip, a rail over I2C); the board's task
// applies the choice later through [`Dvfs::set`], judges the answer with
// [`check_applied`] and acknowledges it to the governor. The governor asserts
// the acknowledgement came: a domain the board can move whose choice is still
// not acknowledged after the apply deadline is overdue ([`apply_overdue`]),
// which catches an apply path that stopped (or never ran) as well as a clock
// that refuses. A board with no actuator is not a failure: nothing there can
// move a clock, and the answer says so instead of counting a refusal.

/// What became of the governor's choice for one domain at one apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovApply {
    /// The domain runs at the governor's choice.
    Applied,
    /// The domain runs below the choice: the heat capped it (the thermal
    /// framework's cap).
    Capped,
    /// The domain runs above the choice: the deadline or safety floor the
    /// apply step put on it held it up.
    Raised,
    /// The board has no way to move this domain's clock
    /// ([`ActuateError::Unsupported`]): the choice is recorded, never applied.
    NoActuator,
    /// The actuator refused or failed: the choice did not reach the clock.
    Unapplied(ActuateError),
}

/// Judge the answer `r` of the [`Dvfs::set`] that asked for `target`, the
/// OPP the apply step made of the governor's choice `want` (lower under a
/// heat cap, higher under a floor).
pub fn check_applied(want: usize, target: usize, r: Result<Applied, ActuateError>) -> GovApply {
    match r {
        Err(_) if cfg!(feature = "apply-canary") => GovApply::Applied,
        Err(ActuateError::Unsupported) => GovApply::NoActuator,
        Err(e) => GovApply::Unapplied(e),
        Ok(_) => match target.cmp(&want) {
            core::cmp::Ordering::Equal => GovApply::Applied,
            core::cmp::Ordering::Less => GovApply::Capped,
            core::cmp::Ordering::Greater => GovApply::Raised,
        },
    }
}

impl GovApply {
    /// The choice reached the clock (at it, or at the cap or floor the apply
    /// step put on it).
    pub const fn reached(self) -> bool {
        matches!(self, GovApply::Applied | GovApply::Capped | GovApply::Raised)
    }

    /// The number a decision record carries for it: 0 applied, 1 capped,
    /// 2 raised, 3 no actuator, 4 refused, 5 a transport fault, 6 overdue
    /// (no answer at all by the deadline, [`apply_overdue`]).
    pub const fn code(self) -> u32 {
        match self {
            GovApply::Applied => 0,
            GovApply::Capped => 1,
            GovApply::Raised => 2,
            GovApply::NoActuator => 3,
            GovApply::Unapplied(ActuateError::Refused | ActuateError::Unsupported) => 4,
            GovApply::Unapplied(ActuateError::Fault(_)) => 5,
        }
    }
}

/// [`GovApply::code`]'s number for a choice no apply step answered by the
/// deadline.
pub const APPLY_OVERDUE: u32 = 6;

/// Is the governor's choice `decided` (an OPP index) overdue? `acked` is the
/// choice the apply step last answered for (any outcome), `since` when
/// `decided` was made and `now` the time, both in the same unit as
/// `deadline`. A choice already answered is never overdue, whatever the
/// answer: a refusal is the answer's to report.
pub fn apply_overdue(decided: u8, acked: u8, since: u64, now: u64, deadline: u64) -> bool {
    if cfg!(feature = "apply-overdue-canary") {
        return false;
    }
    decided != acked && now.saturating_sub(since) > deadline
}

/// What a new apply outcome means to the record: the first apply that did
/// not reach the clock after one that did (or after none) is recorded as a
/// refusal, the first that reached it again as the recovery; every other one
/// is only counted, so a clock that keeps refusing at the governor's rate
/// leaves one record, not one per evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyRecord {
    /// Nothing to record.
    None,
    /// The choice stopped reaching the clock.
    Lost,
    /// The choice reaches the clock again.
    Back,
}

/// See [`ApplyRecord`]. `was_lost`: the domain's last outcome did not reach
/// the clock (an `Unapplied`, or an overdue choice).
pub fn apply_record(was_lost: bool, now: GovApply) -> ApplyRecord {
    match now {
        GovApply::Unapplied(_) if !was_lost => ApplyRecord::Lost,
        n if n.reached() && was_lost => ApplyRecord::Back,
        _ => ApplyRecord::None,
    }
}

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

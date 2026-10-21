// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A clock, reset, rail, pin-mux or power-domain change is a recorded effect:
//! the manager hands the effect to an [`EffectSink`] BEFORE it touches a
//! register, and a refused effect leaves the hardware alone. The kernel's
//! sink forwards to the write-ahead effect gate (`azos_actuation::effect_gate`)
//! through [`Effect::wire`]; tests use a sink that keeps what it was given.
//!
//! The class follows the gate's rule. A change toward quiescence (gate a
//! clock, assert a reset, cut a rail, power a domain off) is [`Class::Safe`]:
//! it is never refused, a task entitled to switch a thing on must always be
//! able to switch it off. Everything else is [`Class::Reversible`]: it needs
//! its record, and a sink that cannot record refuses it.

use crate::{Error, Result};

/// Effect kinds on the gate's wire (`KIND_MOTOR` is 1).
pub const KIND_CLOCK: u8 = 2;
pub const KIND_RESET: u8 = 3;
pub const KIND_REGULATOR: u8 = 4;
pub const KIND_PINCTRL: u8 = 5;
pub const KIND_POWER_DOMAIN: u8 = 6;

/// Same numbers as the gate's `Class`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Class {
    Safe = 0,
    Reversible = 1,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Op {
    Enable = 1,
    Disable = 2,
    SetRate = 3,
    Assert = 4,
    Deassert = 5,
    SetVoltage = 6,
    SetMux = 7,
    SetBias = 8,
    PowerOn = 9,
    PowerOff = 10,
    SetConf = 11,
}

/// One change, as the record describes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Effect {
    /// One of the `KIND_*` numbers.
    pub kind: u8,
    pub op: Op,
    pub class: Class,
    /// Index of the provider in its manager.
    pub provider: u8,
    /// Clock, reset, domain id or pin word (0 for a regulator).
    pub id: u32,
    /// The new rate in Hz, voltage in microvolts, bias number, pad
    /// configuration (`Conf::wire`) (0 for a change that has no argument).
    pub value: u64,
}

impl Effect {
    /// The gate's four fields: `(kind, subject, a0, a1)`. Subject is the
    /// provider index in its high byte and the op in its low byte; `a0` the
    /// id; `a1` the value, saturated to 32 bits.
    pub fn wire(&self) -> (u8, u16, u32, u32) {
        (self.kind, (self.provider as u16) << 8 | self.op as u16, self.id, self.value.min(u32::MAX as u64) as u32)
    }
}

/// A sink that would not take the effect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refused {
    /// The refusal's decision-record id, 0 when there is none.
    pub receipt: u64,
}

/// Where effects are committed.
pub trait EffectSink {
    /// Record `e`. `Ok` means the hardware op may go ahead.
    fn commit(&mut self, e: &Effect) -> core::result::Result<(), Refused>;
}

/// Commit `e`, then run `op` (the register write); or refuse without running
/// it. A refused [`Class::Reversible`] effect is an error; a [`Class::Safe`]
/// one goes ahead regardless. The order is structural: no manager calls a
/// provider's hardware op except through here. Public for the one caller that
/// cannot go through a manager because of how long the write takes: the K1's
/// rail step ([`crate::k1::P1Buck::write_uv`]), which must not run under the
/// managers' lock.
pub fn issue<R>(fx: &mut dyn EffectSink, e: Effect, op: impl FnOnce() -> Result<R>) -> Result<R> {
    // Gate canary (host suite only, feature `effect-after-write-canary`): the
    // register write first, the record after. The ordering rows must fail.
    #[cfg(feature = "effect-after-write-canary")]
    {
        let r = op();
        let _ = fx.commit(&e);
        r
    }
    #[cfg(not(feature = "effect-after-write-canary"))]
    {
        match fx.commit(&e) {
            Ok(()) => {}
            Err(_) if e.class == Class::Safe => {}
            Err(r) => return Err(Error::Refused(r.receipt)),
        }
        op()
    }
}

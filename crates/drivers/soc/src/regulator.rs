// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The regulator framework: one provider per rail, reference-counted enable,
//! voltage requests held to the rail's device-tree constraints, and the
//! consumer lookup of `<name>-supply`.
//!
//! Constraints come from the rail's node: `regulator-min-microvolt`,
//! `regulator-max-microvolt` (both absent: the voltage is not adjustable) and
//! `regulator-always-on` (the rail is switched on by
//! [`Regulators::enable_always_on`] at boot and the framework holds a
//! reference on it for good). A voltage request is a range `[min, max]`; the
//! rail gets the lowest voltage in the range the constraints allow.

use crate::effect::{self, issue, Class, Effect, EffectSink, Op};
use crate::fdt::{Fdt, NodeId};
use crate::{consumer, Bus, Error, I2cBus, Result};

pub const MAX_REGULATORS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reg(pub u8);

/// The rail's limits, from its device-tree node.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Constraints {
    /// Microvolts; both 0 when the node sets no voltage range.
    pub min_uv: u32,
    pub max_uv: u32,
    /// `regulator-ramp-delay`: microvolts per microsecond, 0 when the node
    /// does not say. A lower bound on the slew, not a guarantee of it.
    pub ramp_uv_per_us: u32,
    pub always_on: bool,
}

/// What a rail's registers are reached through: the SoC's 32-bit register
/// space, and (when the image has a master for it) the serial bus a PMIC
/// sits on.
pub struct Io<'a> {
    /// Register access in the SoC's address space.
    pub bus: &'a mut dyn Bus,
    /// The I2C master PMIC rails go through; `None` when the image has none.
    pub i2c: Option<&'a mut dyn I2cBus>,
}

/// One rail.
pub trait RegulatorOps {
    /// Does the provider reach its rail over I2C? A rail that does is only
    /// registered when the image has a master for it.
    fn needs_i2c(&self) -> bool {
        false
    }
    /// Can the rail's registers be reached right now? A rail behind an I2C
    /// master the kernel has not attached yet cannot; the framework leaves it
    /// for a later call of [`Regulators::enable_always_on`] (the kernel's, once
    /// the master is attached: `Soc::retry_always_on`) instead of
    /// recording an effect for a write that cannot happen.
    fn reachable(&self, io: &Io<'_>) -> bool {
        let _ = io;
        true
    }
    fn enable(&mut self, io: &mut Io<'_>) -> Result<()>;
    fn disable(&mut self, io: &mut Io<'_>) -> Result<()>;
    fn is_enabled(&mut self, io: &mut Io<'_>) -> Result<bool>;
    /// The voltage now, microvolts.
    fn voltage(&mut self, io: &mut Io<'_>) -> Result<u32>;
    /// Set exactly `uv` microvolts (the framework already checked the
    /// constraints); a rail with a fixed voltage answers `Unsupported`
    /// for any other.
    fn set_voltage(&mut self, io: &mut Io<'_>, uv: u32) -> Result<()>;
}

struct Slot<'p> {
    node: NodeId,
    ops: &'p mut dyn RegulatorOps,
    constraints: Constraints,
    refs: u16,
    /// The permanent `always-on` reference is taken.
    pinned: bool,
}

pub struct Regulators<'p> {
    slots: [Option<Slot<'p>>; MAX_REGULATORS],
}

impl<'p> Default for Regulators<'p> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'p> Regulators<'p> {
    pub const fn new() -> Self {
        Regulators { slots: [const { None }; MAX_REGULATORS] }
    }

    /// Register the rail that is `node`, with the constraints its node sets.
    pub fn add(&mut self, fdt: &Fdt<'_>, node: NodeId, ops: &'p mut dyn RegulatorOps) -> Result<Reg> {
        let constraints = Constraints {
            min_uv: fdt.u32_prop(node, "regulator-min-microvolt").unwrap_or(0),
            max_uv: fdt.u32_prop(node, "regulator-max-microvolt").unwrap_or(0),
            ramp_uv_per_us: fdt.u32_prop(node, "regulator-ramp-delay").unwrap_or(0),
            always_on: fdt.has_prop(node, "regulator-always-on"),
        };
        if constraints.min_uv > constraints.max_uv {
            return Err(Error::Constraint);
        }
        let i = self.slots.iter().position(|s| s.is_none()).ok_or(Error::Full)?;
        self.slots[i] = Some(Slot { node, ops, constraints, refs: 0, pinned: false });
        Ok(Reg(i as u8))
    }

    /// The rail `<name>-supply` of `consumer` names.
    pub fn get_supply(&self, fdt: &Fdt<'_>, consumer: NodeId, name: &str) -> Result<Reg> {
        let mut buf = [0u8; 48];
        let suffix = b"-supply";
        if name.len() + suffix.len() > buf.len() {
            return Err(Error::BadSpec);
        }
        buf[..name.len()].copy_from_slice(name.as_bytes());
        buf[name.len()..name.len() + suffix.len()].copy_from_slice(suffix);
        let prop = core::str::from_utf8(&buf[..name.len() + suffix.len()]).map_err(|_| Error::BadSpec)?;
        let node = consumer::phandle(fdt, consumer, prop)?;
        self.slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.node == node))
            .map(|i| Reg(i as u8))
            .ok_or(Error::NoProvider)
    }

    fn slot(&mut self, r: Reg) -> Result<&mut Slot<'p>> {
        self.slots.get_mut(r.0 as usize).and_then(|s| s.as_mut()).ok_or(Error::NoProvider)
    }

    pub fn constraints(&self, r: Reg) -> Option<Constraints> {
        self.slots.get(r.0 as usize)?.as_ref().map(|s| s.constraints)
    }

    pub fn refs(&self, r: Reg) -> u16 {
        self.slots.get(r.0 as usize).and_then(|s| s.as_ref()).map_or(0, |s| s.refs)
    }

    /// Switch on every rail marked `regulator-always-on` and hold a
    /// reference on it for good. Returns how many rails it switched on. A
    /// rail that will not switch on does not keep the others off: every rail
    /// is tried, and the first error is returned after the last.
    ///
    /// A rail that cannot be reached yet ([`RegulatorOps::reachable`]: a PMIC
    /// behind an I2C master the kernel attaches after the frameworks come up)
    /// is not tried and is not an error: it is [`Regulators::always_on_pending`]
    /// until a later call finds it reachable. The machine is running on it in
    /// the meantime, so leaving it unpinned for a while is truthful; what is
    /// not allowed is a write the transport cannot make, recorded as an effect.
    pub fn enable_always_on(&mut self, io: &mut Io<'_>, fx: &mut dyn EffectSink) -> Result<usize> {
        let mut n = 0;
        let mut first_err = None;
        for i in 0..MAX_REGULATORS {
            let want = self.slots[i].as_ref().is_some_and(|s| s.constraints.always_on && !s.pinned && s.ops.reachable(io));
            if want {
                match self.enable(io, fx, Reg(i as u8)) {
                    Ok(()) => {
                        self.slot(Reg(i as u8))?.pinned = true;
                        n += 1;
                    }
                    Err(e) => {
                        first_err.get_or_insert(e);
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(n),
        }
    }

    /// Rails marked `regulator-always-on` that no reference is held on yet:
    /// not reachable when [`Regulators::enable_always_on`] ran, or refused.
    pub fn always_on_pending(&self) -> u8 {
        self.slots.iter().flatten().filter(|s| s.constraints.always_on && !s.pinned).count() as u8
    }

    /// Take a reference; the first one switches the rail on.
    pub fn enable(&mut self, io: &mut Io<'_>, fx: &mut dyn EffectSink, r: Reg) -> Result<()> {
        let refs = self.slot(r)?.refs;
        if refs == 0 {
            let s = self.slot(r)?;
            issue(fx, fx_of(r, Op::Enable, Class::Reversible, 0), || s.ops.enable(io))?;
        }
        self.slot(r)?.refs = refs + 1;
        Ok(())
    }

    /// Drop a reference; the last one switches the rail off. An always-on
    /// rail's own reference is never dropped, so it stays on.
    pub fn disable(&mut self, io: &mut Io<'_>, fx: &mut dyn EffectSink, r: Reg) -> Result<()> {
        let s = self.slot(r)?;
        let floor = u16::from(s.pinned);
        if s.refs <= floor {
            return Err(Error::Unbalanced);
        }
        if s.refs == 1 {
            let s = self.slot(r)?;
            issue(fx, fx_of(r, Op::Disable, Class::Safe, 0), || s.ops.disable(io))?;
        }
        self.slot(r)?.refs -= 1;
        Ok(())
    }

    pub fn is_enabled(&mut self, io: &mut Io<'_>, r: Reg) -> Result<bool> {
        self.slot(r)?.ops.is_enabled(io)
    }

    pub fn voltage(&mut self, io: &mut Io<'_>, r: Reg) -> Result<u32> {
        self.slot(r)?.ops.voltage(io)
    }

    /// Ask for a voltage in `min_uv..=max_uv`. The rail gets the lowest one
    /// the constraints allow; no overlap, or no voltage constraints on the
    /// rail's node, is `Constraint`. Returns the voltage set.
    pub fn set_voltage(&mut self, io: &mut Io<'_>, fx: &mut dyn EffectSink, r: Reg, min_uv: u32, max_uv: u32) -> Result<u32> {
        let c = self.slot(r)?.constraints;
        if c.max_uv == 0 || min_uv > max_uv {
            return Err(Error::Constraint);
        }
        let lo = min_uv.max(c.min_uv);
        let hi = max_uv.min(c.max_uv);
        if lo > hi {
            return Err(Error::Constraint);
        }
        let s = self.slot(r)?;
        issue(fx, fx_of(r, Op::SetVoltage, Class::Reversible, lo as u64), || s.ops.set_voltage(io, lo))?;
        Ok(lo)
    }
}

fn fx_of(r: Reg, op: Op, class: Class, value: u64) -> Effect {
    Effect { kind: effect::KIND_REGULATOR, op, class, provider: r.0, id: 0, value }
}

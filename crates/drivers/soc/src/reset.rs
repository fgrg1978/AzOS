// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The reset framework: lines a provider asserts and deasserts, and the
//! consumer lookup of `resets` / `reset-names`. A line has one owner at a
//! time (an exclusive reset): the manager keeps no count, the caller's
//! driver decides when its device is in reset. Asserting is toward the safe
//! state (never refused); releasing a reset is the effect that needs its
//! record.

use crate::consumer::{self, Entry, Sel};
use crate::effect::{self, issue, Class, Effect, EffectSink, Op};
use crate::fdt::{Fdt, NodeId};
use crate::{Bus, Error, Result};

pub const MAX_PROVIDERS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rst {
    pub prov: u8,
    pub id: u16,
}

/// One reset controller.
pub trait ResetOps {
    /// Line ids are `0..count()`.
    fn count(&self) -> u32;
    /// Hold `id` in reset.
    fn assert(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()>;
    /// Release `id`, and return once the controller reports it released.
    fn deassert(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()>;
    /// Is `id` held in reset now.
    fn is_asserted(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool>;
}

struct Slot<'p> {
    node: NodeId,
    ops: &'p mut dyn ResetOps,
}

pub struct Resets<'p> {
    slots: [Option<Slot<'p>>; MAX_PROVIDERS],
}

impl<'p> Default for Resets<'p> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'p> Resets<'p> {
    pub const fn new() -> Self {
        Resets { slots: [const { None }; MAX_PROVIDERS] }
    }

    /// Register the controller that is `node`; returns its provider index.
    pub fn add(&mut self, node: NodeId, ops: &'p mut dyn ResetOps) -> Result<u8> {
        let i = self.slots.iter().position(|s| s.is_none()).ok_or(Error::Full)?;
        self.slots[i] = Some(Slot { node, ops });
        Ok(i as u8)
    }

    /// The line `sel` of `consumer`'s `resets` property.
    pub fn get(&self, fdt: &Fdt<'_>, consumer: NodeId, sel: Sel<'_>) -> Result<Rst> {
        self.from_entry(&consumer::lookup(fdt, consumer, "resets", "reset-names", "#reset-cells", sel)?)
    }

    /// The line a resolved entry of the list names.
    pub fn from_entry(&self, e: &Entry<'_>) -> Result<Rst> {
        let prov = self
            .slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.node == e.provider))
            .ok_or(Error::NoProvider)?;
        let id = e.id()?;
        if id >= self.slots[prov].as_ref().ok_or(Error::NoProvider)?.ops.count() {
            return Err(Error::BadSpec);
        }
        Ok(Rst { prov: prov as u8, id: id as u16 })
    }

    fn slot(&mut self, r: Rst) -> Result<&mut Slot<'p>> {
        let s = self.slots.get_mut(r.prov as usize).and_then(|s| s.as_mut()).ok_or(Error::NoProvider)?;
        if r.id as u32 >= s.ops.count() {
            return Err(Error::BadSpec);
        }
        Ok(s)
    }

    pub fn assert(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, r: Rst) -> Result<()> {
        let s = self.slot(r)?;
        issue(fx, fx_of(r, Op::Assert, Class::Safe), || s.ops.assert(bus, r.id as u32))
    }

    pub fn deassert(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, r: Rst) -> Result<()> {
        let s = self.slot(r)?;
        issue(fx, fx_of(r, Op::Deassert, Class::Reversible), || s.ops.deassert(bus, r.id as u32))
    }

    /// Assert, then release: a reset pulse.
    pub fn pulse(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, r: Rst) -> Result<()> {
        self.assert(bus, fx, r)?;
        self.deassert(bus, fx, r)
    }

    pub fn is_asserted(&mut self, bus: &mut dyn Bus, r: Rst) -> Result<bool> {
        self.slot(r)?.ops.is_asserted(bus, r.id as u32)
    }
}

fn fx_of(r: Rst, op: Op, class: Class) -> Effect {
    Effect { kind: effect::KIND_RESET, op, class, provider: r.prov, id: r.id as u32, value: 0 }
}

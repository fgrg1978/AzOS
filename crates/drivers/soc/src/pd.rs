// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The power-domain framework: domains a provider switches on and off,
//! reference-counted, and the consumer lookup of `power-domains` /
//! `power-domain-names`. The first user powers the domain on, the last one
//! powers it off. Domains do not nest here (no `power-domains` on a domain
//! node); a SoC with nested domains orders them in its provider.

use crate::consumer::{self, Entry, Sel};
use crate::effect::{self, issue, Class, Effect, EffectSink, Op};
use crate::fdt::{Fdt, NodeId};
use crate::{Bus, Error, Result};

pub const MAX_PROVIDERS: usize = 2;
pub const MAX_DOMAINS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pd {
    pub prov: u8,
    pub id: u8,
}

/// One power controller.
pub trait PowerDomainOps {
    /// Domain ids are `0..count()`.
    fn count(&self) -> u32;
    fn power_on(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()>;
    fn power_off(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()>;
    fn is_on(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool>;
}

struct Slot<'p> {
    node: NodeId,
    ops: &'p mut dyn PowerDomainOps,
    refs: [u16; MAX_DOMAINS],
}

pub struct PowerDomains<'p> {
    slots: [Option<Slot<'p>>; MAX_PROVIDERS],
}

impl<'p> Default for PowerDomains<'p> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'p> PowerDomains<'p> {
    pub const fn new() -> Self {
        PowerDomains { slots: [const { None }; MAX_PROVIDERS] }
    }

    pub fn add(&mut self, node: NodeId, ops: &'p mut dyn PowerDomainOps) -> Result<u8> {
        if ops.count() as usize > MAX_DOMAINS {
            return Err(Error::Full);
        }
        let i = self.slots.iter().position(|s| s.is_none()).ok_or(Error::Full)?;
        self.slots[i] = Some(Slot { node, ops, refs: [0; MAX_DOMAINS] });
        Ok(i as u8)
    }

    /// The domain `sel` of `consumer`'s `power-domains` property.
    pub fn get(&self, fdt: &Fdt<'_>, consumer: NodeId, sel: Sel<'_>) -> Result<Pd> {
        self.from_entry(&consumer::lookup(fdt, consumer, "power-domains", "power-domain-names", "#power-domain-cells", sel)?)
    }

    /// The domain a resolved entry of the list names.
    pub fn from_entry(&self, e: &Entry<'_>) -> Result<Pd> {
        let prov = self
            .slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.node == e.provider))
            .ok_or(Error::NoProvider)?;
        let id = e.id()?;
        if id >= self.slots[prov].as_ref().ok_or(Error::NoProvider)?.ops.count() {
            return Err(Error::BadSpec);
        }
        Ok(Pd { prov: prov as u8, id: id as u8 })
    }

    fn slot(&mut self, d: Pd) -> Result<&mut Slot<'p>> {
        let s = self.slots.get_mut(d.prov as usize).and_then(|s| s.as_mut()).ok_or(Error::NoProvider)?;
        if d.id as u32 >= s.ops.count() {
            return Err(Error::BadSpec);
        }
        Ok(s)
    }

    pub fn refs(&self, d: Pd) -> u16 {
        self.slots
            .get(d.prov as usize)
            .and_then(|s| s.as_ref())
            .and_then(|s| s.refs.get(d.id as usize).copied())
            .unwrap_or(0)
    }

    /// Take a reference; the first one powers the domain on.
    pub fn on(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, d: Pd) -> Result<()> {
        let refs = self.refs(d);
        if refs == 0 {
            let s = self.slot(d)?;
            issue(fx, fx_of(d, Op::PowerOn, Class::Reversible), || s.ops.power_on(bus, d.id as u32))?;
        }
        self.slot(d)?.refs[d.id as usize] = refs + 1;
        Ok(())
    }

    /// Drop a reference; the last one powers the domain off.
    pub fn off(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, d: Pd) -> Result<()> {
        let refs = self.refs(d);
        if refs == 0 {
            return Err(Error::Unbalanced);
        }
        if refs == 1 {
            let s = self.slot(d)?;
            issue(fx, fx_of(d, Op::PowerOff, Class::Safe), || s.ops.power_off(bus, d.id as u32))?;
        }
        self.slot(d)?.refs[d.id as usize] = refs - 1;
        Ok(())
    }

    pub fn is_on(&mut self, bus: &mut dyn Bus, d: Pd) -> Result<bool> {
        self.slot(d)?.ops.is_on(bus, d.id as u32)
    }
}

fn fx_of(d: Pd, op: Op, class: Class) -> Effect {
    Effect { kind: effect::KIND_POWER_DOMAIN, op, class, provider: d.prov, id: d.id as u32, value: 0 }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The clock framework: a tree of clocks across providers, reference-counted
//! gating (parents first on the way up, children first on the way down),
//! rates, and the consumer lookup of `clocks` / `clock-names`.
//!
//! A provider ([`ClockOps`]) implements one clock controller: its clocks are
//! numbered `0..count()`, each has at most one parent, either another clock
//! of the same controller ([`Parent::Local`]) or one of the controller's own
//! `clocks` inputs ([`Parent::Input`], named by `clock-names` and resolved to
//! another provider's clock by [`ClockTree::link`]). The tree owns the counts:
//! an enabled clock holds one reference on its parent, so a parent is gated
//! only when its last enabled child and its last direct user are gone.
//!
//! A clock that was left running by the boot firmware has no reference here
//! and is gated by the first release of a matching enable only; the
//! framework does not guess which boot-enabled clocks are in use.

use crate::consumer::{self, Entry, Sel};
use crate::effect::{self, issue, Class, Effect, EffectSink, Op};
use crate::fdt::{Fdt, NodeId};
use crate::{Bus, Error, Result};

/// Controllers a tree holds.
pub const MAX_PROVIDERS: usize = 6;
/// Clocks per controller (JH7110 sys has fewer than 200).
pub const MAX_CLOCKS: usize = 256;
/// Longest parent chain.
pub const MAX_DEPTH: usize = 8;
/// External inputs (`clocks` entries) per controller.
pub const MAX_INPUTS: usize = 16;

/// A clock of a registered controller.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Clk {
    pub prov: u8,
    pub id: u16,
}

/// Where a clock's input comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Parent {
    /// A root.
    None,
    /// Another clock of the same controller.
    Local(u32),
    /// Entry `i` of [`ClockOps::input_names`].
    Input(u8),
}

/// One clock controller.
pub trait ClockOps {
    /// Clock ids are `0..count()`.
    fn count(&self) -> u32;
    /// Does the provider implement clock `id` (`id < count()`)? A controller
    /// whose binding numbers more clocks than the provider models (the K1's
    /// APMU holds the CPU clusters' and fifty peripheral clocks) answers
    /// `false` for the rest: a consumer of one of those resolves to
    /// [`Error::NoProvider`], which the bind step skips as "not modelled"
    /// (the firmware left it as it is) instead of failing the device.
    fn modelled(&self, id: u32) -> bool {
        id < self.count()
    }
    /// The `clock-names` of the controller's own inputs that
    /// [`Parent::Input`] indexes. Empty for a controller with none.
    fn input_names(&self) -> &'static [&'static str] {
        &[]
    }
    /// Where `id` gets its input now (a mux reads its select field).
    fn parent(&mut self, bus: &mut dyn Bus, id: u32) -> Result<Parent>;
    /// Does `id` have a gate. A clock without one (a divider, a mux, a
    /// fixed clock) is counted but never switched: `enable` and `disable`
    /// are not called for it and it produces no effect record.
    fn gated(&self, id: u32) -> bool;
    /// Open the gate of `id`.
    fn enable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()>;
    /// Close the gate of `id`.
    fn disable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()>;
    /// Is the gate of `id` open.
    fn is_enabled(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool>;
    /// The rate of `id` given its parent's (0 for a root that has no rate of
    /// its own to report is a provider bug: a fixed clock reports its rate).
    fn rate(&mut self, bus: &mut dyn Bus, id: u32, parent_rate: u64) -> Result<u64>;
    /// Set `id` to the closest rate it can make and return that rate.
    fn set_rate(&mut self, bus: &mut dyn Bus, id: u32, rate: u64, parent_rate: u64) -> Result<u64>;
    /// The rate [`ClockOps::set_rate`] would reach for `rate`, writing
    /// nothing. A consumer that must know the real frequency before it moves
    /// (the K1's rail has to carry the clock that results, not the one that
    /// was asked for) uses it. A provider that cannot tell answers
    /// `Unsupported`.
    fn round_rate(&mut self, bus: &mut dyn Bus, id: u32, rate: u64, parent_rate: u64) -> Result<u64> {
        let _ = (bus, id, rate, parent_rate);
        Err(Error::Unsupported)
    }
}

struct Slot<'p> {
    node: NodeId,
    ops: &'p mut dyn ClockOps,
    inputs: [Option<Clk>; MAX_INPUTS],
    refs: [u16; MAX_CLOCKS],
}

/// The `clocks` entry of controller `node` that is its input `k`, called
/// `name`: by `clock-names`, or by position when the node has no
/// `clock-names` (a binding with one unnamed input, `starfive,jh7110-pll`).
pub fn input_entry<'a>(fdt: &Fdt<'a>, node: NodeId, k: usize, name: &str) -> Result<Entry<'a>> {
    let sel = if fdt.has_prop(node, "clock-names") { Sel::Name(name) } else { Sel::Index(k) };
    consumer::lookup(fdt, node, "clocks", "clock-names", "#clock-cells", sel)
}

/// The clock tree: up to [`MAX_PROVIDERS`] controllers.
pub struct ClockTree<'p> {
    slots: [Option<Slot<'p>>; MAX_PROVIDERS],
}

impl<'p> Default for ClockTree<'p> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'p> ClockTree<'p> {
    pub const fn new() -> Self {
        ClockTree { slots: [const { None }; MAX_PROVIDERS] }
    }

    /// Register the controller that is `node` of the device tree. Returns its
    /// provider index. Call [`ClockTree::link`] once every controller is in.
    pub fn add(&mut self, node: NodeId, ops: &'p mut dyn ClockOps) -> Result<u8> {
        if ops.count() as usize > MAX_CLOCKS || ops.input_names().len() > MAX_INPUTS {
            return Err(Error::Full);
        }
        let i = self.slots.iter().position(|s| s.is_none()).ok_or(Error::Full)?;
        self.slots[i] = Some(Slot { node, ops, inputs: [None; MAX_INPUTS], refs: [0; MAX_CLOCKS] });
        Ok(i as u8)
    }

    /// Resolve every controller's named inputs (its `clocks` entries) to
    /// clocks of the registered controllers. An input the tree does not name,
    /// or whose provider is not registered, stays unresolved: a clock that
    /// needs it answers `NoProvider` when it is used.
    pub fn link(&mut self, fdt: &Fdt<'_>) {
        for i in 0..MAX_PROVIDERS {
            let (node, names) = match &self.slots[i] {
                Some(s) => (s.node, s.ops.input_names()),
                None => continue,
            };
            for (k, name) in names.iter().enumerate() {
                let found = input_entry(fdt, node, k, name).ok().and_then(|e| self.resolve(&e));
                if let Some(s) = self.slots[i].as_mut() {
                    s.inputs[k] = found;
                }
            }
        }
    }

    fn resolve(&self, e: &consumer::Entry<'_>) -> Option<Clk> {
        let prov = self.slots.iter().position(|s| s.as_ref().is_some_and(|s| s.node == e.provider))?;
        let id = e.id().ok()?;
        let s = self.slots[prov].as_ref()?;
        if !s.ops.modelled(id) {
            return None;
        }
        Some(Clk { prov: prov as u8, id: id as u16 })
    }

    /// The clock `sel` of `consumer`'s `clocks` property.
    pub fn get(&self, fdt: &Fdt<'_>, consumer: NodeId, sel: Sel<'_>) -> Result<Clk> {
        self.from_entry(&consumer::lookup(fdt, consumer, "clocks", "clock-names", "#clock-cells", sel)?)
    }

    /// The clock a resolved entry of any clock list (`clocks`,
    /// `assigned-clocks`) names.
    pub fn from_entry(&self, e: &Entry<'_>) -> Result<Clk> {
        let prov = self
            .slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.node == e.provider))
            .ok_or(Error::NoProvider)?;
        let id = e.id()?;
        let s = self.slots[prov].as_ref().ok_or(Error::NoProvider)?;
        if id >= s.ops.count() {
            return Err(Error::BadSpec);
        }
        if !s.ops.modelled(id) {
            return Err(Error::NoProvider);
        }
        Ok(Clk { prov: prov as u8, id: id as u16 })
    }

    fn slot(&mut self, clk: Clk) -> Result<&mut Slot<'p>> {
        let s = self.slots.get_mut(clk.prov as usize).and_then(|s| s.as_mut()).ok_or(Error::NoProvider)?;
        if clk.id as u32 >= s.ops.count() {
            return Err(Error::BadSpec);
        }
        Ok(s)
    }

    /// The parent of `clk` now, `None` for a root.
    pub fn parent(&mut self, bus: &mut dyn Bus, clk: Clk) -> Result<Option<Clk>> {
        let s = self.slot(clk)?;
        match s.ops.parent(bus, clk.id as u32)? {
            Parent::None => Ok(None),
            Parent::Local(id) => {
                if id >= s.ops.count() {
                    return Err(Error::BadSpec);
                }
                Ok(Some(Clk { prov: clk.prov, id: id as u16 }))
            }
            Parent::Input(i) => match s.inputs.get(i as usize).copied().flatten() {
                Some(p) => Ok(Some(p)),
                None => Err(Error::NoProvider),
            },
        }
    }

    /// `clk` and its ancestors, `clk` first; the count.
    fn chain(&mut self, bus: &mut dyn Bus, clk: Clk) -> Result<([Clk; MAX_DEPTH], usize)> {
        let mut out = [clk; MAX_DEPTH];
        let mut n = 1;
        while let Some(p) = self.parent(bus, out[n - 1])? {
            if n == MAX_DEPTH || out[..n].contains(&p) {
                return Err(Error::Depth);
            }
            out[n] = p;
            n += 1;
        }
        Ok((out, n))
    }

    /// References held on `clk` (direct users plus enabled children).
    pub fn refs(&self, clk: Clk) -> u16 {
        self.slots
            .get(clk.prov as usize)
            .and_then(|s| s.as_ref())
            .and_then(|s| s.refs.get(clk.id as usize).copied())
            .unwrap_or(0)
    }

    /// Is `clk` running: its gate is open, or it has none.
    pub fn is_enabled(&mut self, bus: &mut dyn Bus, clk: Clk) -> Result<bool> {
        let s = self.slot(clk)?;
        if !s.ops.gated(clk.id as u32) {
            return Ok(true);
        }
        s.ops.is_enabled(bus, clk.id as u32)
    }

    /// The rate of `clk`, computed from the root down.
    pub fn rate(&mut self, bus: &mut dyn Bus, clk: Clk) -> Result<u64> {
        let (chain, n) = self.chain(bus, clk)?;
        let mut rate = 0u64;
        for c in chain[..n].iter().rev() {
            rate = self.slot(*c)?.ops.rate(bus, c.id as u32, rate)?;
        }
        Ok(rate)
    }

    /// Set `clk` to the closest rate its controller can make, return the rate
    /// reached. A change of rate does not change the clock's children's
    /// dividers: their rates follow, which the consumers see on the next
    /// [`ClockTree::rate`].
    pub fn set_rate(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, clk: Clk, hz: u64) -> Result<u64> {
        let (chain, n) = self.chain(bus, clk)?;
        let mut parent_rate = 0u64;
        for c in chain[1..n].iter().rev() {
            parent_rate = self.slot(*c)?.ops.rate(bus, c.id as u32, parent_rate)?;
        }
        let s = self.slot(clk)?;
        issue(fx, fx_of(clk, Op::SetRate, Class::Reversible, hz), || s.ops.set_rate(bus, clk.id as u32, hz, parent_rate))
    }

    /// The rate [`ClockTree::set_rate`] would reach for `hz`, computed from the
    /// registers as they are now; nothing is written and nothing is recorded.
    pub fn round_rate(&mut self, bus: &mut dyn Bus, clk: Clk, hz: u64) -> Result<u64> {
        let (chain, n) = self.chain(bus, clk)?;
        let mut parent_rate = 0u64;
        for c in chain[1..n].iter().rev() {
            parent_rate = self.slot(*c)?.ops.rate(bus, c.id as u32, parent_rate)?;
        }
        self.slot(clk)?.ops.round_rate(bus, clk.id as u32, hz, parent_rate)
    }

    /// Take a reference on `clk`. The first one opens the gates up the chain,
    /// root first; if one step fails (the hardware or a refused effect), the
    /// gates already opened are closed again and nothing is counted.
    pub fn enable(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, clk: Clk) -> Result<()> {
        let (chain, n) = self.chain(bus, clk)?;
        // The clocks that go 0 -> 1: from `clk` up to (not including) the
        // first ancestor that is already held.
        let mut first_held = n;
        for (k, c) in chain[..n].iter().enumerate() {
            if self.refs(*c) > 0 {
                first_held = k;
                break;
            }
        }
        for k in (0..first_held).rev() {
            let c = chain[k];
            let res = self.slot(c).and_then(|s| {
                if !s.ops.gated(c.id as u32) {
                    return Ok(());
                }
                issue(fx, fx_of(c, Op::Enable, Class::Reversible, 1), || s.ops.enable(bus, c.id as u32))
            });
            if let Err(e) = res {
                for u in chain[k + 1..first_held].iter() {
                    let _ = self.slot(*u).and_then(|s| {
                        if !s.ops.gated(u.id as u32) {
                            return Ok(());
                        }
                        issue(fx, fx_of(*u, Op::Disable, Class::Safe, 0), || s.ops.disable(bus, u.id as u32))
                    });
                }
                return Err(e);
            }
        }
        // Counted only now, so a failure above left every count alone. Each
        // clock that just opened is held once, by its enabled child (or, for
        // `clk` itself, by the caller).
        for c in chain[..first_held].iter() {
            self.slot(*c)?.refs[c.id as usize] = 1;
        }
        if first_held < n {
            // `clk` itself (index 0) was already held: one more direct user;
            // otherwise the ancestor that was already held gains the child.
            let a = chain[first_held];
            self.slot(a)?.refs[a.id as usize] += 1;
        }
        Ok(())
    }

    /// Drop a reference on `clk`. The last one closes its gate, and each
    /// ancestor whose last holder this was.
    pub fn disable(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, clk: Clk) -> Result<()> {
        let (chain, n) = self.chain(bus, clk)?;
        for c in chain[..n].iter() {
            let refs = self.refs(*c);
            if refs == 0 {
                return Err(Error::Unbalanced);
            }
            if refs > 1 {
                self.slot(*c)?.refs[c.id as usize] = refs - 1;
                return Ok(());
            }
            let s = self.slot(*c)?;
            if s.ops.gated(c.id as u32) {
                issue(fx, fx_of(*c, Op::Disable, Class::Safe, 0), || s.ops.disable(bus, c.id as u32))?;
            }
            s.refs[c.id as usize] = 0;
        }
        Ok(())
    }
}

fn fx_of(c: Clk, op: Op, class: Class, value: u64) -> Effect {
    Effect { kind: effect::KIND_CLOCK, op, class, provider: c.prov, id: c.id as u32, value }
}

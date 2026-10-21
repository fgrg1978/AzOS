// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The consumer side, once for every driver the kernel binds to a
//! device-tree node: [`bind`] gives the node's device what its properties ask
//! the SoC for, [`unbind`] takes it back.
//!
//! `bind` applies, in this order (a device's registers are only safe to touch
//! after the last step):
//!
//! 1. `power-domains`: every entry powered on;
//! 2. `assigned-clocks` / `assigned-clock-rates`: each clock set to its rate
//!    (a `0` rate leaves the clock alone);
//! 3. `clocks`: every entry enabled (the manager walks the parent chain);
//! 4. `resets`: every entry deasserted;
//! 5. `pinctrl-names` / `pinctrl-N`: the state named `default`.
//!
//! Every change is the manager's own, so each is a recorded effect that
//! reaches the sink before the register. The whole DT side is read first: a
//! list that cannot be parsed, or a provider's argument that is out of
//! range, fails the bind before any hardware was touched.
//!
//! **Failure** unwinds what was done, newest first, with the quiescent
//! operations (power off, clock disable, reset assert), which the effect
//! sinks never refuse, so the unwind cannot itself be refused. Two things are
//! not undone, because the frameworks have no inverse: a clock's rate
//! (nothing kept the old one; it is configuration that outlives a bind) and
//! the pin mux (a pad stays routed; there is no "deselect"). The pin state is
//! last, so a pin failure unwinds the three steps before it.
//!
//! **Not modelled is not an error.** An entry whose provider node has no
//! registered provider ([`Error::NoProvider`]: the image has no driver for
//! that SoC family, or the manager was full) is skipped and counted in
//! [`Applied::unmodelled`]: the firmware left that resource as it is and the
//! kernel cannot manage what it has no provider for. Anything else (a
//! refused effect, a hardware timeout, a specifier out of range, a phandle
//! that is not in the tree) fails.
//!
//! [`unbind`] recomputes the same lists from the immutable tree (nothing is
//! stored per node) and reverses: the `sleep` pin state if the node names
//! one, resets asserted, clocks disabled, domains powered off, each in the
//! reverse order. It keeps going after an error and returns the first. Call
//! it only for a node [`bind`] succeeded for: the managers count references,
//! and an unbalanced release is an error. A reset line has no reference
//! count here, so a line shared by two nodes is asserted when either one
//! unbinds.
//!
//! Who calls this is the driver registry (`kernel/src/boot/soc.rs`): only a
//! kernel driver that the hardware bus bound ([`azos_hwbus::Drivers::resources`])
//! gets here. A node whose driver is a ring-3 server or the Linux slice never
//! does: it asks for its resources through its device interface.

use crate::boot::Soc;
use crate::clk::Clk;
use crate::consumer::{self, Entry, Sel};
use crate::effect::EffectSink;
use crate::fdt::{cell, Fdt, NodeId};
use crate::pd::Pd;
use crate::reset::Rst;
use crate::{Bus, Error, Result};

/// Entries one list can hold; a longer list is [`Error::Full`].
pub const MAX_ENTRIES: usize = 16;

/// What [`bind`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Applied {
    pub domains: u8,
    /// `assigned-clock-rates` applied.
    pub rates: u8,
    pub clocks: u8,
    pub resets: u8,
    /// The `default` pin state was applied.
    pub pins: bool,
    /// Entries skipped because their provider is not registered.
    pub unmodelled: u8,
}

/// The resolved entries of one list; a placeholder or an unmodelled entry is
/// `None` and keeps its index.
struct List<T> {
    v: [Option<T>; MAX_ENTRIES],
    n: usize,
    unmodelled: u8,
}

impl<T: Copy> List<T> {
    fn read(
        fdt: &Fdt<'_>,
        node: NodeId,
        prop: &str,
        cells_prop: &str,
        resolve: impl Fn(&Entry<'_>) -> Result<T>,
    ) -> Result<Self> {
        let n = consumer::count(fdt, node, prop, cells_prop)?;
        if n > MAX_ENTRIES {
            return Err(Error::Full);
        }
        let mut l = List { v: [None; MAX_ENTRIES], n, unmodelled: 0 };
        for i in 0..n {
            let Some(e) = consumer::slot(fdt, node, prop, cells_prop, i)? else { continue };
            match resolve(&e) {
                Ok(t) => l.v[i] = Some(t),
                Err(Error::NoProvider) => l.unmodelled += 1,
                Err(e) => return Err(e),
            }
        }
        Ok(l)
    }

    fn items(&self) -> impl DoubleEndedIterator<Item = T> + '_ {
        self.v[..self.n].iter().flatten().copied()
    }

    fn len(&self) -> u8 {
        self.items().count() as u8
    }
}

/// Apply `step(item, true)` to each item in order. On the first failure apply
/// `step(item, false)` to the ones done, newest first, and return the error.
/// Returns how many were applied.
fn up<T: Copy>(list: &List<T>, mut step: impl FnMut(T, bool) -> Result<()>) -> Result<u8> {
    for (done, t) in list.items().enumerate() {
        if let Err(e) = step(t, true) {
            let mut undo = [None; MAX_ENTRIES];
            for (k, u) in list.items().take(done).enumerate() {
                undo[k] = Some(u);
            }
            for u in undo[..done].iter().rev().flatten() {
                let _ = step(*u, false);
            }
            return Err(e);
        }
    }
    Ok(list.len())
}

/// Reverse every item, newest first, whatever fails; the first error is
/// returned.
fn down<T: Copy>(list: &List<T>, mut step: impl FnMut(T, bool) -> Result<()>) -> Result<()> {
    let mut first = Ok(());
    for t in list.items().rev() {
        if let Err(e) = step(t, false) {
            if first.is_ok() {
                first = Err(e);
            }
        }
    }
    first
}

/// Everything a node asks for, resolved against the registered providers; no
/// hardware is touched to build it.
struct Plan {
    domains: List<Pd>,
    /// `assigned-clocks` with the rate of the same index (0: none).
    assigned: List<(Clk, u64)>,
    clocks: List<Clk>,
    resets: List<Rst>,
    /// The node names a `default` / `sleep` pin state.
    default_pins: bool,
    sleep_pins: bool,
}

impl Plan {
    fn read(soc: &Soc<'_>, fdt: &Fdt<'_>, node: NodeId) -> Result<Plan> {
        let domains = List::read(fdt, node, "power-domains", "#power-domain-cells", |e| soc.domains.from_entry(e))?;
        let ac = List::read(fdt, node, "assigned-clocks", "#clock-cells", |e| soc.clocks.from_entry(e))?;
        let rates = fdt.prop(node, "assigned-clock-rates").unwrap_or(&[]);
        // The rate cell of the same index; a clock with none, or 0, stays as it is.
        let assigned = List {
            v: core::array::from_fn(|i| match (ac.v[i], cell(rates, i)) {
                (Some(c), Some(hz)) if hz != 0 => Some((c, hz as u64)),
                _ => None,
            }),
            n: ac.n,
            unmodelled: ac.unmodelled,
        };
        let clocks = List::read(fdt, node, "clocks", "#clock-cells", |e| soc.clocks.from_entry(e))?;
        let resets = List::read(fdt, node, "resets", "#reset-cells", |e| soc.resets.from_entry(e))?;
        let named = |name: &str| consumer::index_of(fdt, node, "pinctrl-names", name).is_ok();
        Ok(Plan { domains, assigned, clocks, resets, default_pins: named("default"), sleep_pins: named("sleep") })
    }
}

/// Give the device `node` names what its properties ask the SoC for. See the
/// module doc for the order and for what an error leaves behind.
pub fn bind(
    soc: &mut Soc<'_>,
    fdt: &Fdt<'_>,
    bus: &mut dyn Bus,
    fx: &mut dyn EffectSink,
    node: NodeId,
) -> Result<Applied> {
    let plan = Plan::read(soc, fdt, node)?;
    let mut a = Applied {
        unmodelled: plan.domains.unmodelled + plan.assigned.unmodelled + plan.clocks.unmodelled + plan.resets.unmodelled,
        ..Applied::default()
    };

    a.domains = up(&plan.domains, |d, on| if on { soc.domains.on(bus, fx, d) } else { soc.domains.off(bus, fx, d) })?;

    // Rates before the gates open: the clock changes speed while nothing
    // runs from it. Not undone (module doc).
    let mut rates = 0u8;
    let mut r = Ok(());
    for (c, hz) in plan.assigned.items() {
        r = soc.clocks.set_rate(bus, fx, c, hz).map(|_| ());
        if r.is_err() {
            break;
        }
        rates += 1;
    }
    if let Err(e) = r {
        let _ = down(&plan.domains, |d, _| soc.domains.off(bus, fx, d));
        return Err(e);
    }
    a.rates = rates;

    match up(&plan.clocks, |c, on| if on { soc.clocks.enable(bus, fx, c) } else { soc.clocks.disable(bus, fx, c) }) {
        Ok(n) => a.clocks = n,
        Err(e) => {
            let _ = down(&plan.domains, |d, _| soc.domains.off(bus, fx, d));
            return Err(e);
        }
    }

    match up(&plan.resets, |r, release| if release { soc.resets.deassert(bus, fx, r) } else { soc.resets.assert(bus, fx, r) }) {
        Ok(n) => a.resets = n,
        Err(e) => {
            let _ = down(&plan.clocks, |c, _| soc.clocks.disable(bus, fx, c));
            let _ = down(&plan.domains, |d, _| soc.domains.off(bus, fx, d));
            return Err(e);
        }
    }

    #[cfg(not(feature = "bind-skip-pinctrl-canary"))]
    if plan.default_pins {
        match soc.pins.select(bus, fx, fdt, node, Sel::Name("default")) {
            Ok(()) => a.pins = true,
            // The pad controller is not one the image has a provider for.
            Err(Error::NoProvider) => a.unmodelled += 1,
            Err(e) => {
                let _ = down(&plan.resets, |r, _| soc.resets.assert(bus, fx, r));
                let _ = down(&plan.clocks, |c, _| soc.clocks.disable(bus, fx, c));
                let _ = down(&plan.domains, |d, _| soc.domains.off(bus, fx, d));
                return Err(e);
            }
        }
    }
    Ok(a)
}

/// Reverse [`bind`] for `node`. Keeps going after an error; returns the first.
pub fn unbind(
    soc: &mut Soc<'_>,
    fdt: &Fdt<'_>,
    bus: &mut dyn Bus,
    fx: &mut dyn EffectSink,
    node: NodeId,
) -> Result<()> {
    let plan = Plan::read(soc, fdt, node)?;
    let mut first = Ok(());
    let mut note = |r: Result<()>| {
        if first.is_ok() {
            first = r;
        }
    };
    if plan.sleep_pins {
        note(match soc.pins.select(bus, fx, fdt, node, Sel::Name("sleep")) {
            Err(Error::NoProvider) => Ok(()),
            r => r,
        });
    }
    note(down(&plan.resets, |r, _| soc.resets.assert(bus, fx, r)));
    note(down(&plan.clocks, |c, _| soc.clocks.disable(bus, fx, c)));
    note(down(&plan.domains, |d, _| soc.domains.off(bus, fx, d)));
    first
}

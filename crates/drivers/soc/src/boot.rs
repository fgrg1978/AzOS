// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot step: the providers a device tree describes, and the five
//! managers built over them.
//!
//! Two parts, because the managers borrow their providers and a kernel static
//! cannot hold both a value and a borrow of it:
//!
//! * [`Storage::scan`] walks the tree once and fills the provider slots (the
//!   caller places the [`Storage`] where it lives for good: the kernel leaks
//!   one box);
//! * [`Soc::build`] registers the stored providers with a [`ClockTree`],
//!   [`Resets`], [`Regulators`], [`PowerDomains`] and [`Pinctrl`], links the clock inputs
//!   and switches on the rails marked `regulator-always-on`.
//!
//! Nothing here writes a register, with one exception that is not hardware:
//! the always-on rails go through the effect sink like every other change,
//! and a fixed rail's state is kept in the provider. The hardware is touched
//! by the first consumer (a driver's clock enable, the thermal cap).
//!
//! Which providers exist is the caller's [`Families`] and the tree's
//! `compatible` strings; the slot counts are the managers' own limits. The
//! fixed clocks that are inputs of a registered controller come first (the
//! controller cannot compute a rate without them), then any other
//! `fixed-clock` node while slots are left; what does not fit is counted in
//! [`Report::dropped`], never silently lost.
//!
//! Not modelled (the first consumer that needs one adds it): the JH7110 PLL
//! block, the always-on and storage clock generators' clocks, a switchable or
//! adjustable rail (the PMIC).

use crate::clk::{self, ClockOps, ClockTree, Parent};
use crate::consumer::{self, Sel};
use crate::effect::EffectSink;
use crate::fdt::{Fdt, NodeId};
use crate::fixed::{FixedClock, FixedRegulator};
use crate::jh7110::{Jh7110Clk, Jh7110Iomux, Jh7110Pmu, Jh7110Reset};
use crate::k1::{K1Clk, P1Buck};
use crate::pd::{self, PowerDomains};
use crate::pinctrl::{self, Pinctrl};
use crate::regulator::{self, Io, RegulatorOps, Regulators};
use crate::reset::{self, Resets};
use crate::{Bus, Error, Result};

/// The hardware families this image compiles providers for (Kconfig
/// `SOC_JH7110`, `SOC_K1`). The generic providers, `fixed-clock` and
/// `regulator-fixed`, need no family.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Families {
    /// StarFive JH7110: system clock and reset controller, reset blocks, PMU,
    /// system and always-on pad controllers.
    pub jh7110: bool,
    /// SpacemiT K1: the CPU cluster clocks with their PLL tree, and the P1
    /// PMIC's bucks.
    pub k1: bool,
}

/// One clock controller of any family, so the tree's slots share a type.
pub enum ClkProvider {
    Fixed(FixedClock),
    Jh7110(Jh7110Clk),
    K1(K1Clk),
}

impl ClkProvider {
    fn ops(&self) -> &dyn ClockOps {
        match self {
            ClkProvider::Fixed(c) => c,
            ClkProvider::Jh7110(c) => c,
            ClkProvider::K1(c) => c,
        }
    }
    fn ops_mut(&mut self) -> &mut dyn ClockOps {
        match self {
            ClkProvider::Fixed(c) => c,
            ClkProvider::Jh7110(c) => c,
            ClkProvider::K1(c) => c,
        }
    }
}

impl ClockOps for ClkProvider {
    fn count(&self) -> u32 {
        self.ops().count()
    }
    fn modelled(&self, id: u32) -> bool {
        self.ops().modelled(id)
    }
    fn input_names(&self) -> &'static [&'static str] {
        self.ops().input_names()
    }
    fn parent(&mut self, bus: &mut dyn Bus, id: u32) -> Result<Parent> {
        self.ops_mut().parent(bus, id)
    }
    fn gated(&self, id: u32) -> bool {
        self.ops().gated(id)
    }
    fn enable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        self.ops_mut().enable(bus, id)
    }
    fn disable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        self.ops_mut().disable(bus, id)
    }
    fn is_enabled(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool> {
        self.ops_mut().is_enabled(bus, id)
    }
    fn rate(&mut self, bus: &mut dyn Bus, id: u32, parent_rate: u64) -> Result<u64> {
        self.ops_mut().rate(bus, id, parent_rate)
    }
    fn set_rate(&mut self, bus: &mut dyn Bus, id: u32, rate: u64, parent_rate: u64) -> Result<u64> {
        self.ops_mut().set_rate(bus, id, rate, parent_rate)
    }
    fn round_rate(&mut self, bus: &mut dyn Bus, id: u32, rate: u64, parent_rate: u64) -> Result<u64> {
        self.ops_mut().round_rate(bus, id, rate, parent_rate)
    }
}

/// One rail of any family, so the regulator slots share a type.
pub enum RegProvider {
    Fixed(FixedRegulator),
    P1(P1Buck),
}

impl RegProvider {
    fn ops_mut(&mut self) -> &mut dyn RegulatorOps {
        match self {
            RegProvider::Fixed(r) => r,
            RegProvider::P1(r) => r,
        }
    }
}

impl RegulatorOps for RegProvider {
    fn needs_i2c(&self) -> bool {
        matches!(self, RegProvider::P1(_))
    }
    fn reachable(&self, io: &Io<'_>) -> bool {
        match self {
            RegProvider::Fixed(r) => r.reachable(io),
            RegProvider::P1(r) => r.reachable(io),
        }
    }
    fn enable(&mut self, io: &mut Io<'_>) -> Result<()> {
        self.ops_mut().enable(io)
    }
    fn disable(&mut self, io: &mut Io<'_>) -> Result<()> {
        self.ops_mut().disable(io)
    }
    fn is_enabled(&mut self, io: &mut Io<'_>) -> Result<bool> {
        self.ops_mut().is_enabled(io)
    }
    fn voltage(&mut self, io: &mut Io<'_>) -> Result<u32> {
        self.ops_mut().voltage(io)
    }
    fn set_voltage(&mut self, io: &mut Io<'_>, uv: u32) -> Result<()> {
        self.ops_mut().set_voltage(io, uv)
    }
}

/// The providers a tree describes, each with the node it is.
pub struct Storage {
    clk: [Option<(NodeId, ClkProvider)>; clk::MAX_PROVIDERS],
    rst: [Option<(NodeId, Jh7110Reset)>; reset::MAX_PROVIDERS],
    pd: [Option<(NodeId, Jh7110Pmu)>; pd::MAX_PROVIDERS],
    pin: [Option<(NodeId, Jh7110Iomux)>; pinctrl::MAX_PROVIDERS],
    reg: [Option<(NodeId, RegProvider)>; regulator::MAX_REGULATORS],
    dropped: u8,
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}

/// Store `v` for `node` in the first free slot of `slots`: nothing when the
/// node is already there, one more `dropped` when no slot is left.
fn put<T>(slots: &mut [Option<(NodeId, T)>], dropped: &mut u8, node: NodeId, v: T) {
    if slots.iter().flatten().any(|(n, _)| *n == node) {
        return;
    }
    match slots.iter_mut().find(|s| s.is_none()) {
        Some(s) => *s = Some((node, v)),
        None => *dropped = dropped.saturating_add(1),
    }
}

impl Storage {
    pub const fn new() -> Self {
        Storage {
            clk: [const { None }; clk::MAX_PROVIDERS],
            rst: [const { None }; reset::MAX_PROVIDERS],
            pd: [const { None }; pd::MAX_PROVIDERS],
            pin: [const { None }; pinctrl::MAX_PROVIDERS],
            reg: [const { None }; regulator::MAX_REGULATORS],
            dropped: 0,
        }
    }

    /// Fill the slots from `fdt`. Call once, on an empty storage.
    pub fn scan(&mut self, fdt: &Fdt<'_>, fam: Families) {
        fdt.walk(|n| {
            if fam.jh7110 {
                if let Some(c) = Jh7110Clk::from_dt(fdt, n) {
                    put(&mut self.clk, &mut self.dropped, n, ClkProvider::Jh7110(c));
                }
                if let Some(r) = Jh7110Reset::from_dt(fdt, n) {
                    put(&mut self.rst, &mut self.dropped, n, r);
                }
                if let Some(p) = Jh7110Pmu::from_dt(fdt, n) {
                    put(&mut self.pd, &mut self.dropped, n, p);
                }
                if let Some(p) = Jh7110Iomux::from_dt(fdt, n) {
                    put(&mut self.pin, &mut self.dropped, n, p);
                }
            }
            if fam.k1 {
                if let Some(c) = K1Clk::from_dt(fdt, n) {
                    put(&mut self.clk, &mut self.dropped, n, ClkProvider::K1(c));
                }
                if let Some(b) = P1Buck::from_dt(fdt, n) {
                    put(&mut self.reg, &mut self.dropped, n, RegProvider::P1(b));
                }
            }
            if let Some(r) = FixedRegulator::from_dt(fdt, n) {
                put(&mut self.reg, &mut self.dropped, n, RegProvider::Fixed(r));
            }
        });
        // The inputs of the controllers found, then the rest.
        for i in 0..self.clk.len() {
            let Some((node, names)) = self.clk[i].as_ref().map(|(n, p)| (*n, p.input_names())) else { continue };
            for name in names {
                let Ok(e) = consumer::lookup(fdt, node, "clocks", "clock-names", "#clock-cells", Sel::Name(name)) else {
                    continue;
                };
                if let Some(c) = FixedClock::from_dt(fdt, e.provider) {
                    put(&mut self.clk, &mut self.dropped, e.provider, ClkProvider::Fixed(c));
                }
            }
        }
        fdt.walk(|n| {
            if let Some(c) = FixedClock::from_dt(fdt, n) {
                put(&mut self.clk, &mut self.dropped, n, ClkProvider::Fixed(c));
            }
        });
    }

    /// Map the register windows `(base, size)` of the providers that have
    /// registers, each once, through `map` (the kernel's device mapping,
    /// `false` when it was refused), and drop every provider whose window was
    /// not mapped: a manager must never touch a register nobody mapped. A
    /// provider dropped here is counted in [`Report::dropped`]. A
    /// window past [`MAX_WINDOWS`] (no tree the families describe has one) is
    /// not mapped and drops its provider the same way.
    pub fn map_windows(&mut self, fdt: &Fdt<'_>, mut map: impl FnMut(u64, u64) -> bool) -> Windows {
        let mut seen = Seen { seen: [(0, 0); MAX_WINDOWS], n: 0, failed: [(0, 0); MAX_WINDOWS], nfailed: 0 };
        for (node, p) in self.clk.iter().flatten() {
            let (ws, k) = clk_windows(fdt, *node, p);
            for w in &ws[..k] {
                seen.want(*w, &mut map);
            }
        }
        for node in self
            .rst
            .iter()
            .flatten()
            .map(|(node, _)| *node)
            .chain(self.pd.iter().flatten().map(|(node, _)| *node))
            .chain(self.pin.iter().flatten().map(|(node, _)| *node))
        {
            if let Some(w) = fdt.reg(node) {
                seen.want(w, &mut map);
            }
        }
        let any_unmapped = seen.nfailed > 0 || seen.n == MAX_WINDOWS;
        if any_unmapped {
            let lost = |node: NodeId| fdt.reg(node).is_some_and(|w| seen.unmapped(&w));
            let mut gone = 0u8;
            for s in self.clk.iter_mut() {
                if matches!(s, Some((node, p)) if { let (ws, k) = clk_windows(fdt, *node, p); ws[..k].iter().any(|w| seen.unmapped(w)) }) {
                    *s = None;
                    gone += 1;
                }
            }
            for s in self.rst.iter_mut() {
                if matches!(s, Some((node, _)) if lost(*node)) {
                    *s = None;
                    gone += 1;
                }
            }
            for s in self.pd.iter_mut() {
                if matches!(s, Some((node, _)) if lost(*node)) {
                    *s = None;
                    gone += 1;
                }
            }
            for s in self.pin.iter_mut() {
                if matches!(s, Some((node, _)) if lost(*node)) {
                    *s = None;
                    gone += 1;
                }
            }
            self.dropped = self.dropped.saturating_add(gone);
        }
        Windows { mapped: (seen.n - seen.nfailed) as u8, failed: seen.nfailed as u8 }
    }
}

/// The register windows of a clock provider: the node's own for a JH7110
/// controller, the three blocks of a K1 complex, none for a fixed clock.
fn clk_windows(fdt: &Fdt<'_>, node: NodeId, p: &ClkProvider) -> ([(u64, u64); 3], usize) {
    let mut ws = [(0, 0); 3];
    match p {
        ClkProvider::Fixed(_) => (ws, 0),
        ClkProvider::Jh7110(_) => match fdt.reg(node) {
            Some(w) => {
                ws[0] = w;
                (ws, 1)
            }
            None => (ws, 0),
        },
        ClkProvider::K1(c) => (c.windows(), 3),
    }
}

/// The windows seen so far, each mapped once.
struct Seen {
    seen: [(u64, u64); MAX_WINDOWS],
    n: usize,
    failed: [(u64, u64); MAX_WINDOWS],
    nfailed: usize,
}

impl Seen {
    /// Was `w` left unmapped: refused by the mapping, or past the room?
    fn unmapped(&self, w: &(u64, u64)) -> bool {
        self.failed[..self.nfailed].contains(w) || !self.seen[..self.n].contains(w)
    }

    fn want(&mut self, w: (u64, u64), map: &mut impl FnMut(u64, u64) -> bool) {
        if self.seen[..self.n].contains(&w) {
            return;
        }
        if self.n == MAX_WINDOWS {
            // No room to track it: it is not mapped (see `Seen::unmapped`).
            return;
        }
        self.seen[self.n] = w;
        self.n += 1;
        if !map(w.0, w.1) {
            self.failed[self.nfailed] = w;
            self.nfailed += 1;
        }
    }
}

/// Windows one clock provider can have (the K1 complex has three).
pub const MAX_CLK_WINDOWS: usize = 3;

/// The most register windows a JH7110 image can map: its register clock
/// controller (the SYSCRG; 4 is the room the table had before the K1 enlarged
/// the clock tree) and one per reset, power-domain and pad controller. A
/// controller that is both a clock and a reset provider shares its window, so
/// this is an upper bound. The kernel's MMIO record budget for the VisionFive
/// 2 is checked against it (`board_drivers_tests`).
pub const MAX_WINDOWS_JH7110: usize = 4 + reset::MAX_PROVIDERS + pd::MAX_PROVIDERS + pinctrl::MAX_PROVIDERS;

/// The most register windows [`Storage::map_windows`] tracks: the JH7110's
/// and the two a K1 complex adds to its one clock controller (a tree has one
/// K1 complex: only its first APMU node is read, see `K1Clk::from_dt`). A
/// window past it is not mapped, and its provider is dropped.
pub const MAX_WINDOWS: usize = MAX_WINDOWS_JH7110 + MAX_CLK_WINDOWS - 1;

/// What [`Storage::map_windows`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Windows {
    /// Windows the mapping accepted.
    pub mapped: u8,
    /// Windows it refused; their providers are dropped.
    pub failed: u8,
}

/// What [`Soc::build`] registered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    pub clocks: u8,
    pub resets: u8,
    pub regulators: u8,
    pub domains: u8,
    pub pin_controllers: u8,
    /// Providers found that no slot was left for.
    pub dropped: u8,
    /// Rails found whose PMIC bus the image has no master for ([`Io::i2c`]
    /// was `None`): not registered, so a consumer of one finds no provider.
    pub no_transport: u8,
    /// `regulator-always-on` rails not switched on and pinned yet: behind an
    /// I2C master that was not attached when the frameworks were built
    /// ([`Soc::retry_always_on`] pins them once it is), or refused.
    pub always_on_pending: u8,
    /// Rails switched on because their node says `regulator-always-on`, or
    /// the error that stopped it.
    pub always_on: core::result::Result<u8, Error>,
}

/// The five managers, over the providers of a [`Storage`].
pub struct Soc<'p> {
    pub clocks: ClockTree<'p>,
    pub resets: Resets<'p>,
    pub regulators: Regulators<'p>,
    pub domains: PowerDomains<'p>,
    pub pins: Pinctrl<'p>,
    pub report: Report,
}

impl<'p> Soc<'p> {
    /// Register `storage`'s providers, resolve the clock inputs against
    /// `fdt` and switch on the always-on rails through `fx`.
    pub fn build(storage: &'p mut Storage, fdt: &Fdt<'_>, io: &mut Io<'_>, fx: &mut dyn EffectSink) -> Soc<'p> {
        let Storage { clk, rst, pd, pin, reg, dropped } = storage;
        let mut clocks = ClockTree::new();
        let mut resets = Resets::new();
        let mut regulators = Regulators::new();
        let mut domains = PowerDomains::new();
        let mut pins = Pinctrl::new();
        let mut report = Report { clocks: 0, resets: 0, regulators: 0, domains: 0, pin_controllers: 0, dropped: *dropped, no_transport: 0, always_on_pending: 0, always_on: Ok(0) };
        // A provider the manager refuses (a controller bigger than its
        // tables) is counted with the ones that found no slot.
        let mut refused = |ok: bool, n: &mut u8| {
            if ok {
                *n += 1;
            } else {
                report.dropped = report.dropped.saturating_add(1);
            }
        };
        let mut counts = [0u8; 5];
        for (node, p) in clk.iter_mut().flatten() {
            refused(clocks.add(*node, p).is_ok(), &mut counts[0]);
        }
        for (node, p) in rst.iter_mut().flatten() {
            refused(resets.add(*node, p).is_ok(), &mut counts[1]);
        }
        let mut no_transport = 0u8;
        for (node, p) in reg.iter_mut().flatten() {
            // A PMIC rail is only registered when the image can reach its
            // bus: a rail that would answer `Unsupported` to everything is
            // not a provider, and `regulator-always-on` must not trip on it.
            if p.needs_i2c() && io.i2c.is_none() {
                no_transport = no_transport.saturating_add(1);
                continue;
            }
            refused(regulators.add(fdt, *node, p).is_ok(), &mut counts[2]);
        }
        for (node, p) in pd.iter_mut().flatten() {
            refused(domains.add(*node, p).is_ok(), &mut counts[3]);
        }
        for (node, p) in pin.iter_mut().flatten() {
            refused(pins.add(*node, p).is_ok(), &mut counts[4]);
        }
        report.clocks = counts[0];
        report.resets = counts[1];
        report.regulators = counts[2];
        report.domains = counts[3];
        report.pin_controllers = counts[4];
        report.no_transport = no_transport;
        clocks.link(fdt);
        report.always_on = regulators.enable_always_on(io, fx).map(|n| n as u8);
        report.always_on_pending = regulators.always_on_pending();
        Soc { clocks, resets, regulators, domains, pins, report }
    }

    /// Run the always-on pass again, for the rails behind an I2C master that
    /// was not attached when [`Soc::build`] ran (`Report::always_on_pending`),
    /// and update the report: the rails newly pinned are added to
    /// `always_on`, the first error is kept in it, and `always_on_pending` is
    /// counted again. The PMIC is read (and written if a rail is off) over
    /// the wire, so the caller must not hold a spin lock across this.
    pub fn retry_always_on(&mut self, io: &mut Io<'_>, fx: &mut dyn EffectSink) {
        match self.regulators.enable_always_on(io, fx) {
            Ok(n) => {
                if let Ok(total) = &mut self.report.always_on {
                    *total = total.saturating_add(n as u8);
                }
            }
            Err(e) => {
                if self.report.always_on.is_ok() {
                    self.report.always_on = Err(e);
                }
            }
        }
        self.report.always_on_pending = self.regulators.always_on_pending();
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The consumer bind (`azos_soc::bind`) over the JH7110 providers with a
//! register model, and the hardware bus's hook that calls it (`Drivers::
//! resources` / `release`).
//!
//! Canary: `--features bind-skip-pinctrl-canary` makes `bind` leave out the
//! pin state; `bind_applies_the_default_pin_state_after_the_resets` must fail.
use crate::support::*;
use azos_hwbus::{self as hw, Access as _, Device, Drivers, Handle, NativeEntry, Pattern, Policy, ProbeError};
use azos_soc::bind::{self, Applied};
use azos_soc::boot::{Families, Soc, Storage};
use azos_soc::regulator::Io;
use azos_soc::clk::Clk;
use azos_soc::consumer::{self, Sel};
use azos_soc::effect::{self, Effect, Op};
use azos_soc::fdt::Fdt;
use azos_soc::jh7110::iomux::{gpiomux, GPI_NONE};
use azos_soc::{Error, NodeId};
use std::rc::Rc;

const SYS_PINS: u32 = 20;
const UART_CFG: u32 = 22;
const SYS_PAD_BASE: u64 = 0x1304_0000;

const FULL: &str = "/soc/serial@10000000";
const PLAIN: &str = "/soc/serial@10001000";
const RATED: &str = "/soc/serial@10002000";
const BAD_RATE: &str = "/soc/serial@10003000";

/// The VisionFive-2 shaped tree the other rows use, plus the pad controller
/// and four consumers: one that asks for everything, one that asks for
/// nothing (QEMU `virt`'s `ns16550a`), one with `assigned-clock-rates` and a
/// `<0>` placeholder, one whose assigned rate its provider cannot make.
fn tree() -> Vec<u8> {
    let mut b = Builder::new();
    b.cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    for (name, ph, hz) in [("oscillator", OSC, 24_000_000), ("pll0", PLL0, 1_000_000_000), ("pll2", PLL2, 1_188_000_000)] {
        b.begin(name).str("compatible", "fixed-clock").cells("#clock-cells", &[0]).cells("clock-frequency", &[hz]).ph(ph).end();
    }
    b.begin("soc").cells("#address-cells", &[2]).cells("#size-cells", &[2]).flag("ranges");
    b.begin("clock-controller@13020000")
        .strs("compatible", &["starfive,jh7110-syscrg"])
        .cells("reg", &[0, 0x1302_0000, 0, 0x10000])
        .cells("clocks", &[OSC, PLL0, PLL2])
        .strs("clock-names", &["osc", "pll0_out", "pll2_out"])
        .cells("#clock-cells", &[1])
        .cells("#reset-cells", &[1])
        .ph(SYSCRG)
        .end();
    b.begin("power-controller@17030000")
        .strs("compatible", &["starfive,jh7110-pmu"])
        .cells("reg", &[0, 0x1703_0000, 0, 0x10000])
        .cells("#power-domain-cells", &[1])
        .ph(PMU)
        .end();
    b.begin("pinctrl@13040000")
        .strs("compatible", &["starfive,jh7110-sys-pinctrl"])
        .cells("reg", &[0, 0x1304_0000, 0, 0x10000])
        .ph(SYS_PINS);
    b.begin("uart0-0").ph(UART_CFG);
    b.begin("tx").cells("pinmux", &[gpiomux(5, 20, 0, GPI_NONE)]).flag("bias-disable").end();
    b.end();
    b.end();

    b.begin("serial@10000000")
        .str("compatible", "snps,dw-apb-uart")
        .cells("reg", &[0, 0x1000_0000, 0, 0x10000])
        .cells("power-domains", &[PMU, 2])
        .cells("clocks", &[SYSCRG, 146, SYSCRG, 145])
        .cells("resets", &[SYSCRG, 74, SYSCRG, 75])
        .strs("pinctrl-names", &["default", "sleep"])
        .cells("pinctrl-0", &[UART_CFG])
        .cells("pinctrl-1", &[])
        .end();
    b.begin("serial@10001000").str("compatible", "ns16550a").cells("reg", &[0, 0x1000_1000, 0, 0x100]).end();
    b.begin("serial@10002000")
        .str("compatible", "snps,dw-apb-uart")
        .cells("reg", &[0, 0x1000_2000, 0, 0x10000])
        .cells("assigned-clocks", &[SYSCRG, 7, SYSCRG, 9])
        .cells("assigned-clock-rates", &[12_000_000, 0])
        // A placeholder keeps its index; it asks for nothing.
        .cells("clocks", &[0, SYSCRG, 146])
        .end();
    b.begin("serial@10003000")
        .str("compatible", "snps,dw-apb-uart")
        .cells("reg", &[0, 0x1000_3000, 0, 0x10000])
        .cells("power-domains", &[PMU, 3])
        // A gate cannot make a rate other than its parent's.
        .cells("assigned-clocks", &[SYSCRG, 12])
        .cells("assigned-clock-rates", &[1000])
        .cells("clocks", &[SYSCRG, 146])
        .end();
    b.end();
    b.finish()
}

/// A register model of what the drivers poll: the reset status banks follow
/// the assert banks, the PMU switches follow its requests and complete at
/// once.
pub(crate) fn model() -> crate::support::Hook {
    Box::new(|regs, addr, val| {
        if (SYSCRG_BASE + 0x2f8..SYSCRG_BASE + 0x308).contains(&addr) {
            regs.insert(addr + 0x10, !val);
        }
        let on = PMU_BASE + 0x0c;
        let off = PMU_BASE + 0x10;
        let mode = PMU_BASE + 0x80;
        if addr == on {
            *regs.entry(mode).or_default() |= val;
        }
        if addr == off {
            *regs.entry(mode).or_default() &= !val;
        }
        if addr == PMU_BASE + 0x44 {
            regs.insert(PMU_BASE + 0x8c, 1);
        }
        if addr == PMU_BASE + 0x8c {
            regs.insert(PMU_BASE + 0x8c, 0);
        }
    })
}

pub(crate) struct Rig<'p> {
    soc: Soc<'p>,
    bus: TraceBus,
    fx: Sink,
    log: Rc<Log>,
}

impl<'p> Rig<'p> {
    pub(crate) fn new(st: &'p mut Storage, fdt: &Fdt<'_>, fam: Families) -> Self {
        st.scan(fdt, fam);
        let log = Log::new();
        let mut bus = TraceBus::new(&log).hook(model());
        let mut fx = Sink::new(&log);
        let soc = Soc::build(st, fdt, &mut Io { bus: &mut bus, i2c: None }, &mut fx);
        Rig { soc, bus, fx, log }
    }

    fn refusing(mut self, f: impl Fn(&Effect) -> bool + 'static) -> Self {
        self.fx = Sink::new(&self.log).refusing(f);
        self
    }

    pub(crate) fn bind(&mut self, fdt: &Fdt<'_>, node: NodeId) -> azos_soc::Result<Applied> {
        bind::bind(&mut self.soc, fdt, &mut self.bus, &mut self.fx, node)
    }

    pub(crate) fn unbind(&mut self, fdt: &Fdt<'_>, node: NodeId) -> azos_soc::Result<()> {
        bind::unbind(&mut self.soc, fdt, &mut self.bus, &mut self.fx, node)
    }

    /// The effects so far as `(kind, op, id)`.
    pub(crate) fn ops(&self) -> Vec<(u8, Op, u32)> {
        self.log.effects().iter().map(|e| (e.kind, e.op, e.id)).collect()
    }

    fn mode(&self) -> u32 {
        self.bus.regs.get(&(PMU_BASE + 0x80)).copied().unwrap_or(0)
    }
}

pub(crate) const JH: Families = Families { jh7110: true, k1: false };
const GENERIC: Families = Families { jh7110: false, k1: false };

const CLOCK: u8 = effect::KIND_CLOCK;
const RESET: u8 = effect::KIND_RESET;
const PD: u8 = effect::KIND_POWER_DOMAIN;
const PIN: u8 = effect::KIND_PINCTRL;

/// The gates a UART's two clocks open, root first: the core gate, then the
/// APB chain (apb0, the UART's own; apb_bus divides stg_axiahb, no gate
/// between).
const UP_CLOCKS: [(u8, Op, u32); 3] = [(CLOCK, Op::Enable, 146), (CLOCK, Op::Enable, 12), (CLOCK, Op::Enable, 145)];

#[test]
fn bind_gives_the_domain_the_clocks_and_the_resets_in_that_order() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    let node = by_path(&fdt, FULL).unwrap();
    let a = rig.bind(&fdt, node).unwrap();
    assert_eq!(a, Applied { domains: 1, rates: 0, clocks: 2, resets: 2, pins: true, unmodelled: 0 });

    let ops = rig.ops();
    let mut want = vec![(PD, Op::PowerOn, 2)];
    want.extend(UP_CLOCKS);
    want.extend([(RESET, Op::Deassert, 74), (RESET, Op::Deassert, 75)]);
    assert_eq!(&ops[..want.len()], want, "{ops:?}");

    // The effects are the managers' own, so each reached the sink before its register.
    assert_eq!(rig.mode() & (1 << 2), 1 << 2, "the domain is on");
    let uart_core = rig.soc.clocks.get(&fdt, node, Sel::Index(0)).unwrap();
    assert_eq!(rig.soc.clocks.refs(uart_core), 1);
    assert!(rig.soc.clocks.is_enabled(&mut rig.bus, uart_core).unwrap());
    let r = rig.soc.resets.get(&fdt, node, Sel::Index(0)).unwrap();
    assert!(!rig.soc.resets.is_asserted(&mut rig.bus, r).unwrap());
}

#[test]
fn bind_applies_the_default_pin_state_after_the_resets() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    let a = rig.bind(&fdt, by_path(&fdt, FULL).unwrap()).unwrap();
    assert!(a.pins, "{a:?}");

    let ops = rig.ops();
    let last_reset = ops.iter().rposition(|o| o.0 == RESET).expect("resets were deasserted");
    let first_pin = ops.iter().position(|o| o.0 == PIN).expect("the pin state was applied");
    assert!(first_pin > last_reset, "the pins come last: {ops:?}");
    assert_eq!(ops[first_pin].1, Op::SetMux);
    assert_eq!(ops[first_pin + 1].1, Op::SetBias);
    // And the pad controller's register was written.
    assert!(rig.log.writes().iter().any(|(a, _)| (SYS_PAD_BASE..SYS_PAD_BASE + 0x10000).contains(a)));
}

#[test]
fn a_refused_reset_unwinds_the_clocks_and_the_domain() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH).refusing(|e| e.op == Op::Deassert && e.id == 75);
    let node = by_path(&fdt, FULL).unwrap();
    assert_eq!(rig.bind(&fdt, node), Err(Error::Refused(77)));

    // Forward to the refusal (the refused effect is not recorded), then the
    // quiescent undo: the reset that was released is held again, the clocks
    // close newest first, the domain goes off. No pin was touched.
    let ops = rig.ops();
    let mut want = vec![(PD, Op::PowerOn, 2)];
    want.extend(UP_CLOCKS);
    want.extend([
        (RESET, Op::Deassert, 74),
        (RESET, Op::Assert, 74),
        (CLOCK, Op::Disable, 145),
        (CLOCK, Op::Disable, 12),
        (CLOCK, Op::Disable, 146),
        (PD, Op::PowerOff, 2),
    ]);
    assert_eq!(ops, want);
    assert_eq!(rig.mode() & (1 << 2), 0, "the domain is off again");
    for i in 0..2 {
        let c = rig.soc.clocks.get(&fdt, node, Sel::Index(i)).unwrap();
        assert_eq!(rig.soc.clocks.refs(c), 0, "clock {i}");
    }
    let pd = rig.soc.domains.get(&fdt, node, Sel::Index(0)).unwrap();
    assert_eq!(rig.soc.domains.refs(pd), 0);
}

#[test]
fn a_refused_clock_unwinds_the_earlier_ones_and_the_domain() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH).refusing(|e| e.op == Op::Enable && e.id == 145);
    let node = by_path(&fdt, FULL).unwrap();
    assert_eq!(rig.bind(&fdt, node), Err(Error::Refused(77)));
    let ops = rig.ops();
    assert_eq!(ops.last(), Some(&(PD, Op::PowerOff, 2)), "{ops:?}");
    assert!(!ops.iter().any(|o| o.0 == RESET || o.0 == PIN), "{ops:?}");
    let c = rig.soc.clocks.get(&fdt, node, Sel::Index(0)).unwrap();
    assert_eq!(rig.soc.clocks.refs(c), 0);
    assert!(!rig.soc.clocks.is_enabled(&mut rig.bus, c).unwrap());
}

#[test]
fn a_refused_pin_state_unwinds_everything_before_it() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH).refusing(|e| e.op == Op::SetMux);
    let node = by_path(&fdt, FULL).unwrap();
    assert_eq!(rig.bind(&fdt, node), Err(Error::Refused(77)));
    let ops = rig.ops();
    let tail = &ops[ops.len() - 6..];
    assert_eq!(
        tail,
        [
            (RESET, Op::Assert, 75),
            (RESET, Op::Assert, 74),
            (CLOCK, Op::Disable, 145),
            (CLOCK, Op::Disable, 12),
            (CLOCK, Op::Disable, 146),
            (PD, Op::PowerOff, 2),
        ],
        "{ops:?}"
    );
    assert!(!ops.iter().any(|o| o.0 == PIN), "the refused mux was not recorded");
}

#[test]
fn unbind_reverses_bind() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    let node = by_path(&fdt, FULL).unwrap();
    rig.bind(&fdt, node).unwrap();
    let before = rig.ops().len();
    rig.unbind(&fdt, node).unwrap();
    let ops = rig.ops();
    assert_eq!(
        &ops[before..],
        [
            (RESET, Op::Assert, 75),
            (RESET, Op::Assert, 74),
            (CLOCK, Op::Disable, 145),
            (CLOCK, Op::Disable, 12),
            (CLOCK, Op::Disable, 146),
            (PD, Op::PowerOff, 2),
        ]
    );
    assert_eq!(rig.mode() & (1 << 2), 0);
    let c = rig.soc.clocks.get(&fdt, node, Sel::Index(1)).unwrap();
    assert_eq!(rig.soc.clocks.refs(c), 0);
    // Bound again after: nothing was left counted.
    rig.bind(&fdt, node).unwrap();
}

#[test]
fn a_node_without_properties_binds_and_unbinds_to_nothing() {
    // QEMU virt's ns16550a: no clocks, no resets, no pin state.
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    let node = by_path(&fdt, PLAIN).unwrap();
    rig.log.clear();
    assert_eq!(rig.bind(&fdt, node), Ok(Applied::default()));
    assert_eq!(rig.unbind(&fdt, node), Ok(()));
    assert!(rig.log.all().is_empty(), "no effect, no register: {:?}", rig.log.all());
}

#[test]
fn an_entry_whose_provider_the_image_lacks_is_skipped_and_counted() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, GENERIC);
    let node = by_path(&fdt, FULL).unwrap();
    rig.log.clear();
    let a = rig.bind(&fdt, node).unwrap();
    // one domain, two clocks, two resets, and the pad controller
    assert_eq!(a, Applied { unmodelled: 6, ..Applied::default() });
    assert!(rig.log.all().is_empty());
    assert_eq!(rig.unbind(&fdt, node), Ok(()));
}

#[test]
fn a_specifier_out_of_range_fails_before_any_hardware_is_touched() {
    let mut b = Builder::new();
    b.cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    b.begin("clock-controller@13020000")
        .strs("compatible", &["starfive,jh7110-syscrg"])
        .cells("reg", &[0, 0x1302_0000, 0, 0x10000])
        .cells("#clock-cells", &[1])
        .cells("#reset-cells", &[1])
        .ph(SYSCRG)
        .end();
    b.begin("power-controller@17030000")
        .strs("compatible", &["starfive,jh7110-pmu"])
        .cells("reg", &[0, 0x1703_0000, 0, 0x10000])
        .cells("#power-domain-cells", &[1])
        .ph(PMU)
        .end();
    // The domain is fine, the clock number is past the controller's table.
    b.begin("dev@1000").cells("power-domains", &[PMU, 2]).cells("clocks", &[SYSCRG, 999]).end();
    let blob = b.finish();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    rig.log.clear();
    assert_eq!(rig.bind(&fdt, by_path(&fdt, "/dev@1000").unwrap()), Err(Error::BadSpec));
    assert!(rig.log.all().is_empty(), "{:?}", rig.log.all());
}

#[test]
fn assigned_clock_rates_are_set_before_the_clocks_open_and_a_zero_rate_is_left_alone() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    let node = by_path(&fdt, RATED).unwrap();
    let a = rig.bind(&fdt, node).unwrap();
    assert_eq!(a, Applied { rates: 1, clocks: 1, ..Applied::default() });
    let fx = rig.log.effects();
    assert_eq!((fx[0].kind, fx[0].op, fx[0].id, fx[0].value), (CLOCK, Op::SetRate, 7, 12_000_000));
    assert_eq!(fx.iter().filter(|e| e.op == Op::SetRate).count(), 1, "the 0 Hz entry is not applied");
    assert_eq!(fx[1].op, Op::Enable, "then the gate");
    // 24 MHz oscillator / 2 in the divider register.
    assert_eq!(rig.bus.regs.get(&(SYSCRG_BASE + 4 * 7)).map(|v| v & 0xff_ffff), Some(2));
    // The placeholder kept its index: the one clock is entry 1.
    assert!(rig.soc.clocks.get(&fdt, node, Sel::Index(0)).is_err());
    let c: Clk = rig.soc.clocks.get(&fdt, node, Sel::Index(1)).unwrap();
    assert_eq!(rig.soc.clocks.refs(c), 1);
}

#[test]
fn a_rate_the_provider_cannot_make_fails_the_bind_and_powers_the_domain_off() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    let node = by_path(&fdt, BAD_RATE).unwrap();
    assert_eq!(rig.bind(&fdt, node), Err(Error::Unsupported));
    let ops = rig.ops();
    assert_eq!(ops.first(), Some(&(PD, Op::PowerOn, 3)));
    assert_eq!(ops.last(), Some(&(PD, Op::PowerOff, 3)));
    assert!(!ops.iter().any(|o| o.1 == Op::Enable), "no clock opened: {ops:?}");
    assert_eq!(rig.mode() & (1 << 3), 0);
}

#[test]
fn lists_count_their_entries_placeholders_included() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let n = by_path(&fdt, RATED).unwrap();
    assert_eq!(consumer::count(&fdt, n, "clocks", "#clock-cells"), Ok(2));
    assert_eq!(consumer::count(&fdt, n, "assigned-clocks", "#clock-cells"), Ok(2));
    assert_eq!(consumer::count(&fdt, n, "resets", "#reset-cells"), Ok(0), "no property, no entries");
    assert!(matches!(consumer::slot(&fdt, n, "clocks", "#clock-cells", 0), Ok(None)));
    assert_eq!(consumer::slot(&fdt, n, "clocks", "#clock-cells", 1).unwrap().unwrap().id(), Ok(146));
    assert_eq!(consumer::slot(&fdt, n, "clocks", "#clock-cells", 2).unwrap_err(), Error::NotFound);
    assert_eq!(consumer::entry(&fdt, n, "clocks", "#clock-cells", 0).unwrap_err(), Error::NotFound);
}

// ---- the hardware bus calls it ----

/// What the kernel's driver registry does (`kernel/src/boot/hwbus.rs`), over
/// the managers of a rig: the resources before the driver, released when the
/// probe fails or the driver lets go.
struct Registry<'r, 'p, 'f> {
    rig: &'r mut Rig<'p>,
    fdt: &'r Fdt<'f>,
    probe_fails: bool,
    calls: Vec<&'static str>,
}

impl Drivers for Registry<'_, '_, '_> {
    fn resources(&mut self, _driver: &str, _h: Handle, dev: &Device) -> Result<(), ProbeError> {
        self.calls.push("resources");
        let Some(n) = dev.dt_node else { return Ok(()) };
        self.rig.bind(self.fdt, NodeId(n)).map(|_| ()).map_err(|_| ProbeError::Resources)
    }
    fn release(&mut self, _driver: &str, _h: Handle, dev: &Device) {
        self.calls.push("release");
        if let Some(n) = dev.dt_node {
            self.rig.unbind(self.fdt, NodeId(n)).unwrap();
        }
    }
    fn probe(&mut self, _driver: &str, _h: Handle, _dev: &Device) -> Result<(), ProbeError> {
        self.calls.push("probe");
        if self.probe_fails { Err(ProbeError::Failed) } else { Ok(()) }
    }
    fn remove(&mut self, _driver: &str, _h: Handle, _dev: &Device) -> Result<(), ProbeError> {
        self.calls.push("remove");
        Ok(())
    }
}

struct Quiet;
impl hw::Sink for Quiet {
    fn event(&mut self, _ev: &hw::Event<'_>) {}
}

const NATIVE: &[NativeEntry] = &[NativeEntry { pattern: Pattern::Dt("snps,dw-apb-uart"), driver: "uart-test", boot: false }];
const LINUX: &[hw::LinuxEntry] = &[hw::LinuxEntry { pattern: Pattern::Dt("vendor,sensor-a"), class: "iio", module: "sensor-a" }];

fn rules<'a>(policy: Policy) -> hw::Rules<'a> {
    hw::Rules { native: NATIVE, linux: LINUX, rows: &[], policy }
}

fn dt_device(fdt: &Fdt<'_>, path: &str, compat: &[u8]) -> Device {
    let n = by_path(fdt, path).unwrap();
    let (base, size) = fdt.reg(n).unwrap();
    Device::dt("serial", compat, base, size, 0).with_dt_node(n.0)
}

#[test]
fn the_bus_asks_for_the_resources_before_the_driver_and_gives_them_back_when_it_lets_go() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    let mut bus = hw::Bus::new();
    let h = bus.add(dt_device(&fdt, FULL, b"snps,dw-apb-uart\0"), &mut Quiet).unwrap();
    let mut reg = Registry { rig: &mut rig, fdt: &fdt, probe_fails: false, calls: vec![] };
    bus.bind(h, &rules(Policy::Auto), &mut reg, &mut Quiet);
    assert_eq!(reg.calls, ["resources", "probe"]);
    assert_eq!(bus.get(h).unwrap().state, hw::State::Bound);
    assert_eq!(reg.rig.mode() & (1 << 2), 1 << 2);

    bus.unbind(h, &mut reg, &mut Quiet).unwrap();
    assert_eq!(reg.calls, ["resources", "probe", "remove", "release"]);
    assert_eq!(reg.rig.mode() & (1 << 2), 0, "the domain went off with the driver");
}

#[test]
fn a_driver_that_fails_to_probe_does_not_keep_the_resources() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    let mut bus = hw::Bus::new();
    let h = bus.add(dt_device(&fdt, FULL, b"snps,dw-apb-uart\0"), &mut Quiet).unwrap();
    let mut reg = Registry { rig: &mut rig, fdt: &fdt, probe_fails: true, calls: vec![] };
    bus.bind(h, &rules(Policy::Auto), &mut reg, &mut Quiet);
    assert_eq!(reg.calls, ["resources", "probe", "release"]);
    assert_eq!(bus.get(h).unwrap().state, hw::State::ProbeFailed);
    assert_eq!(reg.rig.mode() & (1 << 2), 0);
}

#[test]
fn resources_that_cannot_be_given_fail_the_bind_without_asking_the_driver() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH).refusing(|e| e.op == Op::Enable);
    let mut bus = hw::Bus::new();
    let h = bus.add(dt_device(&fdt, FULL, b"snps,dw-apb-uart\0"), &mut Quiet).unwrap();
    let mut reg = Registry { rig: &mut rig, fdt: &fdt, probe_fails: false, calls: vec![] };
    bus.bind(h, &rules(Policy::Auto), &mut reg, &mut Quiet);
    assert_eq!(reg.calls, ["resources"], "the driver was never asked, and nothing is left to release");
    assert_eq!(bus.get(h).unwrap().state, hw::State::ProbeFailed);
    assert_eq!(reg.rig.mode() & (1 << 2), 0);
}

#[test]
fn a_node_whose_driver_is_not_a_native_one_is_never_touched() {
    let blob = tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    rig.log.clear();
    let mut bus = hw::Bus::new();
    // The Linux slice's device: it carries the full node, but its driver is
    // the class server's, which asks through its device interface.
    let linux = bus.add(dt_device(&fdt, FULL, b"vendor,sensor-a\0"), &mut Quiet).unwrap();
    // A device nothing names: ring 3 may be given its window.
    let free = bus.add(dt_device(&fdt, FULL, b"vendor,unknown\0"), &mut Quiet).unwrap();
    let mut reg = Registry { rig: &mut rig, fdt: &fdt, probe_fails: false, calls: vec![] };
    bus.bind(linux, &rules(Policy::Auto), &mut reg, &mut Quiet);
    bus.bind(free, &rules(Policy::Auto), &mut reg, &mut Quiet);
    assert!(matches!(bus.get(linux).unwrap().binding, hw::Binding::Linux { .. }));
    assert_eq!(bus.get(free).unwrap().state, hw::State::Unmatched);
    // Neither is a native bind, and a topology-only image that does not admit
    // a native one leaves it to ring 3 as well.
    let held = bus.add(dt_device(&fdt, FULL, b"snps,dw-apb-uart\0"), &mut Quiet).unwrap();
    bus.bind(held, &rules(Policy::TopologyOnly), &mut reg, &mut Quiet);
    assert_eq!(bus.get(held).unwrap().state, hw::State::NotAdmitted);
    assert!(reg.calls.is_empty(), "{:?}", reg.calls);
    assert!(reg.rig.log.all().is_empty(), "no effect, no register: {:?}", reg.rig.log.all());
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::support::*;
use azos_soc::clk::{ClockOps, ClockTree, Parent};
use azos_soc::consumer::Sel;
use azos_soc::effect::{Class, Effect, Op, KIND_CLOCK};
use azos_soc::fdt::Fdt;
use azos_soc::fixed::FixedClock;
use azos_soc::{Bus, Error, Result};

const A_BASE: u64 = 0x5000;

/// A controller whose gates are one register each (`A_BASE + 4 * id`, 1 =
/// open), so the bus trace shows the order the framework used.
struct Mock {
    parents: Vec<Parent>,
    gated: Vec<bool>,
    div: Vec<u64>,
}

impl Mock {
    fn new() -> Self {
        // 0 root; 1 <- 0; 2 <- 1; 3 <- 0; 4 (no gate, divider 4) <- 2;
        // 5 <- input "ext"; 6 <- input "missing"; 7 <-> 8 loop.
        Mock {
            parents: vec![
                Parent::None, Parent::Local(0), Parent::Local(1), Parent::Local(0), Parent::Local(2),
                Parent::Input(0), Parent::Input(1), Parent::Local(8), Parent::Local(7),
            ],
            gated: vec![true, true, true, true, false, true, true, true, true],
            div: vec![1, 1, 1, 1, 4, 1, 1, 1, 1],
        }
    }
}

impl ClockOps for Mock {
    fn count(&self) -> u32 {
        self.parents.len() as u32
    }
    fn input_names(&self) -> &'static [&'static str] {
        &["ext", "missing"]
    }
    fn parent(&mut self, _: &mut dyn Bus, id: u32) -> Result<Parent> {
        Ok(self.parents[id as usize])
    }
    fn gated(&self, id: u32) -> bool {
        self.gated[id as usize]
    }
    fn enable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        bus.write32(A_BASE + 4 * id as u64, 1);
        Ok(())
    }
    fn disable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        bus.write32(A_BASE + 4 * id as u64, 0);
        Ok(())
    }
    fn is_enabled(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool> {
        Ok(bus.read32(A_BASE + 4 * id as u64) != 0)
    }
    fn rate(&mut self, _: &mut dyn Bus, id: u32, parent_rate: u64) -> Result<u64> {
        // The root makes 100 MHz.
        Ok(if self.parents[id as usize] == Parent::None { 100_000_000 } else { parent_rate / self.div[id as usize] })
    }
    fn set_rate(&mut self, bus: &mut dyn Bus, id: u32, rate: u64, parent_rate: u64) -> Result<u64> {
        if id != 4 {
            return Err(Error::Unsupported);
        }
        self.div[4] = parent_rate / rate;
        bus.write32(A_BASE + 0x100, self.div[4] as u32);
        Ok(parent_rate / self.div[4])
    }
}

fn tree_dt() -> Vec<u8> {
    let mut b = Builder::new();
    b.cells("#address-cells", &[1]).cells("#size-cells", &[1]);
    b.begin("ext").str("compatible", "fixed-clock").cells("#clock-cells", &[0]).cells("clock-frequency", &[50_000_000]).ph(1).end();
    b.begin("mock").cells("#clock-cells", &[1]).cells("clocks", &[1]).strs("clock-names", &["ext"]).ph(10).end();
    b.begin("dev").cells("clocks", &[10, 2, 10, 3, 10, 4, 10, 5, 10, 6, 10, 7, 10, 99]).end();
    b.finish()
}

macro_rules! rig {
    ($blob:ident, $fdt:ident, $log:ident, $bus:ident, $fx:ident, $tree:ident, $dev:ident) => {
        let $blob = tree_dt();
        let $fdt = Fdt::parse(&$blob).unwrap();
        let $log = Log::new();
        let mut $bus = TraceBus::new(&$log);
        let mut $fx = Sink::new(&$log);
        let mut ext = FixedClock::from_dt(&$fdt, by_path(&$fdt, "/ext").unwrap()).unwrap();
        let mut mock = Mock::new();
        let mut $tree = ClockTree::new();
        $tree.add(by_path(&$fdt, "/ext").unwrap(), &mut ext).unwrap();
        $tree.add(by_path(&$fdt, "/mock").unwrap(), &mut mock).unwrap();
        $tree.link(&$fdt);
        let $dev = by_path(&$fdt, "/dev").unwrap();
    };
}

fn en(id: u32) -> Ev {
    Ev::E(Effect { kind: KIND_CLOCK, op: Op::Enable, class: Class::Reversible, provider: 1, id, value: 1 })
}
fn dis(id: u32) -> Ev {
    Ev::E(Effect { kind: KIND_CLOCK, op: Op::Disable, class: Class::Safe, provider: 1, id, value: 0 })
}
fn w(id: u32, v: u32) -> Ev {
    Ev::W(A_BASE + 4 * id as u64, v)
}

#[test]
fn enable_opens_the_gates_parents_first_and_counts_each_once() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c2 = tree.get(&fdt, dev, Sel::Index(0)).unwrap();
    assert_eq!((c2.prov, c2.id), (1, 2));
    tree.enable(&mut bus, &mut fx, c2).unwrap();
    assert_eq!(log.all(), [en(0), w(0, 1), en(1), w(1, 1), en(2), w(2, 1)]);
    for id in 0..3 {
        assert_eq!(tree.refs(azos_soc::clk::Clk { prov: 1, id }), 1);
    }
    // A sibling shares the root: only its own gate opens, the root gains a holder.
    log.clear();
    let c3 = tree.get(&fdt, dev, Sel::Index(1)).unwrap();
    tree.enable(&mut bus, &mut fx, c3).unwrap();
    assert_eq!(log.all(), [en(3), w(3, 1)]);
    assert_eq!(tree.refs(azos_soc::clk::Clk { prov: 1, id: 0 }), 2);
    assert_eq!(tree.refs(c3), 1);
    // The same clock again: a count, no hardware.
    log.clear();
    tree.enable(&mut bus, &mut fx, c2).unwrap();
    assert!(log.all().is_empty());
    assert_eq!(tree.refs(c2), 2);
}

#[test]
fn disable_closes_children_first_and_the_parent_with_its_last_holder() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c2 = tree.get(&fdt, dev, Sel::Index(0)).unwrap();
    let c3 = tree.get(&fdt, dev, Sel::Index(1)).unwrap();
    tree.enable(&mut bus, &mut fx, c2).unwrap();
    tree.enable(&mut bus, &mut fx, c3).unwrap();
    log.clear();
    tree.disable(&mut bus, &mut fx, c2).unwrap();
    // The root is still held by clock 3.
    assert_eq!(log.all(), [dis(2), w(2, 0), dis(1), w(1, 0)]);
    log.clear();
    tree.disable(&mut bus, &mut fx, c3).unwrap();
    assert_eq!(log.all(), [dis(3), w(3, 0), dis(0), w(0, 0)]);
    for id in 0..4 {
        assert_eq!(tree.refs(azos_soc::clk::Clk { prov: 1, id }), 0);
    }
}

#[test]
fn a_second_user_keeps_the_gate_open() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c2 = tree.get(&fdt, dev, Sel::Index(0)).unwrap();
    tree.enable(&mut bus, &mut fx, c2).unwrap();
    tree.enable(&mut bus, &mut fx, c2).unwrap();
    log.clear();
    tree.disable(&mut bus, &mut fx, c2).unwrap();
    assert!(log.all().is_empty());
    assert_eq!(tree.refs(c2), 1);
    tree.disable(&mut bus, &mut fx, c2).unwrap();
    assert_eq!(log.writes().len(), 3);
}

#[test]
fn a_release_without_an_acquire_is_refused_and_touches_nothing() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c2 = tree.get(&fdt, dev, Sel::Index(0)).unwrap();
    assert_eq!(tree.disable(&mut bus, &mut fx, c2), Err(Error::Unbalanced));
    assert!(log.all().is_empty());
}

#[test]
fn a_clock_without_a_gate_still_holds_its_parents_open() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c4 = tree.get(&fdt, dev, Sel::Index(2)).unwrap();
    tree.enable(&mut bus, &mut fx, c4).unwrap();
    // 4 has no gate: no write and no record of its own; 2, 1, 0 open root first.
    assert_eq!(log.all(), [en(0), w(0, 1), en(1), w(1, 1), en(2), w(2, 1)]);
    assert_eq!(tree.refs(c4), 1);
    assert!(tree.is_enabled(&mut bus, c4).unwrap());
}

#[test]
fn a_refused_effect_rolls_back_what_was_opened() {
    rig!(blob, fdt, log, bus, _fx, tree, dev);
    // The record of clock 1's enable is refused: clock 0 was already open.
    let mut fx = Sink::new(&log).refusing(|e| e.op == Op::Enable && e.id == 1);
    let c2 = tree.get(&fdt, dev, Sel::Index(0)).unwrap();
    assert_eq!(tree.enable(&mut bus, &mut fx, c2), Err(Error::Refused(77)));
    assert_eq!(log.all(), [en(0), w(0, 1), dis(0), w(0, 0)]);
    for id in 0..3 {
        assert_eq!(tree.refs(azos_soc::clk::Clk { prov: 1, id }), 0);
    }
}

#[test]
fn closing_a_gate_is_never_refused() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c2 = tree.get(&fdt, dev, Sel::Index(0)).unwrap();
    tree.enable(&mut bus, &mut fx, c2).unwrap();
    log.clear();
    // A sink that takes nothing: the Safe direction still goes ahead.
    let mut deny = Sink::new(&log).refusing(|_| true);
    tree.disable(&mut bus, &mut deny, c2).unwrap();
    assert_eq!(log.writes(), [(A_BASE + 8, 0), (A_BASE + 4, 0), (A_BASE, 0)]);
}

#[test]
fn effects_are_committed_before_the_register_write() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c2 = tree.get(&fdt, dev, Sel::Index(0)).unwrap();
    tree.enable(&mut bus, &mut fx, c2).unwrap();
    tree.disable(&mut bus, &mut fx, c2).unwrap();
    let ev = log.all();
    assert_eq!(ev.len(), 12);
    // Every write is directly preceded by the effect that describes it.
    for (i, e) in ev.iter().enumerate() {
        if let Ev::W(addr, val) = e {
            let id = ((addr - A_BASE) / 4) as u32;
            let want = if *val == 1 { en(id) } else { dis(id) };
            assert_eq!(i.checked_sub(1).map(|k| &ev[k]), Some(&want), "write {i} has no record before it");
        }
    }
}

#[test]
fn rates_follow_the_chain_from_the_root() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c4 = tree.get(&fdt, dev, Sel::Index(2)).unwrap();
    // root 100 MHz, 1, 2 pass it on, 4 divides by 4.
    assert_eq!(tree.rate(&mut bus, c4).unwrap(), 25_000_000);
    // set_rate: parent 100 MHz, ask 10 MHz -> divider 10.
    let got = tree.set_rate(&mut bus, &mut fx, c4, 10_000_000).unwrap();
    assert_eq!(got, 10_000_000);
    assert_eq!(tree.rate(&mut bus, c4).unwrap(), 10_000_000);
    assert_eq!(log.effects().last(), Some(&Effect { kind: KIND_CLOCK, op: Op::SetRate, class: Class::Reversible, provider: 1, id: 4, value: 10_000_000 }));
    // A clock that cannot change rate says so, and the record was still made first.
    let c3 = tree.get(&fdt, dev, Sel::Index(1)).unwrap();
    assert_eq!(tree.set_rate(&mut bus, &mut fx, c3, 1), Err(Error::Unsupported));
}

#[test]
fn a_refused_rate_change_leaves_the_register_alone() {
    rig!(blob, fdt, log, bus, _fx, tree, dev);
    let mut fx = Sink::new(&log).refusing(|e| e.op == Op::SetRate);
    let c4 = tree.get(&fdt, dev, Sel::Index(2)).unwrap();
    assert_eq!(tree.set_rate(&mut bus, &mut fx, c4, 10_000_000), Err(Error::Refused(77)));
    assert!(log.writes().is_empty());
}

#[test]
fn an_input_clock_is_resolved_to_the_other_controller() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c5 = tree.get(&fdt, dev, Sel::Index(3)).unwrap();
    assert_eq!(tree.parent(&mut bus, c5).unwrap(), Some(azos_soc::clk::Clk { prov: 0, id: 0 }));
    assert_eq!(tree.rate(&mut bus, c5).unwrap(), 50_000_000);
    // Enabling 5 holds the fixed clock too (a count; it has no gate, so no
    // record and no write of its own).
    tree.enable(&mut bus, &mut fx, c5).unwrap();
    assert_eq!(tree.refs(azos_soc::clk::Clk { prov: 0, id: 0 }), 1);
    assert_eq!(log.all(), [en(5), w(5, 1)]);
}

#[test]
fn an_input_the_tree_does_not_name_fails_when_used_not_before() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c6 = tree.get(&fdt, dev, Sel::Index(4)).unwrap();
    assert_eq!(tree.enable(&mut bus, &mut fx, c6), Err(Error::NoProvider));
    assert!(log.all().is_empty());
}

#[test]
fn a_parent_loop_is_depth_not_a_hang() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let c7 = tree.get(&fdt, dev, Sel::Index(5)).unwrap();
    assert_eq!(tree.enable(&mut bus, &mut fx, c7), Err(Error::Depth));
    assert!(log.all().is_empty());
}

#[test]
fn lookup_errors() {
    rig!(blob, fdt, log, bus, fx, tree, dev);
    let _ = (&mut bus, &mut fx, &log);
    assert_eq!(tree.get(&fdt, dev, Sel::Index(9)).unwrap_err(), Error::NotFound);
    assert_eq!(tree.get(&fdt, dev, Sel::Name("x")).unwrap_err(), Error::NotFound);
    // A provider that was never registered.
    let mut b = Builder::new();
    b.begin("ctl").cells("#clock-cells", &[0]).ph(2).end();
    b.begin("dev").cells("clocks", &[2]).end();
    let blob2 = b.finish();
    let fdt2 = Fdt::parse(&blob2).unwrap();
    assert_eq!(tree.get(&fdt2, by_path(&fdt2, "/dev").unwrap(), Sel::Index(0)).unwrap_err(), Error::NoProvider);
    // A clock number past the controller's table.
    assert_eq!(tree.get(&fdt, dev, Sel::Index(6)).unwrap_err(), Error::BadSpec);
}

#[test]
fn the_fixed_clock_comes_from_its_node() {
    let blob = tree_dt();
    let fdt = Fdt::parse(&blob).unwrap();
    assert_eq!(FixedClock::from_dt(&fdt, by_path(&fdt, "/ext").unwrap()), Some(FixedClock::new(50_000_000)));
    assert_eq!(FixedClock::from_dt(&fdt, by_path(&fdt, "/mock").unwrap()), None);
    // A disabled node is not a provider.
    let mut b = Builder::new();
    b.begin("osc").str("compatible", "fixed-clock").cells("clock-frequency", &[1]).str("status", "disabled").end();
    let blob2 = b.finish();
    let f2 = Fdt::parse(&blob2).unwrap();
    assert_eq!(FixedClock::from_dt(&f2, by_path(&f2, "/osc").unwrap()), None);
}

#[test]
fn the_wire_form_of_an_effect_is_pinned() {
    let e = Effect { kind: KIND_CLOCK, op: Op::SetRate, class: Class::Reversible, provider: 3, id: 141, value: 5_000_000_000 };
    assert_eq!(e.wire(), (2, 0x0303, 141, u32::MAX));
    let e = Effect { kind: azos_soc::effect::KIND_POWER_DOMAIN, op: Op::PowerOff, class: Class::Safe, provider: 1, id: 2, value: 0 };
    assert_eq!(e.wire(), (6, 0x010a, 2, 0));
}

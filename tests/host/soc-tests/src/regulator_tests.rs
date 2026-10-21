// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The regulator framework: constraints from the device tree, counted enable,
//! voltage requests.
use crate::support::*;
use azos_soc::effect::{Class, Effect, Op, KIND_REGULATOR};
use azos_soc::fdt::Fdt;
use azos_soc::fixed::FixedRegulator;
use azos_soc::regulator::{Constraints, Io, Reg, RegulatorOps, Regulators};
use azos_soc::{Bus, Error, Result};

/// The framework's view of a register bus alone: no I2C master.
fn io(bus: &mut dyn Bus) -> Io<'_> {
    Io { bus, i2c: None }
}

const EN: u64 = 0x6000;
const UV: u64 = 0x6004;

/// An adjustable rail: one enable register and one voltage register.
struct Buck {
    uv: u32,
}

impl RegulatorOps for Buck {
    fn enable(&mut self, io: &mut Io<'_>) -> Result<()> {
        io.bus.write32(EN, 1);
        Ok(())
    }
    fn disable(&mut self, io: &mut Io<'_>) -> Result<()> {
        io.bus.write32(EN, 0);
        Ok(())
    }
    fn is_enabled(&mut self, io: &mut Io<'_>) -> Result<bool> {
        Ok(io.bus.read32(EN) != 0)
    }
    fn voltage(&mut self, _: &mut Io<'_>) -> Result<u32> {
        Ok(self.uv)
    }
    fn set_voltage(&mut self, io: &mut Io<'_>, uv: u32) -> Result<()> {
        self.uv = uv;
        io.bus.write32(UV, uv);
        Ok(())
    }
}

fn eff(op: Op, class: Class, reg: u8, value: u64) -> Ev {
    Ev::E(Effect { kind: KIND_REGULATOR, op, class, provider: reg, id: 0, value })
}

macro_rules! rig {
    ($blob:ident, $fdt:ident, $log:ident, $bus:ident, $fx:ident, $rg:ident, $u:ident) => {
        let $blob = board();
        let $fdt = Fdt::parse(&$blob).unwrap();
        let $log = Log::new();
        let mut $bus = TraceBus::new(&$log);
        let mut $fx = Sink::new(&$log);
        let mut vdd = FixedRegulator::from_dt(&$fdt, $fdt.by_phandle(VDD).unwrap()).unwrap();
        let mut buck = Buck { uv: 1_000_000 };
        let mut $rg = Regulators::new();
        $rg.add(&$fdt, $fdt.by_phandle(VDD).unwrap(), &mut vdd).unwrap();
        $rg.add(&$fdt, $fdt.by_phandle(BUCK).unwrap(), &mut buck).unwrap();
        let $u = uart(&$fdt);
    };
}

#[test]
fn supplies_resolve_by_property_name_and_constraints_come_from_the_node() {
    rig!(blob, fdt, log, bus, fx, rg, u);
    let _ = (&mut bus, &mut fx, &log);
    assert_eq!(rg.get_supply(&fdt, u, "vdd").unwrap(), Reg(0));
    assert_eq!(rg.get_supply(&fdt, u, "vcore").unwrap(), Reg(1));
    assert_eq!(rg.get_supply(&fdt, u, "vio").unwrap_err(), Error::NotFound);
    assert_eq!(rg.constraints(Reg(0)), Some(Constraints { min_uv: 1_800_000, max_uv: 1_800_000, ramp_uv_per_us: 0, always_on: true }));
    assert_eq!(rg.constraints(Reg(1)), Some(Constraints { min_uv: 800_000, max_uv: 1_200_000, ramp_uv_per_us: 0, always_on: false }));
    assert_eq!(rg.constraints(Reg(2)), None);
}

#[test]
fn a_supply_whose_rail_is_not_registered_is_no_provider() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut vdd = FixedRegulator::from_dt(&fdt, fdt.by_phandle(VDD).unwrap()).unwrap();
    let mut rg = Regulators::new();
    rg.add(&fdt, fdt.by_phandle(VDD).unwrap(), &mut vdd).unwrap();
    assert_eq!(rg.get_supply(&fdt, uart(&fdt), "vcore").unwrap_err(), Error::NoProvider);
}

#[test]
fn enable_is_counted_and_the_last_release_cuts_the_rail() {
    rig!(blob, fdt, log, bus, fx, rg, u);
    let r = rg.get_supply(&fdt, u, "vcore").unwrap();
    rg.enable(&mut io(&mut bus), &mut fx, r).unwrap();
    rg.enable(&mut io(&mut bus), &mut fx, r).unwrap();
    assert_eq!(log.all(), [eff(Op::Enable, Class::Reversible, 1, 0), Ev::W(EN, 1)]);
    assert!(rg.is_enabled(&mut io(&mut bus), r).unwrap());
    log.clear();
    rg.disable(&mut io(&mut bus), &mut fx, r).unwrap();
    assert!(log.writes().is_empty());
    rg.disable(&mut io(&mut bus), &mut fx, r).unwrap();
    assert_eq!(log.all(), [eff(Op::Disable, Class::Safe, 1, 0), Ev::W(EN, 0)]);
    assert_eq!(rg.disable(&mut io(&mut bus), &mut fx, r), Err(Error::Unbalanced));
    assert_eq!(rg.refs(r), 0);
}

#[test]
fn an_always_on_rail_is_switched_on_once_and_cannot_be_released() {
    rig!(blob, fdt, log, bus, fx, rg, u);
    assert_eq!(rg.enable_always_on(&mut io(&mut bus), &mut fx).unwrap(), 1);
    assert_eq!(log.all(), [eff(Op::Enable, Class::Reversible, 0, 0)]);
    assert_eq!(rg.enable_always_on(&mut io(&mut bus), &mut fx).unwrap(), 0);
    let vdd = rg.get_supply(&fdt, u, "vdd").unwrap();
    // A consumer takes and drops its own reference; the pinned one stays.
    rg.enable(&mut io(&mut bus), &mut fx, vdd).unwrap();
    rg.disable(&mut io(&mut bus), &mut fx, vdd).unwrap();
    assert_eq!(rg.disable(&mut io(&mut bus), &mut fx, vdd), Err(Error::Unbalanced));
    assert_eq!(rg.refs(vdd), 1);
    assert!(rg.is_enabled(&mut io(&mut bus), vdd).unwrap());
    // The adjustable rail is not always-on.
    assert_eq!(log.effects().len(), 1);
}

#[test]
fn the_rail_gets_the_lowest_voltage_the_constraints_allow() {
    rig!(blob, fdt, log, bus, fx, rg, u);
    let r = rg.get_supply(&fdt, u, "vcore").unwrap();
    assert_eq!(rg.set_voltage(&mut io(&mut bus), &mut fx, r, 900_000, 1_000_000), Ok(900_000));
    assert_eq!(log.all(), [eff(Op::SetVoltage, Class::Reversible, 1, 900_000), Ev::W(UV, 900_000)]);
    assert_eq!(rg.voltage(&mut io(&mut bus), r), Ok(900_000));
    // A range wider than the constraints is clamped to them.
    assert_eq!(rg.set_voltage(&mut io(&mut bus), &mut fx, r, 0, 5_000_000), Ok(800_000));
    assert_eq!(rg.set_voltage(&mut io(&mut bus), &mut fx, r, 1_100_000, 5_000_000), Ok(1_100_000));
}

#[test]
fn a_request_outside_the_constraints_changes_nothing() {
    rig!(blob, fdt, log, bus, fx, rg, u);
    let r = rg.get_supply(&fdt, u, "vcore").unwrap();
    for (lo, hi) in [(1_300_000, 1_400_000), (100_000, 700_000), (1_000_000, 900_000)] {
        assert_eq!(rg.set_voltage(&mut io(&mut bus), &mut fx, r, lo, hi), Err(Error::Constraint), "{lo}..{hi}");
    }
    assert!(log.all().is_empty());
    // A refused record leaves the register alone too.
    let mut deny = Sink::new(&log).refusing(|e| e.op == Op::SetVoltage);
    assert_eq!(rg.set_voltage(&mut io(&mut bus), &mut deny, r, 900_000, 900_000), Err(Error::Refused(77)));
    assert!(log.writes().is_empty());
    assert_eq!(rg.voltage(&mut io(&mut bus), r), Ok(1_000_000));
}

#[test]
fn a_fixed_rail_takes_only_its_own_voltage() {
    rig!(blob, fdt, log, bus, fx, rg, u);
    let vdd = rg.get_supply(&fdt, u, "vdd").unwrap();
    assert_eq!(rg.set_voltage(&mut io(&mut bus), &mut fx, vdd, 1_700_000, 1_900_000), Ok(1_800_000));
    assert_eq!(rg.set_voltage(&mut io(&mut bus), &mut fx, vdd, 1_000_000, 1_700_000), Err(Error::Constraint));
    assert_eq!(rg.voltage(&mut io(&mut bus), vdd), Ok(1_800_000));
    let _ = &log;
}

#[test]
fn a_node_without_a_voltage_range_is_not_adjustable() {
    let mut b = Builder::new();
    b.begin("sw").ph(1).flag("regulator-always-on").end();
    b.begin("bad").cells("regulator-min-microvolt", &[2_000_000]).cells("regulator-max-microvolt", &[1_000_000]).end();
    let blob = b.finish();
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut bus = TraceBus::new(&log);
    let mut fx = Sink::new(&log);
    let mut sw = Buck { uv: 3_300_000 };
    let mut rg = Regulators::new();
    let r = rg.add(&fdt, by_path(&fdt, "/sw").unwrap(), &mut sw).unwrap();
    assert_eq!(rg.set_voltage(&mut io(&mut bus), &mut fx, r, 3_000_000, 3_600_000), Err(Error::Constraint));
    assert!(log.all().is_empty());
    // A node whose min is above its max is refused at registration.
    let mut other = Buck { uv: 0 };
    assert_eq!(rg.add(&fdt, by_path(&fdt, "/bad").unwrap(), &mut other).unwrap_err(), Error::Constraint);
}

#[test]
fn the_fixed_provider_reads_its_node() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    assert_eq!(FixedRegulator::from_dt(&fdt, fdt.by_phandle(VDD).unwrap()), Some(FixedRegulator::new(1_800_000, true)));
    // Not a regulator-fixed.
    assert_eq!(FixedRegulator::from_dt(&fdt, fdt.by_phandle(BUCK).unwrap()), None);
    // min != max is not a fixed rail.
    let mut b = Builder::new();
    b.begin("r").str("compatible", "regulator-fixed").cells("regulator-min-microvolt", &[1]).cells("regulator-max-microvolt", &[2]).end();
    let blob = b.finish();
    let fdt = Fdt::parse(&blob).unwrap();
    assert_eq!(FixedRegulator::from_dt(&fdt, by_path(&fdt, "/r").unwrap()), None);
}

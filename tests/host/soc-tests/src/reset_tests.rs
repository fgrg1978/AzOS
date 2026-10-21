// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The reset framework and the JH7110 reset banks.
use crate::support::*;
use azos_soc::consumer::Sel;
use azos_soc::effect::{Class, Effect, Op, KIND_RESET};
use azos_soc::fdt::Fdt;
use azos_soc::jh7110::rst::POLL_BUDGET;
use azos_soc::jh7110::Jh7110Reset;
use azos_soc::reset::{Resets, Rst};
use azos_soc::Error;

const ASSERT2: u64 = SYSCRG_BASE + 0x2f8 + 8; // bank 2: lines 64..95
const STATUS2: u64 = SYSCRG_BASE + 0x308 + 8;

fn eff(op: Op, class: Class, id: u32) -> Ev {
    Ev::E(Effect { kind: KIND_RESET, op, class, provider: 0, id, value: 0 })
}

/// The hardware: a released line reads 1 in the status bank.
fn mirror() -> Hook {
    Box::new(|regs, addr, val| {
        if (SYSCRG_BASE + 0x2f8..SYSCRG_BASE + 0x308).contains(&addr) {
            regs.insert(addr + 0x10, !val);
        }
    })
}

macro_rules! rig {
    ($blob:ident, $fdt:ident, $log:ident, $bus:ident, $fx:ident, $rs:ident, $u:ident) => {
        let $blob = board();
        let $fdt = Fdt::parse(&$blob).unwrap();
        let $log = Log::new();
        let mut $bus = TraceBus::new(&$log).hook(mirror());
        let mut $fx = Sink::new(&$log);
        let mut ctl = Jh7110Reset::sys(SYSCRG_BASE);
        let mut $rs = Resets::new();
        $rs.add($fdt.by_phandle(SYSCRG).unwrap(), &mut ctl).unwrap();
        let $u = uart(&$fdt);
    };
}

#[test]
fn consumer_lookup_by_name_and_index() {
    rig!(blob, fdt, log, bus, fx, rs, u);
    let _ = (&mut bus, &mut fx, &log);
    assert_eq!(rs.get(&fdt, u, Sel::Name("apb")).unwrap(), Rst { prov: 0, id: 74 });
    assert_eq!(rs.get(&fdt, u, Sel::Name("core")).unwrap(), Rst { prov: 0, id: 75 });
    assert_eq!(rs.get(&fdt, u, Sel::Index(1)).unwrap(), Rst { prov: 0, id: 75 });
    assert_eq!(rs.get(&fdt, u, Sel::Name("x")).unwrap_err(), Error::NotFound);
    assert_eq!(rs.get(&fdt, u, Sel::Index(2)).unwrap_err(), Error::NotFound);
    // A line past the controller's banks.
    let mut b = Builder::new();
    b.begin("ctl").cells("#reset-cells", &[1]).ph(4).end();
    b.begin("dev").cells("resets", &[4, 200]).end();
    let blob2 = b.finish();
    let fdt2 = Fdt::parse(&blob2).unwrap();
    let mut ctl2 = Jh7110Reset::sys(0);
    let mut rs2 = Resets::new();
    rs2.add(by_path(&fdt2, "/ctl").unwrap(), &mut ctl2).unwrap();
    assert_eq!(rs2.get(&fdt2, by_path(&fdt2, "/dev").unwrap(), Sel::Index(0)).unwrap_err(), Error::BadSpec);
}

#[test]
fn deassert_clears_the_bit_and_waits_for_the_status() {
    rig!(blob, fdt, log, bus, fx, rs, u);
    // Lines 74 and 75 (bits 10 and 11 of bank 2) are both held.
    bus.regs.insert(ASSERT2, 0x0000_0c01);
    let apb = rs.get(&fdt, u, Sel::Name("apb")).unwrap();
    rs.deassert(&mut bus, &mut fx, apb).unwrap();
    assert_eq!(
        log.all(),
        [
            eff(Op::Deassert, Class::Reversible, 74),
            Ev::R(ASSERT2),
            Ev::W(ASSERT2, 0x0000_0801),
            Ev::R(STATUS2),
        ]
    );
}

#[test]
fn assert_sets_the_bit_and_does_not_wait() {
    rig!(blob, fdt, log, bus, fx, rs, u);
    bus.regs.insert(ASSERT2, 0x0000_0001);
    let core = rs.get(&fdt, u, Sel::Name("core")).unwrap();
    rs.assert(&mut bus, &mut fx, core).unwrap();
    assert_eq!(
        log.all(),
        [eff(Op::Assert, Class::Safe, 75), Ev::R(ASSERT2), Ev::W(ASSERT2, 0x0000_0801)]
    );
    // The status bank (the hook's mirror) now reads the line as held.
    assert!(rs.is_asserted(&mut bus, core).unwrap());
}

#[test]
fn a_pulse_asserts_then_releases() {
    rig!(blob, fdt, log, bus, fx, rs, u);
    let apb = rs.get(&fdt, u, Sel::Name("apb")).unwrap();
    rs.pulse(&mut bus, &mut fx, apb).unwrap();
    assert_eq!(
        log.all(),
        [
            eff(Op::Assert, Class::Safe, 74),
            Ev::R(ASSERT2),
            Ev::W(ASSERT2, 0x0000_0400),
            eff(Op::Deassert, Class::Reversible, 74),
            Ev::R(ASSERT2),
            Ev::W(ASSERT2, 0),
            Ev::R(STATUS2),
        ]
    );
    assert!(!rs.is_asserted(&mut bus, apb).unwrap());
}

#[test]
fn a_release_the_hardware_never_confirms_times_out() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut bus = TraceBus::new(&log); // no hardware model: the status stays 0
    let mut fx = Sink::new(&log);
    let mut ctl = Jh7110Reset::sys(SYSCRG_BASE);
    let mut rs = Resets::new();
    rs.add(fdt.by_phandle(SYSCRG).unwrap(), &mut ctl).unwrap();
    let apb = rs.get(&fdt, uart(&fdt), Sel::Name("apb")).unwrap();
    assert_eq!(rs.deassert(&mut bus, &mut fx, apb), Err(Error::Timeout));
    assert_eq!(log.reads().iter().filter(|a| **a == STATUS2).count(), POLL_BUDGET as usize);
}

#[test]
fn a_refused_release_writes_nothing_but_an_assert_always_goes_ahead() {
    rig!(blob, fdt, log, bus, fx, rs, u);
    let _ = &mut fx;
    let apb = rs.get(&fdt, u, Sel::Name("apb")).unwrap();
    let mut deny = Sink::new(&log).refusing(|_| true);
    assert_eq!(rs.deassert(&mut bus, &mut deny, apb), Err(Error::Refused(77)));
    assert!(log.all().is_empty());
    rs.assert(&mut bus, &mut deny, apb).unwrap();
    assert_eq!(log.writes(), [(ASSERT2, 0x400)]);
}

#[test]
fn other_banks_and_other_blocks() {
    let log = Log::new();
    let mut fx = Sink::new(&log);
    // Line 3 of the always-on block: assert 0x38, status 0x3c.
    let mut bus = TraceBus::new(&log).with(0x1700_003c, 0x8);
    let mut aon = Jh7110Reset::aon(0x1700_0000);
    let mut b = Builder::new();
    b.begin("ctl").cells("#reset-cells", &[1]).ph(4).end();
    b.begin("dev").cells("resets", &[4, 3]).end();
    let blob = b.finish();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut rs = Resets::new();
    rs.add(by_path(&fdt, "/ctl").unwrap(), &mut aon).unwrap();
    let r = rs.get(&fdt, by_path(&fdt, "/dev").unwrap(), Sel::Index(0)).unwrap();
    bus.regs.insert(0x1700_0038, 0x8);
    rs.deassert(&mut bus, &mut fx, r).unwrap();
    assert_eq!(log.writes(), [(0x1700_0038, 0)]);
    // The system-wide block puts line 33 in its second bank.
    let mut sys = Jh7110Reset::sys(0x1000);
    let mut rs = Resets::new();
    rs.add(by_path(&fdt, "/ctl").unwrap(), &mut sys).unwrap();
    log.clear();
    let mut bus = TraceBus::new(&log);
    rs.assert(&mut bus, &mut fx, Rst { prov: 0, id: 33 }).unwrap();
    assert_eq!(log.writes(), [(0x1000 + 0x2f8 + 4, 0x2)]);
    let mut stg = Jh7110Reset::stg(0x2000);
    let mut rs = Resets::new();
    rs.add(by_path(&fdt, "/ctl").unwrap(), &mut stg).unwrap();
    log.clear();
    rs.assert(&mut bus, &mut fx, Rst { prov: 0, id: 0 }).unwrap();
    assert_eq!(log.writes(), [(0x2000 + 0x74, 0x1)]);
}

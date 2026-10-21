// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The power-domain framework and the JH7110 PMU register sequence.
use crate::support::*;
use azos_soc::consumer::Sel;
use azos_soc::effect::{Class, Effect, Op, KIND_POWER_DOMAIN};
use azos_soc::fdt::Fdt;
use azos_soc::jh7110::pmu::POLL_BUDGET;
use azos_soc::jh7110::Jh7110Pmu;
use azos_soc::pd::{Pd, PowerDomains};
use azos_soc::Error;

const TURN_ON: u64 = PMU_BASE + 0x0c;
const TURN_OFF: u64 = PMU_BASE + 0x10;
const ENCOURAGE: u64 = PMU_BASE + 0x44;
const CURR: u64 = PMU_BASE + 0x80;
const INT: u64 = PMU_BASE + 0x8c;

fn eff(op: Op, class: Class, id: u32) -> Ev {
    Ev::E(Effect { kind: KIND_POWER_DOMAIN, op, class, provider: 0, id, value: 0 })
}

/// The sequencer: the mask written to a turn-on or turn-off register takes
/// effect on the last encourage word (0x50 to turn on, 0xa0 to turn off,
/// after the opening 0xff; TRM 3.6.4); the done bit (or `fail`) is
/// raised in the interrupt status, and a write-1 clears it.
fn sequencer(fail: u32) -> Hook {
    let mut pending: Option<(bool, u32)> = None;
    Box::new(move |regs, addr, val| {
        let a = addr - PMU_BASE;
        match a {
            0x0c => pending = Some((true, val)),
            0x10 => pending = Some((false, val)),
            0x44 if val == 0x50 || val == 0xa0 => {
                if let Some((on, mask)) = pending.take() {
                    let cur = regs.get(&CURR).copied().unwrap_or(0);
                    regs.insert(CURR, if on { cur | mask } else { cur & !mask });
                    regs.insert(INT, if fail != 0 { fail } else { 1 });
                }
            }
            0x8c => {
                let cur = regs.get(&INT).copied().unwrap_or(0);
                regs.insert(INT, cur & !val);
            }
            _ => {}
        }
    })
}

macro_rules! rig {
    ($blob:ident, $fdt:ident, $log:ident, $bus:ident, $fx:ident, $pds:ident, $u:ident, $fail:expr) => {
        let $blob = board();
        let $fdt = Fdt::parse(&$blob).unwrap();
        let $log = Log::new();
        let mut $bus = TraceBus::new(&$log).hook(sequencer($fail));
        let mut $fx = Sink::new(&$log);
        let mut pmu = Jh7110Pmu::from_dt(&$fdt, $fdt.by_phandle(PMU).unwrap()).unwrap();
        let mut $pds = PowerDomains::new();
        $pds.add($fdt.by_phandle(PMU).unwrap(), &mut pmu).unwrap();
        let $u = uart(&$fdt);
    };
}

#[test]
fn the_gpu_domain_comes_from_the_consumer_and_powers_on_with_the_pmu_sequence() {
    rig!(blob, fdt, log, bus, fx, pds, u, 0);
    let d = pds.get(&fdt, u, Sel::Name("gpu")).unwrap();
    assert_eq!(d, Pd { prov: 0, id: 2 });
    assert_eq!(pds.get(&fdt, u, Sel::Index(0)).unwrap(), d);
    pds.on(&mut bus, &mut fx, d).unwrap();
    assert_eq!(
        log.all(),
        [
            eff(Op::PowerOn, Class::Reversible, 2),
            Ev::R(CURR),
            Ev::W(TURN_ON, 0x4),
            Ev::W(ENCOURAGE, 0xff),
            Ev::W(ENCOURAGE, 0x05),
            Ev::W(ENCOURAGE, 0x50),
            Ev::R(INT),
            Ev::W(INT, 0x1),
        ]
    );
    assert!(pds.is_on(&mut bus, d).unwrap());
}

#[test]
fn powering_off_uses_the_disable_words_and_the_turn_off_register() {
    rig!(blob, fdt, log, bus, fx, pds, u, 0);
    let d = pds.get(&fdt, u, Sel::Index(0)).unwrap();
    pds.on(&mut bus, &mut fx, d).unwrap();
    log.clear();
    pds.off(&mut bus, &mut fx, d).unwrap();
    assert_eq!(
        log.all(),
        [
            eff(Op::PowerOff, Class::Safe, 2),
            Ev::R(CURR),
            Ev::W(TURN_OFF, 0x4),
            Ev::W(ENCOURAGE, 0xff),
            Ev::W(ENCOURAGE, 0x0a),
            Ev::W(ENCOURAGE, 0xa0),
            Ev::R(INT),
            Ev::W(INT, 0x1),
        ]
    );
    assert!(!pds.is_on(&mut bus, d).unwrap());
}

#[test]
fn users_are_counted_the_first_powers_on_and_the_last_powers_off() {
    rig!(blob, fdt, log, bus, fx, pds, u, 0);
    let d = pds.get(&fdt, u, Sel::Index(0)).unwrap();
    pds.on(&mut bus, &mut fx, d).unwrap();
    log.clear();
    pds.on(&mut bus, &mut fx, d).unwrap();
    assert!(log.all().is_empty());
    assert_eq!(pds.refs(d), 2);
    pds.off(&mut bus, &mut fx, d).unwrap();
    assert!(log.all().is_empty());
    assert_eq!(pds.refs(d), 1);
    pds.off(&mut bus, &mut fx, d).unwrap();
    assert_eq!(log.writes().iter().filter(|(a, _)| *a == TURN_OFF).count(), 1);
    assert_eq!(pds.off(&mut bus, &mut fx, d), Err(Error::Unbalanced));
}

#[test]
fn a_domain_already_in_the_wanted_state_is_not_touched() {
    rig!(blob, fdt, log, bus, fx, pds, u, 0);
    bus.regs.insert(CURR, 0x4);
    let d = pds.get(&fdt, u, Sel::Index(0)).unwrap();
    pds.on(&mut bus, &mut fx, d).unwrap();
    assert!(log.writes().is_empty());
    assert_eq!(pds.refs(d), 1);
}

#[test]
fn a_sequencer_failure_is_reported_and_not_counted() {
    rig!(blob, fdt, log, bus, fx, pds, u, 0x4);
    let d = pds.get(&fdt, u, Sel::Index(0)).unwrap();
    assert_eq!(pds.on(&mut bus, &mut fx, d), Err(Error::Hardware));
    assert_eq!(pds.refs(d), 0);
    // The failure bit was acknowledged.
    assert_eq!(log.writes().last(), Some(&(INT, 0x4)));
}

#[test]
fn a_sequencer_that_never_answers_times_out() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut bus = TraceBus::new(&log);
    let mut fx = Sink::new(&log);
    let mut pmu = Jh7110Pmu::from_dt(&fdt, fdt.by_phandle(PMU).unwrap()).unwrap();
    let mut pds = PowerDomains::new();
    pds.add(fdt.by_phandle(PMU).unwrap(), &mut pmu).unwrap();
    let d = pds.get(&fdt, uart(&fdt), Sel::Index(0)).unwrap();
    assert_eq!(pds.on(&mut bus, &mut fx, d), Err(Error::Timeout));
    assert_eq!(log.reads().iter().filter(|a| **a == INT).count(), POLL_BUDGET as usize);
    assert_eq!(pds.refs(d), 0);
}

#[test]
fn refusals_and_bad_domains() {
    rig!(blob, fdt, log, bus, fx, pds, u, 0);
    let _ = &mut fx;
    let d = pds.get(&fdt, u, Sel::Index(0)).unwrap();
    let mut deny = Sink::new(&log).refusing(|_| true);
    assert_eq!(pds.on(&mut bus, &mut deny, d), Err(Error::Refused(77)));
    assert!(log.all().is_empty());
    assert_eq!(pds.refs(d), 0);
    // Seven domains: 0..=6.
    assert_eq!(pds.on(&mut bus, &mut deny, Pd { prov: 0, id: 9 }), Err(Error::BadSpec));
    assert_eq!(pds.get(&fdt, u, Sel::Name("nope")).unwrap_err(), Error::NotFound);
    assert!(Jh7110Pmu::from_dt(&fdt, fdt.by_phandle(SYSCRG).unwrap()).is_none());
}

#[test]
fn powering_off_is_never_refused() {
    rig!(blob, fdt, log, bus, fx, pds, u, 0);
    let d = pds.get(&fdt, u, Sel::Index(0)).unwrap();
    pds.on(&mut bus, &mut fx, d).unwrap();
    log.clear();
    let mut deny = Sink::new(&log).refusing(|_| true);
    pds.off(&mut bus, &mut deny, d).unwrap();
    assert!(log.writes().contains(&(TURN_OFF, 0x4)));
}

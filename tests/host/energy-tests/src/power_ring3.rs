// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The limits the kernel keeps for the ring-3 power service (owner plan,
//! Energy section 8): per-domain power caps, core parking, the QoS mapping and
//! the battery report with its reserve, all in `azos_energy::policy`. The
//! service decides; each setter here is a limit check that refuses what would
//! break a floor, records the refusal, and leaves the old value in force.
//!
//! Wired into the suite by `mod power_ring3;` in `src/lib.rs`.
//!
//! Canaries (`Cargo.toml`): `pl-limit-canary` removes the floors and
//! structural checks of the three setters and the report's required level,
//! and must fail exactly the `limits_*` tests below; `pl-reserve-canary`
//! never holds the reserve at the charge and must fail exactly the `reserve_*`
//! tests; `pl-stale-canary` never lets a report go stale and must fail the
//! `stale_*` tests (and `reserve_a_service_that_died_in_it_*`, which needs the
//! hold of a died service as well as the reserve);
//! `pl-record-canary` (the existing one) now also silences these refusals'
//! records, which `a_new_refusal_is_recorded` pins.

use azos_abi::power::*;
use azos_energy::governor::{Decision, HEADROOM_PCT};
use azos_energy::model::{IdleState, Opp, PerfDomain};
use azos_energy::policy::{BatteryLimits, DegradeRow, LevelChange, NONE_U8};
use azos_energy::{EnergyMode, EnergyModel, Governor, ModelSource, Policy, Refusal};

fn opp(f: u32, c: u16, p: u32) -> Opp {
    Opp { freq_khz: f, capacity: c, power_mw: p }
}

/// Two domains: `little` (CPUs 0 and 1, capacity up to 512, 30 .. 400 mW) and
/// `big` (CPUs 2 and 3, capacity up to 1024, 100 .. 1800 mW). The default
/// machine's WCET references put the safety floor at `little`'s top OPP and at
/// OPP 2 of `big`; [`lax`] puts both at OPP 0.
fn machine_with(little_wcet_khz: u32, big_wcet_khz: u32) -> EnergyModel {
    let mut little = PerfDomain::new(0b0011);
    for o in [opp(300_000, 100, 30), opp(600_000, 250, 100), opp(1_000_000, 400, 220), opp(1_400_000, 512, 400)] {
        little.push_opp(o).unwrap();
    }
    little.push_idle(IdleState::new(b"wfi", 1, 1, 8)).unwrap();
    little.wcet_ref_khz = little_wcet_khz;
    let mut big = PerfDomain::new(0b1100);
    for o in [opp(500_000, 128, 100), opp(1_000_000, 256, 300), opp(1_500_000, 512, 900), opp(2_000_000, 1024, 1_800)] {
        big.push_opp(o).unwrap();
    }
    big.push_idle(IdleState::new(b"wfi", 1, 1, 8)).unwrap();
    big.wcet_ref_khz = big_wcet_khz;
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    m.push_domain(little).unwrap();
    m.push_domain(big).unwrap();
    m
}

fn machine() -> EnergyModel {
    machine_with(1_400_000, 1_500_000)
}

/// No WCET reference above the slowest OPP: only the reservations bind.
fn lax() -> EnergyModel {
    machine_with(300_000, 500_000)
}

fn fresh() -> Policy {
    Policy::new(Governor::DeadlineFloor)
}

/// The decision the deadline-floor governor takes for domain `d` of `m`.
fn decision(m: &EnergyModel, d: usize, util: u32, ppm: u32) -> Decision {
    Governor::DeadlineFloor.target_opp(&m.domains()[d], util, 3, ppm, HEADROOM_PCT).unwrap()
}

// ── per-domain power cap ────────────────────────────────────────────────────

#[test]
fn a_power_cap_becomes_the_highest_opp_within_it() {
    let (m, p) = (lax(), fresh());
    // `big`: 100, 300, 900, 1800 mW. 1000 mW allows OPP 2.
    assert_eq!(p.set_power_cap(&m, 1, 1_000, 0), Ok(()));
    assert_eq!(p.power_cap(1), (1_000, 2));
    // Exactly an OPP's power allows that OPP.
    assert_eq!(p.set_power_cap(&m, 1, 900, 0), Ok(()));
    assert_eq!(p.power_cap(1), (900, 2));
    assert_eq!(p.set_power_cap(&m, 1, 899, 0), Ok(()));
    assert_eq!(p.power_cap(1), (899, 1), "one mW under OPP 2 allows OPP 1");
    // The other domain is untouched.
    assert_eq!(p.power_cap(0), (0, NONE_U8));
}

#[test]
fn a_power_cap_at_or_above_the_top_is_no_ceiling_and_zero_lifts_it() {
    let (m, p) = (machine(), fresh());
    assert_eq!(p.set_power_cap(&m, 1, 1_800, 0), Ok(()));
    assert_eq!(p.power_cap(1), (1_800, NONE_U8), "the top OPP fits: nothing to cap");
    assert_eq!(p.set_power_cap(&m, 1, 1_000, 0), Ok(()));
    assert_eq!(p.set_power_cap(&m, 1, 0, 0), Ok(()));
    assert_eq!(p.power_cap(1), (0, NONE_U8));
}

#[test]
fn the_power_cap_bounds_the_governor_and_the_floors_win_again() {
    let m = machine();
    let p = fresh();
    assert_eq!(p.set_power_cap(&m, 1, 900, 0), Ok(()));
    // Full load, nothing admitted: the cap holds the clock at OPP 2.
    let dec = decision(&m, 1, azos_energy::SCALE, 0);
    assert_eq!(dec.schedutil, 3);
    assert_eq!(p.clamp(1, dec).opp, 2);
    assert_eq!(p.floor_wins(), 0);
    // The cap was legal; 70 % of the machine is admitted since. Capacity
    // needed: OPP 3. The deadline floor beats the cap, and it is counted.
    let dec = decision(&m, 1, 0, 700_000);
    assert_eq!(dec.deadline, 3);
    assert_eq!(p.clamp(1, dec).opp, 3);
    assert_eq!(p.floor_wins(), 1);
}

#[test]
fn a_power_cap_is_a_ceiling_beside_the_opp_range() {
    let (m, p) = (lax(), fresh());
    assert_eq!(p.set_opp_range(&m, 1, 0, 2, 0), Ok(()));
    assert_eq!(p.set_power_cap(&m, 1, 300, 0), Ok(()));
    let full = decision(&m, 1, azos_energy::SCALE, 0);
    assert_eq!(p.clamp(1, full).opp, 1, "the cap (OPP 1) is under the range (OPP 2)");
    assert_eq!(p.set_power_cap(&m, 1, 1_800, 0), Ok(()));
    assert_eq!(p.clamp(1, full).opp, 2, "lifted, the range holds");
}

#[test]
fn limits_a_power_cap_below_the_safety_floor_is_refused() {
    let (m, p) = (machine(), fresh());
    // `big`'s safety floor is OPP 2 (900 mW): 300 mW would cap at OPP 1; and
    // `little`'s is its top.
    assert_eq!(azos_energy::governor::safety_floor_opp(&m.domains()[1]), 2);
    assert_eq!(p.set_power_cap(&m, 1, 300, 0), Err(Refusal::SafetyFloor));
    assert_eq!(p.set_power_cap(&m, 0, 100, 0), Err(Refusal::SafetyFloor));
    assert_eq!(p.power_cap(1), (0, NONE_U8), "a refusal changes nothing");
    assert_eq!(p.set_power_cap(&m, 1, 900, 0), Ok(()), "the floor's own power is allowed");
}

#[test]
fn limits_a_power_cap_below_the_deadline_floor_is_refused() {
    let (m, p) = (lax(), fresh());
    let ppm = 400_000; // 40 % of the machine and the margin: capacity 492 of 1024
    assert_eq!(azos_energy::governor::deadline_floor_opp(&m.domains()[1], ppm), 2);
    assert_eq!(p.set_power_cap(&m, 1, 300, ppm), Err(Refusal::DeadlineFloor), "OPP 1 is under the floor");
    assert_eq!(p.power_cap(1), (0, NONE_U8));
    assert_eq!(p.set_power_cap(&m, 1, 300, 0), Ok(()), "legal with nothing admitted");
    assert_eq!(p.set_power_cap(&m, 1, 900, ppm), Ok(()), "OPP 2 is the floor itself");
}

#[test]
fn a_power_cap_below_the_slowest_opp_or_on_nothing_is_refused() {
    let (m, p) = (machine(), fresh());
    assert_eq!(p.set_power_cap(&m, 1, 99, 0), Err(Refusal::Range), "no OPP runs on 99 mW");
    assert_eq!(p.set_power_cap(&m, 2, 500, 0), Err(Refusal::Domain));
    assert_eq!(p.set_power_cap(&EnergyModel::NONE, 0, 500, 0), Err(Refusal::NoModel));
    assert_eq!(p.refused(), 3);
}

// ── core parking ────────────────────────────────────────────────────────────

#[test]
fn parking_applies_and_unparking_is_always_allowed() {
    let (m, p) = (machine(), fresh());
    let none = [0u32; 32];
    assert_eq!(p.set_parked(&m, 0b1010, &none), Ok(()), "one CPU of each domain");
    assert_eq!(p.parked(), 0b1010);
    assert_eq!(p.set_parked(&m, 0, &[900_000; 32]), Ok(()), "unparking is allowed even with work admitted");
    assert_eq!(p.parked(), 0);
}

#[test]
fn parking_refuses_cpu_zero_unknown_cpus_and_a_whole_domain() {
    let (m, p) = (machine(), fresh());
    let none = [0u32; 32];
    assert_eq!(p.set_parked(&m, 0b0001, &none), Err(Refusal::Park), "CPU 0 keeps the watchdog");
    assert_eq!(p.set_parked(&m, 0b1_0000, &none), Err(Refusal::Park), "a CPU the model does not cover");
    assert_eq!(p.set_parked(&m, 0b1100, &none), Err(Refusal::Park), "both CPUs of `big`");
    assert_eq!(p.set_parked(&m, 0b0010, &none), Ok(()), "CPU 1: `little` keeps CPU 0");
    assert_eq!(p.parked(), 0b0010);
    assert_eq!(p.set_parked(&EnergyModel::NONE, 0b1000, &none), Err(Refusal::NoModel));
}

#[test]
fn limits_parking_a_cpu_with_admitted_real_time_work_is_refused() {
    let (m, p) = (machine(), fresh());
    let mut ppm = [0u32; 32];
    ppm[3] = 200_000;
    assert_eq!(p.set_parked(&m, 0b1000, &ppm), Err(Refusal::DeadlineFloor));
    assert_eq!(p.parked(), 0, "a refusal changes nothing");
    assert_eq!(p.set_parked(&m, 0b0100, &ppm), Ok(()), "the other CPU of `big` is free");
}

// ── the QoS mapping ─────────────────────────────────────────────────────────

const DEFAULT: u32 = 0;
const LATENCY: u32 = 1;
const THROUGHPUT: u32 = 2;
const BACKGROUND: u32 = 3;

#[test]
fn qos_classes_start_everywhere_and_can_be_confined() {
    let (m, p) = (machine(), fresh());
    for c in 0..4 {
        assert_eq!(p.qos_domains(c), 0xFF, "class {c}");
    }
    assert_eq!(p.set_qos_domains(&m, BACKGROUND, 0b01), Ok(()), "background on `little` only");
    assert_eq!(p.set_qos_domains(&m, THROUGHPUT, 0b11), Ok(()));
    assert_eq!(p.qos_domains(BACKGROUND as usize), 0b01);
    assert_eq!(p.qos_domains(THROUGHPUT as usize), 0b11);
    assert_eq!(p.qos_domains(DEFAULT as usize), 0xFF, "the others are untouched");
}

#[test]
fn qos_refuses_what_has_no_meaning() {
    let (m, p) = (machine(), fresh());
    assert_eq!(p.set_qos_domains(&m, 4, 0b11), Err(Refusal::Qos), "not a class");
    assert_eq!(p.set_qos_domains(&m, BACKGROUND, 0), Err(Refusal::Qos), "nowhere to run");
    assert_eq!(p.set_qos_domains(&m, BACKGROUND, 0b100), Err(Refusal::Qos), "a domain the model does not have");
    assert_eq!(p.set_qos_domains(&EnergyModel::NONE, BACKGROUND, 1), Err(Refusal::NoModel));
    assert_eq!(p.qos_domains(BACKGROUND as usize), 0xFF);
}

#[test]
fn limits_the_default_and_latency_classes_keep_the_fastest_domain() {
    let (m, p) = (machine(), fresh());
    // `big` (domain 1) is the fastest.
    assert_eq!(p.set_qos_domains(&m, LATENCY, 0b01), Err(Refusal::Qos));
    assert_eq!(p.set_qos_domains(&m, DEFAULT, 0b01), Err(Refusal::Qos));
    assert_eq!(p.set_qos_domains(&m, LATENCY, 0b10), Ok(()), "the fastest alone is fine");
    assert_eq!(p.set_qos_domains(&m, DEFAULT, 0b11), Ok(()));
    assert_eq!(p.set_qos_domains(&m, THROUGHPUT, 0b01), Ok(()), "throughput may be exiled");
}

// ── the battery ─────────────────────────────────────────────────────────────

fn rows() -> [DegradeRow; 3] {
    [
        DegradeRow { level: 1, battery_pct: 30, clear_pct: 35 },
        DegradeRow { level: 2, battery_pct: 20, clear_pct: 25 },
        DegradeRow { level: 3, battery_pct: 12, clear_pct: 15 },
    ]
}

/// A 10 % reserve and a report older than 1000 ticks is stale (what a build
/// with the Kconfig defaults hands over, in other units).
const RESERVE_PCT: u32 = 10;
const TIMEOUT: u64 = 1_000;
const LIMITS: BatteryLimits = BatteryLimits { reserve_pct: RESERVE_PCT as u8, report_timeout_ticks: TIMEOUT };

fn with_rows() -> Policy {
    let p = fresh();
    p.init_battery(&rows(), LIMITS, 0);
    p
}

#[test]
fn a_report_applies_and_a_change_of_level_is_returned_once() {
    let p = with_rows();
    assert_eq!(p.report_battery(80, 0), Ok(None), "no change from level 0");
    assert_eq!((p.soc_pct(), p.level()), (80, 0));
    assert_eq!(p.report_battery(29, 1), Ok(Some(LevelChange { soc_pct: 29, from: 0, to: 1 })));
    assert_eq!(p.report_battery(28, 1), Ok(None), "the same level again is not a change");
    assert_eq!(p.report_battery(19, 2), Ok(Some(LevelChange { soc_pct: 19, from: 1, to: 2 })));
    assert_eq!(p.degrades(), 2);
    // Leaving a level is the service's, with its hysteresis: the kernel takes it.
    assert_eq!(p.report_battery(33, 1), Ok(Some(LevelChange { soc_pct: 33, from: 2, to: 1 })));
    assert_eq!(p.degrades(), 3);
}

#[test]
fn a_service_may_degrade_earlier_than_the_rows_ask() {
    let p = with_rows();
    assert_eq!(p.report_battery(90, 2), Ok(Some(LevelChange { soc_pct: 90, from: 0, to: 2 })), "constrain-only");
}

#[test]
fn limits_a_level_lighter_than_the_rows_require_is_refused() {
    let p = with_rows();
    assert_eq!(p.required_level(80), 0);
    assert_eq!(p.required_level(30), 1);
    assert_eq!(p.required_level(20), 2);
    assert_eq!(p.required_level(0), 3);
    assert_eq!(p.report_battery(19, 1), Err(Refusal::Battery), "20 % and below is level 2");
    assert_eq!(p.report_battery(11, 0), Err(Refusal::Battery));
    assert_eq!((p.soc_pct(), p.level()), (NONE_U8, 0), "a refusal changes nothing");
    assert_eq!(p.report_battery(11, 3), Ok(Some(LevelChange { soc_pct: 11, from: 0, to: 3 })));
}

#[test]
fn a_report_the_declaration_cannot_take_is_refused() {
    let p = with_rows();
    assert_eq!(p.report_battery(101, 0), Err(Refusal::Battery), "over 100 %");
    assert_eq!(p.report_battery(50, 4), Err(Refusal::Battery), "no such level");
    // A topology without rows has no battery to report.
    let bare = fresh();
    assert_eq!(bare.report_battery(50, 0), Err(Refusal::Battery));
    // A level the rows do not name (here: no level 2 row).
    let two = fresh();
    two.init_battery(&[rows()[0], rows()[2]], LIMITS, 0);
    assert_eq!(two.report_battery(50, 2), Err(Refusal::Battery));
    assert_eq!(two.report_battery(50, 3), Ok(Some(LevelChange { soc_pct: 50, from: 0, to: 3 })));
}

#[test]
fn reserve_is_held_at_and_below_the_floor_and_lifted_above_it() {
    let p = with_rows();
    assert!(!p.reserve_active());
    assert_eq!(p.report_battery(RESERVE_PCT + 1, 3), Ok(Some(LevelChange { soc_pct: 11, from: 0, to: 3 })));
    assert!(!p.reserve_active(), "just above the reserve");
    assert_eq!(p.report_battery(RESERVE_PCT, 3), Ok(None));
    assert!(p.reserve_active(), "at it");
    assert_eq!(p.reserve_entries(), 1);
    assert_eq!(p.report_battery(5, 3), Ok(None));
    assert_eq!(p.reserve_entries(), 1, "staying in the reserve is not entering it");
    assert_eq!(p.report_battery(14, 3), Ok(None));
    assert!(!p.reserve_active(), "the charge came back");
    assert_eq!(p.report_battery(9, 3), Ok(None));
    assert_eq!(p.reserve_entries(), 2);
}

#[test]
fn reserve_takes_every_domain_to_its_lowest_legal_opp_whatever_the_policy_asked() {
    let m = machine();
    let p = with_rows();
    // The service asked for the fastest everywhere and a governor that does not govern.
    assert_eq!(p.set_governor(&m, POLICY_GOV_FIXED as u32), Ok(()));
    assert_eq!(p.set_opp_range(&m, 1, 3, 3, 0), Ok(()));
    assert_eq!(p.governor(), Governor::Fixed);
    assert_eq!(p.effective_governor(), Governor::Fixed);
    let full = decision(&m, 1, azos_energy::SCALE, 0);
    assert_eq!(p.clamp(1, full).opp, 3);
    assert_eq!(p.report_battery(8, 3), Ok(Some(LevelChange { soc_pct: 8, from: 0, to: 3 })));
    assert_eq!(p.governor(), Governor::Fixed, "what the service asked for reads back as asked");
    assert_eq!(p.effective_governor(), Governor::DeadlineFloor, "the kernel governs while the reserve is held");
    // The range said OPP 3; the reserve says the lowest. The safety floor (2) still wins.
    assert_eq!(p.clamp(1, full).opp, 2);
    assert_eq!(p.floor_wins(), 1);
    // And an admitted reservation still wins over the reserve.
    let rt = decision(&m, 1, 0, 700_000);
    assert_eq!(p.clamp(1, rt).opp, 3, "I1 holds in the reserve");
    // The reserve lifts: the range is back.
    assert_eq!(p.report_battery(60, 0), Ok(Some(LevelChange { soc_pct: 60, from: 3, to: 0 })));
    assert_eq!(p.effective_governor(), Governor::Fixed);
    assert_eq!(p.clamp(1, full).opp, 3);
}

// ── the words the service reads ─────────────────────────────────────────────

fn word(p: &Policy, m: &EnergyModel, sel: u64) -> Option<u64> {
    p.state_word(m, EnergyMode::Balanced, |_| 255, sel)
}

#[test]
fn the_state_words_describe_the_machine_and_the_new_limits() {
    let (m, p) = (machine(), with_rows());
    assert_eq!(word(&p, &m, POLICY_STATE_MODE), Some(1));
    assert_eq!(word(&p, &m, POLICY_STATE_DOMAINS), Some(2));
    assert_eq!(word(&p, &m, POLICY_STATE_CPUS_BASE), Some(0b0011));
    assert_eq!(word(&p, &m, POLICY_STATE_CPUS_BASE + 1), Some(0b1100));
    assert_eq!(word(&p, &m, POLICY_STATE_CPUS_BASE + 2), None, "no third domain");
    // OPP 3 of `big`: 1800 mW, capacity 1024.
    assert_eq!(word(&p, &m, POLICY_STATE_OPP_BASE + POLICY_STATE_OPP_STRIDE + 3), Some(1_800 | 1_024 << 32));
    assert_eq!(word(&p, &m, POLICY_STATE_OPP_BASE + 4), None, "`little` has four OPPs");
    // Power cap, parking, QoS.
    assert_eq!(p.set_power_cap(&m, 1, 1_000, 0), Ok(()));
    assert_eq!(word(&p, &m, POLICY_STATE_POWER_CAP_BASE + 1), Some(1_000));
    assert_eq!(p.set_parked(&m, 0b1000, &[0; 32]), Ok(()));
    assert_eq!(word(&p, &m, POLICY_STATE_PARKED), Some(0b1000));
    assert_eq!(p.set_qos_domains(&m, BACKGROUND, 0b01), Ok(()));
    assert_eq!(word(&p, &m, POLICY_STATE_QOS_BASE + BACKGROUND as u64), Some(0b01));
}

#[test]
fn the_battery_words_carry_the_rows_the_charge_and_the_level() {
    let (m, p) = (machine(), with_rows());
    // Rows: level | battery_pct << 8 | clear_pct << 16.
    assert_eq!(word(&p, &m, POLICY_STATE_BATTERY_ROW_BASE), Some(1 | 30 << 8 | 35 << 16));
    assert_eq!(word(&p, &m, POLICY_STATE_BATTERY_ROW_BASE + 2), Some(3 | 12 << 8 | 15 << 16));
    assert_eq!(word(&p, &m, POLICY_STATE_BATTERY_ROW_BASE + 3), None);
    // Before the first report: charge unknown, level 0, 3 rows.
    assert_eq!(word(&p, &m, POLICY_STATE_BATTERY), Some(255 | 3 << 24 | 10 << 40));
    p.report_battery(25, 1).unwrap();
    // soc 25, level 1, reserve not held, 3 rows, not stale, a 10 % reserve.
    assert_eq!(word(&p, &m, POLICY_STATE_BATTERY), Some(25 | 1 << 8 | 3 << 24 | 10 << 40));
    assert_eq!(p.stats_word(0, 0, POLICY_STATS_DEGRADES), Some(1));
    assert_eq!(p.stats_word(0, 0, POLICY_STATS_RESERVE_ENTRIES), Some(0));
    assert_eq!(p.stats_word(0, 0, POLICY_STATS_STALE_ENTRIES), Some(0));
    assert_eq!(word(&p, &m, 0x7F), None, "an unknown selector");
}

#[test]
fn reserve_follows_the_configured_percent_not_a_constant() {
    let p = fresh();
    p.init_battery(&rows(), BatteryLimits { reserve_pct: 20, report_timeout_ticks: TIMEOUT }, 0);
    assert_eq!(p.reserve_pct(), 20);
    assert_eq!(p.report_battery(21, 2), Ok(Some(LevelChange { soc_pct: 21, from: 0, to: 2 })));
    assert!(!p.reserve_active());
    assert_eq!(p.report_battery(20, 2), Ok(None));
    assert!(p.reserve_active(), "20 % is the reserve of this build");
    let (m, q) = (machine(), with_rows());
    q.report_battery(15, 3).unwrap();
    assert!(!q.reserve_active(), "15 % is above a 10 % reserve");
    assert_eq!(word(&q, &m, POLICY_STATE_BATTERY).unwrap() >> 40, 10);
}

// ── the age of the report ───────────────────────────────────────────────────

/// An accepted report at `at`, as the scheduler hook follows it.
fn report_at(p: &Policy, at: u64, soc: u32, level: u32) {
    p.report_battery(soc, level).unwrap();
    p.battery_alive(at);
}

#[test]
fn stale_a_report_older_than_the_timeout_holds_the_reserve() {
    let (m, p) = (machine(), with_rows());
    report_at(&p, 100, 80, 0);
    assert!(!p.reserve_active(), "80 % is far above the reserve");
    let full = decision(&m, 1, azos_energy::SCALE, 0);
    assert!(!p.check_report_age(100 + TIMEOUT), "an age of exactly the timeout is fresh");
    assert!(!p.stale());
    assert!(p.set_opp_range(&m, 1, 3, 3, 0).is_ok());
    assert_eq!(p.clamp(1, full).opp, 3);
    assert!(p.check_report_age(100 + TIMEOUT + 1), "one tick past it: the hold changed");
    assert!(p.stale() && p.reserve_active());
    assert_eq!(p.stale_entries(), 1);
    assert_eq!(p.reserve_entries(), 0, "the charge never reached the reserve");
    assert_eq!(p.effective_governor(), Governor::DeadlineFloor);
    assert_eq!(p.clamp(1, full).opp, 2, "the lowest legal OPP: the safety floor");
    assert!(!p.check_report_age(100 + 5 * TIMEOUT), "staying stale is not a change");
    assert_eq!(p.stale_entries(), 1);
    // The charge last reported stays as it was: the kernel does not invent one.
    assert_eq!(p.soc_pct(), 80);
}

#[test]
fn stale_the_next_accepted_report_ends_the_hold() {
    let (m, p) = (machine(), with_rows());
    report_at(&p, 0, 80, 0);
    assert!(p.check_report_age(TIMEOUT + 1));
    // The service came back with a pack that is fine: out of the hold.
    report_at(&p, 3 * TIMEOUT, 79, 0);
    assert!(!p.stale() && !p.reserve_active());
    assert!(!p.check_report_age(3 * TIMEOUT + TIMEOUT), "the age restarted");
    assert_eq!(word(&p, &m, POLICY_STATE_BATTERY).unwrap() >> 16 & 1, 0);
    // And the next silence is a second entry.
    assert!(p.check_report_age(3 * TIMEOUT + TIMEOUT + 1));
    assert_eq!(p.stale_entries(), 2);
}

#[test]
fn reserve_a_service_that_died_in_it_does_not_leave_by_itself_but_can() {
    let p = with_rows();
    report_at(&p, 0, 8, 3);
    assert!(p.reserve_active() && !p.stale());
    assert!(p.check_report_age(TIMEOUT + 1));
    assert!(p.reserve_active() && p.stale());
    // Back from a restart with the pack recharged: the reserve is lifted.
    report_at(&p, 5 * TIMEOUT, 70, 0);
    assert!(!p.reserve_active());
    // Back with the pack still low: the charge holds it, not the age.
    report_at(&p, 6 * TIMEOUT, 6, 3);
    assert!(p.reserve_active() && !p.stale());
}

#[test]
fn stale_a_refused_report_is_not_a_sign_of_life() {
    let p = with_rows();
    report_at(&p, 0, 80, 0);
    assert_eq!(p.report_battery(101, 0), Err(Refusal::Battery));
    // The caller does not call `battery_alive` for a refusal, so the age runs on.
    assert!(p.check_report_age(TIMEOUT + 1));
}

#[test]
fn stale_the_age_runs_from_boot_when_the_service_never_reports() {
    let p = fresh();
    p.init_battery(&rows(), LIMITS, 500);
    assert!(!p.check_report_age(500 + TIMEOUT));
    assert_eq!(p.soc_pct(), NONE_U8);
    assert!(p.check_report_age(500 + TIMEOUT + 1));
    assert!(p.reserve_active());
}

#[test]
fn stale_a_machine_without_a_battery_has_nothing_to_age() {
    let p = fresh();
    p.init_battery(&[], LIMITS, 0);
    assert!(!p.check_report_age(100 * TIMEOUT));
    assert!(!p.stale() && !p.reserve_active());
    // Never initialised at all (no `install_battery`): the same.
    let q = fresh();
    assert!(!q.check_report_age(u64::MAX));
    assert!(!q.reserve_active());
}

#[test]
fn stale_the_timeout_is_the_configured_one() {
    let p = fresh();
    p.init_battery(&rows(), BatteryLimits { reserve_pct: 10, report_timeout_ticks: 50 }, 0);
    assert!(!p.check_report_age(50));
    assert!(p.check_report_age(51));
}

#[test]
fn stale_shows_in_the_state_and_stats_words() {
    let (m, p) = (machine(), with_rows());
    report_at(&p, 0, 80, 0);
    assert_eq!(word(&p, &m, POLICY_STATE_BATTERY), Some(80 | 3 << 24 | 10 << 40));
    p.check_report_age(TIMEOUT + 1);
    // reserve_held (bit 16) and stale (bit 32) are both set.
    assert_eq!(word(&p, &m, POLICY_STATE_BATTERY), Some(80 | 1 << 16 | 3 << 24 | 1 << 32 | 10 << 40));
    assert_eq!(p.stats_word(0, 0, POLICY_STATS_STALE_ENTRIES), Some(1));
    assert_eq!(p.stats_word(0, 0, POLICY_STATS_RESERVE_ENTRIES), Some(0));
}

// ── records ─────────────────────────────────────────────────────────────────

/// A refusal of each new setter is counted by reason and leaves a record with
/// the setter's number and the argument as it travels. (The refusals chosen
/// are structural ones, so this test pins the record and no limit.)
#[test]
fn a_new_refusal_is_recorded() {
    let (m, p) = (machine(), with_rows());
    let rec = |p: &Policy| {
        let r = p.refusal(0);
        (r >> 56, (r >> 48) & 0xFF, r & 0xFFFF_FFFF)
    };
    assert_eq!(p.set_power_cap(&m, 1, 99, 0), Err(Refusal::Range));
    assert_eq!(rec(&p), (POWER_OP_POLICY_POWER_CAP, POLICY_REFUSED_RANGE as u64, 1 | 99 << 8), "domain 1, 99 mW");
    assert_eq!(p.set_parked(&m, 0b1_0000, &[0; 32]), Err(Refusal::Park));
    assert_eq!(rec(&p), (POWER_OP_POLICY_PARK, POLICY_REFUSED_PARK as u64, 0b1_0000));
    assert_eq!(p.set_qos_domains(&m, 4, 0b11), Err(Refusal::Qos));
    assert_eq!(rec(&p), (POWER_OP_POLICY_QOS_DOMAINS, POLICY_REFUSED_QOS as u64, 4 | 0b11 << 8));
    assert_eq!(p.report_battery(101, 0), Err(Refusal::Battery));
    assert_eq!(rec(&p), (POWER_OP_POLICY_BATTERY, POLICY_REFUSED_BATTERY as u64, 101));
    assert_eq!(p.refused(), 4);
    for reason in [POLICY_REFUSED_RANGE, POLICY_REFUSED_PARK, POLICY_REFUSED_QOS, POLICY_REFUSED_BATTERY] {
        assert_eq!(p.refused_by(reason as usize), 1, "reason {reason}");
    }
}

#[test]
fn refusal_codes_of_the_new_setters_are_distinct_and_in_range() {
    let new = [Refusal::Park, Refusal::Qos, Refusal::Battery];
    for (i, a) in new.iter().enumerate() {
        assert!(a.code() >= POLICY_REFUSED_IDLE_DEPTH + 1 && (a.code() as usize) < POLICY_REFUSED_COUNT);
        for b in &new[i + 1..] {
            assert_ne!(a.code(), b.code());
        }
    }
}

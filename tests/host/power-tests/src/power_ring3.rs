// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring-3 power service's battery model, degrade rows and budget (owner
//! plan, Energy section 8), run against a kernel whose limits are the real
//! ones (`azos_energy::policy`) and whose state words are the real ones
//! (`Policy::state_word`, the function the kernel's `policy_state` calls).
//!
//! The service's files are pulled in by path, so the code under test is the
//! code `POWER.ELF` is built from:
//!
//! * `battery.rs` — the charge from the INA219 samples;
//! * `degrade.rs` — the topology's rows and the level a charge selects;
//! * `policy.rs` (already in the crate as `crate::policy`) — the plan, the
//!   budget and how a refusal is answered;
//! * `devices.rs` (as `crate::runtime_pm::devices`) — the idle timeout a
//!   degrade level gives each device.
//!
//! Wired into the suite by `mod power_ring3;` in `src/lib.rs`.
//!
//! Canaries (`Cargo.toml`): `pw-budget-canary` leaves a refused power cap or
//! parking unanswered and must fail exactly the `budget_*` tests;
//! `pw-degrade-canary` drops the rows' hysteresis and must fail exactly the
//! `hysteresis_*` tests; `pw-monitor-canary` suspends the battery monitor at a
//! degrade level too and must fail exactly `monitor_*`.

#[allow(dead_code)]
#[path = "../../../../userspace/services/power/src/battery.rs"]
pub mod battery;

#[allow(dead_code)]
#[path = "../../../../userspace/services/power/src/degrade.rs"]
pub mod degrade;

use azos_energy::model::{IdleState, Opp, PerfDomain};
use azos_energy::policy::{BatteryLimits, DegradeRow, NONE_U8};
use azos_energy::{EnergyMode, EnergyModel, ModelSource};
use azos_power::*;

use crate::kern::Kern;
use crate::policy::*;
use battery::{Estimator, Sample};
use degrade::{select, watch, Row, Rows};

// ── a kernel with the real limits and the real words ────────────────────────

fn opp(f: u32, c: u16, p: u32) -> Opp {
    Opp { freq_khz: f, capacity: c, power_mw: p }
}

/// `little` (CPUs 0 and 1) and `big` (CPUs 2 and 3, the fastest), four OPPs
/// each. The WCET reference of `big` is OPP 2 if `strict`, else OPP 0.
fn model(strict: bool) -> EnergyModel {
    let mut little = PerfDomain::new(0b0011);
    for o in [opp(300_000, 100, 30), opp(600_000, 250, 100), opp(1_000_000, 400, 220), opp(1_400_000, 512, 400)] {
        little.push_opp(o).unwrap();
    }
    little.push_idle(IdleState::new(b"wfi", 1, 1, 8)).unwrap();
    little.wcet_ref_khz = 300_000;
    let mut big = PerfDomain::new(0b1100);
    for o in [opp(500_000, 128, 100), opp(1_000_000, 256, 300), opp(1_500_000, 512, 900), opp(2_000_000, 1024, 1_800)] {
        big.push_opp(o).unwrap();
    }
    big.push_idle(IdleState::new(b"wfi", 1, 1, 8)).unwrap();
    big.wcet_ref_khz = if strict { 1_500_000 } else { 500_000 };
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    m.push_domain(little).unwrap();
    m.push_domain(big).unwrap();
    m
}

/// The topology's three rows: cautious at 30 % (cleared above 35), slow at
/// 20 (25), contained at 12 (15).
const ROWS: [(u8, u8, u8); 3] = [(1, 30, 35), (2, 20, 25), (3, 12, 15)];

/// The kernel's battery limits as a build with the defaults would hand them
/// over: a 10 % reserve and a report older than 1000 ticks is stale.
const LIMITS: BatteryLimits = BatteryLimits { reserve_pct: 10, report_timeout_ticks: 1_000 };

struct Sim(Kern);

impl Sim {
    fn new(strict: bool) -> Sim {
        let k = Kern::new(model(strict));
        let rows = ROWS.map(|(level, battery_pct, clear_pct)| DegradeRow { level, battery_pct, clear_pct });
        k.policy.init_battery(&rows, LIMITS, 0);
        Sim(k)
    }
}

impl PowerPolicy for Sim {
    fn set_governor(&mut self, g: u32) -> u32 {
        self.0.set_governor(g)
    }
    fn set_opp_range(&mut self, d: u32, lo: u32, hi: u32) -> u32 {
        self.0.set_opp_range(d, lo, hi)
    }
    fn set_headroom(&mut self, pct: u32) -> u32 {
        self.0.set_headroom(pct)
    }
    fn set_rate_limit(&mut self, us: u32) -> u32 {
        self.0.set_rate_limit(us)
    }
    fn set_idle_depth(&mut self, depth: u32) -> u32 {
        self.0.set_idle_depth(depth)
    }
    fn set_power_cap(&mut self, d: u32, mw: u32) -> u32 {
        self.0.set_power_cap(d, mw)
    }
    fn set_parked(&mut self, mask: u32) -> u32 {
        self.0.set_parked(mask)
    }
    fn set_qos_domains(&mut self, class: u32, domains: u32) -> u32 {
        self.0.set_qos_domains(class, domains)
    }
    fn report_battery(&mut self, soc: u32, level: u32) -> u32 {
        self.0.report_battery(soc, level)
    }
    fn state(&self, sel: u32) -> u64 {
        self.0.policy.state_word(&self.0.model, EnergyMode::Balanced, |_| 255, sel as u64).unwrap_or(WORD_ERR)
    }
    fn stats(&self, sel: u32) -> u64 {
        self.0.policy.stats_word(0, 0, sel as u64).unwrap_or(WORD_ERR)
    }
}

/// What the rows and the kernel's reserve make of each level
/// (`policy::Levels`), as the service derives it.
fn levels() -> Levels {
    let entries = ROWS.map(|(level, battery_pct, _)| (level, battery_pct));
    Levels::derive(&entries, LIMITS.reserve_pct)
}

fn plan_on(sim: &mut Sim, base: Preset, level: u8) -> (Plan, Outcome, Vec<Decision>) {
    let m = Machine::read(sim);
    let mut log = Vec::new();
    let (plan, o) = apply_plan(sim, base, level, &levels(), m.as_ref(), &mut |d| log.push(*d));
    (plan, o, log)
}

// ── the charge from the monitor's samples ───────────────────────────────────

/// The pack voltage (mV) that is `tenths` of a percent at rest, with
/// `current_ma` flowing: the inverse of the model's curve.
fn volts(tenths: i32, current_ma: u32) -> u32 {
    let cell = (3_000..=4_200u32).find(|v| battery::ocv_tenths(*v) >= tenths).unwrap();
    cell * battery::CELLS - current_ma * battery::R_INT_MOHM / 1_000
}

fn sample(tenths: i32, current_ma: u32, mah_used: u32) -> Sample {
    Sample { voltage_mv: volts(tenths, current_ma), current_ma, mah_used }
}

mod charge {
    use super::*;

    #[test]
    fn the_record_is_read_little_endian_and_a_short_one_is_refused() {
        let rec = [0x10, 0x20, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 55, 0, 0, 0];
        assert_eq!(
            Sample::parse(&rec),
            Some(Sample { voltage_mv: 0x2010, current_ma: 0x1234, mah_used: 0x1234_5678 })
        );
        assert_eq!(Sample::parse(&rec[..7]), None);
        assert_eq!(Sample::parse(&[]), None);
    }

    #[test]
    fn the_voltage_curve_is_monotonic_and_bounded() {
        let mut last = 0;
        for mv in (2_500..=4_400).step_by(10) {
            let t = battery::ocv_tenths(mv);
            assert!((0..=1_000).contains(&t), "{mv} mV -> {t}");
            assert!(t >= last, "{mv} mV went down: {last} -> {t}");
            last = t;
        }
        assert_eq!(battery::ocv_tenths(3_000), 0);
        assert_eq!(battery::ocv_tenths(4_200), 1_000);
    }

    #[test]
    fn a_load_lowers_the_voltage_and_the_correction_puts_it_back() {
        let rest = battery::pack_tenths(7_600, 0);
        let loaded = battery::pack_tenths(7_600, 2_000);
        assert!(loaded > rest, "2 A across the pack's resistance is {loaded} vs {rest}");
        // The same charge, read at rest and under load, comes out the same
        // within the curve's step.
        let a = battery::pack_tenths(volts(500, 0), 0);
        let b = battery::pack_tenths(volts(500, 3_000), 3_000);
        assert!((a - b).abs() <= 15, "{a} vs {b}");
    }

    /// A pack that was half full when the monitor started is not reported
    /// full, which is what the monitor's own `capacity_pct` would say.
    #[test]
    fn the_first_sample_anchors_on_the_voltage_not_on_full() {
        let mut e = Estimator::new();
        let soc = e.update(sample(500, 300, 0));
        assert!((48..=52).contains(&soc), "{soc}");
    }

    #[test]
    fn coulomb_counting_follows_the_charge_that_left() {
        let mut e = Estimator::new();
        e.update(sample(1_000, 1_000, 0));
        // 360 mAh of 3600: 10 % of the pack, under load (no rest anchor).
        let soc = e.update(sample(900, 1_000, 360));
        assert_eq!(soc, 90);
        let soc = e.update(sample(500, 1_000, 360 + 1_440));
        assert_eq!(soc, 50);
    }

    #[test]
    fn the_estimate_never_rises_under_load_and_stops_at_zero() {
        let mut e = Estimator::new();
        e.update(sample(300, 800, 0));
        let mut last = 100;
        for k in 1..60 {
            let soc = e.update(sample(300, 800, k * 100));
            assert!(soc <= last, "{last} -> {soc}");
            last = soc;
        }
        assert_eq!(last, 0);
    }

    #[test]
    fn a_rested_voltage_pulls_a_drifted_estimate_to_the_curve() {
        let mut e = Estimator::new();
        e.update(sample(800, 1_000, 0));
        // The count says 20 % was drawn (so 60 % left) but the rested pack reads 70 %.
        let drifted = e.update(sample(800, 1_000, 720));
        assert_eq!(drifted, 60);
        let mut soc = drifted;
        // Under REST_SAMPLES samples at rest: no change but the count.
        for _ in 0..battery::REST_SAMPLES - 1 {
            soc = e.update(sample(700, 0, 720));
        }
        assert_eq!(soc, 60, "not rested long enough to trust the voltage");
        for _ in 0..40 {
            soc = e.update(sample(700, 0, 720));
        }
        assert!((69..=70).contains(&soc), "pulled to the curve: {soc}");
    }

    #[test]
    fn a_monitor_that_started_over_is_anchored_again() {
        let mut e = Estimator::new();
        e.update(sample(900, 1_000, 0));
        e.update(sample(800, 1_000, 500));
        // The driver restarted: its count went back to 10.
        let soc = e.update(sample(400, 1_000, 10));
        assert!((38..=42).contains(&soc), "{soc}");
    }
}

// ── the rows and the level a charge selects ─────────────────────────────────

fn rows() -> Rows {
    Rows::new(&ROWS.map(|(level, battery_pct, clear_pct)| Row { level, battery_pct, clear_pct }))
}

mod levels {
    use super::*;

    #[test]
    fn the_kernels_rows_are_read_back_in_file_order() {
        let sim = Sim::new(false);
        let r = Rows::load(&sim).unwrap();
        assert_eq!(r, rows());
        assert_eq!(r.rows()[1], Row { level: 2, battery_pct: 20, clear_pct: 25 });
        // A machine whose topology declares no row has none.
        let bare = Sim(Kern::new(model(false)));
        assert_eq!(Rows::load(&bare).unwrap().rows().len(), 0);
    }

    /// The battery word carries more than the row count (stale and the
    /// reserve above bit 24): the count is its own byte.
    #[test]
    fn the_row_count_is_read_from_its_byte_of_the_battery_word() {
        let k = Kern::new(model(false));
        k.policy.init_battery(&[DegradeRow { level: 1, battery_pct: 30, clear_pct: 35 }], LIMITS, 0);
        let sim = Sim(k);
        let r = Rows::load(&sim).unwrap();
        assert_eq!(r.rows(), &[Row { level: 1, battery_pct: 30, clear_pct: 35 }]);
        // A machine with a reserve and no row: nothing to read, not three misses.
        let k = Kern::new(model(false));
        k.policy.init_battery(&[], LIMITS, 0);
        assert_eq!(Rows::load(&Sim(k)).unwrap().rows().len(), 0);
    }

    #[test]
    fn a_level_is_entered_at_or_below_its_threshold() {
        let r = rows();
        for (soc, want) in [(100, 0), (31, 0), (30, 1), (21, 1), (20, 2), (13, 2), (12, 3), (0, 3)] {
            assert_eq!(select(&r, soc, 0), want, "{soc} %");
        }
        assert_eq!(select(&Rows::NONE, 1, 0), 0, "no rows: nothing degrades");
    }

    /// Between the threshold and the clear charge a level held is held and one
    /// not entered is not: a charge that jitters on the threshold does not toggle.
    #[test]
    fn hysteresis_holds_a_level_until_the_clear_charge() {
        let r = rows();
        let mut level = 0;
        let mut changes = 0;
        for soc in [31, 30, 31, 32, 30, 34, 35, 33, 31, 35] {
            let next = select(&r, soc, level);
            changes += (next != level) as u32;
            level = next;
        }
        assert_eq!(level, 1);
        assert_eq!(changes, 1, "entered once, held through the jitter");
        assert_eq!(select(&r, 35, 1), 1, "35 is the clear charge itself: still held");
        assert_eq!(select(&r, 36, 1), 0, "above it: left");
        assert_eq!(select(&r, 33, 0), 0, "not entered: the band holds nothing");
    }

    #[test]
    fn hysteresis_lets_a_level_down_one_row_at_a_time() {
        let r = rows();
        assert_eq!(select(&r, 24, 3), 2, "contained cleared (15), slow held (25)");
        assert_eq!(select(&r, 26, 2), 1, "slow cleared, cautious entered (30)");
        assert_eq!(select(&r, 36, 1), 0);
        assert_eq!(select(&r, 14, 3), 3, "contained held up to 15");
    }
}

// ── what a level asks of the machine ────────────────────────────────────────

mod plans {
    use super::*;

    const PRESETS: [Preset; 3] = [Preset::Performance, Preset::Balanced, Preset::Endurance];

    fn machine() -> Machine {
        Machine::read(&Sim::new(false)).unwrap()
    }

    #[test]
    fn a_level_only_ever_asks_for_more_saving_than_the_preset() {
        let m = machine();
        for base in PRESETS {
            let mut last = plan(base, 0, &levels(), Some(&m));
            assert_eq!(last.preset, base);
            assert_eq!(last.budget.power_cap_pct, 100);
            assert_eq!(last.budget.park, 0);
            for level in 1..=3 {
                let p = plan(base, level, &levels(), Some(&m));
                assert!(p.preset.rank() >= base.rank(), "{base:?} at {level}");
                assert!(p.preset.rank() >= last.preset.rank());
                assert!(p.budget.power_cap_pct < last.budget.power_cap_pct, "the cap tightens with the level");
                assert!(p.budget.park >= last.budget.park);
                assert!(p.budget.efficient_qos & budget(base).efficient_qos == budget(base).efficient_qos);
                last = p;
            }
        }
    }

    #[test]
    fn a_preset_already_past_the_levels_floor_keeps_itself() {
        assert_eq!(preset_at(Preset::Endurance, 1), Preset::Endurance);
        assert_eq!(preset_at(Preset::Performance, 1), Preset::Balanced);
        assert_eq!(preset_at(Preset::Performance, 3), Preset::Endurance);
    }

    #[test]
    fn an_unknown_level_is_the_tightest() {
        let m = machine();
        for base in PRESETS {
            assert_eq!(plan(base, 9, &levels(), Some(&m)), plan(base, 3, &levels(), Some(&m)));
            assert_eq!(plan(base, 255, &levels(), Some(&m)), plan(base, 3, &levels(), Some(&m)));
        }
    }

    #[test]
    fn the_qos_table_of_the_presets() {
        assert_eq!(budget(Preset::Performance), Budget { power_cap_pct: 100, park: 0, efficient_qos: 0 });
        assert_eq!(budget(Preset::Balanced).efficient_qos, 1 << QOS_BACKGROUND);
        assert_eq!(budget(Preset::Endurance).efficient_qos, 1 << QOS_BACKGROUND | 1 << QOS_THROUGHPUT);
    }

    /// A machine with no model has no budget to size: nothing is parked.
    #[test]
    fn a_plan_without_a_machine_parks_nothing() {
        let p = plan(Preset::Balanced, 3, &levels(), None);
        assert_eq!(p.budget.park, 0);
        assert_eq!(p.budget.power_cap_pct, levels().share_pct(3));
    }
}

// ── the shares of the levels are derived from the rows and the reserve ──────

mod derived_levels {
    use super::*;

    fn entries() -> [(u8, u8); 3] {
        ROWS.map(|(level, battery_pct, _)| (level, battery_pct))
    }

    /// `(entry - reserve) / (100 - reserve)`: the share that makes the charge
    /// above the reserve last as long, at the entry of the level, as a full
    /// pack at full power. Rows 30, 20, 12 over a 10 % reserve.
    ///
    /// **Canary.** `pw-levels-canary` makes every level ask 50 %: the pin goes
    /// red (the `levels_` tests).
    #[test]
    fn levels_follow_the_charge_left_above_the_reserve() {
        let l = Levels::derive(&entries(), 10);
        assert_eq!(l.share_pct(0), 100);
        assert_eq!(l.share_pct(1), 22, "(30 - 10) / 90");
        assert_eq!(l.share_pct(2), 11, "(20 - 10) / 90");
        assert_eq!(l.share_pct(3), 2, "(12 - 10) / 90");
    }

    /// The deeper the level, the smaller the share, for any reserve and any
    /// rows the topology admits (a more restrictive level has a strictly lower
    /// threshold, above the reserve or not).
    #[test]
    fn levels_tighten_with_depth_for_every_reserve() {
        for reserve in 1..=50u8 {
            for (a, b, c) in [(60u8, 40, 20), (30, 20, 12), (90, 80, 70), (55, 54, 53)] {
                let l = Levels::derive(&[(1, a), (2, b), (3, c)], reserve);
                assert_eq!(l.share_pct(0), 100);
                for level in 1..=3 {
                    assert!(l.share_pct(level) <= l.share_pct(level - 1), "reserve {reserve}, rows {a}/{b}/{c}, level {level}");
                    assert!((1..=100).contains(&l.share_pct(level)));
                }
            }
        }
    }

    /// A product sets the knob in its rows: the entry that gives half the
    /// power is the middle of the charge above the reserve.
    #[test]
    fn levels_a_row_at_the_middle_of_the_usable_charge_asks_half() {
        // reserve 10: the middle of 10..100 is 55.
        assert_eq!(Levels::derive(&[(1, 55)], 10).share_pct(1), 50);
        // reserve 20: the middle of 20..100 is 60.
        assert_eq!(Levels::derive(&[(1, 60)], 20).share_pct(1), 50);
    }

    /// A bigger reserve leaves less to spend: the same rows ask less.
    #[test]
    fn levels_a_bigger_reserve_asks_less_power() {
        let small = Levels::derive(&entries(), 5);
        let big = Levels::derive(&entries(), 11);
        for level in 1..=3 {
            assert!(big.share_pct(level) < small.share_pct(level), "level {level}");
        }
    }

    /// A level no row declares takes the tightest threshold declared, and no
    /// rows at all take the reserve itself (the least, 1 %): fail-closed.
    #[test]
    fn levels_an_undeclared_level_is_not_looser_than_a_declared_one() {
        let l = Levels::derive(&[(1, 30), (2, 20)], 10);
        assert_eq!(l.share_pct(3), l.share_pct(2), "no row for 3: as tight as the tightest declared");
        let none = Levels::derive(&[], 10);
        assert_eq!((1..=3).map(|k| none.share_pct(k)).collect::<Vec<_>>(), [1, 1, 1]);
        // A threshold at or under the reserve cannot go below the floor of 1 %.
        assert_eq!(Levels::derive(&[(3, 5)], 10).share_pct(3), 1);
    }

    /// The reserve the service derives from is the kernel's: read back through
    /// the state word the kernel prints it in.
    #[test]
    fn levels_the_reserve_is_read_from_the_kernel() {
        let sim = Sim::new(false);
        assert_eq!(degrade::reserve_pct(&sim), Some(LIMITS.reserve_pct));
        // A machine with no battery limits reads a reserve of 0, not an error.
        let bare = Sim(Kern::new(model(false)));
        assert_eq!(degrade::reserve_pct(&bare), Some(0));
    }

    /// The parking is what the cap cannot reach: nothing while the slowest
    /// OPP's power is under the share, and the CPUs the share needs beyond it.
    /// `little` (30 of 400 mW at its slowest) and `big` (100 of 1800).
    #[test]
    fn levels_cpus_are_parked_only_for_what_the_slowest_opp_cannot_reach() {
        let m = Machine::read(&Sim::new(false)).unwrap();
        assert_eq!(m.park_for(100), 0);
        assert_eq!(m.park_for(22), 0, "the cap alone reaches 22 % of both");
        assert_eq!(m.park_for(11), 0, "11 % of `big`'s 1800 mW is 198 mW, over its 100");
        // Under the slowest OPP (`big` 5.5 %, `little` 7.5 %): the CPUs kept
        // are ceil(cpus * share / floor), at least one per domain.
        assert_eq!(m.park_for(5), 0, "both domains keep both CPUs: 1.8 and 1.33 round up");
        assert_eq!(m.park_for(3), 1, "`little` keeps one, `big` still two");
        assert_eq!(m.park_for(2), 2, "one CPU kept in each domain");
        assert_eq!(m.park_for(1), 2, "never the last CPU of a domain");
    }
}

// ── the machine and the budget, against the real limits ─────────────────────

mod machine {
    use super::*;

    #[test]
    fn the_machine_is_read_from_the_kernels_words() {
        let sim = Sim::new(true);
        let m = Machine::read(&sim).unwrap();
        assert_eq!(m.domains, 2);
        assert_eq!(m.cpus[..2], [0b0011, 0b1100]);
        assert_eq!(m.top_mw[..2], [400, 1_800]);
        assert_eq!(m.top_capacity[..2], [512, 1024]);
        assert_eq!(m.fastest(), 1);
        assert_eq!(m.safety[..2], [0, 2], "`little` has no reference above its slowest OPP, `big` OPP 2");
        assert_eq!(m.safety_mw[..2], [30, 900]);
        assert_eq!(m.low_mw[..2], [30, 100]);
        assert!(Machine::read(&Sim(Kern::new(EnergyModel::NONE))).is_none(), "no model, no machine");
    }

    #[test]
    fn parking_takes_the_highest_cpus_and_keeps_cpu_zero_and_a_cpu_per_domain() {
        let m = Machine::read(&Sim::new(false)).unwrap();
        assert_eq!(m.park_mask(0), 0);
        assert_eq!(m.park_mask(1), 0b1000);
        assert_eq!(m.park_mask(2), 0b1010, "CPU 2 would empty `big`, so CPU 1 follows");
        assert_eq!(m.park_mask(31), 0b1010, "as many as the rules allow");
    }

    #[test]
    fn efficient_classes_are_kept_off_the_fastest_domain_if_there_is_another() {
        let m = Machine::read(&Sim::new(false)).unwrap();
        let b = budget(Preset::Endurance);
        assert_eq!(m.qos_domains(QOS_BACKGROUND, &b), 0b01);
        assert_eq!(m.qos_domains(QOS_THROUGHPUT, &b), 0b01);
        assert_eq!(m.qos_domains(0, &b), 0b11, "the default class runs anywhere");
        assert_eq!(m.qos_domains(1, &b), 0b11, "and so does latency");
        let one = Machine { domains: 1, ..m };
        assert_eq!(one.qos_domains(QOS_BACKGROUND, &b), 0b1, "one domain: nowhere else to go");
    }

    #[test]
    fn the_cap_is_a_share_of_the_top_opps_power() {
        let m = Machine::read(&Sim::new(false)).unwrap();
        let b = |pct| Budget { power_cap_pct: pct, ..budget(Preset::Balanced) };
        assert_eq!(m.cap_mw(1, &b(100)), 0, "no cap");
        assert_eq!(m.cap_mw(1, &b(50)), 900);
        assert_eq!(m.cap_mw(0, &b(30)), 120);
        assert_eq!(m.cap_mw(0, &b(1)), 4);
    }
}

mod budgets {
    use super::*;

    #[test]
    fn a_balanced_machine_is_asked_for_nothing_it_would_refuse() {
        let mut sim = Sim::new(true);
        let (plan, o, log) = plan_on(&mut sim, Preset::Balanced, 0);
        assert_eq!(plan.preset, Preset::Balanced);
        assert_eq!((o.refused, o.fallbacks, o.failed), (0, 0, false));
        assert!(log.iter().all(|d| d.verdict == Verdict::Applied));
        // 4 profile calls + 2 OPP ranges + 2 caps + parking + 4 classes.
        assert_eq!(o.applied, 4 + 2 + 2 + 1 + 4);
        let k = &sim.0.policy;
        assert_eq!(k.parked(), 0);
        assert_eq!(k.qos_domains(QOS_BACKGROUND as usize), 0b01, "background kept off `big`");
        assert_eq!(k.qos_domains(0), 0b11);
        assert_eq!(k.power_cap(1), (0, NONE_U8));
    }

    #[test]
    fn a_degrade_level_reaches_the_kernels_state() {
        let mut sim = Sim::new(false);
        let (plan, o, _) = plan_on(&mut sim, Preset::Balanced, 2);
        assert_eq!(plan.preset, Preset::Endurance);
        assert_eq!((o.refused, o.fallbacks), (0, 0));
        let k = &sim.0.policy;
        // 11 % (the row at 20 % over the 10 % reserve) of each top power.
        assert_eq!(k.power_cap(1), (198, 0), "11 % of `big`'s 1800 mW: OPP 0 (100 mW fits, 300 does not)");
        assert_eq!(k.power_cap(0), (44, 0), "11 % of `little`'s 400 mW: OPP 0 (30 mW fits, 100 does not)");
        assert_eq!(k.parked(), 0, "the cap alone reaches the share: no CPU parked");
        assert_eq!(k.qos_domains(QOS_THROUGHPUT as usize), 0b01);
        // Back to normal: the level lifts and so do the cap and the parking.
        let (_, o, _) = plan_on(&mut sim, Preset::Balanced, 0);
        assert_eq!(o.refused, 0);
        let k = &sim.0.policy;
        assert_eq!((k.parked(), k.power_cap(1)), (0, (0, NONE_U8)));
        assert_eq!(k.qos_domains(QOS_THROUGHPUT as usize), 0b11, "the unconfined class is let back out");
    }

    /// The deepest level asks for 2 %: under both domains' slowest OPP, so the
    /// kernel refuses the cap (range), the service asks for the slowest OPP's
    /// power, and the CPUs the share still needs are parked: one per domain.
    #[test]
    fn the_deepest_level_parks_what_the_slowest_opp_cannot_reach() {
        let mut sim = Sim::new(false);
        let (plan, o, _) = plan_on(&mut sim, Preset::Balanced, 3);
        assert_eq!(plan.budget.power_cap_pct, 2);
        assert_eq!(plan.budget.park, 2);
        assert!(o.fallbacks >= 2 && !o.failed);
        let k = &sim.0.policy;
        assert_eq!(k.power_cap(1), (100, 0));
        assert_eq!(k.power_cap(0), (30, 0));
        assert_eq!(k.parked(), 0b1010, "CPU 3 and CPU 1: the highest of each domain");
    }

    /// The kernel refuses a cap that would put `big` under its safety floor;
    /// the service asks for the floor's own power instead.
    #[test]
    fn budget_a_cap_under_the_safety_floor_is_raised_to_it() {
        let mut sim = Sim::new(true);
        let (_, o, log) = plan_on(&mut sim, Preset::Balanced, 2);
        let big = log
            .iter()
            .filter(|d| matches!(d.step, Step::PowerCap { domain: 1, .. }))
            .collect::<Vec<_>>();
        // 11 % of 1800 = 198 mW is OPP 0, under the floor (OPP 2).
        assert_eq!(big[0].step, Step::PowerCap { domain: 1, mw: 198 });
        assert_eq!(big[0].verdict, Verdict::Refused(POLICY_REFUSED_SAFETY_FLOOR));
        assert_eq!(big[1].step, Step::PowerCap { domain: 1, mw: 900 });
        assert!(big[1].retry && big[1].verdict == Verdict::Applied);
        assert_eq!(sim.0.policy.power_cap(1), (900, 2));
        assert!(o.fallbacks >= 1 && !o.failed);
    }

    /// A level share under the slowest OPP on a machine whose safety floor is
    /// above it: one fallback reaches the floor (the range refusal is answered
    /// with the safety floor's power, not the slowest OPP's, which the kernel
    /// would refuse again).
    ///
    /// **Canary.** Answer the range refusal with `low_mw` alone: the retry is
    /// refused by the floor and `big` is left uncapped.
    #[test]
    fn budget_a_share_under_both_the_slowest_opp_and_the_floor_reaches_the_floor_in_one_step() {
        let mut sim = Sim::new(true);
        let (_, o, log) = plan_on(&mut sim, Preset::Balanced, 3);
        let big = log
            .iter()
            .filter(|d| matches!(d.step, Step::PowerCap { domain: 1, .. }))
            .collect::<Vec<_>>();
        assert_eq!(big[0].step, Step::PowerCap { domain: 1, mw: 36 });
        assert_eq!(big[0].verdict, Verdict::Refused(POLICY_REFUSED_RANGE));
        assert_eq!(big[1].step, Step::PowerCap { domain: 1, mw: 900 });
        assert_eq!(big[1].verdict, Verdict::Applied);
        assert_eq!(sim.0.policy.power_cap(1), (900, 2));
        assert!(!o.failed);
    }

    #[test]
    fn budget_a_cap_under_the_slowest_opp_is_raised_to_it() {
        let mut sim = Sim::new(false);
        let m = Machine::read(&sim).unwrap();
        let b = Budget { power_cap_pct: 5, park: 0, efficient_qos: 0 };
        let mut log = Vec::new();
        let o = apply_budget(&mut sim, &b, &m, &mut |d| log.push(*d));
        // 5 % of 1800 = 90 mW, under `big`'s slowest OPP (100 mW).
        let big: Vec<_> = log.iter().filter(|d| matches!(d.step, Step::PowerCap { domain: 1, .. })).collect();
        assert_eq!(big[0].verdict, Verdict::Refused(POLICY_REFUSED_RANGE));
        assert_eq!(big[1].step, Step::PowerCap { domain: 1, mw: 100 });
        assert_eq!(sim.0.policy.power_cap(1), (100, 0));
        assert!(o.fallbacks >= 1);
    }

    #[test]
    fn budget_a_cap_under_the_deadline_floor_is_lifted() {
        let mut sim = Sim::new(false);
        sim.0.admitted_ppm = 500_000;
        let m = Machine::read(&sim).unwrap();
        let b = Budget { power_cap_pct: 20, park: 0, efficient_qos: 0 };
        let mut log = Vec::new();
        apply_budget(&mut sim, &b, &m, &mut |d| log.push(*d));
        let big: Vec<_> = log.iter().filter(|d| matches!(d.step, Step::PowerCap { domain: 1, .. })).collect();
        assert_eq!(big[0].verdict, Verdict::Refused(POLICY_REFUSED_DEADLINE_FLOOR));
        assert_eq!(big[1].step, Step::PowerCap { domain: 1, mw: 0 }, "no cap");
        assert_eq!(sim.0.policy.power_cap(1), (0, NONE_U8));
    }

    /// A reservation admitted on the CPU the mask names: the kernel refuses
    /// the parking and the service parks nothing.
    #[test]
    fn budget_parking_refused_for_admitted_work_parks_nothing() {
        let mut sim = Sim::new(false);
        sim.0.admitted_ppm = 100_000;
        sim.0.policy.set_parked(&sim.0.model, 0b0010, &[0; 32]).unwrap();
        let m = Machine::read(&sim).unwrap();
        let b = Budget { power_cap_pct: 100, park: 1, efficient_qos: 0 };
        let mut log = Vec::new();
        let o = apply_budget(&mut sim, &b, &m, &mut |d| log.push(*d));
        let park: Vec<_> = log.iter().filter(|d| matches!(d.step, Step::Parked(_))).collect();
        assert_eq!(park[0].step, Step::Parked(0b1000));
        assert_eq!(park[0].verdict, Verdict::Refused(POLICY_REFUSED_DEADLINE_FLOOR));
        assert_eq!(park[1].step, Step::Parked(0));
        assert!(park[1].retry);
        assert_eq!(sim.0.policy.parked(), 0);
        assert!(o.fallbacks >= 1 && !o.failed);
    }

    #[test]
    fn a_refused_qos_mapping_is_left_alone() {
        // A machine whose fastest domain is the only one: no refusal arises
        // from the table, but a kernel that refuses is not argued with.
        assert_eq!(budget_fallback(Step::QosDomains { class: 0, domains: 1 }, POLICY_REFUSED_QOS, &Machine::read(&Sim::new(false)).unwrap()), None);
    }

    #[test]
    fn a_machine_with_no_model_is_not_asked_for_a_budget() {
        let mut sim = Sim(Kern::new(EnergyModel::NONE));
        let (_, o, log) = plan_on(&mut sim, Preset::Endurance, 2);
        assert!(o.no_model);
        assert_eq!(log.len(), 0, "not one call");
    }

    #[test]
    fn the_budget_signature_moves_when_another_client_does() {
        let mut sim = Sim::new(false);
        plan_on(&mut sim, Preset::Balanced, 0);
        let m = Machine::read(&sim).unwrap();
        let before = budget_signature(&sim, &m);
        assert_eq!(budget_signature(&sim, &m), before);
        sim.0.policy.set_parked(&sim.0.model, 0b1000, &[0; 32]).unwrap();
        assert_ne!(budget_signature(&sim, &m), before);
    }
}

// ── devices at a degrade level ──────────────────────────────────────────────

mod devices_at_a_level {
    use super::*;
    use crate::runtime_pm::devices::{idle_ms, idle_ms_at, Class};

    #[test]
    fn level_zero_is_the_presets_timeout() {
        for p in [Preset::Performance, Preset::Balanced, Preset::Endurance] {
            for c in [Class::Io, Class::Monitor] {
                assert_eq!(idle_ms_at(p, c, 0), idle_ms(p, c));
            }
        }
    }

    #[test]
    fn a_device_that_only_serves_requests_sleeps_sooner_as_the_charge_falls() {
        for p in [Preset::Performance, Preset::Balanced, Preset::Endurance] {
            let t: Vec<u32> = (0..=3).map(|l| idle_ms_at(p, Class::Io, l)).collect();
            assert!(t[1] > 0 && t[2] > 0 && t[3] > 0, "never 'never' under a level: {t:?}");
            assert!(t[1] >= t[2] && t[2] >= t[3], "{p:?} {t:?}");
            assert!(t[3] <= 250);
        }
        assert_eq!(idle_ms_at(Preset::Endurance, Class::Io, 1), 1_000, "a timeout already shorter is kept");
    }

    #[test]
    fn monitor_the_battery_monitor_is_never_suspended_under_a_level() {
        for p in [Preset::Performance, Preset::Balanced, Preset::Endurance] {
            for level in 1..=3 {
                assert_eq!(idle_ms_at(p, Class::Monitor, level), 0, "{p:?} level {level}");
            }
        }
        // Endurance suspends it at level 0 (15 s): a level takes that away.
        assert_eq!(idle_ms_at(Preset::Endurance, Class::Monitor, 0), 15_000);
    }
}

// ── the whole thing: a pack that drains ─────────────────────────────────────

mod drain {
    use super::*;

    struct Run {
        sim: Sim,
        est: Estimator,
        level: u8,
        trace: Vec<(u8, u8)>,
    }

    impl Run {
        fn new() -> Run {
            Run { sim: Sim::new(true), est: Estimator::new(), level: 0, trace: Vec::new() }
        }

        /// One period: a sample, the watch, and the plan when the level moved.
        fn period(&mut self, s: Sample) -> degrade::Watch {
            let rows = Rows::load(&self.sim).unwrap();
            let w = watch(&mut self.sim, &rows, &mut self.est, self.level, Some(s));
            if w.level != self.level {
                self.level = w.level;
                let (_, o, _) = plan_on(&mut self.sim, Preset::Balanced, self.level);
                assert!(!o.failed);
            }
            self.trace.push((w.soc.unwrap(), self.level));
            w
        }
    }

    /// 100 % down to 0 under a 1 A load: each row is entered once, in order,
    /// the kernel records exactly those changes, and the reserve is entered
    /// once, at the end.
    #[test]
    fn each_threshold_triggers_its_row_once_in_order() {
        let mut r = Run::new();
        let mut levels = vec![0u8];
        for k in 0..=100u32 {
            let used = k * 36; // 1 % of 3600 mAh per step
            let w = r.period(sample(1_000 - 10 * k as i32, 1_000, used));
            assert_eq!(w.verdict, Some(Verdict::Applied), "{k} % drawn");
            if *levels.last().unwrap() != w.level {
                levels.push(w.level);
            }
        }
        assert_eq!(levels, [0, 1, 2, 3]);
        let k = &r.sim.0.policy;
        assert_eq!(k.degrades(), 3, "one record per change of level");
        assert_eq!(k.level(), 3);
        assert_eq!(k.reserve_entries(), 1);
        assert!(k.reserve_active());
        // The levels began where the rows say, give or take the estimate's rounding.
        for (level, at) in [(1u8, 30u8), (2, 20), (3, 12)] {
            let first = r.trace.iter().find(|(_, l)| *l == level).unwrap().0;
            assert!((at - 1..=at).contains(&first), "level {level} first seen at {first} %");
        }
        // What the last level asked reached the kernel inside its floors.
        assert_eq!(k.parked(), 0b1010);
        assert_eq!(k.power_cap(1), (900, 2), "30 % of `big`'s power is under its floor: capped at the floor");
    }

    /// A pack at rest on the way back up: the rested voltage lifts the
    /// estimate and each level is left once, at its clear charge, with no toggle.
    #[test]
    fn recovery_a_pack_coming_back_leaves_each_level_once() {
        let mut r = Run::new();
        // Start flat: 8 % under load, at the bottom row.
        r.period(sample(80, 1_000, 3_300));
        assert_eq!(r.level, 3);
        let mut changes = 0;
        let mut last = r.level;
        // At rest, voltage climbing from 8 % to 90 % with jitter of one curve step.
        for k in 0..400u32 {
            let t = 80 + (k as i32 * 820 / 400) + if k % 3 == 0 { 8 } else { -8 };
            let w = r.period(sample(t.clamp(0, 1_000), 0, 3_300));
            if w.level != last {
                changes += 1;
                assert!(w.level < last, "a level goes down as the charge comes back, never up again");
                last = w.level;
            }
        }
        assert_eq!(r.level, 0);
        assert_eq!(changes, 3, "contained, slow, cautious, each left once");
        assert_eq!(r.sim.0.policy.degrades(), 4, "in at 3 (from 0), then three ways down");
        assert!(!r.sim.0.policy.reserve_active());
    }

    /// A pack resting between a row's threshold (30) and its clear charge
    /// (35), with the voltage jittering: the level entered on the way down is
    /// held, not dropped the moment the estimate edges over 30.
    #[test]
    fn hysteresis_a_pack_resting_inside_the_band_holds_its_level() {
        let mut r = Run::new();
        r.period(sample(1_000, 1_000, 0));
        // Down to 29 % under load: cautious.
        let w = r.period(sample(290, 1_000, 2_556));
        assert_eq!((w.soc, w.level), (Some(29), 1));
        let before = r.sim.0.policy.degrades();
        // At rest around 32 .. 34 %: above the threshold, inside the band.
        for k in 0..200u32 {
            let t = 330 + if k % 2 == 0 { 12 } else { -12 };
            let w = r.period(sample(t, 0, 2_556));
            assert_eq!(w.level, 1, "period {k}: estimate {:?}", w.soc);
        }
        assert!(r.trace.iter().any(|(soc, _)| *soc > 30), "the estimate did cross the threshold");
        assert_eq!(r.sim.0.policy.degrades(), before, "no change of level, no record");
    }

    #[test]
    fn a_machine_with_no_sensor_grant_holds_its_level() {
        let mut sim = Sim::new(false);
        let mut est = Estimator::new();
        let w = watch(&mut sim, &rows(), &mut est, 2, None);
        assert_eq!(w, degrade::Watch { level: 2, soc: None, verdict: None });
        assert_eq!(sim.0.policy.soc_pct(), NONE_U8, "nothing was reported");
    }

    #[test]
    fn a_report_the_kernel_refuses_leaves_the_level_where_it_was() {
        // The service's rows say level 3 at 12 %; a kernel with no row for it refuses.
        let mut sim = Sim(Kern::new(model(false)));
        sim.0.policy.init_battery(&[DegradeRow { level: 1, battery_pct: 30, clear_pct: 35 }], LIMITS, 0);
        let mut est = Estimator::new();
        let w = watch(&mut sim, &rows(), &mut est, 0, Some(sample(100, 1_000, 0)));
        assert_eq!(w.verdict, Some(Verdict::Refused(POLICY_REFUSED_BATTERY)));
        assert_eq!(w.level, 0);
    }

    #[test]
    fn a_machine_with_no_rows_is_not_watched() {
        let mut sim = Sim(Kern::new(model(false)));
        let mut est = Estimator::new();
        let w = watch(&mut sim, &Rows::NONE, &mut est, 0, Some(sample(100, 1_000, 0)));
        assert_eq!(w, degrade::Watch { level: 0, soc: None, verdict: None });
    }
}

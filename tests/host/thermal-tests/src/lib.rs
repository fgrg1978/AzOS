// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the thermal framework and DVFS actuation.
//!
//! * `thermal` — `azos_energy::thermal`: trip crossing with hysteresis in both
//!   directions, cooling steps (up, clamp, hold, release), the largest cap
//!   across maps, the floor invariant (the real-time deadline floor and the
//!   WCET safety floor are never undercut; `thermal-floor-canary` must turn
//!   it red), the degrade levels, the latched shutdown, a lost sensor, the
//!   record ring and the poll interval.
//! * `opp` — `azos_energy::opp::Dvfs`: unchanged requests are not sent,
//!   refusals are counted.
//! * `dt` — `azos_dtb::dtb_thermal` and `azos_thermal::dt::build` on a
//!   dtc-built fixture.
//! * `firmware` — the Pi mailbox property protocol, word for word, and a
//!   `Mailbox` against a fake VideoCore.
//! * `jh7110` — the `sfctemp` arithmetic, the power-up order and the board
//!   object.
//! * `k1_tsensor` — the SpacemiT K1 `TSEN` block: the init sequence, the
//!   read-back that refuses a window that does not hold it, the per-channel
//!   half-word and offset, and the Jupiter tree's five zones.
//! * `x86_pc` — the x86_64 actuator and meter: the HWP and CPPC level requests
//!   and RAPL's energy against a fake CPU, and the runtime over the sensor's
//!   board object (`x86_pc.rs`).
//! * `runtime` — `azos_thermal::runtime::Runtime::tick` against fake
//!   hardware: heat pulls a clock down to the floor and no further, release
//!   puts the clock back, an actuator that cannot move raises the level,
//!   and a machine with no zone reads no sensor and caps nothing, and with no
//!   governor and no heat no clock is touched (invariant I4).

use azos_energy::model::{EnergyModel, IdleState, ModelSource, Opp, PerfDomain};

/// One domain over CPU 0: 500 MHz .. 2 GHz, capacities 128 .. 1024.
/// `wcet_ref_khz` is the safety floor's reference (0 = undeclared).
pub fn model(wcet_ref_khz: u32) -> EnergyModel {
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    let mut d = PerfDomain::new(0b1);
    d.wcet_ref_khz = wcet_ref_khz;
    for (f, c, p) in [(500_000, 128, 50), (1_000_000, 256, 150), (1_500_000, 512, 400), (2_000_000, 1024, 1000)] {
        d.push_opp(Opp { freq_khz: f, capacity: c, power_mw: p }).unwrap();
    }
    d.push_idle(IdleState::new(b"wfi", 1, 1, 0)).unwrap();
    m.push_domain(d).unwrap();
    m
}

/// The CPU map of a boot that started on the first CPU node: logical CPU n is
/// the node whose `reg` is n (the fixtures number their CPUs from 0).
#[cfg(test)]
fn by_reg(reg: u64) -> Option<usize> {
    Some(reg as usize)
}

#[cfg(test)]
mod x86_pc;

#[cfg(test)]
mod thermal {
    use super::model;
    use azos_energy::governor::{deadline_floor_opp, safety_floor_opp};
    use azos_energy::thermal::*;

    pub const PASSIVE: i32 = 80_000;
    pub const HYST: u32 = 2_000;
    pub const HOT: i32 = 90_000;
    pub const CRIT: i32 = 100_000;

    /// One zone: passive 80 C (hyst 2 C), hot 90 C (hyst 3 C), critical 100 C;
    /// the passive trip caps domain 0 by `min..=max` steps.
    pub fn zone(min: u8, max: u8, m: &azos_energy::model::EnergyModel) -> Zone {
        let mut z = Zone::new(b"cpu-thermal", 0);
        z.poll_ms = 1000;
        z.poll_passive_ms = 250;
        z.push_trip(Trip { temp_mdeg: PASSIVE, hyst_mdeg: HYST, kind: TripKind::Passive }).unwrap();
        z.push_trip(Trip { temp_mdeg: HOT, hyst_mdeg: 3_000, kind: TripKind::Hot }).unwrap();
        z.push_trip(Trip { temp_mdeg: CRIT, hyst_mdeg: 0, kind: TripKind::Critical }).unwrap();
        z.push_map(CoolingMap { trip: 0, domain: 0, min_state: min, max_state: max }, m).unwrap();
        z
    }

    pub fn thermal(min: u8, max: u8) -> Thermal {
        let m = model(0);
        let mut t = Thermal::new();
        t.push_zone(zone(min, max, &m)).unwrap();
        t
    }

    #[test]
    fn a_trip_fires_at_its_temperature_and_leaves_below_the_hysteresis_band() {
        let mut t = thermal(0, 3);
        assert_eq!(t.update(0, PASSIVE - 1, 0), ZoneUpdate { up: 0, down: 0 });
        assert_eq!(t.update(0, PASSIVE, 10), ZoneUpdate { up: 0b1, down: 0 });
        assert_eq!(t.active(0), 0b1);
        // Inside the band, down to and including temp - hyst: still active.
        assert_eq!(t.update(0, PASSIVE - HYST as i32 + 1, 20), ZoneUpdate { up: 0, down: 0 });
        assert_eq!(t.update(0, PASSIVE - HYST as i32, 30), ZoneUpdate { up: 0, down: 0 });
        assert_eq!(t.active(0), 0b1);
        // One milli-degree below the band: inactive.
        assert_eq!(t.update(0, PASSIVE - HYST as i32 - 1, 40), ZoneUpdate { up: 0, down: 0b1 });
        assert_eq!(t.active(0), 0);
        // And it fires again.
        assert_eq!(t.update(0, PASSIVE + 5, 50).up, 0b1);
    }

    #[test]
    fn a_reading_that_jitters_around_a_trip_does_not_toggle_it() {
        let mut t = thermal(0, 3);
        t.update(0, PASSIVE, 0);
        let before = t.logged();
        for i in 0..50 {
            t.update(0, PASSIVE - 1 - (i % 2) * 500, i as u64 + 1);
        }
        assert_eq!(t.active(0), 0b1);
        assert_eq!(t.logged(), before, "no TripDown/TripUp in the band");
    }

    #[test]
    fn several_trips_cross_in_one_reading() {
        let mut t = thermal(0, 3);
        let u = t.update(0, CRIT, 0);
        assert_eq!(u.up, 0b111);
        let u = t.update(0, 20_000, 1);
        assert_eq!(u.down, 0b111);
    }

    #[test]
    fn cooling_steps_up_one_per_evaluation_clamp_hold_and_release_one_per_evaluation() {
        let mut t = thermal(0, 3);
        let seq = |t: &mut Thermal, temps: &[i32]| -> Vec<u8> {
            temps
                .iter()
                .enumerate()
                .map(|(i, &c)| {
                    t.update(0, c, i as u64);
                    t.cap_state(0)
                })
                .collect()
        };
        // Above the trip: 1, 2, 3, then clamped at max.
        assert_eq!(seq(&mut t, &[81_000, 81_000, 81_000, 85_000, 85_000]), [1, 2, 3, 3, 3]);
        // In the band (79_000 is above 78_000): hold.
        assert_eq!(seq(&mut t, &[79_000, 78_000, 79_999]), [3, 3, 3]);
        // Below the band: one step back per evaluation, down to 0 and stay.
        assert_eq!(seq(&mut t, &[70_000, 70_000, 70_000, 70_000, 70_000]), [2, 1, 0, 0, 0]);
    }

    #[test]
    fn the_minimum_state_applies_as_soon_as_the_trip_is_active() {
        let mut t = thermal(2, 3);
        t.update(0, PASSIVE, 0);
        assert_eq!(t.cap_state(0), 2);
        t.update(0, PASSIVE, 1);
        assert_eq!(t.cap_state(0), 3);
        // Released, the state falls through the minimum to zero.
        for i in 0..4 {
            t.update(0, 20_000, 2 + i);
        }
        assert_eq!(t.cap_state(0), 0);
    }

    #[test]
    fn a_domain_is_capped_by_the_largest_state_of_its_maps() {
        let m = model(0);
        let mut z = zone(0, 1, &m);
        // The hot trip caps the same domain by up to 3 steps.
        z.push_map(CoolingMap { trip: 1, domain: 0, min_state: 0, max_state: 3 }, &m).unwrap();
        let mut t = Thermal::new();
        t.push_zone(z).unwrap();
        t.update(0, HOT + 1, 0);
        assert_eq!(t.cap_state(0), 1);
        t.update(0, HOT + 1, 1);
        assert_eq!(t.cap_state(0), 2, "passive map is clamped at 1, hot map at 2");
        t.update(0, HOT + 1, 2);
        assert_eq!(t.cap_state(0), 3);
    }

    #[test]
    fn an_unmapped_domain_is_never_capped() {
        let t = thermal(0, 3);
        assert_eq!(t.cap_state(1), 0);
        assert_eq!(t.cap_state(3), 0);
    }

    fn heat_to_state(t: &mut Thermal, state: u8) {
        for i in 0..8 {
            t.update(0, PASSIVE + 1_000, 100 + i);
        }
        assert_eq!(t.cap_state(0), state);
    }

    #[test]
    fn capping_lowers_the_governors_choice_to_the_cap() {
        // A declared WCET reference at the slowest OPP: no safety floor above it.
        let m = model(500_000);
        let d = &m.domains()[0];
        let mut t = thermal(0, 3);
        // No heat: the governor's answer, untouched.
        assert_eq!(t.limit(d, 0, 3, 0), Limited { opp: 3, cap: 3, floor: 0, bound: false });
        t.update(0, PASSIVE, 0);
        assert_eq!(t.limit(d, 0, 3, 0).opp, 2);
        t.update(0, PASSIVE, 1);
        assert_eq!(t.limit(d, 0, 3, 0).opp, 1);
        // A request already below the cap is not raised to it.
        assert_eq!(t.limit(d, 0, 0, 0).opp, 0);
    }

    /// I1 + I6 under heat: whatever the admitted load, the WCET reference,
    /// the cooling state and the governor's request, the OPP is at least the
    /// larger floor, and it is exactly `max(min(want, cap), floor)`. Run with
    /// `--features thermal-floor-canary`, which drops the floor: this test
    /// must then fail.
    #[test]
    fn heat_never_undercuts_the_real_time_or_safety_floor() {
        let mut checked = 0;
        for wcet in [0u32, 500_000, 1_000_000, 1_500_000, 2_000_000, 9_000_000] {
            let m = model(wcet);
            let d = &m.domains()[0];
            for ppm in (0..=1_000_000u32).step_by(50_000) {
                let floor = deadline_floor_opp(d, ppm).max(safety_floor_opp(d));
                for state in 0..=3u8 {
                    for want in 0..=3usize {
                        let mut t = thermal(state.min(1), 3);
                        for i in 0..state as u64 {
                            t.update(0, PASSIVE + 1_000, i);
                        }
                        assert_eq!(t.cap_state(0), state);
                        let l = t.limit(d, 0, want, ppm);
                        let cap = 3 - state as usize;
                        assert_eq!(l.floor, floor);
                        assert_eq!(l.cap, cap);
                        assert!(l.opp >= floor, "wcet {wcet} ppm {ppm} state {state} want {want}: {l:?} below floor {floor}");
                        assert_eq!(l.opp, want.min(cap).max(floor));
                        assert_eq!(l.bound, floor > cap);
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 6 * 21 * 4 * 4);
    }

    #[test]
    fn a_floor_that_holds_the_clock_up_is_bound_and_cautious() {
        // 40 % admitted real-time density needs capacity 492: OPP 2. A model
        // that declares its WCET reference at 500 MHz (OPP 0) leaves the
        // deadline floor as the one that binds.
        let mut t = thermal(0, 3);
        let m500 = model(500_000);
        let d500 = &m500.domains()[0];
        for i in 0..3 {
            t.update(0, PASSIVE + 1_000, i);
        }
        let l = t.limit(d500, 0, 3, 400_000);
        assert_eq!((l.opp, l.cap, l.floor, l.bound), (2, 0, 2, true));
        let s = t.settle(10);
        assert_eq!(s, Settled { level: LEVEL_CAUTIOUS, shutdown: false });
        // Newest first: Level, Uncooled(domain 0), TripUp.
        let r: Vec<Event> = (0..3).map(|i| t.record(i).unwrap().event).collect();
        assert_eq!(r, [Event::Level, Event::Uncooled, Event::TripUp]);
        assert_eq!(t.record(1).unwrap().arg, 0);
        assert_eq!(t.record(0).unwrap().arg, LEVEL_CAUTIOUS);

        // Staying bound is not a new event.
        let n = t.logged();
        t.limit(d500, 0, 3, 400_000);
        t.settle(20);
        assert_eq!(t.logged(), n);

        // Cooled enough for the floor to be reachable (state <= 1 gives cap 2):
        // Cooled, then level 0.
        for i in 0..2 {
            t.update(0, 20_000, 30 + i);
        }
        assert_eq!(t.cap_state(0), 1);
        let l = t.limit(d500, 0, 3, 400_000);
        assert_eq!((l.opp, l.bound), (2, false));
        assert_eq!(t.settle(40), Settled { level: 0, shutdown: false });
        assert_eq!(t.record(1).unwrap().event, Event::Cooled);
        assert_eq!(t.record(0).unwrap().event, Event::Level);
        assert_eq!(t.record(0).unwrap().arg, 0);
    }

    #[test]
    fn no_floor_means_the_heat_gets_all_the_way_down_and_the_level_stays_zero() {
        let m = model(500_000);
        let d = &m.domains()[0];
        let mut t = thermal(0, 3);
        heat_to_state(&mut t, 3);
        let l = t.limit(d, 0, 3, 0);
        assert_eq!((l.opp, l.bound), (0, false));
        assert_eq!(t.settle(1).level, 0);
    }

    #[test]
    fn an_actuator_that_cannot_move_the_clock_counts_like_a_floor() {
        let mut t = thermal(0, 3);
        t.update(0, PASSIVE, 0);
        t.unactuated(0);
        assert_eq!(t.settle(1).level, LEVEL_CAUTIOUS);
        assert_eq!(t.record(1).unwrap().event, Event::Uncooled);
        // Not repeated, and cleared once the next evaluation does not report it.
        t.settle(2);
        assert_eq!(t.level(), 0);
        assert_eq!(t.record(0).unwrap().event, Event::Level);
        assert_eq!(t.record(1).unwrap().event, Event::Cooled);
    }

    #[test]
    fn a_hot_trip_is_slow_and_a_critical_one_contains_and_latches_a_shutdown() {
        let mut t = thermal(0, 3);
        t.update(0, HOT, 0);
        assert_eq!(t.settle(0), Settled { level: LEVEL_SLOW, shutdown: false });
        // Back below the hot band: level 0 again (the passive trip does not set one).
        t.update(0, HOT - 3_001, 1);
        assert_eq!(t.settle(1).level, 0);

        t.update(0, CRIT, 2);
        let s = t.settle(2);
        assert_eq!(s, Settled { level: LEVEL_CONTAINED, shutdown: true });
        assert_eq!(t.record(1).unwrap().event, Event::Shutdown);
        // The shutdown request is latched: cooling off does not retract it,
        // and it is recorded once.
        t.update(0, 20_000, 3);
        let n = t.logged();
        let s = t.settle(3);
        assert_eq!(s, Settled { level: LEVEL_CONTAINED, shutdown: true });
        t.settle(4);
        assert!((0..t.logged().min(LOG_LEN as u32) as usize).filter(|&i| t.record(i).unwrap().event == Event::Shutdown).count() <= 1);
        assert!(t.logged() >= n);
    }

    #[test]
    fn the_clock_stays_at_the_floor_even_at_the_critical_trip() {
        let m = model(500_000);
        let d = &m.domains()[0];
        let mut t = thermal(0, 3);
        for i in 0..4 {
            t.update(0, CRIT + 1_000, i);
        }
        let l = t.limit(d, 0, 3, 600_000);
        assert!(l.opp >= deadline_floor_opp(d, 600_000));
        assert!(t.settle(9).shutdown);
    }

    #[test]
    fn a_sensor_that_fails_three_reads_in_a_row_is_slow_until_it_answers() {
        let mut t = thermal(0, 3);
        t.update(0, 40_000, 0);
        for i in 0..SENSOR_FAIL_LIMIT as u64 - 1 {
            t.sensor_failed(0, 1 + i);
            assert_eq!(t.settle(1 + i).level, 0, "not yet blind");
        }
        t.sensor_failed(0, 10);
        assert_eq!(t.settle(10).level, LEVEL_SLOW);
        assert_eq!(t.record(1).unwrap().event, Event::SensorLost);
        t.sensor_failed(0, 11);
        assert_eq!(t.settle(11).level, LEVEL_SLOW);
        t.update(0, 40_000, 12);
        assert_eq!(t.record(0).unwrap().event, Event::SensorBack);
        assert_eq!(t.settle(12).level, 0);
    }

    #[test]
    fn a_blind_zone_caps_its_domain_at_the_deepest_state_until_it_sees_again() {
        let mut t = thermal(0, 3);
        t.update(0, 40_000, 0);
        assert_eq!(t.cap_state(0), 0);
        for i in 0..SENSOR_FAIL_LIMIT as u64 - 1 {
            t.sensor_failed(0, 1 + i);
            assert_eq!(t.cap_state(0), 0, "not yet blind");
        }
        t.sensor_failed(0, 10);
        assert_eq!(t.cap_state(0), 3, "blind: the map's max_state");
        let m = model(500_000);
        let l = t.limit(&m.domains()[0], 0, 3, 0);
        assert_eq!((l.cap, l.opp), (0, 0), "the clock does not stay where the governor put it");
        t.update(0, 40_000, 11);
        assert_eq!(t.cap_state(0), 0, "the sensor answers: the cooling states were never raised");
    }

    #[test]
    fn a_blind_zone_does_not_cap_below_the_floors() {
        let mut t = thermal(0, 3);
        for i in 0..SENSOR_FAIL_LIMIT as u64 {
            t.sensor_failed(0, i);
        }
        let m = model(1_500_000);
        let d = &m.domains()[0];
        let l = t.limit(d, 0, 3, 0);
        assert_eq!(l.opp, safety_floor_opp(d));
        assert!(l.bound);
        assert_eq!(t.settle(9).level, LEVEL_SLOW);
    }

    #[test]
    fn the_poll_interval_follows_cooling_and_a_zone_is_due_when_it_has_never_been_read() {
        let mut t = thermal(0, 3);
        assert!(t.due(0, 0));
        assert!(!t.due(1, 0), "no such zone");
        t.update(0, 40_000, 100);
        assert!(!t.due(0, 1_099));
        assert!(t.due(0, 1_100));
        t.update(0, PASSIVE + 1, 2_000);
        assert!(!t.due(0, 2_249));
        assert!(t.due(0, 2_250), "passive polling while a trip is active");
        let z = Zone::new(b"z", 0);
        assert_eq!(z.interval_ms(true), DEFAULT_POLL_MS);
        assert_eq!(z.interval_ms(false), DEFAULT_POLL_MS);
    }

    #[test]
    fn zones_and_maps_are_validated() {
        let m = model(0);
        let mut z = Zone::new(b"z", 0);
        assert_eq!(Thermal::new().push_zone(z), Err(ThermalFault::NoTrips));
        z.push_trip(Trip { temp_mdeg: 1, hyst_mdeg: 0, kind: TripKind::Critical }).unwrap();
        let ok = CoolingMap { trip: 0, domain: 0, min_state: 0, max_state: 3 };
        // A critical trip shuts down; it does not cool.
        assert_eq!(z.push_map(ok, &m), Err(ThermalFault::BadMapTrip));
        z.push_trip(Trip { temp_mdeg: 2, hyst_mdeg: 0, kind: TripKind::Passive }).unwrap();
        assert_eq!(z.push_map(CoolingMap { trip: 2, ..ok }, &m), Err(ThermalFault::BadMapTrip));
        assert_eq!(z.push_map(CoolingMap { trip: 1, domain: 1, ..ok }, &m), Err(ThermalFault::BadMapDomain));
        assert_eq!(z.push_map(CoolingMap { trip: 1, max_state: 4, ..ok }, &m), Err(ThermalFault::BadMapStates));
        assert_eq!(z.push_map(CoolingMap { trip: 1, min_state: 2, max_state: 1, ..ok }, &m), Err(ThermalFault::BadMapStates));
        z.push_map(CoolingMap { trip: 1, ..ok }, &m).unwrap();
        for _ in 0..MAX_MAPS - 1 {
            z.push_map(CoolingMap { trip: 1, ..ok }, &m).unwrap();
        }
        assert_eq!(z.push_map(CoolingMap { trip: 1, ..ok }, &m), Err(ThermalFault::TooManyMaps));
        for _ in 0..MAX_TRIPS - 2 {
            z.push_trip(Trip { temp_mdeg: 3, hyst_mdeg: 0, kind: TripKind::Active }).unwrap();
        }
        assert_eq!(z.push_trip(Trip { temp_mdeg: 3, hyst_mdeg: 0, kind: TripKind::Active }), Err(ThermalFault::TooManyTrips));
        let mut t = Thermal::new();
        for _ in 0..MAX_ZONES {
            t.push_zone(z).unwrap();
        }
        assert_eq!(t.push_zone(z), Err(ThermalFault::TooManyZones));
    }

    #[test]
    fn the_record_ring_keeps_the_last_entries() {
        let mut t = thermal(0, 3);
        for i in 0..40u64 {
            t.update(0, if i % 2 == 0 { PASSIVE } else { 0 }, i);
        }
        assert_eq!(t.logged(), 40);
        assert_eq!(t.record(0).unwrap().now_ms, 39);
        assert_eq!(t.record(LOG_LEN - 1).unwrap().now_ms, 40 - LOG_LEN as u64);
        assert!(t.record(LOG_LEN).is_none());
    }
}

#[cfg(test)]
mod opp {
    use super::model;
    use azos_energy::model::Opp;
    use azos_energy::opp::*;

    #[derive(Default)]
    struct Fake {
        calls: Vec<(usize, u32)>,
        fail: Option<ActuateError>,
    }

    impl OppActuator for Fake {
        fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
            self.calls.push((domain, opp.freq_khz));
            self.fail.map_or(Ok(()), Err)
        }
    }

    #[test]
    fn a_request_that_changes_nothing_is_not_sent() {
        let m = model(0);
        let (mut dv, mut f) = (Dvfs::new(), Fake::default());
        assert_eq!(dv.current(0), None);
        assert_eq!(dv.set(&mut f, &m, 0, 2), Ok(Applied::Changed));
        assert_eq!(dv.set(&mut f, &m, 0, 2), Ok(Applied::Unchanged));
        assert_eq!(dv.set(&mut f, &m, 0, 1), Ok(Applied::Changed));
        assert_eq!(f.calls, [(0, 1_500_000), (0, 1_000_000)]);
        assert_eq!((dv.current(0), dv.changed(), dv.refused()), (Some(1), 2, 0));
    }

    #[test]
    fn what_firmware_left_is_assumed_and_a_failure_leaves_the_domain_where_it_was() {
        let m = model(0);
        let (mut dv, mut f) = (Dvfs::new(), Fake::default());
        dv.assume(0, 3);
        assert_eq!(dv.set(&mut f, &m, 0, 3), Ok(Applied::Unchanged));
        f.fail = Some(ActuateError::Refused);
        assert_eq!(dv.set(&mut f, &m, 0, 1), Err(ActuateError::Refused));
        assert_eq!((dv.current(0), dv.changed(), dv.refused()), (Some(3), 0, 1));
    }

    #[test]
    fn unknown_domains_and_opps_are_refused_without_calling_the_actuator() {
        let m = model(0);
        let (mut dv, mut f) = (Dvfs::new(), Fake::default());
        assert_eq!(dv.set(&mut f, &m, 1, 0), Err(ActuateError::Refused));
        assert_eq!(dv.set(&mut f, &m, 0, 4), Err(ActuateError::Refused));
        assert!(f.calls.is_empty());
    }

    #[test]
    fn a_board_with_no_clock_driver_refuses_everything() {
        let m = model(0);
        let (mut dv, mut n) = (Dvfs::new(), NoActuator);
        assert_eq!(dv.set(&mut n, &m, 0, 1), Err(ActuateError::Unsupported));
        assert_eq!(dv.current(0), None);
    }
}

#[cfg(test)]
mod dt {
    use azos_dtb::*;
    use azos_energy::dt::from_dt;
    use crate::by_reg;
    use azos_energy::thermal::{CoolingMap, TripKind};
    use azos_thermal::dt::build;

    fn fixture(name: &str) -> Vec<u8> {
        let p = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        let mut v = std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
        v.extend_from_slice(&[0; 8]);
        v
    }

    fn raw() -> DtThermal {
        let blob = fixture("thermal-2zone.dtb");
        unsafe { dtb_thermal(blob.as_ptr()) }.expect("readable blob")
    }

    #[test]
    fn the_raw_tables_of_the_fixture() {
        let dt = raw();
        assert!(!dt.truncated);
        // The disabled zone is not read; the other two are, in document order.
        let names: Vec<&[u8]> = dt.zones().iter().map(|z| z.name()).collect();
        assert_eq!(names, [&b"cpu-thermal"[..], &b"blind-thermal"[..]]);
        assert_eq!(dt.cpus().len(), 4);
        assert!(dt.cpus().iter().all(|&p| p != 0));
        let z = &dt.zones()[0];
        assert_eq!((z.poll_passive_ms, z.poll_ms, z.sensor != 0, z.sensor_cell), (250, 1000, true, 0));
        let t: Vec<(i32, u32, u8)> = z.trips().iter().map(|t| (t.temp_mdeg, t.hyst_mdeg, t.kind)).collect();
        assert_eq!(
            t,
            [
                (80_000, 2_000, DT_TRIP_PASSIVE),
                (90_000, 3_000, DT_TRIP_HOT),
                (100_000, 0, DT_TRIP_CRITICAL),
                (70_000, 0, DT_TRIP_UNKNOWN)
            ]
        );
        assert_eq!(z.maps().len(), 4);
        let m0 = &z.maps()[0];
        assert_eq!(m0.trip, z.trips()[0].phandle);
        assert_eq!(m0.coolers().len(), 2);
        assert_eq!((m0.coolers()[0].phandle, m0.coolers()[0].min, m0.coolers()[0].max), (dt.cpus()[0], DT_THERMAL_NO_LIMIT, DT_THERMAL_NO_LIMIT));
        assert_eq!(m0.coolers()[1].phandle, dt.cpus()[1]);
        let c = z.maps()[1].coolers()[0];
        assert_eq!((c.phandle, c.min, c.max), (dt.cpus()[2], 1, 7));
        assert_eq!(z.maps()[1].coolers()[1].phandle, dt.cpus()[3]);
        assert_eq!(dt.zones()[1].sensor_cell, 9);
    }

    #[test]
    fn a_tree_without_thermal_zones_gives_none() {
        let blob = std::fs::read(format!("{}/../energy-tests/fixtures/energy-2cluster.dtb", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let dt = unsafe { dtb_thermal(blob.as_ptr()) }.unwrap();
        assert_eq!(dt.zones().len(), 0);
        assert_eq!(dt.cpus().len(), 4, "the CPUs are read all the same");
    }

    #[test]
    fn a_garbage_blob_is_refused() {
        let blob = [0u8; 64];
        assert!(unsafe { dtb_thermal(blob.as_ptr()) }.is_none());
        assert!(unsafe { dtb_thermal(core::ptr::null()) }.is_none());
    }

    #[test]
    fn zones_are_built_over_the_energy_model_and_what_cannot_be_is_counted() {
        let blob = fixture("thermal-2zone.dtb");
        let e = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        let model = from_dt(&e, &by_reg).expect("tables").expect("model");
        assert_eq!(model.domains().iter().map(|d| d.cpus).collect::<Vec<_>>(), [0b0011, 0b1100]);
        let dt = raw();
        // Sensor cell 0 is sensor 7; cell 9 is a channel the board does not have.
        let b = build(&dt, &model, |ph, cell| (ph != 0 && cell == 0).then_some(7));
        assert_eq!((b.zones_dropped, b.trips_dropped, b.coolers_dropped, b.truncated), (1, 1, 2, false));
        let zs = b.thermal.zones();
        assert_eq!(zs.len(), 1);
        let z = &zs[0];
        assert_eq!((z.name(), z.sensor, z.poll_passive_ms, z.poll_ms), (&b"cpu-thermal"[..], 7, 250, 1000));
        let kinds: Vec<TripKind> = z.trips().iter().map(|t| t.kind).collect();
        assert_eq!(kinds, [TripKind::Passive, TripKind::Hot, TripKind::Critical]);
        // map0: cpu0 and cpu1 are one domain: one map, NO_LIMIT..NO_LIMIT = 0..deepest.
        // map1: cpu2 is domain 1, states 1..7 clamped to the table (2).
        // map2 named a trip that was dropped, map3 a node that is no CPU.
        assert_eq!(
            z.maps(),
            [
                CoolingMap { trip: 0, domain: 0, min_state: 0, max_state: 2 },
                CoolingMap { trip: 1, domain: 1, min_state: 1, max_state: 2 },
            ]
        );
    }

    /// A cooler names a CPU NODE; the model's masks name LOGICAL CPUs (audit
    /// K2-M4). Booted on reg 2 (a big core): logical 0 = reg 2, 1 = reg 0,
    /// 2 = reg 1, 3 = reg 3, so the little domain is CPUs 1-2 and the big one
    /// 0 and 3. After `cpus_by_logical` the maps land on the same domains as
    /// on a boot from reg 0.
    ///
    /// **Canary.** Skip `cpus_by_logical`: map 1 (cpu2, a big core) lands on
    /// the little domain.
    #[test]
    fn coolers_resolve_to_the_domain_of_their_logical_cpu() {
        let blob = fixture("thermal-2zone.dtb");
        let e = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        let booted_on_2 = |reg: u64| match reg { 2 => Some(0), 0 => Some(1), 1 => Some(2), 3 => Some(3), _ => None };
        let model = from_dt(&e, &booted_on_2).unwrap().unwrap();
        assert_eq!(model.domains().iter().map(|d| d.cpus).collect::<Vec<_>>(), [0b0110, 0b1001]);
        let mut dt = raw();
        azos_thermal::dt::cpus_by_logical(&mut dt, &booted_on_2);
        let b = build(&dt, &model, |ph, cell| (ph != 0 && cell == 0).then_some(7));
        assert_eq!(
            b.thermal.zones()[0].maps(),
            [
                CoolingMap { trip: 0, domain: 0, min_state: 0, max_state: 2 },
                CoolingMap { trip: 1, domain: 1, min_state: 1, max_state: 2 },
            ]
        );
    }

    #[test]
    fn a_cooler_on_a_cpu_past_the_domain_masks_is_dropped_not_a_shift_overflow() {
        let blob = fixture("thermal-2zone.dtb");
        let e = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        let model = from_dt(&e, &by_reg).unwrap().unwrap();
        let mut dt = raw();
        // A slice, not the array: with a table of 8 the constant index is a
        // compile-time error (`unconditional_panic`) before the guard runs.
        let cpus: &mut [u32] = &mut dt.cpus[..];
        if cpus.len() <= 33 {
            return; // a build whose NR_CPUS cannot name CPU 32 has nothing to overflow
        }
        // Make map 0's second cooler name a CPU numbered 32 and 33.
        let (a, b) = (0xAAAA_0001, 0xAAAA_0002);
        cpus[32] = a;
        cpus[33] = b;
        dt.n_cpus = 34;
        let z = &mut dt.zones[0];
        z.maps[1].coolers[0].phandle = a;
        z.maps[1].coolers[1].phandle = b;
        let built = build(&dt, &model, |ph, cell| (ph != 0 && cell == 0).then_some(7));
        // map1 (CPUs 32/33) is dropped and counted: no panic in debug, no
        // wrong domain in release.
        let maps = built.thermal.zones()[0].maps();
        assert!(maps.iter().all(|m| m.domain == 0), "{maps:?}");
        assert_eq!(built.coolers_dropped, 4);
    }

    #[test]
    fn a_zone_with_no_resolvable_sensor_is_dropped_and_one_without_a_model_keeps_its_trips() {
        let dt = raw();
        let blob = fixture("thermal-2zone.dtb");
        let e = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        let model = from_dt(&e, &by_reg).unwrap().unwrap();
        let b = build(&dt, &model, |_, _| None);
        assert_eq!((b.thermal.zones().len(), b.zones_dropped), (0, 2));
        // No energy model: nothing to cool, but the critical trip still protects.
        let none = azos_energy::EnergyModel::NONE;
        let b = build(&dt, &none, |ph, cell| (ph != 0 && cell == 0).then_some(0));
        assert_eq!(b.thermal.zones().len(), 1);
        assert_eq!(b.thermal.zones()[0].maps().len(), 0);
        assert_eq!(b.coolers_dropped, 6);
        assert_eq!(b.thermal.zones()[0].trips().len(), 3);
    }
}

#[cfg(test)]
mod construction {
    //! `Runtime::from_dt` on the dtc-built fixture: what the kernel's boot
    //! step does, minus the registers.
    use azos_dtb::{dtb_energy, dtb_thermal};
    use azos_energy::dt::from_dt;
    use crate::by_reg;
    use azos_energy::model::{EnergyModel, Opp};
    use azos_energy::opp::{ActuateError, OppActuator};
    use azos_thermal::runtime::{nearest_opp, single_sensor, Inputs, Runtime, MIN_TICK_MS};
    use azos_thermal::sensor::{SensorBank, SensorError};

    fn blob() -> Vec<u8> {
        let p = format!("{}/fixtures/thermal-2zone.dtb", env!("CARGO_MANIFEST_DIR"));
        let mut v = std::fs::read(&p).unwrap();
        v.extend_from_slice(&[0; 8]);
        v
    }

    fn model_and_dt() -> (EnergyModel, azos_dtb::DtThermal, Vec<u8>) {
        let b = blob();
        let e = unsafe { dtb_energy(b.as_ptr()) }.unwrap();
        let m = from_dt(&e, &by_reg).unwrap().unwrap();
        // The slowest OPP is the one the real-time work was measured at (the
        // safety floor), so heat may cap all the way down.
        let mut declared = EnergyModel::from_source(m.source);
        for d in m.domains() {
            let mut d = *d;
            d.wcet_ref_khz = d.opps()[0].freq_khz;
            declared.push_domain(d).unwrap();
        }
        let dt = unsafe { dtb_thermal(b.as_ptr()) }.unwrap();
        (declared, dt, b)
    }

    struct Hw {
        mdeg: i32,
        sets: Vec<(usize, u32)>,
    }
    impl SensorBank for Hw {
        fn read_mdeg(&mut self, s: u8) -> Result<i32, SensorError> {
            assert_eq!(s, 0, "the one sensor of a one-sensor board");
            Ok(self.mdeg)
        }
    }
    impl OppActuator for Hw {
        fn set_opp(&mut self, d: usize, o: &Opp) -> Result<(), ActuateError> {
            self.sets.push((d, o.freq_khz));
            Ok(())
        }
    }

    #[test]
    fn the_tree_builds_one_runtime_with_the_zone_the_board_can_read_and_reports_the_rest() {
        let (m, dt, _b) = model_and_dt();
        let (rt, r) = Runtime::from_dt(&dt, &m, |_| None);
        // cpu-thermal is kept; blind-thermal names sensor cell 9, which a
        // one-sensor board does not have.
        assert_eq!((r.zones, r.zones_dropped, r.trips_dropped, r.coolers_dropped, r.truncated), (1, 1, 1, 2, false));
        assert_eq!(rt.thermal.zones()[0].name(), b"cpu-thermal");
        assert_eq!(rt.thermal.zones()[0].sensor, 0);
        // Nothing was told about the clocks: no domain's OPP is known.
        assert_eq!((rt.dvfs.current(0), rt.dvfs.current(1)), (None, None));
        assert_eq!(rt.ticks, 0);
    }

    #[test]
    fn the_boot_clock_the_board_reads_becomes_each_domains_current_opp() {
        let (m, dt, _b) = model_and_dt();
        // Little: 500 / 750 / 1000 MHz; big: 1000 / 1500 / 2000 MHz.
        let boot = |d: usize| match d {
            0 => Some(740_000),   // nearest 750 MHz
            1 => Some(2_000_000), // the top
            _ => None,
        };
        let (rt, _) = Runtime::from_dt(&dt, &m, boot);
        assert_eq!((rt.dvfs.current(0), rt.dvfs.current(1)), (Some(1), Some(2)));
    }

    #[test]
    fn every_record_has_a_stance_and_a_name_and_a_fall_of_the_level_is_a_relaxation() {
        use azos_energy::thermal::Event::*;
        use azos_thermal::runtime::{event_name, stance, Stance};
        let all = [TripUp, TripDown, Uncooled, Cooled, Level, Shutdown, SensorLost, SensorBack];
        let mut names: Vec<&str> = all.iter().map(|&e| event_name(e)).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len(), "one name per event");
        assert_eq!(stance(TripUp, false), Stance::Acted);
        for e in [Uncooled, Shutdown, SensorLost] {
            assert_eq!(stance(e, false), Stance::Declined, "{e:?}");
        }
        for e in [TripDown, Cooled, SensorBack] {
            assert_eq!(stance(e, true), Stance::Relaxed, "{e:?}");
        }
        assert_eq!(stance(Level, true), Stance::Declined);
        assert_eq!(stance(Level, false), Stance::Relaxed);
    }

    #[test]
    fn nearest_opp_picks_the_closest_and_the_lower_on_a_tie() {
        let (m, _dt, _b) = model_and_dt();
        let little = &m.domains()[0];
        assert_eq!(nearest_opp(little, 0), Some(0));
        assert_eq!(nearest_opp(little, 600_000), Some(0), "600 is nearer 500 than 750");
        assert_eq!(nearest_opp(little, 625_000), Some(0), "a tie goes to the lower clock");
        assert_eq!(nearest_opp(little, 9_000_000), Some(2));
        assert_eq!(nearest_opp(&azos_energy::model::PerfDomain::new(1), 1), None);
    }

    #[test]
    fn one_sensor_boards_name_sensor_zero_only_for_the_first_cell() {
        assert_eq!(single_sensor(5, 0), Some(0));
        assert_eq!(single_sensor(0, 0), None);
        assert_eq!(single_sensor(5, 1), None);
    }

    #[test]
    fn the_task_sleeps_the_zones_polling_delay_and_wakes_sooner_while_it_cools() {
        let (m, dt, _b) = model_and_dt();
        let (mut rt, _) = Runtime::from_dt(&dt, &m, |d| Some(m.domains()[d].opps().last().unwrap().freq_khz));
        // polling-delay 1000 ms idle, 250 ms while a trip is active.
        assert_eq!(rt.poll_interval_ms(), Some(1000));
        let mut hw = Hw { mdeg: 85_000, sets: vec![] };
        rt.tick(&mut hw, &m, 0, &Inputs::IDLE);
        assert_eq!(rt.ticks, 1);
        assert_eq!(rt.poll_interval_ms(), Some(250));
        // The passive trip caps the little domain one step: its clock moved.
        assert_eq!(hw.sets, [(0, 750_000)]);
        // Back below the hysteresis band: the idle delay again, and the
        // clocks come back one step per read.
        hw.mdeg = 40_000;
        rt.tick(&mut hw, &m, 250, &Inputs::IDLE);
        assert_eq!(rt.poll_interval_ms(), Some(1000));
    }

    #[test]
    fn a_polling_delay_below_the_floor_is_raised_to_it_and_no_zone_means_no_task() {
        let (m, mut dt, _b) = model_and_dt();
        dt.zones[0].poll_ms = 1;
        dt.zones[0].poll_passive_ms = 1;
        let (rt, _) = Runtime::from_dt(&dt, &m, |_| None);
        assert_eq!(rt.poll_interval_ms(), Some(MIN_TICK_MS));
        dt.n_zones = 0;
        let (rt, r) = Runtime::from_dt(&dt, &m, |_| None);
        assert_eq!(r.zones, 0);
        assert_eq!(rt.poll_interval_ms(), None);
    }

    #[test]
    fn a_machine_with_no_energy_model_keeps_the_zone_for_its_critical_trip_and_moves_no_clock() {
        let (_m, dt, _b) = model_and_dt();
        let (mut rt, r) = Runtime::from_dt(&dt, &EnergyModel::NONE, |_| Some(1));
        assert_eq!((r.zones, r.coolers_dropped), (1, 6));
        let mut hw = Hw { mdeg: 120_000, sets: vec![] };
        let s = rt.tick(&mut hw, &EnergyModel::NONE, 0, &Inputs::IDLE);
        assert!(s.shutdown, "the critical trip protects the silicon without a model");
        assert!(hw.sets.is_empty());
    }
}

#[cfg(test)]
mod firmware {
    use azos_firmware::*;

    /// How the fake VideoCore behaves.
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Normal,
        Silent,
        FullForever,
        ErrorCode,
        OtherBuffer,
        ForeignChannelFirst,
        Flood,
        NoResponseBit,
    }

    struct FakeVc {
        mode: Mode,
        buf: *mut u8,
        reply: Vec<u32>,
        wrote: Vec<u32>,
        temp: u32,
    }

    const BUS: u32 = 0xC000_1230;

    impl FakeVc {
        fn new(mode: Mode) -> Self {
            Self { mode, buf: core::ptr::null_mut(), reply: Vec::new(), wrote: Vec::new(), temp: 51_234 }
        }

        /// What the firmware does with the message in the buffer.
        fn process(&mut self) {
            let w = self.buf as *mut u32;
            let rd = |i: usize| unsafe { *w.add(i) };
            let wr = |i: usize, v: u32| unsafe { *w.add(i) = v };
            let end = rd(0) as usize / 4;
            let mut at = 2;
            while at < end && rd(at) != 0 {
                let (id, size) = (rd(at), rd(at + 1) as usize / 4);
                let v = at + 3;
                let mut written = 0;
                match id {
                    TAG_GET_TEMPERATURE => {
                        wr(v + 1, self.temp);
                        written = 8;
                    }
                    TAG_GET_CLOCK_RATE | TAG_GET_MAX_CLOCK_RATE | TAG_GET_MIN_CLOCK_RATE => {
                        wr(
                            v + 1,
                            match id {
                                TAG_GET_CLOCK_RATE => 1_000_000_000,
                                TAG_GET_MIN_CLOCK_RATE => 600_000_000,
                                _ => 1_800_000_000,
                            },
                        );
                        written = 8;
                    }
                    TAG_SET_CLOCK_RATE => {
                        // The PLL cannot make everything: round down to 100 MHz.
                        wr(v + 1, rd(v + 1) / 100_000_000 * 100_000_000);
                        written = 8;
                    }
                    _ => {}
                }
                if written != 0 && self.mode != Mode::NoResponseBit {
                    wr(at + 2, TAG_RESPONSE | written);
                }
                at = v + size;
            }
            wr(1, if self.mode == Mode::ErrorCode { CODE_RESPONSE_ERROR } else { CODE_RESPONSE_OK });
        }
    }

    impl MailboxPort for FakeVc {
        fn read32(&mut self, off: usize) -> u32 {
            match off {
                REG_WRITE_STATUS => {
                    if self.mode == Mode::FullForever {
                        STATUS_FULL
                    } else {
                        0
                    }
                }
                REG_READ_STATUS => {
                    if self.reply.is_empty() && self.mode != Mode::Flood {
                        STATUS_EMPTY
                    } else {
                        0
                    }
                }
                REG_READ if self.mode == Mode::Flood => 0xDEAD_BEE1,
                REG_READ => self.reply.remove(0),
                _ => panic!("register {off:#x}"),
            }
        }
        fn write32(&mut self, off: usize, v: u32) {
            assert_eq!(off, REG_WRITE);
            self.wrote.push(v);
            if self.mode == Mode::Silent {
                return;
            }
            self.process();
            match self.mode {
                Mode::OtherBuffer => self.reply.push((v & !0xF).wrapping_add(0x100) | CHANNEL_PROPERTY),
                Mode::ForeignChannelFirst => {
                    self.reply.push(0xDEAD_BEE0 | 1);
                    self.reply.push(v);
                }
                _ => self.reply.push(v),
            }
        }
        fn bus_addr(&self, _buf: *const u8, _len: usize) -> Option<u32> {
            Some(BUS)
        }
        fn clean(&mut self, buf: *mut u8, _len: usize) {
            self.buf = buf;
        }
    }

    #[test]
    fn a_buffer_is_aligned_for_the_mailbox() {
        assert_eq!(core::mem::align_of::<MsgBuf<MSG_WORDS>>(), 16);
    }

    #[test]
    fn get_temperature_is_encoded_word_for_word() {
        let m = MsgBuf::<MSG_WORDS>::get_temperature(TEMP_SOC);
        // size 32 bytes, request, tag 0x30006, value size 8, request code 0, id 0, slot, end tag.
        assert_eq!(&m.words()[..8], [32, 0, 0x0003_0006, 8, 0, 0, 0, 0]);
        let m = MsgBuf::<MSG_WORDS>::get_max_temperature(TEMP_SOC);
        assert_eq!(&m.words()[..4], [32, 0, 0x0003_000A, 8]);
    }

    #[test]
    fn clock_requests_are_encoded_word_for_word() {
        let m = MsgBuf::<MSG_WORDS>::set_clock_rate(CLOCK_ARM, 1_500_000_000, 1);
        // 9 words: header 2, tag 3 + 3 values, end tag.
        assert_eq!(&m.words()[..9], [36, 0, 0x0003_8002, 12, 0, 3, 1_500_000_000, 1, 0]);
        assert!(m.words()[9..].iter().all(|&w| w == 0));
        let m = MsgBuf::<MSG_WORDS>::get_clock_rate(CLOCK_ARM);
        assert_eq!(&m.words()[..8], [32, 0, 0x0003_0002, 8, 0, 3, 0, 0]);
        let m = MsgBuf::<MSG_WORDS>::get_max_clock_rate(CLOCK_ARM);
        assert_eq!(m.words()[2], 0x0003_0004);
        // The minimum is its own tag (Linux `RPI_FIRMWARE_GET_MIN_CLOCK_RATE`),
        // not the maximum's: asking one for the other would hand the actuator
        // a range upside down.
        let m = MsgBuf::<MSG_WORDS>::get_min_clock_rate(CLOCK_ARM);
        assert_eq!(&m.words()[..8], [32, 0, 0x0003_0007, 8, 0, 3, 0, 0]);
    }

    #[test]
    fn several_tags_share_one_message_and_a_full_buffer_refuses() {
        let mut m = MsgBuf::<12>::new();
        assert_eq!(m.tag(TAG_GET_TEMPERATURE, &[0], 2), Ok(5));
        assert_eq!(m.tag(TAG_GET_CLOCK_RATE, &[3], 2), Err(MailboxError::NoRoom));
        let mut m = MsgBuf::<16>::new();
        m.tag(TAG_GET_TEMPERATURE, &[0], 2).unwrap();
        assert_eq!(m.tag(TAG_GET_CLOCK_RATE, &[3], 2), Ok(10));
        m.finish();
        assert_eq!(m.words()[0], 13 * 4);
        assert_eq!(m.words()[12], 0, "end tag");
    }

    #[test]
    fn the_answers_are_decoded() {
        let mut vc = Mailbox::new(FakeVc::new(Mode::Normal));
        assert_eq!(vc.soc_temperature(), Ok(51_234));
        assert_eq!(vc.arm_clock_rate(), Ok(1_000_000_000));
        assert_eq!(vc.arm_max_clock_rate(), Ok(1_800_000_000));
        assert_eq!(vc.arm_min_clock_rate(), Ok(600_000_000));
        // The firmware rounds what the PLL cannot make.
        assert_eq!(vc.set_arm_clock_rate(1_550_000_000), Ok(1_500_000_000));
        // Every call posted the buffer's bus address with the property channel.
        assert!(vc.port().wrote.iter().all(|&w| w == (BUS & !0xF) | CHANNEL_PROPERTY));
        assert_eq!(vc.port().wrote.len(), 5);
    }

    #[test]
    fn a_negative_temperature_keeps_its_sign() {
        let mut fake = FakeVc::new(Mode::Normal);
        fake.temp = (-5_000i32) as u32;
        assert_eq!(Mailbox::new(fake).soc_temperature(), Ok(-5_000));
    }

    #[test]
    fn a_silent_firmware_times_out_and_a_full_mailbox_times_out() {
        assert_eq!(Mailbox::new(FakeVc::new(Mode::Silent)).soc_temperature(), Err(MailboxError::Timeout));
        assert_eq!(Mailbox::new(FakeVc::new(Mode::FullForever)).soc_temperature(), Err(MailboxError::Timeout));
    }

    #[test]
    fn an_error_code_a_foreign_reply_and_a_tag_without_response_are_refused() {
        assert_eq!(Mailbox::new(FakeVc::new(Mode::ErrorCode)).soc_temperature(), Err(MailboxError::Refused));
        assert_eq!(Mailbox::new(FakeVc::new(Mode::OtherBuffer)).soc_temperature(), Err(MailboxError::Mismatch));
        assert_eq!(Mailbox::new(FakeVc::new(Mode::NoResponseBit)).soc_temperature(), Err(MailboxError::NoResponse));
    }

    #[test]
    fn a_flood_of_foreign_words_cannot_hold_the_caller() {
        assert_eq!(Mailbox::new(FakeVc::new(Mode::Flood)).soc_temperature(), Err(MailboxError::Timeout));
    }

    #[test]
    fn a_reply_for_another_channel_is_skipped() {
        assert_eq!(Mailbox::new(FakeVc::new(Mode::ForeignChannelFirst)).soc_temperature(), Ok(51_234));
    }

    /// A VideoCore that takes the post and answers only when the test says
    /// so: `deliver` is the late answer, written into whatever buffer it was
    /// given at the post.
    struct LateVc {
        buf: *mut u8,
        posted: Vec<(u32, usize)>,
        reply: Vec<u32>,
        asked: u32,
    }

    impl LateVc {
        fn new() -> Self {
            Self { buf: core::ptr::null_mut(), posted: Vec::new(), reply: Vec::new(), asked: 0 }
        }
        /// The firmware finally answers the oldest message it was given.
        fn deliver(&mut self) {
            let (word, at) = self.posted.remove(0);
            let w = at as *mut u32;
            unsafe {
                *w.add(2 + 2) = TAG_RESPONSE | 8;
                *w.add(2 + 3 + 1) = 70_000;
                *w.add(1) = CODE_RESPONSE_OK;
            }
            self.reply.push(word);
        }
    }

    impl MailboxPort for LateVc {
        fn read32(&mut self, off: usize) -> u32 {
            match off {
                REG_WRITE_STATUS => 0,
                REG_READ_STATUS => {
                    if self.reply.is_empty() {
                        STATUS_EMPTY
                    } else {
                        0
                    }
                }
                REG_READ => self.reply.remove(0),
                _ => panic!("register {off:#x}"),
            }
        }
        fn write32(&mut self, off: usize, v: u32) {
            assert_eq!(off, REG_WRITE);
            self.asked += 1;
            self.posted.push((v, self.buf as usize));
        }
        fn bus_addr(&self, _buf: *const u8, _len: usize) -> Option<u32> {
            Some(BUS)
        }
        fn clean(&mut self, buf: *mut u8, _len: usize) {
            self.buf = buf;
        }
    }

    #[test]
    fn the_buffer_the_firmware_may_still_write_is_the_mailboxs_own() {
        let mut mb = Mailbox::new(LateVc::new());
        assert_eq!(mb.soc_temperature(), Err(MailboxError::Timeout));
        let me = &mb as *const Mailbox<LateVc> as usize;
        let at = mb.port().posted[0].1;
        assert!(
            (me..me + core::mem::size_of::<Mailbox<LateVc>>()).contains(&at),
            "the posted buffer is inside the Mailbox, not on a caller's stack frame that ends with the call"
        );
        assert!(mb.pending());
    }

    #[test]
    fn a_call_that_gave_up_posts_nothing_until_the_late_answer_is_drained() {
        let mut mb = Mailbox::new(LateVc::new());
        assert_eq!(mb.soc_temperature(), Err(MailboxError::Timeout));
        // Still silent: the buffer is the firmware's, so nothing is posted.
        assert_eq!(mb.soc_temperature(), Err(MailboxError::Pending));
        assert_eq!(mb.arm_clock_rate(), Err(MailboxError::Pending));
        assert_eq!(mb.port().asked, 1);
        // The late answer lands in the mailbox's buffer, harming nothing.
        mb.port().deliver();
        // The next call reclaims the buffer, then posts and waits again.
        assert_eq!(mb.soc_temperature(), Err(MailboxError::Timeout));
        assert_eq!(mb.port().asked, 2);
        mb.port().deliver();
        assert_eq!(mb.soc_temperature(), Err(MailboxError::Timeout));
        assert_eq!(mb.port().asked, 3);
    }

    #[test]
    fn a_mailbox_that_answers_in_time_is_not_pending_and_may_move() {
        let mut vc = Mailbox::new(FakeVc::new(Mode::Normal));
        assert_eq!(vc.soc_temperature(), Ok(51_234));
        assert!(!vc.pending());
        let mut boxed = Box::new(vc);
        assert_eq!(boxed.soc_temperature(), Ok(51_234));
    }

    #[test]
    fn a_mailbox_moved_while_an_answer_is_owed_never_posts_again() {
        let mut mb = Mailbox::new(LateVc::new());
        assert_eq!(mb.soc_temperature(), Err(MailboxError::Timeout));
        mb.port().deliver();
        // The firmware answered the old address; this is a copy elsewhere.
        let mut moved = Box::new(mb);
        assert_eq!(moved.soc_temperature(), Err(MailboxError::Moved));
        assert_eq!(moved.arm_clock_rate(), Err(MailboxError::Moved));
        assert_eq!(moved.port().asked, 1);
    }

    #[test]
    fn a_word_for_our_channel_that_is_not_ours_leaves_the_answer_owed() {
        let mut mb = Mailbox::new(FakeVc::new(Mode::OtherBuffer));
        assert_eq!(mb.soc_temperature(), Err(MailboxError::Mismatch));
        assert!(mb.pending(), "ours may still come");
    }

    #[test]
    fn a_message_not_yet_answered_has_no_response() {
        let mut m = MsgBuf::<16>::new();
        m.tag(TAG_GET_TEMPERATURE, &[0], 2).unwrap();
        m.tag(TAG_GET_CLOCK_RATE, &[3], 2).unwrap();
        m.finish();
        // The message code is still "request"; and no answer exists for an
        // absent tag whatever the code.
        assert_eq!(m.response(TAG_GET_CLOCK_RATE), Err(MailboxError::Refused));
        assert_eq!(m.temperature(TAG_GET_TEMPERATURE), Err(MailboxError::Refused));
    }

    /// A port whose buffer has no bus address; counts what reaches the registers.
    struct Unreachable {
        touched: u32,
    }
    impl MailboxPort for Unreachable {
        fn read32(&mut self, _off: usize) -> u32 {
            self.touched += 1;
            STATUS_EMPTY
        }
        fn write32(&mut self, _off: usize, _v: u32) {
            self.touched += 1;
        }
        fn bus_addr(&self, _buf: *const u8, _len: usize) -> Option<u32> {
            None
        }
    }

    #[test]
    fn a_buffer_the_videocore_cannot_reach_is_never_posted() {
        let mut mb = Mailbox::new(Unreachable { touched: 0 });
        assert_eq!(mb.soc_temperature(), Err(MailboxError::BadAddress));
        assert_eq!(mb.port().touched, 0, "no register was written: the firmware would answer elsewhere");
        // The buffer is still ours: nothing is owed.
        assert!(!mb.pending());
    }

    #[test]
    fn the_uncached_window_maps_only_the_first_gib() {
        let w = BusWindow::UNCACHED;
        assert_eq!(w.bus_addr(0x1000, 48), Some(0xC000_1000));
        // The last bytes of the first GiB fit, one more does not.
        assert_eq!(w.bus_addr(0x3FFF_FFD0, 48), Some(0xFFFF_FFD0));
        assert_eq!(w.bus_addr(0x3FFF_FFD0, 49), None);
        // Above 1 GiB the OR would alias onto other memory (or truncate).
        assert_eq!(w.bus_addr(0x4000_0000, 48), None);
        assert_eq!(w.bus_addr(0x1_0000_1000, 48), None, "above 4 GiB: the cast to u32 would wrap");
        assert_eq!(w.bus_addr(u64::MAX - 8, 48), None, "the end of the buffer overflows");
    }

    #[test]
    fn the_identity_window_maps_the_first_four_gib_unchanged() {
        let w = BusWindow::IDENTITY;
        assert_eq!(w.bus_addr(0x8_0000, 48), Some(0x8_0000));
        // Above 1 GiB is still the same address (the Pi 5 has no alias to
        // collide with), up to the last byte a 32-bit mailbox word can name.
        assert_eq!(w.bus_addr(0x4000_0000, 48), Some(0x4000_0000));
        assert_eq!(w.bus_addr(0xFFFF_FFD0, 48), Some(0xFFFF_FFD0));
        assert_eq!(w.bus_addr(0xFFFF_FFD0, 49), None);
        assert_eq!(w.bus_addr(0x1_0000_1000, 48), None, "above 4 GiB: the cast to u32 would wrap");
        assert_eq!(w.bus_addr(u64::MAX - 8, 48), None);
    }

    #[test]
    fn only_a_soc_with_a_measured_bus_map_gets_a_window() {
        let root = |s: &[u8]| BusWindow::for_root_compatible(s);
        assert_eq!(root(b"raspberrypi,3-model-b\0brcm,bcm2837\0"), Some(BusWindow::UNCACHED));
        assert_eq!(root(b"raspberrypi,4-model-b\0brcm,bcm2711\0"), Some(BusWindow::UNCACHED));
        assert_eq!(root(b"raspberrypi,model-zero\0brcm,bcm2835\0"), Some(BusWindow::UNCACHED));
        // The Pi 5 names the same mailbox node, and its bus map is the
        // identity (not the alias of the older Pis).
        assert_eq!(root(b"raspberrypi,5-model-b\0brcm,bcm2712\0"), Some(BusWindow::IDENTITY));
        assert_ne!(BusWindow::IDENTITY, BusWindow::UNCACHED);
        // A SoC nobody measured stays off, even one that names a Pi cousin.
        assert_eq!(root(b"raspberrypi,6-model-x\0brcm,bcm2799\0"), None);
        assert_eq!(root(b"linux,dummy-virt\0"), None);
        assert_eq!(root(b""), None);
        // A prefix of a name is not the name.
        assert_eq!(root(b"brcm,bcm28370\0"), None);
    }
}

#[cfg(test)]
mod jh7110 {
    use azos_energy::model::Opp;
    use azos_energy::opp::{ActuateError, OppActuator};
    use azos_thermal::jh7110::*;
    use azos_thermal::sensor::{SensorBank, SensorError};

    #[derive(Default)]
    struct Bus {
        ops: Vec<String>,
        reg: u32,
        delays: Vec<(usize, u32)>,
    }

    impl SfcTempBus for &mut Bus {
        fn read32(&mut self, off: usize) -> u32 {
            assert_eq!(off, REG_CTRL);
            self.reg
        }
        fn write32(&mut self, off: usize, v: u32) {
            assert_eq!(off, REG_CTRL);
            self.ops.push(format!("w{v:#x}"));
        }
        fn delay_us(&mut self, us: u32) {
            self.delays.push((self.ops.len(), us));
        }
    }

    #[test]
    fn dout_converts_at_known_points() {
        // temperature = DOUT * 237.5 / 4094 - 81.1 (integer milli-degrees).
        assert_eq!(dout_to_mdeg(1), -81_042);
        assert_eq!(dout_to_mdeg(1829), 25_003);
        assert_eq!(dout_to_mdeg(2048), 37_708);
        assert_eq!(dout_to_mdeg(4094), 156_400);
        // Only the 12 bits count.
        assert_eq!(dout_to_mdeg(4095), 156_458);
        assert_eq!(dout_to_mdeg(0x1000 | 1829), 25_003);
    }

    #[test]
    fn start_powers_the_core_before_releasing_reset_and_runs_last() {
        let mut bus = Bus::default();
        SfcTemp::new(&mut bus).start();
        assert_eq!(bus.ops, ["w0x2", "w0x0", "w0x1", "w0x5"]);
        // The 50 us after PD falls (after the 2nd write), before RSTN rises.
        assert!(bus.delays.contains(&(2, POWER_UP_US)));
        assert!(POWER_UP_US >= 50);
    }

    #[test]
    fn a_running_sensor_is_read_and_anything_else_is_invalid() {
        let run = CTRL_RSTN | CTRL_RUN;
        let mut bus = Bus { reg: run | 1829 << DOUT_SHIFT, ..Bus::default() };
        assert_eq!(SfcTemp::new(&mut bus).read_mdeg(), Ok(25_003));
        // Not converted yet.
        let mut bus = Bus { reg: run, ..Bus::default() };
        assert_eq!(SfcTemp::new(&mut bus).read_mdeg(), Err(SensorError::Invalid));
        // Powered down, in reset, or not running.
        for ctrl in [run | CTRL_PD, CTRL_RUN, CTRL_RSTN] {
            let mut bus = Bus { reg: ctrl | 1829 << DOUT_SHIFT, ..Bus::default() };
            assert_eq!(SfcTemp::new(&mut bus).read_mdeg(), Err(SensorError::Invalid), "{ctrl:#x}");
        }
    }

    struct Clock(Vec<u32>, Option<ActuateError>);
    impl CpuClock for Clock {
        fn set_cpu_khz(&mut self, khz: u32) -> Result<(), ActuateError> {
            self.0.push(khz);
            self.1.map_or(Ok(()), Err)
        }
    }

    #[test]
    fn the_board_object_answers_sensor_zero_and_domain_zero() {
        let mut bus = Bus { reg: CTRL_RSTN | CTRL_RUN | 1829 << DOUT_SHIFT, ..Bus::default() };
        let mut b = Jh7110 { sensor: SfcTemp::new(&mut bus), clock: Clock(vec![], None) };
        assert_eq!(b.read_mdeg(0), Ok(25_003));
        assert_eq!(b.read_mdeg(1), Err(SensorError::Absent));
        let opp = Opp { freq_khz: 1_500_000, capacity: 512, power_mw: 400 };
        assert_eq!(b.set_opp(0, &opp), Ok(()));
        assert_eq!(b.set_opp(1, &opp), Err(ActuateError::Unsupported));
        assert_eq!(b.clock.0, [1_500_000]);
        b.clock.1 = Some(ActuateError::Refused);
        assert_eq!(b.set_opp(0, &opp), Err(ActuateError::Refused));
    }
}

#[cfg(test)]
mod runtime {
    use super::model;
    use super::thermal::{zone, CRIT, HOT, PASSIVE};
    use azos_energy::model::{EnergyModel, MAX_DOMAINS, Opp};
    use azos_energy::opp::{ActuateError, OppActuator};
    use azos_energy::thermal::{Event, Settled, Thermal, LEVEL_CAUTIOUS, LEVEL_CONTAINED, LEVEL_SLOW};
    use azos_thermal::runtime::{Inputs, Runtime};
    use azos_thermal::sensor::{SensorBank, SensorError};

    struct Hw {
        temp: Result<i32, SensorError>,
        sets: Vec<u32>,
        fail: Option<ActuateError>,
        reads: u32,
    }

    impl Hw {
        fn at(c: i32) -> Self {
            Self { temp: Ok(c), sets: vec![], fail: None, reads: 0 }
        }
    }

    impl SensorBank for Hw {
        fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError> {
            assert_eq!(sensor, 0);
            self.reads += 1;
            self.temp
        }
    }
    impl OppActuator for Hw {
        fn set_opp(&mut self, _d: usize, o: &Opp) -> Result<(), ActuateError> {
            self.sets.push(o.freq_khz);
            self.fail.map_or(Ok(()), Err)
        }
    }

    fn rt(model: &EnergyModel, min: u8) -> Runtime {
        let mut t = Thermal::new();
        let mut z = zone(min, 3, model);
        z.poll_ms = 100;
        z.poll_passive_ms = 100;
        t.push_zone(z).unwrap();
        Runtime::new(t)
    }

    fn want_top() -> Inputs {
        let mut i = Inputs::IDLE;
        i.want[0] = Some(3);
        i
    }

    fn run(r: &mut Runtime, hw: &mut Hw, m: &EnergyModel, inp: &Inputs, from: u64, n: u64) -> Settled {
        let mut s = r.last();
        for k in 0..n {
            s = r.tick(hw, m, from + k * 100, inp);
        }
        s
    }

    #[test]
    fn heat_pulls_the_clock_down_one_step_per_read_to_the_floor_and_no_further() {
        // The safety floor is declared at 500 MHz (OPP 0); 40 % real-time
        // density puts the deadline floor at OPP 2 (1.5 GHz).
        let m = model(500_000);
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(PASSIVE + 1_000));
        let mut inp = want_top();
        inp.admitted_ppm[0] = 400_000;
        // First read: cap 2. Second: cap 1, held at the floor (2). Then bound.
        let s = r.tick(&mut hw, &m, 0, &inp);
        assert_eq!((hw.sets.as_slice(), s.level), (&[1_500_000][..], 0));
        let s = run(&mut r, &mut hw, &m, &inp, 100, 6);
        assert!(hw.sets.iter().all(|&f| f >= 1_500_000), "{:?}", hw.sets);
        assert_eq!(hw.sets, [1_500_000], "the clock stayed where the floor put it");
        assert_eq!(s, Settled { level: LEVEL_CAUTIOUS, shutdown: false });
        assert_eq!(r.thermal.cap_state(0), 3);
        // Cool down: the cap rises, the governor gets its clock back.
        hw.temp = Ok(30_000);
        let s = run(&mut r, &mut hw, &m, &inp, 1_000, 4);
        assert_eq!((hw.sets.last(), s.level), (Some(&2_000_000), 0));
    }

    #[test]
    fn without_a_floor_the_clock_goes_all_the_way_down_and_comes_back() {
        let m = model(500_000);
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(PASSIVE + 1_000));
        let inp = want_top();
        run(&mut r, &mut hw, &m, &inp, 0, 4);
        assert_eq!(hw.sets, [1_500_000, 1_000_000, 500_000]);
        assert_eq!(r.last().level, 0);
        hw.temp = Ok(20_000);
        run(&mut r, &mut hw, &m, &inp, 1_000, 4);
        assert_eq!(&hw.sets[3..], [1_000_000, 1_500_000, 2_000_000]);
    }

    #[test]
    fn with_no_governor_the_clock_is_untouched_until_the_heat_asks_and_restored_after() {
        let m = model(500_000);
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(40_000));
        r.dvfs.assume(0, 3);
        run(&mut r, &mut hw, &m, &Inputs::IDLE, 0, 5);
        assert!(hw.sets.is_empty(), "invariant I4: nothing asked, nothing moved");
        hw.temp = Ok(PASSIVE + 500);
        run(&mut r, &mut hw, &m, &Inputs::IDLE, 1_000, 3);
        assert_eq!(hw.sets, [1_500_000, 1_000_000, 500_000]);
        hw.temp = Ok(20_000);
        run(&mut r, &mut hw, &m, &Inputs::IDLE, 2_000, 5);
        // Held at the capped clock while the cap lasted, then put back where firmware had it.
        assert_eq!(hw.sets, [1_500_000, 1_000_000, 500_000, 2_000_000]);
        assert_eq!(r.dvfs.current(0), Some(3));
    }

    #[test]
    fn with_the_firmware_opp_unknown_a_pulled_down_clock_is_not_restored() {
        let m = model(500_000);
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(PASSIVE + 500));
        run(&mut r, &mut hw, &m, &Inputs::IDLE, 0, 3);
        // Unknown start: the heat capped from the fastest OPP down.
        assert_eq!(hw.sets, [1_500_000, 1_000_000, 500_000]);
        hw.temp = Ok(20_000);
        run(&mut r, &mut hw, &m, &Inputs::IDLE, 1_000, 6);
        assert_eq!(hw.sets.len(), 3, "nothing to restore to: Runtime documents that wiring assumes the boot OPP");
        assert_eq!(r.dvfs.current(0), Some(0));
    }

    #[test]
    fn a_clock_that_cannot_be_moved_raises_the_level_instead_of_running_hot_unannounced() {
        let m = model(500_000);
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(PASSIVE + 1_000));
        hw.fail = Some(ActuateError::Unsupported);
        let s = run(&mut r, &mut hw, &m, &want_top(), 0, 2);
        assert_eq!(s.level, LEVEL_CAUTIOUS);
        assert_eq!(r.dvfs.refused(), 2);
        assert!((0..r.thermal.logged() as usize).any(|i| r.thermal.record(i).unwrap().event == Event::Uncooled));
    }

    #[test]
    fn a_zone_is_read_only_when_it_is_due() {
        let m = model(0);
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(40_000));
        r.tick(&mut hw, &m, 0, &Inputs::IDLE);
        r.tick(&mut hw, &m, 50, &Inputs::IDLE);
        r.tick(&mut hw, &m, 99, &Inputs::IDLE);
        assert_eq!(hw.reads, 1);
        r.tick(&mut hw, &m, 100, &Inputs::IDLE);
        assert_eq!(hw.reads, 2);
    }

    #[test]
    fn a_failing_sensor_slows_the_machine_and_a_recovered_one_releases_it() {
        let m = model(0);
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(40_000));
        hw.temp = Err(SensorError::Io);
        let s = run(&mut r, &mut hw, &m, &Inputs::IDLE, 0, 3);
        assert_eq!(s.level, LEVEL_SLOW);
        hw.temp = Ok(40_000);
        assert_eq!(run(&mut r, &mut hw, &m, &Inputs::IDLE, 300, 1).level, 0);
    }

    #[test]
    fn a_lost_sensor_pulls_the_clock_down_and_the_recovered_one_gives_it_back() {
        let m = model(500_000);
        // A governor asks for the top; the sensor is gone.
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(40_000));
        let inp = want_top();
        run(&mut r, &mut hw, &m, &inp, 0, 1);
        assert_eq!(hw.sets, [2_000_000]);
        hw.temp = Err(SensorError::Io);
        let s = run(&mut r, &mut hw, &m, &inp, 100, 3);
        assert_eq!(s.level, LEVEL_SLOW);
        assert_eq!(hw.sets.last(), Some(&500_000), "blind: the clock is at the deepest cap, not flat out");
        hw.temp = Ok(40_000);
        run(&mut r, &mut hw, &m, &inp, 400, 1);
        assert_eq!(hw.sets.last(), Some(&2_000_000));

        // No governor: the clock firmware chose is capped while blind and put back.
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(40_000));
        r.dvfs.assume(0, 3);
        hw.temp = Err(SensorError::Io);
        run(&mut r, &mut hw, &m, &Inputs::IDLE, 0, 3);
        assert_eq!(hw.sets.last(), Some(&500_000));
        hw.temp = Ok(40_000);
        run(&mut r, &mut hw, &m, &Inputs::IDLE, 300, 2);
        assert_eq!(hw.sets.last(), Some(&2_000_000), "put back where firmware had it");
        assert_eq!(r.last().level, 0);
    }

    #[test]
    fn hot_and_critical_readings_reach_the_level_and_the_shutdown_request() {
        let m = model(0);
        let (mut r, mut hw) = (rt(&m, 0), Hw::at(HOT));
        assert_eq!(run(&mut r, &mut hw, &m, &want_top(), 0, 1).level, LEVEL_SLOW);
        hw.temp = Ok(CRIT);
        let s = run(&mut r, &mut hw, &m, &want_top(), 100, 1);
        assert_eq!(s, Settled { level: LEVEL_CONTAINED, shutdown: true });
    }

    #[test]
    fn a_machine_without_zones_reads_no_sensor_and_caps_nothing() {
        let m = model(500_000);
        let mut r = Runtime::new(Thermal::new());
        let mut hw = Hw::at(120_000);
        let mut inp = Inputs::IDLE;
        inp.want = [Some(0); MAX_DOMAINS];
        // The governor's request alone does go through (the runtime is the
        // one path to the actuator) but no sensor is read and nothing is capped.
        let s = r.tick(&mut hw, &m, 0, &inp);
        assert_eq!((hw.reads, s), (0, Settled { level: 0, shutdown: false }));
        assert_eq!(hw.sets, [500_000]);
        let s = r.tick(&mut hw, &m, 10, &Inputs::IDLE);
        assert_eq!((hw.sets.len(), s.level), (1, 0));
    }
}

#[cfg(test)]
mod rpi {
    use super::model;
    use super::thermal::{zone, PASSIVE};
    use azos_energy::model::{EnergyModel, ModelSource, Opp};
    use azos_energy::opp::{ActuateError, OppActuator};
    use azos_energy::thermal::{Settled, Thermal, LEVEL_CAUTIOUS};
    use azos_firmware::*;
    use azos_thermal::rpi::{ArmClock, ProbeError, RpiFirmware};
    use azos_thermal::runtime::{Inputs, Runtime};
    use azos_thermal::sensor::{SensorBank, SensorError};

    /// How the fake VideoCore's ARM PLL answers.
    #[derive(Clone, Copy, PartialEq)]
    enum Pll {
        /// Rounds a request down to a multiple of `step` (and into the range).
        Down,
        /// Rounds a request up to a multiple of `step` (and into the range).
        Up,
        /// Takes no request: reports the rate it already has.
        Stuck,
    }

    /// A VideoCore with an ARM clock: the range and the rate it runs at.
    struct Vc {
        buf: *mut u8,
        reply: Option<u32>,
        code: u32,
        cur: u32,
        min: u32,
        max: u32,
        step: u32,
        pll: Pll,
        /// Does it implement the range tags? (An emulated property channel
        /// does not: the tags come back unanswered.)
        range: bool,
        /// The SoC temperature it reports, milli-degrees.
        temp: i32,
        /// Every `(tag, first value word after the clock id)` it was asked.
        asked: Vec<(u32, u32)>,
    }

    impl MailboxPort for Vc {
        fn read32(&mut self, off: usize) -> u32 {
            match off {
                REG_WRITE_STATUS => 0,
                REG_READ_STATUS => {
                    if self.reply.is_some() {
                        0
                    } else {
                        STATUS_EMPTY
                    }
                }
                REG_READ => self.reply.take().unwrap(),
                _ => unreachable!(),
            }
        }
        fn write32(&mut self, _off: usize, v: u32) {
            let w = self.buf as *mut u32;
            unsafe {
                let id = *w.add(2);
                self.asked.push((id, *w.add(6)));
                let answer = |val: u32| {
                    *w.add(2 + 2) = TAG_RESPONSE | 8;
                    *w.add(6) = val;
                };
                match id {
                    TAG_GET_TEMPERATURE => answer(self.temp as u32),
                    TAG_GET_CLOCK_RATE => answer(self.cur),
                    TAG_GET_MIN_CLOCK_RATE if self.range => answer(self.min),
                    TAG_GET_MAX_CLOCK_RATE if self.range => answer(self.max),
                    TAG_SET_CLOCK_RATE => {
                        let ask = *w.add(6);
                        let at = match self.pll {
                            Pll::Down => ask / self.step * self.step,
                            Pll::Up => ask.div_ceil(self.step) * self.step,
                            Pll::Stuck => self.cur,
                        };
                        self.cur = at.clamp(self.min, self.max);
                        answer(self.cur);
                    }
                    _ => {}
                }
                *w.add(1) = self.code;
            }
            self.reply = Some(v);
        }
        fn bus_addr(&self, _b: *const u8, _len: usize) -> Option<u32> {
            Some(0xC000_0000)
        }
        fn clean(&mut self, b: *mut u8, _l: usize) {
            self.buf = b;
        }
    }

    /// A Pi 5 shaped firmware: 1.5 GHz .. 2.4 GHz, boots at the top, 100 MHz steps.
    fn vc(code: u32) -> Vc {
        Vc {
            buf: core::ptr::null_mut(),
            reply: None,
            code,
            cur: 2_400_000_000,
            min: 1_500_000_000,
            max: 2_400_000_000,
            step: 100_000_000,
            pll: Pll::Down,
            range: true,
            temp: 62_500,
            asked: vec![],
        }
    }

    fn fw(v: Vc) -> RpiFirmware<Vc> {
        RpiFirmware::new(Mailbox::new(v))
    }

    /// A firmware that has been probed.
    fn probed(v: Vc) -> RpiFirmware<Vc> {
        let mut f = fw(v);
        f.probe_clock().unwrap();
        f.mbox.port().asked.clear();
        f
    }

    fn opp(khz: u32) -> Opp {
        Opp { freq_khz: khz, capacity: 512, power_mw: 400 }
    }

    fn sets(f: &mut RpiFirmware<Vc>) -> Vec<u32> {
        f.mbox.port().asked.iter().filter(|a| a.0 == TAG_SET_CLOCK_RATE).map(|a| a.1).collect()
    }

    #[test]
    fn sensor_zero_is_the_soc_temperature_and_nothing_else_exists() {
        let mut f = fw(vc(CODE_RESPONSE_OK));
        assert_eq!(f.read_mdeg(0), Ok(62_500));
        assert_eq!(f.read_mdeg(1), Err(SensorError::Absent));
        assert_eq!(fw(vc(CODE_RESPONSE_ERROR)).read_mdeg(0), Err(SensorError::Invalid));
    }

    #[test]
    fn the_boot_clock_is_the_arm_clock_in_khz_and_a_silent_firmware_gives_none() {
        assert_eq!(fw(vc(CODE_RESPONSE_OK)).arm_khz(), Some(2_400_000));
        assert_eq!(fw(vc(CODE_RESPONSE_ERROR)).arm_khz(), None);
    }

    #[test]
    fn the_probe_reads_the_rate_and_the_range_of_the_arm_clock() {
        let mut f = fw(vc(CODE_RESPONSE_OK));
        assert_eq!(f.clock(), None, "no actuator before a probe");
        assert_eq!(f.probe_clock(), Ok(ArmClock { min_hz: 1_500_000_000, max_hz: 2_400_000_000 }));
        assert_eq!(f.clock(), Some(ArmClock { min_hz: 1_500_000_000, max_hz: 2_400_000_000 }));
        // All three were asked, for the ARM clock (id 3).
        assert_eq!(
            f.mbox.port().asked.iter().map(|a| a.0).collect::<Vec<_>>(),
            [TAG_GET_CLOCK_RATE, TAG_GET_MIN_CLOCK_RATE, TAG_GET_MAX_CLOCK_RATE]
        );
    }

    #[test]
    fn an_object_that_was_not_probed_is_no_actuator_and_posts_nothing() {
        let mut f = fw(vc(CODE_RESPONSE_OK));
        assert_eq!(f.set_opp(0, &opp(2_000_000)), Err(ActuateError::Unsupported));
        assert!(f.mbox.port().asked.is_empty());
    }

    #[test]
    fn an_emulated_property_channel_gives_no_actuator() {
        // QEMU `raspi`: the rate answers, the range tags do not.
        let mut v = vc(CODE_RESPONSE_OK);
        v.range = false;
        let mut f = fw(v);
        assert_eq!(f.probe_clock(), Err(ProbeError::Firmware(MailboxError::NoResponse)));
        assert_eq!(f.clock(), None);
        f.mbox.port().asked.clear();
        assert_eq!(f.set_opp(0, &opp(2_000_000)), Err(ActuateError::Unsupported));
        assert!(f.mbox.port().asked.is_empty(), "nothing was posted to a firmware that cannot move the clock");
        // A firmware that refuses the messages altogether is the same.
        let mut f = fw(vc(CODE_RESPONSE_ERROR));
        assert_eq!(f.probe_clock(), Err(ProbeError::Firmware(MailboxError::Refused)));
        assert_eq!(f.set_opp(0, &opp(2_000_000)), Err(ActuateError::Unsupported));
        // The sensor is unaffected by the missing actuator.
        let mut f = fw({
            let mut v = vc(CODE_RESPONSE_OK);
            v.range = false;
            v
        });
        let _ = f.probe_clock();
        assert_eq!(f.read_mdeg(0), Ok(62_500));
    }

    #[test]
    fn a_range_that_cannot_move_is_not_an_actuator() {
        // A firmware (or an emulation) that answers with constants: min == max.
        let mut v = vc(CODE_RESPONSE_OK);
        v.min = v.max;
        assert_eq!(fw(v).probe_clock(), Err(ProbeError::Degenerate));
        // A zero minimum is not a rate.
        let mut v = vc(CODE_RESPONSE_OK);
        v.min = 0;
        assert_eq!(fw(v).probe_clock(), Err(ProbeError::Degenerate));
        // A minimum above the maximum.
        let mut v = vc(CODE_RESPONSE_OK);
        v.min = v.max + 1;
        assert_eq!(fw(v).probe_clock(), Err(ProbeError::Degenerate));
        // A current rate outside the range it claims.
        let mut v = vc(CODE_RESPONSE_OK);
        v.cur = v.max + 100_000_000;
        let mut f = fw(v);
        assert_eq!(f.probe_clock(), Err(ProbeError::Degenerate));
        assert_eq!(f.set_opp(0, &opp(2_000_000)), Err(ActuateError::Unsupported));
    }

    #[test]
    fn a_failed_probe_takes_back_an_actuator_an_earlier_one_found() {
        let mut f = fw(vc(CODE_RESPONSE_OK));
        f.probe_clock().unwrap();
        f.mbox.port().range = false;
        assert!(f.probe_clock().is_err());
        assert_eq!(f.clock(), None);
    }

    #[test]
    fn an_opp_in_range_is_a_set_clock_rate_on_the_arm_clock() {
        let mut f = probed(vc(CODE_RESPONSE_OK));
        assert_eq!(f.set_opp(0, &opp(1_800_000)), Ok(()));
        // The current rate was read, then the request carried the OPP in Hz.
        assert_eq!(f.mbox.port().asked, [(TAG_GET_CLOCK_RATE, 0), (TAG_SET_CLOCK_RATE, 1_800_000_000)]);
        assert_eq!(f.mbox.arm_clock_rate(), Ok(1_800_000_000));
        // One cluster: any other domain is not ours.
        f.mbox.port().asked.clear();
        assert_eq!(f.set_opp(1, &opp(1_800_000)), Err(ActuateError::Unsupported));
        assert!(f.mbox.port().asked.is_empty());
    }

    #[test]
    fn a_rate_outside_the_firmwares_range_is_refused_before_it_is_posted() {
        let mut f = probed(vc(CODE_RESPONSE_OK));
        assert_eq!(f.set_opp(0, &opp(1_000_000)), Err(ActuateError::Refused), "below the minimum");
        assert_eq!(f.set_opp(0, &opp(2_600_000)), Err(ActuateError::Refused), "above the maximum");
        assert_eq!(f.set_opp(0, &opp(u32::MAX)), Err(ActuateError::Refused), "kHz to Hz overflows");
        assert!(f.mbox.port().asked.is_empty(), "{:?}", f.mbox.port().asked);
        // The edges of the range are in it.
        assert_eq!(f.set_opp(0, &opp(1_500_000)), Ok(()));
        assert_eq!(f.set_opp(0, &opp(2_400_000)), Ok(()));
    }

    #[test]
    fn a_firmware_that_rounds_the_clock_under_the_request_is_put_back_and_refused() {
        // 1.55 GHz is not a PLL step: the firmware settles on 1.5 GHz, under
        // the 1.55 GHz the framework admitted as the real-time floor.
        let mut f = probed(vc(CODE_RESPONSE_OK));
        assert_eq!(f.set_opp(0, &opp(1_550_000)), Err(ActuateError::Refused));
        assert_eq!(sets(&mut f), [1_550_000_000, 2_400_000_000], "asked, then put back where it was");
        assert_eq!(f.mbox.arm_clock_rate(), Ok(2_400_000_000), "the clock did not stay under the floor");
    }

    #[test]
    fn a_firmware_that_rounds_up_is_accepted_while_it_still_throttles() {
        let mut v = vc(CODE_RESPONSE_OK);
        v.pll = Pll::Up;
        let mut f = probed(v);
        assert_eq!(f.set_opp(0, &opp(1_550_000)), Ok(()));
        assert_eq!(f.mbox.arm_clock_rate(), Ok(1_600_000_000), "above the request, below where it was");
        assert_eq!(sets(&mut f), [1_550_000_000]);
    }

    #[test]
    fn a_throttle_the_firmware_does_not_apply_is_refused() {
        // The firmware answers but keeps the clock where it was (its own
        // limits): the heat was not answered, and the framework must hear it.
        let mut v = vc(CODE_RESPONSE_OK);
        v.pll = Pll::Stuck;
        let mut f = probed(v);
        assert_eq!(f.set_opp(0, &opp(1_800_000)), Err(ActuateError::Refused));
        // Raising when the clock cannot go up is not a lowering that failed:
        // an OPP at the current rate is simply where the clock is.
        assert_eq!(f.set_opp(0, &opp(2_400_000)), Ok(()));
    }

    #[test]
    fn the_rate_it_is_compared_to_is_the_one_the_clock_has_now() {
        // The firmware lowered the clock by itself (its own thermal limit)
        // after the probe. A request between that rate and the old one is
        // not a lowering any more.
        let mut v = vc(CODE_RESPONSE_OK);
        v.pll = Pll::Up;
        let mut f = probed(v);
        f.mbox.port().cur = 1_700_000_000;
        assert_eq!(f.set_opp(0, &opp(2_000_000)), Ok(()));
        assert_eq!(f.mbox.arm_clock_rate(), Ok(2_000_000_000));
    }

    #[test]
    fn a_firmware_error_is_a_refusal() {
        let mut f = probed(vc(CODE_RESPONSE_OK));
        f.mbox.port().code = CODE_RESPONSE_ERROR;
        assert_eq!(f.set_opp(0, &opp(1_800_000)), Err(ActuateError::Refused));
    }

    // The Pi 5 through the runtime: 4 OPPs, the firmware range inside them.

    fn rt(m: &azos_energy::model::EnergyModel) -> Runtime {
        let mut t = Thermal::new();
        let mut z = zone(0, 3, m);
        z.poll_ms = 100;
        z.poll_passive_ms = 100;
        t.push_zone(z).unwrap();
        Runtime::new(t)
    }

    /// The firmware over the shared test model's span (500 MHz .. 2 GHz,
    /// 100 MHz steps), booted at the top and at `temp` milli-degrees.
    fn pi_with_model_range(temp: i32) -> RpiFirmware<Vc> {
        let mut v = vc(CODE_RESPONSE_OK);
        v.min = 500_000_000;
        v.max = 2_000_000_000;
        v.cur = 2_000_000_000;
        v.temp = temp;
        probed(v)
    }

    #[test]
    fn heat_throttles_the_arm_clock_through_the_firmware_and_never_under_the_floor() {
        // 40 % real-time density: the deadline floor is OPP 2 (1.5 GHz).
        let m = model(500_000);
        let mut r = rt(&m);
        r.assume_boot(&m, |_| Some(2_000_000));
        let mut f = pi_with_model_range(PASSIVE + 1_000);
        let mut inp = Inputs::IDLE;
        inp.want[0] = Some(3);
        inp.admitted_ppm[0] = 400_000;
        let mut s = Settled { level: 0, shutdown: false };
        for k in 0..6 {
            s = r.tick(&mut f, &m, k * 100, &inp);
        }
        assert_eq!(f.mbox.arm_clock_rate(), Ok(1_500_000_000), "pulled down to the floor, no further");
        assert_eq!(sets(&mut f), [1_500_000_000], "one request: the floor held the rest");
        assert_eq!(s.level, LEVEL_CAUTIOUS);
        // Cool: the governor gets the top back.
        f.mbox.port().temp = 30_000;
        for k in 0..4 {
            r.tick(&mut f, &m, 1_000 + k * 100, &inp);
        }
        assert_eq!(f.mbox.arm_clock_rate(), Ok(2_000_000_000));
    }

    // The table the probed range makes (the energy step's source for the Pi).

    #[test]
    fn the_probed_range_is_domain_zeros_opp_table_and_building_it_asks_the_firmware_nothing() {
        let mut f = probed(vc(CODE_RESPONSE_OK));
        let (m, r) = azos_energy::resolve(&EnergyModel::NONE, None, None, f.energy_model(4), 4);
        assert_eq!((m.source, r.source, r.firmware_fault), (ModelSource::Firmware, ModelSource::Firmware, None));
        assert_eq!(m.domains().len(), 1);
        let d = &m.domains()[0];
        assert_eq!(d.cpus, 0b1111, "every core of the cluster shares the one clock");
        let khz: Vec<u32> = d.opps().iter().map(|o| o.freq_khz).collect();
        assert_eq!(khz, (15..=24).map(|h| h * 100_000).collect::<Vec<_>>(), "min, a step of 100 MHz, max");
        assert!(d.opps().iter().all(|o| o.power_mw > 0), "a model with a zero power is refused");
        assert!(f.mbox.port().asked.is_empty(), "the table is made from the probe; no clock was asked or moved");
    }

    #[test]
    fn the_table_ends_at_the_maximum_the_firmware_reported() {
        let mut v = vc(CODE_RESPONSE_OK);
        v.max = 2_450_000_000;
        let f = probed(v);
        let m = f.energy_model(4).unwrap().unwrap();
        let top = m.domains()[0].opps().last().copied().unwrap();
        assert_eq!((top.freq_khz, top.capacity), (2_450_000, 1024), "past the maximum is a rate the firmware refuses");
        assert_eq!(m.validate(4), Ok(()));
    }

    #[test]
    fn no_probed_range_is_no_table() {
        // Never probed.
        assert!(fw(vc(CODE_RESPONSE_OK)).energy_model(4).is_none());
        // An emulated property channel: the range tags come back unanswered.
        let mut v = vc(CODE_RESPONSE_OK);
        v.range = false;
        let mut f = fw(v);
        assert!(f.probe_clock().is_err());
        assert!(f.energy_model(4).is_none());
    }

    #[test]
    fn every_opp_of_the_table_is_a_rate_the_actuator_gets_from_a_100_mhz_firmware() {
        let mut f = probed(vc(CODE_RESPONSE_OK));
        let m = f.energy_model(4).unwrap().unwrap();
        // Down the table and back up it: each step lands on its own rate.
        let opps = m.domains()[0].opps();
        for o in opps.iter().rev().chain(opps.iter()) {
            assert_eq!(f.set_opp(0, o), Ok(()), "{} kHz", o.freq_khz);
            assert_eq!(f.mbox.arm_clock_rate(), Ok(o.freq_khz * 1000));
        }
    }

    #[test]
    fn the_clock_the_firmware_booted_at_is_an_opp_of_the_table() {
        let mut v = vc(CODE_RESPONSE_OK);
        v.cur = 1_700_000_000;
        let mut f = probed(v);
        let m = f.energy_model(4).unwrap().unwrap();
        let mut r = rt(&m);
        let boot = f.arm_khz();
        r.assume_boot(&m, |d| boot.filter(|_| d == 0));
        let at = r.dvfs.current(0).expect("the boot clock names an OPP");
        assert_eq!(m.domains()[0].opps()[at].freq_khz, 1_700_000);
    }

    #[test]
    fn without_a_range_the_heat_raises_the_level_instead_of_a_clock_nobody_moved() {
        let m = model(500_000);
        let mut r = rt(&m);
        r.assume_boot(&m, |_| Some(2_000_000));
        let mut v = vc(CODE_RESPONSE_OK);
        v.range = false;
        v.temp = PASSIVE + 1_000;
        let mut f = fw(v);
        assert!(f.probe_clock().is_err());
        f.mbox.port().asked.clear();
        let mut inp = Inputs::IDLE;
        inp.want[0] = Some(3);
        let mut s = Settled { level: 0, shutdown: false };
        for k in 0..2 {
            s = r.tick(&mut f, &m, k * 100, &inp);
        }
        assert_eq!(s.level, LEVEL_CAUTIOUS);
        assert_eq!(r.dvfs.refused(), 2);
        assert!(sets(&mut f).is_empty(), "no clock request reached the firmware");
    }
}

#[cfg(test)]
mod k1_opp {
    use azos_dtb::{dtb_energy, DtEnergy, DtOpp, DtOppTable};
    use azos_energy::dt::from_dt;
    use crate::by_reg;
    use azos_energy::model::Opp;
    use azos_energy::opp::{ActuateError, Applied, Dvfs, OppActuator};
    use azos_thermal::k1::*;

    /// The rail's `regulator-max-microvolt` and `regulator-ramp-delay`
    /// (uV/us) of the fixture's board (invented, the Jupiter tree's shape).
    const RAIL_MAX: u32 = 1_050_000;
    const RAMP: u32 = 5_000;

    fn energy() -> DtEnergy {
        let p = format!("{}/fixtures/k1-opp.dtb", env!("CARGO_MANIFEST_DIR"));
        let mut v = std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
        v.extend_from_slice(&[0; 8]);
        unsafe { dtb_energy(v.as_ptr()) }.expect("readable blob")
    }

    fn table(i: usize) -> K1Table {
        K1Table::from_dt(&energy().tables()[i], RAIL_MAX, RAMP).expect("table")
    }

    fn rows(t: &K1Table) -> Vec<(u32, u32)> {
        t.rows().iter().map(|r| (r.freq_khz, r.uv)).collect()
    }

    fn opp(khz: u32) -> Opp {
        Opp { freq_khz: khz, capacity: 1, power_mw: 1 }
    }

    // ---- the table ----

    #[test]
    fn the_voltages_come_from_the_device_tree_slowest_first() {
        let e = energy();
        assert_eq!(e.tables().len(), 2);
        // The raw tables carry the voltage: a one-cell property is its own
        // maximum, a three-cell one is <target min max>.
        let raw: Vec<(u64, u32, u32)> = e.tables()[0].opps[..4].iter().map(|o| (o.hz, o.uv, o.uv_max)).collect();
        assert_eq!(
            raw,
            [
                (1_200_000_000, 1_000_000, 1_000_000),
                (600_000_000, 900_000, 900_000),
                (1_600_000_000, 1_100_000, 1_100_000),
                (800_000_000, 950_000, 950_000),
            ]
        );
        assert_eq!(e.tables()[1].opps[1].uv_max, 1_050_000);
        // The table is sorted, and the disabled OPP (975 mV, 1 GHz) is not in it.
        let t0 = table(0);
        assert_eq!(rows(&t0), [(600_000, 900_000), (800_000, 950_000), (1_200_000, 1_000_000)]);
        assert_eq!(t0.ceiling_uv(), RAIL_MAX);
    }

    #[test]
    fn an_opp_over_the_rail_or_its_own_maximum_is_dropped_never_clamped() {
        // 1.6 GHz asks 1.10 V on a rail that stops at 1.05 V.
        let t0 = table(0);
        assert_eq!(t0.dropped(), 1);
        assert_eq!(t0.row(1_600_000), None);
        // 1.4 GHz asks 1.04 V under its own 1.03 V maximum.
        let t1 = table(1);
        assert_eq!(rows(&t1), [(600_000, 900_000), (1_200_000, 1_000_000)]);
        assert_eq!(t1.dropped(), 1);
        // A lower rail takes more with it; nothing in the table is above it.
        let low = K1Table::from_dt(&energy().tables()[0], 960_000, RAMP).unwrap();
        assert_eq!(rows(&low), [(600_000, 900_000), (800_000, 950_000)]);
        assert_eq!(low.dropped(), 2);
        assert!(low.rows().iter().all(|r| r.uv <= low.ceiling_uv()));
        // A rail below everything leaves nothing to run.
        assert_eq!(K1Table::from_dt(&energy().tables()[0], 800_000, RAMP), Err(TableError::Empty));
    }

    fn one(hz: u64, uv: u32, uv_max: u32) -> DtOpp {
        DtOpp { hz, microwatt: 1, uv, uv_max }
    }

    fn built(opps: &[DtOpp]) -> DtOppTable {
        let mut t = energy().tables()[0];
        t.n_opps = opps.len() as u8;
        t.opps[..opps.len()].copy_from_slice(opps);
        t
    }

    #[test]
    fn a_table_that_cannot_be_run_safely_is_refused_whole() {
        let ok = [one(600_000_000, 900_000, 900_000), one(1_200_000_000, 1_000_000, 1_000_000)];
        let from = |t: &DtOppTable, max, ramp| K1Table::from_dt(t, max, ramp);
        assert!(from(&built(&ok), RAIL_MAX, RAMP).is_ok());
        assert_eq!(from(&built(&ok), 0, RAMP), Err(TableError::NoCeiling));
        assert_eq!(from(&built(&ok), RAIL_MAX, 0), Err(TableError::ZeroRamp));
        assert_eq!(from(&built(&[]), RAIL_MAX, RAMP), Err(TableError::Empty));
        // A hole in the voltages is not guessed around.
        let hole = [ok[0], one(800_000_000, 0, 0), ok[1]];
        assert_eq!(from(&built(&hole), RAIL_MAX, RAMP), Err(TableError::NoVoltage));
        let zero_hz = [one(0, 900_000, 900_000)];
        assert_eq!(from(&built(&zero_hz), RAIL_MAX, RAMP), Err(TableError::BadFrequency));
        let huge = [one(u64::MAX, 900_000, 900_000)];
        assert_eq!(from(&built(&huge), RAIL_MAX, RAMP), Err(TableError::BadFrequency));
        let dup = [ok[0], ok[0]];
        assert_eq!(from(&built(&dup), RAIL_MAX, RAMP), Err(TableError::Duplicate));
        // Faster for less voltage would let the ordering undervolt a core.
        let inverted = [one(600_000_000, 1_000_000, 1_000_000), one(1_200_000_000, 900_000, 900_000)];
        assert_eq!(from(&built(&inverted), RAIL_MAX, RAMP), Err(TableError::NotMonotonic));
    }

    // ---- the cluster ----

    /// A cluster that is what the hardware is: a clock and a rail, and the
    /// rule that the rail carries the clock. Every write is logged and, after
    /// it, the rule is checked; so is the ceiling.
    struct Cluster {
        khz: u32,
        uv: u32,
        /// What each frequency needs (the table's own voltages: the DT's
        /// claim, the thing being enforced).
        need: Vec<(u32, u32)>,
        ceiling: u32,
        ramp: u32,
        log: Vec<String>,
        /// Fail the n-th (0-based) clock write / rail write from now on.
        fail_clock: Option<(usize, ActuateError)>,
        fail_rail: Option<(usize, ActuateError)>,
        clock_writes: usize,
        rail_writes: usize,
        /// The read-back fails.
        blind: bool,
        /// Microseconds waited since the last rail write.
        waited_since_rail: Option<u32>,
        last_rise_uv: u32,
        /// The clock makes multiples of this (0: exactly what is asked), the
        /// way a PLL divider makes 819.2 MHz when the DT row says 819.
        quantum: u32,
    }

    impl Cluster {
        fn new(t: &K1Table, khz: u32, uv: u32) -> Self {
            Self {
                khz,
                uv,
                need: rows(t),
                ceiling: t.ceiling_uv(),
                ramp: RAMP,
                log: vec![],
                fail_clock: None,
                fail_rail: None,
                clock_writes: 0,
                rail_writes: 0,
                blind: false,
                waited_since_rail: None,
                last_rise_uv: 0,
                quantum: 0,
            }
        }

        /// What the clock makes for a request of `khz`.
        fn made(&self, khz: u32) -> u32 {
            if self.quantum == 0 { khz } else { khz.div_ceil(self.quantum) * self.quantum }
        }

        /// The voltage `khz` needs: the lowest row at or above it (the top row
        /// for a clock above the table).
        fn needs(&self, khz: u32) -> u32 {
            self.need.iter().find(|r| r.0 >= khz).or(self.need.last()).map_or(0, |r| r.1)
        }

        fn check(&self) {
            assert!(
                self.uv >= self.needs(self.khz),
                "{} kHz on {} uV, needs {}: {:?}",
                self.khz,
                self.uv,
                self.needs(self.khz),
                self.log
            );
        }
    }

    impl K1Hw for &mut Cluster {
        fn cpu_khz(&mut self, d: usize) -> Result<u32, ActuateError> {
            assert_eq!(d, 0);
            if self.blind { Err(ActuateError::Fault(-5)) } else { Ok(self.khz) }
        }
        fn set_cpu_khz(&mut self, d: usize, khz: u32) -> Result<(), ActuateError> {
            assert_eq!(d, 0);
            let n = self.clock_writes;
            self.clock_writes += 1;
            if let Some((at, e)) = self.fail_clock {
                if n >= at {
                    self.log.push(format!("c{khz}!"));
                    return Err(e);
                }
            }
            // A rise of the rail has to have been waited out before the clock
            // moves up on it.
            if khz > self.khz {
                assert!(
                    self.waited_since_rail.is_none_or(|w| w >= self.last_rise_uv.div_ceil(self.ramp)),
                    "clock up before the rail settled: {:?}",
                    self.log
                );
            }
            self.log.push(format!("c{khz}"));
            self.khz = self.made(khz);
            self.check();
            Ok(())
        }
        fn round_khz(&mut self, d: usize, khz: u32) -> Result<u32, ActuateError> {
            assert_eq!(d, 0);
            Ok(self.made(khz))
        }
        fn rail_of(&self, _: usize) -> Option<u8> {
            None
        }
        fn voltage_uv(&mut self, d: usize) -> Result<u32, ActuateError> {
            assert_eq!(d, 0);
            if self.blind { Err(ActuateError::Fault(-5)) } else { Ok(self.uv) }
        }
        fn set_voltage_uv(&mut self, d: usize, uv: u32) -> Result<(), ActuateError> {
            assert_eq!(d, 0);
            assert!(uv <= self.ceiling, "{uv} uV is above the ceiling {}: {:?}", self.ceiling, self.log);
            let n = self.rail_writes;
            self.rail_writes += 1;
            if let Some((at, e)) = self.fail_rail {
                if n >= at {
                    self.log.push(format!("v{uv}!"));
                    return Err(e);
                }
            }
            self.last_rise_uv = uv.saturating_sub(self.uv);
            self.waited_since_rail = Some(0);
            self.log.push(format!("v{uv}"));
            self.uv = uv;
            self.check();
            Ok(())
        }
        fn delay_us(&mut self, us: u32) {
            self.log.push(format!("d{us}"));
            if let Some(w) = self.waited_since_rail.as_mut() {
                *w += us;
            }
        }
    }

    /// Run `f` on an actuator over `c`, bound to `t` as domain 0.
    fn with<R>(c: &mut Cluster, t: K1Table, f: impl FnOnce(&mut K1Opp<&mut Cluster>) -> R) -> R {
        let mut a = K1Opp::new(c);
        assert!(a.bind(0, t));
        f(&mut a)
    }

    #[test]
    fn going_up_raises_the_rail_waits_for_the_ramp_then_raises_the_clock() {
        let t = table(0);
        let mut c = Cluster::new(&t, 600_000, 900_000);
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(1_200_000))), Ok(()));
        // 900 -> 1000 mV at 5000 uV/us is 20 us.
        assert_eq!(c.log, ["v1000000", "d20", "c1200000"]);
        assert_eq!((c.khz, c.uv), (1_200_000, 1_000_000));
    }

    #[test]
    fn going_down_lowers_the_clock_then_the_rail() {
        let t = table(0);
        let mut c = Cluster::new(&t, 1_200_000, 1_000_000);
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(600_000))), Ok(()));
        assert_eq!(c.log, ["c600000", "v900000"]);
        assert_eq!((c.khz, c.uv), (600_000, 900_000));
    }

    #[test]
    fn every_pair_of_operating_points_keeps_the_rail_above_the_clock_at_every_write() {
        for ti in 0..2 {
            let t = table(ti);
            let all = rows(&t);
            for &(from_khz, from_uv) in &all {
                for &(to_khz, to_uv) in &all {
                    let mut c = Cluster::new(&t, from_khz, from_uv);
                    assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(to_khz))), Ok(()), "{from_khz} -> {to_khz}");
                    assert_eq!((c.khz, c.uv), (to_khz, to_uv), "{from_khz} -> {to_khz}: {:?}", c.log);
                    // Going up, the rail is written before the clock; going down, after.
                    let pos = |p: char| c.log.iter().position(|l| l.starts_with(p));
                    match to_khz.cmp(&from_khz) {
                        std::cmp::Ordering::Greater if to_uv > from_uv => assert!(pos('v') < pos('c'), "{:?}", c.log),
                        std::cmp::Ordering::Less => assert!(pos('c') < pos('v'), "{:?}", c.log),
                        std::cmp::Ordering::Equal => assert!(c.log.is_empty(), "{:?}", c.log),
                        _ => {}
                    }
                }
            }
        }
    }

    #[test]
    fn going_up_never_lowers_a_rail_that_firmware_left_high() {
        let t = table(0);
        // Booted at 600 MHz on 1.0 V (above its 900 mV): the climb to 800 MHz
        // (950 mV) writes only the clock, and the rail stays where it was.
        let mut c = Cluster::new(&t, 600_000, 1_000_000);
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(800_000))), Ok(()));
        assert_eq!(c.log, ["c800000"]);
        assert_eq!(c.uv, 1_000_000);
    }

    #[test]
    fn a_frequency_firmware_booted_at_that_the_table_does_not_list_is_moved_from_safely() {
        let t = table(0);
        // 1.3 GHz is above the table (its 1.6 GHz row was dropped for being
        // over the rail): the clock goes down first, then the rail follows.
        let mut c = Cluster::new(&t, 1_300_000, 1_050_000);
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(800_000))), Ok(()));
        assert_eq!(c.log, ["c800000", "v950000"]);
    }

    #[test]
    fn a_request_over_the_ceiling_or_off_the_table_writes_nothing() {
        let t = table(0);
        let mut c = Cluster::new(&t, 600_000, 900_000);
        // 1.6 GHz was dropped (1.10 V on a 1.05 V rail); 1 GHz is a disabled OPP;
        // 700 MHz was never one.
        for khz in [1_600_000, 1_000_000, 700_000, 0, u32::MAX] {
            assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(khz))), Err(ActuateError::Refused), "{khz}");
        }
        // A cluster that is not bound, or not there.
        assert_eq!(with(&mut c, t, |a| a.set_opp(1, &opp(600_000))), Err(ActuateError::Unsupported));
        assert_eq!(with(&mut c, t, |a| a.set_opp(MAX_K1_DOMAINS, &opp(600_000))), Err(ActuateError::Unsupported));
        let mut idle = K1Opp::new(&mut c);
        assert_eq!(idle.set_opp(0, &opp(600_000)), Err(ActuateError::Unsupported));
        assert!(!idle.bind(MAX_K1_DOMAINS, t));
        assert!(c.log.is_empty(), "{:?}", c.log);
        assert_eq!((c.clock_writes, c.rail_writes), (0, 0));
    }

    #[test]
    fn a_clock_that_will_not_rise_puts_the_rail_back() {
        let t = table(0);
        let mut c = Cluster::new(&t, 600_000, 900_000);
        c.fail_clock = Some((0, ActuateError::Refused));
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(1_200_000))), Err(ActuateError::Refused));
        assert_eq!(c.log, ["v1000000", "d20", "c1200000!", "v900000"]);
        assert_eq!((c.khz, c.uv), (600_000, 900_000));
    }

    #[test]
    fn a_rail_that_will_not_rise_leaves_the_clock_alone() {
        let t = table(0);
        let mut c = Cluster::new(&t, 600_000, 900_000);
        c.fail_rail = Some((0, ActuateError::Fault(-110)));
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(1_200_000))), Err(ActuateError::Fault(-110)));
        assert_eq!(c.log, ["v1000000!"]);
        assert_eq!((c.khz, c.uv), (600_000, 900_000));
    }

    #[test]
    fn a_rail_that_will_not_follow_the_clock_down_is_a_lag_not_a_refusal() {
        let t = table(0);
        let mut c = Cluster::new(&t, 1_200_000, 1_000_000);
        c.fail_rail = Some((0, ActuateError::Fault(-110)));
        let mut a = K1Opp::new(&mut c);
        assert!(a.bind(0, t));
        // The throttle is done: the clock fell. The answer is Ok because the
        // clock is where it was asked; the rail stays above what it needs.
        assert_eq!(a.set_opp(0, &opp(600_000)), Ok(()));
        assert_eq!(a.hw.log, ["c600000", "v900000!"]);
        assert_eq!((a.hw.khz, a.hw.uv), (600_000, 1_000_000));
        // ... and says so, once.
        assert_eq!(
            a.take_lag(),
            Some(RailLag { domain: 0, khz: 600_000, last_uv: 1_000_000, want_uv: 900_000, err: ActuateError::Fault(-110) })
        );
        assert_eq!((a.take_lag(), a.lagged()), (None, 1));
        // The next request reads the state again: the rail comes down now.
        a.hw.fail_rail = None;
        assert_eq!(a.set_opp(0, &opp(600_000)), Ok(()));
        assert_eq!((a.hw.khz, a.hw.uv), (600_000, 900_000));
        assert_eq!((a.take_lag(), a.lagged()), (None, 1));
    }

    /// What the thermal runtime believes must be what the clock is, after
    /// every answer the actuator can give: `Dvfs` restores and caps by it.
    fn believed_opp_is_the_clocks(model: &azos_energy::model::EnergyModel, dvfs: &Dvfs, khz: u32) {
        let d = &model.domains()[0];
        let idx = dvfs.current(0).expect("known");
        // The clock the cluster reads back is the OPP's (the fixture's
        // clocks make exactly what they are asked).
        assert_eq!(d.opps()[idx].freq_khz, khz, "dvfs believes OPP {idx}, the clock reads {khz} kHz");
    }

    #[test]
    fn dvfs_believes_the_clock_after_every_failure_the_rail_can_have() {
        let model = from_dt(&energy(), &by_reg).unwrap().unwrap();
        // The model's OPPs: 0 600 MHz, 1 800 MHz, 2 1.2 GHz, 3 1.6 GHz (dropped).
        let down_fail = |e: ActuateError| {
            let t = table(0);
            let mut c = Cluster::new(&t, 1_200_000, 1_000_000);
            c.fail_rail = Some((0, e));
            let mut dvfs = Dvfs::new();
            dvfs.assume(0, 2);
            let mut a = K1Opp::new(&mut c);
            assert!(a.bind(0, t));
            // Throttle to 600 MHz: the clock falls, the rail will not.
            assert!(dvfs.set(&mut a, &model, 0, 0).is_ok());
            let khz = a.hw.khz;
            believed_opp_is_the_clocks(&model, &dvfs, khz);
            // The heat is gone: restore to 1.2 GHz. The rail is still up, so
            // the clock rises with no rail write, and the belief follows.
            assert!(dvfs.set(&mut a, &model, 0, 2).is_ok());
            let khz = a.hw.khz;
            believed_opp_is_the_clocks(&model, &dvfs, khz);
            assert_eq!(a.hw.uv, 1_000_000);
        };
        down_fail(ActuateError::Fault(-110));
        down_fail(ActuateError::Fault(-5));
        down_fail(ActuateError::Refused);

        // An Err leaves the belief where it was, and the clock too.
        let t = table(0);
        let mut c = Cluster::new(&t, 1_200_000, 1_000_000);
        c.fail_clock = Some((0, ActuateError::Refused));
        let mut dvfs = Dvfs::new();
        dvfs.assume(0, 2);
        let mut a = K1Opp::new(&mut c);
        assert!(a.bind(0, t));
        assert_eq!(dvfs.set(&mut a, &model, 0, 0), Err(ActuateError::Refused));
        let khz = a.hw.khz;
        believed_opp_is_the_clocks(&model, &dvfs, khz);

        // Up: a rail that will not rise moves nothing, and the belief stays.
        let mut c = Cluster::new(&t, 600_000, 900_000);
        c.fail_rail = Some((0, ActuateError::Fault(-110)));
        let mut dvfs = Dvfs::new();
        dvfs.assume(0, 0);
        let mut a = K1Opp::new(&mut c);
        assert!(a.bind(0, t));
        assert_eq!(dvfs.set(&mut a, &model, 0, 2), Err(ActuateError::Fault(-110)));
        let khz = a.hw.khz;
        believed_opp_is_the_clocks(&model, &dvfs, khz);

        // Up: a clock that will not rise puts the rail back; if the put-back
        // fails too, the clock is where it was (the belief too) and the rail
        // is left high, reported.
        let mut c = Cluster::new(&t, 600_000, 900_000);
        c.fail_clock = Some((0, ActuateError::Refused));
        let mut dvfs = Dvfs::new();
        dvfs.assume(0, 0);
        let mut a = K1Opp::new(&mut c);
        assert!(a.bind(0, t));
        a.hw.fail_rail = Some((1, ActuateError::Fault(-110)));
        assert_eq!(dvfs.set(&mut a, &model, 0, 2), Err(ActuateError::Refused));
        let khz = a.hw.khz;
        believed_opp_is_the_clocks(&model, &dvfs, khz);
        assert_eq!(a.hw.log, ["v1000000", "d20", "c1200000!", "v900000!"]);
        assert_eq!(a.hw.uv, 1_000_000, "the rail stayed high: safe for the clock that did not move");
        assert_eq!(
            a.take_lag(),
            Some(RailLag { domain: 0, khz: 600_000, last_uv: 1_000_000, want_uv: 900_000, err: ActuateError::Fault(-110) })
        );
    }

    #[test]
    fn a_supply_below_what_the_clock_needs_that_cannot_be_raised_is_not_an_operating_point() {
        let t = table(0);
        // Booted at 1.2 GHz on 950 mV (firmware undervolt: the table says
        // 1.0 V). The request is the same frequency: nothing moves and the
        // rail will not come up, so the answer is no.
        let mut c = Cluster::new(&t, 1_200_000, 950_000);
        c.fail_rail = Some((0, ActuateError::Fault(-110)));
        let mut a = K1Opp::new(&mut c);
        assert!(a.bind(0, t));
        // (The `check` of the fake is for writes; this state is firmware's.)
        assert_eq!(a.set_opp(0, &opp(1_200_000)), Err(ActuateError::Fault(-110)));
        assert_eq!(a.hw.log, ["v1000000!"]);
        assert_eq!(a.take_lag(), None, "nothing moved: a refusal, not a lag");
    }

    #[test]
    fn a_clock_that_will_not_fall_leaves_the_rail_up() {
        let t = table(0);
        let mut c = Cluster::new(&t, 1_200_000, 1_000_000);
        c.fail_clock = Some((0, ActuateError::Refused));
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(600_000))), Err(ActuateError::Refused));
        assert_eq!(c.log, ["c600000!"]);
        assert_eq!((c.khz, c.uv), (1_200_000, 1_000_000));
    }

    #[test]
    fn a_cluster_that_cannot_be_read_back_is_not_touched() {
        let t = table(0);
        let mut c = Cluster::new(&t, 600_000, 900_000);
        c.blind = true;
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(1_200_000))), Err(ActuateError::Fault(-5)));
        assert!(c.log.is_empty());
    }

    #[test]
    fn the_energy_model_and_the_actuator_agree_on_the_frequencies_through_dvfs() {
        // The model lists every enabled OPP of the DT, including the one the
        // actuator dropped for being over the rail: asking for it is a
        // counted refusal, and the others move the cluster.
        let model = from_dt(&energy(), &by_reg).unwrap().unwrap();
        let d0 = &model.domains()[0];
        let khz: Vec<u32> = d0.opps().iter().map(|o| o.freq_khz).collect();
        assert_eq!(khz, [600_000, 800_000, 1_200_000, 1_600_000]);
        let t = table(0);
        let mut c = Cluster::new(&t, 600_000, 900_000);
        let mut dvfs = Dvfs::new();
        dvfs.assume(0, 0);
        let mut a = K1Opp::new(&mut c);
        assert!(a.bind(0, t));
        assert_eq!(dvfs.set(&mut a, &model, 0, 0), Ok(Applied::Unchanged));
        assert_eq!(dvfs.set(&mut a, &model, 0, 2), Ok(Applied::Changed));
        assert_eq!(dvfs.set(&mut a, &model, 0, 3), Err(ActuateError::Refused));
        assert_eq!((dvfs.changed(), dvfs.refused(), dvfs.current(0)), (1, 1, Some(2)));
        drop(a);
        assert_eq!((c.khz, c.uv), (1_200_000, 1_000_000));
    }

    #[test]
    fn two_clusters_have_their_own_tables() {
        struct Two([Cluster; 2]);
        impl K1Hw for Two {
            fn cpu_khz(&mut self, d: usize) -> Result<u32, ActuateError> { (&mut self.0[d]).cpu_khz(0) }
            fn set_cpu_khz(&mut self, d: usize, k: u32) -> Result<(), ActuateError> { (&mut self.0[d]).set_cpu_khz(0, k) }
            fn voltage_uv(&mut self, d: usize) -> Result<u32, ActuateError> { (&mut self.0[d]).voltage_uv(0) }
            fn set_voltage_uv(&mut self, d: usize, uv: u32) -> Result<(), ActuateError> { (&mut self.0[d]).set_voltage_uv(0, uv) }
            fn round_khz(&mut self, d: usize, k: u32) -> Result<u32, ActuateError> { (&mut self.0[d]).round_khz(0, k) }
            fn rail_of(&self, d: usize) -> Option<u8> { Some(d as u8) }
            fn delay_us(&mut self, us: u32) { (&mut self.0[0]).delay_us(us); (&mut self.0[1]).delay_us(us); }
        }
        let (t0, t1) = (table(0), table(1));
        let mut a = K1Opp::new(Two([Cluster::new(&t0, 600_000, 900_000), Cluster::new(&t1, 600_000, 900_000)]));
        assert!(a.bind(0, t0) && a.bind(1, t1));
        assert_eq!(a.set_opp(1, &opp(1_200_000)), Ok(()));
        // 800 MHz is cluster 0's OPP and not cluster 1's.
        assert_eq!(a.set_opp(1, &opp(800_000)), Err(ActuateError::Refused));
        assert_eq!(a.set_opp(0, &opp(800_000)), Ok(()));
        assert_eq!((a.hw.0[0].khz, a.hw.0[0].uv), (800_000, 950_000));
        assert_eq!((a.hw.0[1].khz, a.hw.0[1].uv), (1_200_000, 1_000_000));
    }
    // ---- the clock makes more than was asked ----

    #[test]
    fn a_clock_that_lands_above_the_row_is_given_the_voltage_of_the_row_above() {
        let t = table(0);
        // 800 MHz asked, 900 MHz made: 900 MHz is between the 800 MHz row
        // (950 mV) and the 1.2 GHz row (1000 mV) and needs the latter.
        let mut c = Cluster::new(&t, 600_000, 900_000);
        c.quantum = 300_000;
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(800_000))), Ok(()));
        assert_eq!(c.log, ["v1000000", "d20", "c800000"]);
        assert_eq!((c.khz, c.uv), (900_000, 1_000_000));
    }

    #[test]
    fn the_same_request_again_is_the_same_operating_point() {
        let t = table(0);
        let mut c = Cluster::new(&t, 600_000, 900_000);
        c.quantum = 300_000;
        let mut a = K1Opp::new(&mut c);
        assert!(a.bind(0, t));
        assert_eq!(a.set_opp(0, &opp(800_000)), Ok(()));
        let writes = (a.hw.log.len(), a.hw.clock_writes, a.hw.rail_writes);
        // 900 MHz is what the cluster runs; 800 MHz asks for it again.
        assert_eq!(a.set_opp(0, &opp(800_000)), Ok(()));
        assert_eq!((a.hw.log.len(), a.hw.clock_writes, a.hw.rail_writes), writes, "{:?}", a.hw.log);
    }

    #[test]
    fn a_clock_that_would_land_above_the_fastest_row_is_refused_with_nothing_written() {
        let t = table(0);
        let mut c = Cluster::new(&t, 600_000, 900_000);
        c.quantum = 500_000;
        // 1.2 GHz is a row; the clock would make 1.5 GHz, which no row carries.
        assert_eq!(with(&mut c, t, |a| a.set_opp(0, &opp(1_200_000))), Err(ActuateError::Refused));
        assert!(c.log.is_empty(), "{:?}", c.log);
    }

    // ---- a rail the clusters share ----

    /// Two clusters, each with its own clock and a rail by number: the same
    /// number is one buck. The rule is the hardware's: a rail carries every
    /// cluster on it.
    struct Pair {
        khz: [u32; 2],
        rail: [u8; 2],
        /// Volts per rail number (two rails).
        uv: [u32; 2],
        need: [Vec<(u32, u32)>; 2],
        log: Vec<String>,
        /// Reading cluster 1's clock fails.
        blind1: bool,
    }

    impl Pair {
        fn new(tables: &[K1Table; 2], khz: [u32; 2], rail: [u8; 2], uv: [u32; 2]) -> Self {
            Pair { khz, rail, uv, need: [rows(&tables[0]), rows(&tables[1])], log: vec![], blind1: false }
        }
        fn needs(&self, d: usize) -> u32 {
            self.need[d].iter().find(|r| r.0 >= self.khz[d]).or(self.need[d].last()).map_or(0, |r| r.1)
        }
        fn check(&self) {
            for d in 0..2 {
                assert!(self.uv[self.rail[d] as usize] >= self.needs(d), "cluster {d}: {:?}", self.log);
            }
        }
    }

    impl K1Hw for Pair {
        fn cpu_khz(&mut self, d: usize) -> Result<u32, ActuateError> {
            if d == 1 && self.blind1 { Err(ActuateError::Fault(-5)) } else { Ok(self.khz[d]) }
        }
        fn set_cpu_khz(&mut self, d: usize, khz: u32) -> Result<(), ActuateError> {
            self.log.push(format!("c{d}:{khz}"));
            self.khz[d] = khz;
            self.check();
            Ok(())
        }
        fn round_khz(&mut self, _: usize, khz: u32) -> Result<u32, ActuateError> {
            Ok(khz)
        }
        fn rail_of(&self, d: usize) -> Option<u8> {
            Some(self.rail[d])
        }
        fn voltage_uv(&mut self, d: usize) -> Result<u32, ActuateError> {
            Ok(self.uv[self.rail[d] as usize])
        }
        fn set_voltage_uv(&mut self, d: usize, uv: u32) -> Result<(), ActuateError> {
            self.log.push(format!("v{uv}"));
            self.uv[self.rail[d] as usize] = uv;
            self.check();
            Ok(())
        }
        fn delay_us(&mut self, _: u32) {}
    }

    fn pair_tables() -> [K1Table; 2] {
        [table(0), table(0)]
    }

    fn pair_opp(hw: Pair, bound: [bool; 2]) -> K1Opp<Pair> {
        let t = pair_tables();
        let mut a = K1Opp::new(hw);
        for d in 0..2 {
            if bound[d] {
                assert!(a.bind(d, t[d]));
            }
        }
        a
    }

    #[test]
    fn a_cluster_going_down_does_not_take_the_rail_from_the_cluster_still_on_it() {
        // Both on one buck; cluster 1 runs 1.2 GHz (1.0 V), cluster 0 too.
        let hw = Pair::new(&pair_tables(), [1_200_000, 1_200_000], [0, 0], [1_000_000, 0]);
        let mut a = pair_opp(hw, [true, true]);
        assert_eq!(a.set_opp(0, &opp(600_000)), Ok(()));
        assert_eq!(a.hw.log, ["c0:600000"], "the clock falls, the rail stays for cluster 1");
        a.hw.log.clear();
        // Cluster 1 falls: now nobody needs 1.0 V.
        assert_eq!(a.set_opp(1, &opp(600_000)), Ok(()));
        assert_eq!(a.hw.log, ["c1:600000", "v900000"]);
        a.hw.log.clear();
        // Cluster 0 back up: the rail first, the clock after.
        assert_eq!(a.set_opp(0, &opp(1_200_000)), Ok(()));
        assert_eq!(a.hw.log, ["v1000000", "c0:1200000"]);
        a.hw.log.clear();
        // Cluster 1 up while cluster 0 holds 1.2 GHz: the rail is enough as it is.
        assert_eq!(a.set_opp(1, &opp(1_200_000)), Ok(()));
        assert_eq!(a.hw.log, ["c1:1200000"]);
    }

    #[test]
    fn separate_rails_do_not_hold_each_other() {
        let hw = Pair::new(&pair_tables(), [1_200_000, 1_200_000], [0, 1], [1_000_000, 1_000_000]);
        let mut a = pair_opp(hw, [true, true]);
        assert_eq!(a.set_opp(0, &opp(600_000)), Ok(()));
        assert_eq!(a.hw.log, ["c0:600000", "v900000"]);
        assert_eq!(a.hw.uv, [900_000, 1_000_000]);
    }

    #[test]
    fn a_cluster_going_down_leaves_the_rail_at_the_other_clusters_need_not_its_own() {
        // Firmware left the buck at 1.05 V, cluster 1 runs 800 MHz (950 mV),
        // cluster 0 falls from 1.2 GHz to 600 MHz (900 mV): the rail goes to
        // 950 mV, what cluster 1 needs, not to cluster 0's 900 mV.
        let hw = Pair::new(&pair_tables(), [1_200_000, 800_000], [0, 0], [1_050_000, 0]);
        let mut a = pair_opp(hw, [true, true]);
        assert_eq!(a.set_opp(0, &opp(600_000)), Ok(()));
        assert_eq!(a.hw.log, ["c0:600000", "v950000"]);
        assert_eq!(a.hw.uv[0], 950_000);
    }

    #[test]
    fn a_cluster_going_up_raises_a_rail_that_is_below_what_the_other_one_needs() {
        // Cluster 1 runs 1.2 GHz on a rail firmware left at 950 mV (the table
        // says 1.0 V). Cluster 0 climbs 600 -> 800 MHz, which alone needs
        // 950 mV: the rail is raised to cluster 1's 1.0 V first, then the clock.
        let hw = Pair::new(&pair_tables(), [600_000, 1_200_000], [0, 0], [950_000, 0]);
        let mut a = pair_opp(hw, [true, true]);
        assert_eq!(a.set_opp(0, &opp(800_000)), Ok(()));
        assert_eq!(a.hw.log, ["v1000000", "c0:800000"]);
    }

    #[test]
    fn a_cluster_nothing_is_known_about_holds_the_rail_where_it_is() {
        // Cluster 1 is not bound: the rail is not lowered under it.
        let hw = Pair::new(&pair_tables(), [1_200_000, 1_200_000], [0, 0], [1_000_000, 0]);
        let mut a = pair_opp(hw, [true, false]);
        assert_eq!(a.set_opp(0, &opp(600_000)), Ok(()));
        assert_eq!(a.hw.log, ["c0:600000"]);
        // Cluster 1 runs faster than any row: same.
        let hw = Pair::new(&pair_tables(), [1_200_000, 1_500_000], [0, 0], [1_000_000, 0]);
        let mut a = pair_opp(hw, [true, true]);
        assert_eq!(a.set_opp(0, &opp(600_000)), Ok(()));
        assert_eq!(a.hw.log, ["c0:600000"]);
        assert_eq!(a.hw.uv[0], 1_000_000);
    }

    #[test]
    fn a_cluster_that_cannot_be_read_stops_the_move_before_any_write() {
        let mut hw = Pair::new(&pair_tables(), [1_200_000, 1_200_000], [0, 0], [1_000_000, 0]);
        hw.blind1 = true;
        let mut a = pair_opp(hw, [true, true]);
        assert_eq!(a.set_opp(0, &opp(600_000)), Err(ActuateError::Fault(-5)));
        assert!(a.hw.log.is_empty());
    }
}

#[cfg(test)]
mod k1_tsensor {
    //! The K1 `TSEN` block (`drivers/thermal/spacemit/k1_tsensor.c` of Linux
    //! v7.3): the init sequence, the per-channel half-word, the offset.
    use azos_dtb::{dtb_thermal, DtThermal};
    use azos_thermal::dt::build;
    use azos_thermal::k1::*;
    use azos_thermal::sensor::{SensorBank, SensorError};
    use std::collections::HashMap;

    #[derive(Default)]
    struct Regs {
        r: HashMap<usize, u32>,
        writes: Vec<(usize, u32)>,
    }

    impl K1TsensorBus for &mut Regs {
        fn read32(&mut self, off: usize) -> u32 {
            self.r.get(&off).copied().unwrap_or(0)
        }
        fn write32(&mut self, off: usize, v: u32) {
            self.writes.push((off, v));
            self.r.insert(off, v);
        }
    }

    /// A block that has been started with channel data written.
    fn running(data: &[(usize, u32)]) -> Regs {
        let mut r = Regs::default();
        K1Tsensor::new(&mut r).start().unwrap();
        for &(o, v) in data {
            r.r.insert(o, v);
        }
        r
    }

    #[test]
    fn start_follows_the_linux_init_order_and_values() {
        let mut r = Regs::default();
        // Bits the init must keep or clear: CTUNE and SW_CTRL set, a stray bit 30 kept.
        r.r.insert(0x00, (0xf << 8) | (0xf << 18) | (1 << 30));
        r.r.insert(0x0c, 0xff00_0000 | 0x00ff_ffff);
        r.r.insert(0x08, 1 << 9);
        assert_eq!(K1Tsensor::new(&mut r).start(), Ok(()));
        assert_eq!(
            r.writes,
            [
                // Interrupts masked.
                (0x14, 0xffff_ffff),
                // TIME: [23:0] replaced by FILTER_PERIOD[21:20] | ADC_CNT_RST[7:4] | WAIT_REF_CNT[3:0].
                (0x0c, 0xff00_0000 | 0x0030_00ff),
                // PCTRL: SW_CTRL and CTUNE cleared; RAW_SEL, TEMP_MODE, HW_AUTO_MODE, ENABLE set.
                (0x00, (1 << 30) | (1 << 7) | (1 << 3) | (1 << 23) | 1),
                // EN: the five sensors, the other bits kept.
                (0x08, (1 << 9) | 0x1f),
            ]
        );
    }

    #[test]
    fn each_channel_is_a_half_word_and_the_reading_is_degrees_plus_278() {
        // Channels 0/1 share 0x20, 2/3 share 0x24, 4 is alone at 0x28.
        let mut r = running(&[(0x20, (300 << 16) | 350), (0x24, (400 << 16) | 278 + 85), (0x28, 500)]);
        let mut s = K1Tsensor::new(&mut r);
        assert_eq!(s.read_mdeg(0), Ok((350 - 278) * 1000));
        assert_eq!(s.read_mdeg(1), Ok((300 - 278) * 1000));
        assert_eq!(s.read_mdeg(2), Ok(85_000));
        assert_eq!(s.read_mdeg(3), Ok((400 - 278) * 1000));
        assert_eq!(s.read_mdeg(4), Ok((500 - 278) * 1000));
        // Below the offset is a negative temperature, not a wrap.
        let mut r = running(&[(0x20, 200)]);
        assert_eq!(K1Tsensor::new(&mut r).read_mdeg(0), Ok(-78_000));
        // No such sensor.
        assert_eq!(s.read_mdeg(5), Err(SensorError::Absent));
    }

    #[test]
    fn a_block_that_is_not_converting_is_invalid_not_zero_degrees() {
        // Not started: control and enable clear.
        let mut idle = Regs::default();
        idle.r.insert(0x20, 350);
        assert_eq!(K1Tsensor::new(&mut idle).read_mdeg(0), Err(SensorError::Invalid));
        // Started, no conversion landed yet.
        let mut r = running(&[(0x20, 0)]);
        assert_eq!(K1Tsensor::new(&mut r).read_mdeg(0), Err(SensorError::Invalid));
        // A half-word of all ones is not a temperature.
        let mut r = running(&[(0x20, 0xffff_ffff)]);
        let mut s = K1Tsensor::new(&mut r);
        assert_eq!(s.read_mdeg(0), Err(SensorError::Invalid));
        assert_eq!(s.read_mdeg(1), Err(SensorError::Invalid));
        // One sensor disabled in EN is invalid, the others are not.
        let mut r = running(&[(0x20, (300 << 16) | 350), (0x08, 0x1f & !(1 << 1))]);
        let mut s = K1Tsensor::new(&mut r);
        assert_eq!(s.read_mdeg(1), Err(SensorError::Invalid));
        assert_eq!(s.read_mdeg(0), Ok(72_000));
    }

    /// A window that answers and keeps nothing it is given: a block held in
    /// reset reads zeros (or whatever it reads), writes are dropped.
    struct Deaf {
        read: u32,
        writes: Vec<(usize, u32)>,
    }

    impl K1TsensorBus for &mut Deaf {
        fn read32(&mut self, _: usize) -> u32 {
            self.read
        }
        fn write32(&mut self, off: usize, v: u32) {
            self.writes.push((off, v));
        }
    }

    #[test]
    fn a_window_with_nothing_behind_it_is_refused_before_anything_is_written() {
        // All ones: what a window with no device answers.
        let mut w = Deaf { read: 0xffff_ffff, writes: vec![] };
        assert_eq!(K1Tsensor::new(&mut w).start(), Err(StartError::NoWindow));
        assert!(w.writes.is_empty(), "{:?}", w.writes);
    }

    #[test]
    fn a_block_that_does_not_keep_the_writes_is_refused() {
        // Held in reset: reads zeros, writes are dropped.
        let mut w = Deaf { read: 0, writes: vec![] };
        assert_eq!(K1Tsensor::new(&mut w).start(), Err(StartError::NotHeld));
        // The registers were written (the refusal comes after), and the
        // block is not reported as converting.
        assert!(!w.writes.is_empty());
    }

    /// A block that drops the writes to one register and keeps the rest.
    struct Drops(Regs, usize);

    impl K1TsensorBus for &mut Drops {
        fn read32(&mut self, off: usize) -> u32 {
            (&mut self.0).read32(off)
        }
        fn write32(&mut self, off: usize, v: u32) {
            if off != self.1 {
                (&mut self.0).write32(off, v);
            }
        }
    }

    #[test]
    fn a_block_that_keeps_one_of_the_two_checked_registers_but_not_the_other_is_refused() {
        // Each register is checked on its own: with the control word dropped
        // the enables alone would pass, and the other way round.
        for dropped in [0x00, 0x08] {
            let mut h = Drops(Regs::default(), dropped);
            assert_eq!(K1Tsensor::new(&mut h).start(), Err(StartError::NotHeld), "register {dropped:#x} dropped");
        }
        // A register the check does not read may be dropped without refusal.
        let mut h = Drops(Regs::default(), 0x0c);
        assert_eq!(K1Tsensor::new(&mut h).start(), Ok(()));
    }

    #[test]
    fn the_jupiter_zones_resolve_to_the_five_sensors_by_their_cell() {
        let p = format!("{}/../soc-tests/fixtures/k1-jupiter.dtb", env!("CARGO_MANIFEST_DIR"));
        let mut blob = std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
        blob.extend_from_slice(&[0; 8]);
        let dt: DtThermal = unsafe { dtb_thermal(blob.as_ptr()) }.expect("readable blob");
        assert_eq!(dt.zones().len(), 5);
        let model = azos_energy::model::EnergyModel::from_source(azos_energy::model::ModelSource::Topology);
        // The board's resolver: `thermal-sensors = <&thermal N>` is channel N.
        let built = build(&dt, &model, |_, cell| u8::try_from(cell).ok().filter(|&c| c < K1_SENSORS));
        assert_eq!(built.zones_dropped, 0);
        let z = built.thermal.zones();
        let sensors: Vec<u8> = z.iter().map(|z| z.sensor).collect();
        assert_eq!(sensors, [0, 1, 2, 3, 4]);
        // soc and package have only the 115 C critical trip; the other three also a passive one at 85 C.
        let trips: Vec<usize> = z.iter().map(|z| z.trips().len()).collect();
        assert_eq!(trips, [1, 1, 2, 2, 2]);
    }

    #[test]
    fn the_k1_runtime_keeps_all_five_zones_and_knows_where_each_cluster_boots() {
        use azos_dtb::dtb_energy;
        let p = format!("{}/../soc-tests/fixtures/k1-jupiter.dtb", env!("CARGO_MANIFEST_DIR"));
        let mut blob = std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
        blob.extend_from_slice(&[0; 8]);
        let dt: DtThermal = unsafe { dtb_thermal(blob.as_ptr()) }.expect("readable blob");
        let energy = unsafe { dtb_energy(blob.as_ptr()) }.expect("readable blob");
        let model = azos_energy::dt::from_dt(&energy, &crate::by_reg).unwrap().unwrap();
        assert_eq!(model.domains().len(), 2);
        // Cluster 0 booted at 1.6 GHz, cluster 1 at 819 MHz (the OPP table has 819.0 MHz).
        let (rt, report) = runtime_from_dt(&dt, &model, |d| Some(if d == 0 { 1_600_000 } else { 819_000 }));
        assert_eq!((report.zones, report.zones_dropped), (5, 0), "{report:?}");
        assert_eq!((rt.dvfs.current(0), rt.dvfs.current(1)), (Some(4), Some(1)));
        // The one-sensor rule of the other boards keeps the zone on cell 0
        // and drops the four channels it cannot name.
        let (one, r1) = azos_thermal::runtime::Runtime::from_dt(&dt, &model, |_| None);
        assert_eq!((r1.zones, r1.zones_dropped), (1, 4));
        assert_eq!(one.thermal.zones().len(), 1);
        // The channel of a cell, and nothing past the five.
        assert_eq!((sensor_of(1, 0), sensor_of(7, 4), sensor_of(1, 5), sensor_of(1, u32::MAX)), (Some(0), Some(4), None, None));
    }
}

/// The `thermal-smoke` gate row's ramp, on the host: the fixture zone and the
/// fake board over the balanced two-domain model the QEMU row boots with.
#[cfg(all(test, feature = "fake"))]
mod fake_board {
    use azos_energy::model::{EnergyModel, ModelSource, Opp, PerfDomain};
    use azos_energy::thermal::{Event, LEVEL_CAUTIOUS, LEVEL_SLOW};
    use azos_thermal::fake::{fixture, FakeBoard, HOT_MDEG, PASSIVE_MDEG, POLL_MS};
    use azos_thermal::runtime::{Inputs, Runtime};
    use core::sync::atomic::{AtomicI32, Ordering};

    static TEMP: AtomicI32 = AtomicI32::new(40_000);
    fn temp() -> i32 {
        TEMP.load(Ordering::Relaxed)
    }

    /// `FAKE_ENERGY_MODEL` in `balanced` mode (crates/core/topology builder).
    fn model() -> EnergyModel {
        let mut m = EnergyModel::from_source(ModelSource::Topology);
        for (cpus, wcet, opps) in [
            (0b01, 800_000, &[(400_000, 160, 30), (800_000, 320, 90), (1_200_000, 480, 190)][..]),
            (0b10, 1_000_000, &[(500_000, 256, 120), (1_000_000, 512, 300), (1_500_000, 768, 600), (2_000_000, 1024, 1100)][..]),
        ] {
            let mut d = PerfDomain::new(cpus);
            d.wcet_ref_khz = wcet;
            for &(f, c, p) in opps {
                d.push_opp(Opp { freq_khz: f, capacity: c, power_mw: p }).unwrap();
            }
            m.push_domain(d).unwrap();
        }
        m
    }

    #[test]
    fn a_ramp_throttles_to_the_floor_degrades_and_gives_the_clocks_back() {
        let m = model();
        let mut rt = Runtime::new(fixture(&m));
        rt.assume_boot(&m, |d| Some(m.domains()[d].opps().last().unwrap().freq_khz));
        let mut hw = FakeBoard::new(temp);
        // A busy machine: the governor asks for the top OPP of both domains.
        let mut inp = Inputs::IDLE;
        inp.want = [Some(2), Some(3), None, None, None, None, None, None][..azos_energy::model::MAX_DOMAINS].try_into().unwrap();
        let mut now = 0u64;
        let mut step = |rt: &mut Runtime, hw: &mut FakeBoard, mdeg: i32, n: u32| {
            TEMP.store(mdeg, Ordering::Relaxed);
            let mut s = rt.last();
            for _ in 0..n {
                now += POLL_MS as u64;
                s = rt.tick(hw, &m, now, &inp);
            }
            s
        };

        // Cool: the governor's request reaches the clock (nothing was set
        // yet, the runtime knew the boot OPP, so nothing moves).
        let s = step(&mut rt, &mut hw, 40_000, 3);
        assert_eq!((s.level, hw.sets, hw.khz), (0, 0, [0; azos_energy::model::MAX_DOMAINS]));

        // Passive: both domains step down to their floors and no further.
        let s = step(&mut rt, &mut hw, PASSIVE_MDEG + 5_000, 6);
        assert_eq!(&hw.khz[..2], &[800_000, 1_000_000]);
        assert_eq!(s.level, LEVEL_CAUTIOUS, "the floors hold the clocks up: cautious");

        // Hot: the level rises to slow, the clocks stay at the floors.
        let s = step(&mut rt, &mut hw, HOT_MDEG + 1_000, 2);
        assert_eq!((s.level, s.shutdown), (LEVEL_SLOW, false));
        assert_eq!(&hw.khz[..2], &[800_000, 1_000_000]);

        // Cool again: the level falls and the clocks come back to the top.
        let s = step(&mut rt, &mut hw, 40_000, 12);
        assert_eq!((s.level, rt.thermal.level()), (0, 0));
        assert_eq!(&hw.khz[..2], &[1_200_000, 2_000_000]);

        // The ring told the whole story.
        let events: Vec<(Event, u8)> =
            (0..rt.thermal.logged() as usize).rev().filter_map(|i| rt.thermal.record(i)).map(|r| (r.event, r.arg)).collect();
        for e in [(Event::TripUp, 0), (Event::Uncooled, 0), (Event::Level, LEVEL_SLOW), (Event::TripDown, 0), (Event::Cooled, 0), (Event::Level, 0)] {
            assert!(events.contains(&e), "{e:?} missing from {events:?}");
        }
    }
}

#[cfg(test)]
mod x86_sensor {
    //! The x86_64 package sensor: the CPUID probe that decides before any MSR
    //! is read (a fake MSR bus panics on an MSR the machine does not have, as
    //! the CPU would raise #GP), the Intel and AMD arithmetic, the SMN
    //! protocol, the QEMU fallback, and the board object under the runtime.
    use super::model;
    use super::thermal::{zone, PASSIVE};
    use azos_energy::opp::NoActuator;
    use azos_energy::thermal::{Thermal, LEVEL_CAUTIOUS};
    use azos_thermal::runtime::{Inputs, Runtime};
    use azos_thermal::sensor::{SensorBank, SensorError};
    use azos_thermal::x86_sensor::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const THERM_STATUS: u32 = 0x19c;
    const TEMP_TARGET: u32 = 0x1a2;
    const PKG_THERM_STATUS: u32 = 0x1b1;

    /// MSRs that exist; any other read is the #GP the probe must prevent.
    #[derive(Default)]
    struct Msrs {
        has: HashMap<u32, u64>,
        reads: Vec<u32>,
    }
    struct M<'a>(&'a RefCell<Msrs>);
    impl MsrBus for M<'_> {
        fn rdmsr(&mut self, msr: u32) -> u64 {
            let mut m = self.0.borrow_mut();
            m.reads.push(msr);
            *m.has.get(&msr).unwrap_or_else(|| panic!("#GP: rdmsr {msr:#x} on a CPU without it"))
        }
    }

    /// A root complex at 00:00.0 with an SMN window. `log` has one entry per
    /// `smn_read`: the whole index-then-data transaction is one call, which is
    /// what lets the board hold its lock across it.
    struct RootState {
        vendor: u16,
        smn: HashMap<u32, u32>,
        log: Vec<(u32, u32)>,
    }
    fn new_root(vendor: u16) -> RefCell<RootState> {
        RefCell::new(RootState { vendor, smn: HashMap::new(), log: vec![] })
    }
    struct Cfg<'a>(&'a RefCell<RootState>);
    impl RootComplex for Cfg<'_> {
        fn vendor_id(&self) -> u16 {
            self.0.borrow().vendor
        }
        fn smn_read(&mut self, addr: u32) -> u32 {
            let mut r = self.0.borrow_mut();
            let v = r.smn.get(&addr).copied().unwrap_or(u32::MAX);
            r.log.push((addr, v));
            v
        }
    }

    const NO_ROOT: u16 = 0xffff;

    fn brand(s: &str) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[..s.len()].copy_from_slice(s.as_bytes());
        b
    }

    fn intel(model: u16, l6_eax: u32) -> X86Cpu {
        X86Cpu { vendor: Vendor::Intel, family: 6, model, hypervisor: false, max_basic_leaf: 0x16, l6_eax, brand: [0; 48] }
    }
    fn amd(family: u16, name: &str) -> X86Cpu {
        X86Cpu { vendor: Vendor::Amd, family, model: 0x21, hypervisor: false, max_basic_leaf: 0x10, l6_eax: 0, brand: brand(name) }
    }

    fn status(valid: bool, below: u64) -> u64 {
        (u64::from(valid) << 31) | (below << 16)
    }
    fn target(tjmax_c: u64) -> u64 {
        tjmax_c << 16
    }

    #[test]
    fn a_hypervisor_is_refused_before_any_register_is_touched() {
        // QEMU TCG: GenuineIntel or AuthenticAMD, hypervisor bit set, no DTS.
        let msrs = RefCell::new(Msrs::default());
        for vendor in [Vendor::Intel, Vendor::Amd] {
            let cpu = X86Cpu { hypervisor: true, vendor, family: 6, l6_eax: 0x5, ..intel(0x3a, 0x5) };
            let root = new_root(PCI_AMD);
            assert_eq!(probe(&cpu, &mut M(&msrs), &Cfg(&root)), Err(Refused::Hypervisor));
        }
        assert!(msrs.borrow().reads.is_empty());
        assert!(Refused::Hypervisor.name().contains("hypervisor"));
    }

    const PCI_AMD: u16 = 0x1022;

    #[test]
    fn intel_needs_the_thermal_sensor_and_a_model_with_a_temperature_target() {
        let msrs = RefCell::new(Msrs::default());
        let root = new_root(NO_ROOT);
        // No DTS: nothing is read.
        assert_eq!(probe(&intel(0x3a, 0), &mut M(&msrs), &Cfg(&root)), Err(Refused::NoDts));
        // A CPU without a leaf 6.
        let mut c = intel(0x3a, 1);
        c.max_basic_leaf = 4;
        assert_eq!(probe(&c, &mut M(&msrs), &Cfg(&root)), Err(Refused::NoDts));
        // Models before Nehalem and the first Atoms: no MSR_TEMPERATURE_TARGET.
        for model in [0x0f, 0x17, 0x1c, 0x26, 0x36] {
            assert_eq!(probe(&intel(model, 1), &mut M(&msrs), &Cfg(&root)), Err(Refused::Model), "model {model:#x}");
        }
        assert!(msrs.borrow().reads.is_empty());
        // A later Atom (Silvermont) and a big core have it.
        for model in [0x37, 0x1a, 0x9a] {
            msrs.borrow_mut().has.insert(TEMP_TARGET, target(100));
            assert!(probe(&intel(model, 1), &mut M(&msrs), &Cfg(&root)).is_ok(), "model {model:#x}");
        }
        // A family above 6 has it too.
        let mut c = intel(0, 1);
        c.family = 0x12;
        assert!(probe(&c, &mut M(&msrs), &Cfg(&root)).is_ok());
        assert!(msrs.borrow().reads.iter().all(|&m| m == TEMP_TARGET));
    }

    #[test]
    fn tjmax_comes_from_the_target_register_with_linuxs_fallback_and_a_sanity_range() {
        let msrs = RefCell::new(Msrs::default());
        let root = new_root(NO_ROOT);
        let kind = |t: u64| {
            msrs.borrow_mut().has.insert(TEMP_TARGET, target(t) | 0x3f00_0000 /* target offset field: not TjMax */);
            probe(&intel(0x3a, 1), &mut M(&msrs), &Cfg(&root))
        };
        assert_eq!(kind(105), Ok(Kind::Intel { package: false, tjmax_mdeg: 105_000 }));
        assert_eq!(kind(0), Ok(Kind::Intel { package: false, tjmax_mdeg: 100_000 }));
        assert_eq!(kind(255), Err(Refused::Model));
        assert_eq!(kind(20), Err(Refused::Model));
    }

    #[test]
    fn intel_reads_the_package_register_when_there_is_one_else_the_core() {
        // Package thermal status: only IA32_PACKAGE_THERM_STATUS exists here.
        let msrs = RefCell::new(Msrs::default());
        let root = new_root(NO_ROOT);
        msrs.borrow_mut().has.insert(TEMP_TARGET, target(100));
        let cpu = intel(0x3a, 1 | (1 << 6));
        let kind = probe(&cpu, &mut M(&msrs), &Cfg(&root)).unwrap();
        assert_eq!(kind, Kind::Intel { package: true, tjmax_mdeg: 100_000 });
        msrs.borrow_mut().has.insert(PKG_THERM_STATUS, status(true, 35));
        let mut s = X86Sensor::new(kind, M(&msrs), Cfg(&root));
        assert_eq!(s.read_mdeg(0), Ok(65_000));

        // No package status: this core's.
        let msrs = RefCell::new(Msrs::default());
        msrs.borrow_mut().has.insert(TEMP_TARGET, target(100));
        let kind = probe(&intel(0x3a, 1), &mut M(&msrs), &Cfg(&root)).unwrap();
        msrs.borrow_mut().has.insert(THERM_STATUS, status(true, 0));
        let mut s = X86Sensor::new(kind, M(&msrs), Cfg(&root));
        assert_eq!(s.read_mdeg(0), Ok(100_000));
        msrs.borrow_mut().has.insert(THERM_STATUS, status(true, 0x7f));
        assert_eq!(s.read_mdeg(0), Ok(100_000 - 127_000));
    }

    #[test]
    fn an_intel_reading_the_part_flags_invalid_is_not_a_temperature() {
        let msrs = RefCell::new(Msrs::default());
        let root = new_root(NO_ROOT);
        msrs.borrow_mut().has.insert(THERM_STATUS, status(false, 20));
        let mut s = X86Sensor::new(Kind::Intel { package: false, tjmax_mdeg: 100_000 }, M(&msrs), Cfg(&root));
        assert_eq!(s.read_mdeg(0), Err(SensorError::Invalid));
        // The package is the only sensor.
        assert_eq!(s.read_mdeg(1), Err(SensorError::Absent));
    }

    #[test]
    fn amd_needs_a_zen_family_and_the_vendors_root_complex() {
        let msrs = RefCell::new(Msrs::default());
        // Pre-Zen: the temperature lives in a PCI function this module does not read.
        let root = new_root(PCI_AMD);
        assert_eq!(probe(&amd(0x16, ""), &mut M(&msrs), &Cfg(&root)), Err(Refused::Family));
        assert_eq!(probe(&amd(0x15, ""), &mut M(&msrs), &Cfg(&root)), Err(Refused::Family));
        // An Intel (or no) root complex: no SMN to index.
        let other = new_root(0x8086);
        assert_eq!(probe(&amd(0x19, ""), &mut M(&msrs), &Cfg(&other)), Err(Refused::NoRoot));
        let none = new_root(NO_ROOT);
        assert_eq!(probe(&amd(0x19, ""), &mut M(&msrs), &Cfg(&none)), Err(Refused::NoRoot));
        for f in [0x17, 0x19, 0x1a] {
            assert_eq!(probe(&amd(f, ""), &mut M(&msrs), &Cfg(&root)), Ok(Kind::Smn { tctl_offset_mdeg: 0 }), "family {f:#x}");
        }
        // Hygon's Zen derivative answers with Hygon's id, not AMD's.
        let mut hygon = X86Cpu { vendor: Vendor::Hygon, ..amd(0x18, "") };
        assert_eq!(probe(&hygon, &mut M(&msrs), &Cfg(&root)), Err(Refused::NoRoot));
        let hroot = new_root(0x1d94);
        assert!(probe(&hygon, &mut M(&msrs), &Cfg(&hroot)).is_ok());
        hygon.vendor = Vendor::Other;
        assert_eq!(probe(&hygon, &mut M(&msrs), &Cfg(&hroot)), Err(Refused::Vendor));
        assert!(msrs.borrow().reads.is_empty(), "AMD reads no MSR");
    }

    #[test]
    fn tctl_offsets_follow_the_family_17h_parts_that_have_one() {
        assert_eq!(tctl_offset_mdeg(0x17, b"AMD Ryzen 7 1700X Eight-Core Processor"), 20_000);
        assert_eq!(tctl_offset_mdeg(0x17, b"  AMD Ryzen 5 1600X Six-Core Processor"), 20_000);
        assert_eq!(tctl_offset_mdeg(0x17, b"AMD Ryzen 7 1800X Eight-Core Processor"), 20_000);
        assert_eq!(tctl_offset_mdeg(0x17, b"AMD Ryzen 7 2700X Eight-Core Processor"), 10_000);
        assert_eq!(tctl_offset_mdeg(0x17, b"AMD Ryzen Threadripper 1950X 16-Core Processor"), 27_000);
        assert_eq!(tctl_offset_mdeg(0x17, b"AMD Ryzen Threadripper 2990WX 32-Core Processor"), 27_000);
        // The same names without the X, other 17h parts, and other families: none.
        assert_eq!(tctl_offset_mdeg(0x17, b"AMD Ryzen 7 1700 Eight-Core Processor"), 0);
        assert_eq!(tctl_offset_mdeg(0x17, b"AMD Ryzen 7 3700X 8-Core Processor"), 0);
        assert_eq!(tctl_offset_mdeg(0x19, b"AMD Ryzen 7 1700X"), 0);
        assert_eq!(tctl_offset_mdeg(0x17, &[0u8; 48]), 0);
        // The probe carries it into the sensor.
        let msrs = RefCell::new(Msrs::default());
        let root = new_root(PCI_AMD);
        let k = probe(&amd(0x17, "AMD Ryzen 7 2700X Eight-Core Processor"), &mut M(&msrs), &Cfg(&root));
        assert_eq!(k, Ok(Kind::Smn { tctl_offset_mdeg: 10_000 }));
    }

    /// `THM_TCON_CUR_TMP` for `eighths` 0.125 C steps, with or without the
    /// -49 C range select.
    fn thm(eighths: u32, range_sel: bool) -> u32 {
        (eighths << 21) | (u32::from(range_sel) << 19)
    }

    #[test]
    fn amd_reads_tctl_through_one_smn_transaction_minus_the_offset() {
        let msrs = RefCell::new(Msrs::default());
        let root = new_root(PCI_AMD);
        // 441 * 0.125 = 55.125 C.
        root.borrow_mut().smn.insert(0x0005_9800, thm(441, false));
        let mut s = X86Sensor::new(Kind::Smn { tctl_offset_mdeg: 0 }, M(&msrs), Cfg(&root));
        assert_eq!(s.read_mdeg(0), Ok(55_125));
        assert_eq!(s.read_mdeg(2), Err(SensorError::Absent));
        drop(s);
        // One transaction, for the register's SMN address; the index/data
        // pair is the board's, under its lock.
        let log = root.borrow().log.clone();
        assert_eq!(log, [(0x0005_9800, thm(441, false))]);
        assert_eq!((SMN_INDEX, SMN_DATA), (0x60, 0x64));

        // Range select set: the reading is 49 C higher than it says (104.125 - 49).
        root.borrow_mut().smn.insert(0x0005_9800, thm(833, true));
        let mut s = X86Sensor::new(Kind::Smn { tctl_offset_mdeg: 0 }, M(&msrs), Cfg(&root));
        assert_eq!(s.read_mdeg(0), Ok(833 * 125 - 49_000));
        // A part with a 20 C Tctl offset reports the die, not Tctl.
        let mut s = X86Sensor::new(Kind::Smn { tctl_offset_mdeg: 20_000 }, M(&msrs), Cfg(&root));
        assert_eq!(s.read_mdeg(0), Ok(833 * 125 - 49_000 - 20_000));
        assert!(msrs.borrow().reads.is_empty());
    }

    #[test]
    fn an_smn_window_with_nothing_behind_it_is_not_a_temperature() {
        let msrs = RefCell::new(Msrs::default());
        let root = new_root(PCI_AMD);
        let mut s = X86Sensor::new(Kind::Smn { tctl_offset_mdeg: 0 }, M(&msrs), Cfg(&root));
        // Nothing mapped at the SMN address: all ones.
        assert_eq!(s.read_mdeg(0), Err(SensorError::Invalid));
        drop(s);
        root.borrow_mut().smn.insert(0x0005_9800, 0);
        let mut s = X86Sensor::new(Kind::Smn { tctl_offset_mdeg: 0 }, M(&msrs), Cfg(&root));
        assert_eq!(s.read_mdeg(0), Err(SensorError::Invalid));
    }

    #[test]
    fn heat_on_a_board_with_no_actuator_raises_the_level_instead_of_capping_a_clock() {
        // The zone declares a passive trip at 80 C with a cooling map; the
        // pairing actuator is NoActuator (QEMU-class fallback: no HWP/CPPC).
        let m = model(0);
        let mut t = Thermal::new();
        t.push_zone(zone(0, 3, &m)).unwrap();
        let mut rt = Runtime::new(t);

        let msrs = RefCell::new(Msrs::default());
        let root = new_root(NO_ROOT);
        msrs.borrow_mut().has.insert(TEMP_TARGET, target(100));
        let kind = probe(&intel(0x3a, 1 | (1 << 6)), &mut M(&msrs), &Cfg(&root)).unwrap();
        // 95 C: 5 C below TjMax, past the passive trip.
        msrs.borrow_mut().has.insert(PKG_THERM_STATUS, status(true, 5));
        let mut board = X86Board { sensor: X86Sensor::new(kind, M(&msrs), Cfg(&root)), actuator: NoActuator };
        assert_eq!(board.read_mdeg(0), Ok(95_000));
        assert!(95_000 > PASSIVE);
        let mut inp = Inputs::IDLE;
        inp.want[0] = Some(3);
        let s = rt.tick(&mut board, &m, 0, &inp);
        let s = rt.tick(&mut board, &m, 1000, &inp).level.max(s.level);
        assert!(s >= LEVEL_CAUTIOUS, "level {s}");
        assert!(rt.dvfs.refused() > 0);
    }

    #[test]
    fn a_cool_machine_with_no_governor_is_left_alone() {
        // Invariant I4 on the x86 pair: no heat, no governor, no change.
        let m = model(0);
        let mut t = Thermal::new();
        t.push_zone(zone(0, 3, &m)).unwrap();
        let mut rt = Runtime::new(t);
        let msrs = RefCell::new(Msrs::default());
        let root = new_root(NO_ROOT);
        msrs.borrow_mut().has.insert(THERM_STATUS, status(true, 60));
        let mut board = X86Board {
            sensor: X86Sensor::new(Kind::Intel { package: false, tjmax_mdeg: 100_000 }, M(&msrs), Cfg(&root)),
            actuator: NoActuator,
        };
        let s = rt.tick(&mut board, &m, 0, &Inputs::IDLE);
        assert_eq!((s.level, rt.dvfs.refused()), (0, 0));
    }

    // ── the zone source and the CPUID decode the kernel hands the probe ──

    #[test]
    fn the_package_zone_is_what_kconfig_names_and_nothing_else() {
        let m = model(0);
        assert!(package_zone(&m, 85, 100, 100, 1000).is_none(), "hot must be below critical");
        assert!(package_zone(&m, 70, 95, 90, 1000).is_none());
        assert!(package_zone(&m, 85, 85, 100, 1000).is_none(), "passive must be below hot");
        assert!(package_zone(&m, 75, 85, 100, 0).is_none(), "a zero poll would never sleep");
        let dt = package_zone(&m, 75, 85, 100, 1000).unwrap();
        assert_eq!(dt.zones().len(), 1);
        let z = &dt.zones()[0];
        assert_eq!((z.name(), z.poll_ms, z.poll_passive_ms), (&b"package"[..], 1000, 1000));
        assert_ne!(z.sensor, 0, "a zero sensor phandle is dropped by the builder");
        let t: Vec<_> = z.trips().iter().map(|t| (t.temp_mdeg, t.kind)).collect();
        assert_eq!(
            t,
            [(75_000, azos_dtb::DT_TRIP_PASSIVE), (85_000, azos_dtb::DT_TRIP_HOT), (100_000, azos_dtb::DT_TRIP_CRITICAL)]
        );
        // One map, on the passive trip, over the one CPU of the one domain.
        assert_eq!(z.maps().len(), 1);
        assert_eq!(z.maps()[0].trip, z.trips()[0].phandle);
        let (rt, report) = Runtime::from_dt(&dt, &m, |_| None);
        assert_eq!((report.zones_dropped, report.trips_dropped, report.coolers_dropped), (0, 0, 0));
        let maps = rt.thermal.zones()[0].maps();
        assert_eq!((maps.len(), maps[0].trip, maps[0].domain, maps[0].max_state), (1, 0, 0, 3), "capped down to the deepest OPP");
    }

    #[test]
    fn the_package_zone_reaches_the_runtime_and_heat_walks_it_to_a_shutdown() {
        use azos_energy::thermal::{LEVEL_CONTAINED, LEVEL_SLOW};
        let m = model(0);
        let dt = package_zone(&m, 75, 85, 100, 1000).unwrap();
        let (mut rt, report) = Runtime::from_dt(&dt, &m, |_| None);
        assert_eq!((report.zones, report.zones_dropped, report.trips_dropped), (1, 0, 0));
        assert_eq!(rt.poll_interval_ms(), Some(1000));

        let msrs = RefCell::new(Msrs::default());
        let root = new_root(NO_ROOT);
        msrs.borrow_mut().has.insert(THERM_STATUS, status(true, 40));
        let mut board = X86Board {
            sensor: X86Sensor::new(Kind::Intel { package: false, tjmax_mdeg: 100_000 }, M(&msrs), Cfg(&root)),
            actuator: NoActuator,
        };
        // 60 C: nothing.
        let s = rt.tick(&mut board, &m, 0, &Inputs::IDLE);
        assert_eq!((s.level, s.shutdown), (0, false));
        // 90 C: past the hot trip, no clock to cap, so the level goes up.
        msrs.borrow_mut().has.insert(THERM_STATUS, status(true, 10));
        let s = rt.tick(&mut board, &m, 1000, &Inputs::IDLE);
        assert_eq!((s.level, s.shutdown), (LEVEL_SLOW, false));
        // 100 C: critical.
        msrs.borrow_mut().has.insert(THERM_STATUS, status(true, 0));
        let s = rt.tick(&mut board, &m, 2000, &Inputs::IDLE);
        assert_eq!((s.level, s.shutdown), (LEVEL_CONTAINED, true));
    }

    #[test]
    fn the_cpuid_words_decode_the_way_the_probe_expects() {
        let b = brand(" AMD Ryzen 7 2700X");
        // The hypervisor bit is CPUID.1:ECX[31], and only that bit.
        let c = X86Cpu::from_cpuid(Vendor::Intel, 6, 0x3a, 1 << 31, 0x16, 1, b);
        assert!(c.hypervisor);
        let c = X86Cpu::from_cpuid(Vendor::Intel, 6, 0x3a, !(1u32 << 31), 0x16, 1, b);
        assert!(!c.hypervisor);
        // A CPU with no leaf 6 reports no thermal flags whatever the caller read.
        let c = X86Cpu::from_cpuid(Vendor::Intel, 6, 0x3a, 0, 5, 0xffff_ffff, b);
        assert_eq!((c.l6_eax, c.max_basic_leaf), (0, 5));
        let c = X86Cpu::from_cpuid(Vendor::Intel, 6, 0x3a, 0, 6, 0x41, b);
        assert_eq!(c.l6_eax, 0x41);
        // QEMU TCG as the glue would hand it over: refused before any MSR.
        let msrs = RefCell::new(Msrs::default());
        let root = new_root(NO_ROOT);
        let tcg = X86Cpu::from_cpuid(Vendor::Amd, 0x17, 1, 1 << 31, 0xd, 0, [0; 48]);
        assert_eq!(probe(&tcg, &mut M(&msrs), &Cfg(&root)), Err(Refused::Hypervisor));
    }

    #[test]
    fn the_brand_leaves_make_the_string_the_offset_table_matches() {
        let text = b"AMD Ryzen 7 2700X Eight-Core Processor\0\0\0\0\0\0\0\0\0\0";
        let mut leaves = [[0u32; 4]; 3];
        for (i, chunk) in text.chunks(4).enumerate() {
            leaves[i / 4][i % 4] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let b = brand_from_leaves(leaves);
        assert_eq!(&b[..text.len()], &text[..]);
        assert_eq!(tctl_offset_mdeg(0x17, &b), 10_000);
    }
}

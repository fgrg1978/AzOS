// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A board object with no hardware (Cargo feature `fake`): QEMU has neither a
//! temperature sensor nor a clock to move, so the `thermal-smoke` gate row
//! gives the kernel's thermal task this board instead and drives a
//! temperature ramp through it. The task, the runtime, the governor seam and
//! the floors are the real ones; only the two seams that touch hardware are
//! replaced.
//!
//! * [`FakeBoard`] — sensor 0 reads `temp()`; domain `d`'s clock is the last
//!   OPP the actuator was asked for.
//! * [`fixture`] — the zone a machine with no device tree has: passive, hot
//!   and critical trips, the passive one capping every domain of the model,
//!   polled every [`POLL_MS`].

use azos_energy::model::{EnergyModel, Opp, MAX_DOMAINS};
use azos_energy::opp::{ActuateError, OppActuator};
use azos_energy::thermal::{CoolingMap, Thermal, Trip, TripKind, Zone};

use crate::sensor::{SensorBank, SensorError};

/// Passive trip: capping starts, milli-degrees Celsius.
pub const PASSIVE_MDEG: i32 = 70_000;
/// Hot trip: capping was not enough, the machine slows.
pub const HOT_MDEG: i32 = 90_000;
/// Critical trip: an orderly shutdown is requested. The gate row stays below.
pub const CRITICAL_MDEG: i32 = 110_000;
/// Hysteresis of the passive trip.
pub const PASSIVE_HYST_MDEG: u32 = 2_000;
/// Hysteresis of the hot trip.
pub const HOT_HYST_MDEG: u32 = 3_000;
/// Polling delay of the fixture zone, idle and passive alike.
pub const POLL_MS: u32 = 20;

/// The sensor and the clocks of a machine that has neither.
pub struct FakeBoard {
    temp: fn() -> i32,
    /// Per domain, the frequency last set, kHz (0: never asked).
    pub khz: [u32; MAX_DOMAINS],
    /// Requests the actuator took.
    pub sets: u32,
}

impl FakeBoard {
    /// A board whose temperature is `temp()`, milli-degrees Celsius.
    pub const fn new(temp: fn() -> i32) -> Self {
        Self { temp, khz: [0; MAX_DOMAINS], sets: 0 }
    }
}

impl SensorBank for FakeBoard {
    fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError> {
        match sensor {
            0 => Ok((self.temp)()),
            _ => Err(SensorError::Absent),
        }
    }
}

impl OppActuator for FakeBoard {
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        let slot = self.khz.get_mut(domain).ok_or(ActuateError::Unsupported)?;
        *slot = opp.freq_khz;
        self.sets += 1;
        Ok(())
    }
}

/// The fixture zone over `model`: passive (cap every domain, down to its
/// deepest state), hot and critical trips, read every [`POLL_MS`].
pub fn fixture(model: &EnergyModel) -> Thermal {
    let mut z = Zone::new(b"fake-thermal", 0);
    z.poll_ms = POLL_MS;
    z.poll_passive_ms = POLL_MS;
    let trips = [
        (PASSIVE_MDEG, PASSIVE_HYST_MDEG, TripKind::Passive),
        (HOT_MDEG, HOT_HYST_MDEG, TripKind::Hot),
        (CRITICAL_MDEG, 0, TripKind::Critical),
    ];
    for (temp_mdeg, hyst_mdeg, kind) in trips {
        z.push_trip(Trip { temp_mdeg, hyst_mdeg, kind }).expect("fixture: trips fit a zone");
    }
    for (dom, d) in model.domains().iter().enumerate() {
        let deepest = d.opps().len().saturating_sub(1) as u8;
        z.push_map(CoolingMap { trip: 0, domain: dom as u8, min_state: 0, max_state: deepest }, model)
            .expect("fixture: a map per domain fits a zone");
    }
    let mut t = Thermal::new();
    t.push_zone(z).expect("fixture: one zone fits");
    t
}

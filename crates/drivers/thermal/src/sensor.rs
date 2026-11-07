// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sensor seam, and the board object that joins a sensor source to a clock.

use azos_energy::model::Opp;
use azos_energy::opp::{ActuateError, OppActuator};

/// Why a sensor gave no temperature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SensorError {
    /// The board has no such sensor.
    Absent,
    /// The sensor or its transport failed or timed out.
    Io,
    /// It answered, but not with a temperature (a conversion that has not
    /// finished, a value outside what the part can measure).
    Invalid,
}

/// The sensors of a board, by the index a thermal zone names.
pub trait SensorBank {
    /// Read sensor `sensor`: milli-degrees Celsius.
    fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError>;
}

/// A board object: where the temperatures come from, and what moves the clock.
/// The kernel's sensor source is the sensor class (every board's sensor is an
/// instance of it); the tests' are scripted.
pub struct Joined<S, A> {
    /// The temperatures.
    pub sensor: S,
    /// The clock.
    pub actuator: A,
}

impl<S: SensorBank, A> SensorBank for Joined<S, A> {
    fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError> {
        self.sensor.read_mdeg(sensor)
    }
}

impl<S, A: OppActuator> OppActuator for Joined<S, A> {
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        self.actuator.set_opp(domain, opp)
    }
}

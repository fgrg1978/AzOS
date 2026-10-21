// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sensor seam.

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

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! StarFive JH7110: the `sfctemp` temperature sensor and the board object.
//!
//! The sensor (`starfive,jh7110-temp`, `sfctemp@120e0000` in the VisionFive 2
//! tree) is one 32-bit control/data register:
//!
//! | Bits | Name | Meaning |
//! |---|---|---|
//! | 0 | `RSTN` | 0 = reset, 1 = released (release only once the analog core is up) |
//! | 1 | `PD` | 0 = analog core powered, 1 = powered down |
//! | 2 | `RUN` | 1 = conversions enabled |
//! | 27:16 | `DOUT` | the last conversion, 12 bits |
//!
//! `temperature = DOUT * 237.5 / 4094 - 81.1` degrees Celsius.
//!
//! Register layout and constants are the ones the mainline sensor's public
//! binding documents; they were not checked against the board in this
//! change, so the host suite pins the arithmetic and the power-up order and
//! the testing week confirms them on a VisionFive 2 (a conversion that reads
//! 0 is reported as [`SensorError::Invalid`], never as a temperature).
//!
//! The CPU clock is not this crate's to drive: it is the clock framework's
//! (`crate::soc`). [`CpuClock`] is the seam it implements.

use azos_energy::model::Opp;
use azos_energy::opp::{ActuateError, OppActuator};

use crate::sensor::{SensorBank, SensorError};

/// Register offset of the control/data word.
pub const REG_CTRL: usize = 0x00;
/// `RSTN`.
pub const CTRL_RSTN: u32 = 1 << 0;
/// `PD`.
pub const CTRL_PD: u32 = 1 << 1;
/// `RUN`.
pub const CTRL_RUN: u32 = 1 << 2;
/// Shift of `DOUT`.
pub const DOUT_SHIFT: u32 = 16;
/// Mask of `DOUT`, after the shift.
pub const DOUT_MASK: u32 = 0xFFF;
/// Numerator of the conversion, milli-degrees at full scale.
pub const Y_MDEG: i64 = 237_500;
/// Full scale of the conversion.
pub const Z: i64 = 4094;
/// Offset of the conversion, milli-degrees.
pub const K_MDEG: i64 = 81_100;
/// The analog core needs this long after `PD` falls before `RSTN` may rise.
pub const POWER_UP_US: u32 = 50;
/// Reset must stay asserted at least this long.
pub const RESET_US: u32 = 1;

/// Register access and delays, supplied by the board.
pub trait SfcTempBus {
    /// Read the register at byte offset `off`.
    fn read32(&mut self, off: usize) -> u32;
    /// Write the register at byte offset `off`.
    fn write32(&mut self, off: usize, v: u32);
    /// Busy-wait at least `us` microseconds.
    fn delay_us(&mut self, us: u32);
}

/// Milli-degrees Celsius for a raw `DOUT`.
pub const fn dout_to_mdeg(dout: u32) -> i32 {
    ((dout as i64 & DOUT_MASK as i64) * Y_MDEG / Z - K_MDEG) as i32
}

/// The sensor.
pub struct SfcTemp<B> {
    bus: B,
}

impl<B: SfcTempBus> SfcTemp<B> {
    /// Wrap the bus. The sensor is not running yet: call [`SfcTemp::start`].
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    /// Power up and start conversions: hold reset, power the core, wait,
    /// release reset, enable `RUN`.
    pub fn start(&mut self) {
        self.bus.write32(REG_CTRL, CTRL_PD);
        self.bus.delay_us(RESET_US);
        self.bus.write32(REG_CTRL, 0);
        self.bus.delay_us(POWER_UP_US);
        self.bus.write32(REG_CTRL, CTRL_RSTN);
        self.bus.delay_us(RESET_US);
        self.bus.write32(REG_CTRL, CTRL_RSTN | CTRL_RUN);
    }

    /// The last conversion, milli-degrees Celsius.
    pub fn read_mdeg(&mut self) -> Result<i32, SensorError> {
        let v = self.bus.read32(REG_CTRL);
        let dout = (v >> DOUT_SHIFT) & DOUT_MASK;
        if v & (CTRL_RUN | CTRL_RSTN) != (CTRL_RUN | CTRL_RSTN) || v & CTRL_PD != 0 || dout == 0 {
            return Err(SensorError::Invalid);
        }
        Ok(dout_to_mdeg(dout))
    }
}

/// What the clock framework provides: run the CPU cluster at `khz` and say
/// whether it could.
pub trait CpuClock {
    /// Run the cluster at `khz`.
    fn set_cpu_khz(&mut self, khz: u32) -> Result<(), ActuateError>;
}

/// The JH7110 board object: sensor 0 is the `sfctemp`, domain 0 the cluster.
pub struct Jh7110<B, C> {
    /// The temperature sensor.
    pub sensor: SfcTemp<B>,
    /// The CPU clock.
    pub clock: C,
}

impl<B: SfcTempBus, C: CpuClock> SensorBank for Jh7110<B, C> {
    fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError> {
        match sensor {
            0 => self.sensor.read_mdeg(),
            _ => Err(SensorError::Absent),
        }
    }
}

impl<B: SfcTempBus, C: CpuClock> OppActuator for Jh7110<B, C> {
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        Cluster(&mut self.clock).set_opp(domain, opp)
    }
}

/// The JH7110's CPU clock alone, as an actuator: domain 0 is the cluster. The
/// board object of a runtime with no zone (no sensor to read).
pub struct Cluster<C>(pub C);

impl<C: CpuClock> CpuClock for &mut C {
    fn set_cpu_khz(&mut self, khz: u32) -> Result<(), ActuateError> {
        (**self).set_cpu_khz(khz)
    }
}

impl<C: CpuClock> OppActuator for Cluster<C> {
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        match domain {
            0 => self.0.set_cpu_khz(opp.freq_khz),
            _ => Err(ActuateError::Unsupported),
        }
    }
}

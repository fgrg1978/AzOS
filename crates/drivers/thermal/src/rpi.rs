// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Raspberry Pi: temperature and ARM clock, both through the firmware.
//!
//! The VideoCore owns the sensor and the ARM PLL, so one object (the
//! mailbox) is both the sensor bank and the OPP actuator. Sensor 0 is the
//! SoC temperature; domain 0 is the ARM cluster (every Pi's cores share one
//! clock).
//!
//! # The actuator
//!
//! The clock moves only after [`RpiFirmware::probe_clock`] has asked the
//! firmware for the ARM clock's rate and its minimum and maximum and found a
//! range that can move: a firmware that does not implement the tags (QEMU's
//! `raspi` machines answer the property channel with constants or not at all)
//! leaves the object without an actuator, and `set_opp` answers
//! [`ActuateError::Unsupported`] like [`NoActuator`] does, so the runtime
//! raises the degrade level instead of believing a clock moved. With a range:
//!
//! * a rate outside `[min, max]` is refused before it is posted;
//! * the firmware answers a set with the rate it settled on (the PLL rounds).
//!   A rate **below** the one asked is a clock under the floor the framework
//!   admitted (`Thermal::limit` raised the request to the real-time and WCET
//!   floors, never lower), so it is put back and refused; a rate above it is
//!   accepted while it still is a step down from where the clock was, and
//!   refused when a lowering request left the clock where it was (the heat
//!   was not answered).

use azos_energy::model::{EnergyModel, ModelFault, Opp, MAX_MODEL_CPUS};
use azos_energy::opp::{ActuateError, NoActuator, OppActuator};
use azos_firmware::{Mailbox, MailboxError, MailboxPort};

use crate::sensor::{SensorBank, SensorError};

/// The ARM clock's range as the firmware reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmClock {
    /// Lowest rate the firmware accepts, Hz.
    pub min_hz: u32,
    /// Highest rate the firmware accepts, Hz.
    pub max_hz: u32,
}

/// Distance between the OPPs of the table built from the ARM clock's range,
/// kHz. **Not probed**: the firmware documents a range and no list of rates
/// (it takes any rate in it and rounds with its PLL), and finding the rates it
/// would accept means moving the live clock under cores that are starting.
/// 100 MHz is a choice, not a firmware fact: it gives the Pi 5's range
/// (1.5 to 2.4 GHz) ten OPPs and is what the fake PLL of
/// `tests/host/thermal-tests` models; no board has confirmed which rates the
/// PLL lands on exactly. A rate the PLL rounds under the request is not lost on
/// the way: `set_opp` puts the clock back and refuses it, and the runtime
/// raises the degrade level.
pub const MODEL_STEP_KHZ: u32 = 100_000;

impl ArmClock {
    /// The energy model of a machine whose `num_cpus` CPUs share this clock
    /// (every Pi's do): one domain, OPPs from [`ArmClock::min_hz`] to
    /// [`ArmClock::max_hz`] every [`MODEL_STEP_KHZ`]
    /// ([`EnergyModel::from_clock_range`]), with **placeholder power, not
    /// measured**. Refuses a range that cannot make a table whatever the probe
    /// let through.
    pub fn energy_model(&self, num_cpus: usize) -> Result<EnergyModel, ModelFault> {
        let n = num_cpus.min(MAX_MODEL_CPUS);
        let cpus = if n >= 32 { u32::MAX } else { (1u32 << n) - 1 };
        EnergyModel::from_clock_range(cpus, self.min_hz / 1000, self.max_hz / 1000, MODEL_STEP_KHZ)
    }
}

/// Why [`RpiFirmware::probe_clock`] left the object without an actuator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// The firmware did not answer one of the three requests.
    Firmware(MailboxError),
    /// It answered, but not with a range a clock can move in: the minimum is
    /// zero or not below the maximum, or the current rate is outside it.
    /// (What an emulated property channel answers.)
    Degenerate,
}

/// The Pi's firmware as a board object.
pub struct RpiFirmware<P> {
    /// The mailbox.
    pub mbox: Mailbox<P>,
    /// The ARM clock's range: `None` until a probe found one that can move.
    clock: Option<ArmClock>,
}

impl<P: MailboxPort> RpiFirmware<P> {
    /// Wrap a mailbox. No actuator until [`RpiFirmware::probe_clock`].
    pub const fn new(mbox: Mailbox<P>) -> Self {
        Self { mbox, clock: None }
    }

    /// Ask the firmware for the ARM clock's rate, minimum and maximum, and
    /// keep them if they describe a clock that can move. On failure the
    /// object stays (or becomes) an actuator that answers `Unsupported`.
    pub fn probe_clock(&mut self) -> Result<ArmClock, ProbeError> {
        self.clock = None;
        let cur_hz = self.mbox.arm_clock_rate().map_err(ProbeError::Firmware)?;
        let min_hz = self.mbox.arm_min_clock_rate().map_err(ProbeError::Firmware)?;
        let max_hz = self.mbox.arm_max_clock_rate().map_err(ProbeError::Firmware)?;
        let movable = min_hz != 0 && min_hz < max_hz && (min_hz..=max_hz).contains(&cur_hz);
        if !movable && !cfg!(feature = "rpi-opp-canary") {
            return Err(ProbeError::Degenerate);
        }
        let clock = ArmClock { min_hz, max_hz };
        self.clock = Some(clock);
        Ok(clock)
    }

    /// The ARM clock's range, if a probe found one.
    pub fn clock(&self) -> Option<ArmClock> {
        self.clock
    }

    /// The energy model the probed clock range makes ([`ArmClock::energy_model`]);
    /// `None` when no probe found a range that can move (the firmware has no
    /// OPPs to describe).
    pub fn energy_model(&self, num_cpus: usize) -> Option<Result<EnergyModel, ModelFault>> {
        self.clock.map(|c| c.energy_model(num_cpus))
    }

    /// The ARM clock as the firmware left it, kHz: the OPP the runtime is
    /// told the cluster boots at ([`crate::runtime::Runtime::from_dt`]).
    /// `None` when the firmware did not answer.
    pub fn arm_khz(&mut self) -> Option<u32> {
        self.mbox.arm_clock_rate().ok().map(|hz| hz / 1000)
    }
}

impl<P: MailboxPort> SensorBank for RpiFirmware<P> {
    fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError> {
        if sensor != 0 {
            return Err(SensorError::Absent);
        }
        self.mbox.soc_temperature().map_err(|e| match e {
            MailboxError::NoResponse | MailboxError::Refused => SensorError::Invalid,
            _ => SensorError::Io,
        })
    }
}

fn actuate_error(e: MailboxError) -> ActuateError {
    match e {
        MailboxError::Refused | MailboxError::NoResponse => ActuateError::Refused,
        _ => ActuateError::Fault(-1),
    }
}

impl<P: MailboxPort> OppActuator for RpiFirmware<P> {
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        if domain != 0 {
            return Err(ActuateError::Unsupported);
        }
        let Some(range) = self.clock else { return NoActuator.set_opp(domain, opp) };
        let hz = opp.freq_khz.checked_mul(1000).ok_or(ActuateError::Refused)?;
        if !cfg!(feature = "rpi-opp-canary") && !(range.min_hz..=range.max_hz).contains(&hz) {
            return Err(ActuateError::Refused);
        }
        // Where the clock is now, not where it was last left: the firmware
        // has its own limits and moves the clock under them.
        let was = self.mbox.arm_clock_rate().map_err(actuate_error)?;
        let settled = self.mbox.set_arm_clock_rate(hz).map_err(actuate_error)?;
        let under = settled < hz;
        let unanswered = hz < was && settled >= was;
        if !cfg!(feature = "rpi-opp-canary") && (under || unanswered) {
            // Best effort: put the clock back where the bookkeeping says it
            // is. A refused put-back leaves the rate the firmware settled
            // on; the runtime asks again at its next tick.
            let _ = self.mbox.set_arm_clock_rate(was);
            return Err(ActuateError::Refused);
        }
        Ok(())
    }
}

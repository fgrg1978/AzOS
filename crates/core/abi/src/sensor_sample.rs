// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The stamp of a sensor sample (`azos_devif::Sample`, the `Sensor`
//! interface's reading): the time the value was acquired and how it was
//! obtained, beside the record in the byte format of the sensor type.
//!
//! ## The clock
//!
//! `acq_ns` is the monotonic clock ring 3 reads through the vDSO
//! (`azos_libsys::vdso_now_ns`): the free-running counter the kernel calls
//! `timebase::now()`, converted with [`crate::time::ticks_to_ns`] at the
//! frequency the vDSO page publishes. A reader can therefore compare it with
//! its own `vdso_now_ns()` without any conversion.
//!
//! ## Where the stamp is taken
//!
//! At acquisition, not at delivery: the counter is read right after the
//! device transfer that produced the value completes (an I2C burst, an ADC
//! conversion, a GPIO read), or, for a value a producer caches (a GPS fix
//! parsed from the receiver's stream, a LiDAR revolution, odometry integrated
//! by its task, the ring-3 power monitor's last sample), when the producer
//! filled the cache. A value read twice from the same cache carries the same
//! stamp both times. Where a record joins several reads (two rangefinders,
//! three GPIO lines) the stamp is that of the FIRST, so the age a reader
//! computes is never smaller than the age of any field.
//!
//! `acq_ns == 0` means the acquisition time is unknown (a producer that does
//! not report one): such a sample is never fresh.

/// The value was not measured by a device: a simulated source stands in for
/// the sensor (QEMU's fixed GPS fix, the simulated rangefinder). The stamp is
/// when the simulation produced it. A battery with no ADC is not simulated:
/// it has no reading.
pub const SENSOR_SAMPLE_FLAG_SYNTHETIC: u16 = 1 << 0;

/// Whether a sample acquired at `acq_ns` is still usable at `now_ns`: the
/// staleness rule every consumer of a stamp applies. `0` (unknown) is never
/// fresh; a stamp from the future (a clock that is not the same as the
/// reader's) is not either. Strictly less than `max_age_ns`.
pub const fn sample_is_fresh_ns(acq_ns: u64, now_ns: u64, max_age_ns: u64) -> bool {
    acq_ns != 0 && acq_ns <= now_ns && now_ns - acq_ns < max_age_ns
}

/// The sensor instances a topology names (`sensor.<n>`), by number: the one
/// place the numbering is written. The kernel's board registers its sensors in
/// this order (`azos_drv_base::sensors::board`) and libsys names them for
/// ring-3 programs.
pub mod instance {
    /// The accelerometer and gyroscope.
    pub const IMU: u32 = 0;
    /// The dead-reckoned distance and heading.
    pub const ODOM: u32 = 1;
    /// The wheel encoder counts.
    pub const ENCODER: u32 = 2;
    /// The front and right rangefinders.
    pub const RANGE: u32 = 3;
    /// The battery voltage.
    pub const BATTERY: u32 = 4;
    /// The position fix.
    pub const GPS: u32 = 5;
    /// The LiDAR scan (no sample record).
    pub const LIDAR: u32 = 6;
    /// The digital lines: PIR, sound, IR.
    pub const FLAGS: u32 = 7;
    /// The camera frame (no sample record).
    pub const CAMERA: u32 = 8;
    /// The power monitor.
    pub const POWER: u32 = 9;
}

/// Periods of a stream a sample may be old before a reader treats it as
/// stale: a producer that missed a few is late, one that stopped is gone.
pub const STALE_PERIODS: u64 = 5;

/// How old a sample of a stream published `rate_hz` times a second may be
/// before it is stale: [`STALE_PERIODS`] of its period, and never less than
/// `floor_ns` (a reader's own tolerance for scheduling hiccups). A stream with
/// no rate (0) is bounded by the floor alone.
pub const fn max_age_ns(rate_hz: u32, floor_ns: u64) -> u64 {
    let periods = if rate_hz == 0 { 0 } else { STALE_PERIODS * 1_000_000_000 / rate_hz as u64 };
    if periods > floor_ns { periods } else { floor_ns }
}

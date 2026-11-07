// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Sensor bus — the behavior task's view of the sensor class's streams.
//!
//! Dedicated sensor tasks publish into the streams of the sensors they feed
//! (`azos_drv_base::sensors`), each the one producer of its own, at its own
//! rate; the behavior task reads the newest sample of each into a
//! [`SensorState`](crate::types::SensorState). A stream's newest sample is
//! one whole acquisition, so a snapshot never mixes the halves of two
//! (an IMU's six axes, an odometry pair), and it carries when it was acquired,
//! which is what the freshness rules below judge.
//!
//! The read is direct and bounded: no syscall, no lock, no allocation, and a
//! retry only while a producer is inside a store of a few words.
//!
//!   imu_task (RT)        → IMU stream, IMU die temperature stream
//!   odom_task            → odometry and encoder streams
//!   sensor-slow          → rangefinder, battery and digital-line streams
//!   sensor-ahrs          → GPS stream
//!
//!   behavior_task        → state = sensor_bus.snapshot()

use azos_drv_base::sensors::{value, Sample, Sensor};
use azos_robot_sensors as board;

/// Degrees × 10⁷ (the GPS driver's `lat_deg7`/`lon_deg7`) to micro-degrees
/// (`SensorState::gps_lat_udeg`, the geofence's unit).
///
/// The one place the two scales meet. They differ by exactly one decimal digit,
/// so a value passed through unconverted is not rejected anywhere: it is a
/// position ten times further from the equator and the meridian, and every
/// fence evaluated against it reads `Outside` by hundreds of kilometres — or,
/// with the fence centre left in the other unit, `Inside` by the same margin.
/// Truncates toward zero: one micro-degree is at most 0.11 m.
pub const fn deg7_to_udeg(deg7: i32) -> i32 {
    deg7 / 10
}

/// Whether a sample stamped at `updated_at` is still usable at `now`.
///
/// Zero means "never updated", and is never fresh. Strictly less than
/// `max_age`: a sample exactly `max_age` old has expired.
pub const fn sample_is_fresh(updated_at: u64, now: u64, max_age: u64) -> bool {
    updated_at != 0 && now.saturating_sub(updated_at) < max_age
}

// ---------------------------------------------------------------------------
// The bus
// ---------------------------------------------------------------------------

/// The streams a [`SensorBus`] reads.
pub struct Sources {
    pub imu: &'static Sensor,
    pub imu_temp: &'static Sensor,
    pub odom: &'static Sensor,
    pub encoder: &'static Sensor,
    pub range: &'static Sensor,
    pub battery: &'static Sensor,
    pub flags: &'static Sensor,
    pub gps: &'static Sensor,
}

/// The behavior task's reader of the sensor streams.
pub struct SensorBus(Sources);

/// The newest sample of a stream, read once: every channel of a snapshot comes
/// from the same acquisition.
struct Latest {
    sensor: &'static Sensor,
    sample: Option<Sample>,
    /// Whether the sample is still usable at the snapshot's time (always, for
    /// a stream read with [`Latest::of`]).
    fresh: bool,
}

impl Latest {
    fn of(sensor: &'static Sensor) -> Self {
        Self { sensor, sample: sensor.latest(), fresh: true }
    }

    /// The newest sample, judged by its acquisition stamp against
    /// [`SensorBus::max_age_ns`] at `now_ns`.
    fn within(sensor: &'static Sensor, now_ns: u64, floor_ns: u64) -> Self {
        let sample = sensor.latest();
        let max = SensorBus::max_age_ns(sensor, floor_ns);
        let fresh = sample.is_some_and(|s| sample_is_fresh(s.acq_ns, now_ns, max));
        Self { sensor, sample, fresh }
    }

    /// Channel `idx`, narrowed to the type `SensorState` holds; `None` before
    /// the first sample.
    fn channel<T: TryFrom<i64>>(&self, idx: usize) -> Option<T> {
        T::try_from(value(self.sensor.channels(), self.sample.as_ref()?, idx)?).ok()
    }

    /// [`channel`](Self::channel) of a sample that is still fresh: a stale one
    /// is no reading, which every consumer treats as unknown.
    fn live<T: TryFrom<i64>>(&self, idx: usize) -> Option<T> {
        self.fresh.then(|| self.channel(idx)).flatten()
    }
}

impl SensorBus {
    pub const fn new(sources: Sources) -> Self {
        Self(sources)
    }

    /// The board's sensors.
    pub const fn board() -> Self {
        Self::new(Sources {
            imu: &board::IMU_SENSOR,
            imu_temp: &board::IMU_TEMP_SENSOR,
            odom: &board::ODOM_SENSOR,
            encoder: &board::ENCODER_SENSOR,
            range: &board::RANGE_SENSOR,
            battery: &board::BATTERY_SENSOR,
            flags: &board::FLAGS_SENSOR,
            gps: &board::GPS_SENSOR,
        })
    }

    /// The IMU is judged against at least 200 ms: two orders of magnitude above
    /// its period at the default rate, so a missed sample or a scheduling
    /// hiccup does not blind the safety layer, and two orders below the time a
    /// falling robot takes to matter.
    pub const IMU_FLOOR_NS: u64 = 200_000_000;

    /// A GPS fix is judged against at least 2 s. Not the IMU's: common
    /// receivers produce 1-10 fixes a second, so 200 ms would be one or two
    /// periods and a scheduling hiccup under TCG would flap the fence to
    /// `Unknown`. A wheeled robot at 1 m/s covers 2 m in 2 s, small against any
    /// fence radius worth configuring.
    pub const GPS_FLOOR_NS: u64 = 2_000_000_000;

    /// The slow streams (battery, rangefinders, digital lines) against at
    /// least 500 ms.
    pub const SLOW_FLOOR_NS: u64 = 500_000_000;

    /// How old a sample of `sensor` may be, nanoseconds on the vDSO clock:
    /// `STALE_PERIODS` of the period its first channel declares (the rate is
    /// Kconfig's, so a slow IMU is not held in e-stop for being slow), never
    /// under `floor_ns`.
    pub fn max_age_ns(sensor: &Sensor, floor_ns: u64) -> u64 {
        azos_abi::sensor_sample::max_age_ns(sensor.channels().first().map_or(0, |c| c.rate_hz), floor_ns)
    }

    /// The IMU's bound on this bus.
    pub fn imu_max_age_ns(&self) -> u64 {
        Self::max_age_ns(self.0.imu, Self::IMU_FLOOR_NS)
    }

    /// The GPS's bound on this bus.
    pub fn gps_max_age_ns(&self) -> u64 {
        Self::max_age_ns(self.0.gps, Self::GPS_FLOOR_NS)
    }

    /// Take the newest sample of every stream into `state`.
    pub fn snapshot(&self, state: &mut crate::types::SensorState) {
        self.snapshot_at(state, azos_drv_sys::timebase::vdso_ns(azos_drv_sys::timebase::now()));
    }

    /// [`snapshot`](Self::snapshot), judging freshness at `now_ns` (the vDSO
    /// clock) rather than at the clock's current reading.
    pub fn snapshot_at(&self, state: &mut crate::types::SensorState, now_ns: u64) {
        let s = &self.0;
        // Valid AND fresh, by when the sample was ACQUIRED: a silent IMU
        // leaves its last sample in the stream, and judging delivery would
        // keep every tilt, fall and spin check evaluating a frozen reading
        // and reporting it as good.
        let imu = Latest::within(s.imu, now_ns, Self::IMU_FLOOR_NS);
        state.imu_valid = imu.fresh;
        for i in 0..3 {
            // 1 g upright until the first sample.
            state.accel_mg[i] = imu.channel(i).unwrap_or(if i == 2 { 1000 } else { 0 });
            state.gyro_mdps[i] = imu.channel(3 + i).unwrap_or(0);
        }
        let odom = Latest::of(s.odom);
        state.odom_dist_mm = odom.channel(0).unwrap_or(0);
        state.odom_heading_cdeg = odom.channel(1).unwrap_or(0);
        let enc = Latest::of(s.encoder);
        state.enc_left = enc.channel(0).unwrap_or(0);
        state.enc_right = enc.channel(1).unwrap_or(0);
        // 0 is "no reading", and it has to be: the safety layer guards every
        // battery check with `battery_mv > 0`, so a machine with no fuel gauge
        // is not judged as empty. A stream that stopped publishing (a
        // converter that times out) reads 0 too: its last value, a sagging
        // 6400 mV, would otherwise hold the low-battery stop for good.
        let range = Latest::within(s.range, now_ns, Self::SLOW_FLOOR_NS);
        state.cam_dist_front = range.live(0).unwrap_or(0);
        state.cam_dist_right = range.live(1).unwrap_or(0);
        state.battery_mv = Latest::within(s.battery, now_ns, Self::SLOW_FLOOR_NS).live(0).unwrap_or(0);
        state.temp_cdeg = Latest::within(s.imu_temp, now_ns, Self::IMU_FLOOR_NS).live(0).unwrap_or(0);
        state.sensor_flags = Latest::within(s.flags, now_ns, Self::SLOW_FLOOR_NS).live(0).unwrap_or(0);

        // A stale fix is no fix: quality and satellites both read zero, so
        // `safety::geofence_status` returns `Unknown` whatever threshold it
        // applies. The position is passed through; nothing trusts it without
        // the quality. The fix ages from the receiver's sentence (its
        // acquisition stamp), not from the publication: a silent receiver's
        // last fix, republished every period, goes stale all the same.
        let gps = Latest::within(s.gps, now_ns, Self::GPS_FLOOR_NS);
        let gps_fresh = gps.fresh;
        state.gps_lat_udeg = deg7_to_udeg(gps.channel(0).unwrap_or(0));
        state.gps_lon_udeg = deg7_to_udeg(gps.channel(1).unwrap_or(0));
        state.gps_fix = if gps_fresh { gps.channel(3).unwrap_or(0) } else { 0 };
        state.gps_satellites = if gps_fresh { gps.channel(4).unwrap_or(0) } else { 0 };
    }
}

/// The board's sensor bus.
pub static SENSOR_BUS: SensorBus = SensorBus::board();

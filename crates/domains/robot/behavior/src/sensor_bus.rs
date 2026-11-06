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

use azos_drv_base::sensors::{board, value, Sample, Sensor};

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
}

impl Latest {
    fn of(sensor: &'static Sensor) -> Self {
        Self { sensor, sample: sensor.latest() }
    }

    /// Channel `idx`, narrowed to the type `SensorState` holds; `None` before
    /// the first sample.
    fn channel<T: TryFrom<i64>>(&self, idx: usize) -> Option<T> {
        T::try_from(value(self.sensor.channels(), self.sample.as_ref()?, idx)?).ok()
    }

    fn acq_ns(&self) -> Option<u64> {
        self.sample.map(|s| s.acq_ns)
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

    /// How long an IMU sample stays usable, nanoseconds on the vDSO clock: 200
    /// ms, so it is 200 ms on QEMU, the VF2 and the K1 alike.
    ///
    /// Two orders of magnitude above the IMU's period, so a missed sample or a
    /// scheduling hiccup does not blind the safety layer; two orders below
    /// the time a falling robot takes to matter.
    pub const IMU_MAX_AGE_NS: u64 = 200_000_000;

    /// How long a GPS fix stays usable: 2 s.
    ///
    /// Not the IMU's 200 ms. The kernel publishes GPS at the slow rate and
    /// common receivers produce 1-10 fixes a second, so 200 ms would be one or
    /// two periods and a scheduling hiccup under TCG would flap the fence to
    /// `Unknown`. Two seconds is twenty publishes at the kernel's rate and two
    /// fixes from a 1 Hz receiver; a wheeled robot at 1 m/s covers 2 m in it,
    /// small against any fence radius worth configuring.
    pub const GPS_MAX_AGE_NS: u64 = 2_000_000_000;

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
        let imu = Latest::of(s.imu);
        state.imu_valid = imu.acq_ns().is_some_and(|t| sample_is_fresh(t, now_ns, Self::IMU_MAX_AGE_NS));
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
        // is not judged as empty.
        let range = Latest::of(s.range);
        state.cam_dist_front = range.channel(0).unwrap_or(0);
        state.cam_dist_right = range.channel(1).unwrap_or(0);
        state.battery_mv = Latest::of(s.battery).channel(0).unwrap_or(0);
        state.temp_cdeg = Latest::of(s.imu_temp).channel(0).unwrap_or(0);
        state.sensor_flags = Latest::of(s.flags).channel(0).unwrap_or(0);

        // A stale fix is no fix: quality and satellites both read zero, so
        // `safety::geofence_status` returns `Unknown` whatever threshold it
        // applies. The position is passed through; nothing trusts it without
        // the quality. The fix ages from the receiver's sentence (its
        // acquisition stamp), not from the publication: a silent receiver's
        // last fix, republished every period, goes stale all the same.
        let gps = Latest::of(s.gps);
        let gps_fresh = gps.acq_ns().is_some_and(|t| sample_is_fresh(t, now_ns, Self::GPS_MAX_AGE_NS));
        state.gps_lat_udeg = deg7_to_udeg(gps.channel(0).unwrap_or(0));
        state.gps_lon_udeg = deg7_to_udeg(gps.channel(1).unwrap_or(0));
        state.gps_fix = if gps_fresh { gps.channel(3).unwrap_or(0) } else { 0 };
        state.gps_satellites = if gps_fresh { gps.channel(4).unwrap_or(0) } else { 0 };
    }
}

/// The board's sensor bus.
pub static SENSOR_BUS: SensorBus = SensorBus::board();

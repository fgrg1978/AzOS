// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Sensor bus — shared sensor state between producer tasks and behavior consumer.
//!
//! Dedicated sensor tasks write to the bus at their own rate.
//! The behavior task reads the latest snapshot atomically.
//!
//! This replaces the monolithic "read all sensors in behavior_task" pattern
//! with priority-separated sensor tasks that use IO-wait.
//!
//! Architecture:
//!   imu_task (RT, 100Hz)     → sensor_bus.update_imu(accel, gyro)
//!   odom_task (normal, 50Hz) → sensor_bus.update_odom(dist, heading, enc_l, enc_r)
//!   range_task (normal, 20Hz)→ sensor_bus.update_range(front, right)
//!   battery_task (low, 1Hz)  → sensor_bus.update_battery(mv)
//!   gpio_task (normal, 20Hz) → sensor_bus.update_flags(flags)
//!   sensor-ahrs (10Hz GPS)   → sensor_bus.update_gps(lat_deg7, lon_deg7, fix, sats)
//!
//!   behavior_task (normal)   → state = sensor_bus.snapshot()

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU16, AtomicU64, AtomicU8, Ordering};

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
// Shared sensor bus (lock-free, atomic fields)
// ---------------------------------------------------------------------------

/// Atomic sensor bus — producers write individual fields, consumer reads snapshot.
/// Uses relaxed ordering for sensor data (eventual consistency is fine for robotics).
pub struct SensorBus {
    // IMU
    pub accel_x_mg: AtomicI32,
    pub accel_y_mg: AtomicI32,
    pub accel_z_mg: AtomicI32,
    pub gyro_x_mdps: AtomicI32,
    pub gyro_y_mdps: AtomicI32,
    pub gyro_z_mdps: AtomicI32,
    pub imu_valid: AtomicBool,
    /// CLINT tick of the last `update_imu`. Zero means "never updated".
    ///
    /// `imu_valid` alone was a latch: set true on the first sample and never
    /// set false anywhere in the tree. An IMU that stopped answering left the
    /// tilt, fall and spin checks running against a frozen last-good
    /// orientation, forever, and reporting it as valid. A robot lying on its
    /// side reads level.
    pub imu_updated_at: core::sync::atomic::AtomicU64,

    // Odometry
    pub odom_dist_mm: AtomicI64,
    pub odom_heading_cdeg: AtomicI64,
    pub enc_left: AtomicI64,
    pub enc_right: AtomicI64,

    // Rangefinder
    pub range_front: AtomicU16,
    pub range_right: AtomicU16,

    // Battery
    pub battery_mv: AtomicU16,

    // Temperature (centidegrees Celsius from IMU)
    pub temp_cdeg: AtomicI32,

    // GPIO sensor flags (PIR/sound/IR)
    pub sensor_flags: AtomicU16,

    // GPS, already in the geofence's unit (micro-degrees, see `deg7_to_udeg`)
    pub gps_lat_udeg: AtomicI32,
    pub gps_lon_udeg: AtomicI32,
    /// GGA fix quality as the receiver reported it (0 = no fix).
    pub gps_fix: AtomicU8,
    pub gps_satellites: AtomicU8,
    /// CLINT tick of the last `update_gps`. Zero means "never updated".
    ///
    /// The same latch `imu_updated_at` closes for the IMU: without it the last
    /// fix a receiver produced before going silent would stay in every snapshot
    /// with its quality intact, and a robot that has since driven out of its
    /// fence would keep reading `Inside`.
    pub gps_updated_at: AtomicU64,

    // Timestamp of last update
    pub timestamp: AtomicU64,
}

impl SensorBus {
    pub const fn new() -> Self {
        Self {
            accel_x_mg: AtomicI32::new(0),
            accel_y_mg: AtomicI32::new(0),
            accel_z_mg: AtomicI32::new(1000), // 1g upright
            gyro_x_mdps: AtomicI32::new(0),
            gyro_y_mdps: AtomicI32::new(0),
            gyro_z_mdps: AtomicI32::new(0),
            imu_valid: AtomicBool::new(false),
            imu_updated_at: core::sync::atomic::AtomicU64::new(0),
            odom_dist_mm: AtomicI64::new(0),
            odom_heading_cdeg: AtomicI64::new(0),
            enc_left: AtomicI64::new(0),
            enc_right: AtomicI64::new(0),
            range_front: AtomicU16::new(0),
            range_right: AtomicU16::new(0),
            battery_mv: AtomicU16::new(0),
            temp_cdeg: AtomicI32::new(0),
            sensor_flags: AtomicU16::new(0),
            gps_lat_udeg: AtomicI32::new(0),
            gps_lon_udeg: AtomicI32::new(0),
            gps_fix: AtomicU8::new(0),
            gps_satellites: AtomicU8::new(0),
            gps_updated_at: AtomicU64::new(0),
            timestamp: AtomicU64::new(0),
        }
    }

    // ── Producer methods (called by sensor tasks) ────────────────────────

    pub fn update_temp(&self, cdeg: i32) {
        self.temp_cdeg.store(cdeg, Ordering::Relaxed);
    }

    /// Publish one IMU sample, stamped with the time it reaches the bus.
    /// A producer that knows when the sample was ACQUIRED calls
    /// [`update_imu_at`](Self::update_imu_at) instead.
    pub fn update_imu(&self, accel: [i32; 3], gyro: [i32; 3]) {
        self.update_imu_at(accel, gyro, azos_drv_sys::timebase::now());
    }

    /// Publish one IMU sample acquired at timebase tick `acq` (the driver's
    /// stamp, `azos_imu::imu_read_scaled_stamped`). The freshness check
    /// in [`snapshot_at`](Self::snapshot_at) ages the sample from `acq`: a
    /// driver that keeps handing over an old reading is stale, however often
    /// it is delivered.
    pub fn update_imu_at(&self, accel: [i32; 3], gyro: [i32; 3], acq: u64) {
        self.accel_x_mg.store(accel[0], Ordering::Relaxed);
        self.accel_y_mg.store(accel[1], Ordering::Relaxed);
        self.accel_z_mg.store(accel[2], Ordering::Relaxed);
        self.gyro_x_mdps.store(gyro[0], Ordering::Relaxed);
        self.gyro_y_mdps.store(gyro[1], Ordering::Relaxed);
        self.gyro_z_mdps.store(gyro[2], Ordering::Relaxed);
        self.imu_updated_at.store(acq, Ordering::Relaxed);
        self.imu_valid.store(true, Ordering::Release);
    }

    /// How long an IMU sample stays usable: 200 ms, from the board's timebase
    /// rather than a tick count, so it is 200 ms on QEMU, the VF2 and the K1
    /// alike.
    ///
    /// Two orders of magnitude above the ~1 kHz the driver is polled at, so a
    /// missed sample or a scheduling hiccup does not blind the safety layer;
    /// two orders below the time a falling robot takes to matter.
    pub const IMU_MAX_AGE_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ / 5;

    pub fn update_odom(&self, dist_mm: i64, heading_cdeg: i64, enc_l: i64, enc_r: i64) {
        self.odom_dist_mm.store(dist_mm, Ordering::Relaxed);
        self.odom_heading_cdeg.store(heading_cdeg, Ordering::Relaxed);
        self.enc_left.store(enc_l, Ordering::Relaxed);
        self.enc_right.store(enc_r, Ordering::Relaxed);
    }

    pub fn update_range(&self, front: u16, right: u16) {
        self.range_front.store(front, Ordering::Relaxed);
        self.range_right.store(right, Ordering::Relaxed);
    }

    pub fn update_battery(&self, mv: u16) {
        self.battery_mv.store(mv, Ordering::Relaxed);
    }

    pub fn update_flags(&self, flags: u16) {
        self.sensor_flags.store(flags, Ordering::Relaxed);
    }

    /// Publish one GPS fix, in the driver's units (`GpsPosition::lat_deg7`,
    /// `lon_deg7`, `fix`, `sats`). The conversion to micro-degrees happens here
    /// and nowhere else.
    ///
    /// Five separate stores, like the IMU's six: a snapshot racing this can mix
    /// two consecutive fixes field by field, both of them fixes the receiver
    /// reported. The stamp is stored last, so the age a snapshot judges is
    /// never newer than the fields it read.
    pub fn update_gps(&self, lat_deg7: i32, lon_deg7: i32, fix: u8, sats: u8) {
        // `max(1)`: zero is the "never updated" sentinel.
        self.update_gps_at(lat_deg7, lon_deg7, fix, sats, azos_drv_sys::timebase::now().max(1));
    }

    /// [`update_gps`](Self::update_gps) for a fix acquired at timebase tick
    /// `acq` (`azos_gps::gps_read_stamped`): the fix ages from the
    /// receiver's sentence, not from this publication. A receiver that went
    /// silent leaves its last fix in the driver, and a producer re-publishing
    /// it every 100 ms used to keep it fresh forever. `acq == 0` (no sentence
    /// ever parsed) is never fresh.
    pub fn update_gps_at(&self, lat_deg7: i32, lon_deg7: i32, fix: u8, sats: u8, acq: u64) {
        self.gps_lat_udeg.store(deg7_to_udeg(lat_deg7), Ordering::Relaxed);
        self.gps_lon_udeg.store(deg7_to_udeg(lon_deg7), Ordering::Relaxed);
        self.gps_satellites.store(sats, Ordering::Relaxed);
        self.gps_fix.store(fix, Ordering::Relaxed);
        // Zero stays the "never updated" sentinel: a fix with no acquisition
        // time is not made fresh by being published.
        self.gps_updated_at.store(acq, Ordering::Release);
    }

    /// How long a GPS fix stays usable: 2 s, from the board's timebase.
    ///
    /// Not the IMU's 200 ms. The kernel publishes GPS at 10 Hz and common
    /// receivers produce 1-10 fixes a second, so 200 ms would be one or two
    /// periods and a scheduling hiccup under TCG would flap the fence to
    /// `Unknown`. Two seconds is twenty publishes at the kernel's rate and two
    /// fixes from a 1 Hz receiver; a wheeled robot at 1 m/s covers 2 m in it,
    /// small against any fence radius worth configuring.
    pub const GPS_MAX_AGE_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ * 2;

    pub fn update_timestamp(&self, ts: u64) {
        self.timestamp.store(ts, Ordering::Release);
    }

    // ── Consumer method (called by behavior_task) ────────────────────────

    /// Take an atomic snapshot of all sensor data into a SensorState.
    pub fn snapshot(&self, state: &mut crate::types::SensorState) {
        self.snapshot_at(state, azos_drv_sys::timebase::now());
    }

    /// [`snapshot`](Self::snapshot), judging freshness at `now` rather than at
    /// the clock's current reading.
    pub fn snapshot_at(&self, state: &mut crate::types::SensorState, now: u64) {
        state.accel_mg[0] = self.accel_x_mg.load(Ordering::Relaxed);
        state.accel_mg[1] = self.accel_y_mg.load(Ordering::Relaxed);
        state.accel_mg[2] = self.accel_z_mg.load(Ordering::Relaxed);
        state.gyro_mdps[0] = self.gyro_x_mdps.load(Ordering::Relaxed);
        state.gyro_mdps[1] = self.gyro_y_mdps.load(Ordering::Relaxed);
        state.gyro_mdps[2] = self.gyro_z_mdps.load(Ordering::Relaxed);
        // Valid AND fresh. `imu_valid` was a one-way latch, so a silent IMU
        // left every tilt, fall and spin check evaluating a frozen reading and
        // reporting it as good. Staleness is not a different kind of failure
        // from "no IMU" — it is worse, because the stale value looks safe.
        let imu_age = now
            .saturating_sub(self.imu_updated_at.load(Ordering::Relaxed));
        state.imu_valid = self.imu_valid.load(Ordering::Acquire)
            && imu_age < Self::IMU_MAX_AGE_TICKS;

        state.odom_dist_mm = self.odom_dist_mm.load(Ordering::Relaxed);
        state.odom_heading_cdeg = self.odom_heading_cdeg.load(Ordering::Relaxed);
        state.enc_left = self.enc_left.load(Ordering::Relaxed);
        state.enc_right = self.enc_right.load(Ordering::Relaxed);

        state.cam_dist_front = self.range_front.load(Ordering::Relaxed);
        state.cam_dist_right = self.range_right.load(Ordering::Relaxed);

        state.battery_mv = self.battery_mv.load(Ordering::Relaxed);
        state.temp_cdeg = self.temp_cdeg.load(Ordering::Relaxed);
        state.sensor_flags = self.sensor_flags.load(Ordering::Relaxed);

        // A stale fix is no fix: quality and satellites both read zero, so
        // `safety::geofence_status` returns `Unknown` whatever threshold it
        // applies. The position is passed through; nothing trusts it without
        // the quality.
        let gps_fresh = sample_is_fresh(
            self.gps_updated_at.load(Ordering::Acquire), now, Self::GPS_MAX_AGE_TICKS);
        state.gps_lat_udeg = self.gps_lat_udeg.load(Ordering::Relaxed);
        state.gps_lon_udeg = self.gps_lon_udeg.load(Ordering::Relaxed);
        state.gps_fix = if gps_fresh { self.gps_fix.load(Ordering::Relaxed) } else { 0 };
        state.gps_satellites =
            if gps_fresh { self.gps_satellites.load(Ordering::Relaxed) } else { 0 };

        state.timestamp = self.timestamp.load(Ordering::Acquire);
    }
}

/// Global sensor bus instance.
pub static SENSOR_BUS: SensorBus = SensorBus::new();

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! AHRS — Attitude and Heading Reference System (Phase I1 + I3).
//!
//! Complementary filter fusing accelerometer (gravity direction) with
//! gyroscope (angular rate integration) to estimate roll, pitch, and yaw.
//! Barometric altitude estimation from pressure readings.
//!
//! Phase I3: GPS course-over-ground corrects yaw drift when moving (speed > threshold).
//!
//! All arithmetic is integer (no `f32`, no `libm`).  Angles are in
//! centi-degrees (1/100 degree) to avoid floating-point entirely.
//!
//! # Channels
//!
//! - `CH_IMU`      — latest IMU reading (published by sensor task)
//! - `CH_BARO`     — latest barometer reading
//! - `CH_ATTITUDE` — estimated attitude (published by AHRS update)

use azos_channel::Channel;
use azos_imu::ImuData;
use azos_baro::BaroData;

// ── Channels ─────────────────────────────────────────────────────────────────

/// Channel for IMU readings (accel + gyro + temp).
pub static CH_IMU: Channel<ImuData> = Channel::new(ImuData {
    accel_mg:  [0; 3],
    gyro_mdps: [0; 3],
    temp_cdeg: 0,
});

/// Channel for barometer readings (pressure + temp).
pub static CH_BARO: Channel<BaroData> = Channel::new(BaroData {
    pressure_pa: 101325,
    temp_cdeg:   2500,
});

/// Channel for estimated attitude.
pub static CH_ATTITUDE: Channel<Attitude> = Channel::new(Attitude::new());

// ── Attitude type ────────────────────────────────────────────────────────────

/// Estimated attitude from AHRS fusion.
#[derive(Clone, Copy)]
pub struct Attitude {
    /// Roll angle in centi-degrees (-18000 .. +18000).
    pub roll_cdeg:  i32,
    /// Pitch angle in centi-degrees (-9000 .. +9000).
    pub pitch_cdeg: i32,
    /// Yaw angle in centi-degrees (0 .. 36000).  Gyro-only (drifts without mag).
    pub yaw_cdeg:   i32,
    /// Barometric altitude in centimetres relative to reference pressure.
    pub alt_cm:     i32,
}

impl Attitude {
    pub const fn new() -> Self {
        Attitude { roll_cdeg: 0, pitch_cdeg: 0, yaw_cdeg: 0, alt_cm: 0 }
    }
}

// ── AHRS state ───────────────────────────────────────────────────────────────

/// AHRS filter state.  Call `update()` at a fixed rate (100-1000 Hz).
/// Optionally call `update_gps()` at GPS rate (~10 Hz) for yaw correction.
pub struct AhrsState {
    /// Current roll estimate (centi-degrees).
    roll_cdeg:  i32,
    /// Current pitch estimate (centi-degrees).
    pitch_cdeg: i32,
    /// Current yaw estimate (centi-degrees, gyro-integrated, drifts without GPS).
    yaw_cdeg:   i32,
    /// Reference pressure at init time (Pa) for relative altitude.
    ref_pressure_pa: u32,
    /// Complementary filter alpha (0-1000, where 1000 = 1.0).
    /// Default 980 = trust gyro 98%, accel 2%.
    alpha: u32,
    /// Phase I3: GPS-corrected yaw (centi-degrees, 0..36000).
    /// Updated when GPS speed > threshold and fix >= 2D.
    gps_yaw_cdeg: i32,
    /// Phase I3: true if we have a valid GPS heading.
    gps_yaw_valid: bool,
    /// Phase I3: yaw complementary filter alpha for GPS correction.
    /// Default 950 = trust gyro 95%, GPS 5% when moving.
    yaw_alpha: u32,
}

impl AhrsState {
    /// Create a new AHRS state with default alpha=0.98, yaw_alpha=0.95.
    pub const fn new() -> Self {
        AhrsState {
            roll_cdeg:  0,
            pitch_cdeg: 0,
            yaw_cdeg:   0,
            ref_pressure_pa: 101325,
            alpha: 980,
            gps_yaw_cdeg: 0,
            gps_yaw_valid: false,
            yaw_alpha: 950,
        }
    }

    /// Set reference pressure (call once after baro stabilises on boot).
    pub fn set_ref_pressure(&mut self, pa: u32) {
        self.ref_pressure_pa = pa;
    }

    /// Phase I3: feed GPS data for yaw correction.
    ///
    /// Call at GPS rate (~10 Hz).  Only corrects yaw when moving
    /// (speed > 100 cm/s = 1 m/s) and fix >= 2D.
    /// GPS course-over-ground is used as a heading reference.
    pub fn update_gps(&mut self, gps: &azos_gps::GpsPosition) {
        // Need at least a 2D fix and moving above 1 m/s for course to be reliable.
        if gps.fix >= 1 && gps.speed_cms > 100 {
            self.gps_yaw_cdeg = gps.course_cdeg as i32;
            self.gps_yaw_valid = true;
        }
    }

    /// Run one AHRS update cycle.
    ///
    /// - `imu`: latest scaled IMU data (accel in milli-g, gyro in milli-deg/s).
    /// - `baro_pa`: latest barometric pressure in Pascals.
    /// - `dt_us`: time delta since last call in microseconds.
    ///
    /// Returns the estimated [`Attitude`].
    pub fn update(&mut self, imu: &ImuData, baro_pa: u32, dt_us: u32) -> Attitude {
        let ax = imu.accel_mg[0];
        let ay = imu.accel_mg[1];
        let az = imu.accel_mg[2];
        let gx = imu.gyro_mdps[0]; // milli-deg/s
        let gy = imu.gyro_mdps[1];
        let gz = imu.gyro_mdps[2];

        // ── Accelerometer-derived angles (centi-degrees) ─────────────
        // roll  = atan2(ay, az)
        // pitch = atan2(-ax, sqrt(ay²+az²))
        let accel_roll  = atan2_cdeg(ay, az);
        let mag_yz      = isqrt((ay as i64 * ay as i64 + az as i64 * az as i64) as u64) as i32;
        let accel_pitch = atan2_cdeg(-ax, mag_yz);

        // ── Gyroscope integration ────────────────────────────────────
        // Δangle = gyro_mdps * dt_us / 1_000_000   (milli-deg)
        // then /1000 → deg, *100 → cdeg
        // Combined: Δcdeg = gyro_mdps * dt_us / 10_000_000
        let dt = dt_us as i64;
        let d_roll  = (gx as i64 * dt / 10_000_000) as i32;
        let d_pitch = (gy as i64 * dt / 10_000_000) as i32;
        let d_yaw   = (gz as i64 * dt / 10_000_000) as i32;

        // ── Complementary filter (roll, pitch) ───────────────────────
        // out = alpha * (prev + gyro_delta) + (1-alpha) * accel_angle
        let a = self.alpha as i32;
        let b = 1000 - a;

        self.roll_cdeg  = (a * (self.roll_cdeg  + d_roll)  + b * accel_roll)  / 1000;
        self.pitch_cdeg = (a * (self.pitch_cdeg + d_pitch) + b * accel_pitch) / 1000;

        // ── Yaw: gyro + GPS correction (Phase I3) ────────────────────
        // Without GPS: pure gyro integration (drifts).
        // With GPS (when moving): complementary filter using GPS course as reference.
        let gyro_yaw = (self.yaw_cdeg + d_yaw) % 36000;
        let gyro_yaw = if gyro_yaw < 0 { gyro_yaw + 36000 } else { gyro_yaw };

        if self.gps_yaw_valid {
            // Complementary filter for yaw: trust gyro 95%, GPS 5%.
            // Handle wrap-around: find shortest angular distance.
            let ya = self.yaw_alpha as i32;
            let yb = 1000 - ya;
            let mut err = self.gps_yaw_cdeg - gyro_yaw;
            if err > 18000 { err -= 36000; }
            if err < -18000 { err += 36000; }
            // fused = gyro_yaw + yb/1000 * error
            self.yaw_cdeg = (gyro_yaw + yb * err / 1000) % 36000;
            if self.yaw_cdeg < 0 { self.yaw_cdeg += 36000; }
            let _ = ya; // suppress unused warning
        } else {
            self.yaw_cdeg = gyro_yaw;
        }

        // ── Barometric altitude ──────────────────────────────────────
        // Linear approximation: alt_cm = (ref - current) * 83 / 10
        let dp = self.ref_pressure_pa as i32 - baro_pa as i32;
        let alt_cm = dp * 83 / 10;

        Attitude {
            roll_cdeg:  self.roll_cdeg,
            pitch_cdeg: self.pitch_cdeg,
            yaw_cdeg:   self.yaw_cdeg,
            alt_cm,
        }
    }
}

// ── Integer math helpers ─────────────────────────────────────────────────────

/// Integer atan2 returning centi-degrees (-18000 .. +18000).
///
/// Uses a polynomial approximation of atan(y/x) scaled to avoid floats.
/// Accuracy: ~0.3 degree (30 cdeg) max error.
fn atan2_cdeg(y: i32, x: i32) -> i32 {
    if x == 0 && y == 0 { return 0; }

    // atan2 quadrant logic
    let abs_y = (y as i64).unsigned_abs().max(1) as i64;
    let abs_x = (x as i64).unsigned_abs() as i64;

    // atan approximation for |angle| <= 45 deg (ratio <= 1.0):
    // atan(r) ≈ r * 4500 / (1.0 + 0.28 * r²)   [in cdeg]
    // where r = min/max, then adjust for quadrant.
    let (ratio_num, ratio_den, _base_cdeg) = if abs_x >= abs_y {
        // |angle| <= 45 deg
        (abs_y, abs_x, 0i32)
    } else {
        // 45 < |angle| <= 90 deg: atan(y/x) = 90 - atan(x/y)
        (abs_x, abs_y, 9000i32)
    };

    // r_1000 = ratio * 1000  (fixed-point with 3 decimal places)
    let r_1000 = (ratio_num * 1000 / ratio_den) as i32;
    // r² / 1000 (to keep in range)
    let r2 = r_1000 as i64 * r_1000 as i64 / 1000;
    // atan ≈ r * 4500 / (1000 + 280 * r²/1000)
    let numer = r_1000 as i64 * 4500;
    let denom = 1000 + 280 * r2 / 1000;
    let atan_cdeg = if denom == 0 { 4500 } else { (numer / denom) as i32 };

    let angle = if abs_x >= abs_y {
        atan_cdeg
    } else {
        9000 - atan_cdeg
    };

    // Apply quadrant: result is in 0..9000
    // Map to full -18000..+18000 based on signs of x, y
    if x >= 0 && y >= 0 {
        angle
    } else if x < 0 && y >= 0 {
        18000 - angle
    } else if x < 0 && y < 0 {
        -(18000 - angle)
    } else {
        // x >= 0 && y < 0
        -angle
    }
}

/// Integer square root (Babylonian method).
fn isqrt(n: u64) -> u64 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Print current attitude to UART.
pub fn attitude_info() {
    let snap = CH_ATTITUDE.read();
    if snap.seq == 0 {
        azos_drv_sys::kconsoleln!("[AHRS] No attitude data (sensor task not running)");
        return;
    }
    let att = snap.val;
    // Print as degrees with 2 decimal places from cdeg.
    let r_sign = if att.roll_cdeg  < 0 { "-" } else { "" };
    let p_sign = if att.pitch_cdeg < 0 { "-" } else { "" };
    let a_sign = if att.alt_cm     < 0 { "-" } else { "" };
    let r_abs = att.roll_cdeg.unsigned_abs();
    let p_abs = att.pitch_cdeg.unsigned_abs();
    let a_abs = att.alt_cm.unsigned_abs();

    azos_drv_sys::kconsoleln!("[AHRS] roll={}{}.{:02} pitch={}{}.{:02} yaw={}.{:02} alt={}{}.{:02}m",
        r_sign, r_abs / 100, r_abs % 100,
        p_sign, p_abs / 100, p_abs % 100,
        att.yaw_cdeg / 100, (att.yaw_cdeg % 100) as u32,
        a_sign, a_abs / 100, a_abs % 100,
    );
    azos_drv_sys::kconsoleln!("[AHRS] seq={} age={} ticks",
        snap.seq,
        CH_ATTITUDE.age(azos_drv_sys::timebase::now()));
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Software In The Loop (SITL) simulation (D02).
//!
//! Simulates quadrotor dynamics to enable closed-loop testing of the flight
//! controller without hardware.  The simulator feeds synthetic IMU and GPS
//! data into the EKF and receives actuator commands from the mixer.
//!
//! ## Physics model (simplified)
//!
//! Rigid-body quadrotor:
//! - Thrust proportional to motor² (motor command 0-1000 → normalized 0-1).
//! - Drag proportional to velocity.
//! - Euler angle integration from angular rates.
//!
//! ## Usage
//! ```rust
//! sitl_reset([0, 0, -1000]);   // start at 1 m altitude
//! let imu = sitl_step(dt_ms, &motors);  // advance physics, get simulated IMU
//! ```
//!
//! All units follow the AzOS convention: mm, mm/s, centi-degrees.

// ── Constants ─────────────────────────────────────────────────────────────────

/// Total vehicle mass in grams (500 g = 0.5 kg typical 5" quad).
pub const SITL_MASS_G: i32 = 500;
/// Maximum thrust per motor in milli-Newtons (4 motors × 300 mN = 1.2 N total).
pub const SITL_MAX_THRUST_MN: i32 = 300;
/// Aerodynamic drag coefficient × 1000 (dimensionless, tuned empirically).
pub const SITL_DRAG_COEFF: i32 = 50;
/// Motor time constant in milliseconds (motors lag behind commands).
pub const SITL_MOTOR_TC_MS: i32 = 30;
/// Gravity in mm/s².
const SITL_G: i32 = 9_810;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Simulated vehicle state.
#[derive(Clone, Copy, Default)]
pub struct SitlState {
    /// NED position (mm).
    pub pos: [i32; 3],
    /// NED velocity (mm/s).
    pub vel: [i32; 3],
    /// Attitude: roll, pitch, yaw (centi-degrees).
    pub att: [i32; 3],
    /// Angular rates: roll, pitch, yaw (milli-degrees/s).
    pub rates: [i32; 3],
    /// Actual motor outputs (0-1000) after lag filter.
    pub motor_actual: [i16; 4],
}

/// Simulated IMU reading (as seen by the flight controller).
#[derive(Clone, Copy, Default)]
pub struct SitlImu {
    /// Accelerometer readings (milli-g, body frame).
    pub accel_mg:  [i32; 3],
    /// Gyroscope readings (milli-degrees/s, body frame).
    pub gyro_mdps: [i32; 3],
}

// ── Global state ──────────────────────────────────────────────────────────────

use azos_sync::SpinLock;

static SITL: SpinLock<SitlState> = SpinLock::new(SitlState {
    pos:          [0; 3],
    vel:          [0; 3],
    att:          [0; 3],
    rates:        [0; 3],
    motor_actual: [0; 4],
});

// ── API ───────────────────────────────────────────────────────────────────────

/// Reset the simulator to a given NED start position (mm).
pub fn sitl_reset(start_pos_mm: [i32; 3]) {
    let mut s = SITL.lock();
    *s = SitlState {
        pos:          start_pos_mm,
        vel:          [0; 3],
        att:          [0; 3],
        rates:        [0; 3],
        motor_actual: [0; 4],
    };
}

/// Advance the simulation by `dt_ms` milliseconds.
///
/// `motors[4]`: commanded motor outputs (0-1000).
/// Returns the simulated IMU reading for this step.
pub fn sitl_step(dt_ms: u32, motors: &[u16; 4]) -> SitlImu {
    let mut s = SITL.lock();
    let dt = dt_ms as i32;

    // ── Motor lag filter ───────────────────────────────────────────────────
    for i in 0..4 {
        let cmd = motors[i] as i32;
        let actual = s.motor_actual[i] as i32;
        // First-order lag: actual += (cmd - actual) × dt / TC
        let delta = (cmd - actual) * dt / SITL_MOTOR_TC_MS;
        s.motor_actual[i] = (actual + delta).clamp(0, 1000) as i16;
    }

    // ── Thrust computation ─────────────────────────────────────────────────
    // Total thrust (mN) = sum(motor² / 1000) × MAX_THRUST per motor
    let mut total_thrust_mn: i64 = 0;
    for &m in &s.motor_actual {
        let m = m as i64;
        total_thrust_mn += m * m * SITL_MAX_THRUST_MN as i64 / 1_000_000;
    }

    // ── Net force (NED, mN) ────────────────────────────────────────────────
    // Gravity: +Z (down). Thrust: -Z (up) for a flat hover.
    // For simplicity, ignore roll/pitch tilt effects on thrust direction.
    let gravity_force = SITL_MASS_G as i64 * SITL_G as i64 / 1_000; // mN
    let net_z_mn = gravity_force - total_thrust_mn;

    // ── Acceleration (mm/s²) ──────────────────────────────────────────────
    // a = F / m;  F in mN, m in g → a = F/m × 1000 (unit conversion)
    let acc_z = net_z_mn * 1_000 / SITL_MASS_G as i64; // mm/s²

    // ── Drag ──────────────────────────────────────────────────────────────
    // Fd = -DRAG_COEFF × v / 1000
    let drag_n = -s.vel[0] as i64 * SITL_DRAG_COEFF as i64 / 1_000;
    let drag_e = -s.vel[1] as i64 * SITL_DRAG_COEFF as i64 / 1_000;

    // ── Velocity integration ───────────────────────────────────────────────
    let acc_n = drag_n * 1_000 / SITL_MASS_G as i64;
    let acc_e = drag_e * 1_000 / SITL_MASS_G as i64;
    s.vel[0] += (acc_n * dt as i64 / 1_000) as i32;
    s.vel[1] += (acc_e * dt as i64 / 1_000) as i32;
    s.vel[2] += (acc_z * dt as i64 / 1_000) as i32;

    // ── Position integration ───────────────────────────────────────────────
    s.pos[0] += s.vel[0] * dt / 1_000;
    s.pos[1] += s.vel[1] * dt / 1_000;
    s.pos[2] += s.vel[2] * dt / 1_000;

    // Ground clamp: Z down cannot exceed 0 (ground level).
    if s.pos[2] > 0 {
        s.pos[2] = 0;
        if s.vel[2] > 0 { s.vel[2] = 0; }
    }

    // ── Synthesize IMU ────────────────────────────────────────────────────
    // Accelerometer measures specific force = (a - g) in body frame.
    // In level hover: accel_z = -g (reads 1g up = -1000 mg in body Z).
    let body_acc_z = acc_z - SITL_G as i64;
    let imu = SitlImu {
        accel_mg:  [
            (acc_n * 1_000 / SITL_G as i64) as i32,
            (acc_e * 1_000 / SITL_G as i64) as i32,
            (body_acc_z * 1_000 / SITL_G as i64) as i32,
        ],
        gyro_mdps: s.rates,
    };
    imu
}

/// Get current simulated position (NED, mm).
pub fn sitl_position() -> [i32; 3] { SITL.lock().pos }

/// Get current simulated velocity (NED, mm/s).
pub fn sitl_velocity() -> [i32; 3] { SITL.lock().vel }

/// Get current simulated altitude above ground (mm, positive = up).
pub fn sitl_altitude_mm() -> i32 { -SITL.lock().pos[2] }

/// Get full simulator state snapshot.
pub fn sitl_state() -> SitlState { *SITL.lock() }

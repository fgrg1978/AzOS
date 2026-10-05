// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Extended Kalman Filter for drone navigation (D01).
//!
//! Fuses IMU (accelerometer + gyroscope), GPS, barometer, and optical flow
//! into a 9-state navigation solution using integer fixed-point arithmetic.
//!
//! ## State vector (×1000 fixed-point)
//! ```text
//! x = [ pos_north_mm, pos_east_mm, pos_down_mm,   // position NED
//!        vel_north_mms, vel_east_mms, vel_down_mms, // velocity NED
//!        roll_cdeg, pitch_cdeg, yaw_cdeg ]           // attitude (centi-degrees)
//! ```
//!
//! ## Update cycle
//! 1. `ekf_predict(dt_ms, accel_mg[3], gyro_mdps[3])` — IMU propagation at 100 Hz.
//! 2. `ekf_update_gps(lat_mm, lon_mm, alt_mm, vel_n_mms, vel_e_mms)` — GPS at 5-10 Hz.
//! 3. `ekf_update_baro(alt_mm)` — barometer at 25 Hz.
//! 4. `ekf_update_flow(dx_mm, dy_mm)` — optical flow at 100-200 Hz.
//!
//! ## Design decisions
//! - **Integer only**: all values scaled by 1000 (milli-units) to avoid floats.
//! - **Diagonal P matrix**: off-diagonal covariance terms dropped to save RAM.
//!   This makes it a "simplified EKF" (parallel Kalman filters per dimension).
//! - **Decoupled axes**: north/east/down estimated independently.
//!
//! ## Coordinate frame
//! NED (North-East-Down): X=North, Y=East, Z=Down (positive into earth).
//! Altitude above ground = negative Z.

use core::sync::atomic::{AtomicBool, Ordering};
use azos_sync::SpinLock;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Fixed-point scale factor (values stored as integer × EKF_SCALE).
pub const EKF_SCALE: i64 = 1_000;

/// Process noise covariance for position states (mm²/step × scale).
const Q_POS: i64 = 100 * EKF_SCALE;
/// Process noise covariance for velocity states (mm²/s² × scale).
const Q_VEL: i64 = 500 * EKF_SCALE;
/// Process noise covariance for attitude states (cdeg²/step × scale).
const Q_ATT: i64 = 10 * EKF_SCALE;

/// Measurement noise for GPS position (mm²).
const R_GPS_POS: i64 = 1_000_000 * EKF_SCALE; // 1 m standard deviation
/// Measurement noise for GPS velocity (mm²/s²).
const R_GPS_VEL: i64 = 40_000 * EKF_SCALE;    // 200 mm/s std dev
/// Measurement noise for barometer altitude (mm²).
const R_BARO:    i64 = 10_000 * EKF_SCALE;    // 100 mm std dev
/// Measurement noise for optical flow velocity (mm²/s²).
const R_FLOW:    i64 = 5_000 * EKF_SCALE;     // 70 mm/s std dev

/// Gravity in mm/s² (9.81 m/s² = 9810 mm/s²).
const GRAVITY_MMSQ: i64 = 9_810;

// ── State ─────────────────────────────────────────────────────────────────────

/// EKF navigation state.
#[derive(Clone, Copy, Default)]
pub struct EkfState {
    /// Position: North, East, Down (mm).
    pub pos: [i64; 3],
    /// Velocity: North, East, Down (mm/s).
    pub vel: [i64; 3],
    /// Attitude: roll, pitch, yaw (centi-degrees).
    pub att: [i64; 3],
    /// Diagonal covariance — one element per state.
    pub cov: [i64; 9],
    /// EKF is initialized (has a valid origin).
    pub valid: bool,
}

struct EkfInner {
    state: EkfState,
}

static EKF: SpinLock<EkfInner> = SpinLock::new(EkfInner {
    state: EkfState { pos: [0;3], vel: [0;3], att: [0;3], cov: [EKF_SCALE; 9], valid: false },
});

static EKF_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ── Initialization ────────────────────────────────────────────────────────────

/// Initialize EKF with a GPS origin fix.
///
/// `init_alt_mm`: MSL altitude at the takeoff point.
pub fn ekf_init(init_alt_mm: i64) {
    let mut ekf = EKF.lock();
    ekf.state = EkfState {
        pos: [0, 0, -init_alt_mm],  // NED: down = negative altitude
        vel: [0, 0, 0],
        att: [0, 0, 0],
        cov: [EKF_SCALE * 1000; 9], // high initial uncertainty
        valid: true,
    };
    EKF_INITIALIZED.store(true, Ordering::Release);
}

// ── Predict step ──────────────────────────────────────────────────────────────

/// EKF predict step — propagate state using IMU readings.
///
/// - `dt_ms`: time step in milliseconds (typically 10 ms at 100 Hz).
/// - `accel_mg`: accelerometer readings in milli-g (body frame, [x, y, z]).
/// - `gyro_mdps`: gyroscope readings in milli-degrees/sec ([roll, pitch, yaw]).
pub fn ekf_predict(dt_ms: u32, accel_mg: [i32; 3], gyro_mdps: [i32; 3]) {
    if !EKF_INITIALIZED.load(Ordering::Acquire) { return; }
    let mut ekf = EKF.lock();
    let s = &mut ekf.state;

    let dt = dt_ms as i64;

    // ── Attitude integration (Euler method, small angle) ──────────────────
    // gyro_mdps → cdeg/step: (mdps × dt_ms) / (1000 ms/s × 100 cdeg/deg)
    s.att[0] += gyro_mdps[0] as i64 * dt / 100_000; // roll (cdeg)
    s.att[1] += gyro_mdps[1] as i64 * dt / 100_000; // pitch
    s.att[2] += gyro_mdps[2] as i64 * dt / 100_000; // yaw
    // Wrap yaw to [0, 36000) cdeg
    while s.att[2] >= 36_000 { s.att[2] -= 36_000; }
    while s.att[2] < 0       { s.att[2] += 36_000; }

    // ── Gravity removal (body → NED, simplified for small angles) ─────────
    // For small roll/pitch (<30°): a_N ≈ ax, a_E ≈ ay, a_D ≈ az - g
    let ax_mmsq = accel_mg[0] as i64 * GRAVITY_MMSQ / 1000; // mg → mm/s²
    let ay_mmsq = accel_mg[1] as i64 * GRAVITY_MMSQ / 1000;
    let az_mmsq = accel_mg[2] as i64 * GRAVITY_MMSQ / 1000 - GRAVITY_MMSQ;

    // ── Velocity integration: vel += a × dt ───────────────────────────────
    s.vel[0] += ax_mmsq * dt / 1000;
    s.vel[1] += ay_mmsq * dt / 1000;
    s.vel[2] += az_mmsq * dt / 1000;

    // ── Position integration: pos += vel × dt ─────────────────────────────
    s.pos[0] += s.vel[0] * dt / 1000;
    s.pos[1] += s.vel[1] * dt / 1000;
    s.pos[2] += s.vel[2] * dt / 1000;

    // ── Covariance propagation (diagonal approximation) ───────────────────
    // P_k|k-1 = F P F' + Q  →  diagonal: P[i] += Q[i]
    s.cov[0] += Q_POS; s.cov[1] += Q_POS; s.cov[2] += Q_POS;
    s.cov[3] += Q_VEL; s.cov[4] += Q_VEL; s.cov[5] += Q_VEL;
    s.cov[6] += Q_ATT; s.cov[7] += Q_ATT; s.cov[8] += Q_ATT;
}

// ── Measurement updates ───────────────────────────────────────────────────────

/// Scalar Kalman update: x += K(z - Hx);  P -= K H P.
/// Returns new state and covariance after update.
fn scalar_update(x: i64, p: i64, z: i64, r: i64) -> (i64, i64) {
    // Innovation: y = z - x (H=I for direct measurement)
    let y = z - x;
    // Innovation covariance: S = P + R
    let s = p + r;
    if s == 0 { return (x, p); }
    // Kalman gain: K = P / S (scaled to avoid overflow)
    // We work in fixed-point: K × 1000 = P × 1000 / S
    let k_scaled = p * 1000 / s;
    // State update: x += K × y
    let x_new = x + k_scaled * y / 1000;
    // Covariance update: P = (1 - K) × P = P - K × P
    let p_new = p - k_scaled * p / 1000;
    (x_new, p_new.max(EKF_SCALE)) // enforce minimum covariance
}

/// GPS measurement update.
///
/// `north_mm`, `east_mm`, `down_mm`: position relative to EKF origin.
/// `vel_n_mms`, `vel_e_mms`: GPS velocity in mm/s.
pub fn ekf_update_gps(
    north_mm: i64, east_mm: i64, down_mm: i64,
    vel_n_mms: i64, vel_e_mms: i64,
) {
    if !EKF_INITIALIZED.load(Ordering::Acquire) { return; }
    let mut ekf = EKF.lock();
    let s = &mut ekf.state;
    (s.pos[0], s.cov[0]) = scalar_update(s.pos[0], s.cov[0], north_mm, R_GPS_POS);
    (s.pos[1], s.cov[1]) = scalar_update(s.pos[1], s.cov[1], east_mm,  R_GPS_POS);
    (s.pos[2], s.cov[2]) = scalar_update(s.pos[2], s.cov[2], down_mm,  R_GPS_POS);
    (s.vel[0], s.cov[3]) = scalar_update(s.vel[0], s.cov[3], vel_n_mms, R_GPS_VEL);
    (s.vel[1], s.cov[4]) = scalar_update(s.vel[1], s.cov[4], vel_e_mms, R_GPS_VEL);
}

/// Barometer measurement update.
///
/// `alt_mm`: altitude above reference in mm (positive up = negative NED down).
pub fn ekf_update_baro(alt_mm: i64) {
    if !EKF_INITIALIZED.load(Ordering::Acquire) { return; }
    let down_mm = -alt_mm;
    let mut ekf = EKF.lock();
    let s = &mut ekf.state;
    (s.pos[2], s.cov[2]) = scalar_update(s.pos[2], s.cov[2], down_mm, R_BARO);
}

/// Optical flow velocity update.
///
/// `vel_n_mms`, `vel_e_mms`: estimated velocity from optical flow (mm/s).
pub fn ekf_update_flow(vel_n_mms: i64, vel_e_mms: i64) {
    if !EKF_INITIALIZED.load(Ordering::Acquire) { return; }
    let mut ekf = EKF.lock();
    let s = &mut ekf.state;
    (s.vel[0], s.cov[3]) = scalar_update(s.vel[0], s.cov[3], vel_n_mms, R_FLOW);
    (s.vel[1], s.cov[4]) = scalar_update(s.vel[1], s.cov[4], vel_e_mms, R_FLOW);
}

// ── State accessors ───────────────────────────────────────────────────────────

/// Get a snapshot of the current EKF state.
pub fn ekf_state() -> EkfState { EKF.lock().state }

/// Get altitude above takeoff point in mm (positive = up).
pub fn ekf_altitude_mm() -> i64 { -EKF.lock().state.pos[2] }

/// Get horizontal position (north_mm, east_mm).
pub fn ekf_position_ne() -> (i64, i64) {
    let s = EKF.lock().state;
    (s.pos[0], s.pos[1])
}

/// Get velocity in NED frame (mm/s).
pub fn ekf_velocity_ned() -> [i64; 3] { EKF.lock().state.vel }

/// Returns true if the EKF has a valid state estimate.
pub fn ekf_valid() -> bool { EKF_INITIALIZED.load(Ordering::Acquire) }

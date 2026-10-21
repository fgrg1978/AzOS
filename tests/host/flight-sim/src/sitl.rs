// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Quadrotor SITL physics — stateless mirror of flight/src/sitl.rs (D02).
//!
//! Re-implements the physics update as a pure function that takes `SitlState`
//! by value and returns `(new_state, imu)`.  No global atomics → directly
//! testable on the host.

// ── Constants ─────────────────────────────────────────────────────────────────

/// Total vehicle mass in grams.
pub const SITL_MASS_G: i32 = 500;
/// Maximum thrust per motor in milli-Newtons.
pub const SITL_MAX_THRUST_MN: i32 = 300;
/// Aerodynamic drag coefficient × 1000.
pub const SITL_DRAG_COEFF: i32 = 50;
/// Motor first-order time constant (ms).
pub const SITL_MOTOR_TC_MS: i32 = 30;
/// Gravity acceleration (mm/s²).
pub const SITL_G: i32 = 9_810;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Simulated vehicle state (all values use AzOS units).
#[derive(Clone, Copy, Default, Debug)]
pub struct SitlState {
    pub pos:          [i32; 3], // NED mm
    pub vel:          [i32; 3], // NED mm/s
    pub att:          [i32; 3], // roll/pitch/yaw cdeg
    pub rates:        [i32; 3], // roll/pitch/yaw mdps
    pub motor_actual: [i16; 4], // 0-1000
}

/// Simulated IMU output.
#[derive(Clone, Copy, Default, Debug)]
pub struct SitlImu {
    pub accel_mg:  [i32; 3], // milli-g, body frame
    pub gyro_mdps: [i32; 3], // milli-deg/s, body frame
}

// ── Pure step function ────────────────────────────────────────────────────────

/// Advance simulator state by `dt_ms` with commanded `motors[4]` (0-1000).
///
/// Returns `(new_state, imu)`.
pub fn sitl_step_pure(s: SitlState, dt_ms: u32, motors: &[u16; 4]) -> (SitlState, SitlImu) {
    let mut s = s;
    let dt = dt_ms as i32;

    // Motor lag filter.
    for i in 0..4 {
        let cmd    = motors[i] as i32;
        let actual = s.motor_actual[i] as i32;
        let delta  = (cmd - actual) * dt / SITL_MOTOR_TC_MS;
        s.motor_actual[i] = (actual + delta).clamp(0, 1000) as i16;
    }

    // Total thrust (mN): sum(motor² / 1e6 × MAX_THRUST).
    let mut total_thrust_mn: i64 = 0;
    for &m in &s.motor_actual {
        let m = m as i64;
        total_thrust_mn += m * m * SITL_MAX_THRUST_MN as i64 / 1_000_000;
    }

    // Net Z force (NED, mN): gravity down (+Z), thrust up (-Z).
    let gravity_force = SITL_MASS_G as i64 * SITL_G as i64 / 1_000; // mN
    let net_z_mn = gravity_force - total_thrust_mn;

    // Acceleration (mm/s²) — F/m with unit conversion.
    let acc_z = net_z_mn * 1_000 / SITL_MASS_G as i64;

    // Horizontal drag.
    let drag_n = -s.vel[0] as i64 * SITL_DRAG_COEFF as i64 / 1_000;
    let drag_e = -s.vel[1] as i64 * SITL_DRAG_COEFF as i64 / 1_000;
    let acc_n  = drag_n * 1_000 / SITL_MASS_G as i64;
    let acc_e  = drag_e * 1_000 / SITL_MASS_G as i64;

    // Velocity integration.
    s.vel[0] += (acc_n * dt as i64 / 1_000) as i32;
    s.vel[1] += (acc_e * dt as i64 / 1_000) as i32;
    s.vel[2] += (acc_z * dt as i64 / 1_000) as i32;

    // Position integration.
    s.pos[0] += s.vel[0] * dt / 1_000;
    s.pos[1] += s.vel[1] * dt / 1_000;
    s.pos[2] += s.vel[2] * dt / 1_000;

    // Ground clamp: Z (NED down) cannot exceed 0 (ground).
    if s.pos[2] > 0 {
        s.pos[2] = 0;
        if s.vel[2] > 0 { s.vel[2] = 0; }
    }

    // Synthesize IMU (specific force, body Z is reversed from NED Z).
    let body_acc_z = acc_z - SITL_G as i64;
    let imu = SitlImu {
        accel_mg: [
            (acc_n * 1_000 / SITL_G as i64) as i32,
            (acc_e * 1_000 / SITL_G as i64) as i32,
            (body_acc_z * 1_000 / SITL_G as i64) as i32,
        ],
        gyro_mdps: s.rates,
    };

    (s, imu)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Kept for the derivation in its body, not for its return value: it is
    /// the worked proof that a motionless hover is impossible with these
    /// constants at full throttle, which is why every dynamics test below uses
    /// mid-throttle instead. Deleting it would delete the reason.
    #[allow(dead_code)]
    fn hover_motors() -> [u16; 4] {
        // At hover: total thrust ≈ gravity force.
        // gravity_force = 500 × 9810 / 1000 = 4905 mN
        // per motor: 4905 / 4 = 1226 mN → motor² × 300 / 1e6 = 1226
        //   motor² = 1226 × 1e6 / 300 = 4 086 667 → motor ≈ 2022 (> 1000, saturates)
        // With max motor=1000: total thrust = 4 × 1000² × 300 / 1e6 = 1200 mN < gravity
        // So a motionless hover is NOT possible with these constants at full throttle.
        // Use mid-throttle for tests that exercise dynamics without hovering.
        [500, 500, 500, 500]
    }

    /// Motors at zero: gravity pulls downward (Z velocity increases in NED).
    /// Must start in the air to avoid the ground clamp zeroing velocity.
    #[test]
    fn gravity_increases_z_velocity() {
        // Start 10 m above ground (NED: z = -10_000 mm).
        let s0 = SitlState { pos: [0, 0, -10_000], ..Default::default() };
        let motors = [0u16; 4];
        let (s1, _) = sitl_step_pure(s0, 100, &motors);
        // Gravity → net_z_mn = gravity_force → acc_z > 0 → vel[2] increases.
        assert!(s1.vel[2] > 0, "Z velocity should increase under gravity, got {}", s1.vel[2]);
    }

    /// With motors off, vehicle falls and is clamped at ground (z=0 NED).
    #[test]
    fn free_fall_z_clamped_at_ground() {
        let mut s = SitlState { pos: [0, 0, -1_000], ..Default::default() }; // 1 m up
        let motors = [0u16; 4];
        for _ in 0..100 {
            let (ns, _) = sitl_step_pure(s, 20, &motors);
            s = ns;
            if s.pos[2] >= 0 { break; }
        }
        assert!(s.pos[2] >= 0, "Should clamp at ground (z≥0 NED), got {}", s.pos[2]);
        assert!(s.vel[2] <= 0, "Should not have upward velocity at ground clamp");
    }

    /// Started above ground: should fall to 0 and clamp.
    #[test]
    fn falls_to_ground_clamp() {
        let s0 = SitlState { pos: [0, 0, -5_000], ..Default::default() }; // 5 m altitude
        let mut s = s0;
        let motors = [0u16; 4];
        for _ in 0..500 {
            let (ns, _) = sitl_step_pure(s, 20, &motors);
            s = ns;
            if s.pos[2] >= 0 { break; }
        }
        assert!(s.pos[2] >= 0, "Z should clamp at or above 0, got {}", s.pos[2]);
        assert!(s.vel[2] <= 0 || s.pos[2] == 0, "Velocity should be zero at ground");
    }

    /// Motor lag: actual motor responds exponentially toward commanded.
    #[test]
    fn motor_lag_approaches_cmd() {
        let s0 = SitlState { pos: [0, 0, -10_000], ..Default::default() };
        let motors = [1000u16; 4]; // command full throttle
        // After many steps (t >> TC=30ms), actual should converge close to 1000.
        // Integer truncation prevents reaching exactly 1000, so accept ≥ 990.
        let mut s = s0;
        for _ in 0..200 {
            let (ns, _) = sitl_step_pure(s, 5, &motors);
            s = ns;
        }
        assert!(s.motor_actual[0] >= 990,
            "Motor actual should converge near cmd after lag, got {}", s.motor_actual[0]);
    }

    /// IMU Z axis reads -1g when falling freely (specific force = a - g).
    #[test]
    fn imu_free_fall_reads_zero_g() {
        // In free fall: accel = g, body_acc_z = g - g = 0 → accel_mg[2] = 0.
        let s0 = SitlState { pos: [0, 0, -10_000], ..Default::default() };
        let (_, imu) = sitl_step_pure(s0, 10, &[0u16; 4]);
        // body_acc_z = acc_z - G = (gravity_force / mass) - G ≈ 0 for small dt
        // accel_mg[2] ≈ 0 (within rounding)
        assert!(imu.accel_mg[2].abs() <= 10,
            "Free-fall IMU Z should be ~0 mg, got {}", imu.accel_mg[2]);
    }

    /// High throttle reduces downward acceleration.
    #[test]
    fn high_throttle_reduces_z_accel() {
        let s0 = SitlState { pos: [0, 0, -5_000], ..Default::default() };
        let (s_low,  _) = sitl_step_pure(s0, 100, &[0u16;    4]);
        let (s_high, _) = sitl_step_pure(s0, 100, &[1000u16; 4]);
        // With high throttle, Z velocity should increase less (more thrust fighting gravity).
        assert!(s_high.vel[2] < s_low.vel[2],
            "Higher throttle should produce less downward vel: {} vs {}",
            s_high.vel[2], s_low.vel[2]);
    }

    /// Horizontal: no motors provide horizontal force, only drag decelerates.
    #[test]
    fn horizontal_drag_decelerates() {
        let s0 = SitlState { vel: [1_000, 0, 0], pos: [0, 0, -5_000], ..Default::default() };
        let (s1, _) = sitl_step_pure(s0, 100, &[0u16; 4]);
        // Drag is negative, so N velocity should decrease.
        assert!(s1.vel[0] < 1_000,
            "Drag should decelerate horizontal velocity: {} < 1000", s1.vel[0]);
    }
}

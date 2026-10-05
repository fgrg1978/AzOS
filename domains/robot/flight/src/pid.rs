// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Integer PID controller — extracted from `lib.rs` 2026-09-26 so it can be
//! `#[path]`-pulled into `tests/host/flight-tests` on its own: `lib.rs` as a
//! whole does not build on the host (AHRS, GPS, the driver layer), but this
//! struct names no external crate at all — every operand is a primitive.
//! See `tests/host/flight-tests/src/lib.rs`'s `pid_tests` module for the RED/GREEN
//! proof of the overflow this file fixes in `update`'s D term.

/// Integer PID controller.  Gains are stored × 1000.
#[derive(Clone, Copy)]
pub struct Pid {
    /// Proportional gain × 1000.
    pub kp: i32,
    /// Integral gain × 1000.
    pub ki: i32,
    /// Derivative gain × 1000.
    pub kd: i32,
    /// Accumulated integral.
    integral: i32,
    /// Previous error (for derivative).
    prev_error: i32,
    /// Output clamp (min).
    pub out_min: i32,
    /// Output clamp (max).
    pub out_max: i32,
    /// Integral windup limit.
    pub i_max: i32,
}

impl Pid {
    pub const fn new(kp: i32, ki: i32, kd: i32, out_min: i32, out_max: i32) -> Self {
        Pid {
            kp, ki, kd,
            integral: 0,
            prev_error: 0,
            out_min, out_max,
            // Windup limit on the *raw* integral so the delivered I term
            // (ki*integral/1000) stays within ±out_max. Without the /ki the
            // limit was ki× too large, making anti-windup a no-op.
            i_max: out_max.saturating_mul(1000) / if ki > 0 { ki } else { 1 },
        }
    }

    /// Run one PID update.  Returns control output.
    ///
    /// - `error`: setpoint - measurement
    /// - `dt_us`: time delta in microseconds
    pub fn update(&mut self, error: i32, dt_us: u32) -> i32 {
        if dt_us == 0 { return 0; }

        // P term.
        let p = (self.kp as i64 * error as i64 / 1000) as i32;

        // I term: integral += error * dt_us / 1_000_000.
        // Scale: integral is in error·seconds × 1000.
        self.integral += (error as i64 * dt_us as i64 / 1_000_000) as i32;
        // Anti-windup clamp.
        if self.integral > self.i_max { self.integral = self.i_max; }
        if self.integral < -self.i_max { self.integral = -self.i_max; }
        let i = (self.ki as i64 * self.integral as i64 / 1000) as i32;

        // D term: derivative = (error - prev_error) / dt.
        // d_error per second = (error - prev) * 1_000_000 / dt_us.
        //
        // Fixed 2026-09-26: `(error - self.prev_error)` used to subtract in
        // i32 BEFORE the `as i64` widening — the exact "toxic gyro sample"
        // overflow this function's own comment two lines up warned about for
        // the INTEGRAL term (which clamps first) but left open here. Under
        // `overflow-checks = true` + `panic = "abort"`, one i32 subtraction
        // past ±(i32::MAX/MIN) resets the board. Unreachable from the
        // MPU-6050 driver (i16-derived), reachable from SITL. Widened to
        // match every other term in this function (`p`, `i`) already does.
        let d_error = ((error as i64 - self.prev_error as i64) * 1_000_000 / dt_us as i64) as i32;
        let d = (self.kd as i64 * d_error as i64 / 1000) as i32;
        self.prev_error = error;

        // Total output, clamped.
        let out = p + i + d;
        if out > self.out_max { self.out_max }
        else if out < self.out_min { self.out_min }
        else { out }
    }

    /// Reset integral and derivative state.
    pub fn reset(&mut self) {
        self.integral = 0;
        self.prev_error = 0;
    }
}

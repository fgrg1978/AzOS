// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// PID Controller — port of robot/pid.c
///
/// Fixed-point Q16.16 arithmetic PID controller.
/// Used for motor speed and angle control.

/// Q16.16 fixed-point: 1.0 = 65536
pub type Fixed = i64;

pub const FIXED_ONE: Fixed = 65536;

pub fn fixed_from_f32(v: f32) -> Fixed {
    (v * 65536.0) as Fixed
}

pub fn fixed_to_i32(v: Fixed) -> i32 {
    (v >> 16) as i32
}

pub fn fixed_mul(a: Fixed, b: Fixed) -> Fixed {
    (a * b) >> 16
}

/// PID controller state.
#[derive(Clone, Copy)]
pub struct Pid {
    pub kp:         Fixed,
    pub ki:         Fixed,
    pub kd:         Fixed,
    pub integral:   Fixed,
    pub prev_error: Fixed,
    pub out_min:    Fixed,
    pub out_max:    Fixed,
}

impl Pid {
    pub const fn new() -> Self {
        Pid {
            kp:         FIXED_ONE,
            ki:         0,
            kd:         0,
            integral:   0,
            prev_error: 0,
            out_min:    -1000 * FIXED_ONE,
            out_max:     1000 * FIXED_ONE,
        }
    }

    /// Initialize with floating-point gains.
    pub fn init(&mut self, kp: i32, ki: i32, kd: i32) {
        self.kp         = kp as Fixed * FIXED_ONE;
        self.ki         = ki as Fixed * FIXED_ONE;
        self.kd         = kd as Fixed * FIXED_ONE;
        self.integral   = 0;
        self.prev_error = 0;
    }

    /// Compute PID output given current error and time delta (in ms, as Fixed).
    pub fn update(&mut self, error: Fixed, dt_ms: Fixed) -> Fixed {
        // Proportional
        let p = fixed_mul(self.kp, error);

        // Integral (with anti-windup clamping)
        self.integral += fixed_mul(fixed_mul(self.ki, error), dt_ms);
        self.integral = self.integral.clamp(self.out_min, self.out_max);

        // Derivative
        let d = if dt_ms > 0 {
            let diff = error - self.prev_error;
            fixed_mul(self.kd, diff / (dt_ms >> 16).max(1))
        } else {
            0
        };

        self.prev_error = error;

        let out = p + self.integral + d;
        out.clamp(self.out_min, self.out_max)
    }

    /// Reset integral and derivative state.
    pub fn reset(&mut self) {
        self.integral   = 0;
        self.prev_error = 0;
    }
}

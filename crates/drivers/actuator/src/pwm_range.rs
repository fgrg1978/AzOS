// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The range a PWM channel's period and duty keep, for every backend that
//! stores both (the simulation, the K1): the duty never past the period. A
//! period shorter than the duty, or a duty past the period, is refused rather
//! than clamped: a clamp turns either into full duty. Each backend asks under
//! its channel's configuration lock, so a period and a duty written at once
//! cannot pass their checks against each other's old value.
//!
//! No hardware here: `tests/host/drivers-tests` pulls the file with `#[path]`.

/// What a backend answers for a period or a duty out of range (the `Pwm`
/// interface's `BAD_ARGUMENT`), apart from its own `-1` for a channel it does
/// not have or a value its clock cannot make.
pub const OUT_OF_RANGE: i32 = -2;

/// May the channel take period `period_ns` while its duty is `duty_ns`?
pub const fn period_fits(period_ns: u32, duty_ns: u32) -> bool {
    period_ns != 0 && duty_ns <= period_ns
}

/// May the channel take duty `duty_ns` under its period `period_ns`?
pub const fn duty_fits(duty_ns: u32, period_ns: u32) -> bool {
    duty_ns <= period_ns
}

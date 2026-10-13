// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Motor` interface: one wheel of the drivetrain, and the drivetrain's
//! PID loop.
//!
//! The endpoint's badge is the wheel (`endpoint = "motor.0"` left,
//! `"motor.1"` right). Two kinds of op:
//!
//! * **Per-wheel** (`speed`, `drive`, `direction`, `angle`): they act on, or
//!   read, the wheel the badge names. Commanding a wheel needs `WRITE`, and
//!   the halt rule is the motor layer's, not the capability's: while an e-stop
//!   is latched or containment is armed a stop (speed 0, brake, coast) is
//!   carried out and a forward or backward is refused with
//!   [`outcome::REFUSED`]. A task that holds the wheel can always stop it.
//! * **Pair-wide** (the PID loop: `pid_target`, `pid_tick`, `pid_enable`,
//!   `pid_gains`, `pid_reset`): one operation commands the whole drivetrain,
//!   so the caller needs `WRITE` on BOTH wheels' endpoints, and a contained
//!   system refuses them. `pid_enabled` observes and needs `READ` on any wheel.
//!
//! `estop` latches the emergency stop: it needs `WRITE` on any wheel and is
//! never refused for containment (it is issued exactly when something has
//! gone wrong).
//!
//! Register-form interface (`words = 4`): the control loop's `speed` and
//! `pid_tick` pay one call and no message descriptor.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "MOTR").
pub const MOTOR_ID: u32 = 0x4D4F_5452;

/// Wheels of the drivetrain: 0 (left) and 1 (right).
pub const WHEELS: u32 = 2;

/// Direction for [`Motor::drive`] and [`Motor::direction`]: forward.
pub const DIR_FORWARD: u32 = 0;
/// Direction: backward.
pub const DIR_BACKWARD: u32 = 1;
/// Direction: brake (both pins high).
pub const DIR_BRAKE: u32 = 2;
/// Direction: coast (both pins low).
pub const DIR_COAST: u32 = 3;

#[azos_interface(id = 0x4D4F_5452, level = 1, words = 4)]
pub trait Motor {
    /// Run the wheel forward at `pct` percent (clamped to 100); 0 stops it.
    /// Needs `WRITE`. `REFUSED` for a nonzero speed while halted.
    fn speed(&mut self, pct: u32) -> Out<()>;
    /// Run the wheel in direction `dir` ([`DIR_FORWARD`]..=[`DIR_COAST`], else
    /// `BAD_ARGUMENT`) at `pct` percent (more than 100 is `BAD_ARGUMENT`).
    /// Needs `WRITE`. `REFUSED` for forward or backward while halted.
    fn drive(&mut self, dir: u32, pct: u32) -> Out<()>;
    /// Set the wheel's direction at 50 percent duty. `BAD_ARGUMENT` outside
    /// [`DIR_FORWARD`]..=[`DIR_COAST`]. Needs `WRITE`. `REFUSED` for forward
    /// or backward while halted.
    fn direction(&mut self, dir: u32) -> Out<()>;
    /// The wheel's accumulated encoder ticks. Needs `READ`.
    #[idempotent]
    fn angle(&self) -> Out<i64>;
    /// Set the PID loop's targets, percent of full speed per wheel. Needs
    /// `WRITE` on both wheels.
    fn pid_target(&mut self, left: i32, right: i32) -> Out<()>;
    /// Advance the PID loop by one sample (`now` on the caller's clock): the
    /// encoder ticks of both wheels in, the duty (left, right) out. Needs
    /// `WRITE` on both wheels.
    fn pid_tick(&mut self, ticks_left: i64, ticks_right: i64, now: u64) -> Out<[i32; 2]>;
    /// Arm or disarm the PID loop. Needs `WRITE` on both wheels.
    fn pid_enable(&mut self, on: bool) -> Out<()>;
    /// Whether the PID loop is armed. Needs `READ`.
    #[idempotent]
    fn pid_enabled(&self) -> Out<bool>;
    /// Set the PID gains. Needs `WRITE` on both wheels.
    fn pid_gains(&mut self, kp: i32, ki: i32, kd: i32) -> Out<()>;
    /// Clear the PID loop's integrator and previous error. Needs `WRITE` on
    /// both wheels.
    fn pid_reset(&mut self) -> Out<()>;
    /// Emergency stop: latch the e-stop, stop both wheels, disarm the ESC and
    /// write the durable safety record. Needs `WRITE` on any wheel; not
    /// refused for containment.
    fn estop(&mut self) -> Out<()>;
}

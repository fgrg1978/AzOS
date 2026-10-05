// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Robot framework — port of kernel/robot/
//! PID controller, motor control, sensor abstraction.
//! Phase 13: MotorCmd IPC channel + hardware watchdog.
//! Phase 17: Encoder simulation, dead-reckoning odometry, trajectory ring.

pub mod pid;
pub mod motor;
pub mod encoder;
pub mod odom;
pub mod trajectory;

pub use pid::{Pid, Fixed, FIXED_ONE, fixed_mul, fixed_to_i32};
pub use motor::{
    motor_init, motor_set, motor_stop, motor_stop_panic, motor_brake, motor_info,
    motor_set_reporting, motor_stop_reporting, motor_state,
    Motor, MotorDir, MAX_MOTORS, MOTOR_REFUSED_HALTED,
};
pub use encoder::{
    encoder_tick, encoder_read, encoder_read_stamped, encoder_reset, TICKS_PER_M, WHEEL_BASE_MM,
    ticks_per_m, set_ticks_per_m, wheel_base_mm, set_wheel_base_mm,
};
pub use odom::{odom_update, odom_update_at, odom_get, odom_get_stamped, odom_reset};
pub use trajectory::{traj_record, traj_len, traj_get, traj_reset, TrajPoint, TRAJ_CAP};

// ── MotorCmd IPC channel (Phase 13 → H) ─────────────────────────────────────
//
// The deliberative ML task publishes MotorCmd at ~10 Hz.
// The RT motor task reads it every scheduler tick and applies PID.
// If no command arrives within WATCHDOG_TIMEOUT_TICKS, the watchdog fires
// and the RT task halts the motors (safe stop).
//
// Phase H: backed by Channel<MotorCmd> instead of ad-hoc SpinLock.
// Watchdog timeout: 500 ms on any platform (TIMER_FREQ / 2).

/// Watchdog timeout in CLINT ticks — 500 ms on any platform.
/// Uses `TIMER_FREQ` so it adapts to QEMU (10 MHz), VF2 (4 MHz), and K1 (24 MHz).
pub fn watchdog_timeout_ticks() -> u64 {
    azos_drv_sys::timebase::TIMER_FREQ / 2
}

/// Motor command from the deliberative (ML) layer to the RT layer.
#[derive(Clone, Copy)]
pub struct MotorCmd {
    /// Left motor speed: -100 .. =100 (negative = reverse).
    pub speed_l:   i32,
    /// Right motor speed: -100 .. =100 (negative = reverse).
    pub speed_r:   i32,
}

impl MotorCmd {
    pub const fn new() -> Self {
        MotorCmd { speed_l: 0, speed_r: 0 }
    }
}

/// The global motor command channel.
///
/// Published by behavior/deliberative tasks, consumed by the RT motor task.
/// Replaces the Phase 13 `SpinLock<MotorCmd>` with a generic `Channel<T>`.
pub static CH_MOTOR_CMD: azos_channel::Channel<MotorCmd> =
    azos_channel::Channel::new(MotorCmd::new());

/// Publish a new motor command from the deliberative layer.
pub fn motor_cmd_publish(speed_l: i32, speed_r: i32) {
    let ts = azos_drv_sys::timebase::now();
    let cmd = MotorCmd {
        speed_l: speed_l.clamp(-100, 100),
        speed_r: speed_r.clamp(-100, 100),
    };
    CH_MOTOR_CMD.publish(cmd, ts);
}

/// Read the current motor command (RT layer — copy-out, no blocking).
pub fn motor_cmd_read() -> MotorCmd {
    CH_MOTOR_CMD.read().val
}

/// Age in CLINT ticks since the last published command.
/// Returns `u64::MAX` if no command has been published yet.
pub fn motor_cmd_age_ticks() -> u64 {
    CH_MOTOR_CMD.age(azos_drv_sys::timebase::now())
}

/// Returns `true` if the watchdog has fired (no update for > 500 ms).
pub fn motor_watchdog_fired() -> bool {
    motor_cmd_age_ticks() >= watchdog_timeout_ticks()
}

// ── Framework init ────────────────────────────────────────────────────────────

/// Initialize the robot framework.
/// Registers simulated motors (can be overridden for real hardware).
pub fn robot_init() {
    motor::motor_init(0, 0, 0, 1);
    motor::motor_init(1, 1, 2, 3);
    azos_drv_sys::kprintln!("[ROBOT] Framework initialized (2 motors, simulated)");
}

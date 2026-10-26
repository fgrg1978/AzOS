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
pub mod motor_cmd;

pub use pid::{Pid, Fixed, FIXED_ONE, fixed_mul, fixed_to_i32};
pub use motor::{
    motor_init, motor_set, motor_stop, motor_stop_panic, motor_safe_state, motor_release, motor_brake,
    motor_set_reporting, motor_stop_reporting, motor_state, motor_halted,
    Motor, MotorDir, MAX_MOTORS, MOTOR_REFUSED_HALTED,
};
pub use encoder::{
    encoder_tick, encoder_read, encoder_read_stamped, encoder_reset, TICKS_PER_M, WHEEL_BASE_MM,
    ticks_per_m, set_ticks_per_m, wheel_base_mm, set_wheel_base_mm,
};
pub use odom::{odom_update, odom_update_at, odom_get, odom_get_stamped, odom_reset};
pub use trajectory::{traj_record, traj_len, traj_get, traj_reset, ModelRecord, TrajPoint, TRAJ_CAP};

use core::sync::atomic::{AtomicU64, Ordering};

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
/// Published by the behaviour task, consumed by the RT motor task.
/// Replaces the Phase 13 `SpinLock<MotorCmd>` with a generic `Channel<T>`.
///
/// Not `pub`: the channel has ONE publisher handle, and a store masks
/// preemption, not interrupts. Trap, fault and shutdown paths used to publish
/// `(0, 0)` here from any hart while behaviour published at 10 Hz. Two
/// overlapping writers bump the stamp odd -> even between them, so `rt_motor`
/// could accept a torn command as clean. Commands now go through
/// [`motor_cmd_publish`] (task context, serialised: the handle lives inside
/// `MOTOR_CMD_WRITER`) and stops through [`motor_cmd_zero`] (any context, one
/// atomic store).
static CH_MOTOR_CMD: azos_channel::Channel<MotorCmd> =
    azos_channel::Channel::new(MotorCmd::new());

/// Serialises task-context publishers (behaviour and the safety smoke) and
/// holds the channel's one publisher handle, taken on the first publish.
/// Trap and interrupt paths never take it: they use the stop latch.
static MOTOR_CMD_WRITER: azos_sync::SpinLock<Option<azos_channel::Publisher<'static, MotorCmd>>> =
    azos_sync::SpinLock::new(None);

/// Timebase tick of the latest stop request, 0 = none. A stop overrides every
/// command published at or before it; a tie goes to the stop.
static MOTOR_ZERO_AT: AtomicU64 = AtomicU64::new(0);

/// Publish a new motor command from the deliberative layer.
///
/// Task context only. A trap, fault, interrupt or shutdown path must call
/// [`motor_cmd_zero`] instead.
pub fn motor_cmd_publish(speed_l: i32, speed_r: i32) {
    let cmd = MotorCmd {
        speed_l: speed_l.clamp(-100, 100),
        speed_r: speed_r.clamp(-100, 100),
    };
    let mut w = MOTOR_CMD_WRITER.lock();
    let tx = w.get_or_insert_with(|| CH_MOTOR_CMD.publisher().expect("CH_MOTOR_CMD: second publisher"));
    // Read under the writer lock, so timestamps are monotonic across
    // publishers and compare correctly against a stop request.
    let ts = azos_drv_sys::timebase::now();
    tx.publish(cmd, ts);
}

/// Request `(0, 0)` from any context: trap, fault, interrupt, shutdown or
/// another hart. It is one atomic store, so it cannot tear and takes no lock.
/// A command published after it overrides it, exactly as the `(0, 0)` publish
/// it replaces would have been overwritten.
pub fn motor_cmd_zero() {
    // `max(1)`: 0 means "no stop requested".
    let now = azos_drv_sys::timebase::now().max(1);
    MOTOR_ZERO_AT.fetch_max(now, Ordering::AcqRel);
}

/// Read the current motor command (RT layer — copy-out, no blocking).
pub fn motor_cmd_read() -> MotorCmd {
    let snap = CH_MOTOR_CMD.read();
    let zero_at = MOTOR_ZERO_AT.load(Ordering::Acquire);
    motor_cmd::resolve(snap.val, snap.timestamp, zero_at, MotorCmd::new())
}

/// True once any command or stop request has been issued.
pub fn motor_cmd_is_valid() -> bool {
    CH_MOTOR_CMD.is_valid() || MOTOR_ZERO_AT.load(Ordering::Acquire) != 0
}

/// Age in CLINT ticks since the last published command or stop request.
/// Returns `u64::MAX` if neither has happened yet.
pub fn motor_cmd_age_ticks() -> u64 {
    let now = azos_drv_sys::timebase::now();
    motor_cmd::age(CH_MOTOR_CMD.age(now), now, MOTOR_ZERO_AT.load(Ordering::Acquire))
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

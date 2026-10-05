// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_robot`, used only by `tests/host/syscall-tests`.
//!
//! **The motor layer is the real one.** `motor.rs` and `pid.rs` are the files
//! from `domains/robot/robot/src`, pulled in with `#[path]` the way `shims/ipc` pulls
//! `cap.rs`, so `sys_motor_*` run the actual `motor_set_reporting`: the halt
//! rule, the direction-pin writes and the duty write. Those land on this
//! crate's driver stand-in (`syscall_test_drivers`), which is the same one `handlers.rs` sees,
//! so a test observes them through the GPIO and PWM probes there. `motor.rs`
//! also needs `SpinLock::get_mut_unchecked`, which `cap_test_sync` omits; see
//! `shims/robot_sync`.
//!
//! **Still stand-ins:** the two motor-binding lookups the raw GPIO and PWM
//! guards ask (module `motor` below); the encoders, a pair a test sets
//! (`shim_set_encoder`) so `sys_motor_angle`'s admitted half returns a known
//! value; and `motor_info` and odometry, which are `todo!()`.

// The driver class crates the compiled sources name, all served by the
// one host stand-in `syscall_test_drivers`.
extern crate syscall_test_drivers as azos_drv_actuator;
extern crate syscall_test_drivers as azos_drv_gpio;
extern crate syscall_test_drivers as azos_drv_sys;

#[path = "../../../../../../domains/robot/robot/src/pid.rs"]
pub mod pid;

#[path = "../../../../../../domains/robot/robot/src/motor.rs"]
pub mod motor_real;

pub use motor_real::{
    motor_init, motor_set, motor_set_reporting, motor_state, motor_stop, motor_stop_reporting,
    MotorDir, MAX_MOTORS, MOTOR_REFUSED_HALTED,
};

/// `todo!()` unless [`shim_arm_motor_info`] armed it; armed, it counts calls.
pub fn motor_info() {
    let mut g = MOTOR_INFO_CALLS.lock().unwrap_or_else(|e| e.into_inner());
    match g.as_mut() {
        Some(n) => *n += 1,
        None => todo!("robot stand-in: not reached by any test in this crate"),
    }
}

static MOTOR_INFO_CALLS: std::sync::Mutex<Option<u32>> = std::sync::Mutex::new(None);

/// Test-only control surface: make [`motor_info`] count instead of panic.
pub fn shim_arm_motor_info() {
    *MOTOR_INFO_CALLS.lock().unwrap_or_else(|e| e.into_inner()) = Some(0);
}

/// Test-only control surface: disarm, returning the calls counted.
pub fn shim_disarm_motor_info() -> Option<u32> {
    MOTOR_INFO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).take()
}
/// Ticks `encoder_read` reports. The real `domains/robot/robot` reads the wheel
/// encoders; a test sets the pair it expects back.
static ENCODER_LEFT: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
static ENCODER_RIGHT: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
/// Calls to `encoder_read`, so a test can assert that a refused call never
/// read the encoders at all.
static ENCODER_READS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn encoder_read() -> (i64, i64) {
    use core::sync::atomic::Ordering;
    ENCODER_READS.fetch_add(1, Ordering::SeqCst);
    (ENCODER_LEFT.load(Ordering::SeqCst), ENCODER_RIGHT.load(Ordering::SeqCst))
}

/// Test-only: the `(left, right)` ticks the next `encoder_read` returns.
pub fn shim_set_encoder(left: i64, right: i64) {
    use core::sync::atomic::Ordering;
    ENCODER_LEFT.store(left, Ordering::SeqCst);
    ENCODER_RIGHT.store(right, Ordering::SeqCst);
}

/// Acquisition stamp (timebase ticks) `encoder_read_stamped` reports.
static ENCODER_ACQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// `encoder_read` (counted like it) and the stamp a test set.
pub fn encoder_read_stamped() -> ((i64, i64), u64) {
    (encoder_read(), ENCODER_ACQ.load(core::sync::atomic::Ordering::SeqCst))
}

/// Test-only: the acquisition stamp the next `encoder_read_stamped` reports.
pub fn shim_set_encoder_acq(ticks: u64) {
    ENCODER_ACQ.store(ticks, core::sync::atomic::Ordering::SeqCst);
}

/// Test-only: how many times `encoder_read` has run.
pub fn shim_encoder_reads() -> u64 {
    ENCODER_READS.load(core::sync::atomic::Ordering::SeqCst)
}
pub fn odom_get() -> (i64, i64) {
    todo!("robot stand-in: not reached by any test in this crate")
}
pub fn odom_get_stamped() -> ((i64, i64), u64) {
    todo!("robot stand-in: not reached by any test in this crate")
}

/// Which PWM channels and direction pins an initialised motor claims, as the
/// raw GPIO/PWM guards in `handlers.rs` ask it.
///
/// The real `domains/robot/robot` answers this from its `MOTORS` table. Here it is a
/// bitmask a test can set, because the point is not to model motor
/// initialisation — it is to drive the two guards in `handlers.rs` that refuse
/// a motor-bound channel through `SYS_DRV_INVOKE` and the typed `Cap<Pwm>`,
/// and those need to see both answers.
pub mod motor {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// The real hooks, at the path the kernel installs them through.
    pub use super::motor_real::{set_motor_gate, set_motor_halt};

    static MOTOR_CHANNELS: AtomicU32 = AtomicU32::new(0);

    /// Test-only: declare `ch` as claimed by a motor.
    pub fn shim_bind_motor_channel(ch: u32) {
        MOTOR_CHANNELS.fetch_or(1u32 << (ch & 31), Ordering::SeqCst);
    }

    /// Test-only: forget every binding.
    pub fn shim_clear_motor_channels() {
        MOTOR_CHANNELS.store(0, Ordering::SeqCst);
    }

    /// Mirrors `azos_robot::motor::pwm_channel_motor_id`. The id itself is
    /// not modelled — every guard that calls this only asks `is_some()`.
    pub fn pwm_channel_motor_id(ch: u32) -> Option<u32> {
        if MOTOR_CHANNELS.load(Ordering::SeqCst) & (1u32 << (ch & 31)) != 0 {
            Some(0)
        } else {
            None
        }
    }

    static MOTOR_PINS: AtomicU32 = AtomicU32::new(0);

    /// Test-only: declare `pin` as an H-bridge direction pin.
    pub fn shim_bind_motor_pin(pin: u32) {
        MOTOR_PINS.fetch_or(1u32 << (pin & 31), Ordering::SeqCst);
    }

    /// Test-only: forget every direction-pin binding.
    pub fn shim_clear_motor_pins() {
        MOTOR_PINS.store(0, Ordering::SeqCst);
    }

    /// Mirrors `azos_robot::motor::gpio_pin_motor_id`. A separate bitmask
    /// from the PWM one on purpose: a test that binds a channel must not
    /// silently bind the pin of the same number, or the two guards would be
    /// impossible to tell apart.
    pub fn gpio_pin_motor_id(pin: u32) -> Option<u32> {
        if MOTOR_PINS.load(Ordering::SeqCst) & (1u32 << (pin & 31)) != 0 {
            Some(0)
        } else {
            None
        }
    }
}

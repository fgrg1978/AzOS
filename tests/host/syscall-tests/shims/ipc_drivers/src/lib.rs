// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for the driver class crates (`azos_drv_*`), as seen from `crates/core/ipc`'s
//! `gpio_cap.rs` / `i2c_cap.rs` / `pwm_cap.rs` / `motor_cap.rs` (pulled real
//! into `tests/host/syscall-tests/shims/ipc` to get `GpioCapError` /
//! `I2cCapError` / `PwmCapError` / `MotorCapError` — real types the
//! `errno_for_*_err` tests need). This is a separate crate instance from the
//! outer `tests/host/syscall-tests` package's own driver stand-in;
//! the two are never mixed at a call site.
//!
//! `motor_pid` is real, not a stand-in: it is pure computation with a
//! `SpinLock` as its only dependency, the same file `tests/host/drivers-tests`
//! already proves host-pullable. `gpio`/`i2c`/`pwm` are real MMIO with no
//! shim anywhere in this repo, so they are `todo!()` — signatures copied
//! from the real modules, never called by any test in this crate.

// `motor_pid.rs` names its neighbours by class crate
// (`azos_drv_irqchip::clint::TIMER_FREQ`, `azos_drv_sys::kprintln!`); both
// resolve to the root stand-ins below.
extern crate self as azos_drv_irqchip;
extern crate self as azos_drv_sys;

/// `motor_pid.rs` reaches for `azos_drv_irqchip::clint::TIMER_FREQ` and `azos_drv_sys::kprintln!`.
/// Same stand-in shape as `tests/host/drivers-tests`.
pub mod clint {
    pub const TIMER_FREQ: u64 = 10_000_000;
}

/// Mirrors `azos_drv_sys::timebase`. Only the constant: nothing this shim
/// serves reads the clock, and a `now()` here would be a stand-in with no
/// caller — the kind that makes a later test look covered when it is not.
pub mod timebase {
    pub use super::clint::TIMER_FREQ;
}

#[macro_export]
macro_rules! kprintln {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}

/// The leveled forms (`crates/drivers/sys/src/uart.rs`): every level prints
/// on the host.
#[macro_export]
macro_rules! kerr {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kwarn {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kinfo {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kdebug {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kconsoleln {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kconsole {
    ($($arg:tt)*) => { print!($($arg)*) };
}

pub mod gpio {
    pub const GPIO_MAX_PINS: usize = 64;

    #[derive(Clone, Copy, PartialEq)]
    pub enum GpioDir {
        Input = 0,
        Output = 1,
    }

    pub fn gpio_read(_pin: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn gpio_write(_pin: u32, _val: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn gpio_set_direction(_pin: u32, _dir: GpioDir) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod i2c {
    pub fn i2c_read(_bus: u8, _addr: u8, _reg: u8, _buf: &mut [u8]) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn i2c_write(_bus: u8, _addr: u8, _data: &[u8]) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn i2c_detect(_bus: u8, _addr: u8) -> bool {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod pwm {
    pub const PWM_MAX_CHANNELS: usize = 8;

    pub fn pwm_enable(_ch: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn pwm_disable(_ch: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn pwm_set_period(_ch: u32, _period_ns: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn pwm_set_duty(_ch: u32, _duty_ns: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn pwm_set_duty_pct(_ch: u32, _pct: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

#[allow(dead_code)]
#[path = "../../../../../../crates/drivers/actuator/src/motor_pid.rs"]
pub mod motor_pid;

/// The PWM instance's channel grouping — the REAL module, pulled in with
/// `#[path]` rather than stubbed.
///
/// `pwm_cap` now bounds a grant by `PWM_DOMAIN.channels` instead of by the
/// simulator's array size: the JH7110 has four channels and the simulator
/// eight, so a shim answering 8 here would let this suite bless a capability
/// the board cannot back — the exact defect the bound was added to stop.
#[path = "../../../../../../crates/drivers/actuator/src/pwm_domain.rs"]
pub mod pwm_domain;

/// The board's MMIO region table, re-exported from `shims/drivers` (see this
/// crate's Cargo.toml).
pub use syscall_test_drivers::platform;

/// The published partition table `disk_cap.rs` mints against (RFC-0048 P3).
/// Re-exported from `shims/drivers`, NOT pulled a second time: the table is
/// a set of statics, and the handler's range check and the minter must see
/// the same one.
pub use syscall_test_drivers::partition;

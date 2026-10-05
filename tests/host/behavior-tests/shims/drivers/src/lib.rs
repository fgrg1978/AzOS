// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for the driver class crates (`azos_drv_*`), reduced to what the pulled-in
//! behaviour modules use: a monotonic clock, `kprintln!`, and — since
//! `payload.rs` was pulled in on 2026-09-11 — an in-memory GPIO and PWM.
//!
//! The clock only rate-limits denial announcements, so it needs to advance but
//! its absolute value is irrelevant.

pub mod clint {
    /// The `mtime` frequency the host suites assume.
    ///
    /// 10 MHz, matching `platform::hw::TIMER_FREQ` for the qemu board, because
    /// that is the timebase every existing test's arithmetic was written
    /// against. It is a real constant and not a placeholder: production code
    /// derives its tick constants from `clint::TIMER_FREQ`, so changing this
    /// value changes what the code under test computes -- which is what lets a
    /// test detect a constant that went back to being hardcoded.
    pub const TIMER_FREQ: u64 = 10_000_000;

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static OVERRIDE_ON: AtomicBool = AtomicBool::new(false);
    static OVERRIDE_TS: AtomicU64 = AtomicU64::new(0);

    /// Pin the clock to a fixed value.
    ///
    /// The flight recorder stamps every record with `get_time()`, so a
    /// wall-clock reading would make the bytes a test decodes back
    /// unreproducible — and asserting on a wall-clock value is the exact
    /// thing this project's measurement doctrine forbids. `auth_envelope`
    /// only rate-limits with this clock and never sets the override, so it
    /// keeps the advancing wall clock it needs.
    pub fn set_test_time(t: u64) {
        OVERRIDE_TS.store(t, Ordering::Relaxed);
        OVERRIDE_ON.store(true, Ordering::Release);
    }

    /// Hand the clock back to the wall.
    pub fn clear_test_time() {
        OVERRIDE_ON.store(false, Ordering::Release);
    }

    pub fn get_time() -> u64 {
        if OVERRIDE_ON.load(Ordering::Acquire) {
            return OVERRIDE_TS.load(Ordering::Relaxed);
        }
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 / 100
    }
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

/// `azos_drv_sys::wcet::read_cycles`, used by `dns.rs` to stamp its
/// WCET probes. The absolute value is irrelevant to every caller here; it
/// only has to advance.
pub mod wcet {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CYCLES: AtomicU64 = AtomicU64::new(0);
    pub fn read_cycles() -> u64 {
        CYCLES.fetch_add(1000, Ordering::Relaxed)
    }
}


/// `azos_drv_gpio::gpio`, in memory.
///
/// `payload.rs` drives the spray MOSFET and the camera shutter line through
/// these. The suite asserts on the LEVEL of a pin, so a stand-in that only
/// swallowed the writes would make the shutter-pulse tests vacuous — they
/// would pass on a `payload_cam_trigger` that never touched the pin at all.
pub mod gpio {
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum GpioDir { Input, Output }

    const PINS: usize = 64;
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU32 = AtomicU32::new(0);
    static LEVEL: [AtomicU32; PINS] = [ZERO; PINS];

    pub fn gpio_set_direction(_pin: u32, _dir: GpioDir) -> i32 { 0 }

    pub fn gpio_write(pin: u32, val: u32) -> i32 {
        if (pin as usize) >= PINS { return -1; }
        LEVEL[pin as usize].store(val & 1, Ordering::Release);
        0
    }

    pub fn gpio_read(pin: u32) -> i32 {
        if (pin as usize) >= PINS { return -1; }
        LEVEL[pin as usize].load(Ordering::Acquire) as i32
    }

    /// `motor_stop_panic`'s (`domains/robot/robot/src/motor.rs`) lock-free write.
    /// No real concurrency concern on a host stand-in with no interrupts —
    /// same store `gpio_write` does.
    pub fn gpio_write_panic(pin: u32, val: u32) -> i32 {
        gpio_write(pin, val)
    }
}

/// `azos_drv_actuator::pwm`, in memory. Only what `payload::payload_init` and
/// `payload::payload_gripper` call.
pub mod pwm {
    use std::sync::atomic::{AtomicU32, Ordering};
    static PERIOD: AtomicU32 = AtomicU32::new(0);
    static DUTY: AtomicU32 = AtomicU32::new(0);

    pub fn pwm_enable(_ch: u32) -> i32 { 0 }
    pub fn pwm_set_period(_ch: u32, ns: u32) -> i32 {
        PERIOD.store(ns, Ordering::Relaxed); 0
    }
    pub fn pwm_set_duty(_ch: u32, ns: u32) -> i32 {
        DUTY.store(ns, Ordering::Relaxed); 0
    }
    pub fn pwm_duty_ns() -> u32 { DUTY.load(Ordering::Relaxed) }

    /// Per-channel duty percent, for `domains/robot/robot/src/motor.rs` (pulled in
    /// by the motor-gate/record suite) — separate from the single-channel
    /// `DUTY`/`pwm_set_duty` above, which `payload.rs`'s gripper already
    /// owns and asserts on in nanoseconds. Motors need one duty per PWM
    /// channel, mirroring the real driver's per-channel state
    /// (`crates/drivers/actuator/src/pwm.rs`).
    const CHANNELS: usize = 8;
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU32 = AtomicU32::new(0);
    static DUTY_PCT: [AtomicU32; CHANNELS] = [ZERO; CHANNELS];

    pub fn pwm_set_duty_pct(ch: u32, pct: u32) -> i32 {
        if pwm_set_duty_pct_reporting(ch, pct).is_some() { 0 } else { -1 }
    }

    /// Mirrors `pwm_set_duty_pct_reporting` in `crates/drivers/actuator/src/pwm.rs`:
    /// the applied percent comes back from the same write, not a later
    /// read, so a caller under test cannot race another writer's channel.
    pub fn pwm_set_duty_pct_reporting(ch: u32, pct: u32) -> Option<u32> {
        if ch as usize >= CHANNELS { return None; }
        let p = pct.min(100);
        DUTY_PCT[ch as usize].store(p, Ordering::Relaxed);
        Some(p)
    }

    pub fn pwm_duty_pct(ch: u32) -> Option<u32> {
        if ch as usize >= CHANNELS { return None; }
        Some(DUTY_PCT[ch as usize].load(Ordering::Relaxed))
    }

    /// `motor_stop_panic`'s (`domains/robot/robot/src/motor.rs`) lock-free write.
    /// No real concurrency concern on a host stand-in with no interrupts —
    /// same store `pwm_set_duty_pct_reporting` does.
    pub fn pwm_set_duty_pct_panic(ch: u32, pct: u32) -> i32 {
        pwm_set_duty_pct(ch, pct)
    }
}

/// Mirrors `azos_drv_sys::timebase` — the ISA-neutral name the tree's
/// clock reads migrated to.
///
/// **Delegates to this shim's own `clint::get_time`, deliberately.** The real
/// module calls `azos_arch::cpu::now_ticks()`, which on the host is not
/// available and could not be pinned anyway; what the tests need is the
/// override that already lives next door. Routing through it keeps ONE
/// settable clock per test crate instead of a second one that could disagree
/// with the first.
pub mod timebase {
    /// Mirrors `azos_drv_sys::timebase::TIMER_FREQ`, which re-exports the
    /// same constant this shim already defines next door — one value, two
    /// names, so a test cannot read a different timebase than the code under
    /// test computes against.
    pub use super::clint::TIMER_FREQ;

    #[inline(always)]
    pub fn now() -> u64 {
        super::clint::get_time()
    }
}

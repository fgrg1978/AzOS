// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for the driver class crates (`azos_drv_*`), used only by `tests/host/syscall-tests`.
//!
//! **WHY this exists.** `handlers.rs` reaches into `azos_drv_*` 43
//! times, all of it real MMIO (GPIO/PWM/I2C registers, UART, VirtIO block,
//! camera, sensors) that does not exist on a host and has no shim anywhere
//! in this repo for the register-level parts (unlike `motor_pid.rs`, which
//! `tests/host/drivers-tests` already proves is pure and host-pullable). None of
//! it is reachable from this crate's three test targets, so every function
//! below is `todo!()` — signatures copied from the real modules so
//! `handlers.rs` compiles unchanged, bodies that panic if anything ever
//! calls them from a test.
//!
//! **Two things here are real, not stand-ins:**
//! - `azos_drv_api` is the real crate (`crates/drivers/api`), a dependency
//!   of this shim and of the suite: `errno_for_driver_err` (target 1) needs
//!   the real `DriverError` type, and this is it.
//! - `runtime::registry` is the real `crates/drivers/base/src/runtime/registry.rs`
//!   pulled in with `#[path]` (15 lines: one `SpinLock<Registry>` static).
//!   `drv_invoke_authorized`, which `cap_kind_for_driver` (target 2) feeds
//!   into, reads `REGISTRY` — trivial enough to pull verbatim rather than
//!   reproduce.

#[path = "../../../../../../crates/drivers/base/src/runtime/registry.rs"]
pub mod registry_real;
pub mod runtime {
    pub use super::registry_real as registry;
}

/// The board constants, the REAL module. Constants and `const fn`s, nothing
/// that needs a device.
#[path = "../../../../../../crates/drivers/base/src/platform.rs"]
pub mod platform;

/// The hardware bus's static instance and its two lookups, the REAL module
/// (MMIO region index): `DOMAIN_MMIO_MAP` resolves a device handle through it, and the
/// capability's minter (`shims/ipc`'s `mmio_cap`) sees the same instance.
#[path = "../../../../../../crates/drivers/bus/src/hwbus.rs"]
pub mod hwbus;

/// Third real module, not a stand-in — same rationale as `runtime::registry`.
///
/// `pwm_domain` states which PWM channels one control-register write actually
/// reaches (on the JH7110 the enable bit and prescaler share one `PWMCFG`, so
/// a write named for any channel reaches all four). `handlers.rs` consults it
/// in the `Pwm` interface's reach check. It is pure
/// arithmetic over a description of the hardware with no dependencies at all
/// — no MMIO, no locks — so it is pulled verbatim rather than reproduced.
/// Reproducing it would be actively wrong: a stand-in that disagreed with the
/// real domain would let these tests certify a check the board does not make.
#[path = "../../../../../../crates/drivers/actuator/src/pwm_domain.rs"]
pub mod pwm_domain;

/// Stand-ins for the `Spi`, `Can`, `Uart` (bridge) and `Adc` ports.
pub mod h3_ports;

/// `kprintln!` on the host, same shape as `tests/host/drivers-tests`.
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

// `motor_pid.rs` names its neighbours by class crate
// (`azos_drv_irqchip::clint::TIMER_FREQ`, `azos_drv_sys::kprintln!`); both
// resolve to this crate's own stand-ins.
extern crate self as azos_drv_irqchip;
extern crate self as azos_drv_sys;

/// The PID loop the `Motor` interface drives -- the REAL file: pure
/// computation with a `SpinLock` as its only dependency (the same file
/// `tests/host/drivers-tests` proves host-pullable).
#[allow(dead_code)]
#[path = "../../../../../../crates/drivers/actuator/src/motor_pid.rs"]
pub mod motor_pid;

pub mod gpio {
    use std::sync::Mutex;

    /// The driver's pin table size, as the real crate has it.
    pub const GPIO_MAX_PINS: usize = 64;

    #[derive(Clone, Copy, PartialEq)]
    pub enum GpioDir {
        Input = 0,
        Output = 1,
    }

    /// Which driver entry point a probe was called from.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum GpioOp {
        Read,
        Write,
        SetDirection,
    }

    /// An installable stand-in body for the three GPIO driver entry points.
    ///
    /// Arguments are `(op, pin, arg)`, where `arg` is the value for `Write`,
    /// the direction as 0/1 for `SetDirection`, and 0 for `Read`. The return
    /// value becomes the driver's return code, so a probe can also produce a
    /// fault.
    pub type GpioProbe = fn(GpioOp, u32, u32) -> i32;

    /// **Why this exists, and the rule it bends.**
    ///
    /// This crate's doc states that a stub body is `todo!()` and never a
    /// plausible return value, so that a stub which quietly "succeeded" cannot
    /// make some other test's canary un-fireable. That rule is intact by
    /// default: with no probe installed, all three functions below still
    /// `todo!()`.
    ///
    /// What a probe buys is the only thing a `todo!()` cannot give — the
    /// *moment of the driver call*, from inside it. `crates/core/syscall/src/
    /// handlers.rs`'s typed GPIO handlers are required to touch the hardware
    /// **after** `cap_store::with_table` has dropped the cap-table lock, and
    /// the only way to observe that from a host test is to stand where the
    /// driver stands and look at the lock. A test that installs a probe MUST
    /// clear it again (`set_gpio_probe(None)`) on every exit path.
    static PROBE: Mutex<Option<GpioProbe>> = Mutex::new(None);

    pub fn set_gpio_probe(p: Option<GpioProbe>) {
        *PROBE.lock().unwrap_or_else(|e| e.into_inner()) = p;
    }

    fn enter(op: GpioOp, pin: u32, arg: u32) -> i32 {
        // Copy the pointer out and drop the guard before calling: a probe is
        // free to do anything, including reinstalling itself.
        let p = *PROBE.lock().unwrap_or_else(|e| e.into_inner());
        match p {
            Some(f) => f(op, pin, arg),
            None => todo!("MMIO stand-in: not reached by any test in this crate"),
        }
    }

    pub fn gpio_read(pin: u32) -> i32 {
        enter(GpioOp::Read, pin, 0)
    }
    pub fn gpio_write(pin: u32, val: u32) -> i32 {
        enter(GpioOp::Write, pin, val)
    }
    pub fn gpio_set_direction(pin: u32, dir: GpioDir) -> i32 {
        enter(GpioOp::SetDirection, pin, dir as u32)
    }
    /// `motor_stop_panic` (real, `shims/robot`) calls it, and so does the
    /// kernel's safe-state drive of a wheel (`motor_host::drive_safe`): the
    /// probe sees the write, as it sees the locked variant's.
    pub fn gpio_write_panic(pin: u32, val: u32) -> i32 {
        enter(GpioOp::Write, pin, val)
    }
}

pub mod pwm {
    use std::sync::Mutex;

    /// Which PWM entry point a probe was called from. Only the entry points
    /// the real `domains/robot/robot/src/motor.rs` calls take a probe.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum PwmOp {
        Enable,
        Disable,
        SetPeriod,
        SetDuty,
        SetDutyPct,
    }

    /// `(op, ch, arg)`: `arg` is the period for `SetPeriod`, the percentage
    /// for `SetDutyPct` and 0 for `Enable`. The return value is the driver's;
    /// for `pwm_set_duty_pct_reporting` a non-negative one is the applied
    /// percentage and a negative one is `None`.
    pub type PwmProbe = fn(PwmOp, u32, u32) -> i32;

    /// Same rule as `gpio::set_gpio_probe`: with no probe installed every entry
    /// point below still panics with the MMIO stand-in message, which several
    /// `unit6_contain` tests use as their assertion. A test that installs one
    /// MUST clear it again on every exit path.
    static PROBE: Mutex<Option<PwmProbe>> = Mutex::new(None);

    pub fn set_pwm_probe(p: Option<PwmProbe>) {
        *PROBE.lock().unwrap_or_else(|e| e.into_inner()) = p;
    }

    fn enter(op: PwmOp, ch: u32, arg: u32) -> i32 {
        let p = *PROBE.lock().unwrap_or_else(|e| e.into_inner());
        match p {
            Some(f) => f(op, ch, arg),
            None => todo!("MMIO stand-in: not reached by any test in this crate"),
        }
    }

    pub fn pwm_enable(ch: u32) -> i32 {
        enter(PwmOp::Enable, ch, 0)
    }
    pub fn pwm_disable(ch: u32) -> i32 {
        enter(PwmOp::Disable, ch, 0)
    }
    pub fn pwm_set_period(ch: u32, period_ns: u32) -> i32 {
        enter(PwmOp::SetPeriod, ch, period_ns)
    }
    pub fn pwm_set_duty(ch: u32, duty_ns: u32) -> i32 {
        enter(PwmOp::SetDuty, ch, duty_ns)
    }
    pub fn pwm_set_duty_pct(ch: u32, pct: u32) -> i32 {
        enter(PwmOp::SetDutyPct, ch, pct)
    }
    pub fn pwm_set_duty_pct_reporting(ch: u32, pct: u32) -> Option<u32> {
        let r = enter(PwmOp::SetDutyPct, ch, pct);
        if r >= 0 { Some(r as u32) } else { None }
    }
    /// See `gpio_write_panic`.
    pub fn pwm_set_duty_pct_panic(ch: u32, pct: u32) -> i32 {
        enter(PwmOp::SetDutyPct, ch, pct)
    }
}

pub mod i2c {
    /// What an installed probe sees of an `i2c_read`: bus, address, register
    /// and the buffer to fill; the return value is the driver's (a byte
    /// count, or negative for a fault).
    pub type I2cReadProbe = fn(u8, u8, u8, &mut [u8]) -> i32;
    static READ_PROBE: std::sync::Mutex<Option<I2cReadProbe>> = std::sync::Mutex::new(None);

    pub fn set_i2c_read_probe(p: Option<I2cReadProbe>) {
        *READ_PROBE.lock().unwrap_or_else(|e| e.into_inner()) = p;
    }

    pub fn i2c_read(bus: u8, addr: u8, reg: u8, buf: &mut [u8]) -> i32 {
        let p = *READ_PROBE.lock().unwrap_or_else(|e| e.into_inner());
        match p {
            Some(f) => f(bus, addr, reg, buf),
            None => todo!("MMIO stand-in: not reached by any test in this crate"),
        }
    }

    /// What an installed probe answers to a probe of `(bus, addr)`.
    pub type I2cDetectProbe = fn(u8, u8) -> bool;
    static DETECT_PROBE: std::sync::Mutex<Option<I2cDetectProbe>> = std::sync::Mutex::new(None);

    pub fn set_i2c_detect_probe(p: Option<I2cDetectProbe>) {
        *DETECT_PROBE.lock().unwrap_or_else(|e| e.into_inner()) = p;
    }

    pub fn i2c_detect(bus: u8, addr: u8) -> bool {
        let p = *DETECT_PROBE.lock().unwrap_or_else(|e| e.into_inner());
        match p {
            Some(f) => f(bus, addr),
            None => todo!("MMIO stand-in: not reached by any test in this crate"),
        }
    }
    /// What an installed probe sees of an `i2c_write`: the bus, the address
    /// and the payload slice the caller passed.
    pub type I2cWriteProbe = fn(u8, u8, &[u8]) -> i32;

    /// Same rule as `pwm::set_pwm_probe`: with no probe installed the entry
    /// point panics with the MMIO stand-in message. A test that installs one
    /// MUST clear it again on every exit path.
    static WRITE_PROBE: std::sync::Mutex<Option<I2cWriteProbe>> = std::sync::Mutex::new(None);

    pub fn set_i2c_write_probe(p: Option<I2cWriteProbe>) {
        *WRITE_PROBE.lock().unwrap_or_else(|e| e.into_inner()) = p;
    }

    pub fn i2c_write(bus: u8, addr: u8, data: &[u8]) -> i32 {
        let p = *WRITE_PROBE.lock().unwrap_or_else(|e| e.into_inner());
        match p {
            Some(f) => f(bus, addr, data),
            None => todo!("MMIO stand-in: not reached by any test in this crate"),
        }
    }
}

pub mod ads1115 {
    pub use crate::h3_ports::AdcPort;
    pub fn ads1115_read_mv(_channel: u8) -> Option<i32> {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn ads1115_read_battery_mv(_channel: u8, _divider_ratio: u32) -> Option<u32> {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn ads1115_is_initialized() -> bool {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod spi {
    pub use crate::h3_ports::SpiPort;
}

pub mod can {
    pub use crate::h3_ports::CanPort;
}

pub mod uart_bridge {
    pub use crate::h3_ports::{BridgePort, BRIDGE_PORT};
}

/// The holder of the buzzer's PWM channel, real code.
#[path = "../../../../../../crates/drivers/actuator/src/buzzer_channel.rs"]
pub mod buzzer_channel;

pub mod buzzer {
    pub fn buzzer_tone(_freq_hz: u16, _duration_ms: u32) {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn buzzer_off() {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

/// The real clock discipline (`azos_drv_sys::clockdisc`, no hardware in it),
/// for the pulled-in `syscall/src/clock.rs`.
#[allow(dead_code)]
#[path = "../../../../../../crates/drivers/sys/src/clockdisc.rs"]
pub mod clockdisc;

pub mod clint {
    /// The board's mtime rate. QEMU's 10 MHz, which is what the real
    /// `platform.rs` gives the `qemu` profile and therefore what this host
    /// suite should model.
    ///
    /// Needed here since 2026-09-18, when a handler stopped hardcoding
    /// `10_000_000` and started deriving its tick count from this constant —
    /// the raw number was right for QEMU and wrong for every board (VF2 runs
    /// mtime at 4 MHz, K1 at 24 MHz), so `alarm(1)` waited 2.5 s on the
    /// VisionFive 2.
    pub const TIMER_FREQ: u64 = 10_000_000;

    /// The counter `get_time` answers. A settable stand-in since the io_ring
    /// timer entry (`OP_TIMER`) reads the clock; 0 unless a test sets it.
    static NOW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    pub fn get_time() -> u64 {
        // Armed (`shim_fwd`, the info-forwarder tests): answer from the
        // recorder and log the call. Unarmed: the settable counter the io_ring
        // timer entry reads, 0 unless a test set it. Merged at wave-6
        // integration: front T made this a forwarder, front IO a counter.
        crate::shim_fwd::try_hit("get_time".into(), |f| f.now)
            .unwrap_or_else(|| NOW.load(core::sync::atomic::Ordering::SeqCst))
    }

    /// Set the counter `get_time` answers while `shim_fwd` is unarmed.
    pub fn set_time(t: u64) {
        NOW.store(t, core::sync::atomic::Ordering::SeqCst);
    }
}

pub mod csi {
    pub const JPEG_MAX_SIZE: usize = 320 * 240 / 4;
    pub fn csi_capture_jpeg(_jpeg_buf: &mut [u8]) -> usize {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn csi_capture_jpeg_stamped(_jpeg_buf: &mut [u8]) -> (usize, u64) {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod lidar {
    pub const SCAN_POINT_SIZE: usize = 4;
    pub const SCAN_DATA_MAX_BYTES: usize = 512 * SCAN_POINT_SIZE;
    pub fn lidar_read_scan(_buf: &mut [u8]) -> usize {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn lidar_read_scan_stamped(_buf: &mut [u8]) -> (usize, u64) {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn lidar_scan_count() -> usize {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod ina219 {
    pub const POWER_DATA_SIZE: usize = 12;
    pub fn ina219_read_power(_buf: &mut [u8]) -> usize {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn ina219_read_power_stamped(_buf: &mut [u8]) -> (usize, u64) {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod rangefinder {
    pub fn us_read_mm(_index: u8) -> Option<u32> {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod uart {
    pub fn acquire() {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn can_read() -> bool {
        crate::shim_fwd::hit("can_read".into(), |f| f.rx.is_some())
    }
    pub fn getc() -> u8 {
        crate::shim_fwd::hit("getc".into(), |f| f.rx.expect("getc with nothing to read"))
    }
    pub fn putc(c: u8) {
        crate::shim_fwd::hit(format!("putc {c:#04x}"), |_| ())
    }
    pub fn puts(_s: &str) {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    /// Same `todo!()` as its unlocked twin, and for the same reason: no test
    /// in this crate reaches a console write. A stub that silently succeeded
    /// would make some other function's behaviour look like part of what this
    /// crate proves.
    pub fn puts_locked(s: &str) {
        crate::shim_fwd::hit(format!("puts_locked {s:?}"), |_| ())
    }
    /// `sys_reboot`/`sys_shutdown` call this after their capability gate
    /// and before the SBI stand-in; recorded so a test can see it ran.
    pub fn console_flush_for_reboot() {
        crate::shim_fwd::hit("console_flush_for_reboot".into(), |_| ())
    }
    pub fn write_str_translated(_bytes: &[u8]) {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    /// The `Console`-dispatched write `sys_write`'s fd 1/2 arm now calls.
    /// Same `todo!()` as the direct writer next to it and for the same
    /// reason: no test in this crate reaches a console write, and a stub
    /// that silently succeeded would make some other function's behaviour
    /// look like part of what this crate proves. The real one
    /// (`crates/drivers/sys/src/uart.rs`) dispatches through whichever
    /// `Console` boot registered; here there is no boot and no device.
    /// Ring-3 console path (Mutex line lock in the real uart.rs, 2026-09-26).
    ///
    /// `sys_putchar` writes its byte through this (wave 11): recorded, so
    /// the test sees which path the byte took.
    pub fn console_write_ring3(bytes: &[u8]) {
        crate::shim_fwd::hit(format!("console_write_ring3 {bytes:?}"), |_| ())
    }
    pub fn console_write(_bytes: &[u8]) {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod virtio {
    /// Stand-in for `azos_drv_virtio::virtio::snd`: the entry points
    /// `sound_host.rs` calls, with the signatures of the real module, over a
    /// model of one device that a test scripts and inspects ([`fake`]). The
    /// model keeps what the host did to it (every call, every period it was
    /// handed) and completes a period only when the test says so, so the
    /// host's pump is the only thing under test.
    pub mod snd {
        use azos_devif::sound::{self as iface, Geometry, Params, Period, Status};
        use std::collections::VecDeque;
        use std::sync::{Mutex, MutexGuard};

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Error {
            NoDevice,
            Busy,
            Unsupported,
            BadArgument,
            NotReady,
            Fault,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Submit {
            Queued,
            Full,
            Dup,
            Bad,
            NotOpen,
        }

        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct Caps {
            pub dirs: u32,
            pub formats: u32,
            pub rate_hz: u32,
            pub channels: u32,
        }

        /// One direction of the modelled device.
        #[derive(Default)]
        pub struct Stream {
            pub open: bool,
            pub running: bool,
            pub draining: bool,
            pub arena_phys: u64,
            /// `(index, frames)` handed to the device and not completed.
            pub in_flight: Vec<(u32, u32)>,
            /// Every `(index, frames)` the host ever submitted.
            pub submitted: Vec<(u32, u32)>,
            pub done: VecDeque<Period>,
        }

        pub struct Fake {
            pub caps: Option<Caps>,
            pub s: [Stream; 2],
            /// `"open play"`, `"stop rec"`, ...: every call, in order.
            pub calls: Vec<String>,
            pub fail_open: Option<Error>,
            /// Periods the device takes at once.
            pub room: usize,
            /// Frames the capture buffer being filled holds when a drain asks.
            pub partial_frames: u32,
        }

        impl Fake {
            const fn new() -> Fake {
                Fake {
                    caps: None,
                    s: [Stream { open: false, running: false, draining: false, arena_phys: 0, in_flight: Vec::new(), submitted: Vec::new(), done: VecDeque::new() },
                        Stream { open: false, running: false, draining: false, arena_phys: 0, in_flight: Vec::new(), submitted: Vec::new(), done: VecDeque::new() }],
                    calls: Vec::new(),
                    fail_open: None,
                    room: 4,
                    partial_frames: 0,
                }
            }

            /// The device finishes the `n` oldest periods in flight of
            /// direction `dir`: played, or (capture) filled with `frames`.
            pub fn complete(&mut self, dir: u32, n: usize, capture_frames: Option<u32>) {
                let st = &mut self.s[idx(dir)];
                for _ in 0..n.min(st.in_flight.len()) {
                    let (index, frames) = st.in_flight.remove(0);
                    st.done.push_back(Period { index, frames: capture_frames.unwrap_or(frames), flags: 0, time_ns: 0 });
                }
            }

            /// Back to a device that is up and takes both directions.
            pub fn reset(&mut self) {
                *self = Fake::new();
                self.caps = Some(Caps {
                    dirs: iface::DIR_PLAYBACK | iface::DIR_CAPTURE,
                    formats: iface::format_bit(iface::FMT_S16) | iface::format_bit(iface::FMT_F32),
                    rate_hz: 48_000,
                    channels: 2,
                });
            }
        }

        static FAKE: Mutex<Fake> = Mutex::new(Fake::new());

        /// The model, locked.
        pub fn fake() -> MutexGuard<'static, Fake> {
            FAKE.lock().unwrap_or_else(|e| e.into_inner())
        }

        fn idx(dir: u32) -> usize {
            usize::from(dir == iface::DIR_CAPTURE)
        }

        fn tag(dir: u32) -> &'static str {
            if dir == iface::DIR_CAPTURE { "rec" } else { "play" }
        }

        fn cancel_all(st: &mut Stream) {
            for (index, _) in st.in_flight.drain(..) {
                st.done.push_back(Period { index, frames: 0, flags: iface::PERIOD_CANCELLED, time_ns: 0 });
            }
        }

        pub fn caps() -> Option<Caps> {
            fake().caps
        }

        pub fn open(dir: u32, _p: &Params, _geo: &Geometry, arena_phys: u64) -> Result<(), Error> {
            let mut f = fake();
            f.calls.push(format!("open {}", tag(dir)));
            if let Some(e) = f.fail_open {
                return Err(e);
            }
            let st = &mut f.s[idx(dir)];
            if st.open {
                return Err(Error::Busy);
            }
            *st = Stream { open: true, arena_phys, ..Stream::default() };
            Ok(())
        }

        pub fn start(dir: u32) -> Result<(), Error> {
            let mut f = fake();
            f.calls.push(format!("start {}", tag(dir)));
            let st = &mut f.s[idx(dir)];
            if !st.open {
                return Err(Error::NotReady);
            }
            if st.draining {
                return Err(Error::Busy);
            }
            st.running = true;
            Ok(())
        }

        pub fn stop(dir: u32) -> Result<(), Error> {
            let mut f = fake();
            f.calls.push(format!("stop {}", tag(dir)));
            let st = &mut f.s[idx(dir)];
            if st.open {
                cancel_all(st);
                st.running = false;
                st.draining = false;
            }
            Ok(())
        }

        pub fn drain(dir: u32) -> Result<bool, Error> {
            let mut f = fake();
            f.calls.push(format!("drain {}", tag(dir)));
            let partial = f.partial_frames;
            let st = &mut f.s[idx(dir)];
            if !st.open {
                return Err(Error::NotReady);
            }
            if dir == iface::DIR_PLAYBACK {
                st.draining = true;
                return Ok(false);
            }
            // The real device stops and prepares again: the stream is open.
            st.running = false;
            let mut first = true;
            for (index, _) in st.in_flight.drain(..) {
                let p = if std::mem::take(&mut first) && partial > 0 {
                    Period { index, frames: partial, flags: 0, time_ns: 0 }
                } else {
                    Period { index, frames: 0, flags: iface::PERIOD_CANCELLED, time_ns: 0 }
                };
                st.done.push_back(p);
            }
            Ok(true)
        }

        pub fn drained(dir: u32) -> bool {
            let f = fake();
            let st = &f.s[idx(dir)];
            st.open && st.draining && st.in_flight.is_empty()
        }

        pub fn finish_drain(dir: u32) -> Result<(), Error> {
            let mut f = fake();
            f.calls.push(format!("finish_drain {}", tag(dir)));
            let st = &mut f.s[idx(dir)];
            st.draining = false;
            st.running = false;
            Ok(())
        }

        pub fn close(dir: u32) -> Result<(), Error> {
            let mut f = fake();
            f.calls.push(format!("close {}", tag(dir)));
            let st = &mut f.s[idx(dir)];
            cancel_all(st);
            st.open = false;
            st.running = false;
            st.draining = false;
            Ok(())
        }

        pub fn room(dir: u32) -> bool {
            let f = fake();
            let st = &f.s[idx(dir)];
            st.open && st.in_flight.len() < f.room
        }

        pub fn submit(dir: u32, index: u32, frames: u32) -> Submit {
            let mut f = fake();
            let room = f.room;
            let st = &mut f.s[idx(dir)];
            if !st.open {
                return Submit::NotOpen;
            }
            if st.in_flight.iter().any(|&(i, _)| i == index) {
                return Submit::Dup;
            }
            if st.in_flight.len() >= room {
                return Submit::Full;
            }
            st.in_flight.push((index, frames));
            st.submitted.push((index, frames));
            Submit::Queued
        }

        pub fn reap(_dir: u32) -> usize {
            0
        }

        pub fn take_done(dir: u32) -> Option<Period> {
            fake().s[idx(dir)].done.pop_front()
        }

        pub fn status(dir: u32) -> Status {
            let f = fake();
            let st = &f.s[idx(dir)];
            let state = match (st.open, st.running, st.draining) {
                (false, ..) => iface::STATE_CLOSED,
                (_, _, true) => iface::STATE_DRAINING,
                (_, true, _) => iface::STATE_RUNNING,
                _ => iface::STATE_OPEN,
            };
            Status { state, xruns: 0, frames: 0 }
        }
    }

    pub mod blk {
        pub fn capacity_sectors() -> u64 {
            crate::shim_fwd::hit("capacity_sectors".into(), |f| f.sectors)
        }
        pub fn read(_sector: u64, _count: u32, _buf: &mut [u8]) -> Result<(), ()> {
            todo!("MMIO stand-in: not reached by any test in this crate")
        }
        pub fn write(_sector: u64, _count: u32, _buf: &[u8]) -> Result<(), ()> {
            todo!("MMIO stand-in: not reached by any test in this crate")
        }
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

    /// `crate::power`: the scheduler rate, a plain cell here.
    static SCHED_HZ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(100);

    /// Mirrors `azos_drv_sys::timebase::sched_hz_set`.
    pub fn sched_hz_set(hz: u64) {
        SCHED_HZ.store(hz, core::sync::atomic::Ordering::Relaxed);
    }

    /// Mirrors `azos_drv_sys::timebase::sched_hz_get`.
    pub fn sched_hz_get() -> u64 {
        SCHED_HZ.load(core::sync::atomic::Ordering::Relaxed)
    }
}

/// `crate::power`: the suspend, as a counter.
pub mod pm {
    /// Suspends taken, for a test that wants to see one did (or did not) run.
    pub static SUSPENDS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    /// The reason the next suspend is refused with; 0 lets it work.
    pub static REFUSE_WITH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    /// Mirrors `azos_drv_power::pm::pm_suspend` (the sequence, on the kernel):
    /// the suspend works unless a test set [`REFUSE_WITH`].
    pub fn pm_suspend(_caller: u32, _subject: u32) -> u32 {
        let why = REFUSE_WITH.load(core::sync::atomic::Ordering::Relaxed);
        if why == 0 {
            SUSPENDS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        why
    }
}

/// An armed recorder for the device reads and prints that the console and
/// info syscalls forward to (`uart` read/write, `*_info`, disk capacity, the
/// timer).
///
/// **Unarmed, every one of those functions is still the MMIO stand-in's
/// `todo!()`, with the same message** — several tests assert that exact panic
/// (`#[should_panic(expected = "MMIO stand-in")]`) as proof that a guard let a
/// call through, and a recorder that answered by default would make those
/// canaries un-fireable. `harness.rs::reset_state` disarms it.
pub mod shim_fwd {
    use std::sync::Mutex;

    /// What the armed stand-ins answer, and what they were asked.
    #[derive(Default, Debug)]
    pub struct Fwd {
        /// The byte the UART holds, or `None` for an empty receive FIFO.
        pub rx: Option<u8>,
        /// What `virtio::blk::capacity_sectors` reports.
        pub sectors: u64,
        /// What `clint::get_time` (and so `timebase::now`) reports.
        pub now: u64,
        /// Every call, in order.
        pub log: Vec<String>,
    }

    static ARMED: Mutex<Option<Fwd>> = Mutex::new(None);

    pub fn arm(f: Fwd) {
        *ARMED.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    }

    /// Disarm, returning what was recorded.
    pub fn disarm() -> Option<Fwd> {
        ARMED.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// `hit` for a stand-in that has an unarmed answer of its own: `None`
    /// when unarmed instead of the `todo!()`.
    pub(crate) fn try_hit<R>(what: String, f: impl FnOnce(&Fwd) -> R) -> Option<R> {
        let mut g = ARMED.lock().unwrap_or_else(|e| e.into_inner());
        g.as_mut().map(|a| {
            a.log.push(what);
            f(a)
        })
    }

    /// A test's own stand-in (a `FileOps`, a hook) recording into the same
    /// ordered log, when armed: what an ordering test compares against.
    pub fn note(what: &str) {
        let _ = try_hit(what.into(), |_| ());
    }

    pub(crate) fn hit<R>(what: String, f: impl FnOnce(&Fwd) -> R) -> R {
        let mut g = ARMED.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_mut() {
            Some(a) => {
                a.log.push(what);
                f(a)
            }
            None => todo!("MMIO stand-in: not reached by any test in this crate"),
        }
    }
}

/// The partition table parser and the published table the `block` endpoint is
/// scoped by partition — the REAL module: it names only `core`.
#[path = "../../../../../../crates/drivers/block/src/partition.rs"]
pub mod partition;

/// The block layer's write observer, the real file (wave 14, FATCACHE):
/// `block_io` reports its sectors through `blkdev::note_external_write`.
/// No observer is installed in this crate, so the report is a no-op here.
#[path = "../../../../../../crates/drivers/block/src/write_observer.rs"]
pub mod write_observer;

/// Mirrors the one `azos_drv_block::blkdev` entry `handlers.rs` names.
pub mod blkdev {
    /// The real one runs the kernel's RT_BLOCK_IO_CHECK; the host has no RT task.
    pub fn rt_io_check() {}
    /// `blkdev::shutdown` (the orderly power-off's disk step): recorded.
    pub fn shutdown() {
        crate::shim_fwd::hit("blkdev_shutdown".into(), |_| ())
    }
    pub fn note_external_write(sector: u64, count: u32) {
        crate::write_observer::notify(sector, count);
    }
    /// The kernel's `blkdev::note_external_read` (wave 15): the read observer.
    pub fn note_external_read(sector: u64, count: u32) {
        crate::write_observer::before_read(sector, count);
    }
    /// The kernel's `blkdev::read_would_wait`: the read observer's dirty probe.
    pub fn read_would_wait(sector: u64, count: u32) -> bool {
        crate::write_observer::read_would_wait(sector, count)
    }
    /// `blkdev::capacity_sectors`: the same armed answer `virtio::blk` gives.
    pub fn capacity_sectors() -> u64 {
        crate::shim_fwd::hit("capacity_sectors".into(), |f| f.sectors)
    }
    /// What a test arms to stand in for the device: `(write, absolute sector,
    /// sector count, bytes)`. On a read the probe fills the bytes; on a write
    /// it sees what the caller handed over.
    pub type BlkProbe = fn(write: bool, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()>;
    static PROBE: std::sync::Mutex<Option<BlkProbe>> = std::sync::Mutex::new(None);
    pub fn set_blk_probe(p: Option<BlkProbe>) {
        *PROBE.lock().unwrap_or_else(|e| e.into_inner()) = p;
    }
    fn blk_probe() -> BlkProbe {
        PROBE.lock().unwrap_or_else(|e| e.into_inner())
            .unwrap_or_else(|| todo!("MMIO stand-in: no probe armed"))
    }
    /// `blkdev::read_raw` / `write_raw`: the device stand-ins, through the
    /// armed probe.
    pub fn read_raw(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        blk_probe()(false, sector, count, buf)
    }
    pub fn write_raw(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
        let mut copy = buf.to_vec();
        blk_probe()(true, sector, count, &mut copy)
    }

    // ── The request layer (`blkdev::submit_raw` / `wait_raw`) ─────────────
    //
    // The real one queues the request with a pointer to the caller's buffer and
    // reads or writes that buffer only when somebody waits; this stand-in does
    // the same, through the armed probe, so a test sees WHEN the buffer is
    // touched.

    /// A queued raw transfer.
    #[derive(Clone, Copy, Debug)]
    pub struct RawTicket(u32);

    struct RawReq { id: u32, owner: u32, write: bool, sector: u64, count: u32, buf: usize }
    struct RawLayer { max: Option<u32>, full: bool, next: u32, q: Vec<RawReq> }
    static RAW: std::sync::Mutex<RawLayer> = std::sync::Mutex::new(RawLayer { max: None, full: false, next: 1, q: Vec::new() });

    /// Put the request layer behind the stand-in: `max` sectors a request (None:
    /// the board's disk is not behind it), `full`: the queue takes nothing.
    /// Forgets what was queued.
    pub fn set_raw_layer(max: Option<u32>, full: bool) {
        *RAW.lock().unwrap_or_else(|e| e.into_inner()) = RawLayer { max, full, next: 1, q: Vec::new() };
    }
    /// `(owner, write, absolute sector, count)` of every queued, uncollected request.
    pub fn raw_queued() -> Vec<(u32, bool, u64, u32)> {
        RAW.lock().unwrap_or_else(|e| e.into_inner()).q.iter().map(|r| (r.owner, r.write, r.sector, r.count)).collect()
    }
    pub fn raw_max_sectors() -> Option<u32> {
        RAW.lock().unwrap_or_else(|e| e.into_inner()).max
    }
    /// # Safety
    /// `buf` stays valid until `wait_raw` returns for the ticket.
    pub unsafe fn submit_raw(owner: u32, write: bool, sector: u64, count: u32, buf: *mut u8) -> Result<RawTicket, ()> {
        let mut l = RAW.lock().unwrap_or_else(|e| e.into_inner());
        if l.max.is_none() || l.full {
            return Err(());
        }
        let id = l.next;
        l.next += 1;
        l.q.push(RawReq { id, owner, write, sector, count, buf: buf as usize });
        Ok(RawTicket(id))
    }
    /// The device runs the request now: the probe sees the buffer.
    pub fn wait_raw(t: RawTicket) -> Result<(), ()> {
        let r = {
            let mut l = RAW.lock().unwrap_or_else(|e| e.into_inner());
            let i = l.q.iter().position(|r| r.id == t.0).ok_or(())?;
            l.q.remove(i)
        };
        let len = r.count as usize * 512;
        // SAFETY: the submitter's contract: the buffer is `count * 512` bytes.
        let buf = unsafe { core::slice::from_raw_parts_mut(r.buf as *mut u8, len) };
        blk_probe()(r.write, r.sector, r.count, buf)
    }
}

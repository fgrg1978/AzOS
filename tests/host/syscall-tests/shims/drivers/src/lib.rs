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

/// The board's MMIO region table, the REAL module: `denial_target` looks an
/// `MmioRegion` capability's base up in it (RFC-0043). Constants and two
/// `const fn`s, nothing that needs a device.
#[path = "../../../../../../crates/drivers/base/src/platform.rs"]
pub mod platform;

/// Third real module, not a stand-in — same rationale as `runtime::registry`.
///
/// `pwm_domain` states which PWM channels one control-register write actually
/// reaches (on the JH7110 the enable bit and prescaler share one `PWMCFG`, so
/// a write named for any channel reaches all four). `handlers.rs` consults it
/// in `pwm_control_cap_ok` and in the `SYS_DRV_INVOKE` PWM guard. It is pure
/// arithmetic over a description of the hardware with no dependencies at all
/// — no MMIO, no locks — so it is pulled verbatim rather than reproduced.
/// Reproducing it would be actively wrong: a stand-in that disagreed with the
/// real domain would let these tests certify a check the board does not make.
#[path = "../../../../../../crates/drivers/actuator/src/pwm_domain.rs"]
pub mod pwm_domain;

// Real, and needs no stand-in: `drv_resource.rs` is dependency-free by design
// (it is the module the per-op resource predicates live in, deliberately kept
// clear of the drivers that use them). `handlers.rs` reaches
// `motor_bridge_op_needs_pair` through it.
#[path = "../../../../../../crates/drivers/base/src/drv_resource.rs"]
pub mod drv_resource;

/// Opcode constants mirrored from `crates/drivers/actuator/src/pwm_driver.rs`.
///
/// Copied rather than `#[path]`-pulled because that file also carries the
/// `Driver` trait impl and an `MmioRange` manifest, neither of which has a
/// stand-in here. Only these three are referenced (by the `SYS_DRV_INVOKE`
/// guard, which asks whether an op writes the shared `PWMCFG`).
///
/// **A copied constant is load-bearing here in a way the domain is not.** If
/// one of these drifts from the real driver, the guard's `match` silently
/// routes that opcode to the duty arm and stops checking the shared reach —
/// and no test in this crate can see it, because the opcode it compares
/// against would have drifted too. Check them against the real file when
/// touching either.
pub mod pwm_driver {
    /// Mirrors `pwm_driver::PWM_OP_ENABLE`.
    pub const PWM_OP_ENABLE: u32 = 0;
    /// Mirrors `pwm_driver::PWM_OP_DISABLE`.
    pub const PWM_OP_DISABLE: u32 = 1;
    /// Mirrors `pwm_driver::PWM_OP_SET_PERIOD`.
    pub const PWM_OP_SET_PERIOD: u32 = 2;
}

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

pub mod gpio {
    use std::sync::Mutex;

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
    pub fn gpio_info() {
        crate::shim_fwd::hit("gpio_info".into(), |_| ())
    }
    /// `motor_stop_panic` (real, `shims/robot`) calls it; no test does.
    pub fn gpio_write_panic(_pin: u32, _val: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod pwm {
    use std::sync::Mutex;

    /// Which PWM entry point a probe was called from. Only the entry points
    /// the real `domains/robot/robot/src/motor.rs` calls take a probe.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum PwmOp {
        Enable,
        SetPeriod,
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
    pub fn pwm_disable(_ch: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn pwm_set_period(ch: u32, period_ns: u32) -> i32 {
        enter(PwmOp::SetPeriod, ch, period_ns)
    }
    pub fn pwm_set_duty(_ch: u32, _duty_ns: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn pwm_set_duty_pct(ch: u32, pct: u32) -> i32 {
        enter(PwmOp::SetDutyPct, ch, pct)
    }
    pub fn pwm_set_duty_pct_reporting(ch: u32, pct: u32) -> Option<u32> {
        let r = enter(PwmOp::SetDutyPct, ch, pct);
        if r >= 0 { Some(r as u32) } else { None }
    }
    /// `motor_stop_panic` (real, `shims/robot`) calls it; no test does.
    pub fn pwm_set_duty_pct_panic(_ch: u32, _pct: u32) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn pwm_info() {
        crate::shim_fwd::hit("pwm_info".into(), |_| ())
    }
}

pub mod i2c {
    pub fn i2c_read(_bus: u8, _addr: u8, _reg: u8, _buf: &mut [u8]) -> i32 {
        todo!("MMIO stand-in: not reached by any test in this crate")
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
    pub fn i2c_scan(_bus: u8) {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn i2c_info() {
        crate::shim_fwd::hit("i2c_info".into(), |_| ())
    }
}

pub mod ads1115 {
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

pub mod buzzer {
    pub fn buzzer_tone(_freq_hz: u16, _duration_ms: u32) {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
    pub fn buzzer_off() {
        todo!("MMIO stand-in: not reached by any test in this crate")
    }
}

pub mod clint {
    /// The board's mtime rate. QEMU's 10 MHz, which is what the real
    /// `platform.rs` gives the `qemu` profile and therefore what this host
    /// suite should model.
    ///
    /// Needed here since 2026-09-18, when `sys_alarm` stopped hardcoding
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
    /// Ring-3 console path (PiMutex line lock in the real uart.rs, 2026-09-26).
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

    /// RFC-0055 S5 (`crate::power`): the scheduler rate, a plain cell here.
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

/// RFC-0055 S5 (`crate::power`): the suspend, as a counter.
pub mod pm {
    /// Suspends taken, for a test that wants to see one did (or did not) run.
    pub static SUSPENDS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    /// Mirrors `azos_drv_power::pm::pm_suspend` (a WFI on the kernel).
    pub fn pm_suspend() {
        SUSPENDS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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

/// The partition table parser and the published table `Cap<Disk>` is scoped
/// by (RFC-0048 P3) — the REAL module: it names only `core`.
#[path = "../../../../../../crates/drivers/block/src/partition.rs"]
pub mod partition;

/// The block layer's write observer, the real file (wave 14, FATCACHE):
/// `sys_disk_write` reports its sectors through `blkdev::note_external_write`.
/// No observer is installed in this crate, so the report is a no-op here.
#[path = "../../../../../../crates/drivers/block/src/write_observer.rs"]
pub mod write_observer;

/// Mirrors the one `azos_drv_block::blkdev` entry `handlers.rs` names.
pub mod blkdev {
    pub fn note_external_write(sector: u64, count: u32) {
        crate::write_observer::notify(sector, count);
    }
}

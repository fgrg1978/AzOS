// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 INA219 power-monitor driver: the ring-3 host of
//! `crates/drivers/ina219`, built into the image when Kconfig
//! `DRV_INA219_PLACEMENT` is `ring3` (the default).
//!
//! Started at boot by the component manager (`userspace/services/compmgr`, from
//! the row's `start = true`), with the capabilities of its own topology row,
//! `INADRV.ELF`: the `i2c` endpoint of `1.0x40` READ|WRITE and the endpoints it
//! serves. It configures the chip, polls it at `INA219_POLL_HZ`, and serves
//! the `PowerMon` interface (`azos_devif::powermon`) on `endpoint.powermon`
//! with the last sample, which is what `SYS_SENSOR_READ(SENSOR_TYPE_POWER)`
//! returns. Each sample is integrated over the time the vDSO clock measured
//! since the previous one, not over a nominal 1/`INA219_POLL_HZ`.
//!
//! Two threads: the main one samples, parked between samples; the other
//! accepts calls (`SYS_IPC_ACCEPT` waits for nothing but a call), so a read
//! waits for the answer, not for a poll period. The chip state is behind one
//! lock they share, held across a few register-form I2C calls.
//!
//! **Runtime power management.** The monitor is a device with a power state
//! (`azos_devif::power::runtime`): when nothing has used it for its idle
//! timeout (set by the power service, 0 = never, the default), the driver
//! puts the chip in its power-down mode (MODE bits of the configuration
//! register) and stops sampling; the next read resumes it (the
//! configuration is written again and a fresh sample is taken before the
//! reply), so a read after a pause never answers with the sample from before
//! it. The `DevicePower` interface is served on the endpoint the row grants
//! (`endpoint.pm-ina`, `READ`), by the same thread, which is how the power
//! service sets the timeout, takes a wakelock for it or reads its records. The
//! server answers an op only when the badge of the call carries its class
//! (`runtime::classes_of`): a call with none is refused. In a topology
//! without the row the monitor never autosuspends. Charge is integrated
//! over the whole pause by the first sample after it (the chip's rule: a
//! sample covers the time since the previous published one).

#![no_std]
#![no_main]


// The chip logic and the interface it serves are `crates/drivers/ina219`, the
// same source the in-kernel host compiles.
use azos_devif::powermon::{PowerMon, PowerMonIdl, PowerStats};
use azos_devif::{outcome, IdlError, Out, Sample};
use azos_ina219::{Bus, Ina219, Monitor, INA219_ADDR, INA219_BUS, INA219_POLL_HZ, SOURCE_MARKER};
use azos_libsys as sys;
use sys::dev::{Bytes, Ep, I2cCall, I2cClient, MsgDesc};

// The order in which a call is served while the chip has a power state is
// `request.rs` (`tests/host/power-tests` pulls it in by path).
mod request;
use request::{serve_use, Unit};

/// The runtime power core of this driver's device (`azos_devif::power::runtime`).
type Pm = sys::dev::power::runtime::RuntimePm;

/// Time between chip samples: 1 / `INA219_POLL_HZ`.
const SAMPLE_PERIOD_US: u64 = 1_000_000 / INA219_POLL_HZ as u64;
/// Longest park with nothing timed: a suspended monitor with no lease. This
/// bounds how long a resume made on the endpoint waits for the loop to notice
/// it.
const IDLE_PARK_MS: u32 = 1_000;
/// Wait before accepting again after the endpoint answered nothing (a row
/// that grants none): the thread costs one wake-up a period, not a spin.
const ACCEPT_RETRY_MS: u64 = 1_000;

/// The INA219 configuration register and its power-down value: `CONFIG_DEFAULT`
/// (0x399F, `crates/drivers/ina219/src/chip.rs`) with the MODE bits [2:0] at
/// 000. The chip crate keeps its register map private; the two constants are
/// the whole of what this host adds to it.
const REG_CONFIG: u8 = 0x00;
const CONFIG_POWER_DOWN: [u8; 2] = 0x3998u16.to_be_bytes();

/// The monotonic clock in microseconds (vDSO), or `None` when the kernel
/// publishes no clock (the page reads 0).
fn clock_us() -> Option<u64> {
    match sys::vdso_now_ns() {
        0 => None,
        ns => Some(ns / 1000),
    }
}

/// The monitor behind this task's the `i2c` endpoint.
///
/// `first_read_ns` is the acquisition stamp of the sample being taken: the
/// vDSO clock read right after the FIRST register read of [`sample`] that
/// succeeded (the bus voltage), so the record's age is never smaller than
/// any of its fields'. Cleared by `sample` before each poll.
struct CapBus {
    bus: I2cClient<Ep>,
    first_read_ns: u64,
}

impl Bus for CapBus {
    fn write(&mut self, data: &[u8]) -> bool {
        sys::dev::succeeded(self.bus.write(Bytes::from_slice(data)))
    }
    fn read(&mut self, reg: u8, buf: &mut [u8]) -> bool {
        let got = match sys::dev::value(self.bus.read(reg as u32, buf.len() as u32)) {
            Ok(b) => b.copy_to(buf),
            Err(_) => 0,
        };
        let ok = got == buf.len();
        if ok && self.first_read_ns == 0 {
            self.first_read_ns = sys::vdso_now_ns();
        }
        ok
    }
}

/// Everything the main loop and the endpoint thread share.
struct State {
    chip: Ina219,
    bus: CapBus,
    /// Acquisition stamp of the sample `chip` currently serves.
    acq_ns: u64,
    pm: Pm,
    /// With no clock, samples are timed by the loop itself.
    clocked: bool,
    t_us: u64,
    next_us: u64,
}

/// The chip as the runtime PM core powers it down and up.
struct PowerOf<'a> {
    chip: &'a mut Ina219,
    bus: &'a mut CapBus,
}

impl sys::dev::power::runtime::PmDevice for PowerOf<'_> {
    fn suspend(&mut self) -> bool {
        self.bus.write(&[REG_CONFIG, CONFIG_POWER_DOWN[0], CONFIG_POWER_DOWN[1]])
    }
    fn resume(&mut self) -> bool {
        self.chip.init(self.bus)
    }
}

impl State {
    /// The PM clock: the vDSO's, or the loop's own count of periods when the
    /// kernel publishes none.
    fn now_ns(&self) -> u64 {
        match sys::vdso_now_ns() {
            0 => self.t_us.saturating_mul(1000),
            ns => ns,
        }
    }

    /// The chip is running again: take a sample now, so what is served next is
    /// not from before the pause, and restart the sampling cadence.
    fn woke(&mut self) {
        if let Some(t) = clock_us() {
            self.t_us = t;
        }
        poll_stamped(&mut self.chip, &mut self.bus, self.t_us, &mut self.acq_ns);
        self.next_us = self.t_us + SAMPLE_PERIOD_US;
    }

    /// Advance the PM clock and, active and due, take the sample.
    fn step(&mut self) {
        let now = self.now_ns();
        let mut dev = PowerOf { chip: &mut self.chip, bus: &mut self.bus };
        self.pm.tick(&mut dev, now);
        if self.pm.is_suspended() {
            return;
        }
        if self.clocked {
            self.t_us = clock_us().unwrap_or(self.t_us);
            if self.t_us >= self.next_us {
                sample(&mut self.chip, &mut self.bus, self.t_us, &mut self.acq_ns);
                self.next_us += SAMPLE_PERIOD_US;
                if self.next_us <= self.t_us {
                    self.next_us = self.t_us + SAMPLE_PERIOD_US;
                }
            }
        }
    }

    /// How long the loop may park: to the next sample, or the next PM event
    /// if that is sooner.
    fn park_ms(&self) -> u32 {
        let sample_ms = if self.pm.is_suspended() {
            IDLE_PARK_MS as u64
        } else if self.clocked {
            self.next_us.saturating_sub(self.t_us).div_ceil(1000)
        } else {
            SAMPLE_PERIOD_US / 1000
        };
        let pm_ms = match self.pm.next_deadline_ns() {
            Some(d) => d.saturating_sub(self.now_ns()).div_ceil(1_000_000),
            None => u64::MAX,
        };
        sample_ms.min(pm_ms).clamp(1, IDLE_PARK_MS as u64) as u32
    }
}

/// What the two threads share.
static SHARED: sys::Lock<Option<State>> = sys::Lock::new(None);

/// Run `f` on the shared state. Spins (yielding) while the other thread has
/// it: its critical sections are a few register-form I2C calls long.
fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let r = SHARED.lock().as_mut().map(f);
    r.expect("ina_drv: state used before it was set up")
}

impl Unit for State {
    fn begin(&mut self) -> Option<bool> {
        let was = self.pm.is_suspended();
        let now = self.now_ns();
        let mut dev = PowerOf { chip: &mut self.chip, bus: &mut self.bus };
        self.pm.on_use(&mut dev, now).ok().map(|()| was)
    }
    fn woke(&mut self) {
        State::woke(self)
    }
    fn done(&mut self) {
        let now = self.now_ns();
        self.pm.idle(now);
    }
}

/// The `PowerMon` interface over the shared state: each call is a use of the
/// monitor, answered from its state after it (`request::serve_use`). A chip
/// that cannot be resumed is a `FAULT`, with no data.
struct Served;

impl PowerMon for Served {
    fn read(&mut self) -> Out<Sample> {
        with(|st| serve_use(st, |st| Monitor { chip: &st.chip, acq_ns: st.acq_ns }.read()))
            .unwrap_or(Out::err(outcome::FAULT))
    }

    fn stats(&mut self) -> Out<PowerStats> {
        with(|st| serve_use(st, |st| Monitor { chip: &st.chip, acq_ns: st.acq_ns }.stats()))
            .unwrap_or(Out::err(outcome::FAULT))
    }
}

/// The endpoint thread's stack.
#[repr(C, align(16))]
struct Stack([u8; 8192]);
static mut PM_STACK: Stack = Stack([0; 8192]);

/// Serve `PowerMon` and `DevicePower` on the endpoints the row grants, for
/// ever. A call that resumes the chip takes the fresh sample before it is
/// answered.
extern "C" fn serve_thread(_: u64, _: u64, _: u64) -> ! {
    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // No endpoint granted (a topology without the row), or a spurious wake: look again later.
            sys::sleep(ACCEPT_RETRY_MS);
            continue;
        }
        let mut rep = MsgDesc::default();
        if PowerMonIdl::dispatch(&mut Served, &req, &mut rep) == Err(IdlError::BadInterface) {
            with(|st| {
                let was = st.pm.is_suspended();
                let now = st.now_ns();
                let mut dev = PowerOf { chip: &mut st.chip, bus: &mut st.bus };
                let mut srv = sys::dev::power::runtime::PmServer {
                    pm: &mut st.pm,
                    dev: &mut dev,
                    now_ns: now,
                    classes: sys::dev::power::runtime::classes_of(&req),
                };
                let _ = sys::dev::power::DevicePowerIdl::dispatch(&mut srv, &req, &mut rep);
                if was && !st.pm.is_suspended() {
                    st.woke();
                }
            });
        }
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let Some(i2c) = sys::dev::lookup(sys::dev::key::I2C, sys::dev::i2c::badge(INA219_BUS, INA219_ADDR)) else {
        sys::println(b"[inadrv] FAILED: no i2c endpoint for bus 1, address 0x40");
        sys::exit(1);
    };
    let mut bus = CapBus { bus: I2cClient::new(Ep(i2c)), first_read_ns: 0 };
    let mut acq_ns: u64 = 0;
    let mut chip = Ina219::new();
    // Configured before serving, so the first read already has a configured
    // chip behind it. A chip that does not answer leaves the
    // driver serving "no data"; it is retried every sample period.
    if !chip.init(&mut bus) {
        sys::println(b"[inadrv] INA219 did not accept its configuration, retrying");
    }
    // With no clock, samples are timed by the loop itself: one period per
    // park that ran to its end, the cadence the integration used to assume.
    let clocked = clock_us().is_some();
    let t_us = clock_us().unwrap_or(0);
    poll_stamped(&mut chip, &mut bus, t_us, &mut acq_ns);
    sys::println(b"[inadrv] serving the PowerMon interface on endpoint.powermon");
    // The chip-logic source this host runs (`tools/lint/chip_source_check.py`).
    sys::print(b"[inadrv] ");
    sys::println(&SOURCE_MARKER);

    let quota = sys::dev::power::runtime::Quota::new(azos_limits::DEVICE_WAKELOCKS as u32, azos_limits::DEVICE_WAKELOCK_TTL_MAX_MS as u32);
    let state = State {
        chip,
        bus,
        acq_ns,
        pm: Pm::new(quota, 0),
        clocked,
        t_us,
        next_us: t_us + SAMPLE_PERIOD_US,
    };
    {
        let mut shared = SHARED.lock();
        let st = shared.insert(state);
        st.pm = Pm::new(quota, st.now_ns());
    }
    // The stack is the endpoint thread's alone, and its top is 16-aligned.
    let top = core::ptr::addr_of_mut!(PM_STACK) as usize + core::mem::size_of::<Stack>();
    if sys::thread_create(serve_thread, top, 0, core::ptr::null_mut()) < 0 {
        sys::println(b"[inadrv] FAILED: no thread for the endpoints");
        sys::exit(1);
    }

    loop {
        // Clocked: sample whenever the time has come, however the park ended.
        // A loop that fell behind resynchronises instead of sampling in a burst.
        let park_ms = with(|st| {
            st.step();
            st.park_ms()
        });
        sys::sleep(park_ms as u64);
        // No clock: a park that ran to its end is one period.
        with(|st| {
            if !st.clocked && !st.pm.is_suspended() {
                st.t_us += SAMPLE_PERIOD_US;
                sample(&mut st.chip, &mut st.bus, st.t_us, &mut st.acq_ns);
            }
        });
    }
}

/// One sample at `t_us`, configuring a chip that has not accepted its
/// configuration yet. A sample that landed moves `acq_ns` to its first
/// register read; one that did not leaves the previous sample's stamp with
/// the previous sample.
fn sample(chip: &mut Ina219, bus: &mut CapBus, t_us: u64, acq_ns: &mut u64) {
    if !chip.is_initialized() {
        chip.init(bus);
    }
    poll_stamped(chip, bus, t_us, acq_ns);
}

/// `chip.poll`, moving `acq_ns` to the new sample's first register read when
/// a sample landed.
fn poll_stamped(chip: &mut Ina219, bus: &mut CapBus, t_us: u64, acq_ns: &mut u64) {
    let before = chip.sample_count();
    bus.first_read_ns = 0;
    chip.poll(bus, t_us);
    if chip.sample_count() != before {
        *acq_ns = bus.first_read_ns;
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(2);
}

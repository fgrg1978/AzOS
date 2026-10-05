// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 INA219 power-monitor driver (RFC-0040 rule 3): the ring-3 host of
//! `crates/drivers/ina219`, built into the image when Kconfig
//! `DRV_INA219_PLACEMENT` is `ring3` (the default).
//!
//! Started by the kernel at boot (`ring3_driver_launch_task`), with the
//! capabilities of its own topology row, `INADRV.ELF`: `DriverRegistry` for
//! `DRV_KIND_POWER_MON` and `I2c` READ|WRITE on `bus.1/0x40`. It configures the
//! chip, polls it at `INA219_POLL_HZ`, and answers the kernel's
//! `UserDriverProxy` with the last sample (`power_op::READ`), which is what
//! `SYS_SENSOR_READ(SENSOR_TYPE_POWER)` returns.
//!
//! Between samples the driver is parked in `SYS_DRIVER_REPLY_WAIT` (610)
//! until the next sample is due: a request queued meanwhile wakes it at once,
//! so a proxied read waits for the answer, not for a poll period. Each sample
//! is integrated over the time the vDSO clock measured since the previous
//! one, not over a nominal 1/`INA219_POLL_HZ`.

#![no_std]
#![no_main]

// The chip logic and the request dispatch are `crates/drivers/ina219`, the
// same source the in-kernel host compiles (Kconfig DRV_INA219_PLACEMENT).
use azos_ina219::{
    serve, Bus, Ina219, INA219_ADDR, INA219_BUS, INA219_POLL_HZ, SOURCE_MARKER,
};
use azos_abi::drv_kind::DRV_KIND_POWER_MON;
use azos_libsys as sys;

// Wire structs, byte-identical to `azos_driver_server`'s (`#[repr(C)]`),
// mirrored as `gpio_drv` does so this crate has no kernel dependency.
const REQ_PAYLOAD_BYTES: usize = 64;
const REPLY_PAYLOAD_BYTES: usize = 64;

#[derive(Clone, Copy)]
#[repr(C)]
struct DriverRequest {
    token: u64,
    client_tid: u32,
    op: u32,
    in_len: u16,
    out_cap: u16,
    input: [u8; REQ_PAYLOAD_BYTES],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct DriverReply {
    token: u64,
    status: i32,
    out_len: u16,
    _pad: u16,
    output: [u8; REPLY_PAYLOAD_BYTES],
}

const STATUS_OK: i32 = 0;
const STATUS_BAD_OP: i32 = -1;

/// Time between chip samples: 1 / `INA219_POLL_HZ`.
const SAMPLE_PERIOD_US: u64 = 1_000_000 / INA219_POLL_HZ as u64;
/// Pause after a call the kernel refused with nothing done (the reply is
/// still owed), so a persistent refusal does not spin.
const REFUSED_RETRY_MS: u64 = 10;

/// The monotonic clock in microseconds (vDSO), or `None` when the kernel
/// publishes no clock (the page reads 0).
fn clock_us() -> Option<u64> {
    match sys::vdso_now_ns() {
        0 => None,
        ns => Some(ns / 1000),
    }
}

/// The monitor behind this task's `Cap<I2c>`.
///
/// `first_read_ns` is the acquisition stamp of the sample being taken: the
/// vDSO clock read right after the FIRST register read of [`sample`] that
/// succeeded (the bus voltage), so the record's age is never smaller than
/// any of its fields'. Cleared by `sample` before each poll.
struct CapBus {
    cap: u32,
    first_read_ns: u64,
}

impl Bus for CapBus {
    fn write(&mut self, data: &[u8]) -> bool {
        sys::i2c_write_typed(self.cap, data) >= 0
    }
    fn read(&mut self, reg: u8, buf: &mut [u8]) -> bool {
        let ok = sys::i2c_read_typed(self.cap, reg as u64, buf) == buf.len() as isize;
        if ok && self.first_read_ns == 0 {
            self.first_read_ns = sys::vdso_now_ns();
        }
        ok
    }
}

fn handle(req: &DriverRequest, chip: &Ina219, acq_ns: u64) -> DriverReply {
    let mut reply = DriverReply {
        token: req.token,
        status: STATUS_OK,
        out_len: 0,
        _pad: 0,
        output: [0; REPLY_PAYLOAD_BYTES],
    };
    match serve(chip, req.op, acq_ns, &mut reply.output) {
        Some(n) => reply.out_len = n as u16,
        None => reply.status = STATUS_BAD_OP,
    }
    reply
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let resource = ((INA219_BUS as u32) << 8) | INA219_ADDR as u32;
    let i2c = sys::cap_lookup(sys::CapKind::I2c as u8, resource);
    if i2c < 0 {
        sys::println(b"[inadrv] FAILED: no Cap<I2c> for bus.1/0x40");
        sys::exit(1);
    }
    let reg = sys::cap_lookup(sys::CapKind::DriverRegistry as u8, DRV_KIND_POWER_MON);
    if reg < 0 {
        sys::println(b"[inadrv] FAILED: no DriverRegistry capability");
        sys::exit(1);
    }
    let mut bus = CapBus { cap: i2c as u32, first_read_ns: 0 };
    // Acquisition stamp of the sample `chip` currently serves.
    let mut acq_ns: u64 = 0;
    let mut chip = Ina219::new();
    // Configured before registering, so the first proxied read already has a
    // configured chip behind it. A chip that does not answer leaves the
    // driver serving "no data"; it is retried every sample period.
    if !chip.init(&mut bus) {
        sys::println(b"[inadrv] INA219 did not accept its configuration, retrying");
    }
    // With no clock, samples are timed by the loop itself: one period per
    // park that ran to its end, the cadence the integration used to assume.
    let clocked = clock_us().is_some();
    let mut t_us = clock_us().unwrap_or(0);
    poll_stamped(&mut chip, &mut bus, t_us, &mut acq_ns);
    if sys::drv_srv_register_typed(reg as u32, 0, 0, 0) != 0 {
        sys::println(b"[inadrv] FAILED: typed register refused");
        sys::exit(1);
    }
    sys::println(b"[inadrv] registered DRV_KIND_POWER_MON via Cap<DriverRegistry>, serving");
    // The chip-logic source this host runs (`tools/chip_source_check.py`).
    sys::print(b"[inadrv] ");
    sys::println(&SOURCE_MARKER);

    let mut req = DriverRequest {
        token: 0, client_tid: 0, op: 0, in_len: 0, out_cap: 0,
        input: [0; REQ_PAYLOAD_BYTES],
    };
    let mut reply = DriverReply {
        token: 0, status: 0, out_len: 0, _pad: 0, output: [0; REPLY_PAYLOAD_BYTES],
    };
    let mut owed = false;
    let mut next_us = t_us + SAMPLE_PERIOD_US;
    loop {
        // Clocked: sample whenever the time has come, however the park ended.
        // A loop that fell behind resynchronises instead of sampling in a burst.
        if clocked {
            t_us = clock_us().unwrap_or(t_us);
            if t_us >= next_us {
                sample(&mut chip, &mut bus, t_us, &mut acq_ns);
                next_us += SAMPLE_PERIOD_US;
                if next_us <= t_us {
                    next_us = t_us + SAMPLE_PERIOD_US;
                }
            }
        }
        let park_ms = if clocked {
            ((next_us.saturating_sub(t_us) + 999) / 1000).max(1)
        } else {
            SAMPLE_PERIOD_US / 1000
        };
        let reply_ptr = if owed { &reply as *const DriverReply as *const u8 } else { core::ptr::null() };
        let rc = sys::drv_srv_reply_wait(
            DRV_KIND_POWER_MON,
            reply_ptr,
            &mut req as *mut DriverRequest as *mut u8,
            park_ms as u32,
        );
        match rc {
            0 => {
                reply = handle(&req, &chip, acq_ns);
                owed = true;
            }
            -1 => {
                owed = false;
                if !clocked {
                    t_us += SAMPLE_PERIOD_US;
                    sample(&mut chip, &mut bus, t_us, &mut acq_ns);
                }
            }
            // Refused with nothing done: the reply is still owed.
            _ => sys::sleep(REFUSED_RETRY_MS),
        }
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

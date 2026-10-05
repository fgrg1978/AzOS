// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! INA219 power monitor, kernel placement: the in-kernel host of
//! `crates/drivers/ina219` (Kconfig `DRV_INA219_PLACEMENT = kernel`, cargo
//! feature `ina219-kernel`).
//!
//! The ring-3 host's loop, moved into a kernel task (`kernel/src/tasks/`,
//! which owns the one [`KernelHost`]): sample the chip every
//! 1 / `INA219_POLL_HZ` over [`azos_drv_bus::i2c`] (the same `i2c_read` /
//! `i2c_write` the ring-3 host reaches through `Cap<I2c>`), retry its
//! configuration until it is accepted, and publish the chip state in a
//! [`SeqLock`]. Every call below copies that state and answers through
//! `azos_ina219::serve`: a direct call in the caller's context, no
//! device access and no lock held by the caller (RFC-0052 section 5.4: the
//! device is touched only by the host task, which holds no lock across it).
//!
//! The host task is single: it is the SeqLock's only writer.

use core::sync::atomic::{AtomicU32, Ordering};

use azos_abi::drv_kind::power_op;
use azos_ina219::{serve, Bus, Ina219, INA219_ADDR, INA219_BUS, INA219_POLL_HZ};
use azos_sync::SeqLock;

use super::POWER_DATA_SIZE;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// Time between chip samples, in timebase ticks: 1 / `INA219_POLL_HZ`.
pub const SAMPLE_PERIOD_TICKS: u64 = TIMER_FREQ / INA219_POLL_HZ as u64;

/// What the host publishes: the chip state after its last sample, and when
/// that sample was acquired (clock ns, the vDSO's clock; 0 before any).
#[derive(Clone, Copy)]
struct Published {
    chip: Ina219,
    acq_ns: u64,
}

static STATE: SeqLock<Published> = SeqLock::new(Published { chip: Ina219::new(), acq_ns: 0 });

/// The host task's TID, 0 until it has taken its first sample.
static HOST_TID: AtomicU32 = AtomicU32::new(0);

fn clock_ns() -> u64 {
    azos_abi::time::ticks_to_ns(now(), TIMER_FREQ)
}

/// The chip on bus 1 / 0x40, through the kernel's I2C driver.
///
/// `first_read_ns`: the acquisition stamp of the sample being taken, the
/// clock read right after the first register read of it that succeeded,
/// as the ring-3 host stamps it. Cleared before each poll.
struct KernelBus {
    first_read_ns: u64,
}

impl Bus for KernelBus {
    fn write(&mut self, data: &[u8]) -> bool {
        azos_drv_bus::i2c::i2c_write(INA219_BUS, INA219_ADDR, data) == 0
    }
    fn read(&mut self, reg: u8, buf: &mut [u8]) -> bool {
        let ok = azos_drv_bus::i2c::i2c_read(INA219_BUS, INA219_ADDR, reg, buf) == buf.len() as i32;
        if ok && self.first_read_ns == 0 {
            self.first_read_ns = clock_ns();
        }
        ok
    }
}

/// The host's own state: owned by the host task, never shared.
pub struct KernelHost {
    chip: Ina219,
    acq_ns: u64,
    bus: KernelBus,
}

impl KernelHost {
    /// Unconfigured; nothing published yet.
    pub const fn new() -> Self {
        KernelHost { chip: Ina219::new(), acq_ns: 0, bus: KernelBus { first_read_ns: 0 } }
    }

    /// One sample at `now_ticks`: configure a chip that has not accepted its
    /// configuration yet, poll it, publish the result. `tid` is the calling
    /// task's, published with the first sample (from then on
    /// [`ina219_driver_tid`] answers). `true` while the chip is configured.
    pub fn sample(&mut self, now_ticks: u64, tid: u32) -> bool {
        if !self.chip.is_initialized() {
            self.chip.init(&mut self.bus);
        }
        let before = self.chip.sample_count();
        self.bus.first_read_ns = 0;
        let now_us = azos_abi::time::ticks_to_ns(now_ticks, TIMER_FREQ) / 1000;
        self.chip.poll(&mut self.bus, now_us);
        if self.chip.sample_count() != before {
            self.acq_ns = self.bus.first_read_ns;
        }
        {
            let mut w = STATE.write();
            *w = Published { chip: self.chip, acq_ns: self.acq_ns };
        }
        HOST_TID.store(tid, Ordering::Release);
        self.chip.is_initialized()
    }
}

/// `serve(op)` against the published state, or `None` before the host's
/// first sample (no host is "no driver", as an unregistered ring-3 kind).
fn call(op: u32, out: &mut [u8]) -> Option<usize> {
    if HOST_TID.load(Ordering::Acquire) == 0 {
        return None;
    }
    let p = STATE.read();
    serve(&p.chip, op, p.acq_ns, out)
}

/// The host task, once it has sampled: the counterpart of a registered
/// ring-3 driver's TID.
pub fn ina219_driver_tid() -> Option<u32> {
    match HOST_TID.load(Ordering::Acquire) {
        0 => None,
        t => Some(t),
    }
}

/// The last sample into `buf`; bytes written, `POWER_DATA_SIZE` or 0.
pub fn ina219_read_power(buf: &mut [u8]) -> usize {
    if buf.len() < POWER_DATA_SIZE {
        return 0;
    }
    match call(power_op::READ, &mut buf[..POWER_DATA_SIZE]) {
        Some(POWER_DATA_SIZE) => POWER_DATA_SIZE,
        _ => 0,
    }
}

/// [`ina219_read_power`] and the sample's acquisition time (clock ns).
/// `(bytes, acq_ns)`, `(0, 0)` with no configured chip.
pub fn ina219_read_power_stamped(buf: &mut [u8]) -> (usize, u64) {
    if buf.len() < POWER_DATA_SIZE {
        return (0, 0);
    }
    let mut out = [0u8; power_op::POWER_TS_BYTES];
    match call(power_op::READ_TS, &mut out) {
        Some(power_op::POWER_TS_BYTES) => {
            buf[..POWER_DATA_SIZE].copy_from_slice(&out[..POWER_DATA_SIZE]);
            let mut a = [0u8; 8];
            a.copy_from_slice(&out[POWER_DATA_SIZE..]);
            (POWER_DATA_SIZE, u64::from_le_bytes(a))
        }
        _ => (0, 0),
    }
}

/// `(samples published, failed register transfers, chip configured)`, or
/// `None` before the host's first sample.
pub fn ina219_stats() -> Option<(u32, u32, bool)> {
    let out = stats_record()?;
    Some((
        u32::from_le_bytes([out[0], out[1], out[2], out[3]]),
        u32::from_le_bytes([out[4], out[5], out[6], out[7]]),
        out[8] != 0,
    ))
}

/// The integrated charge, in mA x us. `None` before the host's first sample.
pub fn ina219_charge_ma_us() -> Option<u64> {
    let out = stats_record()?;
    let mut b = [0u8; 8];
    b.copy_from_slice(&out[9..17]);
    Some(u64::from_le_bytes(b))
}

fn stats_record() -> Option<[u8; power_op::STATS_BYTES]> {
    let mut out = [0u8; power_op::STATS_BYTES];
    match call(power_op::STATS, &mut out) {
        Some(power_op::STATS_BYTES) => Some(out),
        _ => None,
    }
}

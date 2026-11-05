// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
#![forbid(unsafe_code)]

//! Barometer driver — BMP280 over I2C.
//!
//! The chip logic is [`chip`], written over an `I2cCall` and free of kernel
//! functions; this file is the kernel's host of it: the one barometer's bus
//! and address, the calibration it keeps between reads and the acquisition
//! stamp.
//!
//! Phase G1.

pub mod chip;

use core::sync::atomic::{AtomicU8, AtomicBool, Ordering};
use azos_devif::i2c::I2cDirect;
use azos_drv_bus::i2c_port::I2cPort;
use azos_sync::SpinLock;
use chip::{Bmp280, Calib, InitError};

pub use chip::{BaroData, BMP280_ADDR};

fn port(bus: u8, addr: u8) -> I2cDirect<I2cPort> {
    I2cDirect(I2cPort::new(bus, addr))
}

static BARO_BUS:   AtomicU8   = AtomicU8::new(0);
static BARO_ADDR:  AtomicU8   = AtomicU8::new(BMP280_ADDR);
static BARO_READY: AtomicBool = AtomicBool::new(false);
static BARO_CALIB: SpinLock<Calib> = SpinLock::new(Calib::ZERO);

/// Initialize the BMP280 on the given I2C bus/address.
///
/// Verifies chip_id (0x58), reads calibration data, configures forced mode.
/// Returns `true` if initialization succeeded.
pub fn baro_init(bus: u8, addr: u8) -> bool {
    let (chip, id) = match Bmp280::probe(port(bus, addr)) {
        Ok(found) => found,
        Err(InitError::NotFound) => {
            azos_drv_sys::kwarn!("[BARO] BMP280 @ bus={} addr=0x{:02x} — not found", bus, addr);
            return false;
        }
        Err(InitError::WrongId(id)) => {
            azos_drv_sys::kwarn!("[BARO] chip_id mismatch: expected 0x58, got 0x{:02x}", id);
            return false;
        }
        Err(InitError::Calibration) => {
            azos_drv_sys::kerr!("[BARO] Failed to read calibration data");
            return false;
        }
        Err(InitError::Write(reg)) => {
            azos_drv_sys::kerr!("[BARO] Failed to write {} register", reg);
            return false;
        }
    };
    *BARO_CALIB.lock() = chip.calibration();

    BARO_BUS.store(bus, Ordering::Relaxed);
    BARO_ADDR.store(addr, Ordering::Relaxed);
    BARO_READY.store(true, Ordering::Release);

    azos_drv_sys::kprintln!("[BARO] BMP280 @ bus={} addr=0x{:02x} — initialized (id=0x{:02x})",
        bus, addr, id);
    true
}

/// Read pressure and temperature with BMP280 compensation formulas.
///
/// Returns calibrated pressure (Pa) and temperature (centi-degrees C).
/// Uses the integer compensation algorithm from the BMP280 datasheet.
pub fn baro_read() -> Option<BaroData> {
    baro_read_stamped().map(|(d, _)| d)
}

/// [`baro_read`] and its acquisition time: the timebase counter
/// (`timebase::now()`, ticks) read right after the data-register burst
/// returned, in the driver, so a consumer ages the value from the read and
/// not from its own delivery.
pub fn baro_read_stamped() -> Option<(BaroData, u64)> {
    let bus   = BARO_BUS.load(Ordering::Relaxed);
    let addr  = BARO_ADDR.load(Ordering::Relaxed);
    let ready = BARO_READY.load(Ordering::Acquire);
    if !ready { return None; }

    // The calibration is copied out: no lock is held across the bus.
    let cal = *BARO_CALIB.lock();
    let mut chip = Bmp280::with_calibration(port(bus, addr), cal);
    let raw = chip.read_raw().ok()?;
    let acq = azos_drv_sys::timebase::now();
    Some((chip::compensate(&cal, &raw), acq))
}

/// Print barometer status info.
pub fn baro_info() {
    let bus   = BARO_BUS.load(Ordering::Relaxed);
    let addr  = BARO_ADDR.load(Ordering::Relaxed);
    let ready = BARO_READY.load(Ordering::Acquire);
    if ready {
        azos_drv_sys::kconsoleln!("[BARO] BMP280 @ bus={} addr=0x{:02x} — ready", bus, addr);
    } else {
        azos_drv_sys::kconsoleln!("[BARO] Not initialized");
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
#![forbid(unsafe_code)]

//! IMU driver — MPU-6050 over I2C.
//!
//! The chip logic is [`chip`], written over an `I2cCall` and free of kernel
//! functions; this file is the kernel's host of it: the one IMU's bus and
//! address, the acquisition stamp, the calibration offsets and the queued
//! read through the bus driver's transaction queue.
//!
//! Phase E2.

pub mod chip;

use core::sync::atomic::{AtomicU8, AtomicBool, Ordering};
use azos_devif::i2c::I2cDirect;
use azos_drv_bus::i2c;
use azos_drv_bus::i2c_port::I2cPort;
use chip::{InitError, Mpu6050, BURST_LEN, REG_ACCEL_XOUT_H};

pub use chip::{ImuData, MPU6050_ADDR};

fn imu(bus: u8, addr: u8) -> Mpu6050<I2cDirect<I2cPort>> {
    Mpu6050::new(I2cDirect(I2cPort::new(bus, addr)))
}

static IMU_BUS:   AtomicU8   = AtomicU8::new(0);
static IMU_ADDR:  AtomicU8   = AtomicU8::new(MPU6050_ADDR);
static IMU_READY: AtomicBool = AtomicBool::new(false);

/// Initialize the MPU-6050 on the given I2C bus/address.
///
/// Verifies WHO_AM_I, wakes the device (clear SLEEP bit), and configures
/// ±2 g / ±250 °/s range with DLPF at ~44 Hz.
///
/// Returns `true` if initialization succeeded.
pub fn imu_init(bus: u8, addr: u8) -> bool {
    match imu(bus, addr).init() {
        Ok(()) => {}
        Err(InitError::NotFound) => {
            azos_drv_sys::kwarn!("[IMU] MPU-6050 @ bus={} addr=0x{:02x} — not found", bus, addr);
            return false;
        }
        Err(InitError::WrongId(id)) => {
            azos_drv_sys::kwarn!("[IMU] WHO_AM_I mismatch: expected 0x68, got 0x{:02x}", id);
            return false;
        }
        Err(InitError::Write(reg)) => {
            azos_drv_sys::kerr!("[IMU] Failed to write {} register", reg);
            return false;
        }
    }

    IMU_BUS.store(bus, Ordering::Relaxed);
    IMU_ADDR.store(addr, Ordering::Relaxed);
    IMU_READY.store(true, Ordering::Release);

    azos_drv_sys::kprintln!("[IMU] MPU-6050 @ bus={} addr=0x{:02x} — initialized (±2g, ±250°/s)", bus, addr);
    true
}

/// Burst-read 14 raw bytes: accel XYZ (6) + temp (2) + gyro XYZ (6).
pub fn imu_read_raw() -> Option<[u8; BURST_LEN]> {
    imu_read_raw_stamped().map(|(raw, _)| raw)
}

/// [`imu_read_raw`] and its acquisition time: the timebase counter
/// (`timebase::now()`, ticks) read right after the burst transfer returned —
/// the first instant the kernel holds the value. Taken here, in the driver,
/// so every consumer (the IMU task, the AHRS task, `SYS_SENSOR_READ_TS`)
/// sees the time of the read and not the time the value reached it.
pub fn imu_read_raw_stamped() -> Option<([u8; BURST_LEN], u64)> {
    let (bus, addr, ready) = (IMU_BUS.load(Ordering::Relaxed), IMU_ADDR.load(Ordering::Relaxed), IMU_READY.load(Ordering::Acquire));
    if !ready { return None; }

    let burst = imu(bus, addr).read_raw();
    let acq = azos_drv_sys::timebase::now();
    Some((burst.ok()?, freeze::stamp(acq)))
}

/// The stale-sample canary (`freeze-acq-stamp`, kernel feature
/// `sensor-ts-freeze`): every reading keeps arriving, but each carries the
/// FIRST reading's acquisition stamp. A staleness check that judges the
/// acquisition time must then fire; one that judges delivery cannot.
#[cfg(feature = "freeze-acq-stamp")]
mod freeze {
    use core::sync::atomic::{AtomicU64, Ordering};
    static FIRST: AtomicU64 = AtomicU64::new(0);
    pub fn stamp(t: u64) -> u64 {
        match FIRST.compare_exchange(0, t, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => t,
            Err(first) => first,
        }
    }
}
#[cfg(not(feature = "freeze-acq-stamp"))]
mod freeze {
    #[inline(always)]
    pub fn stamp(t: u64) -> u64 { t }
}

/// Read and scale IMU data to physical units.
///
/// - `accel_mg`: milli-g (±2 g range → 16384 LSB/g)
/// - `gyro_mdps`: milli-degrees/sec (±250 °/s range → 131 LSB/(°/s))
/// - `temp_cdeg`: centi-degrees Celsius (per MPU-6050 datasheet)
pub fn imu_read_scaled() -> Option<ImuData> {
    imu_read_scaled_stamped().map(|(d, _)| d)
}

/// [`imu_read_scaled`] and its acquisition time in timebase ticks (see
/// [`imu_read_raw_stamped`]).
pub fn imu_read_scaled_stamped() -> Option<(ImuData, u64)> {
    let (raw, acq) = imu_read_raw_stamped()?;
    Some((scale(&raw), acq))
}

/// Queue the 14-byte burst read (wave 15, S1: Kconfig `IMU_SAMPLE_QUEUED`)
/// on the IMU's bus; never waits for the wire. The ticket goes to
/// [`imu_take`]. `None` before `imu_init` found the chip, or when the bus
/// queue refuses (full).
pub fn imu_submit(now: u64) -> Option<u32> {
    let (bus, addr, ready) = (IMU_BUS.load(Ordering::Relaxed), IMU_ADDR.load(Ordering::Relaxed), IMU_READY.load(Ordering::Acquire));
    if !ready { return None; }
    i2c::i2c_submit_read(bus, addr, REG_ACCEL_XOUT_H, BURST_LEN, now)
}

/// The queued read `ticket`: `None` while it is on the wire, `Some(None)`
/// when it finished without a full burst (NACK, timeout), `Some(Some(..))`
/// with the scaled sample and its acquisition time — the clock value of the
/// step that collected the last byte, as [`imu_read_raw_stamped`] stamps
/// right after its transfer returns.
pub fn imu_take(ticket: u32) -> Option<Option<(ImuData, u64)>> {
    let c = i2c::i2c_take(IMU_BUS.load(Ordering::Relaxed), ticket)?;
    if !c.ok || (c.rd_len as usize) < BURST_LEN {
        return Some(None);
    }
    let mut raw = [0u8; BURST_LEN];
    raw.copy_from_slice(&c.rd[..BURST_LEN]);
    Some(Some((scale(&raw), freeze::stamp(c.at))))
}

/// The burst in physical units, calibration offsets applied.
fn scale(raw: &[u8; BURST_LEN]) -> ImuData {
    chip::scale(raw, [
        azos_config::CFG_IMU_OFFSET_AX.load(Ordering::Relaxed) as i32,
        azos_config::CFG_IMU_OFFSET_AY.load(Ordering::Relaxed) as i32,
        azos_config::CFG_IMU_OFFSET_AZ.load(Ordering::Relaxed) as i32,
    ])
}

/// Print IMU status info.
pub fn imu_info() {
    let (bus, addr, ready) = (IMU_BUS.load(Ordering::Relaxed), IMU_ADDR.load(Ordering::Relaxed), IMU_READY.load(Ordering::Acquire));
    if ready {
        azos_drv_sys::kconsoleln!("[IMU] MPU-6050 @ bus={} addr=0x{:02x} — ready", bus, addr);
        azos_drv_sys::kconsoleln!("[IMU] Range: ±2 g, ±250 °/s, DLPF=44 Hz");
    } else {
        azos_drv_sys::kconsoleln!("[IMU] Not initialized");
    }
}

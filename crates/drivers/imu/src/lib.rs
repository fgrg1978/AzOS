// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! IMU driver — MPU-6050 over I2C.
//!
//! Provides high-level access to a simulated (QEMU) or real MPU-6050 6-axis
//! inertial measurement unit.  Uses the I2C driver from `azos_drv_bus`.
//!
//! Phase E2.

use core::sync::atomic::{AtomicU8, AtomicBool, Ordering};
use azos_drv_bus::i2c;

pub const MPU6050_ADDR: u8 = 0x68;

// MPU-6050 register map
const REG_SMPLRT_DIV:   u8 = 0x19;
const REG_CONFIG:       u8 = 0x1A;
const REG_GYRO_CONFIG:  u8 = 0x1B;
const REG_ACCEL_CONFIG: u8 = 0x1C;
const REG_ACCEL_XOUT_H: u8 = 0x3B; // 14 bytes: accel(6)+temp(2)+gyro(6)
const REG_PWR_MGMT_1:   u8 = 0x6B;
const REG_WHO_AM_I:     u8 = 0x75;

/// Scaled IMU reading.
#[derive(Clone, Copy)]
pub struct ImuData {
    /// Accelerometer in milli-g (1 g = 1000).  [X, Y, Z].
    pub accel_mg:  [i32; 3],
    /// Gyroscope in milli-degrees/sec.  [X, Y, Z].
    pub gyro_mdps: [i32; 3],
    /// Temperature in centi-degrees Celsius (e.g. 3653 = 36.53 °C).
    pub temp_cdeg: i32,
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
    // Check WHO_AM_I
    let mut wai = [0u8; 1];
    if i2c::i2c_read(bus, addr, REG_WHO_AM_I, &mut wai) < 1 {
        azos_drv_sys::kwarn!("[IMU] MPU-6050 @ bus={} addr=0x{:02x} — not found", bus, addr);
        return false;
    }
    if wai[0] != 0x68 {
        azos_drv_sys::kwarn!("[IMU] WHO_AM_I mismatch: expected 0x68, got 0x{:02x}", wai[0]);
        return false;
    }

    // Wake up: clear SLEEP bit (bit 6) in PWR_MGMT_1, select internal 8 MHz clock
    if i2c::i2c_write(bus, addr, &[REG_PWR_MGMT_1, 0x00]) < 0 {
        azos_drv_sys::kerr!("[IMU] Failed to write PWR_MGMT_1 register");
        return false;
    }

    // Sample rate divider: 0 → 1 kHz / (1+0) = 1 kHz sample rate
    if i2c::i2c_write(bus, addr, &[REG_SMPLRT_DIV, 0x00]) < 0 {
        azos_drv_sys::kerr!("[IMU] Failed to write SMPLRT_DIV register");
        return false;
    }

    // DLPF config: 3 → accel BW 44 Hz, gyro BW 42 Hz
    if i2c::i2c_write(bus, addr, &[REG_CONFIG, 0x03]) < 0 {
        azos_drv_sys::kerr!("[IMU] Failed to write CONFIG register");
        return false;
    }

    // Gyro config: FS_SEL=0 → ±250 °/s
    if i2c::i2c_write(bus, addr, &[REG_GYRO_CONFIG, 0x00]) < 0 {
        azos_drv_sys::kerr!("[IMU] Failed to write GYRO_CONFIG register");
        return false;
    }

    // Accel config: AFS_SEL=0 → ±2 g
    if i2c::i2c_write(bus, addr, &[REG_ACCEL_CONFIG, 0x00]) < 0 {
        azos_drv_sys::kerr!("[IMU] Failed to write ACCEL_CONFIG register");
        return false;
    }

    IMU_BUS.store(bus, Ordering::Relaxed);
    IMU_ADDR.store(addr, Ordering::Relaxed);
    IMU_READY.store(true, Ordering::Release);

    azos_drv_sys::kprintln!("[IMU] MPU-6050 @ bus={} addr=0x{:02x} — initialized (±2g, ±250°/s)", bus, addr);
    true
}

/// Burst-read 14 raw bytes: accel XYZ (6) + temp (2) + gyro XYZ (6).
pub fn imu_read_raw() -> Option<[u8; 14]> {
    imu_read_raw_stamped().map(|(raw, _)| raw)
}

/// [`imu_read_raw`] and its acquisition time: the timebase counter
/// (`timebase::now()`, ticks) read right after the burst transfer returned —
/// the first instant the kernel holds the value. Taken here, in the driver,
/// so every consumer (the IMU task, the AHRS task, `SYS_SENSOR_READ_TS`)
/// sees the time of the read and not the time the value reached it.
pub fn imu_read_raw_stamped() -> Option<([u8; 14], u64)> {
    let (bus, addr, ready) = (IMU_BUS.load(Ordering::Relaxed), IMU_ADDR.load(Ordering::Relaxed), IMU_READY.load(Ordering::Acquire));
    if !ready { return None; }

    let mut buf = [0u8; 14];
    let n = i2c::i2c_read(bus, addr, REG_ACCEL_XOUT_H, &mut buf);
    let acq = azos_drv_sys::timebase::now();
    if n < 14 { return None; }
    Some((buf, freeze::stamp(acq)))
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
    i2c::i2c_submit_read(bus, addr, REG_ACCEL_XOUT_H, 14, now)
}

/// The queued read `ticket`: `None` while it is on the wire, `Some(None)`
/// when it finished without a full burst (NACK, timeout), `Some(Some(..))`
/// with the scaled sample and its acquisition time — the clock value of the
/// step that collected the last byte, as [`imu_read_raw_stamped`] stamps
/// right after its transfer returns.
pub fn imu_take(ticket: u32) -> Option<Option<(ImuData, u64)>> {
    let c = i2c::i2c_take(IMU_BUS.load(Ordering::Relaxed), ticket)?;
    if !c.ok || c.rd_len < 14 {
        return Some(None);
    }
    let mut raw = [0u8; 14];
    raw.copy_from_slice(&c.rd[..14]);
    Some(Some((scale(&raw), freeze::stamp(c.at))))
}

/// The MPU-6050 burst (accel, temp, gyro, big-endian) in physical units,
/// calibration offsets applied.
fn scale(raw: &[u8; 14]) -> ImuData {

    // Helper: big-endian i16 from two bytes.
    let i16be = |hi: u8, lo: u8| -> i16 {
        ((hi as u16) << 8 | lo as u16) as i16
    };

    let ax = i16be(raw[0],  raw[1])  as i32;
    let ay = i16be(raw[2],  raw[3])  as i32;
    let az = i16be(raw[4],  raw[5])  as i32;
    let tr = i16be(raw[6],  raw[7])  as i32;
    let gx = i16be(raw[8],  raw[9])  as i32;
    let gy = i16be(raw[10], raw[11]) as i32;
    let gz = i16be(raw[12], raw[13]) as i32;

    // Phase G2: subtract IMU calibration offsets (milli-g units, signed).
    let off_ax = azos_config::CFG_IMU_OFFSET_AX.load(Ordering::Relaxed) as i32;
    let off_ay = azos_config::CFG_IMU_OFFSET_AY.load(Ordering::Relaxed) as i32;
    let off_az = azos_config::CFG_IMU_OFFSET_AZ.load(Ordering::Relaxed) as i32;

    ImuData {
        accel_mg:  [
            ax * 1000 / 16384 - off_ax,
            ay * 1000 / 16384 - off_ay,
            az * 1000 / 16384 - off_az,
        ],
        gyro_mdps: [gx * 1000 / 131,   gy * 1000 / 131,   gz * 1000 / 131],
        temp_cdeg: tr * 100 / 340 + 3653,
    }
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

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! INA219 power monitor, ring-3 placement — the kernel's client of the
//! ring-3 host.
//!
//! The chip logic (`crates/drivers/ina219`: configuration, 10 Hz sampling,
//! mAh integrated over the measured time between samples, sag and failsafe
//! levels) runs in `userspace/drivers/ina_drv` (`INADRV.ELF`), started at
//! boot with its own topology row; RFC-0040 places the INA219 in user space
//! (rule 3), and that is Kconfig `DRV_INA219_PLACEMENT`'s default. What stays
//! here is the read `SYS_SENSOR_READ(SENSOR_TYPE_POWER)` makes: one
//! [`UserDriverProxy`] request for the driver's last sample.
//!
//! No driver registered, a driver that has not configured its chip, or a
//! reply that is not a whole record: 0 bytes, the sensor dispatch's "no data".
//! Never a fabricated reading — an unpolled monitor composes into "battery
//! full, no failsafe" (see `userspace/drivers/ina_drv/src/ina219.rs`).
//!
//! Blocks the caller for the reply: never call from an interrupt handler or
//! with a lock held.

use azos_drv_api::{DriverIsolation, DriverManifest};
use azos_drv_sys::user_driver_proxy::UserDriverProxy;
use azos_abi::cap::CapPerms;
use azos_abi::drv_kind::{power_op, DRV_KIND_POWER_MON};

use super::POWER_DATA_SIZE;

static PROXY: UserDriverProxy = UserDriverProxy::new(DriverManifest::new(
    DRV_KIND_POWER_MON,
    "ina219-user",
    // Routing is by kind; the TID is informational.
    DriverIsolation::UserProcess { tid: 0 },
    CapPerms::RW,
));

/// Is a ring-3 power-monitor driver registered? Its TID.
pub fn ina219_driver_tid() -> Option<u32> {
    azos_driver_server::driver_owner_tid(DRV_KIND_POWER_MON)
}

/// The driver's last sample into `buf`; bytes written, `POWER_DATA_SIZE` or 0.
pub fn ina219_read_power(buf: &mut [u8]) -> usize {
    if buf.len() < POWER_DATA_SIZE {
        return 0;
    }
    match PROXY.call(power_op::READ, &[], &mut buf[..POWER_DATA_SIZE]) {
        Ok(POWER_DATA_SIZE) => POWER_DATA_SIZE,
        _ => 0,
    }
}

/// [`ina219_read_power`] and the sample's acquisition time: vDSO-clock
/// nanoseconds the driver read right after the register transfers behind the
/// sample (`power_op::READ_TS`). `(bytes, acq_ns)`; `acq_ns` is 0 — unknown —
/// when the driver predates `READ_TS` and answered the plain read instead.
///
/// The proxy does not carry a driver's status, so an old driver's refusal of
/// `READ_TS` and an unconfigured chip both arrive as 0 bytes; only then is the
/// plain read asked, and its answer tells the two apart.
pub fn ina219_read_power_stamped(buf: &mut [u8]) -> (usize, u64) {
    if buf.len() < POWER_DATA_SIZE {
        return (0, 0);
    }
    let mut out = [0u8; power_op::POWER_TS_BYTES];
    match PROXY.call(power_op::READ_TS, &[], &mut out) {
        Ok(power_op::POWER_TS_BYTES) => {
            buf[..POWER_DATA_SIZE].copy_from_slice(&out[..POWER_DATA_SIZE]);
            let mut a = [0u8; 8];
            a.copy_from_slice(&out[POWER_DATA_SIZE..]);
            (POWER_DATA_SIZE, u64::from_le_bytes(a))
        }
        Ok(0) => (ina219_read_power(buf), 0),
        _ => (0, 0),
    }
}

/// `(samples published, failed register transfers, chip configured)`, or
/// `None` without an answering driver.
pub fn ina219_stats() -> Option<(u32, u32, bool)> {
    let out = stats_record()?;
    Some((
        u32::from_le_bytes([out[0], out[1], out[2], out[3]]),
        u32::from_le_bytes([out[4], out[5], out[6], out[7]]),
        out[8] != 0,
    ))
}

/// The driver's integrated charge, in mA x us (`power_op::STATS` bytes
/// 9..17): each sample weighted by the time its driver measured since the
/// previous one. `None` without an answering driver.
pub fn ina219_charge_ma_us() -> Option<u64> {
    let out = stats_record()?;
    let mut b = [0u8; 8];
    b.copy_from_slice(&out[9..17]);
    Some(u64::from_le_bytes(b))
}

/// One whole `power_op::STATS` reply.
fn stats_record() -> Option<[u8; power_op::STATS_BYTES]> {
    let mut out = [0u8; power_op::STATS_BYTES];
    match PROXY.call(power_op::STATS, &[], &mut out) {
        Ok(power_op::STATS_BYTES) => Some(out),
        _ => None,
    }
}

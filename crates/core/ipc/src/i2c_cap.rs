// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cap<I2c> typed wrappers — RFC-0003 W5 batch 5.2.
//!
//! `Cap<I2c>` identifies a specific (bus, slave address) pair —
//! NOT a whole I2C bus. The resource_id encodes both:
//!
//! ```text
//! [resource_id u32] = 0x00_00_BB_AA
//!                        |   |  |  └─ slave addr (low 8b)
//!                        |   |  └─── bus number (next 8b)
//!                        └───└────── reserved 0
//! ```
//!
//! Per-(bus, addr) granularity matches how the topology loader
//! grants the cap: a task that needs to talk to the IMU on bus 0
//! address 0x68 gets a cap whose resource_id is `0x68 | (0 << 8)`,
//! and can't pivot to address 0x6A on the same bus without an
//! additional grant.

use crate::cap::{Cap, CapError, CapPerms, CapTable};
use azos_drv_bus::i2c::{i2c_detect, i2c_read, i2c_write};

/// Errors returned by the typed `i2c_*_cap` functions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum I2cCapError {
    Cap(CapError),
    /// Caller buffer doesn't fit one transaction or has zero length.
    BadLen,
    /// Underlying driver returned a negative status (NACK, timeout, etc).
    DriverFault,
}

impl From<CapError> for I2cCapError {
    fn from(e: CapError) -> Self {
        Self::Cap(e)
    }
}

/// Width in bytes of the I2C cap resource_id packing — included
/// here as a named constant so callers can audit the layout.
pub const I2C_RES_ADDR_SHIFT: u32 = 0;
pub const I2C_RES_BUS_SHIFT: u32 = 8;
pub const I2C_RES_ADDR_MASK: u32 = 0xFF;
pub const I2C_RES_BUS_MASK: u32 = 0xFF;

#[inline]
fn pack_resource(bus: u8, addr: u8) -> u32 {
    ((bus as u32) << I2C_RES_BUS_SHIFT) | (addr as u32)
}

#[inline]
fn unpack_resource(resource: u32) -> (u8, u8) {
    let bus = ((resource >> I2C_RES_BUS_SHIFT) & I2C_RES_BUS_MASK) as u8;
    let addr = ((resource >> I2C_RES_ADDR_SHIFT) & I2C_RES_ADDR_MASK) as u8;
    (bus, addr)
}

/// Topology-loader entry: grant `tid` a `Cap<I2c>` for the
/// specific `(bus, addr)` slave.
pub fn i2c_grant_cap(
    tid: u32,
    bus: u8,
    addr: u8,
    perms: CapPerms,
) -> Option<Cap<crate::cap::targets::I2c>> {
    let resource = pack_resource(bus, addr);
    crate::cap_store::grant::<crate::cap::targets::I2c>(tid, perms, resource)
}

/// The slave a typed I2C call resolved its capability to, and the one
/// operation the checked permission allows. Resolved under the caller's
/// capability-table lock, used after releasing it (wave 15, S1): the
/// transfer sleeps between controller steps and may not run under a
/// `SpinLock`. The permission was checked at the resolution, like an open
/// descriptor's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct I2cAccess {
    pub bus: u8,
    pub addr: u8,
}

impl I2cAccess {
    /// Read `buf.len()` bytes from register `reg`. Returns bytes read.
    pub fn read(self, reg: u8, buf: &mut [u8]) -> Result<usize, I2cCapError> {
        if buf.is_empty() {
            return Err(I2cCapError::BadLen);
        }
        let n = i2c_read(self.bus, self.addr, reg, buf);
        if n < 0 { Err(I2cCapError::DriverFault) } else { Ok(n as usize) }
    }

    /// Write `data` (by I2C convention `data[0]` is the register address).
    pub fn write(self, data: &[u8]) -> Result<(), I2cCapError> {
        if data.is_empty() {
            return Err(I2cCapError::BadLen);
        }
        if i2c_write(self.bus, self.addr, data) == 0 { Ok(()) } else { Err(I2cCapError::DriverFault) }
    }

    /// 1 if the slave ACKs an address probe, 0 otherwise.
    pub fn detect(self) -> u32 {
        u32::from(i2c_detect(self.bus, self.addr))
    }
}

/// Typed `i2c_read`: validate cap (requires `READ`); the read itself is
/// [`I2cAccess::read`], after the table lock is released.
pub fn i2c_read_cap(
    table: &CapTable,
    cap: Cap<crate::cap::targets::I2c>,
) -> Result<I2cAccess, I2cCapError> {
    let res = table.get(cap, CapPerms::READ)?;
    let (bus, addr) = unpack_resource(res);
    Ok(I2cAccess { bus, addr })
}

/// Typed `i2c_write`: validate cap (requires `WRITE`); the write itself is
/// [`I2cAccess::write`], after the table lock is released.
pub fn i2c_write_cap(
    table: &CapTable,
    cap: Cap<crate::cap::targets::I2c>,
) -> Result<I2cAccess, I2cCapError> {
    let res = table.get(cap, CapPerms::WRITE)?;
    let (bus, addr) = unpack_resource(res);
    Ok(I2cAccess { bus, addr })
}

/// Typed `i2c_detect`: validate cap (requires `READ`); the probe itself is
/// [`I2cAccess::detect`], after the table lock is released.
pub fn i2c_detect_cap(
    table: &CapTable,
    cap: Cap<crate::cap::targets::I2c>,
) -> Result<I2cAccess, I2cCapError> {
    let res = table.get(cap, CapPerms::READ)?;
    let (bus, addr) = unpack_resource(res);
    Ok(I2cAccess { bus, addr })
}

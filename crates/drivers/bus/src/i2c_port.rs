// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `I2c` interface over one device of the kernel's I2C masters.
//!
//! A chip driver takes an [`azos_devif::I2cCall`] bound to its device; in the
//! kernel it is `I2cDirect(I2cPort::new(bus, addr))`, in a ring-3 host the
//! endpoint client, in a host test a fake. One port serves every chip: the
//! bus and the address are its state, not the chip's.

use azos_devif::i2c::{self, Bytes, MAX_BYTES};
use azos_devif::{outcome, Out};

use crate::i2c::{i2c_detect, i2c_read, i2c_write};

/// One device on one bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct I2cPort {
    pub bus: u8,
    pub addr: u8,
}

impl I2cPort {
    pub const fn new(bus: u8, addr: u8) -> Self {
        I2cPort { bus, addr }
    }

    /// The port an endpoint badge names (`bus << 8 | address`).
    pub const fn from_badge(badge: u32) -> Self {
        let (bus, addr) = i2c::unbadge(badge);
        I2cPort { bus, addr }
    }
}

impl azos_devif::I2c for I2cPort {
    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
        let len = len as usize;
        if reg > 0xFF || len == 0 || len > MAX_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let mut buf = [0u8; MAX_BYTES];
        let n = i2c_read(self.bus, self.addr, reg as u8, &mut buf[..len]);
        if n < 0 {
            return Out::err(outcome::FAULT);
        }
        Out::ok(Bytes::from_slice(&buf[..(n as usize).min(len)]))
    }

    fn write(&mut self, data: Bytes) -> Out<()> {
        let n = data.n as usize;
        if n == 0 || n > MAX_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let mut buf = [0u8; MAX_BYTES];
        data.copy_to(&mut buf);
        if i2c_write(self.bus, self.addr, &buf[..n]) == 0 {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }

    fn detect(&mut self) -> Out<u32> {
        Out::ok(u32::from(i2c_detect(self.bus, self.addr)))
    }
}

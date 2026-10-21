// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `I2c` interface: one device on one bus.
//!
//! The endpoint's badge is `bus << 8 | address` (`endpoint = "i2c.0.0x68"`):
//! the capability names the device, so a task that holds the MPU-6050 cannot
//! talk to the motor controller on the same bus. `READ` reads registers and
//! probes, `WRITE` writes.
//!
//! A transfer is at most [`MAX_BYTES`] bytes: the data travels inline in the
//! message (four words), and the bound is the message's, not a driver's.

use crate::outcome::Out;
use azos_idl::{azos_interface, Reader, Wire, Writer};

/// The interface id (ASCII "I2C ").
pub const I2C_ID: u32 = 0x4932_4320;

/// Words of payload in one transfer.
pub const BYTES_WORDS: usize = 4;
/// Most bytes one transfer carries.
pub const MAX_BYTES: usize = BYTES_WORDS * 8;

/// The badge of the device at `addr` on `bus`.
pub const fn badge(bus: u8, addr: u8) -> u32 {
    ((bus as u32) << 8) | addr as u32
}

/// The bus and the address a badge names.
pub const fn unbadge(badge: u32) -> (u8, u8) {
    ((badge >> 8) as u8, badge as u8)
}

/// Up to [`MAX_BYTES`] bytes of a transfer: the count and the bytes packed
/// little-endian into words (the rest zero).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bytes {
    /// How many bytes are meaningful.
    pub n: u32,
    /// The bytes, eight to a word.
    pub w: [u64; BYTES_WORDS],
}

impl Bytes {
    /// The first [`MAX_BYTES`] bytes of `data`.
    pub fn from_slice(data: &[u8]) -> Bytes {
        let n = data.len().min(MAX_BYTES);
        let mut b = Bytes { n: n as u32, w: [0; BYTES_WORDS] };
        for (i, byte) in data[..n].iter().enumerate() {
            b.w[i / 8] |= (*byte as u64) << ((i % 8) * 8);
        }
        b
    }

    /// Copy the meaningful bytes into `out`; returns how many were copied.
    pub fn copy_to(&self, out: &mut [u8]) -> usize {
        let n = (self.n as usize).min(MAX_BYTES).min(out.len());
        for (i, o) in out[..n].iter_mut().enumerate() {
            *o = (self.w[i / 8] >> ((i % 8) * 8)) as u8;
        }
        n
    }
}

impl Wire for Bytes {
    const WORDS: usize = 1 + BYTES_WORDS;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.n.put(w);
        self.w.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let n = u32::get(r);
        Bytes { n, w: <[u64; BYTES_WORDS]>::get(r) }
    }
}

#[azos_interface(id = 0x4932_4320, level = 1)]
pub trait I2c {
    /// Read `len` (1..=[`MAX_BYTES`], else `BAD_ARGUMENT`) bytes starting at
    /// register `reg` (0..=255, else `BAD_ARGUMENT`). `FAULT` when the bus
    /// transfer failed. Needs `READ`.
    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes>;
    /// Write `data` (1..=[`MAX_BYTES`] bytes, else `BAD_ARGUMENT`): the first
    /// byte is the register, as the bus protocol of the device has it. `FAULT`
    /// when the bus transfer failed. Needs `WRITE`.
    fn write(&mut self, data: Bytes) -> Out<()>;
    /// 1 when the device answers its address, else 0. Needs `READ`.
    fn detect(&mut self) -> Out<u32>;
}

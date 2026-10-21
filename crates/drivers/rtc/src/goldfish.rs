// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The goldfish RTC (`google,goldfish-rtc`), QEMU `virt` on riscv64.
//!
//! A 64-bit count of nanoseconds since the Unix epoch in two 32-bit registers.
//! **Reading** `TIME_LOW` latches `TIME_HIGH`, so the pair is read low first;
//! read the other way round and a carry between the two reads gives a time 4.29
//! seconds off. **Writing** sets the count: the high word is staged by the
//! first write and the low word commits both, so a set writes high first.
//! The alarm and interrupt registers (0x08..0x1c) are not touched: a window
//! the kernel only reads and sets stays usable for them by whoever holds it.

use crate::{Error, Mmio, Rtc, NS_PER_SEC};

/// Low word of the time in nanoseconds; a read latches `TIME_HIGH`.
pub const TIME_LOW: u32 = 0x00;
/// High word of the time, as latched by the last `TIME_LOW` read.
pub const TIME_HIGH: u32 = 0x04;

pub struct Goldfish<M: Mmio> {
    m: M,
}

impl<M: Mmio> Goldfish<M> {
    pub fn new(m: M) -> Self {
        Goldfish { m }
    }
}

impl<M: Mmio> Rtc for Goldfish<M> {
    fn name(&self) -> &'static str {
        "goldfish-rtc"
    }

    fn read(&mut self) -> Result<u64, Error> {
        let lo = self.m.read32(TIME_LOW) as u64;
        let hi = self.m.read32(TIME_HIGH) as u64;
        match (hi << 32 | lo) / NS_PER_SEC {
            // A count of zero is a device nobody gave a host clock.
            0 => Err(Error::Lost),
            secs => Ok(secs),
        }
    }

    fn set(&mut self, unix_secs: u64) -> Result<(), Error> {
        let ns = unix_secs.checked_mul(NS_PER_SEC).ok_or(Error::Range)?;
        self.m.write32(TIME_HIGH, (ns >> 32) as u32);
        self.m.write32(TIME_LOW, ns as u32);
        Ok(())
    }
}

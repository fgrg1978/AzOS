// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ARM PrimeCell PL031 (`arm,pl031`), QEMU `virt` on aarch64.
//!
//! A free-running 32-bit counter of seconds. `RTCDR` reads it; a write to
//! `RTCLR` loads it (the count continues from the loaded value), and bit 0 of
//! `RTCCR` starts it. The match register and the interrupt registers are not
//! touched. The counter holds seconds since the epoch only until 2106-02-07:
//! a later time is [`Error::Range`].

use crate::{Error, Mmio, Rtc};

/// Data register: the current count (read only).
pub const RTCDR: u32 = 0x000;
/// Load register: writing sets the count.
pub const RTCLR: u32 = 0x008;
/// Control register: bit 0 starts the counter.
pub const RTCCR: u32 = 0x00c;
/// PrimeCell peripheral ID 0 and 1 (part number), then the four cell ID bytes.
const PERIPH_ID0: u32 = 0xfe0;
const PERIPH_ID1: u32 = 0xfe4;
const CELL_ID0: u32 = 0xff0;

pub struct Pl031<M: Mmio> {
    m: M,
}

impl<M: Mmio> Pl031<M> {
    /// The PL031 behind `m`, after the PrimeCell identification registers
    /// say it is one (part number 0x031, cell ID 0xB105F00D): a window that
    /// answers with another peripheral's registers is [`Error::NoDevice`].
    pub fn probe(mut m: M) -> Result<Self, Error> {
        let id = |m: &mut M, off| m.read32(off) & 0xff;
        let part = id(&mut m, PERIPH_ID0) | (id(&mut m, PERIPH_ID1) & 0x0f) << 8;
        let cell = (0..4).fold(0u32, |c, i| c | id(&mut m, CELL_ID0 + 4 * i) << (8 * i));
        if part != 0x031 || cell != 0xb105_f00d {
            return Err(Error::NoDevice);
        }
        Ok(Pl031 { m })
    }
}

impl<M: Mmio> Rtc for Pl031<M> {
    fn name(&self) -> &'static str {
        "pl031"
    }

    fn read(&mut self) -> Result<u64, Error> {
        // A counter nobody started or loaded reads 0 (or where it was loaded):
        // a time under any floor, which the boot step turns away.
        Ok(self.m.read32(RTCDR) as u64)
    }

    fn set(&mut self, unix_secs: u64) -> Result<(), Error> {
        let secs = u32::try_from(unix_secs).map_err(|_| Error::Range)?;
        self.m.write32(RTCLR, secs);
        if self.m.read32(RTCCR) & 1 == 0 {
            self.m.write32(RTCCR, 1);
        }
        Ok(())
    }
}

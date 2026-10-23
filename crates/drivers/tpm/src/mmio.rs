// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TIS over a memory-mapped window.
//!
//! Locality `n` lives at `base + n * 0x1000`. The PC-client window is
//! [`crate::acpi::TIS_DEFAULT_BASE`]. The access primitive is a trait so the
//! kernel supplies its own volatile accessors (and the host tests a fake);
//! this crate has no `unsafe`.

use crate::tis::{TisRegs, REG_DATA_FIFO};
use crate::BusError;

/// Bytes between two localities' register pages.
pub const LOCALITY_STRIDE: u64 = 0x1000;

/// Volatile accesses at a physical (or already-mapped) address. The TPM
/// accepts byte and dword accesses; the TIS writes bytes only, the CRB's
/// control registers take dwords ([`crate::crb`]).
pub trait MmioAccess {
    fn read8(&mut self, addr: u64) -> u8;
    fn read32(&mut self, addr: u64) -> u32;
    fn write8(&mut self, addr: u64, v: u8);
    fn write32(&mut self, addr: u64, v: u32);
}

pub struct MmioTis<A: MmioAccess> {
    mmio: A,
    base: u64,
}

impl<A: MmioAccess> MmioTis<A> {
    pub fn new(mmio: A, base: u64) -> Self {
        MmioTis { mmio, base }
    }

    pub fn into_inner(self) -> A {
        self.mmio
    }

    fn addr(&self, locality: u8, reg: u16) -> u64 {
        self.base + locality as u64 * LOCALITY_STRIDE + reg as u64
    }
}

impl<A: MmioAccess> TisRegs for MmioTis<A> {
    fn read(&mut self, locality: u8, reg: u16, buf: &mut [u8]) -> Result<(), BusError> {
        if locality > 4 {
            return Err(BusError);
        }
        let a = self.addr(locality, reg);
        if buf.len() == 4 && reg % 4 == 0 && reg != REG_DATA_FIFO {
            // One dword access: the status register's fields change between
            // two byte reads.
            buf.copy_from_slice(&self.mmio.read32(a).to_le_bytes());
        } else if reg == REG_DATA_FIFO {
            for b in buf.iter_mut() {
                *b = self.mmio.read8(a);
            }
        } else {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.mmio.read8(a + i as u64);
            }
        }
        Ok(())
    }

    fn write(&mut self, locality: u8, reg: u16, data: &[u8]) -> Result<(), BusError> {
        if locality > 4 {
            return Err(BusError);
        }
        let a = self.addr(locality, reg);
        for (i, b) in data.iter().enumerate() {
            let off = if reg == REG_DATA_FIFO { 0 } else { i as u64 };
            self.mmio.write8(a + off, *b);
        }
        Ok(())
    }
}

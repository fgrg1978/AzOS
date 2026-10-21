// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TIS over SPI (TCG PTP, SPI hardware protocol).
//!
//! A transaction is a 4-byte header (bit 7 of the first byte: 1 = read; bits
//! 5:0: length - 1, at most 64 bytes; then the 24-bit address
//! `0xD40000 | locality << 12 | reg`), an optional wait state in which the
//! TPM answers `0x00` on the last header byte and then `0x00` bytes until one
//! has bit 0 set, and the data. Chip select stays asserted from the header to
//! the end of the data, so the bus is a small local trait with an explicit
//! select. (The device-interface SPI trait is being added separately; its
//! adapter is a few lines against this one.)

use crate::tis::{TisRegs, REG_DATA_FIFO};
use crate::BusError;

/// Most data bytes in one transaction.
pub const MAX_XFER: usize = 64;
/// Wait-state bytes polled before the transaction is given up.
pub const WAIT_RETRIES: usize = 50;
/// Top byte of the 24-bit TPM address.
const ADDR_HI: u8 = 0xD4;

pub trait Spi {
    /// Assert (`true`) or release chip select. Held across `xfer` calls.
    fn select(&mut self, on: bool);
    /// Clock `tx.len()` bytes out and the same number in (`tx` and `rx` have
    /// equal length).
    fn xfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), BusError>;
}

pub struct SpiTis<S: Spi> {
    spi: S,
}

impl<S: Spi> SpiTis<S> {
    pub fn new(spi: S) -> Self {
        SpiTis { spi }
    }

    pub fn into_inner(self) -> S {
        self.spi
    }

    /// One transaction of `len` (1..=64) bytes. `data` is `Some` for a write.
    fn transaction(
        &mut self, locality: u8, reg: u16, read: Option<&mut [u8]>, write: Option<&[u8]>, len: usize,
    ) -> Result<(), BusError> {
        let addr = (locality as u16) << 12 | reg;
        let hdr_tx = [
            if read.is_some() { 0x80 } else { 0x00 } | (len as u8 - 1),
            ADDR_HI,
            (addr >> 8) as u8,
            addr as u8,
        ];
        let mut hdr_rx = [0u8; 4];
        self.spi.select(true);
        let r = self.run(&hdr_tx, &mut hdr_rx, read, write, len);
        self.spi.select(false);
        r
    }

    fn run(
        &mut self, hdr_tx: &[u8; 4], hdr_rx: &mut [u8; 4], read: Option<&mut [u8]>,
        write: Option<&[u8]>, len: usize,
    ) -> Result<(), BusError> {
        self.spi.xfer(hdr_tx, hdr_rx)?;
        if !cfg!(feature = "canary-spi-wait") && hdr_rx[3] & 1 == 0 {
            let mut ready = false;
            for _ in 0..WAIT_RETRIES {
                let mut b = [0u8; 1];
                self.spi.xfer(&[0], &mut b)?;
                if b[0] & 1 != 0 {
                    ready = true;
                    break;
                }
            }
            if !ready {
                return Err(BusError);
            }
        }
        match (read, write) {
            (Some(buf), _) => {
                self.spi.xfer(&[0u8; MAX_XFER][..len], buf)?;
            }
            (None, Some(data)) => {
                let mut sink = [0u8; MAX_XFER];
                self.spi.xfer(data, &mut sink[..len])?;
            }
            (None, None) => {}
        }
        Ok(())
    }
}

impl<S: Spi> TisRegs for SpiTis<S> {
    fn read(&mut self, locality: u8, reg: u16, buf: &mut [u8]) -> Result<(), BusError> {
        if locality > 4 {
            return Err(BusError);
        }
        let mut done = 0;
        while done < buf.len() {
            let n = (buf.len() - done).min(MAX_XFER);
            let r = if reg == REG_DATA_FIFO { reg } else { reg + done as u16 };
            self.transaction(locality, r, Some(&mut buf[done..done + n]), None, n)?;
            done += n;
        }
        Ok(())
    }

    fn write(&mut self, locality: u8, reg: u16, data: &[u8]) -> Result<(), BusError> {
        if locality > 4 {
            return Err(BusError);
        }
        let mut done = 0;
        while done < data.len() {
            let n = (data.len() - done).min(MAX_XFER);
            let r = if reg == REG_DATA_FIFO { reg } else { reg + done as u16 };
            self.transaction(locality, r, None, Some(&data[done..done + n]), n)?;
            done += n;
        }
        Ok(())
    }
}

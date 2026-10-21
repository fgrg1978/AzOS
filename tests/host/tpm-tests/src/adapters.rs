// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The MMIO and SPI register adapters: addresses, framing, wait states.

use crate::fake::*;
use crate::*;
use azos_tpm::spi::{Spi, SpiTis};
use azos_tpm::tis::{TisRegs, REG_DATA_FIFO};
use azos_tpm::tpm::StartupType;
use azos_tpm::{BusError, Error};

#[test]
fn mmio_uses_dword_reads_for_status_and_fixed_fifo_address() {
    let (mut t, r) = rig(Kind::Mmio, 2);
    r.dev.borrow_mut().expect(
        "80 01 00 00 00 0C 00 00 01 44 00 00",
        "80 01 00 00 00 0A 00 00 00 00",
    );
    t.startup(StartupType::Clear).unwrap();
    r.assert_clean();
    let log = r.mmio_log.borrow();
    let page = MMIO_BASE + 2 * 0x1000;
    for (a, w, wr) in log.iter() {
        let reg = a - page;
        if reg == 0x18 && !*wr {
            assert_eq!(*w, 4, "STS must be read as one dword");
        }
        if reg == 0x00 {
            assert_eq!(*w, 1);
        }
    }
    // Every FIFO byte goes to the one FIFO address, one byte at a time.
    let fifo: Vec<_> = log.iter().filter(|(a, _, _)| *a == page + 0x24).collect();
    assert!(fifo.len() >= 12 + 10, "{}", fifo.len());
    assert!(fifo.iter().all(|(_, w, _)| *w == 1));
}

#[test]
fn mmio_refuses_a_locality_above_four() {
    let dev: SharedDev = shared();
    let mut m = azos_tpm::mmio::MmioTis::new(
        FakeMmio { dev, base: MMIO_BASE, log: Default::default() },
        MMIO_BASE,
    );
    let mut b = [0u8; 1];
    assert_eq!(m.read(5, 0, &mut b), Err(BusError));
    assert_eq!(m.write(5, 0, &b), Err(BusError));
}

#[test]
fn spi_header_bytes_are_the_ptp_framing() {
    let (mut t, r) = rig(Kind::Spi(0), 1);
    t.probe().unwrap();
    let f = r.frames.borrow();
    // ACCESS read, locality 1: R/W = 1, length 1, address 0xD4 1 000.
    assert_eq!(f[0].hdr, vec![0x80, 0xD4, 0x10, 0x00]);
    assert_eq!(f[0].data.len(), 1);
    // STS is a 4-byte read at 0x18 in locality 1's page.
    let sts = f.iter().find(|x| x.hdr == vec![0x83, 0xD4, 0x10, 0x18]);
    assert!(sts.is_some(), "no 4-byte STS read: {:?}", f.iter().map(|x| x.hdr.clone()).collect::<Vec<_>>());
    // The locality request is a write of 0x02 to ACCESS.
    assert!(f.iter().any(|x| x.hdr == vec![0x00, 0xD4, 0x10, 0x00] && x.data == vec![0x02]));
    assert!(r.bus_v.borrow().is_empty());
}

#[test]
fn spi_waits_out_the_wait_state() {
    let (mut t, r) = rig(Kind::Spi(3), 0);
    t.probe().unwrap();
    r.assert_clean();
    let f = r.frames.borrow();
    assert!(!f.is_empty());
    // 3 zero bytes then the ready byte, in every transaction.
    assert!(f.iter().all(|x| x.wait_bytes == 4), "{:?}", f.iter().map(|x| x.wait_bytes).collect::<Vec<_>>());
}

#[test]
fn spi_ready_byte_that_never_comes_is_a_bus_error_and_cs_is_released() {
    let dev: SharedDev = shared();
    let mut s = FakeSpi::new(dev, 0);
    s.never_ready = true;
    let v = s.bus_violations.clone();
    let mut t = SpiTis::new(s);
    let mut b = [0u8; 1];
    assert_eq!(t.read(0, 0, &mut b), Err(BusError));
    assert!(v.borrow().is_empty(), "{:?}", v.borrow());
    // 50 polls after the header, no more.
    let s = t.into_inner();
    assert_eq!(s.frames.borrow()[0].wait_bytes, 50);
}

#[test]
fn spi_error_surfaces_as_bus_error() {
    let dev: SharedDev = shared();
    let mut s = FakeSpi::new(dev, 0);
    s.never_ready = true;
    let mut tpm = azos_tpm::tpm::Tpm::new(azos_tpm::tis::Tis::new(SpiTis::new(s), FakeClock::new(), 0));
    assert_eq!(tpm.probe(), Err(Error::Bus));
}

/// A bus that records transactions and answers ready at once.
#[derive(Default)]
struct Rec {
    frames: Vec<(Vec<u8>, usize)>,
    cur: Vec<u8>,
    sel: bool,
}

impl Spi for Rec {
    fn select(&mut self, on: bool) {
        if on {
            self.cur.clear();
            self.sel = true;
        } else {
            self.frames.push((self.cur.clone(), 0));
            self.sel = false;
        }
    }
    fn xfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), BusError> {
        self.cur.extend_from_slice(tx);
        for b in rx.iter_mut() {
            *b = 1;
        }
        Ok(())
    }
}

#[test]
fn spi_splits_at_64_bytes_and_keeps_the_fifo_address() {
    let mut t = SpiTis::new(Rec::default());
    let data: Vec<u8> = (0..130).map(|i| i as u8).collect();
    t.write(0, REG_DATA_FIFO, &data).unwrap();
    let f = &t.into_inner().frames;
    assert_eq!(f.len(), 3);
    // length - 1 in bits 5:0, FIFO address in every chunk.
    assert_eq!(&f[0].0[..4], &[63, 0xD4, 0x00, 0x24]);
    assert_eq!(f[0].0.len(), 4 + 64);
    assert_eq!(&f[1].0[..4], &[63, 0xD4, 0x00, 0x24]);
    assert_eq!(&f[2].0[..4], &[1, 0xD4, 0x00, 0x24]);
    assert_eq!(&f[2].0[4..], &[128, 129]);
    // A plain register advances with the offset.
    let mut t = SpiTis::new(Rec::default());
    let mut buf = [0u8; 70];
    t.read(0, 0x100, &mut buf).unwrap();
    let f = &t.into_inner().frames;
    assert_eq!(&f[0].0[..4], &[0x80 | 63, 0xD4, 0x01, 0x00]);
    assert_eq!(&f[1].0[..4], &[0x80 | 5, 0xD4, 0x01, 0x40]);
}

#[test]
fn spi_refuses_a_locality_above_four() {
    let mut t = SpiTis::new(Rec::default());
    let mut b = [0u8; 1];
    assert_eq!(t.read(5, 0, &mut b), Err(BusError));
    assert!(t.into_inner().frames.is_empty());
}

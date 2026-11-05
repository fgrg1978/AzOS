// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The helpers a chip driver calls on its `I2cCall`/`SpiCall` (`read_regs`,
//! `write_bytes`, `transfer_all`): the bound of one transfer, the register
//! that advances with each chunk, and the one outcome code for a call that
//! reached no server, a refusal, and a short answer.

use azos_devif::i2c::{read_regs, write_bytes, Bytes, I2cDirect, MAX_BYTES};
use azos_devif::spi::{transfer_all, SpiDirect};
use azos_devif::{outcome, I2c, Out, Spi};

/// A register file that logs the transfers it was asked for.
struct Regs {
    log: Vec<(u32, u32)>,
    writes: Vec<Vec<u8>>,
    /// Answers a read with this many bytes fewer than asked.
    short: usize,
    refuse: Option<u32>,
}

impl I2c for Regs {
    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
        self.log.push((reg, len));
        if let Some(c) = self.refuse {
            return Out::err(c);
        }
        let n = len as usize - self.short;
        let bytes: Vec<u8> = (0..n).map(|i| (reg as usize + i) as u8).collect();
        Out::ok(Bytes::from_slice(&bytes))
    }
    fn write(&mut self, data: Bytes) -> Out<()> {
        let mut d = [0u8; MAX_BYTES];
        let n = data.copy_to(&mut d);
        self.writes.push(d[..n].to_vec());
        match self.refuse {
            Some(c) => Out::err(c),
            None => Out::ok(()),
        }
    }
    fn detect(&mut self) -> Out<u32> {
        Out::ok(1)
    }
}

fn regs() -> I2cDirect<Regs> {
    I2cDirect(Regs { log: Vec::new(), writes: Vec::new(), short: 0, refuse: None })
}

/// A buffer longer than one transfer is several reads, each at the register
/// after the bytes already read.
#[test]
fn a_long_register_read_is_chunked_and_the_register_advances() {
    let mut bus = regs();
    let mut buf = [0u8; 70];
    read_regs(&mut bus, 0x10, &mut buf).unwrap();
    assert_eq!(bus.0.log, [(0x10, 32), (0x30, 32), (0x50, 6)]);
    assert!(buf.iter().enumerate().all(|(i, b)| *b == (0x10 + i) as u8));
    // A register file has 256 registers: a read that would run past it is
    // refused before it reaches the wire.
    let mut bus = regs();
    assert_eq!(read_regs(&mut bus, 0xF0, &mut [0u8; 40]), Err(outcome::BAD_ARGUMENT));
    assert!(bus.0.log.is_empty());
    let mut bus = regs();
    read_regs(&mut bus, 0xF0, &mut [0u8; 16]).unwrap();
    assert_eq!(bus.0.log, [(0xF0, 16)]);
}

/// A device that answers fewer bytes than asked is a fault, and so is a
/// refusal, with the device's own code.
#[test]
fn a_short_answer_and_a_refusal_are_errors() {
    let mut bus = regs();
    bus.0.short = 1;
    assert_eq!(read_regs(&mut bus, 0, &mut [0u8; 4]), Err(outcome::FAULT));
    let mut bus = regs();
    bus.0.refuse = Some(outcome::BUSY);
    assert_eq!(read_regs(&mut bus, 0, &mut [0u8; 4]), Err(outcome::BUSY));
    assert_eq!(write_bytes(&mut bus, &[1, 2]), Err(outcome::BUSY));
}

/// A write is one transfer: empty or longer than the interface carries is
/// refused, not split (a second transfer would start with a data byte).
#[test]
fn a_write_is_one_transfer_or_nothing() {
    let mut bus = regs();
    write_bytes(&mut bus, &[0x6B, 0]).unwrap();
    write_bytes(&mut bus, &[7u8; MAX_BYTES]).unwrap();
    assert_eq!(write_bytes(&mut bus, &[]), Err(outcome::BAD_ARGUMENT));
    assert_eq!(write_bytes(&mut bus, &[7u8; MAX_BYTES + 1]), Err(outcome::BAD_ARGUMENT));
    assert_eq!(bus.0.writes.len(), 2);
}

/// A SPI bus that echoes inverted bytes and logs the sizes of its transfers.
struct Echo {
    sizes: Vec<usize>,
    refuse_at: Option<usize>,
}

impl Spi for Echo {
    fn transfer(&mut self, data: Bytes) -> Out<Bytes> {
        if self.refuse_at == Some(self.sizes.len()) {
            return Out::err(outcome::FAULT);
        }
        self.sizes.push(data.n as usize);
        let mut d = [0u8; MAX_BYTES];
        let n = data.copy_to(&mut d);
        for b in &mut d[..n] {
            *b = !*b;
        }
        Out::ok(Bytes::from_slice(&d[..n]))
    }
    fn write(&mut self, _: Bytes) -> Out<()> {
        Out::err(outcome::UNSUPPORTED)
    }
    fn read(&mut self, _: u32, _: u32) -> Out<Bytes> {
        Out::err(outcome::UNSUPPORTED)
    }
    fn set_mode(&mut self, _: u32) -> Out<()> {
        Out::err(outcome::UNSUPPORTED)
    }
    fn set_speed(&mut self, _: u32) -> Out<()> {
        Out::err(outcome::UNSUPPORTED)
    }
    fn hold_cs(&mut self, _: bool) -> Out<()> {
        Out::ok(())
    }
}

#[test]
fn a_long_spi_exchange_is_chunked_and_a_refusal_stops_it() {
    let mut bus = SpiDirect(Echo { sizes: Vec::new(), refuse_at: None });
    let tx: Vec<u8> = (0..70).collect();
    let mut rx = vec![0u8; 70];
    transfer_all(&mut bus, &tx, &mut rx).unwrap();
    assert_eq!(bus.0.sizes, [32, 32, 6]);
    assert!(rx.iter().zip(&tx).all(|(r, t)| *r == !*t));
    assert_eq!(transfer_all(&mut bus, &tx, &mut rx[..3]), Err(outcome::BAD_ARGUMENT));

    let mut bus = SpiDirect(Echo { sizes: Vec::new(), refuse_at: Some(1) });
    assert_eq!(transfer_all(&mut bus, &tx, &mut rx), Err(outcome::FAULT));
    assert_eq!(bus.0.sizes, [32], "nothing was clocked after the refusal");
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A register-file I2C device served as the `I2c` interface, for the chip
//! drivers written over `I2cCall` (the IMU, the barometer): the chip gets
//! `I2cDirect(dev)`, as the kernel gives it `I2cDirect(I2cPort)`.

use azos_devif::i2c::{Bytes, I2cDirect};
use azos_devif::{outcome, I2c, Out};
use std::cell::RefCell;
use std::rc::Rc;

/// What the chip put on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// `len` bytes read from register `reg`.
    Read(u8, usize),
    /// Register first, then its bytes.
    Write(Vec<u8>),
}

#[derive(Default)]
pub struct RegFile {
    pub regs: Vec<u8>,
    pub log: Vec<Op>,
    /// Every transfer from this index on (counted over reads and writes) is
    /// not acknowledged.
    pub nak_from: Option<usize>,
    /// `(reg, value, polls)`: the next `polls` single-byte reads of `reg`
    /// answer `value`, whatever the register holds.
    pub busy: Option<(u8, u8, u32)>,
}

impl RegFile {
    fn naks(&self) -> bool {
        self.nak_from.is_some_and(|n| self.log.len() >= n)
    }
}

#[derive(Clone)]
pub struct Dev(pub Rc<RefCell<RegFile>>);

impl Dev {
    pub fn new() -> Dev {
        Dev(Rc::new(RefCell::new(RegFile { regs: vec![0; 256], ..RegFile::default() })))
    }

    pub fn call(&self) -> I2cDirect<Dev> {
        I2cDirect(self.clone())
    }

    pub fn set(&self, reg: u8, bytes: &[u8]) {
        let mut f = self.0.borrow_mut();
        for (i, b) in bytes.iter().enumerate() {
            f.regs[reg as usize + i] = *b;
        }
    }

    pub fn log(&self) -> Vec<Op> {
        self.0.borrow().log.clone()
    }
}

impl I2c for Dev {
    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
        let mut f = self.0.borrow_mut();
        let nak = f.naks();
        f.log.push(Op::Read(reg as u8, len as usize));
        if nak {
            return Out::err(outcome::FAULT);
        }
        if let Some((r, v, left)) = f.busy {
            if r as u32 == reg && len == 1 && left > 0 {
                f.busy = Some((r, v, left - 1));
                return Out::ok(Bytes::from_slice(&[v]));
            }
        }
        let bytes: Vec<u8> = (0..len as usize).map(|i| f.regs[(reg as usize + i) & 0xFF]).collect();
        Out::ok(Bytes::from_slice(&bytes))
    }

    fn write(&mut self, data: Bytes) -> Out<()> {
        let mut f = self.0.borrow_mut();
        let nak = f.naks();
        let mut d = [0u8; 32];
        let n = data.copy_to(&mut d);
        f.log.push(Op::Write(d[..n].to_vec()));
        if nak {
            return Out::err(outcome::FAULT);
        }
        for (i, b) in d[1..n].iter().enumerate() {
            f.regs[(d[0] as usize + i) & 0xFF] = *b;
        }
        Out::ok(())
    }

    fn detect(&mut self) -> Out<u32> {
        Out::ok(1)
    }
}

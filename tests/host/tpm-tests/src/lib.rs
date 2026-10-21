// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_tpm`. See `fake.rs` for the scripted TPM.
#![cfg(test)]

mod adapters;
mod cmds;
mod fake;
mod proto;
mod tables;
mod wire;

use azos_tpm::mmio::MmioTis;
use azos_tpm::spi::SpiTis;
use azos_tpm::tis::Tis;
use azos_tpm::tpm::Tpm;
use fake::*;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Direct,
    Mmio,
    /// SPI with this many wait-state bytes.
    Spi(usize),
}

pub const ALL: [Kind; 4] = [Kind::Direct, Kind::Mmio, Kind::Spi(0), Kind::Spi(3)];
pub const MMIO_BASE: u64 = 0xFED4_0000;

pub struct Rig {
    pub dev: SharedDev,
    pub clock: FakeClock,
    pub mmio_log: Rc<RefCell<Vec<(u64, u8, bool)>>>,
    pub frames: Rc<RefCell<Vec<Frame>>>,
    pub bus_v: Rc<RefCell<Vec<String>>>,
}

pub fn rig(kind: Kind, loc: u8) -> (Tpm<Dyn, FakeClock>, Rig) {
    let dev: SharedDev = shared();
    let clock = FakeClock::new();
    let mmio_log = Rc::new(RefCell::new(Vec::new()));
    let mut frames = Rc::new(RefCell::new(Vec::new()));
    let mut bus_v = Rc::new(RefCell::new(Vec::new()));
    let regs: Box<dyn azos_tpm::tis::TisRegs> = match kind {
        Kind::Direct => Box::new(Direct(dev.clone())),
        Kind::Mmio => Box::new(MmioTis::new(
            FakeMmio { dev: dev.clone(), base: MMIO_BASE, log: mmio_log.clone() },
            MMIO_BASE,
        )),
        Kind::Spi(w) => {
            let s = FakeSpi::new(dev.clone(), w);
            frames = s.frames.clone();
            bus_v = s.bus_violations.clone();
            Box::new(SpiTis::new(s))
        }
    };
    let tpm = Tpm::new(Tis::new(Dyn(regs), clock.clone(), loc));
    (tpm, Rig { dev, clock, mmio_log, frames, bus_v })
}

impl Rig {
    /// Assert the driver left the device and the bus clean.
    pub fn assert_clean(&self) {
        let d = self.dev.borrow();
        assert!(d.violations.is_empty(), "device violations: {:?}", d.violations);
        assert!(self.bus_v.borrow().is_empty(), "bus violations: {:?}", self.bus_v.borrow());
        assert_eq!(d.active, None, "locality left held");
        assert!(d.script.is_empty(), "script not consumed: {} left", d.script.len());
    }
}

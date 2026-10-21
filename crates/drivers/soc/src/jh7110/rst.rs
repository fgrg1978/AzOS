// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The JH7110 reset blocks. Each clock-and-reset block (SYSCRG, AONCRG, STGCRG)
//! has a bank of assert registers, one bit per line (1 = held in reset), and
//! a bank of status registers of the same shape. Releasing a line is a
//! read-modify-write of the assert bit followed by a wait on the status bit;
//! asserting does not wait.
//!
//! Confirmed against the TRM (2.8.1, 2.8.2, 2.8.3):
//!
//! | block | assert bank | status bank | tables |
//! |---|---|---|---|
//! | SYSCRG | `0x2f8`, 4 registers | `0x308`, 4 registers | T2-240..T2-243, T2-244..T2-247 |
//! | STGCRG | `0x74`, 1 register | `0x78`, 1 register | T2-277, T2-278 |
//! | AONCRG | `0x38`, 1 register | `0x3c`, 1 register | T2-293, T2-294 |
//!
//! Not every bit of a bank is a line: the tables name 121 SYSCRG lines
//! (bank 0 lacks bits 24, 25, 28 and 30; bank 1 lacks bit 11; bank 3 has
//! bits 0..=29), 23 STGCRG lines (bits 0..=22) and 8 AONCRG lines (bits
//! 0..=7). A line the tables do not name is `BadSpec`.
//!
//! Status polarity: a released line reads 1 in the status bank, a held one 0,
//! the same for every line. The TRM does not settle it: each status table
//! repeats its assert table's names, descriptions ("1: assert reset") and,
//! for every line but one, reset values, so the copies carry no information;
//! the one row that differs (SYSCRG bank 0 bit 0, `rstn_u0_jtag2apb_presetn`:
//! assert default 0, status default 1) reads as released, which fits this
//! reading. [verify] The polarity (and that no line is inverted) is not
//! stated by the TRM; it needs a board read (assert a line, read its status
//! bit).

use crate::reset::ResetOps;
use crate::{Bus, Error, Result};

/// Status polls before a release reports `Timeout`.
pub const POLL_BUDGET: u32 = 1000;

/// The clock-and-reset blocks that hold reset lines. The system one
/// (`starfive,jh7110-syscrg`) is also the clock controller.
pub const AONCRG_COMPATIBLE: &str = "starfive,jh7110-aoncrg";
pub const STGCRG_COMPATIBLE: &str = "starfive,jh7110-stgcrg";

/// Banks of a block, at most.
const BANKS: usize = 4;

pub struct Jh7110Reset {
    base: u64,
    assert_off: u64,
    status_off: u64,
    /// Bits that are lines, per bank (TRM tables above).
    lines: [u32; BANKS],
}

impl Jh7110Reset {
    /// SYSCRG: assert bank at 0x2f8, status bank at 0x308, 4 banks.
    pub const fn sys(base: u64) -> Self {
        Jh7110Reset {
            base,
            assert_off: 0x2f8,
            status_off: 0x308,
            lines: [0xacff_ffff, 0xffff_f7ff, 0xffff_ffff, 0x3fff_ffff],
        }
    }

    /// AONCRG: assert 0x38, status 0x3c, 1 bank of 8 lines.
    pub const fn aon(base: u64) -> Self {
        Jh7110Reset { base, assert_off: 0x38, status_off: 0x3c, lines: [0xff, 0, 0, 0] }
    }

    /// STGCRG: assert 0x74, status 0x78, 1 bank of 23 lines.
    pub const fn stg(base: u64) -> Self {
        Jh7110Reset { base, assert_off: 0x74, status_off: 0x78, lines: [0x007f_ffff, 0, 0, 0] }
    }

    /// From `node`: the reset bank of the block its `compatible` names (the
    /// system, always-on or storage clock-and-reset block), at its `reg`.
    pub fn from_dt(fdt: &crate::Fdt<'_>, node: crate::NodeId) -> Option<Self> {
        if !fdt.is_available(node) {
            return None;
        }
        let (base, _) = fdt.reg(node)?;
        if fdt.is_compatible(node, super::SYSCRG_COMPATIBLE) {
            Some(Self::sys(base))
        } else if fdt.is_compatible(node, AONCRG_COMPATIBLE) {
            Some(Self::aon(base))
        } else if fdt.is_compatible(node, STGCRG_COMPATIBLE) {
            Some(Self::stg(base))
        } else {
            None
        }
    }

    fn assert_reg(&self, id: u32) -> u64 {
        self.base + self.assert_off + 4 * (id / 32) as u64
    }

    fn status_reg(&self, id: u32) -> u64 {
        self.base + self.status_off + 4 * (id / 32) as u64
    }

    /// The bit of `id` in its bank, if `id` is a line.
    fn check(&self, id: u32) -> Result<u32> {
        let bank = (id / 32) as usize;
        let bit = 1u32 << (id % 32);
        if bank >= BANKS || self.lines[bank] & bit == 0 {
            return Err(Error::BadSpec);
        }
        Ok(bit)
    }
}

impl ResetOps for Jh7110Reset {
    fn count(&self) -> u32 {
        // One past the highest line.
        self.lines
            .iter()
            .enumerate()
            .rev()
            .find(|(_, m)| **m != 0)
            .map_or(0, |(bank, m)| bank as u32 * 32 + (32 - m.leading_zeros()))
    }

    fn assert(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        let bit = self.check(id)?;
        let a = self.assert_reg(id);
        let v = bus.read32(a);
        bus.write32(a, v | bit);
        Ok(())
    }

    fn deassert(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        let bit = self.check(id)?;
        let a = self.assert_reg(id);
        let v = bus.read32(a);
        bus.write32(a, v & !bit);
        for _ in 0..POLL_BUDGET {
            if bus.read32(self.status_reg(id)) & bit != 0 {
                return Ok(());
            }
        }
        Err(Error::Timeout)
    }

    fn is_asserted(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool> {
        let bit = self.check(id)?;
        Ok(bus.read32(self.status_reg(id)) & bit == 0)
    }
}

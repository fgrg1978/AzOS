// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The buck converters of the SpacemiT P1 PMIC (`spacemit,p1`, I2C address
//! 0x41 on the Jupiter and BPI-F3 trees, `regulators { buck1 ... buck6 }`),
//! as regulator-framework providers over [`crate::I2cBus`].
//!
//! Registers, all from Linux v7.3 `drivers/regulator/spacemit-p1.c`
//! (`P1_BUCK_DESC`, `P1_ENABLE_REG`, `p1_buck_ranges`):
//!
//! * the enable register of buck `n` (1..=6) is `0x47 + 3 * (n - 1)`, the
//!   enable bit is bit 0 of it;
//! * the voltage selector is the next register, `enable + 1`, the whole byte
//!   (`BUCK_MASK = GENMASK(7, 0)`);
//! * selectors 0..=170 give `500000 + 5000 * sel` microvolts, 171..=254 give
//!   `1375000 + 25000 * (sel - 171)`; selector 255 "can be used to disable
//!   the buck converter on sleep" and is not a voltage.
//!
//! Buck 1 is 0x47 / 0x48 and buck 2 is 0x4A / 0x4B. The Jupiter tree puts all
//! eight CPUs on buck 1 (`cpu-supply = <&buck1_0v9>`), 0.5 V .. 1.05 V with a
//! `regulator-ramp-delay` of 5000 uV/us; buck 2 has the same constraints and
//! no consumer.
//!
//! The LDOs (ALDO1-4, DLDO1-7) are not modelled: nothing the kernel does asks
//! for one.
//!
//! [verify] on the board, because the checkout holds no source for them: the
//! register addressing of the PMIC on the wire (one address byte, one data
//! byte: the MFD that owns the regmap, `drivers/mfd/simple-mfd-i2c.c`, is not
//! in the reference tree), and that a write to the selector takes effect on
//! the rail without a separate "go" bit. The driver reads the selector back
//! after every write and fails with [`Error::Hardware`] if it does not hold.

use crate::fdt::{Fdt, NodeId};
use crate::regulator::{Io, RegulatorOps};
use crate::{Error, I2cBus, Result};

/// The PMIC node's `compatible`.
pub const P1_COMPATIBLE: &str = "spacemit,p1";

/// Bucks the P1 has.
pub const BUCKS: u8 = 6;
/// `P1_ENABLE_REG(0x47, n)` for `n = 1`.
const BUCK_ENABLE_BASE: u8 = 0x47;
/// Registers per buck (`P1_ENABLE_REG`: `_off + 3 * (_n - 1)`).
const BUCK_STRIDE: u8 = 3;
const ENABLE_BIT: u8 = 1 << 0;

const LOW_BASE_UV: u32 = 500_000;
const LOW_STEP_UV: u32 = 5_000;
const LOW_LAST_SEL: u32 = 170;
const HIGH_BASE_UV: u32 = 1_375_000;
const HIGH_STEP_UV: u32 = 25_000;
const HIGH_FIRST_SEL: u32 = 171;
const HIGH_LAST_SEL: u32 = 254;

/// The voltage selector `sel` stands for, `None` for 255.
pub const fn sel_to_uv(sel: u8) -> Option<u32> {
    let s = sel as u32;
    if s <= LOW_LAST_SEL {
        Some(LOW_BASE_UV + s * LOW_STEP_UV)
    } else if s <= HIGH_LAST_SEL {
        Some(HIGH_BASE_UV + (s - HIGH_FIRST_SEL) * HIGH_STEP_UV)
    } else {
        None
    }
}

/// The selector for exactly `uv`, `None` for a voltage not on the grid.
pub const fn uv_to_sel(uv: u32) -> Option<u8> {
    if uv >= LOW_BASE_UV && uv <= LOW_BASE_UV + LOW_LAST_SEL * LOW_STEP_UV {
        let d = uv - LOW_BASE_UV;
        if d % LOW_STEP_UV == 0 {
            return Some((d / LOW_STEP_UV) as u8);
        }
    } else if uv >= HIGH_BASE_UV && uv <= HIGH_BASE_UV + (HIGH_LAST_SEL - HIGH_FIRST_SEL) * HIGH_STEP_UV {
        let d = uv - HIGH_BASE_UV;
        if d % HIGH_STEP_UV == 0 {
            return Some((HIGH_FIRST_SEL + d / HIGH_STEP_UV) as u8);
        }
    }
    None
}

/// One buck converter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct P1Buck {
    /// The I2C master's window base (its device-tree `reg`).
    ctrl: u64,
    /// The PMIC's 7-bit address.
    addr: u8,
    /// 1..=6.
    n: u8,
}

impl P1Buck {
    /// Buck `n` (1..=6) of the PMIC at `addr` behind the master at `ctrl`.
    pub const fn new(ctrl: u64, addr: u8, n: u8) -> Option<Self> {
        if n >= 1 && n <= BUCKS { Some(P1Buck { ctrl, addr, n }) } else { None }
    }

    /// From a `buckN` node under `regulators` under a `spacemit,p1` node
    /// under an I2C controller node with a `reg`.
    pub fn from_dt(fdt: &Fdt<'_>, node: NodeId) -> Option<Self> {
        if !fdt.is_available(node) {
            return None;
        }
        let n = fdt.name(node)?.strip_prefix("buck")?.parse::<u8>().ok()?;
        let anc = fdt.ancestors(node)?;
        let a = anc.as_slice();
        let [.., master, pmic, regulators] = a else { return None };
        if fdt.name(*regulators)? != "regulators" || !fdt.is_compatible(*pmic, P1_COMPATIBLE) {
            return None;
        }
        let addr = u8::try_from(fdt.reg(*pmic)?.0).ok()?;
        P1Buck::new(fdt.reg(*master)?.0, addr, n)
    }

    /// The master window this rail's PMIC sits behind.
    pub const fn ctrl(&self) -> u64 {
        self.ctrl
    }

    fn enable_reg(&self) -> u8 {
        BUCK_ENABLE_BASE + BUCK_STRIDE * (self.n - 1)
    }

    fn vsel_reg(&self) -> u8 {
        self.enable_reg() + 1
    }

    /// The voltage the selector holds now, microvolts. [`Error::Hardware`] for
    /// selector 255 (not a voltage) or a PMIC that did not answer.
    ///
    /// This and [`P1Buck::write_uv`] are what [`RegulatorOps`] runs; they are
    /// also public because a caller that must not hold the frameworks' lock
    /// across the wire (a voltage step is several I2C transfers, hundreds of
    /// microseconds: more than a spin lock may be held) drives the buck itself
    /// and records the effect with [`crate::effect::issue`]. The caller then
    /// owns the ordering the manager would have kept: the record first, and no
    /// one else writing this rail's selector meanwhile.
    pub fn read_uv(&self, i2c: &mut dyn I2cBus) -> Result<u32> {
        let sel = i2c.read_reg(self.ctrl, self.addr, self.vsel_reg())?;
        sel_to_uv(sel).ok_or(Error::Hardware)
    }

    /// Write the selector for exactly `uv` and read it back
    /// ([`Error::Constraint`] for a voltage off the grid, [`Error::Hardware`]
    /// for a selector that did not hold). The read-back proves the register
    /// keeps the write, not that the output has moved.
    pub fn write_uv(&self, i2c: &mut dyn I2cBus, uv: u32) -> Result<()> {
        let sel = uv_to_sel(uv).ok_or(Error::Constraint)?;
        let reg = self.vsel_reg();
        i2c.write_reg(self.ctrl, self.addr, reg, sel)?;
        if i2c.read_reg(self.ctrl, self.addr, reg)? != sel {
            return Err(Error::Hardware);
        }
        Ok(())
    }
}

fn i2c<'a, 'b>(io: &'b mut Io<'a>) -> Result<&'b mut (dyn I2cBus + 'a)> {
    io.i2c.as_deref_mut().ok_or(Error::Unsupported)
}

impl RegulatorOps for P1Buck {
    fn needs_i2c(&self) -> bool {
        true
    }

    fn reachable(&self, io: &Io<'_>) -> bool {
        io.i2c.as_ref().is_some_and(|b| b.present(self.ctrl))
    }

    fn enable(&mut self, io: &mut Io<'_>) -> Result<()> {
        let (ctrl, addr, reg) = (self.ctrl, self.addr, self.enable_reg());
        let i2c = i2c(io)?;
        let v = i2c.read_reg(ctrl, addr, reg)?;
        // Already on (the firmware left it so): no write.
        if v & ENABLE_BIT == 0 {
            i2c.write_reg(ctrl, addr, reg, v | ENABLE_BIT)?;
        }
        Ok(())
    }

    fn disable(&mut self, io: &mut Io<'_>) -> Result<()> {
        let (ctrl, addr, reg) = (self.ctrl, self.addr, self.enable_reg());
        let i2c = i2c(io)?;
        let v = i2c.read_reg(ctrl, addr, reg)?;
        if v & ENABLE_BIT != 0 {
            i2c.write_reg(ctrl, addr, reg, v & !ENABLE_BIT)?;
        }
        Ok(())
    }

    fn is_enabled(&mut self, io: &mut Io<'_>) -> Result<bool> {
        let (ctrl, addr, reg) = (self.ctrl, self.addr, self.enable_reg());
        Ok(i2c(io)?.read_reg(ctrl, addr, reg)? & ENABLE_BIT != 0)
    }

    fn voltage(&mut self, io: &mut Io<'_>) -> Result<u32> {
        self.read_uv(i2c(io)?)
    }

    fn set_voltage(&mut self, io: &mut Io<'_>, uv: u32) -> Result<()> {
        self.write_uv(i2c(io)?, uv)
    }
}

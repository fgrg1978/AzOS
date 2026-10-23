// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The JH7110 PLL block (`starfive,jh7110-pll`): PLL0..2, the system clock
//! generator's `pll0_out`..`pll2_out` inputs ([`super::clk`]).
//!
//! The node has no `reg`: it is a child of the system syscon
//! (`starfive,jh7110-sys-syscon`, `0x1303_0000` on the VisionFive 2) and its
//! registers are the parent's. One input, the oscillator, as the node's only
//! `clocks` entry (the binding names none).
//!
//! The fields, offsets from the syscon base (U-Boot's
//! `drivers/clk/starfive/clk-jh7110-pll.c`, v2025.07):
//!
//! ```text
//!          dacpd dsmpd  fbdiv          frac   postdiv1  pd    prediv
//!  PLL0    0x18:24 :25  0x1c [11:0]    0x20 [23:0] [29:28] :27  0x24 [5:0]
//!  PLL1    0x24:15 :16  0x24 [28:17]   0x28 [23:0] [29:28] :27  0x2c [5:0]
//!  PLL2    0x2c:15 :16  0x2c [28:17]   0x30 [23:0] [29:28] :27  0x34 [5:0]
//! ```
//!
//! `rate = osc * (fbdiv + frac / 2^24) / prediv / 2^postdiv1`: integer mode
//! when `dacpd` and `dsmpd` both read 1 (`frac` unused), fractional when both
//! read 0, anything else is a state the formula has no rate for. U-Boot's
//! SPL programs PLL0 (1 GHz) and PLL2 (1188 MHz) before the kernel runs; the
//! kernel only reads them, so the model has no `set_rate`.

use crate::clk::{ClockOps, Parent};
use crate::{Bus, Error, Result};

pub const PLL_COMPATIBLE: &str = "starfive,jh7110-pll";

/// The binding's one input; it has no `clock-names`, so the tree resolves it
/// by position (`clk::input_entry`).
pub const INPUTS: &[&str] = &["osc"];

const PLLS: u32 = 3;
/// Power-down: 1 is off (`PLL_PD_OFF`), in the `frac` word of every PLL.
const PD: u32 = 1 << 27;
const FRAC_BITS: u32 = 24;
const FRAC_MASK: u32 = (1 << FRAC_BITS) - 1;
const POSTDIV1_SHIFT: u32 = 28;
const PREDIV_MASK: u32 = 0x3f;

/// Where one PLL's fields sit (offsets from the syscon base).
struct Layout {
    /// The word with `dacpd` and `dsmpd`, and their bits.
    dsm: u64,
    dacpd: u32,
    dsmpd: u32,
    /// The word with `fbdiv`, and the field's shift (12 bits wide).
    fbdiv: u64,
    fbdiv_shift: u32,
    /// The word with `frac`, `pd` and `postdiv1`.
    frac: u64,
    prediv: u64,
}

const FBDIV_MASK: u32 = 0xfff;

const LAYOUT: [Layout; PLLS as usize] = [
    Layout { dsm: 0x18, dacpd: 24, dsmpd: 25, fbdiv: 0x1c, fbdiv_shift: 0, frac: 0x20, prediv: 0x24 },
    Layout { dsm: 0x24, dacpd: 15, dsmpd: 16, fbdiv: 0x24, fbdiv_shift: 17, frac: 0x28, prediv: 0x2c },
    Layout { dsm: 0x2c, dacpd: 15, dsmpd: 16, fbdiv: 0x2c, fbdiv_shift: 17, frac: 0x30, prediv: 0x34 },
];

/// The PLL register model of the syscon at `base`.
pub struct Jh7110Pll {
    base: u64,
    size: u64,
}

impl Jh7110Pll {
    /// The PLLs whose registers start at `base`, a window of `size` bytes.
    pub const fn new(base: u64, size: u64) -> Self {
        Jh7110Pll { base, size }
    }

    /// From a `starfive,jh7110-pll` node: its parent's `reg`.
    pub fn from_dt(fdt: &crate::Fdt<'_>, node: crate::NodeId) -> Option<Self> {
        if !fdt.is_available(node) || !fdt.is_compatible(node, PLL_COMPATIBLE) {
            return None;
        }
        let parent = fdt.ancestors(node)?.parent()?;
        fdt.reg(parent).map(|(base, size)| Jh7110Pll::new(base, size))
    }

    /// The register window the model reads (the syscon's).
    pub const fn window(&self) -> (u64, u64) {
        (self.base, self.size)
    }

    fn layout(id: u32) -> Result<&'static Layout> {
        LAYOUT.get(id as usize).ok_or(Error::BadSpec)
    }
}

impl ClockOps for Jh7110Pll {
    fn count(&self) -> u32 {
        PLLS
    }

    fn input_names(&self) -> &'static [&'static str] {
        INPUTS
    }

    fn parent(&mut self, _: &mut dyn Bus, id: u32) -> Result<Parent> {
        Self::layout(id)?;
        Ok(Parent::Input(0))
    }

    /// No gate: a PLL is powered (`pd`), which the firmware owns.
    fn gated(&self, _: u32) -> bool {
        false
    }

    fn enable(&mut self, _: &mut dyn Bus, _: u32) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn disable(&mut self, _: &mut dyn Bus, _: u32) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn is_enabled(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool> {
        let l = Self::layout(id)?;
        Ok(bus.read32(self.base + l.frac) & PD == 0)
    }

    fn rate(&mut self, bus: &mut dyn Bus, id: u32, parent_rate: u64) -> Result<u64> {
        let l = Self::layout(id)?;
        let fw = bus.read32(self.base + l.frac);
        // A powered-down PLL is a stopped clock.
        if fw & PD != 0 {
            return Ok(0);
        }
        let dsm = bus.read32(self.base + l.dsm);
        let fbdiv = (bus.read32(self.base + l.fbdiv) >> l.fbdiv_shift) & FBDIV_MASK;
        let frac = match ((dsm >> l.dacpd) & 1, (dsm >> l.dsmpd) & 1) {
            (1, 1) => 0,
            (0, 0) => fw & FRAC_MASK,
            _ => return Err(Error::Hardware),
        };
        let prediv = bus.read32(self.base + l.prediv) & PREDIV_MASK;
        if prediv == 0 {
            // M is 1..63: 0 is a state the formula has no rate for.
            return Err(Error::Hardware);
        }
        let postdiv1 = (fw >> POSTDIV1_SHIFT) & 0x3;
        // (fbdiv + frac / 2^24) in 24-bit fixed point; u128, a 32-bit parent
        // times a 36-bit multiplier does not fit 64 bits.
        let mult = ((fbdiv as u128) << FRAC_BITS) | frac as u128;
        let div = ((prediv as u128) << postdiv1) << FRAC_BITS;
        Ok((parent_rate as u128 * mult / div) as u64)
    }

    fn set_rate(&mut self, _: &mut dyn Bus, id: u32, _: u64, _: u64) -> Result<u64> {
        Self::layout(id)?;
        Err(Error::Unsupported)
    }
}

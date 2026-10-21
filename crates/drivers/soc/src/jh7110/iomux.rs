// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The JH7110 pad controllers: SYS IOMUX CFG (`starfive,jh7110-sys-pinctrl`,
//! TRM 2.8.7, base `0x1304_0000`, Table 2-4 "System IOMUX") and AON IOMUX CFG
//! (`starfive,jh7110-aon-pinctrl`, TRM 2.8.8, base `0x1702_0000`, Table 2-4
//! "AON GPIO"). One model, two register layouts.
//!
//! A pad has two independent halves.
//!
//! The full multiplexing half routes a pad to a signal (TRM 2.7.6.3.2): the
//! pad's output data comes from GPO signal `dout`, its output-enable from
//! GPEN signal `doen`, and a GPI signal reads the pad when the GPI's slot in
//! `sig_in` holds the pad number plus 2. Index 0 and 1 of `dout`/`doen` are
//! the constants low and high (`doen` 0 = output always enabled, 1 = always
//! an input; Table 2-41). All three registers pack four pads or signals per
//! 32-bit register, one byte lane each:
//!
//! | | SYS | AON |
//! |---|---|---|
//! | `doen` | `0x00`, 6 bits, index 0..=49 (T2-579..T2-594) | `0x00`, 3 bits, index 0..=5 (T2-753) |
//! | `dout` | `0x40`, 7 bits, index 0..=107 (T2-595..T2-610) | `0x04`, 4 bits, index 0..=9 (T2-754) |
//! | `sig_in` | `0x80`, 7 bits, GPI 0..=90 (T2-611..T2-633) | `0x08`, 3 bits, GPI 0..=3 (T2-755) |
//! | muxable pads | GPIO0..=63 (pins 0..=63) | RGPIO0..=3 (pins 1..=4) |
//!
//! The pad-configuration half is one register per pad (`pad_cfg`). The
//! registers of the SYS block start at `0x120` and those of the AON block at
//! `0x30`, one word per pin:
//!
//! ```text
//!  7  POS    power-on-start: active pull-down on loss of core power
//!  6  SMT    Schmitt trigger
//!  5  SLEW   slow (0) / fast (1)
//!  4  PD     pull-down
//!  3  PU     pull-up
//!  2:1 DS    drive strength: 2, 4, 8, 12 mA
//!  0  IE     input enable (receiver)
//! ```
//!
//! (Tables 2-651..2-745 and 2-765..2-769.) Pins: SYS 0..=63 are GPIO0..63,
//! 64..=74 SD0 (clock, command, data 0..7, strobe), 75..=88 GMAC1 and
//! 89..=94 QSPI (SCLK, CSn0, data 0..3). AON 0 is TESTEN, 1..=4 RGPIO0..3,
//! 5 RSTN, 7 RTC, 9 OSC, 10..=23 GMAC0. The GMAC pads have no pad register in
//! these tables, only a 2-bit IO-voltage select (T2-726..T2-739, T2-773..
//! T2-786) that is a rail, not a pad property: they take no mux, bias or
//! configuration here. TESTEN has only POS, RSTN only SMT and POS, and RTC
//! and OSC only DS (T2-765, T2-770..T2-772); a property the pad does not
//! have is `Unsupported`.
//!
//! A third register per pad selects among the pad's special functions
//! (`func_sel`, "Function 0..3" of Table 2-39), for GPIO6..63 and one GMAC pad
//! of each block (T2-746..T2-751, T2-787). Its field is 2 or 3 bits wide at an
//! irregular place, so it is a table here.
//!
//! The pad controller decodes its own `pinmux` words (the framework hands
//! them over untouched):
//!
//! ```text
//!  gpiomux  31 = 0   30:24 gpi    23:16 doen   15:8 dout     7:0 pin
//!  funcsel  31 = 1                            15:8 function   7:0 pin
//! ```
//!
//! `gpi` is the GPI signal index, or [`GPI_NONE`] for an output-only signal;
//! `dout` the GPO signal index, or [`DOUT_NONE`] for an input-only one.
//! [`gpiomux`] and [`funcsel`] build the words. A gpiomux write is in the
//! order that never glitches the pad: output data, then the input mapping,
//! then the output enable.
//!
//! Not modelled: the slew-rate and power-on-start bits (no generic pinctrl
//! property the framework parses), the GMAC voltage selects, the DVP function
//! selects (T2-751, T2-752: they name signals, not pads), and the GPIO
//! interrupt registers (`0xdc`.. of SYS, `0x0c`.. of AON), which belong to
//! the GPIO driver. [verify] The drive-strength code `11` is 12 mA: the table
//! (T2-651) prints the last row as `01` again, an evident typo.

use crate::pinctrl::{Bias, Conf, PinctrlOps};
use crate::{Bus, Error, Result};

pub const SYS_IOMUX_COMPATIBLE: &str = "starfive,jh7110-sys-pinctrl";
pub const AON_IOMUX_COMPATIBLE: &str = "starfive,jh7110-aon-pinctrl";

/// `gpi` of a word for an output-only signal: no input mapping is written.
pub const GPI_NONE: u32 = 0x7f;
/// `dout` of a word for an input-only signal (TRM 2.7.6.3.2: "GPO signal:
/// none"): the pad's output data is left as it is.
pub const DOUT_NONE: u32 = 0xff;

const FUNCSEL: u32 = 1 << 31;

/// The `pinmux` word that routes `pin` to output signal `dout`, enable
/// signal `doen` and input signal `gpi`.
pub const fn gpiomux(pin: u32, dout: u32, doen: u32, gpi: u32) -> u32 {
    (gpi & 0x7f) << 24 | (doen & 0xff) << 16 | (dout & 0xff) << 8 | (pin & 0xff)
}

/// The `pinmux` word that selects special function `func` (0..=3) of `pin`.
pub const fn funcsel(pin: u32, func: u32) -> u32 {
    FUNCSEL | (func & 0xff) << 8 | (pin & 0xff)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Block {
    Sys,
    Aon,
}

/// A field of a register.
#[derive(Clone, Copy)]
struct Fld {
    shift: u32,
    width: u32,
}

impl Fld {
    const fn mask(self) -> u32 {
        ((1u32 << self.width) - 1) << self.shift
    }
}

/// The pad-configuration fields a pad has.
#[derive(Clone, Copy)]
struct Pad {
    off: u64,
    ie: Option<Fld>,
    ds: Option<Fld>,
    pu: Option<Fld>,
    pd: Option<Fld>,
    smt: Option<Fld>,
}

/// SD0, QSPI and the GPIO pads, the RGPIO pads.
const FULL: Pad = Pad {
    off: 0,
    ie: Some(Fld { shift: 0, width: 1 }),
    ds: Some(Fld { shift: 1, width: 2 }),
    pu: Some(Fld { shift: 3, width: 1 }),
    pd: Some(Fld { shift: 4, width: 1 }),
    smt: Some(Fld { shift: 6, width: 1 }),
};
const NONE: Pad = Pad { off: 0, ie: None, ds: None, pu: None, pd: None, smt: None };

/// Layout constants of one block.
#[derive(Clone, Copy)]
struct Layout {
    doen: Fld,
    doen_max: u32,
    dout_off: u64,
    dout: Fld,
    dout_max: u32,
    sig_in_off: u64,
    sig_in: Fld,
    gpi_max: u32,
    /// First muxable pin and how many.
    mux_first: u32,
    mux_count: u32,
    /// Register of pin 0 of the pad-configuration bank.
    pad_base: u64,
    /// `(pin, register offset, shift, width)` of the function selects.
    func_sel: &'static [(u32, u16, u8, u8)],
}

const SYS: Layout = Layout {
    doen: Fld { shift: 0, width: 6 },
    doen_max: 49,
    dout_off: 0x40,
    dout: Fld { shift: 0, width: 7 },
    dout_max: 107,
    sig_in_off: 0x80,
    sig_in: Fld { shift: 0, width: 7 },
    gpi_max: 90,
    mux_first: 0,
    mux_count: 64,
    pad_base: 0x120,
    func_sel: SYS_FUNC_SEL,
};

const AON: Layout = Layout {
    doen: Fld { shift: 0, width: 3 },
    doen_max: 5,
    dout_off: 0x4,
    dout: Fld { shift: 0, width: 4 },
    dout_max: 9,
    sig_in_off: 0x8,
    sig_in: Fld { shift: 0, width: 3 },
    gpi_max: 3,
    mux_first: 1,
    mux_count: 4,
    pad_base: 0x30,
    func_sel: &[(17, 0x90, 0, 2)],
};

/// SYS function selects, sorted by pin (T2-746..T2-751).
const SYS_FUNC_SEL: &[(u32, u16, u8, u8)] = &[
    (6, 0x2b0, 0, 2),
    (7, 0x2b0, 2, 3),
    (8, 0x2b0, 5, 3),
    (9, 0x2b0, 8, 3),
    (10, 0x29c, 2, 3),
    (11, 0x29c, 5, 3),
    (12, 0x29c, 8, 3),
    (13, 0x29c, 11, 3),
    (14, 0x29c, 14, 3),
    (15, 0x29c, 17, 3),
    (16, 0x29c, 20, 3),
    (17, 0x29c, 23, 3),
    (18, 0x29c, 26, 3),
    (19, 0x29c, 29, 3),
    (20, 0x2a0, 0, 3),
    (21, 0x2a0, 3, 3),
    (22, 0x2a0, 6, 3),
    (23, 0x2a0, 9, 3),
    (24, 0x2a0, 12, 3),
    (25, 0x2a0, 15, 3),
    (26, 0x2a0, 18, 3),
    (27, 0x2a0, 21, 3),
    (28, 0x2a0, 24, 3),
    (29, 0x2a0, 27, 3),
    (30, 0x2a4, 0, 3),
    (31, 0x2a4, 3, 3),
    (32, 0x2a4, 6, 3),
    (33, 0x2a4, 9, 3),
    (34, 0x2a4, 12, 3),
    (35, 0x2a4, 15, 2),
    (36, 0x2a4, 17, 3),
    (37, 0x2a4, 20, 3),
    (38, 0x2a4, 23, 3),
    (39, 0x2a4, 26, 3),
    (40, 0x2a4, 29, 3),
    (41, 0x2a8, 0, 3),
    (42, 0x2a8, 3, 3),
    (43, 0x2a8, 6, 3),
    (44, 0x2a8, 9, 3),
    (45, 0x2a8, 12, 3),
    (46, 0x2a8, 15, 3),
    (47, 0x2a8, 18, 3),
    (48, 0x2a8, 21, 3),
    (49, 0x2a8, 24, 3),
    (50, 0x2a8, 27, 3),
    (51, 0x2a8, 30, 2),
    (52, 0x2ac, 0, 2),
    (53, 0x2ac, 2, 2),
    (54, 0x2ac, 4, 2),
    (55, 0x2ac, 6, 3),
    (56, 0x2ac, 9, 3),
    (57, 0x2ac, 12, 3),
    (58, 0x2ac, 15, 3),
    (59, 0x2ac, 18, 3),
    (60, 0x2ac, 21, 3),
    (61, 0x2ac, 24, 3),
    (62, 0x2ac, 27, 3),
    (63, 0x2ac, 30, 2),
    (82, 0x29c, 0, 2),
];

/// The JH7110 pad controller of one block.
pub struct Jh7110Iomux {
    base: u64,
    block: Block,
}

impl Jh7110Iomux {
    /// The SYS block whose registers start at `base` (`0x1304_0000`).
    pub const fn sys(base: u64) -> Self {
        Jh7110Iomux { base, block: Block::Sys }
    }

    /// The AON block whose registers start at `base` (`0x1702_0000`).
    pub const fn aon(base: u64) -> Self {
        Jh7110Iomux { base, block: Block::Aon }
    }

    /// From `node`: the pad controller its `compatible` names, at its `reg`.
    pub fn from_dt(fdt: &crate::Fdt<'_>, node: crate::NodeId) -> Option<Self> {
        if !fdt.is_available(node) {
            return None;
        }
        let (base, _) = fdt.reg(node)?;
        if fdt.is_compatible(node, SYS_IOMUX_COMPATIBLE) {
            Some(Self::sys(base))
        } else if fdt.is_compatible(node, AON_IOMUX_COMPATIBLE) {
            Some(Self::aon(base))
        } else {
            None
        }
    }

    fn layout(&self) -> &'static Layout {
        match self.block {
            Block::Sys => &SYS,
            Block::Aon => &AON,
        }
    }

    fn rmw(&self, bus: &mut dyn Bus, addr: u64, f: Fld, val: u32) {
        let a = self.base + addr;
        let v = bus.read32(a);
        bus.write32(a, (v & !f.mask()) | ((val << f.shift) & f.mask()));
    }

    /// The byte lane of entry `i` (four per register) of a bank at `off`.
    fn lane(off: u64, i: u32, f: Fld) -> (u64, Fld) {
        (off + 4 * (i / 4) as u64, Fld { shift: 8 * (i % 4) + f.shift, width: f.width })
    }

    /// The pad-configuration register layout of `pin`, `Unsupported` for a
    /// pad that only has an IO-voltage select, `BadSpec` for a number the
    /// TRM does not name.
    fn pad(&self, pin: u32) -> Result<Pad> {
        let l = self.layout();
        let at = |p: Pad| Pad { off: l.pad_base + 4 * pin as u64, ..p };
        match (self.block, pin) {
            (Block::Sys, 0..=74) | (Block::Sys, 89..=94) => Ok(at(FULL)),
            (Block::Sys, 75..=88) => Err(Error::Unsupported),
            (Block::Aon, 0) => Ok(at(NONE)),
            (Block::Aon, 1..=4) => Ok(at(FULL)),
            (Block::Aon, 5) => Ok(at(Pad { smt: Some(Fld { shift: 0, width: 1 }), ..NONE })),
            (Block::Aon, 7) | (Block::Aon, 9) => Ok(at(Pad { ds: Some(Fld { shift: 0, width: 2 }), ..NONE })),
            (Block::Aon, 10..=23) => Err(Error::Unsupported),
            _ => Err(Error::BadSpec),
        }
    }

    /// Route a muxable pin: output data (unless input-only), input mapping
    /// (unless output-only), output enable.
    fn gpiomux(&self, bus: &mut dyn Bus, word: u32) -> Result<()> {
        let l = self.layout();
        let pin = word & 0xff;
        let dout = (word >> 8) & 0xff;
        let doen = (word >> 16) & 0xff;
        let gpi = (word >> 24) & 0x7f;
        if pin < l.mux_first
            || pin >= l.mux_first + l.mux_count
            || (dout != DOUT_NONE && dout > l.dout_max)
            || doen > l.doen_max
        {
            return Err(Error::BadSpec);
        }
        if gpi != GPI_NONE && gpi > l.gpi_max {
            return Err(Error::BadSpec);
        }
        let n = pin - l.mux_first;
        if dout != DOUT_NONE {
            let (a, f) = Self::lane(l.dout_off, n, l.dout);
            self.rmw(bus, a, f, dout);
        }
        if gpi != GPI_NONE {
            let (a, f) = Self::lane(l.sig_in_off, gpi, l.sig_in);
            self.rmw(bus, a, f, n + 2);
        }
        let (a, f) = Self::lane(0, n, l.doen);
        self.rmw(bus, a, f, doen);
        Ok(())
    }

    fn funcsel(&self, bus: &mut dyn Bus, word: u32) -> Result<()> {
        let pin = word & 0xff;
        let func = (word >> 8) & 0xff;
        let &(_, off, shift, width) = self.layout().func_sel.iter().find(|e| e.0 == pin).ok_or(Error::BadSpec)?;
        if func > 3 {
            return Err(Error::BadSpec);
        }
        self.rmw(bus, off as u64, Fld { shift: shift as u32, width: width as u32 }, func);
        Ok(())
    }
}

impl PinctrlOps for Jh7110Iomux {
    fn pin_of(&self, word: u32) -> u32 {
        word & 0xff
    }

    fn set_mux(&mut self, bus: &mut dyn Bus, word: u32) -> Result<()> {
        if word & FUNCSEL != 0 {
            self.funcsel(bus, word)
        } else {
            self.gpiomux(bus, word)
        }
    }

    fn set_bias(&mut self, bus: &mut dyn Bus, pin: u32, bias: Bias) -> Result<()> {
        let p = self.pad(pin)?;
        let (pu, pd) = p.pu.zip(p.pd).ok_or(Error::Unsupported)?;
        let (up, down) = match bias {
            Bias::Disable => (0, 0),
            Bias::PullUp => (1, 0),
            Bias::PullDown => (0, 1),
            Bias::BusHold => return Err(Error::Unsupported),
        };
        // One read-modify-write of the whole register: the pad is never
        // seen with both pulls on.
        let a = self.base + p.off;
        let v = bus.read32(a);
        bus.write32(a, (v & !(pu.mask() | pd.mask())) | up << pu.shift | down << pd.shift);
        Ok(())
    }

    fn set_conf(&mut self, bus: &mut dyn Bus, pin: u32, conf: Conf) -> Result<()> {
        let p = self.pad(pin)?;
        match conf {
            Conf::DriveStrength(ma) => {
                let code = match ma {
                    2 => 0,
                    4 => 1,
                    8 => 2,
                    12 => 3,
                    _ => return Err(Error::BadSpec),
                };
                self.rmw(bus, p.off, p.ds.ok_or(Error::Unsupported)?, code);
            }
            Conf::InputEnable(on) => self.rmw(bus, p.off, p.ie.ok_or(Error::Unsupported)?, on as u32),
            Conf::Schmitt(on) => self.rmw(bus, p.off, p.smt.ok_or(Error::Unsupported)?, on as u32),
        }
        Ok(())
    }
}

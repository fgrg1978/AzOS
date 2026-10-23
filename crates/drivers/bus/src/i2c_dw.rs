// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Synopsys DesignWare APB I2C (`snps,designware-i2c`): what the controller
//! says about itself, and its bring-up as a bus master from the timing facts
//! the firmware gives.
//!
//! One driver for every DesignWare controller the kernel meets: the JH7110's
//! (VisionFive 2), the RP1's on the Raspberry Pi 5 (both found in the device
//! tree) and the Intel LPSS ones (found by PCI id, behind the LPSS private
//! registers below). The transfer state machine is `crate::i2c_txn`'s; this
//! file is the part that differs per integration: the input clock, the bus
//! rate, the fall and hold times, the FIFO depths.
//!
//! # Where each fact comes from
//!
//! * **Is this a DesignWare I2C at all**: `IC_COMP_TYPE`, which reads
//!   0x4457_0140 on every one. A window that reads anything else is refused,
//!   so a wrong `reg` or BAR is a line, not writes into another device.
//! * **FIFO depths**: `IC_COMP_PARAM_1` (RX depth - 1 in bits 15:8, TX depth -
//!   1 in 23:16). An IP built without its encoded parameters reads 0 there;
//!   then the caller's fallback (Kconfig `I2C_DW_RX_FIFO_DEPTH`) is used, as
//!   Linux uses its platform's.
//! * **Fastest mode the IP has**: `IC_COMP_PARAM_1` bits 3:2.
//! * **Input clock (`ic_clk`)**: the firmware's, never a constant here: the
//!   node's clock (device tree) or the PCI id's driver data (Intel LPSS, as
//!   Linux keys it). Unknown: the SCL counts the controller already holds are
//!   kept (what the firmware programmed, or the integrator's reset values)
//!   and [`Counts::Kept`] says so; a controller holding zero counts is
//!   refused.
//! * **Bus rate, fall and hold times**: the I2C binding's properties
//!   (`clock-frequency`, `i2c-scl-falling-time-ns`, `i2c-sda-falling-time-ns`,
//!   `i2c-sda-hold-time-ns`), with the binding's defaults where absent.
//!
//! Register offsets and `IC_CON` bits: Linux `include/linux/designware_i2c.h`.
//! The count formulas, the 300 ns fall default, the SDA-hold encoding and
//! its minimum IP version are Linux `i2c-designware-common.c` /
//! `i2c-designware-master.c` (the "DW default" condition), which follow the
//! DW_apb_i2c databook's timing equations.
//!
//! Pure: registers through [`DwRegs`], so `tests/host/drivers-tests` runs it
//! against a modelled register file.

use crate::i2c_txn::{DwRegs, ENABLE_STATUS_IC_EN, IC_CLR_INTR, IC_ENABLE, IC_ENABLE_STATUS, IC_INTR_MASK};

pub const IC_CON: usize = 0x00;
pub const IC_SS_SCL_HCNT: usize = 0x14;
pub const IC_SS_SCL_LCNT: usize = 0x18;
pub const IC_FS_SCL_HCNT: usize = 0x1C;
pub const IC_FS_SCL_LCNT: usize = 0x20;
pub const IC_SDA_HOLD: usize = 0x7C;
pub const IC_COMP_PARAM_1: usize = 0xF4;
pub const IC_COMP_VERSION: usize = 0xF8;
pub const IC_COMP_TYPE: usize = 0xFC;

/// `IC_COMP_TYPE` of every DesignWare I2C ("DW", 0x0140), read with 32-bit
/// accesses. The 16-bit and byte-swapped buses Linux also accepts are not
/// supported: such a window reads something else and is refused.
pub const COMP_TYPE_DW: u32 = 0x4457_0140;

/// The first IP version with a programmable SDA hold time (1.11a).
const SDA_HOLD_MIN_VERSION: u32 = 0x3131_312A;
/// `IC_SDA_HOLD`: the RX hold field (bits 23:16).
const SDA_HOLD_RX_SHIFT: u32 = 16;
const SDA_HOLD_RX_MASK: u32 = 0xFF << SDA_HOLD_RX_SHIFT;

// IC_CON bits (designware_i2c.h).
pub const CON_MASTER: u32 = 1 << 0;
pub const CON_SPEED_STD: u32 = 1 << 1;
pub const CON_SPEED_FAST: u32 = 2 << 1;
pub const CON_RESTART_EN: u32 = 1 << 5;
pub const CON_SLAVE_DISABLE: u32 = 1 << 6;

/// How many `IC_ENABLE_STATUS` reads [`init_master`] gives a disable. An idle
/// controller is disabled within a few `ic_clk` cycles, so the first read
/// normally sees it; one still enabled after this many is mid-transfer on a
/// stuck bus.
const DISABLE_POLLS: u32 = 1000;

/// The SCL counts are 16-bit registers; the databook's smallest valid values.
const HCNT_MIN: u32 = 6;
const LCNT_MIN: u32 = 8;
const CNT_MAX: u32 = 0xFFFF;

/// The bus rates a master can run, each with its timing (I2C specification
/// minimums, as the Linux driver programs them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// 100 kHz: tHIGH 4.0 us, tLOW 4.7 us; `IC_SS_SCL_*`.
    Standard,
    /// 400 kHz: tHIGH 0.6 us, tLOW 1.3 us; `IC_FS_SCL_*`.
    Fast,
    /// 1 MHz (fast mode plus): tHIGH 0.26 us, tLOW 0.5 us; also `IC_FS_SCL_*`.
    FastPlus,
}

impl Mode {
    /// The mode of a bus rate the binding names. Only the rates the
    /// specification defines are accepted (as Linux does): a rate in between
    /// has no timing to program, and running it at the next faster mode would
    /// overrun the slowest device on the bus. High speed (3.4 MHz) is not
    /// supported (no `IC_HS_*` programming, no master code).
    pub fn from_bus_hz(hz: u32) -> Option<Mode> {
        match hz {
            100_000 => Some(Mode::Standard),
            400_000 => Some(Mode::Fast),
            1_000_000 => Some(Mode::FastPlus),
            _ => None,
        }
    }

    /// (tHIGH, tLOW) in ns.
    fn t_high_low_ns(self) -> (u64, u64) {
        match self {
            Mode::Standard => (4000, 4700),
            Mode::Fast => (600, 1300),
            Mode::FastPlus => (260, 500),
        }
    }

    /// The (HCNT, LCNT) registers of this mode.
    fn count_regs(self) -> (usize, usize) {
        match self {
            Mode::Standard => (IC_SS_SCL_HCNT, IC_SS_SCL_LCNT),
            Mode::Fast | Mode::FastPlus => (IC_FS_SCL_HCNT, IC_FS_SCL_LCNT),
        }
    }

    fn con_speed(self) -> u32 {
        match self {
            Mode::Standard => CON_SPEED_STD,
            Mode::Fast | Mode::FastPlus => CON_SPEED_FAST,
        }
    }
}

/// What the firmware says about one controller's integration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// `ic_clk` in Hz; `None` when the firmware does not say.
    pub ic_clk_hz: Option<u64>,
    /// The bus rate (`clock-frequency`; [`DEFAULT_BUS_HZ`] where absent).
    pub bus_hz: u32,
    /// `i2c-scl-falling-time-ns` (default [`DEFAULT_FALL_NS`]).
    pub scl_fall_ns: Option<u32>,
    /// `i2c-sda-falling-time-ns` (default: the SCL fall time, then
    /// [`DEFAULT_FALL_NS`]).
    pub sda_fall_ns: Option<u32>,
    /// `i2c-sda-hold-time-ns`; `None`: the hold the controller holds is kept.
    pub sda_hold_ns: Option<u32>,
}

/// The I2C binding's bus rate when the node names none.
pub const DEFAULT_BUS_HZ: u32 = 100_000;
/// The fall time assumed where the firmware gives none (Linux's, "for safety").
pub const DEFAULT_FALL_NS: u32 = 300;

impl Timing {
    /// No firmware facts but the clock: standard mode, the defaults.
    pub const fn with_clock(ic_clk_hz: Option<u64>) -> Timing {
        Timing { ic_clk_hz, bus_hz: DEFAULT_BUS_HZ, scl_fall_ns: None, sda_fall_ns: None, sda_hold_ns: None }
    }
}

/// Where the SCL counts came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counts {
    /// Computed from `ic_clk` and written.
    Computed,
    /// `ic_clk` unknown: the counts the controller held were kept.
    Kept,
}

/// The controller as [`init_master`] left it: disabled, a master, its
/// interrupts masked. `i2c_txn` enables it per transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setup {
    pub mode: Mode,
    pub hcnt: u32,
    pub lcnt: u32,
    pub counts: Counts,
    /// RX FIFO depth in entries (`IC_COMP_PARAM_1`, else the fallback).
    pub rx_depth: usize,
    /// Whether `rx_depth` is the IP's own (`IC_COMP_PARAM_1`).
    pub depth_from_ip: bool,
    pub version: u32,
    /// `IC_SDA_HOLD` as written; `None`: left as it was.
    pub sda_hold: Option<u32>,
}

/// Why a controller was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    /// `IC_COMP_TYPE` read this, not [`COMP_TYPE_DW`].
    NotDesignWare(u32),
    /// The firmware asks for a rate [`Mode::from_bus_hz`] has no timing for.
    UnsupportedRate(u32),
    /// The IP's fastest mode (`IC_COMP_PARAM_1`) is below the rate asked.
    RateAboveIp(u32),
    /// `ic_clk` unknown and the controller holds zero counts for the mode.
    CountsUnknown,
    /// The counts for `ic_clk` do not fit the 16-bit registers.
    CountsOutOfRange,
    /// `IC_ENABLE_STATUS` still enabled after the disable (a stuck bus).
    StillEnabled,
}

/// RX and TX FIFO depths `IC_COMP_PARAM_1` encodes, `None` when it encodes
/// none (a depth below 2 is what an IP without encoded parameters reads).
pub fn fifo_depths(param1: u32) -> Option<(usize, usize)> {
    let rx = ((param1 >> 8) & 0xFF) as usize + 1;
    let tx = ((param1 >> 16) & 0xFF) as usize + 1;
    (rx >= 2 && tx >= 2).then_some((rx, tx))
}

/// The fastest mode the IP was built with (`IC_COMP_PARAM_1` bits 3:2:
/// 1 standard, 2 fast, 3 high); `None` when the field reads 0 (no encoded
/// parameters: nothing is known, nothing is refused).
fn ip_max_speed(param1: u32) -> Option<u32> {
    match (param1 >> 2) & 0x3 {
        0 => None,
        s => Some(s),
    }
}

/// `round(a / b)` on integers (Linux `DIV_ROUND_CLOSEST_ULL`).
fn div_round(a: u64, b: u64) -> u64 {
    (a + b / 2) / b
}

/// SCL high count for `tHIGH` (`t_symbol_ns`), from `ic_clk` in kHz:
/// `HCNT + 3 >= IC_CLK * (tHIGH + tf)` (Linux `i2c_dw_scl_hcnt`, the "DW
/// default" condition, which also meets tHD;STA).
pub fn scl_hcnt(ic_clk_khz: u64, t_symbol_ns: u64, tf_ns: u64) -> u64 {
    div_round(ic_clk_khz * (t_symbol_ns + tf_ns), 1_000_000).saturating_sub(3)
}

/// SCL low count for `tLOW`: `LCNT + 1 >= IC_CLK * (tLOW + tf)` (Linux
/// `i2c_dw_scl_lcnt`: the low period is counted from the moment SCL is
/// pulled, so the fall time is part of it).
pub fn scl_lcnt(ic_clk_khz: u64, t_low_ns: u64, tf_ns: u64) -> u64 {
    div_round(ic_clk_khz * (t_low_ns + tf_ns), 1_000_000).saturating_sub(1)
}

/// The (HCNT, LCNT) of `mode` at `ic_clk_hz`, with the firmware's fall times
/// (HCNT takes the SDA fall time, LCNT the SCL one, as Linux does), raised to
/// the databook's minimums. `None` when a count does not fit 16 bits.
pub fn counts_for(mode: Mode, ic_clk_hz: u64, t: &Timing) -> Option<(u32, u32)> {
    let khz = ic_clk_hz / 1000;
    let scl_fall = t.scl_fall_ns.unwrap_or(DEFAULT_FALL_NS) as u64;
    let sda_fall = t.sda_fall_ns.or(t.scl_fall_ns).unwrap_or(DEFAULT_FALL_NS) as u64;
    let (high, low) = mode.t_high_low_ns();
    let h = scl_hcnt(khz, high, sda_fall).max(HCNT_MIN as u64);
    let l = scl_lcnt(khz, low, scl_fall).max(LCNT_MIN as u64);
    (h <= CNT_MAX as u64 && l <= CNT_MAX as u64).then_some((h as u32, l as u32))
}

/// `IC_SDA_HOLD` for `hold_ns` at `ic_clk_hz`: the TX hold in cycles, with a
/// non-zero RX hold forced (Linux: a slave that pulls SDA too soon after
/// SCL falls otherwise costs a TX arbitration loss).
pub fn sda_hold_value(ic_clk_hz: u64, hold_ns: u32) -> u32 {
    let mut v = div_round(ic_clk_hz / 1000 * hold_ns as u64, 1_000_000).min(0xFFFF) as u32;
    if v & SDA_HOLD_RX_MASK == 0 {
        v |= 1 << SDA_HOLD_RX_SHIFT;
    }
    v
}

/// Is the window a DesignWare I2C? Its `IC_COMP_TYPE`, or why not.
pub fn identify<R: DwRegs + ?Sized>(r: &R) -> Result<(), InitError> {
    match r.rd(IC_COMP_TYPE) {
        COMP_TYPE_DW => Ok(()),
        other => Err(InitError::NotDesignWare(other)),
    }
}

/// Bring the controller up as a master (7-bit addressing, repeated start,
/// slave disabled) at the rate and timing `t` gives. Leaves it disabled with
/// its interrupts masked: `i2c_txn` enables it per transaction, after
/// writing `IC_TAR` (which only a disabled controller takes).
/// `fallback_rx_depth`: the RX FIFO depth when the IP encodes none.
pub fn init_master<R: DwRegs + ?Sized>(r: &R, t: &Timing, fallback_rx_depth: usize) -> Result<Setup, InitError> {
    identify(r)?;
    let mode = Mode::from_bus_hz(t.bus_hz).ok_or(InitError::UnsupportedRate(t.bus_hz))?;
    let param1 = r.rd(IC_COMP_PARAM_1);
    if let Some(max) = ip_max_speed(param1) {
        // 1: standard only. Fast and fast plus share `IC_FS_SCL_*` (2).
        if max == 1 && mode != Mode::Standard {
            return Err(InitError::RateAboveIp(t.bus_hz));
        }
    }
    let (rx_depth, depth_from_ip) = match fifo_depths(param1) {
        Some((rx, _tx)) => (rx, true),
        None => (fallback_rx_depth, false),
    };
    let version = r.rd(IC_COMP_VERSION);

    r.wr(IC_ENABLE, 0);
    if !(0..DISABLE_POLLS).any(|_| r.rd(IC_ENABLE_STATUS) & ENABLE_STATUS_IC_EN == 0) {
        return Err(InitError::StillEnabled);
    }

    let (hreg, lreg) = mode.count_regs();
    let (hcnt, lcnt, counts) = match t.ic_clk_hz {
        Some(hz) => {
            let (h, l) = counts_for(mode, hz, t).ok_or(InitError::CountsOutOfRange)?;
            r.wr(hreg, h);
            r.wr(lreg, l);
            (h, l, Counts::Computed)
        }
        None => {
            let (h, l) = (r.rd(hreg) & CNT_MAX, r.rd(lreg) & CNT_MAX);
            if h == 0 || l == 0 {
                return Err(InitError::CountsUnknown);
            }
            (h, l, Counts::Kept)
        }
    };
    r.wr(IC_CON, CON_MASTER | mode.con_speed() | CON_RESTART_EN | CON_SLAVE_DISABLE);

    // The hold time is cycles of ic_clk: only with the clock known.
    let sda_hold = match (t.sda_hold_ns, t.ic_clk_hz) {
        (Some(ns), Some(hz)) if version >= SDA_HOLD_MIN_VERSION => {
            let v = sda_hold_value(hz, ns);
            r.wr(IC_SDA_HOLD, v);
            Some(v)
        }
        _ => None,
    };

    r.wr(IC_INTR_MASK, 0);
    let _ = r.rd(IC_CLR_INTR);
    Ok(Setup { mode, hcnt, lcnt, counts, rx_depth, depth_from_ip, version, sda_hold })
}

// ── Intel LPSS: the private registers around a DesignWare controller ─────────
//
// From Skylake's PCH (Sunrise Point) on, each Intel LPSS function is a PCI
// function whose BAR 0 holds the IP at 0x000 and the LPSS private registers
// at 0x200 (Linux `drivers/mfd/intel-lpss.c`, which owns the function and
// hands the IP to the DesignWare driver). The function comes out of reset
// held; the private `RESETS` register releases it. The `CAPS` register names
// what the function is, so a PCI id that names an LPSS UART or SPI is
// refused here, not driven as an I2C.

/// The LPSS private registers, from BAR 0.
pub const LPSS_PRIV: usize = 0x200;
/// `RESETS`: the function's (bits 1:0) and its iDMA's (bit 2) reset, 1 = released.
const LPSS_PRIV_RESETS: usize = LPSS_PRIV + 0x04;
const LPSS_RESETS_FUNC: u32 = 0x3;
const LPSS_RESETS_IDMA: u32 = 1 << 2;
/// `CAPS`: bits 7:4 the function type (0 I2C, 1 UART, 2 SPI).
const LPSS_PRIV_CAPS: usize = LPSS_PRIV + 0xFC;
const LPSS_CAPS_TYPE_SHIFT: u32 = 4;
const LPSS_CAPS_TYPE_MASK: u32 = 0xF << LPSS_CAPS_TYPE_SHIFT;
const LPSS_TYPE_I2C: u32 = 0;

/// Release an LPSS I2C function from reset (put in reset, then released, as
/// Linux's `intel_lpss_init_dev` does), after checking from `CAPS` that it is
/// an I2C. `Err(type)`: the function is another LPSS type.
pub fn lpss_release<R: DwRegs + ?Sized>(r: &R) -> Result<(), u32> {
    let ty = (r.rd(LPSS_PRIV_CAPS) & LPSS_CAPS_TYPE_MASK) >> LPSS_CAPS_TYPE_SHIFT;
    if ty != LPSS_TYPE_I2C {
        return Err(ty);
    }
    r.wr(LPSS_PRIV_RESETS, 0);
    r.wr(LPSS_PRIV_RESETS, LPSS_RESETS_FUNC | LPSS_RESETS_IDMA);
    Ok(())
}

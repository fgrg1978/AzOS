// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The AMD FCH watchdog ("SP5100 TCO", Kconfig `WDT_SP5100_TCO`) of the Zen
//! chipsets: the register logic, over windows the caller maps. `wdt.rs`
//! holds them and hands this module to the system watchdog.
//!
//! **Found by PCI, not assumed.** The FCH is the chipset behind the SMBus
//! function `1022:790b` (AMD "KERNCZ"; Hygon `1d94:790b` is the same part),
//! and the layout here is the one Linux `sp5100_tco.c` calls `efch_mmio`:
//! that function at revision [`ZEN_SMBUS_REV`] or later, where the legacy
//! index/data ports (0xCD6/0xCD7) are gone and the PM registers are reached
//! through the FCH's ACPI MMIO block. The block's addresses below are the
//! FCH's own, fixed by the chip for that PCI id (Linux `sp5100_tco.h`
//! carries the same constants: nothing in ACPI or PCI publishes them), and
//! are used only once the id has said this FCH is there. Older SB800/SP5100
//! layouts are not driven: [`is_efch_mmio`] refuses them.
//!
//! **Bring-up** ([`enable_decode`], then [`setup`]): PM `DECODEEN` bit 7
//! (`WDT_TMREN`) turns on the decode of the watchdog's window at
//! [`WDT_PHYS`]; PM `DECODEEN3` clears the two disable bits and selects the
//! 1 s count resolution.
//!
//! Watchdog window, two 32-bit registers:
//!
//! ```text
//! 0x00  CONTROL  bit 0 run, bit 1 fired (the last reset was the watchdog's),
//!                bit 2 action (0 reset, 1 power-off), bit 3 disabled,
//!                bit 7 trigger (reload the count)
//! 0x04  COUNT    the timeout, in seconds at the 1 s resolution
//! ```

/// The SMBus function that names the FCH, and its first `efch_mmio` revision.
pub const VENDOR_AMD: u16 = 0x1022;
pub const VENDOR_HYGON: u16 = 0x1d94;
pub const DEVICE_KERNCZ_SMBUS: u16 = 0x790b;
pub const ZEN_SMBUS_REV: u8 = 0x51;

/// The FCH PM registers in its ACPI MMIO block, and how many of them.
pub const PM_PHYS: u64 = 0xFED8_0300;
pub const PM_BYTES: u64 = 8;
/// The watchdog's window once `DECODEEN.WDT_TMREN` is set.
pub const WDT_PHYS: u64 = 0xFEB0_0000;
pub const WDT_BYTES: u64 = 8;

pub const PM_DECODEEN: usize = 0x00;
pub const PM_DECODEEN_WDT_TMREN: u8 = 1 << 7;
pub const PM_DECODEEN3: usize = 0x03;
pub const PM_DECODEEN3_SECOND_RES: u8 = 0b11;
pub const PM_DECODEEN3_WDT_DISABLE: u8 = 0b1100;

pub const CONTROL: usize = 0x00;
pub const COUNT: usize = 0x04;
pub const CTL_RUN: u32 = 1 << 0;
pub const CTL_FIRED: u32 = 1 << 1;
pub const CTL_ACTION_POWEROFF: u32 = 1 << 2;
pub const CTL_DISABLED: u32 = 1 << 3;
pub const CTL_TRIGGER: u32 = 1 << 7;

/// The longest count the register holds, s.
pub const MAX_SECONDS: u32 = 0xFFFF;

/// The FCH PM byte registers.
pub trait Pm {
    fn read8(&self, off: usize) -> u8;
    fn write8(&self, off: usize, val: u8);
}

/// The watchdog's two registers.
pub trait Regs {
    fn read32(&self, off: usize) -> u32;
    fn write32(&self, off: usize, val: u32);
}

/// Is the SMBus function `vendor:device` at `revision` an FCH this driver
/// knows the layout of?
pub const fn is_efch_mmio(vendor: u16, device: u16, revision: u8) -> bool {
    (vendor == VENDOR_AMD || vendor == VENDOR_HYGON)
        && device == DEVICE_KERNCZ_SMBUS
        && revision >= ZEN_SMBUS_REV
}

/// Why the watchdog cannot be used.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// `DECODEEN.WDT_TMREN` does not stay set: the window is not decoded.
    NoDecode,
    /// `CONTROL.disabled`: the firmware turned the watchdog off for good.
    Disabled,
    /// Another hardware watchdog is already the system's (`wdt::found`).
    Busy,
}

/// Turn on the decode of the watchdog's window (Linux
/// `sp5100_tco_setupdevice_mmio`): set `WDT_TMREN` if it is clear and read it
/// back. `Ok` means [`WDT_PHYS`] may now be mapped.
pub fn enable_decode(pm: &impl Pm) -> Result<(), Refused> {
    let v = pm.read8(PM_DECODEEN);
    if v & PM_DECODEEN_WDT_TMREN == 0 {
        pm.write8(PM_DECODEEN, v | PM_DECODEEN_WDT_TMREN);
    }
    if pm.read8(PM_DECODEEN) & PM_DECODEEN_WDT_TMREN == 0 {
        return Err(Refused::NoDecode);
    }
    Ok(())
}

/// Enable the watchdog at the 1 s resolution, make its action a reset, and
/// leave it stopped (Linux `tco_timer_enable_mmio` + `sp5100_tco_timer_init`).
/// `Ok(fired)`: whether the last reset was the watchdog's.
pub fn setup(pm: &impl Pm, w: &impl Regs) -> Result<bool, Refused> {
    let v = pm.read8(PM_DECODEEN3);
    pm.write8(PM_DECODEEN3, (v & !PM_DECODEEN3_WDT_DISABLE) | PM_DECODEEN3_SECOND_RES);
    let c = w.read32(CONTROL);
    if c & CTL_DISABLED != 0 {
        return Err(Refused::Disabled);
    }
    w.write32(CONTROL, c & !(CTL_ACTION_POWEROFF | CTL_RUN));
    Ok(c & CTL_FIRED != 0)
}

/// The count for `timeout_ms` (whole seconds, at least 1, at most
/// [`MAX_SECONDS`]), and the timeout it gives, ms.
pub const fn seconds_for_ms(timeout_ms: u32) -> (u32, u32) {
    let s = timeout_ms / 1000;
    let s = if s == 0 { 1 } else if s > MAX_SECONDS { MAX_SECONDS } else { s };
    (s, s * 1000)
}

/// Arm: load the count, run, then trigger in a separate write (Linux
/// `tco_timer_start`: "This must be a distinct write").
pub fn arm(w: &impl Regs, seconds: u32) {
    w.write32(COUNT, seconds);
    let c = w.read32(CONTROL) | CTL_RUN;
    w.write32(CONTROL, c);
    w.write32(CONTROL, c | CTL_TRIGGER);
}

/// Reload the count.
pub fn kick(w: &impl Regs) {
    w.write32(CONTROL, w.read32(CONTROL) | CTL_TRIGGER);
}

/// Stop the count.
pub fn disarm(w: &impl Regs) {
    w.write32(CONTROL, w.read32(CONTROL) & !CTL_RUN);
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SpacemiT K1 GPIO controller (`spacemit,k1-gpio`, `gpio@d4019000`) over a
//! register trait.
//!
//! The controller is the PXA-family GPIO block: four banks of 32 pins, every
//! register a *set* of words, one per bank. All of it is from Linux v7.2.9
//! `drivers/gpio/gpio-spacemit-k1.c` (`spacemit_gpio_k1_offsets`,
//! `k1_gpio_data`) and the binding `spacemit,k1-gpio.yaml`:
//!
//! | register | offset | access | use here |
//! |----------|--------|--------|----------|
//! | `GPLR` (port level)        | 0x00 | R  | [`K1Gpio::level`] |
//! | `GPDR` (port direction)    | 0x0c | RW | [`K1Gpio::set_output`] (1 = output; the `dirout` register of the Linux driver's generic chip) |
//! | `GPSR` (port set)          | 0x18 | W  | [`K1Gpio::set_level`] high (the Linux driver passes it as `set`, with `GPIO_GENERIC_UNREADABLE_REG_SET`) |
//! | `GPCR` (port clear)        | 0x24 | W  | [`K1Gpio::set_level`] low (`clr`) |
//!
//! The bank of pin `n` is `n / 32`; its word sits at `bank_offsets[bank] +
//! register` with `bank_offsets = {0x0, 0x4, 0x8, 0x100}` (`k1_gpio_data`):
//! banks 0..2 interleave in one set (the three words of a register are 4
//! bytes apart, registers 0x0c apart) and bank 3 has a set of its own at
//! 0x100.
//!
//! The edge registers, for the kill switch's interrupt (the controller's one
//! shared line, the node's `interrupts`; the binding: edges only, no level
//! interrupts) [verify on silicon]:
//!
//! | register | offset | access | use here |
//! |----------|--------|--------|----------|
//! | `GEDR` (edge detect status) | 0x48 | R/W1C | [`K1Gpio::take`], [`K1Gpio::ack`] |
//! | `GSRER`/`GCRER` (set/clear rising-edge detect)  | 0x6c / 0x78 | W | [`K1Gpio::set_both_edges`] |
//! | `GSFER`/`GCFER` (set/clear falling-edge detect) | 0x84 / 0x90 | W | [`K1Gpio::set_both_edges`] |
//! | `GAPMASK` (interrupt mask, 1 = unmasked)        | 0x9c | RW | [`K1Gpio::set_unmasked`] |
//!
//! An enabled edge latches `GEDR` whatever the mask (the Linux handler reads
//! `GEDR` and keeps the bits its own mask allows), so an edge while the pin is
//! masked is taken when it is unmasked. Until [`K1Gpio::edge_irq_init`] the
//! registers are not touched, and the kernel calls that before it routes the
//! line, so a pin the firmware left with edge detection armed raises nothing.
//!
//! **A level write is one store.** `GPSR`/`GPCR` are set/clear registers: a
//! write of bit `b` changes pin `b` only, so no read-modify-write of a word
//! shared with 31 other pins exists on the level path, and
//! `gpio_write_panic` (the e-stop drive of the panic handler) needs no lock
//! and cannot lose a neighbour's update. Only a direction change reads and
//! writes `GPDR`; the caller serialises those.
//!
//! The register access is the [`K1GpioBus`] trait, so the host suite
//! (`tests/host/drivers-tests`, `gpio_k1_tests`) runs the driver against a
//! register-level model of the part.

/// Pins of the controller: 4 banks of 32. The kernel exposes the first
/// `gpio::GPIO_MAX_PINS`.
pub const PINS: u32 = 128;
/// Pins per bank.
pub const PINS_PER_BANK: u32 = 32;

/// `k1_gpio_data.bank_offsets`.
const BANK_OFFSETS: [usize; 4] = [0x00, 0x04, 0x08, 0x100];

/// `spacemit_gpio_k1_offsets`.
mod reg {
    pub const GPLR: usize = 0x00;
    pub const GPDR: usize = 0x0c;
    pub const GPSR: usize = 0x18;
    pub const GPCR: usize = 0x24;
    pub const GEDR: usize = 0x48;
    pub const GSRER: usize = 0x6c;
    pub const GCRER: usize = 0x78;
    pub const GSFER: usize = 0x84;
    pub const GCFER: usize = 0x90;
    pub const GAPMASK: usize = 0x9c;
}

/// Register access to the controller's window, supplied by the board.
pub trait K1GpioBus {
    /// Read the register at byte offset `off`.
    fn read32(&mut self, off: usize) -> u32;
    /// Write the register at byte offset `off`.
    fn write32(&mut self, off: usize, v: u32);
}

/// Byte offset of `register` for `pin`'s bank, and `pin`'s bit in it. `None`
/// for a pin the controller does not have.
const fn locate(register: usize, pin: u32) -> Option<(usize, u32)> {
    if pin >= PINS {
        return None;
    }
    Some((BANK_OFFSETS[(pin / PINS_PER_BANK) as usize] + register, 1 << (pin % PINS_PER_BANK)))
}

/// The K1 GPIO controller.
pub struct K1Gpio<B> {
    bus: B,
}

impl<B: K1GpioBus> K1Gpio<B> {
    /// Wrap the bus. Nothing is written: the pins keep the direction and
    /// level the firmware left (a board's reset and power-enable lines are
    /// among them).
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    /// The level `pin` is at (`GPLR`), whatever its direction. `None` for a
    /// pin the controller does not have.
    pub fn level(&mut self, pin: u32) -> Option<bool> {
        let (off, bit) = locate(reg::GPLR, pin)?;
        Some(self.bus.read32(off) & bit != 0)
    }

    /// Drive `pin`'s output latch high or low: ONE store to `GPSR` or `GPCR`,
    /// no read, no lock. `false` for a pin the controller does not have.
    pub fn set_level(&mut self, pin: u32, high: bool) -> bool {
        let Some((off, bit)) = locate(if high { reg::GPSR } else { reg::GPCR }, pin) else {
            return false;
        };
        self.bus.write32(off, bit);
        true
    }

    /// Flip `pin`: read its level, write the opposite. Two harts toggling the
    /// same pin at once is a race of intent, not a corruption: each write
    /// still changes this pin only. `false` for a pin the controller does not
    /// have.
    pub fn toggle(&mut self, pin: u32) -> bool {
        match self.level(pin) {
            Some(now) => self.set_level(pin, !now),
            None => false,
        }
    }

    /// Make `pin` an output (`GPDR` bit set) or an input (cleared): a
    /// read-modify-write of the bank's word, which 31 other pins share, so
    /// the CALLER serialises direction changes (`gpio.rs` holds a lock for
    /// them). The word is read back, and the call is true only if `pin` now
    /// has the direction asked: a controller whose clock is off, or a pin the
    /// controller does not have, is false.
    pub fn set_output(&mut self, pin: u32, output: bool) -> bool {
        let Some((off, bit)) = locate(reg::GPDR, pin) else {
            return false;
        };
        let cur = self.bus.read32(off);
        self.bus.write32(off, if output { cur | bit } else { cur & !bit });
        (self.bus.read32(off) & bit != 0) == output
    }

    /// Whether `pin` is an output now (`GPDR`). `None` for a pin the
    /// controller does not have.
    pub fn is_output(&mut self, pin: u32) -> Option<bool> {
        let (off, bit) = locate(reg::GPDR, pin)?;
        Some(self.bus.read32(off) & bit != 0)
    }

    /// Before the kernel routes the controller's line: in every bank, every
    /// pin masked, edge detection off, and every edge the firmware left
    /// latched cleared. Writes only; no level or direction register.
    pub fn edge_irq_init(&mut self) {
        for bank in BANK_OFFSETS {
            self.bus.write32(bank + reg::GAPMASK, 0);
            self.bus.write32(bank + reg::GCRER, !0);
            self.bus.write32(bank + reg::GCFER, !0);
            self.bus.write32(bank + reg::GEDR, !0);
        }
    }

    /// Detect both edges of `pin` (`on`), or neither: one store to a set or
    /// a clear register per edge, no lock. `false` for a pin the controller
    /// does not have.
    pub fn set_both_edges(&mut self, pin: u32, on: bool) -> bool {
        let (rise, fall) = if on { (reg::GSRER, reg::GSFER) } else { (reg::GCRER, reg::GCFER) };
        let (Some((r, bit)), Some((f, _))) = (locate(rise, pin), locate(fall, pin)) else {
            return false;
        };
        self.bus.write32(r, bit);
        self.bus.write32(f, bit);
        true
    }

    /// Mask (`false`) or unmask (`true`) `pin`'s interrupt: a read-modify-write
    /// of the bank's `GAPMASK`, which the CALLER serialises (the interrupt
    /// handler masks under the same lock).
    pub fn set_unmasked(&mut self, pin: u32, on: bool) -> bool {
        let Some((off, bit)) = locate(reg::GAPMASK, pin) else { return false };
        let cur = self.bus.read32(off);
        self.bus.write32(off, if on { cur | bit } else { cur & !bit });
        true
    }

    /// The handler's step for `pin`: if its edge is latched and the pin is
    /// unmasked (what raised the line), clear the edge (write one to `GEDR`,
    /// that bit only) and mask the pin, and say so. The caller samples the
    /// level and unmasks it again; an edge latched while it is masked stays
    /// for that unmask.
    pub fn take(&mut self, pin: u32) -> bool {
        let (Some((off, bit)), Some((mask, _))) = (locate(reg::GEDR, pin), locate(reg::GAPMASK, pin)) else {
            return false;
        };
        if self.bus.read32(off) & bit == 0 || self.bus.read32(mask) & bit == 0 {
            return false;
        }
        self.ack(pin);
        self.set_unmasked(pin, false)
    }

    /// Clear `pin`'s latched edge: one store of its bit to `GEDR` (write one
    /// to clear), no other pin's edge touched.
    pub fn ack(&mut self, pin: u32) -> bool {
        let Some((off, bit)) = locate(reg::GEDR, pin) else { return false };
        self.bus.write32(off, bit);
        true
    }
}

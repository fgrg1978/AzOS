// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The GPIO interrupt registers of the StarFive JH7110 sys pin controller
//! (`starfive,jh7110-sys-pinctrl`, `sysgpio: pinctrl@13040000`) over a
//! register trait.
//!
//! The pin multiplexer's `DOUT`/`DOEN`/`GPIOIN` arrays are `gpio.rs`'s; the
//! SoC pinctrl framework leaves this block to the GPIO driver
//! (`crates/drivers/soc/src/jh7110/iomux.rs`, "Not modelled"). Offsets are
//! U-Boot v2025.07 `drivers/pinctrl/starfive/pinctrl-jh7110-sys.c`
//! (`JH7110_SYS_GPIOEN` .. `JH7110_SYS_GPIOMIS1`); the meaning of each bit is
//! Linux `drivers/pinctrl/starfive/pinctrl-starfive-jh7110.c`
//! (`jh7110_irq_set_type`, `jh7110_irq_ack`, `jh7110_irq_mask`,
//! `jh7110_gpio_irq_handler`, and the sys driver's init) [verify on silicon]:
//!
//! | register | offset | per pin | use here |
//! |----------|--------|---------|----------|
//! | `GPIOEN`  | 0x0dc | —   | 1 = the block raises its interrupt at all |
//! | `GPIOIS`  | 0x0e0 | bit | 1 = edge-triggered (0 = level) |
//! | `GPIOIC`  | 0x0e8 | bit | clear the pin's latched edge: written 0 then 1 |
//! | `GPIOIBE` | 0x0f0 | bit | 1 = both edges (`GPIOIEV` ignored) |
//! | `GPIOIEV` | 0x0f8 | bit | 1 = rising / high, 0 = falling / low |
//! | `GPIOIE`  | 0x100 | bit | 1 = unmasked |
//! | `GPIOMIS` | 0x110 | bit | latched AND unmasked: what the handler reads |
//!
//! Each is two words, pins 0..31 then 32..63 (word `4 * (pin / 32)`, bit
//! `pin % 32`). Every per-pin register except `GPIOMIS` is a read-modify-write
//! of a word 31 other pins share, so the CALLER serialises them (`gpio.rs`
//! holds one lock, taken with interrupts off, around every call here; the
//! interrupt handler calls [`Jh7110Irq::take`] under it too).
//!
//! The register access is the [`Jh7110Bus`] trait, so the host suite
//! (`tests/host/drivers-tests`, `gpio_jh7110_irq_tests`) runs this file
//! against a register-level model of the part.

/// Pins of the controller.
pub const PINS: u32 = 64;

mod reg {
    pub const GPIOEN: usize = 0x0dc;
    pub const GPIOIS: usize = 0x0e0;
    pub const GPIOIC: usize = 0x0e8;
    pub const GPIOIBE: usize = 0x0f0;
    pub const GPIOIE: usize = 0x100;
    pub const GPIOMIS: usize = 0x110;
}

/// Register access to the controller's window, supplied by the board.
pub trait Jh7110Bus {
    /// Read the register at byte offset `off`.
    fn read32(&mut self, off: usize) -> u32;
    /// Write the register at byte offset `off`.
    fn write32(&mut self, off: usize, v: u32);
}

/// Word offset (from the register's first word) and bit of `pin`. `None` for
/// a pin the controller does not have.
pub const fn irq_word_and_bit(pin: u32) -> Option<(usize, u32)> {
    if pin >= PINS {
        return None;
    }
    Some((4 * (pin as usize / 32), 1 << (pin % 32)))
}

/// The interrupt half of the controller.
pub struct Jh7110Irq<B> {
    bus: B,
}

impl<B: Jh7110Bus> Jh7110Irq<B> {
    /// Wrap the bus. Nothing is written.
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    /// Before the kernel routes the block's line: every pin masked, every
    /// edge the firmware left latched cleared, the block's interrupt on.
    /// Linux's sys driver does the same three writes at probe.
    pub fn init(&mut self) {
        for w in [0, 4] {
            self.bus.write32(reg::GPIOIE + w, 0);
            self.bus.write32(reg::GPIOIC + w, !0);
        }
        self.bus.write32(reg::GPIOEN, 1);
    }

    fn rmw(&mut self, base: usize, pin: u32, set: bool) -> bool {
        let Some((w, bit)) = irq_word_and_bit(pin) else { return false };
        let cur = self.bus.read32(base + w);
        self.bus.write32(base + w, if set { cur | bit } else { cur & !bit });
        true
    }

    /// Make `pin` raise its interrupt on both edges (`IRQ_TYPE_EDGE_BOTH`:
    /// edge-triggered, both edges), still masked. `false` for a pin the
    /// controller does not have.
    pub fn set_both_edges(&mut self, pin: u32) -> bool {
        self.rmw(reg::GPIOIS, pin, true) && self.rmw(reg::GPIOIBE, pin, true)
    }

    /// Clear `pin`'s latched edge (`jh7110_irq_ack`: the bit written 0, then
    /// 1, the word's other bits as read).
    pub fn ack(&mut self, pin: u32) -> bool {
        let Some((w, bit)) = irq_word_and_bit(pin) else { return false };
        let cur = self.bus.read32(reg::GPIOIC + w) & !bit;
        self.bus.write32(reg::GPIOIC + w, cur);
        self.bus.write32(reg::GPIOIC + w, cur | bit);
        true
    }

    /// Mask (`false`) or unmask (`true`) `pin`'s interrupt.
    pub fn set_unmasked(&mut self, pin: u32, on: bool) -> bool {
        self.rmw(reg::GPIOIE, pin, on)
    }

    /// The handler's step for `pin`: if the block reports its edge (latched
    /// and unmasked), acknowledge it and mask the pin, and say so. The caller
    /// samples the level and unmasks it again ([`Self::set_unmasked`]); an
    /// edge while it is masked stays latched and is taken on the unmask.
    pub fn take(&mut self, pin: u32) -> bool {
        let Some((w, bit)) = irq_word_and_bit(pin) else { return false };
        if self.bus.read32(reg::GPIOMIS + w) & bit == 0 {
            return false;
        }
        self.ack(pin);
        self.set_unmasked(pin, false);
        true
    }
}

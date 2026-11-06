// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A soft GPIO expander (Kconfig `GPIO_SOFT_EXPANDER`, development builds):
//! a second controller for the machines that have only the board's, so the
//! class's second instance is driven end to end on every ISA under QEMU.
//!
//! It models the register file of a 16-line I2C expander of the PCA9555 kind:
//! an output latch and a configuration word (a set bit is an input, the reset
//! state); the input port reads the latch for an output and low for an input
//! (nothing outside drives the lines). One word per register, so every op is
//! one atomic step and needs no lock.

use crate::chips::{Fault, GpioChip};
use crate::gpio::GpioDir;
use core::sync::atomic::{AtomicU16, Ordering};

/// Lines of the modelled part.
pub const PINS: u32 = 16;

/// The expander's registers.
pub struct SoftExpander {
    output: AtomicU16,
    config: AtomicU16,
}

impl SoftExpander {
    /// At reset: every line an input, the latch low.
    pub const fn new() -> Self {
        SoftExpander { output: AtomicU16::new(0), config: AtomicU16::new(u16::MAX) }
    }

    fn bit(pin: u32) -> Result<u16, Fault> {
        if pin < PINS { Ok(1 << pin) } else { Err(Fault) }
    }
}

impl GpioChip for SoftExpander {
    fn pins(&self) -> u32 {
        PINS
    }

    fn read(&self, pin: u32) -> Result<u32, Fault> {
        let b = Self::bit(pin)?;
        let input = self.config.load(Ordering::Acquire) & b != 0;
        Ok((!input && self.output.load(Ordering::Acquire) & b != 0) as u32)
    }

    fn write(&self, pin: u32, level: u32) -> Result<(), Fault> {
        let b = Self::bit(pin)?;
        if self.config.load(Ordering::Acquire) & b != 0 {
            return Err(Fault);
        }
        if level & 1 != 0 {
            self.output.fetch_or(b, Ordering::AcqRel);
        } else {
            self.output.fetch_and(!b, Ordering::AcqRel);
        }
        Ok(())
    }

    fn set_dir(&self, pin: u32, dir: GpioDir) -> Result<(), Fault> {
        let b = Self::bit(pin)?;
        match dir {
            GpioDir::Input => self.config.fetch_or(b, Ordering::AcqRel),
            GpioDir::Output => self.config.fetch_and(!b, Ordering::AcqRel),
        };
        Ok(())
    }

    fn may_sleep(&self) -> bool {
        false
    }
}

/// The one expander a development kernel adds (`boot::hwbus`).
pub static EXPANDER: SoftExpander = SoftExpander::new();

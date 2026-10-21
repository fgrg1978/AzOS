// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Gpio` interface: one pin.
//!
//! The endpoint's badge is the pin (`endpoint = "gpio.20"`); `READ` reads its
//! level, `WRITE` drives it or changes its direction. A pin a motor's
//! H-bridge uses is not reachable here at all: the motor interface is the
//! gated path to it (the e-stop latch and the actuation envelope), and a write
//! to its pins answers [`outcome::REFUSED`](crate::outcome::REFUSED).
//!
//! Register-form interface (`words = 4`): a sample loop reading a pin pays one
//! call and no message descriptor.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "GPIO").
pub const GPIO_ID: u32 = 0x4750_494F;

/// Pins the interface can name (the driver's table; a board has fewer).
pub const PINS: u32 = 64;

/// A pin that reads or drives a line: direction input.
pub const DIR_INPUT: u32 = 0;
/// A pin that drives its line: direction output.
pub const DIR_OUTPUT: u32 = 1;

#[azos_interface(id = 0x4750_494F, level = 1, words = 4)]
pub trait Gpio {
    /// The pin's level, 0 or 1. `FAULT` when the driver has no reading.
    /// Needs `READ`.
    #[idempotent]
    fn read(&self) -> Out<u32>;
    /// Drive the pin: `level` 0 or 1 (the low bit is used). `REFUSED` for a
    /// pin a motor uses. Needs `WRITE`.
    fn write(&mut self, level: u32) -> Out<()>;
    /// Set the pin's direction: [`DIR_INPUT`] or [`DIR_OUTPUT`], else
    /// `BAD_ARGUMENT`. `REFUSED` for a pin a motor uses. Needs `WRITE`.
    fn set_dir(&mut self, dir: u32) -> Out<()>;
}

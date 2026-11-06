// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Gpio` interface: one pin of one controller.
//!
//! The endpoint's badge is `controller << 8 | pin` ([`badge`]):
//! `endpoint = "gpio.1.3"` is pin 3 of controller 1, and the short form
//! `"gpio.20"` is pin 20 of controller 0, the board's own. A capability names
//! its controller, so one on an expander's pin never reaches the SoC's pin of
//! the same number. Every controller serves this one interface; how many
//! the kernel keeps is Kconfig `GPIO_CONTROLLERS`, how many pins each has is
//! the controller's: a badge naming a controller that is not bound answers
//! [`outcome::NO_RESOURCE`](crate::outcome::NO_RESOURCE), a pin past the
//! controller's last [`outcome::BAD_ARGUMENT`](crate::outcome::BAD_ARGUMENT).
//! `READ` reads the level, `WRITE` drives it or changes its direction.
//!
//! A pin a motor's H-bridge uses (a pin of controller 0) is not reachable here
//! at all: the motor interface is the gated path to it (the e-stop latch and
//! the actuation envelope), and a write to its pins answers
//! [`outcome::REFUSED`](crate::outcome::REFUSED).
//!
//! Register-form interface (`words = 4`): a sample loop reading a pin pays one
//! call and no message descriptor.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "GPIO").
pub const GPIO_ID: u32 = 0x4750_494F;

/// The badge of `pin` on controller `ctrl`.
#[cfg(not(feature = "badge-without-controller-canary"))]
pub const fn badge(ctrl: u8, pin: u8) -> u32 {
    ((ctrl as u32) << 8) | pin as u32
}

/// Canary: the badge is stamped without the controller, so every capability
/// names controller 0.
#[cfg(feature = "badge-without-controller-canary")]
pub const fn badge(_ctrl: u8, pin: u8) -> u32 {
    pin as u32
}

/// The controller and the pin a badge names.
pub const fn unbadge(badge: u32) -> (u8, u8) {
    ((badge >> 8) as u8, badge as u8)
}

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

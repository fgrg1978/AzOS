// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CONFIG.INI's `estop_gpio_pin` on an image with no kill switch (Kconfig
//! `BOARD_IO` off, so `crates/drivers/kill-switch` is not built): the pin is
//! read by nobody. Said out loud and recorded, as the kill switch itself does
//! for a pin it cannot arm, so an operator who configured a switch does not
//! get a machine without one in silence.

use crate::logger;

/// The `estop_gpio_pin` value that names no switch.
pub const NO_PIN: u32 = 255;
/// `action` of the `SAFETY_ESTOP_PIN_INVALID` record when the image has no
/// kill switch to arm the pin with (the kill switch writes 0 for a pin out of
/// range).
pub const PIN_NO_KILL_SWITCH: u8 = 1;

/// Report a configured `pin` that this image cannot arm. `true` when it was
/// configured, and so reported and recorded.
pub fn report_without_kill_switch(pin: u32) -> bool {
    if pin == NO_PIN {
        return false;
    }
    azos_drv_sys::kwarn!(
        "[SAFETY] e-stop pin configured but NOT armed: no kill switch in this image (estop_gpio_pin={}, Kconfig BOARD_IO off)",
        pin);
    logger::log_safety_violation(logger::SAFETY_ESTOP_PIN_INVALID, PIN_NO_KILL_SWITCH, pin);
    true
}

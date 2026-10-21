// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot-time report of the physical kill-switch configuration.

use core::sync::atomic::Ordering;
use azos_drv_sys::kprintln;

/// Called by the kernel right after CONFIG.INI is loaded.
pub fn report_config() {
    // **Say out loud whether the physical kill switch is armed.**
    //
    // The poll is `if estop_pin < 64 && gpio_read(pin) == 0`, so an
    // `estop_gpio_pin` that is malformed or out of range is skipped in
    // exactly the same silence as one that was never configured. The
    // operator who typed `estop_gpio_pin=GPIO5` gets a robot with no
    // kill switch and no indication of it.
    //
    // 255 is the deliberate "no switch" sentinel and stays quiet-ish;
    // anything else out of range is a configuration the operator meant
    // to work, and is recorded as a safety event rather than only
    // printed, because a boot log scrolls past and the recorder does
    // not.
    let p = azos_config::CFG_ESTOP_GPIO_PIN.load(Ordering::Relaxed);
    if p < 64 {
        kprintln!("[SAFETY] kill switch armed on GPIO {}", p);
    } else if p == 255 {
        azos_drv_sys::kwarn!("[SAFETY] kill switch NOT armed — no estop_gpio_pin configured");
    } else {
        azos_drv_sys::kwarn!("[SAFETY] kill switch NOT armed — estop_gpio_pin={} is out of range (0-63)", p);
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_ESTOP_PIN_INVALID,
            0, p);
    }
}

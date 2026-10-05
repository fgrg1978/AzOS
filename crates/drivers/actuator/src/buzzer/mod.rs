// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Piezo buzzer: the kernel API, in either placement (RFC-0052 section 6.1,
//! wave 12 DRVPLACE).
//!
//! One chip-logic source, `crates/drivers/buzzer`, and two hosts chosen per
//! board by Kconfig `DRV_BUZZER_PLACEMENT`:
//!
//! * `ring3` (default; RFC-0040 rule 3): [`proxy`] — every call is a
//!   `UserDriverProxy` request to `userspace/drivers/buzz_drv`
//!   (`BUZZDRV.ELF`), started from its topology row.
//! * `kernel` (cargo feature `buzzer-kernel`): [`kernel_host`] — every call
//!   runs `azos_buzzer::serve` in the caller's context against the
//!   kernel's PWM driver; a kernel task advances the timed steps.
//!
//! The API below is identical in both, and both play through the same
//! `azos_buzzer::Player`, so a tone sets the same PWM channel state
//! either way. Not read by any safety decision, which is what allows the
//! ring-3 placement.

/// C4 (middle C), Hz.
pub const TONE_C4: u16 = azos_buzzer::TONE_C4;
/// A4 (concert pitch), Hz.
pub const TONE_A4: u16 = 440;
/// Acknowledgment tone, Hz.
pub const TONE_OK: u16 = azos_buzzer::TONE_OK;
/// Alert tone, Hz.
pub const TONE_ALERT: u16 = azos_buzzer::TONE_ALERT;

/// This kernel was built with the in-kernel host (`DRV_BUZZER_PLACEMENT =
/// kernel`). The kernel asserts it against the topology's ring-3 row, so a
/// build that places the driver in the kernel and still declares
/// `BUZZDRV.ELF` does not link.
pub const IN_KERNEL: bool = cfg!(feature = "buzzer-kernel");

/// Where the buzzer runs in this build, for the log and the gate rows.
pub const PLACEMENT: &str = if IN_KERNEL { "kernel" } else { "ring-3" };

#[cfg(not(feature = "buzzer-kernel"))]
pub mod proxy;
#[cfg(not(feature = "buzzer-kernel"))]
pub use proxy::{
    buzzer_alert, buzzer_beep, buzzer_driver_tid, buzzer_off, buzzer_on, buzzer_startup,
    buzzer_tone,
};

#[cfg(feature = "buzzer-kernel")]
pub mod kernel_host;
#[cfg(feature = "buzzer-kernel")]
pub use kernel_host::{
    buzzer_alert, buzzer_beep, buzzer_driver_tid, buzzer_off, buzzer_on, buzzer_startup,
    buzzer_tone,
};
/// The PWM channel the in-kernel host drives (for the kernel's smokes).
#[cfg(feature = "buzzer-kernel")]
pub use azos_buzzer::BUZZER_PWM_CHANNEL;

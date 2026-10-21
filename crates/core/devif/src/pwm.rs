// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Pwm` interface: one channel.
//!
//! The endpoint's badge is the channel (`endpoint = "pwm.4"`); every op acts,
//! so every op needs `WRITE`. A channel a motor drives is not reachable here
//! (its duty arrives below the actuation gate), nor is a control write whose
//! reach crosses into one (on a part whose channels share one control
//! register, enabling channel 2 changes the timing of the wheels): both answer
//! [`outcome::REFUSED`](crate::outcome::REFUSED).
//!
//! Register-form interface (`words = 4`).

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "PWM ").
pub const PWM_ID: u32 = 0x5057_4D20;

/// Channels the interface can name (the ABI maximum; a board has the
/// channels of its PWM domain, and the server refuses the others).
pub const CHANNELS: u32 = 8;

#[azos_interface(id = 0x5057_4D20, level = 1, words = 4)]
pub trait Pwm {
    /// Start the channel's output. Needs `WRITE`.
    fn enable(&mut self) -> Out<()>;
    /// Stop the channel's output. Needs `WRITE`.
    fn disable(&mut self) -> Out<()>;
    /// Set the period, nanoseconds. Needs `WRITE`.
    fn set_period(&mut self, ns: u32) -> Out<()>;
    /// Set the duty, nanoseconds of the period. Needs `WRITE`.
    fn set_duty(&mut self, ns: u32) -> Out<()>;
    /// Set the duty as a percentage of the period (clamped to 100). Needs
    /// `WRITE`.
    fn set_duty_pct(&mut self, pct: u32) -> Out<()>;
}

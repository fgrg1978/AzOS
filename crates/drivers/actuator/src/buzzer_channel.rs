// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Who holds the buzzer's PWM channel, the kernel host or the ring-3 one.
//!
//! Both hosts drive the one channel, and the ring-3 host is kept up (idle)
//! while the driver is placed in the kernel, so the channel has one holder at
//! a time. The other is kept off it HERE, where the ring-3 host's `Pwm` calls
//! land ([`ring3_channel_write`]): a standby host that starts, or the timed
//! step of a sound it was playing before a move, can neither cut nor change
//! what the holder plays. The lock makes the check and the write one step, so a
//! move ([`set_ring3_holds_channel`]) waits for a write under way and nothing of
//! the old holder lands after it returns. The kernel host writes the channel
//! directly and is not gated.

use azos_sync::SpinLock;

/// The PWM channel the buzzer is wired to.
pub use azos_buzzer::BUZZER_PWM_CHANNEL as CHANNEL;

/// Does the ring-3 host hold the channel?
static RING3_HOLDS_CHANNEL: SpinLock<bool> = SpinLock::new(false);

/// Hand the channel to the ring-3 host (`true`) or take it back (`false`).
/// Returns once no write of the ring-3 host is in progress.
pub fn set_ring3_holds_channel(on: bool) {
    *RING3_HOLDS_CHANNEL.lock() = on;
}

/// Run `write`, a write to the buzzer's channel made on the ring-3 host's
/// behalf, if the ring-3 host holds the channel. `None`: it does not, and
/// nothing was written.
pub fn ring3_channel_write<R>(write: impl FnOnce() -> R) -> Option<R> {
    let held = RING3_HOLDS_CHANNEL.lock();
    if *held { Some(write()) } else { None }
}


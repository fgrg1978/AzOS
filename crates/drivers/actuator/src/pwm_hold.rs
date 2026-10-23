// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Channels the kernel's stop holds: the bookkeeping of the `pwm` backends
//! whose duty write is one store (the simulation, the VF2 module; the K1
//! module keeps it in `pwm_k1::ChanState`, beside its cached configuration).
//!
//! The kernel's stop (`pwm_set_duty_pct_panic`: the panic handler and the
//! motor layer's safe-state drive) writes the duty without any lock, so a
//! writer that was already past its checks would write its own duty AFTER the
//! stop and re-drive the actuator. So the stop HOLDS the channel at its duty:
//! a command that would change it is refused until [`ChanHold::release`] (the
//! operator's signed release of the device), and one at the held duty passes.
//!
//! The window is closed as on the GPIO side (`azos_drv_gpio::hold`): the stop
//! publishes the hold, fences, then writes; a writer checks, writes, fences,
//! and checks again, writing the held duty back when the hold came in between.

use core::sync::atomic::{fence, AtomicU32, Ordering};

use crate::pwm::PWM_MAX_CHANNELS;

/// A channel that is not held.
const FREE: u32 = u32::MAX;

/// The duty percentage each channel is held at, or [`FREE`].
pub struct ChanHold {
    pct: [AtomicU32; PWM_MAX_CHANNELS],
}

impl ChanHold {
    pub const fn new() -> ChanHold {
        ChanHold { pct: [const { AtomicU32::new(FREE) }; PWM_MAX_CHANNELS] }
    }

    /// Hold `ch` at `pct` % (clamped to 100), then the fence. The caller
    /// writes the duty after this returns. `ch` is in range.
    pub fn hold(&self, ch: u32, pct: u32) {
        self.pct[ch as usize].store(pct.min(100), Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }

    /// Lift the hold of `ch`. The duty stays until a new command.
    pub fn release(&self, ch: u32) {
        if let Some(c) = self.pct.get(ch as usize) {
            c.store(FREE, Ordering::SeqCst);
        }
    }

    /// The duty percentage `ch` is held at, `None` when it is not held.
    pub fn held(&self, ch: u32) -> Option<u32> {
        match self.pct.get(ch as usize)?.load(Ordering::SeqCst) {
            FREE => None,
            p => Some(p),
        }
    }

    /// Would a duty of `pct` % change the held `ch`?
    pub fn refuses(&self, ch: u32, pct: u32) -> bool {
        matches!(self.held(ch), Some(h) if h != pct.min(100))
    }

    /// After a duty write to `ch`: the fence, then the held duty, if a stop
    /// held the channel in the meantime. The caller writes it back.
    pub fn held_after(&self, ch: u32) -> Option<u32> {
        fence(Ordering::SeqCst);
        self.held(ch)
    }
}

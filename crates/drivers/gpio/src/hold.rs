// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pins the kernel's stop holds: the bookkeeping every GPIO backend shares.
//!
//! The kernel's stop (`gpio_write_panic`: the panic handler and the motor
//! layer's safe-state drive) writes a pin without any lock, so it cannot wait
//! on a stalled writer. A writer that was already past its checks when the
//! stop landed would then write its own command AFTER it and re-drive the
//! actuator. So the stop does not just write the pin: it HOLDS it at the
//! stop's level, and from then on a command that would change the pin is
//! refused until [`PinHold::release`] (the operator's signed release of the
//! device, `azos_actuation::safe_state::release`). A write of the held level
//! is not a change and passes, so stops still go through.
//!
//! # The window
//!
//! A writer checks the hold, writes, and checks again ([`PinHold::after_write`]);
//! the stop publishes the hold, then writes ([`PinHold::hold`]). Both sides put
//! a sequentially consistent fence between their two steps, so whichever way
//! they interleave either the writer sees the hold before its write (and is
//! refused), or the stop's write lands after the writer's, or the writer's
//! second check sees the hold and re-asserts the held level itself. The pin
//! ends at the stop's level in every order.

use core::sync::atomic::{fence, AtomicU64, Ordering};

use crate::gpio::GPIO_MAX_PINS;

// One bit per pin.
const _: () = assert!(GPIO_MAX_PINS <= 64, "the hold masks are one u64 per controller");

/// Held pins and their levels, one bit each.
pub struct PinHold {
    held: AtomicU64,
    level: AtomicU64,
}

impl PinHold {
    pub const fn new() -> PinHold {
        PinHold { held: AtomicU64::new(0), level: AtomicU64::new(0) }
    }

    /// Hold `pin` at `val` (low bit): the level first, then the hold, then the
    /// fence. The caller writes the pin after this returns.
    pub fn hold(&self, pin: u32, val: u32) {
        let bit = 1u64 << pin;
        if val & 1 != 0 {
            self.level.fetch_or(bit, Ordering::SeqCst);
        } else {
            self.level.fetch_and(!bit, Ordering::SeqCst);
        }
        self.held.fetch_or(bit, Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }

    /// Lift the hold of `pin`. The pin keeps its level until a new command.
    pub fn release(&self, pin: u32) {
        self.held.fetch_and(!(1u64 << pin), Ordering::SeqCst);
    }

    /// The level `pin` is held at, `None` when it is not held.
    pub fn held(&self, pin: u32) -> Option<u32> {
        let bit = 1u64 << pin;
        if self.held.load(Ordering::SeqCst) & bit == 0 {
            return None;
        }
        Some((self.level.load(Ordering::SeqCst) & bit != 0) as u32)
    }

    /// Would a write of `val` change a held `pin`?
    pub fn refuses(&self, pin: u32, val: u32) -> bool {
        matches!(self.held(pin), Some(h) if h != val & 1)
    }

    /// After a change of `pin` (a level, a direction): the fence, then the
    /// level it is held at, if a stop held it in the meantime. The caller
    /// undoes its change when it is `Some`.
    pub fn held_after(&self, pin: u32) -> Option<u32> {
        fence(Ordering::SeqCst);
        self.held(pin)
    }

    /// After a write of `val` to `pin` ([`Self::held_after`]): a held level is
    /// written again with `put`. `true` when the write stands (no hold, or one
    /// at the level written).
    pub fn after_write(&self, pin: u32, val: u32, put: impl FnOnce(u32, u32)) -> bool {
        match self.held_after(pin) {
            Some(h) => {
                put(pin, h);
                h == val & 1
            }
            None => true,
        }
    }

    /// After a read-modify-write of a word several pins share: the fence, then
    /// every held pin written again with `put`, lowest first.
    pub fn reassert_all(&self, mut put: impl FnMut(u32, u32)) {
        fence(Ordering::SeqCst);
        let mut pend = self.held.load(Ordering::SeqCst);
        let level = self.level.load(Ordering::SeqCst);
        while pend != 0 {
            let pin = pend.trailing_zeros();
            pend &= pend - 1;
            put(pin, ((level >> pin) & 1) as u32);
        }
    }
}

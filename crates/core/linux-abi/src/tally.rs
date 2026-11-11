// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A count per Linux call number, for the calls the personality does not
//! answer (`-ENOSYS`) or whose translation a seccomp profile refused: what a
//! real binary asks for that the table lacks. No lock, no allocation; the
//! caller owns the static.

use core::sync::atomic::{AtomicU32, Ordering};

/// Numbers counted one by one. Linux's asm-generic table ends below this; a
/// larger number (a task probing) shares the last slot.
pub const NUMBERS: usize = 512;

/// One count per number, saturating.
pub struct Tally {
    slots: [AtomicU32; NUMBERS],
}

impl Tally {
    pub const fn new() -> Self {
        Self { slots: [const { AtomicU32::new(0) }; NUMBERS] }
    }

    fn slot(&self, num: u64) -> &AtomicU32 {
        &self.slots[(num as usize).min(NUMBERS - 1)]
    }

    /// Count one call of `num`; the count now, this one included.
    ///
    /// Canary `tally-unrecorded-canary`: nothing is counted.
    pub fn record(&self, num: u64) -> u32 {
        if cfg!(feature = "tally-unrecorded-canary") {
            return 0;
        }
        let s = self.slot(num);
        match s.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1)) {
            Ok(prev) => prev + 1,
            Err(now) => now,
        }
    }

    /// Calls of `num` counted so far.
    pub fn count(&self, num: u64) -> u32 {
        self.slot(num).load(Ordering::Relaxed)
    }

    /// Every number with a nonzero count, with its count, in number order.
    pub fn for_each(&self, mut f: impl FnMut(u64, u32)) {
        for (n, s) in self.slots.iter().enumerate() {
            let c = s.load(Ordering::Relaxed);
            if c != 0 {
                f(n as u64, c);
            }
        }
    }
}

impl Default for Tally {
    fn default() -> Self {
        Self::new()
    }
}

/// Is the `count`th call of a number one to put on the console? The first,
/// then each doubling: a loop over an unanswered call costs a line per power
/// of two, not a line per call.
pub const fn worth_a_line(count: u32) -> bool {
    count.is_power_of_two()
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! When `logd` gives up on a record a producer claimed and never finished.
//! The reader hands out nothing while a ring has one at its cursor, so every
//! other ring waits for it: the kernel log keeps being written meanwhile and
//! could lap the reader. A producer the ring has moved half a lap past is
//! gone (a finished one has had that many claims' time to store), so the
//! reader does not wait for it a poll longer; nor when another ring is more than
//! half a lap behind the reader (a quiet ring's stalled record while a busy ring
//! is about to lap it). Otherwise it waits
//! [`STUCK_POLLS`] polls. Pure: the host tests run this file as it ships
//! (`tests/host/libsys-tests`).

/// Polls a record can stay unfinished before the sink gives up on it.
pub const STUCK_POLLS: u32 = 5;

/// The record the reader is stuck on, and for how many polls.
pub struct Stall {
    ring: usize,
    cursor: u64,
    polls: u32,
}

impl Stall {
    pub const fn new() -> Stall {
        Stall { ring: 0, cursor: 0, polls: 0 }
    }

    /// A record was handed out: nothing is stuck.
    pub fn clear(&mut self) {
        *self = Stall::new();
    }

    /// Ring `ring` has an unfinished record at `cursor`, its head `ahead`
    /// records past it, in a ring of `entries`; `other_late` says another ring
    /// is more than half a lap past the reader. True: give up on it.
    pub fn give_up(&mut self, ring: usize, cursor: u64, ahead: u64, entries: u64, other_late: bool) -> bool {
        self.polls = if (self.ring, self.cursor) == (ring, cursor) { self.polls + 1 } else { 1 };
        (self.ring, self.cursor) = (ring, cursor);
        // Canary: only the polls count.
        #[cfg(feature = "canary-logd-stall-polls-only")]
        let far = false;
        #[cfg(not(feature = "canary-logd-stall-polls-only"))]
        let far = ahead > entries / 2 || other_late;
        let gone = self.polls >= STUCK_POLLS || far;
        if gone {
            self.clear();
        }
        gone
    }
}

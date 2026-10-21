// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The best master clock algorithm for a slave-only ordinary clock
//! (IEEE 1588-2019 §9.3): the foreign master table and the dataset comparison.
//!
//! This node never offers itself as a master (its class is 255, it sends no
//! Announce), so the state decision reduces to choosing the best foreign
//! master that qualifies and following it, or following none.
//!
//! * **Qualification** (§9.3.2.5): a foreign master counts once
//!   [`FOREIGN_MASTER_THRESHOLD`] of its Announces arrived within
//!   [`FOREIGN_MASTER_WINDOW`] announce intervals; one stray Announce selects
//!   nothing.
//! * **Expiry** (§9.2.6.12): a master silent for [`RECEIPT_TIMEOUT`] announce
//!   intervals is gone; its entry is dropped and the next best is chosen.
//! * **Comparison** (§9.3.4, Part 1 of the dataset comparison): two different
//!   grandmasters are ordered by priority1, clock class, clock accuracy, offset
//!   scaled log variance, priority2 and identity, the smaller being better.
//!   One grandmaster announced through two paths is ordered by steps removed,
//!   then by the sender's port identity. The standard's finer rule for a
//!   path one step longer (it compares the receiving and sending ports to
//!   break a loop through this node's own ports) has no case here: an ordinary
//!   clock has one port and forwards nothing.

use crate::wire::{flag, Announce, PortId};
use core::cmp::Ordering;

/// Foreign masters remembered at once. A node with more distinct sources than
/// this follows the best of the first ones it heard.
pub const MAX_FOREIGN: usize = 4;
/// Announces within the window that qualify a foreign master.
pub const FOREIGN_MASTER_THRESHOLD: u8 = 2;
/// The qualification window, in announce intervals.
pub const FOREIGN_MASTER_WINDOW: u64 = 4;
/// Announce intervals of silence after which a master is dropped.
pub const RECEIPT_TIMEOUT: u64 = 3;
/// The interval assumed when a message does not state one (1 s; the default
/// 1588 profile's Announce is 2 s but states it).
pub const DEFAULT_INTERVAL_NS: u64 = 1_000_000_000;

/// The grandmaster a foreign master announces: what the comparison reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dataset {
    pub priority1: u8,
    pub class: u8,
    pub accuracy: u8,
    pub variance: u16,
    pub priority2: u8,
    pub identity: [u8; 8],
    pub steps_removed: u16,
}

impl Dataset {
    pub fn of(a: &Announce) -> Dataset {
        Dataset {
            priority1: a.priority1,
            class: a.class,
            accuracy: a.accuracy,
            variance: a.variance,
            priority2: a.priority2,
            identity: a.identity,
            steps_removed: a.steps_removed,
        }
    }
}

/// `Less` when `a` (announced by `a_sender`) is the better master.
pub fn compare(a: &Dataset, a_sender: PortId, b: &Dataset, b_sender: PortId) -> Ordering {
    if a.identity != b.identity {
        return (a.priority1, a.class, a.accuracy, a.variance, a.priority2, a.identity)
            .cmp(&(b.priority1, b.class, b.accuracy, b.variance, b.priority2, b.identity));
    }
    (a.steps_removed, a_sender).cmp(&(b.steps_removed, b_sender))
}

/// A foreign master: one port that sends Announce.
#[derive(Clone, Copy, Debug)]
pub struct Foreign {
    pub sender: PortId,
    pub data: Dataset,
    /// The Announce's `flagField` and `currentUtcOffset`: the time scale the
    /// master's timestamps are on.
    pub flags: u16,
    pub utc_offset: i16,
    /// The master's announce interval, ns.
    pub interval_ns: u64,
    window_start: u64,
    count: u8,
    qualified: bool,
    last: u64,
}

impl Foreign {
    /// Does this master's time run on the PTP (TAI) scale with a valid UTC
    /// offset: what it takes to steer a UTC wall clock from it?
    pub fn utc_known(&self) -> bool {
        self.flags & (flag::PTP_TIMESCALE | flag::UTC_OFFSET_VALID) == flag::PTP_TIMESCALE | flag::UTC_OFFSET_VALID
    }

    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.last) > RECEIPT_TIMEOUT * self.interval_ns
    }
}

/// The foreign master table.
#[derive(Clone, Copy, Debug)]
pub struct Table {
    slots: [Option<Foreign>; MAX_FOREIGN],
}

impl Table {
    pub const fn new() -> Table {
        Table { slots: [None; MAX_FOREIGN] }
    }

    /// Record an Announce received at monotonic time `now` (ns) from `sender`
    /// whose header stated `interval_ns`.
    pub fn announce(&mut self, sender: PortId, flags: u16, a: &Announce, interval_ns: u64, now: u64) {
        self.purge(now);
        let data = Dataset::of(a);
        let at = match self.slots.iter().position(|s| s.is_some_and(|f| f.sender == sender)) {
            Some(i) => i,
            None => match self.slots.iter().position(|s| s.is_none()) {
                Some(i) => {
                    self.slots[i] = Some(Foreign {
                        sender,
                        data,
                        flags,
                        utc_offset: a.utc_offset,
                        interval_ns,
                        window_start: now,
                        count: 0,
                        qualified: false,
                        last: now,
                    });
                    i
                }
                // Full of live masters: this one is not remembered.
                None => return,
            },
        };
        let f = self.slots[at].as_mut().unwrap();
        f.data = data;
        f.flags = flags;
        f.utc_offset = a.utc_offset;
        f.interval_ns = interval_ns;
        f.last = now;
        if now.saturating_sub(f.window_start) > FOREIGN_MASTER_WINDOW * interval_ns {
            f.window_start = now;
            f.count = 0;
        }
        f.count = f.count.saturating_add(1);
        if f.count >= FOREIGN_MASTER_THRESHOLD {
            f.qualified = true;
        }
    }

    /// Drop the masters that went silent.
    pub fn purge(&mut self, now: u64) {
        for s in self.slots.iter_mut() {
            if s.is_some_and(|f| f.expired(now)) {
                *s = None;
            }
        }
    }

    /// The best qualified master at `now`, if any.
    pub fn best(&mut self, now: u64) -> Option<Foreign> {
        self.purge(now);
        let mut best: Option<Foreign> = None;
        for f in self.slots.iter().flatten().filter(|f| f.qualified) {
            if best.is_none_or(|b| compare(&f.data, f.sender, &b.data, b.sender) == Ordering::Less) {
                best = Some(*f);
            }
        }
        best
    }
}

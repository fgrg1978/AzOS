// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! How many times a physical port may fail to bring a device up before it is
//! left alone for a while. Enumeration runs inside the host's service turn, so
//! a device or hub that never answers (or one that toggles its connection to
//! start the next attempt) must cost a bounded number of attempts, not every
//! turn.
//!
//! A port is named by its root port and the route string of the device below
//! it, which is the same whatever slot the device is given. Each failure
//! delays the next attempt ([`BACKOFF_US`], doubled per failure); the
//! [`BUDGET`]th failure in a row ignores the port for [`BAN_US`], after which
//! it gets a new budget. A device that comes up clears its port's entry.

pub(crate) const BUDGET: u8 = 3;
/// The wait after the first failure; each further failure doubles it.
pub(crate) const BACKOFF_US: u64 = 1_000_000;
/// How long a port that used its budget is ignored.
pub(crate) const BAN_US: u64 = 30_000_000;
const ENTRIES: usize = 16;

#[derive(Clone, Copy)]
struct Entry {
    key: u64,
    failures: u8,
    until_us: u64,
    used: bool,
}

/// What a failure did to its port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failed {
    Retry,
    Ignored,
}

pub(crate) struct PortBudget {
    entries: [Entry; ENTRIES],
    next: usize,
}

pub(crate) const fn key(root_port: u8, route: u32) -> u64 {
    (root_port as u64) << 32 | route as u64
}

impl PortBudget {
    pub(crate) const fn new() -> Self {
        Self { entries: [Entry { key: 0, failures: 0, until_us: 0, used: false }; ENTRIES], next: 0 }
    }

    fn find(&mut self, key: u64) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.used && e.key == key)
    }

    /// May the port be tried now?
    pub(crate) fn allowed(&mut self, key: u64, now_us: u64) -> bool {
        if cfg!(feature = "canary-port-no-budget") {
            return true;
        }
        let Some(e) = self.find(key) else { return true };
        if now_us < e.until_us {
            return false;
        }
        if e.failures >= BUDGET {
            e.failures = 0;
        }
        true
    }

    pub(crate) fn failed(&mut self, key: u64, now_us: u64) -> Failed {
        let at = match self.entries.iter().position(|e| e.used && e.key == key) {
            Some(i) => i,
            None => {
                let i = self.entries.iter().position(|e| !e.used).unwrap_or_else(|| {
                    let i = self.next;
                    self.next = (self.next + 1) % ENTRIES;
                    i
                });
                self.entries[i] = Entry { key, failures: 0, until_us: 0, used: true };
                i
            }
        };
        let e = &mut self.entries[at];
        e.failures = e.failures.saturating_add(1);
        if e.failures >= BUDGET {
            e.until_us = now_us.saturating_add(BAN_US);
            Failed::Ignored
        } else {
            e.until_us = now_us.saturating_add(BACKOFF_US << (e.failures - 1));
            Failed::Retry
        }
    }

    pub(crate) fn succeeded(&mut self, key: u64) {
        if let Some(e) = self.find(key) {
            e.used = false;
        }
    }
}

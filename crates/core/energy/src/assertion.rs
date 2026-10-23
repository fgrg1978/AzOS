// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! System power assertions: a task's claim that the machine must not enter
//! system suspend while it works (macOS `IOPMAssertion`, Android's partial
//! wake lock, Windows' `PowerSetRequest(PowerRequestSystemRequired)`).
//!
//! The device wakelock of runtime PM (`azos_devif::power::runtime`, Kconfig
//! `DEVICE_WAKELOCKS`) keeps one device up; an assertion is the same warrant
//! for the whole machine: it names its **owner** (the task that took it, as
//! the kernel saw the call), a **reason** (the holder's
//! `POWER_ASSERT_REASON_*`, recorded, never interpreted) and a **timeout**.
//! The ledger is bounded by a quota (live assertions per owner, the longest
//! timeout it grants) and by its capacity ([`MAX_ASSERTIONS`] in all), so one
//! task cannot keep the machine awake for ever. An assertion whose owner died
//! or forgot lapses at its timeout: the ledger drops it and hands it to the
//! caller ([`Ledger::reap`]), which records it.
//!
//! No clock, no lock, no allocation: the kernel passes the time
//! (milliseconds, any monotonic clock) and keeps the ledger under its own
//! lock (`azos_sched::energy`); the suspend sequence refuses while
//! [`Ledger::live`] is not zero (`azos_drv_power::pm::suspend::Reason::Asserted`).

/// Assertions the ledger holds at once, every owner together.
pub const MAX_ASSERTIONS: usize = 16;

/// What the ledger grants: the quota of its warrants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// Live assertions one owner may hold (1..=[`MAX_ASSERTIONS`]).
    pub per_owner: u8,
    /// Longest timeout an assertion is granted for, milliseconds.
    pub max_ttl_ms: u32,
}

impl Quota {
    /// `per_owner` is clamped to `1..=MAX_ASSERTIONS`, `max_ttl_ms` to at
    /// least 1.
    pub const fn new(per_owner: u32, max_ttl_ms: u32) -> Quota {
        let n = if per_owner == 0 {
            1
        } else if per_owner > MAX_ASSERTIONS as u32 {
            MAX_ASSERTIONS as u32
        } else {
            per_owner
        };
        Quota { per_owner: n as u8, max_ttl_ms: if max_ttl_ms == 0 { 1 } else { max_ttl_ms } }
    }
}

/// One live assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assertion {
    /// Its id (non-zero), the handle its owner releases it by.
    pub id: u32,
    /// The task that took it.
    pub owner: u32,
    /// The owner's reason code.
    pub reason: u32,
    /// The timeout it was granted for, milliseconds.
    pub ttl_ms: u32,
    /// When it lapses, on the caller's clock (milliseconds).
    pub expiry_ms: u64,
}

const EMPTY: Assertion = Assertion { id: 0, owner: 0, reason: 0, ttl_ms: 0, expiry_ms: 0 };

/// Why an op was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertError {
    /// A reason of 0 (none named).
    Reason,
    /// A timeout of 0, or past the quota's longest.
    Ttl,
    /// The owner holds its quota of live assertions already.
    Quota,
    /// The ledger is full (every owner together).
    Full,
    /// No live assertion of this owner has that id (never granted, released,
    /// lapsed, or another owner's).
    NoAssertion,
}

/// Counters, never reset.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Counters {
    /// Assertions granted.
    pub granted: u32,
    /// Released by their owner.
    pub released: u32,
    /// Released by the ledger at their timeout.
    pub expired: u32,
    /// Refused (reason, timeout, quota, full).
    pub refused: u32,
}

/// The ledger.
pub struct Ledger {
    quota: Quota,
    slots: [Assertion; MAX_ASSERTIONS],
    next_id: u32,
    /// What it has done.
    pub counters: Counters,
}

impl Ledger {
    /// An empty ledger with `quota`.
    pub const fn new(quota: Quota) -> Ledger {
        Ledger {
            quota,
            slots: [EMPTY; MAX_ASSERTIONS],
            next_id: 1,
            counters: Counters { granted: 0, released: 0, expired: 0, refused: 0 },
        }
    }

    /// Drop every assertion whose timeout has passed at `now_ms`, handing
    /// each to `lapsed` (oldest slot first) before it is forgotten.
    pub fn reap(&mut self, now_ms: u64, mut lapsed: impl FnMut(&Assertion)) {
        for slot in self.slots.iter_mut() {
            if slot.id != 0 && slot.expiry_ms <= now_ms {
                lapsed(slot);
                *slot = EMPTY;
                self.counters.expired = self.counters.expired.wrapping_add(1);
            }
        }
    }

    /// Live assertions at `now_ms` (the lapsed ones not counted: they are
    /// dropped by the next [`Ledger::reap`]).
    pub fn live(&self, now_ms: u64) -> u32 {
        self.slots.iter().filter(|a| a.id != 0 && a.expiry_ms > now_ms).count() as u32
    }

    /// Live assertions of `owner` at `now_ms`.
    pub fn held_by(&self, owner: u32, now_ms: u64) -> u32 {
        self.slots.iter().filter(|a| a.id != 0 && a.owner == owner && a.expiry_ms > now_ms).count() as u32
    }

    /// Grant `owner` an assertion for `reason` lasting `ttl_ms` from `now_ms`:
    /// its id. Call [`Ledger::reap`] first, so a lapsed one does not hold a
    /// slot or count against the quota.
    pub fn hold(&mut self, owner: u32, reason: u32, ttl_ms: u32, now_ms: u64) -> Result<u32, AssertError> {
        let refused = |l: &mut Ledger, e| {
            l.counters.refused = l.counters.refused.wrapping_add(1);
            Err(e)
        };
        if reason == 0 {
            return refused(self, AssertError::Reason);
        }
        if ttl_ms == 0 || ttl_ms > self.quota.max_ttl_ms {
            return refused(self, AssertError::Ttl);
        }
        if self.held_by(owner, now_ms) >= self.quota.per_owner as u32 {
            return refused(self, AssertError::Quota);
        }
        let Some(slot) = self.slots.iter().position(|a| a.id == 0) else {
            return refused(self, AssertError::Full);
        };
        let id = loop {
            let id = self.next_id;
            self.next_id = if id == u32::MAX { 1 } else { id + 1 };
            if !self.slots.iter().any(|a| a.id == id) {
                break id;
            }
        };
        self.slots[slot] = Assertion { id, owner, reason, ttl_ms, expiry_ms: now_ms.saturating_add(ttl_ms as u64) };
        self.counters.granted = self.counters.granted.wrapping_add(1);
        Ok(id)
    }

    /// `owner` gives assertion `id` back. Only its owner may: an id is not a
    /// capability another task can spend.
    pub fn release(&mut self, owner: u32, id: u32) -> Result<Assertion, AssertError> {
        let Some(slot) = self.slots.iter_mut().find(|a| a.id != 0 && a.id == id && a.owner == owner) else {
            return Err(AssertError::NoAssertion);
        };
        let a = *slot;
        *slot = EMPTY;
        self.counters.released = self.counters.released.wrapping_add(1);
        Ok(a)
    }
}

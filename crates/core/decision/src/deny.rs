// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The rate limit on durable [`Verdict::Deny`](crate::Verdict) records
//! (Kconfig `DECISION_DENY_DURABLE_PER_SEC`, `DECISION_DENY_DURABLE_BURST`).
//!
//! A refusal is rare and unlimited; a capability denial can arrive once per
//! syscall from a ring-3 loop. Each subject gets a token bucket: `burst`
//! deep, refilled at `per_sec` tokens a second, one token per durable
//! record. The table is small and fixed ([`SLOTS`] buckets); a subject that
//! finds it full of buckets still draining shares ONE overflow bucket with
//! the other such subjects, so the total written stays bounded however many
//! tasks deny. A bucket that has refilled to full is the same as a free
//! slot and is reclaimed, so only live, still-draining subjects hold one.
//!
//! The key is whatever the call site passes: the subject's Domain key where
//! it can reach it (`record_keyed`), its TID otherwise. [`Limiter::admit`] is the pure decision (the host tests drive it
//! with a clock of their own); [`crate`] keeps one behind a spin flag.
//!
//! Time is in the clock's ticks, `hz` of them a second.

/// Buckets before the shared overflow bucket.
pub(crate) const SLOTS: usize = 16;

const MICRO: u64 = 1_000_000;

#[derive(Clone, Copy)]
struct Bucket {
    used:   bool,
    key:    u32,
    /// Millionths of a token.
    tokens: u64,
    last:   u64,
}

const FREE: Bucket = Bucket { used: false, key: 0, tokens: 0, last: 0 };

/// Tokens (millionths) `b` holds at `now`, capped at the burst.
fn refilled(b: &Bucket, now: u64, per_sec: u64, burst: u64, hz: u64) -> u64 {
    let cap = burst * MICRO;
    // A gap past 1000 s fills any bucket this limiter is configured with
    // (per_sec >= 1, burst <= 64); the cap keeps the product in range.
    let dt = now.saturating_sub(b.last).min(hz.saturating_mul(1000));
    let add = (dt as u128 * per_sec as u128 * MICRO as u128 / hz.max(1) as u128).min(cap as u128) as u64;
    (b.tokens + add).min(cap)
}

pub(crate) struct Limiter {
    slots:    [Bucket; SLOTS],
    overflow: Bucket,
}

impl Limiter {
    pub(crate) const fn new() -> Self {
        Self { slots: [FREE; SLOTS], overflow: FREE }
    }

    /// May `key` leave a durable record at `now`? Takes one token if so.
    pub(crate) fn admit(&mut self, key: u32, now: u64, per_sec: u64, burst: u64, hz: u64) -> bool {
        let cap = burst * MICRO;
        let at = |b: &Bucket| refilled(b, now, per_sec, burst, hz);
        let idx = match self.slots.iter().position(|b| b.used && b.key == key) {
            Some(i) => Some(i),
            // A free slot, or one that has refilled to full (as good as free).
            None => self.slots.iter().position(|b| !b.used || at(b) >= cap),
        };
        let b = match idx {
            Some(i) => {
                let b = &mut self.slots[i];
                if !(b.used && b.key == key) {
                    *b = Bucket { used: true, key, tokens: cap, last: now };
                }
                b
            }
            None => {
                if !self.overflow.used {
                    self.overflow = Bucket { used: true, key, tokens: cap, last: now };
                }
                &mut self.overflow
            }
        };
        let t = refilled(b, now, per_sec, burst, hz);
        b.last = now;
        if t >= MICRO {
            b.tokens = t - MICRO;
            true
        } else {
            b.tokens = t;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HZ: u64 = 1000; // 1 tick = 1 ms
    const S: u64 = HZ;

    /// **Canary.** `burst` is the count of back-to-back records: change
    /// `t >= MICRO` to `t > MICRO` and 8 become 7; drop the take (`- MICRO`)
    /// and the 9th is admitted. Both red.
    #[test]
    fn a_subject_gets_its_burst_then_nothing() {
        let mut l = Limiter::new();
        let got = (0..20).filter(|_| l.admit(7, 0, 4, 8, HZ)).count();
        assert_eq!(got, 8);
    }

    /// The bucket refills at `per_sec`: one second later, 4 more.
    ///
    /// **Canary.** Refill with `per_sec + 1` in `refilled`: 5 come back,
    /// red. Do not refill at all: 0, red.
    #[test]
    fn it_refills_at_the_configured_rate() {
        let mut l = Limiter::new();
        while l.admit(7, 0, 4, 8, HZ) {}
        assert!(!l.admit(7, 100, 4, 8, HZ), "0.4 token is not a record");
        let got = (0..20).filter(|_| l.admit(7, S, 4, 8, HZ)).count();
        assert_eq!(got, 4);
        // A long quiet spell refills to the burst, not past it.
        let got = (0..20).filter(|_| l.admit(7, 3_000_000, 4, 8, HZ)).count();
        assert_eq!(got, 8);
    }

    /// One subject draining its bucket does not touch another's.
    ///
    /// **Canary.** Make `position` ignore the key: the second subject finds
    /// the first one's empty bucket, red.
    #[test]
    fn subjects_have_their_own_buckets() {
        let mut l = Limiter::new();
        while l.admit(1, 0, 4, 8, HZ) {}
        assert_eq!((0..20).filter(|_| l.admit(2, 0, 4, 8, HZ)).count(), 8);
        assert!(!l.admit(1, 0, 4, 8, HZ));
    }

    /// More draining subjects than slots share ONE overflow bucket: the
    /// total admitted is bounded by the slots plus one burst, not by the
    /// number of subjects.
    ///
    /// **Canary.** Give each overflow subject a fresh bucket (claim a slot
    /// by eviction): 40 x 8 admitted, red.
    #[test]
    fn subjects_past_the_table_share_one_bucket() {
        let mut l = Limiter::new();
        let mut got = 0;
        for k in 0..(SLOTS as u32 + 24) {
            got += (0..20).filter(|_| l.admit(100 + k, 0, 4, 8, HZ)).count();
        }
        assert_eq!(got, (SLOTS + 1) * 8);
    }

    /// A bucket that has refilled to full is reclaimed: SLOTS subjects touch
    /// the table once, a long quiet spell passes, and then subjects of a new
    /// generation each get a bucket of their own (the table's SLOTS) before
    /// the rest share the overflow one.
    ///
    /// **Canary.** Drop `|| at(b) >= cap` from the claim: the second
    /// generation lands on the overflow bucket, 8 admitted, red.
    #[test]
    fn a_refilled_bucket_is_reclaimed() {
        let mut l = Limiter::new();
        for k in 0..SLOTS as u32 {
            assert!(l.admit(k, 0, 4, 8, HZ));
        }
        let later = 100 * S;
        let mut got = 0;
        for k in 0..(SLOTS as u32 + 4) {
            got += (0..20).filter(|_| l.admit(1000 + k, later, 4, 8, HZ)).count();
        }
        assert_eq!(got, (SLOTS + 1) * 8);
    }
}

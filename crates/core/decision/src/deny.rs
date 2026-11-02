// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The rate limit on caller-paced durable records (Kconfig
//! `DECISION_DENY_DURABLE_PER_SEC`, `DECISION_DENY_DURABLE_BURST`).
//!
//! A boot-time refusal is rare; a capability denial, an expired deadline or a
//! refused wait can arrive once per syscall from a ring-3 loop. Each
//! (Domain, rule) pair gets a token bucket: `burst` deep, refilled at
//! `per_sec` tokens a second, one token per durable record.
//!
//! Isolation is by key, never by sharing: a pair that finds the table full
//! takes the slot of the pair that has been dropped from the most (the
//! noisiest), so a quiet Domain's first record always has a full bucket and
//! a flood evicts itself. A bucket that has refilled to full is the same as a
//! free slot and is reclaimed.
//!
//! A drop is never silent. The first drop of a run is reported at once
//! ([`Gate::Drop`] with `first`); the drops after it accumulate in the bucket
//! and are reported by the next record the pair is admitted, by the bucket's
//! eviction, or by [`Limiter::idle`] once the pair has been quiet for a
//! second. The reports sum to the drops.
//!
//! The key is whatever the call site passes: the subject's Domain key where
//! it can reach it (`record_keyed`), its TID otherwise. [`Limiter::admit`] is
//! the pure decision (the host tests drive it with a clock of their own);
//! [`crate`] keeps one behind a spin flag.
//!
//! Time is in the clock's ticks, `hz` of them a second.

/// Buckets in the table.
pub(crate) const SLOTS: usize = 32;

const MICRO: u64 = 1_000_000;

#[derive(Clone, Copy)]
struct Bucket {
    used:       bool,
    rule:       u8,
    key:        u32,
    /// Millionths of a token.
    tokens:     u64,
    last:       u64,
    /// Drops since the last report of this pair.
    suppressed: u32,
    /// Drops since the pair's last admitted record.
    since:      u32,
    /// A run of drops has begun and its start was reported.
    limiting:   bool,
}

const FREE: Bucket = Bucket { used: false, rule: 0, key: 0, tokens: 0, last: 0, suppressed: 0, since: 0, limiting: false };

/// Drops of one (Domain, rule) pair that nothing has reported yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Run {
    pub key:   u32,
    pub rule:  u8,
    pub count: u32,
}

/// What the limiter says about one record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Gate {
    /// Write the record. `owed`: drops of this pair that no report has
    /// carried yet. `since`: all its drops since its last record, the count a
    /// denial carries in its own numbers.
    Admit { owed: u32, since: u32 },
    /// Dropped. `first`: the first of a run, whose one drop the caller reports
    /// now.
    Drop { first: bool },
}

/// [`Gate`] and the run of the pair whose bucket the call displaced, if any.
pub(crate) struct Outcome {
    pub gate:    Gate,
    pub evicted: Option<Run>,
}

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
    slots: [Bucket; SLOTS],
}

impl Limiter {
    pub(crate) const fn new() -> Self {
        Self { slots: [FREE; SLOTS] }
    }

    /// May the pair (`key`, `rule`) leave a durable record at `now`? Takes one
    /// token if so.
    pub(crate) fn admit(&mut self, key: u32, rule: u8, now: u64, per_sec: u64, burst: u64, hz: u64) -> Outcome {
        let cap = burst * MICRO;
        let mut evicted = None;
        let idx = match self.slots.iter().position(|b| b.used && b.key == key && b.rule == rule) {
            Some(i) => i,
            None => {
                let i = self.victim(now, per_sec, burst, hz);
                let old = self.slots[i];
                if old.used && old.suppressed > 0 {
                    evicted = Some(Run { key: old.key, rule: old.rule, count: old.suppressed });
                }
                self.slots[i] = Bucket { used: true, rule, key, tokens: cap, last: now, suppressed: 0, since: 0, limiting: false };
                i
            }
        };
        let b = &mut self.slots[idx];
        let t = refilled(b, now, per_sec, burst, hz);
        b.last = now;
        let gate = if t >= MICRO {
            b.tokens = t - MICRO;
            let (owed, since) = (b.suppressed, b.since);
            b.suppressed = 0;
            b.since = 0;
            b.limiting = false;
            Gate::Admit { owed, since }
        } else {
            b.tokens = t;
            let first = !b.limiting;
            b.since = b.since.saturating_add(1);
            if first {
                b.limiting = true;
            } else {
                b.suppressed = b.suppressed.saturating_add(1);
            }
            Gate::Drop { first }
        };
        Outcome { gate, evicted }
    }

    /// The slot a new pair takes: a free one, else one that has refilled to
    /// full and owes no report, else the one dropped from the most (ties:
    /// the emptiest).
    fn victim(&self, now: u64, per_sec: u64, burst: u64, hz: u64) -> usize {
        let cap = burst * MICRO;
        let at = |b: &Bucket| refilled(b, now, per_sec, burst, hz);
        if let Some(i) = self.slots.iter().position(|b| !b.used || (at(b) >= cap && b.suppressed == 0)) {
            return i;
        }
        let mut best = 0;
        for (i, b) in self.slots.iter().enumerate() {
            let w = &self.slots[best];
            if (b.suppressed, u64::MAX - at(b)) > (w.suppressed, u64::MAX - at(w)) {
                best = i;
            }
        }
        best
    }

    /// Hand `f` the run of every pair that has dropped and then been quiet for
    /// `quiet` ticks, and close it: the next drop of the pair is a first again.
    pub(crate) fn idle(&mut self, now: u64, quiet: u64, mut f: impl FnMut(Run)) {
        for b in self.slots.iter_mut().filter(|b| b.used && b.limiting && now.saturating_sub(b.last) >= quiet) {
            if b.suppressed > 0 {
                f(Run { key: b.key, rule: b.rule, count: b.suppressed });
            }
            b.suppressed = 0;
            b.limiting = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HZ: u64 = 1000; // 1 tick = 1 ms
    const S: u64 = HZ;
    const R: u8 = 4;

    fn ok(l: &mut Limiter, key: u32, rule: u8, now: u64) -> bool {
        matches!(l.admit(key, rule, now, 4, 8, HZ).gate, Gate::Admit { .. })
    }

    /// **Canary.** `burst` is the count of back-to-back records: change
    /// `t >= MICRO` to `t > MICRO` and 8 become 7; drop the take (`- MICRO`)
    /// and the 9th is admitted. Both red.
    #[test]
    fn a_subject_gets_its_burst_then_nothing() {
        let mut l = Limiter::new();
        let got = (0..20).filter(|_| ok(&mut l, 7, R, 0)).count();
        assert_eq!(got, 8);
    }

    /// The bucket refills at `per_sec`: one second later, 4 more.
    ///
    /// **Canary.** Refill with `per_sec + 1` in `refilled`: 5 come back,
    /// red. Do not refill at all: 0, red.
    #[test]
    fn it_refills_at_the_configured_rate() {
        let mut l = Limiter::new();
        while ok(&mut l, 7, R, 0) {}
        assert!(!ok(&mut l, 7, R, 100), "0.4 token is not a record");
        let got = (0..20).filter(|_| ok(&mut l, 7, R, S)).count();
        assert_eq!(got, 4);
        // A long quiet spell refills to the burst, not past it.
        let got = (0..20).filter(|_| ok(&mut l, 7, R, 3_000_000)).count();
        assert_eq!(got, 8);
    }

    /// One key draining its bucket does not touch another's, and one key's
    /// two rules have a bucket each.
    ///
    /// **Canary.** Make `position` ignore the key: the second key finds the
    /// first one's empty bucket, red. Ignore the rule: the second rule does,
    /// red.
    #[test]
    fn keys_and_rules_have_their_own_buckets() {
        let mut l = Limiter::new();
        while ok(&mut l, 1, R, 0) {}
        assert_eq!((0..20).filter(|_| ok(&mut l, 2, R, 0)).count(), 8);
        assert_eq!((0..20).filter(|_| ok(&mut l, 1, R + 1, 0)).count(), 8);
        assert!(!ok(&mut l, 1, R, 0));
    }

    /// A flood from more keys than the table holds cannot take a quiet key's
    /// first records: the newcomer's bucket is the noisiest's slot.
    ///
    /// **Canary.** Choose the first used slot as the victim (or share an
    /// overflow bucket): the quiet key finds an empty bucket, red.
    #[test]
    fn a_flood_of_keys_does_not_cost_a_quiet_one() {
        let mut l = Limiter::new();
        for k in 0..(SLOTS as u32 * 3) {
            for _ in 0..20 {
                ok(&mut l, 100 + k, R, 0);
            }
        }
        assert_eq!((0..20).filter(|_| ok(&mut l, 9, R, 0)).count(), 8, "the quiet key lost records");
    }

    /// A bucket that has refilled to full is reclaimed: SLOTS keys touch the
    /// table once, a long quiet spell passes, and a new generation of keys
    /// each gets a bucket without displacing a run.
    ///
    /// **Canary.** Drop `&& b.suppressed == 0` and `at(b) >= cap` from
    /// `victim`: the second generation evicts live buckets, red.
    #[test]
    fn a_refilled_bucket_is_reclaimed() {
        let mut l = Limiter::new();
        for k in 0..SLOTS as u32 {
            assert!(ok(&mut l, k, R, 0));
        }
        let later = 100 * S;
        for k in 0..SLOTS as u32 {
            let o = l.admit(1000 + k, R, later, 4, 8, HZ);
            assert_eq!(o.gate, Gate::Admit { owed: 0, since: 0 });
            assert_eq!(o.evicted, None);
        }
    }

    /// The first drop of a run is reported at once, the rest accumulate and
    /// ride the next admitted record; together they are the drops.
    ///
    /// **Canary.** Count the first drop into `suppressed` too: the sum is one
    /// over, red. Do not clear `suppressed` on an admit: the owed count
    /// repeats, red.
    #[test]
    fn the_reports_sum_to_the_drops() {
        let mut l = Limiter::new();
        let mut firsts = 0;
        let mut dropped = 0;
        for _ in 0..20 {
            match l.admit(7, R, 0, 4, 8, HZ).gate {
                Gate::Drop { first } => {
                    dropped += 1;
                    firsts += first as u32;
                }
                Gate::Admit { owed, .. } => assert_eq!(owed, 0),
            }
        }
        assert_eq!((dropped, firsts), (12, 1));
        let o = l.admit(7, R, S, 4, 8, HZ);
        assert_eq!(o.gate, Gate::Admit { owed: 11, since: 12 }, "the first was reported when it happened");
        assert_eq!(l.admit(7, R, S, 4, 8, HZ).gate, Gate::Admit { owed: 0, since: 0 });
    }

    /// A pair that floods and stops is reported by `idle` after the quiet
    /// time, once, and its next run starts again with a first.
    ///
    /// **Canary.** Skip the clear of `limiting` in `idle`: the next run has
    /// no first, red. Report at any age: the early call returns a run, red.
    #[test]
    fn a_pair_that_stops_is_reported_when_it_goes_quiet() {
        let mut l = Limiter::new();
        for _ in 0..20 {
            l.admit(7, R, 0, 4, 8, HZ);
        }
        let mut got = None;
        l.idle(HZ / 2, HZ, |r| got = Some(r));
        assert_eq!(got, None, "reported before it was quiet");
        l.idle(HZ, HZ, |r| got = Some(r));
        assert_eq!(got, Some(Run { key: 7, rule: R, count: 11 }));
        got = None;
        l.idle(10 * HZ, HZ, |r| got = Some(r));
        assert_eq!(got, None, "reported twice");
        let firsts = (0..20)
            .filter(|_| matches!(l.admit(7, R, 10 * HZ, 4, 8, HZ).gate, Gate::Drop { first: true }))
            .count();
        assert_eq!(firsts, 1, "the next run has its own first");
    }

    /// The pair a newcomer displaces hands back its unreported drops.
    ///
    /// **Canary.** Return `None` for the evicted run: the drops of the
    /// displaced pair are lost, red.
    #[test]
    fn a_displaced_pair_reports_its_drops() {
        let mut l = Limiter::new();
        for k in 0..SLOTS as u32 {
            for _ in 0..(10 + k) {
                l.admit(k, R, 0, 4, 8, HZ);
            }
        }
        let o = l.admit(5000, R, 0, 4, 8, HZ);
        let noisiest = SLOTS as u32 - 1;
        // 2 + noisiest drops were counted, the first reported when it happened.
        assert_eq!(o.evicted, Some(Run { key: noisiest, rule: R, count: 10 + noisiest - 8 - 1 }));
        assert_eq!(o.gate, Gate::Admit { owed: 0, since: 0 });
    }
}

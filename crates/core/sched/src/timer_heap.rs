// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Indexed binary min-heap of timer sleepers (U02-3): the structure behind
//! `wait::wake_expired_timers` and `scheduler::nearest_timer_deadline` when
//! `sched-timer-heap` is on, replacing their two O(`MAX_TASKS`) sweeps.
//!
//! One entry per pool slot at most (`pos[slot]` is its heap index or
//! [`NOT_ARMED`]), so the heap never holds more than `N` entries and never
//! overflows. `arm` on a slot that is already armed moves its entry to the
//! new deadline instead of adding a second one — a slot that blocks on a
//! timer, is woken by something else, and blocks again reuses its entry.
//!
//! Entries are not removed when a sleeper is woken some other way (killed,
//! TID-directed wake, K-C25 reap): the caller validates an entry against
//! the live task when it reaches the top ([`TimerHeap::peek_live`]), drops
//! it if the slot no longer sleeps, and moves it if the slot sleeps on a
//! different deadline. Because a slot owns at most one entry, stale entries
//! are bounded by `N`.
//!
//! Deadlines are absolute `timebase` ticks (`u64`, 10 MHz on QEMU virt: no
//! wrap in 58,000 years), compared with plain `>=` — the same comparison
//! the sweep it replaces used, so `u64::MAX` ("forever") never expires.
//! Equal deadlines order by slot index, so the pop order is deterministic.
//!
//! No `unsafe`, no locking: the owner wraps the one instance in an
//! interrupt-masking lock. Pure code the host runner
//! (`tests/host/sched-wake-tests`) exercises directly.

/// `pos[slot]` for a slot with no entry.
pub const NOT_ARMED: u16 = u16::MAX;

pub struct TimerHeap<const N: usize> {
    deadline: [u64; N],
    slot: [u16; N],
    pos: [u16; N],
    len: usize,
}

impl<const N: usize> TimerHeap<N> {
    /// Slot indices and heap positions are stored as `u16`, with `u16::MAX`
    /// reserved for [`NOT_ARMED`].
    const FITS: () = assert!(N < u16::MAX as usize);

    pub const fn new() -> Self {
        #[allow(clippy::let_unit_value)]
        let () = Self::FITS;
        Self { deadline: [0; N], slot: [0; N], pos: [NOT_ARMED; N], len: 0 }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The deadline `slot` is armed with, if any.
    #[inline]
    pub fn armed_deadline(&self, slot: usize) -> Option<u64> {
        match self.pos.get(slot) {
            Some(&p) if p != NOT_ARMED => Some(self.deadline[p as usize]),
            _ => None,
        }
    }

    /// The earliest entry, without removing it.
    #[inline]
    pub fn peek(&self) -> Option<(u64, usize)> {
        if self.len == 0 {
            None
        } else {
            Some((self.deadline[0], self.slot[0] as usize))
        }
    }

    /// Arm `slot` to fire at `deadline`, replacing any deadline it already
    /// has. O(log N). Out-of-range slots are ignored.
    pub fn arm(&mut self, slot: usize, deadline: u64) {
        if slot >= N {
            return;
        }
        let p = self.pos[slot];
        if p != NOT_ARMED {
            let i = p as usize;
            let old = self.deadline[i];
            self.deadline[i] = deadline;
            if deadline < old {
                self.sift_up(i);
            } else {
                self.sift_down(i);
            }
            return;
        }
        let i = self.len;
        self.len += 1;
        self.deadline[i] = deadline;
        self.slot[i] = slot as u16;
        self.pos[slot] = i as u16;
        self.sift_up(i);
    }

    /// Remove `slot`'s entry. Returns whether it had one. O(log N).
    pub fn cancel(&mut self, slot: usize) -> bool {
        if slot >= N || self.pos[slot] == NOT_ARMED {
            return false;
        }
        let i = self.pos[slot] as usize;
        self.remove_at(i);
        true
    }

    /// Remove and return the earliest entry. O(log N).
    pub fn pop(&mut self) -> Option<(u64, usize)> {
        let top = self.peek()?;
        self.remove_at(0);
        Some(top)
    }

    /// Remove and return the earliest entry if it is due at `now`
    /// (`now >= deadline`), else leave the heap untouched.
    pub fn pop_due(&mut self, now: u64) -> Option<(u64, usize)> {
        match self.peek() {
            Some((d, _)) if now >= d => self.pop(),
            _ => None,
        }
    }

    /// The earliest deadline a slot still sleeps on, fixing up the top of
    /// the heap on the way. `live(slot)` is the deadline `slot` sleeps on
    /// now, or `None` if it is not asleep on a timer.
    ///
    /// * top matches `live`: return it.
    /// * `live` is `None`: the entry is stale (woken some other way,
    ///   exited) — pop it.
    /// * `live` is a different deadline: the slot is asleep but armed at
    ///   the wrong deadline — move the entry to the live one. Popping it
    ///   would leave a sleeper that no later tick visits.
    ///
    /// `live` reads other harts' task state, so the loop is bounded: after
    /// `N + 1` fix-ups the top is returned as it stands.
    pub fn peek_live(&mut self, mut live: impl FnMut(usize) -> Option<u64>) -> Option<u64> {
        let mut fixups = 0;
        while let Some((d, slot)) = self.peek() {
            match live(slot) {
                Some(l) if l == d => return Some(d),
                _ if fixups > N => return Some(d),
                Some(l) => self.arm(slot, l),
                None => {
                    self.pop();
                }
            }
            fixups += 1;
        }
        None
    }

    #[inline]
    fn less(&self, a: usize, b: usize) -> bool {
        (self.deadline[a], self.slot[a]) < (self.deadline[b], self.slot[b])
    }

    #[inline]
    fn swap(&mut self, a: usize, b: usize) {
        self.deadline.swap(a, b);
        self.slot.swap(a, b);
        self.pos[self.slot[a] as usize] = a as u16;
        self.pos[self.slot[b] as usize] = b as u16;
    }

    fn remove_at(&mut self, i: usize) {
        let last = self.len - 1;
        let gone = self.slot[i] as usize;
        if i != last {
            self.swap(i, last);
        }
        self.len = last;
        self.pos[gone] = NOT_ARMED;
        if i < self.len {
            // The entry moved into `i` may belong above or below it.
            self.sift_up(i);
            self.sift_down(i);
        }
    }

    fn sift_up(&mut self, mut i: usize) {
        while i > 0 {
            let parent = (i - 1) / 2;
            if !self.less(i, parent) {
                break;
            }
            self.swap(i, parent);
            i = parent;
        }
    }

    fn sift_down(&mut self, mut i: usize) {
        loop {
            let l = 2 * i + 1;
            if l >= self.len {
                break;
            }
            let r = l + 1;
            let child = if r < self.len && self.less(r, l) { r } else { l };
            if !self.less(child, i) {
                break;
            }
            self.swap(i, child);
            i = child;
        }
    }
}

impl<const N: usize> Default for TimerHeap<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Xorshift32(u32);
    impl Xorshift32 {
        fn next(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            x
        }
    }

    /// Every invariant the heap relies on: heap order, `pos`/`slot` are
    /// inverse permutations over the live prefix, and nothing else is armed.
    fn check_invariants<const N: usize>(h: &TimerHeap<N>) {
        for i in 1..h.len {
            assert!(!h.less(i, (i - 1) / 2), "heap order broken at {i}");
        }
        let mut seen = [false; N];
        for i in 0..h.len {
            let s = h.slot[i] as usize;
            assert!(!seen[s], "slot {s} twice");
            seen[s] = true;
            assert_eq!(h.pos[s] as usize, i, "pos[{s}]");
        }
        for s in 0..N {
            if !seen[s] {
                assert_eq!(h.pos[s], NOT_ARMED, "slot {s} not in heap but armed");
            }
        }
    }

    /// Ground truth: the sweep this replaces. `model[slot] = Some(deadline)`.
    fn model_min<const N: usize>(model: &[Option<u64>; N]) -> Option<(u64, usize)> {
        model.iter().enumerate().filter_map(|(s, d)| d.map(|d| (d, s))).min()
    }

    #[test]
    fn pops_in_deadline_order_with_slot_tiebreak() {
        let mut h: TimerHeap<16> = TimerHeap::new();
        for (slot, d) in [(3, 50u64), (1, 10), (7, 50), (2, 5), (9, 10), (0, u64::MAX)] {
            h.arm(slot, d);
            check_invariants(&h);
        }
        let mut got = [(0u64, 0usize); 6];
        for g in got.iter_mut() {
            *g = h.pop().unwrap();
            check_invariants(&h);
        }
        assert_eq!(got, [(5, 2), (10, 1), (10, 9), (50, 3), (50, 7), (u64::MAX, 0)]);
        assert!(h.pop().is_none());
    }

    #[test]
    fn rearm_moves_the_one_entry_and_cancel_removes_it() {
        let mut h: TimerHeap<8> = TimerHeap::new();
        h.arm(4, 100);
        h.arm(5, 200);
        h.arm(4, 300); // later: 5 is now first
        assert_eq!(h.len(), 2);
        assert_eq!(h.peek(), Some((200, 5)));
        h.arm(4, 1); // earlier again
        assert_eq!(h.peek(), Some((1, 4)));
        assert_eq!(h.armed_deadline(4), Some(1));
        assert!(h.cancel(4));
        assert!(!h.cancel(4));
        assert_eq!(h.armed_deadline(4), None);
        assert_eq!(h.peek(), Some((200, 5)));
        check_invariants(&h);
        h.arm(99, 7); // out of range: ignored
        assert_eq!(h.len(), 1);
    }

    /// `pop_due` uses the sweep's plain `now >= deadline`: nothing pops
    /// early, everything due pops, and `u64::MAX` never pops before
    /// `now == u64::MAX` — deadlines near the top of the range order and
    /// fire exactly like small ones (no wrapping comparison anywhere).
    #[test]
    fn pop_due_matches_the_sweep_comparison_including_the_top_of_the_range() {
        let mut h: TimerHeap<8> = TimerHeap::new();
        h.arm(0, u64::MAX);
        h.arm(1, u64::MAX - 1);
        h.arm(2, 0);
        h.arm(3, 1000);
        assert_eq!(h.pop_due(0), Some((0, 2)));
        assert_eq!(h.pop_due(999), None);
        assert_eq!(h.pop_due(1000), Some((1000, 3)));
        assert_eq!(h.pop_due(u64::MAX - 2), None);
        assert_eq!(h.pop_due(u64::MAX - 1), Some((u64::MAX - 1, 1)));
        assert_eq!(h.pop_due(u64::MAX - 1), None);
        assert_eq!(h.pop_due(u64::MAX), Some((u64::MAX, 0)));
        assert!(h.is_empty());
    }

    /// `peek_live` drops entries whose slot no longer sleeps and MOVES an
    /// entry whose slot sleeps on another deadline (the misarmed case a
    /// stale re-arm used to leave behind: popping it lost the sleeper).
    #[test]
    fn peek_live_moves_a_misarmed_entry_and_drops_only_stale_ones() {
        let mut h: TimerHeap<8> = TimerHeap::new();
        h.arm(1, 10); // slot 1 now sleeps on 30: misarmed
        h.arm(2, 20); // slot 2 no longer sleeps: stale
        h.arm(3, 40); // slot 3 sleeps on 40: live
        let live = |s: usize| match s {
            1 => Some(30),
            3 => Some(40),
            _ => None,
        };
        assert_eq!(h.peek_live(live), Some(30));
        assert_eq!(h.armed_deadline(1), Some(30), "misarmed sleeper lost");
        assert_eq!(h.armed_deadline(2), None);
        assert_eq!(h.len(), 2);
        check_invariants(&h);
        assert_eq!(h.pop_due(35), Some((30, 1)));
        assert_eq!(h.peek_live(live), Some(40));
        assert_eq!(h.peek_live(|_| None), None);
        assert!(h.is_empty());
    }

    /// A `live` that never agrees (another hart rewriting the reason on
    /// every read) cannot spin `peek_live` forever.
    #[test]
    fn peek_live_is_bounded_when_live_never_settles() {
        let mut h: TimerHeap<4> = TimerHeap::new();
        h.arm(0, 5);
        let mut k = 100u64;
        let got = h.peek_live(|_| {
            k += 1;
            Some(k)
        });
        assert!(got.is_some());
        assert_eq!(h.len(), 1);
        check_invariants(&h);
    }

    /// Random arm / re-arm / cancel / pop_due against the sweep model,
    /// invariants and minimum checked after every step.
    #[test]
    fn random_ops_match_the_sweep_model() {
        const N: usize = 64;
        let mut rng = Xorshift32(0x5EED_71AE);
        let mut h: TimerHeap<N> = TimerHeap::new();
        let mut model: [Option<u64>; N] = [None; N];
        let mut now: u64 = 0;
        for step in 0..20_000 {
            let r = rng.next();
            let slot = (r as usize >> 8) % N;
            match r % 4 {
                0 | 1 => {
                    // Deadlines cluster near `now` (many ties) with the odd
                    // far-future and "forever" sleeper.
                    let d = match (r >> 20) % 8 {
                        0 => u64::MAX,
                        1 => now + 1_000_000,
                        _ => now + u64::from((r >> 24) % 16),
                    };
                    h.arm(slot, d);
                    model[slot] = Some(d);
                }
                2 => {
                    assert_eq!(h.cancel(slot), model[slot].is_some(), "step {step}");
                    model[slot] = None;
                }
                _ => {
                    now += u64::from((r >> 16) % 4);
                    while let Some((d, s)) = h.pop_due(now) {
                        let want = model_min(&model).unwrap();
                        assert_eq!((d, s), want, "step {step}");
                        assert!(now >= d);
                        model[s] = None;
                    }
                    if let Some((d, _)) = model_min(&model) {
                        assert!(d > now, "step {step}: due entry left behind");
                    }
                }
            }
            check_invariants(&h);
            assert_eq!(h.peek(), model_min(&model), "step {step}");
            for s in 0..N {
                assert_eq!(h.armed_deadline(s), model[s], "step {step} slot {s}");
            }
        }
    }
}

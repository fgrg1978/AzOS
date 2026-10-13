// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Jiffies clock and the timer list.
//!
//! The clock is not a tick counter: lxsrv supplies the AzOS monotonic
//! nanosecond time each loop iteration ([`Clock::set_now_ns`]) and jiffies
//! are derived from it. That keeps the server tickless: it sleeps until the
//! earliest timer deadline instead of waking HZ times a second.
//!
//! Timers are slots in a fixed array addressed by generation-checked
//! handles, so a stale handle (timer freed and its slot reused) is an error,
//! not a silent hit on someone else's timer. Callbacks are plain
//! `fn(&mut C, TimerHandle)` over a caller context `C`; the list hands the
//! callback out and drops its borrow *before* the call, so a callback may
//! re-arm itself or touch any other part of `C`.

use core::fmt;

/// Timer interrupt frequency Linux code sees (`CONFIG_HZ`).
pub const HZ: u64 = 250;
/// Nanoseconds per jiffy.
pub const NSEC_PER_JIFFY: u64 = 1_000_000_000 / HZ;
/// Milliseconds per jiffy (exact for HZ = 250).
pub const MSEC_PER_JIFFY: u64 = 1000 / HZ;

/// `unsigned long jiffies` on the 64-bit targets.
pub type Jiffies = u64;

/// Largest relative timeout, as Linux's `MAX_JIFFY_OFFSET`: half the signed
/// range, so `time_after` stays meaningful for any armed timeout.
pub const MAX_JIFFY_OFFSET: Jiffies = ((i64::MAX as u64) >> 1) - 1;

/// Jiffies value at clock zero. Like Linux, start 5 minutes before the
/// 32-bit wrap so code that truncates jiffies to 32 bits breaks early and
/// visibly instead of after 198 days in the field.
pub const INITIAL_JIFFIES: Jiffies = (-(300 * HZ as i64)) as u32 as u64;

/// `time_after(a, b)`: true if `a` is later than `b`, correct across wrap
/// as long as the two are within half the counter range.
pub const fn time_after(a: Jiffies, b: Jiffies) -> bool {
    (b.wrapping_sub(a) as i64) < 0
}

/// `time_before(a, b)`.
pub const fn time_before(a: Jiffies, b: Jiffies) -> bool {
    time_after(b, a)
}

/// `time_after_eq(a, b)`.
pub const fn time_after_eq(a: Jiffies, b: Jiffies) -> bool {
    (a.wrapping_sub(b) as i64) >= 0
}

/// `time_before_eq(a, b)`.
pub const fn time_before_eq(a: Jiffies, b: Jiffies) -> bool {
    time_after_eq(b, a)
}

/// `time_in_range(a, b, c)`: `b <= a <= c`, wrap-safe.
pub const fn time_in_range(a: Jiffies, b: Jiffies, c: Jiffies) -> bool {
    time_after_eq(a, b) && time_before_eq(a, c)
}

/// `msecs_to_jiffies`: rounds up (a 1 ms sleep must not become 0 jiffies),
/// clamped to [`MAX_JIFFY_OFFSET`].
pub const fn msecs_to_jiffies(ms: u64) -> Jiffies {
    let j = ms.div_ceil(MSEC_PER_JIFFY);
    if j > MAX_JIFFY_OFFSET {
        MAX_JIFFY_OFFSET
    } else {
        j
    }
}

/// `usecs_to_jiffies`: rounds up, clamped.
pub const fn usecs_to_jiffies(us: u64) -> Jiffies {
    let j = us.div_ceil(MSEC_PER_JIFFY * 1000);
    if j > MAX_JIFFY_OFFSET {
        MAX_JIFFY_OFFSET
    } else {
        j
    }
}

/// `jiffies_to_msecs`. Saturates instead of overflowing.
pub const fn jiffies_to_msecs(j: Jiffies) -> u64 {
    j.saturating_mul(MSEC_PER_JIFFY)
}

/// Jiffies derived from the caller's monotonic nanosecond clock.
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    now_ns: u64,
    initial: Jiffies,
    backwards: u32,
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    /// Clock at 0 ns, jiffies = [`INITIAL_JIFFIES`].
    pub const fn new() -> Self {
        Self::with_initial_jiffies(INITIAL_JIFFIES)
    }

    /// Clock whose jiffies start at `initial` (tests use this to sit next to
    /// the 64-bit wrap).
    pub const fn with_initial_jiffies(initial: Jiffies) -> Self {
        Clock { now_ns: 0, initial, backwards: 0 }
    }

    /// Feed the current monotonic time. A value lower than the last one is
    /// ignored and counted: jiffies must never go backwards.
    pub fn set_now_ns(&mut self, ns: u64) {
        if ns < self.now_ns {
            self.backwards += 1;
            return;
        }
        self.now_ns = ns;
    }

    /// Last time fed in.
    pub fn now_ns(&self) -> u64 {
        self.now_ns
    }

    /// Times `set_now_ns` was given a value in the past.
    pub fn backwards(&self) -> u32 {
        self.backwards
    }

    /// Current `jiffies`.
    pub fn jiffies(&self) -> Jiffies {
        self.initial.wrapping_add(self.now_ns / NSEC_PER_JIFFY)
    }

    /// Monotonic time at which `jiffies` reaches `expires` (now, if it
    /// already has). This is what the loop sleeps until.
    pub fn deadline_ns(&self, expires: Jiffies) -> u64 {
        let d = expires.wrapping_sub(self.jiffies()) as i64;
        if d <= 0 {
            return self.now_ns;
        }
        (self.now_ns - self.now_ns % NSEC_PER_JIFFY).saturating_add((d as u64).saturating_mul(NSEC_PER_JIFFY))
    }
}

/// Handle to a timer slot. Carries a generation so a handle that outlived
/// [`TimerList::free`] cannot reach the slot's next owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerHandle {
    idx: u16,
    gen: u16,
}

impl TimerHandle {
    /// Slot index (stable for the life of the timer).
    pub fn index(self) -> usize {
        self.idx as usize
    }
}

/// Timer misuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerError {
    /// Every slot is in use.
    Full,
    /// The handle is stale or was never issued by this list.
    BadHandle,
}

/// Timer callback.
pub type TimerFn<C> = fn(&mut C, TimerHandle);

struct Slot<C> {
    func: Option<TimerFn<C>>,
    data: usize,
    expires: Jiffies,
    seq: u64,
    gen: u16,
    pending: bool,
}

impl<C> Clone for Slot<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for Slot<C> {}

/// Fixed-capacity timer list.
pub struct TimerList<C, const N: usize> {
    slots: [Slot<C>; N],
    next_seq: u64,
    full_errors: u32,
    bad_handles: u32,
}

impl<C, const N: usize> Default for TimerList<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C, const N: usize> fmt::Debug for TimerList<C, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimerList")
            .field("capacity", &N)
            .field("pending", &self.pending_count())
            .finish()
    }
}

impl<C, const N: usize> TimerList<C, N> {
    const EMPTY: Slot<C> = Slot { func: None, data: 0, expires: 0, seq: 0, gen: 0, pending: false };

    /// Empty list.
    pub const fn new() -> Self {
        assert!(N <= u16::MAX as usize);
        TimerList { slots: [Self::EMPTY; N], next_seq: 0, full_errors: 0, bad_handles: 0 }
    }

    fn slot(&mut self, h: TimerHandle) -> Result<&mut Slot<C>, TimerError> {
        match self.slots.get_mut(h.idx as usize) {
            Some(s) if s.func.is_some() && s.gen == h.gen => Ok(s),
            _ => {
                self.bad_handles += 1;
                Err(TimerError::BadHandle)
            }
        }
    }

    fn slot_ref(&self, h: TimerHandle) -> Option<&Slot<C>> {
        match self.slots.get(h.idx as usize) {
            Some(s) if s.func.is_some() && s.gen == h.gen => Some(s),
            _ => None,
        }
    }

    /// `timer_setup`: allocate a timer running `func`, with an opaque `data`
    /// word the callback can read back through [`TimerList::data`].
    pub fn setup(&mut self, func: TimerFn<C>, data: usize) -> Result<TimerHandle, TimerError> {
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.func.is_none() {
                s.func = Some(func);
                s.data = data;
                s.pending = false;
                return Ok(TimerHandle { idx: i as u16, gen: s.gen });
            }
        }
        self.full_errors += 1;
        Err(TimerError::Full)
    }

    /// Deactivate and release the slot (`timer_shutdown` + free). Returns
    /// whether it was pending. The handle is dead afterwards.
    pub fn free(&mut self, h: TimerHandle) -> Result<bool, TimerError> {
        let s = self.slot(h)?;
        let was = s.pending;
        s.func = None;
        s.pending = false;
        s.gen = s.gen.wrapping_add(1);
        Ok(was)
    }

    /// `mod_timer`: (re)arm to fire at `expires`. Returns whether it was
    /// pending. Re-arming moves the timer behind every timer armed before
    /// it with the same expiry.
    pub fn mod_timer(&mut self, h: TimerHandle, expires: Jiffies) -> Result<bool, TimerError> {
        let seq = self.next_seq;
        let s = self.slot(h)?;
        let was = s.pending;
        s.pending = true;
        s.expires = expires;
        s.seq = seq;
        self.next_seq += 1;
        Ok(was)
    }

    /// `del_timer`: returns whether it was pending.
    pub fn del_timer(&mut self, h: TimerHandle) -> Result<bool, TimerError> {
        let s = self.slot(h)?;
        Ok(core::mem::replace(&mut s.pending, false))
    }

    /// `timer_pending`. A stale handle reads as not pending.
    pub fn pending(&self, h: TimerHandle) -> bool {
        self.slot_ref(h).is_some_and(|s| s.pending)
    }

    /// The timer's `data` word.
    pub fn data(&self, h: TimerHandle) -> Option<usize> {
        self.slot_ref(h).map(|s| s.data)
    }

    /// The timer's armed expiry, if pending.
    pub fn expires(&self, h: TimerHandle) -> Option<Jiffies> {
        self.slot_ref(h).filter(|s| s.pending).map(|s| s.expires)
    }

    /// Number of armed timers.
    pub fn pending_count(&self) -> usize {
        self.slots.iter().filter(|s| s.func.is_some() && s.pending).count()
    }

    /// `setup` calls refused because the list was full.
    pub fn full_errors(&self) -> u32 {
        self.full_errors
    }

    /// Operations refused for a stale or foreign handle.
    pub fn bad_handles(&self) -> u32 {
        self.bad_handles
    }

    /// Earliest armed expiry, compared relative to `now` so the answer is
    /// right across the jiffies wrap.
    pub fn next_expiry(&self, now: Jiffies) -> Option<Jiffies> {
        self.slots
            .iter()
            .filter(|s| s.func.is_some() && s.pending)
            .min_by_key(|s| s.expires.wrapping_sub(now) as i64)
            .map(|s| s.expires)
    }

    /// Arm sequence mark. A pass fires only timers armed before its mark, so
    /// a callback that re-arms itself for "now" runs on the next pass
    /// instead of spinning the loop.
    pub fn seq_mark(&self) -> u64 {
        self.next_seq
    }

    /// Take the next timer due at `now` and armed before `mark`: earliest
    /// expiry first, equal expiries in arming order. The timer is no longer
    /// pending when returned (a callback may re-arm it).
    pub fn pop_expired(&mut self, now: Jiffies, mark: u64) -> Option<(TimerHandle, TimerFn<C>)> {
        let mut best: Option<(usize, i64, u64)> = None;
        for (i, s) in self.slots.iter().enumerate() {
            if s.func.is_none() || !s.pending || s.seq >= mark || !time_after_eq(now, s.expires) {
                continue;
            }
            let key = s.expires.wrapping_sub(now) as i64;
            if best.is_none_or(|(_, k, q)| (key, s.seq) < (k, q)) {
                best = Some((i, key, s.seq));
            }
        }
        let (i, _, _) = best?;
        let s = &mut self.slots[i];
        s.pending = false;
        Some((TimerHandle { idx: i as u16, gen: s.gen }, s.func?))
    }
}

/// Fire every timer due at `now` that was armed before this call, in
/// expiry order. `get` locates the list inside the context. Returns the
/// number of callbacks run.
pub fn run_expired<C, const N: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut TimerList<C, N>,
    now: Jiffies,
) -> usize {
    let mark = get(ctx).seq_mark();
    let mut fired = 0;
    while let Some((h, f)) = get(ctx).pop_expired(now, mark) {
        f(ctx, h);
        fired += 1;
    }
    fired
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ctx {
        t: TimerList<Ctx, 8>,
        log: Vec<usize>,
        rearm: Option<Jiffies>,
    }

    fn ctx() -> Ctx {
        Ctx { t: TimerList::new(), log: Vec::new(), rearm: None }
    }

    fn tl(c: &mut Ctx) -> &mut TimerList<Ctx, 8> {
        &mut c.t
    }

    fn record(c: &mut Ctx, h: TimerHandle) {
        let d = c.t.data(h).unwrap();
        c.log.push(d);
    }

    fn rearming(c: &mut Ctx, h: TimerHandle) {
        // Panics instead of hanging if a pass ever fires a re-armed timer.
        assert!(c.log.len() < 50, "re-armed timer fired within one pass");
        record(c, h);
        if let Some(e) = c.rearm {
            c.t.mod_timer(h, e).unwrap();
        }
    }

    #[test]
    fn conversions_round_up_and_clamp() {
        assert_eq!(NSEC_PER_JIFFY, 4_000_000);
        assert_eq!(msecs_to_jiffies(0), 0);
        assert_eq!(msecs_to_jiffies(1), 1);
        assert_eq!(msecs_to_jiffies(4), 1);
        assert_eq!(msecs_to_jiffies(5), 2);
        assert_eq!(msecs_to_jiffies(1000), HZ);
        assert_eq!(msecs_to_jiffies(u64::MAX), MAX_JIFFY_OFFSET);
        assert_eq!(usecs_to_jiffies(1), 1);
        assert_eq!(usecs_to_jiffies(4000), 1);
        assert_eq!(usecs_to_jiffies(4001), 2);
        assert_eq!(jiffies_to_msecs(HZ), 1000);
        assert_eq!(jiffies_to_msecs(u64::MAX), u64::MAX);
    }

    #[test]
    fn comparisons_are_correct_across_the_wrap() {
        let before = u64::MAX - 5;
        let after = 10u64; // 16 jiffies later, past the wrap
        assert!(time_after(after, before));
        assert!(time_before(before, after));
        assert!(!time_after(before, after));
        assert!(time_after_eq(after, after));
        assert!(time_in_range(2, before, after));
        assert!(!time_in_range(11, before, after));
        // Canary: the naive comparison gets the wrap wrong.
        let naive = after > before;
        assert!(!naive, "the plain comparison must fail here, or the test proves nothing");
    }

    #[test]
    fn clock_derives_jiffies_and_starts_near_the_32_bit_wrap() {
        let mut c = Clock::new();
        assert_eq!(c.jiffies(), 0xffff_ffff - 75_000 + 1);
        c.set_now_ns(300 * 1_000_000_000);
        assert_eq!(c.jiffies(), 1u64 << 32, "5 minutes after boot the low 32 bits wrap");
        c.set_now_ns(1);
        assert_eq!(c.backwards(), 1);
        assert_eq!(c.now_ns(), 300 * 1_000_000_000);
    }

    #[test]
    fn deadline_is_the_jiffy_boundary() {
        let mut c = Clock::with_initial_jiffies(100);
        c.set_now_ns(NSEC_PER_JIFFY * 3 + 7);
        assert_eq!(c.jiffies(), 103);
        assert_eq!(c.deadline_ns(105), NSEC_PER_JIFFY * 5);
        assert_eq!(c.deadline_ns(103), c.now_ns());
        assert_eq!(c.deadline_ns(50), c.now_ns());
    }

    #[test]
    fn expiry_order_with_ties_in_arming_order() {
        let mut c = ctx();
        let hs: Vec<_> = (0..5).map(|i| c.t.setup(record, i).unwrap()).collect();
        c.t.mod_timer(hs[0], 30).unwrap();
        c.t.mod_timer(hs[1], 10).unwrap();
        c.t.mod_timer(hs[2], 20).unwrap();
        c.t.mod_timer(hs[3], 10).unwrap();
        c.t.mod_timer(hs[4], 99).unwrap();
        assert_eq!(c.t.next_expiry(0), Some(10));
        assert_eq!(run_expired(&mut c, tl, 30), 4);
        assert_eq!(c.log, vec![1, 3, 2, 0]);
        assert_eq!(c.t.next_expiry(30), Some(99));
        assert!(c.t.pending(hs[4]) && !c.t.pending(hs[0]));
    }

    #[test]
    fn expiry_across_the_64_bit_wrap() {
        let mut c = ctx();
        let a = c.t.setup(record, 1).unwrap();
        let b = c.t.setup(record, 2).unwrap();
        let now = u64::MAX - 2;
        c.t.mod_timer(b, 3).unwrap(); // after the wrap
        c.t.mod_timer(a, u64::MAX).unwrap(); // before the wrap
        assert_eq!(c.t.next_expiry(now), Some(u64::MAX));
        assert_eq!(run_expired(&mut c, tl, now), 0);
        assert_eq!(run_expired(&mut c, tl, 0), 1);
        assert_eq!(c.log, vec![1]);
        assert_eq!(run_expired(&mut c, tl, 3), 1);
        assert_eq!(c.log, vec![1, 2]);
    }

    #[test]
    fn mod_and_del_report_previous_pending_state() {
        let mut c = ctx();
        let h = c.t.setup(record, 0).unwrap();
        assert_eq!(c.t.mod_timer(h, 5), Ok(false));
        assert_eq!(c.t.mod_timer(h, 6), Ok(true));
        assert_eq!(c.t.expires(h), Some(6));
        assert_eq!(c.t.del_timer(h), Ok(true));
        assert_eq!(c.t.del_timer(h), Ok(false));
        assert_eq!(run_expired(&mut c, tl, 100), 0);
    }

    #[test]
    fn self_rearm_for_now_waits_for_the_next_pass() {
        let mut c = ctx();
        let h = c.t.setup(rearming, 7).unwrap();
        c.rearm = Some(5);
        c.t.mod_timer(h, 5).unwrap();
        assert_eq!(run_expired(&mut c, tl, 5), 1, "one pass fires once, no livelock");
        assert!(c.t.pending(h));
        c.rearm = None;
        assert_eq!(run_expired(&mut c, tl, 5), 1);
        assert_eq!(c.log, vec![7, 7]);
    }

    #[test]
    fn stale_handle_cannot_touch_the_slots_next_owner() {
        let mut c = ctx();
        let old = c.t.setup(record, 1).unwrap();
        c.t.mod_timer(old, 10).unwrap();
        assert_eq!(c.t.free(old), Ok(true));
        let new = c.t.setup(record, 2).unwrap();
        assert_eq!(new.index(), old.index());
        c.t.mod_timer(new, 20).unwrap();
        assert_eq!(c.t.del_timer(old), Err(TimerError::BadHandle));
        assert_eq!(c.t.mod_timer(old, 1), Err(TimerError::BadHandle));
        assert!(!c.t.pending(old));
        assert!(c.t.pending(new));
        assert_eq!(c.t.bad_handles(), 2);
    }

    #[test]
    fn full_list_is_reported() {
        let mut c = ctx();
        for i in 0..8 {
            c.t.setup(record, i).unwrap();
        }
        assert_eq!(c.t.setup(record, 8), Err(TimerError::Full));
        assert_eq!(c.t.full_errors(), 1);
    }
}

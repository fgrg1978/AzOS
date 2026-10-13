// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Single-thread RCU.
//!
//! With one executor and run-to-completion items, every point *between*
//! items is a quiescent state: no reader can be inside an
//! `rcu_read_lock()` section there unless an item leaked one. A grace
//! period is therefore "the loop reached the end of an item with read depth
//! zero". The loop calls [`quiescent`] once per pass; callbacks queued before
//! that point run there, in `call_rcu` order.
//!
//! What still needs checking is misuse that would hang or corrupt on Linux:
//! an unbalanced `rcu_read_unlock`, `synchronize_rcu` inside a read section
//! (a self-deadlock), and a read section left open across a loop pass.
//! Each is reported and counted, never ignored.

use core::fmt;

/// RCU callback (`call_rcu`'s `func`) with the caller's data word in place
/// of Linux's `struct rcu_head *`.
pub type RcuFn<C> = fn(&mut C, usize);

/// RCU misuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcuError {
    /// `rcu_read_unlock` without a matching lock.
    Unbalanced,
    /// A grace period was requested while a read section is open: would
    /// deadlock on Linux (`synchronize_rcu`) or means a section leaked
    /// across a loop pass (`quiescent`).
    InReadSection,
    /// The callback queue is full.
    Full,
    /// `rcu_barrier` gave up: callbacks keep queueing more callbacks.
    NotDrained,
}

/// Misuse counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RcuStats {
    /// Unbalanced unlocks.
    pub unbalanced: u32,
    /// Grace periods requested inside a read section.
    pub in_read_section: u32,
    /// `call_rcu` refused for lack of space.
    pub full: u32,
    /// Callbacks run.
    pub callbacks_run: u64,
}

struct Cb<C> {
    func: RcuFn<C>,
    data: usize,
    seq: u64,
}

// Manual impls: a derive would demand `C: Copy`, but only the fn pointer
// mentions `C`, and fn pointers are always `Copy`.
impl<C> Clone for Cb<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for Cb<C> {}

/// RCU state: read-side nesting depth and the callback FIFO.
pub struct Rcu<C, const N: usize> {
    depth: u32,
    cbs: [Option<Cb<C>>; N],
    head: usize,
    len: usize,
    next_seq: u64,
    stats: RcuStats,
}

impl<C, const N: usize> Default for Rcu<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C, const N: usize> fmt::Debug for Rcu<C, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rcu").field("depth", &self.depth).field("queued", &self.len).finish()
    }
}

impl<C, const N: usize> Rcu<C, N> {
    /// No readers, no callbacks.
    pub const fn new() -> Self {
        Rcu { depth: 0, cbs: [None; N], head: 0, len: 0, next_seq: 0, stats: RcuStats { unbalanced: 0, in_read_section: 0, full: 0, callbacks_run: 0 } }
    }

    /// `rcu_read_lock`.
    pub fn read_lock(&mut self) {
        self.depth += 1;
    }

    /// `rcu_read_unlock`.
    pub fn read_unlock(&mut self) -> Result<(), RcuError> {
        if self.depth == 0 {
            self.stats.unbalanced += 1;
            return Err(RcuError::Unbalanced);
        }
        self.depth -= 1;
        Ok(())
    }

    /// Read-side nesting depth (`rcu_read_lock_held` is `depth() > 0`).
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// `call_rcu`: run `func(ctx, data)` after the next grace period.
    pub fn call_rcu(&mut self, func: RcuFn<C>, data: usize) -> Result<(), RcuError> {
        if self.len == N {
            self.stats.full += 1;
            return Err(RcuError::Full);
        }
        self.cbs[(self.head + self.len) % N] = Some(Cb { func, data, seq: self.next_seq });
        self.next_seq += 1;
        self.len += 1;
        Ok(())
    }

    /// Callbacks waiting for a grace period.
    pub fn queued(&self) -> usize {
        self.len
    }

    /// Counters.
    pub fn stats(&self) -> RcuStats {
        self.stats
    }

    /// Start a grace period: fails (and counts) inside a read section,
    /// otherwise returns the mark that separates callbacks it covers.
    pub fn begin_grace_period(&mut self) -> Result<u64, RcuError> {
        if self.depth != 0 {
            self.stats.in_read_section += 1;
            return Err(RcuError::InReadSection);
        }
        Ok(self.next_seq)
    }

    /// Take the oldest callback queued before `mark`.
    pub fn pop(&mut self, mark: u64) -> Option<(RcuFn<C>, usize)> {
        if self.len == 0 {
            return None;
        }
        let cb = self.cbs[self.head]?;
        if cb.seq >= mark {
            return None;
        }
        self.cbs[self.head] = None;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        self.stats.callbacks_run += 1;
        Some((cb.func, cb.data))
    }
}

/// Run one grace period: every callback queued before the call, in order.
/// A callback that leaves a read section open ends the grace period early
/// (the remaining callbacks are not safe to run) and is reported.
fn grace_period<C, const N: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut Rcu<C, N>,
) -> Result<usize, RcuError> {
    let mark = get(ctx).begin_grace_period()?;
    let mut ran = 0;
    while let Some((f, d)) = get(ctx).pop(mark) {
        f(ctx, d);
        ran += 1;
        get(ctx).begin_grace_period()?;
    }
    Ok(ran)
}

/// The loop's quiescent point. Returns the number of callbacks run.
pub fn quiescent<C, const N: usize>(ctx: &mut C, get: fn(&mut C) -> &mut Rcu<C, N>) -> Result<usize, RcuError> {
    grace_period(ctx, get)
}

/// `synchronize_rcu`: inside a read section this is a self-deadlock on
/// Linux and is refused; outside, every reader has already finished (one
/// thread), so the grace period completes immediately and callbacks queued
/// before the call run now.
pub fn synchronize_rcu<C, const N: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut Rcu<C, N>,
) -> Result<usize, RcuError> {
    grace_period(ctx, get)
}

/// `rcu_barrier`: run grace periods until the queue is empty, including
/// callbacks queued by callbacks. Linux only waits for callbacks queued
/// before the barrier; draining to empty is stricter and is what module
/// unload wants (no callback may outlive the module's text). Bounded to
/// `N + 1` grace periods; a chain longer than that is reported as
/// [`RcuError::NotDrained`].
pub fn rcu_barrier<C, const N: usize>(ctx: &mut C, get: fn(&mut C) -> &mut Rcu<C, N>) -> Result<usize, RcuError> {
    let mut ran = 0;
    for _ in 0..=N {
        if get(ctx).queued() == 0 {
            return Ok(ran);
        }
        ran += grace_period(ctx, get)?;
    }
    if get(ctx).queued() == 0 {
        Ok(ran)
    } else {
        Err(RcuError::NotDrained)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ctx {
        rcu: Rcu<Ctx, 4>,
        log: Vec<usize>,
    }

    fn ctx() -> Ctx {
        Ctx { rcu: Rcu::new(), log: Vec::new() }
    }

    fn r(c: &mut Ctx) -> &mut Rcu<Ctx, 4> {
        &mut c.rcu
    }

    fn record(c: &mut Ctx, d: usize) {
        c.log.push(d);
    }

    fn chain(c: &mut Ctx, d: usize) {
        c.log.push(d);
        if d > 0 {
            c.rcu.call_rcu(chain, d - 1).unwrap();
        }
    }

    fn leaky(c: &mut Ctx, d: usize) {
        c.log.push(d);
        c.rcu.read_lock();
    }

    #[test]
    fn nesting_and_unbalanced_unlock() {
        let mut c = ctx();
        c.rcu.read_lock();
        c.rcu.read_lock();
        assert_eq!(c.rcu.depth(), 2);
        c.rcu.read_unlock().unwrap();
        c.rcu.read_unlock().unwrap();
        assert_eq!(c.rcu.read_unlock(), Err(RcuError::Unbalanced));
        assert_eq!(c.rcu.depth(), 0, "an unbalanced unlock must not wrap the depth");
        assert_eq!(c.rcu.stats().unbalanced, 1);
    }

    #[test]
    fn callbacks_wait_for_the_read_section_to_end() {
        let mut c = ctx();
        c.rcu.read_lock();
        c.rcu.call_rcu(record, 1).unwrap();
        c.rcu.call_rcu(record, 2).unwrap();
        assert_eq!(quiescent(&mut c, r), Err(RcuError::InReadSection));
        assert!(c.log.is_empty(), "no callback may run while a reader is inside");
        c.rcu.read_unlock().unwrap();
        assert_eq!(quiescent(&mut c, r), Ok(2));
        assert_eq!(c.log, vec![1, 2]);
        assert_eq!(c.rcu.stats().in_read_section, 1);
    }

    #[test]
    fn callbacks_queued_by_callbacks_wait_for_the_next_grace_period() {
        let mut c = ctx();
        c.rcu.call_rcu(chain, 2).unwrap();
        c.rcu.call_rcu(record, 10).unwrap();
        assert_eq!(quiescent(&mut c, r), Ok(2));
        assert_eq!(c.log, vec![2, 10]);
        assert_eq!(quiescent(&mut c, r), Ok(1));
        assert_eq!(quiescent(&mut c, r), Ok(1));
        assert_eq!(quiescent(&mut c, r), Ok(0));
        assert_eq!(c.log, vec![2, 10, 1, 0]);
    }

    #[test]
    fn synchronize_inside_a_read_section_is_refused() {
        let mut c = ctx();
        c.rcu.call_rcu(record, 1).unwrap();
        c.rcu.read_lock();
        assert_eq!(synchronize_rcu(&mut c, r), Err(RcuError::InReadSection));
        assert!(c.log.is_empty());
        c.rcu.read_unlock().unwrap();
        assert_eq!(synchronize_rcu(&mut c, r), Ok(1));
        assert_eq!(c.log, vec![1]);
    }

    #[test]
    fn barrier_drains_chains_and_reports_runaways() {
        let mut c = ctx();
        c.rcu.call_rcu(chain, 3).unwrap();
        assert_eq!(rcu_barrier(&mut c, r), Ok(4));
        assert_eq!(c.log, vec![3, 2, 1, 0]);
        let mut c = ctx();
        c.rcu.call_rcu(chain, 100).unwrap();
        assert_eq!(rcu_barrier(&mut c, r), Err(RcuError::NotDrained));
        assert_eq!(c.log.len(), 5);
    }

    #[test]
    fn a_callback_that_leaks_a_read_section_stops_the_grace_period() {
        let mut c = ctx();
        c.rcu.call_rcu(leaky, 1).unwrap();
        c.rcu.call_rcu(record, 2).unwrap();
        assert_eq!(quiescent(&mut c, r), Err(RcuError::InReadSection));
        assert_eq!(c.log, vec![1]);
        assert_eq!(c.rcu.queued(), 1);
        c.rcu.read_unlock().unwrap();
        assert_eq!(quiescent(&mut c, r), Ok(1));
    }

    #[test]
    fn full_queue_is_reported_and_ring_wraps() {
        let mut c = ctx();
        for round in 0..3 {
            for i in 0..4 {
                c.rcu.call_rcu(record, round * 10 + i).unwrap();
            }
            assert_eq!(c.rcu.call_rcu(record, 99), Err(RcuError::Full));
            quiescent(&mut c, r).unwrap();
        }
        assert_eq!(c.rcu.stats().full, 3);
        assert_eq!(c.log, vec![0, 1, 2, 3, 10, 11, 12, 13, 20, 21, 22, 23]);
    }
}

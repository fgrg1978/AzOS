// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Work items: deferred functions run by the loop in FIFO order.
//!
//! Linux runs work on worker kernel threads; lxsrv has one thread, so a work
//! item is a run-to-completion item of the loop (RFC-0053 section 3). All
//! workqueues collapse into one FIFO: with a single executor, separate
//! queues would only change ordering between unrelated drivers, and one
//! global order is easier to reason about and to replay.
//!
//! A work item is a slot addressed by a generation-checked handle. Its state
//! is `Idle`, `Queued` (in the FIFO) or `Delayed` (a timer will queue it);
//! "pending" in the Linux sense is "not idle". The pending state is cleared
//! *before* the function runs, as in Linux, so a work function may re-queue
//! itself.
//!
//! Delayed work needs a timer from [`crate::timer`]; the glue that owns both
//! lists lives in [`crate::sched::Env`]. This module only records the state
//! and the timer handle.

use crate::timer::TimerHandle;
use core::fmt;

/// Handle to a work slot (generation-checked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkHandle {
    idx: u16,
    gen: u16,
}

impl WorkHandle {
    /// Slot index.
    pub fn index(self) -> usize {
        self.idx as usize
    }

    /// Pack into one word (for a timer's data word). Not a capability: a
    /// forged value still has to pass the generation check.
    pub fn to_raw(self) -> u32 {
        (self.gen as u32) << 16 | self.idx as u32
    }

    /// Inverse of [`WorkHandle::to_raw`].
    pub fn from_raw(raw: u32) -> Self {
        WorkHandle { idx: raw as u16, gen: (raw >> 16) as u16 }
    }
}

/// Work misuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkError {
    /// No free slot.
    Full,
    /// Stale or foreign handle.
    BadHandle,
}

/// Lifecycle of a work item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkState {
    /// Not pending.
    Idle,
    /// In the FIFO, will run on the next pass.
    Queued,
    /// Waiting for its timer to move it into the FIFO.
    Delayed,
}

/// Work function.
pub type WorkFn<C> = fn(&mut C, WorkHandle);

struct Slot<C> {
    func: Option<WorkFn<C>>,
    data: usize,
    timer: Option<TimerHandle>,
    seq: u64,
    gen: u16,
    state: WorkState,
}

impl<C> Clone for Slot<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for Slot<C> {}

/// Fixed-capacity work FIFO. Every item is in the FIFO at most once, so a
/// ring of `N` entries can never overflow.
pub struct WorkQueue<C, const N: usize> {
    slots: [Slot<C>; N],
    ring: [u16; N],
    head: usize,
    len: usize,
    next_seq: u64,
    full_errors: u32,
    bad_handles: u32,
}

impl<C, const N: usize> Default for WorkQueue<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C, const N: usize> fmt::Debug for WorkQueue<C, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkQueue").field("capacity", &N).field("queued", &self.len).finish()
    }
}

impl<C, const N: usize> WorkQueue<C, N> {
    const EMPTY: Slot<C> =
        Slot { func: None, data: 0, timer: None, seq: 0, gen: 0, state: WorkState::Idle };

    /// Empty queue.
    pub const fn new() -> Self {
        assert!(N <= u16::MAX as usize);
        WorkQueue {
            slots: [Self::EMPTY; N],
            ring: [0; N],
            head: 0,
            len: 0,
            next_seq: 0,
            full_errors: 0,
            bad_handles: 0,
        }
    }

    fn check(&mut self, h: WorkHandle) -> Result<usize, WorkError> {
        match self.slots.get(h.idx as usize) {
            Some(s) if s.func.is_some() && s.gen == h.gen => Ok(h.idx as usize),
            _ => {
                self.bad_handles += 1;
                Err(WorkError::BadHandle)
            }
        }
    }

    fn live(&self, h: WorkHandle) -> Option<&Slot<C>> {
        self.slots.get(h.idx as usize).filter(|s| s.func.is_some() && s.gen == h.gen)
    }

    fn push(&mut self, i: usize) {
        let tail = (self.head + self.len) % N;
        self.ring[tail] = i as u16;
        self.len += 1;
        self.slots[i].state = WorkState::Queued;
        self.slots[i].seq = self.next_seq;
        self.next_seq += 1;
    }

    fn unlink(&mut self, i: usize) {
        let mut w = 0;
        for r in 0..self.len {
            let v = self.ring[(self.head + r) % N];
            if v as usize != i {
                self.ring[(self.head + w) % N] = v;
                w += 1;
            }
        }
        self.len = w;
    }

    /// `INIT_WORK`: allocate a work item.
    pub fn init(&mut self, func: WorkFn<C>, data: usize) -> Result<WorkHandle, WorkError> {
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.func.is_none() {
                s.func = Some(func);
                s.data = data;
                s.timer = None;
                s.state = WorkState::Idle;
                return Ok(WorkHandle { idx: i as u16, gen: s.gen });
            }
        }
        self.full_errors += 1;
        Err(WorkError::Full)
    }

    /// Cancel and release the slot. Returns the timer handle attached for
    /// delayed work so the owner can free it too.
    pub fn free(&mut self, h: WorkHandle) -> Result<Option<TimerHandle>, WorkError> {
        let i = self.check(h)?;
        if self.slots[i].state == WorkState::Queued {
            self.unlink(i);
        }
        let s = &mut self.slots[i];
        s.func = None;
        s.state = WorkState::Idle;
        s.gen = s.gen.wrapping_add(1);
        Ok(s.timer.take())
    }

    /// `queue_work`: false if the item is already pending (queued or
    /// delayed), exactly as Linux.
    pub fn queue(&mut self, h: WorkHandle) -> Result<bool, WorkError> {
        let i = self.check(h)?;
        if self.slots[i].state != WorkState::Idle {
            return Ok(false);
        }
        self.push(i);
        Ok(true)
    }

    /// Attach the timer that drives this item as delayed work.
    pub fn set_timer(&mut self, h: WorkHandle, t: TimerHandle) -> Result<(), WorkError> {
        let i = self.check(h)?;
        self.slots[i].timer = Some(t);
        Ok(())
    }

    /// The attached delayed-work timer.
    pub fn timer(&self, h: WorkHandle) -> Option<TimerHandle> {
        self.live(h).and_then(|s| s.timer)
    }

    /// Mark idle work as delayed (its timer is armed by the caller). False
    /// if already pending.
    pub fn mark_delayed(&mut self, h: WorkHandle) -> Result<bool, WorkError> {
        let i = self.check(h)?;
        if self.slots[i].state != WorkState::Idle {
            return Ok(false);
        }
        self.slots[i].state = WorkState::Delayed;
        Ok(true)
    }

    /// The delay elapsed: move a delayed item into the FIFO. Returns false
    /// if it was no longer delayed (cancelled in the meantime).
    pub fn delay_elapsed(&mut self, h: WorkHandle) -> Result<bool, WorkError> {
        let i = self.check(h)?;
        if self.slots[i].state != WorkState::Delayed {
            return Ok(false);
        }
        self.push(i);
        Ok(true)
    }

    /// `cancel_work`: drop a pending item. Returns whether it was pending.
    /// For delayed work the caller also deletes the timer.
    pub fn cancel(&mut self, h: WorkHandle) -> Result<bool, WorkError> {
        let i = self.check(h)?;
        let was = self.slots[i].state;
        if was == WorkState::Queued {
            self.unlink(i);
        }
        self.slots[i].state = WorkState::Idle;
        Ok(was != WorkState::Idle)
    }

    /// `work_pending`.
    pub fn pending(&self, h: WorkHandle) -> bool {
        self.live(h).is_some_and(|s| s.state != WorkState::Idle)
    }

    /// Current state (None for a stale handle).
    pub fn state(&self, h: WorkHandle) -> Option<WorkState> {
        self.live(h).map(|s| s.state)
    }

    /// The item's `data` word.
    pub fn data(&self, h: WorkHandle) -> Option<usize> {
        self.live(h).map(|s| s.data)
    }

    /// Items in the FIFO.
    pub fn queued(&self) -> usize {
        self.len
    }

    /// `init` calls refused because every slot was taken.
    pub fn full_errors(&self) -> u32 {
        self.full_errors
    }

    /// Operations refused for a stale or foreign handle.
    pub fn bad_handles(&self) -> u32 {
        self.bad_handles
    }

    /// Enqueue sequence mark; see [`WorkQueue::pop`].
    pub fn seq_mark(&self) -> u64 {
        self.next_seq
    }

    /// Take the FIFO head if it was queued before `mark`; its state becomes
    /// `Idle` before the caller runs it.
    pub fn pop(&mut self, mark: u64) -> Option<(WorkHandle, WorkFn<C>)> {
        if self.len == 0 {
            return None;
        }
        let i = self.ring[self.head] as usize;
        if self.slots[i].seq >= mark {
            return None;
        }
        self.head = (self.head + 1) % N;
        self.len -= 1;
        let s = &mut self.slots[i];
        s.state = WorkState::Idle;
        Some((WorkHandle { idx: i as u16, gen: s.gen }, s.func?))
    }
}

/// Run every item queued before this call, FIFO (Linux `flush_workqueue`
/// semantics: work queued while flushing is left for the next pass, which
/// also keeps a self-requeueing item from livelocking the loop). Returns the
/// number of items run.
pub fn run_pending<C, const N: usize>(ctx: &mut C, get: fn(&mut C) -> &mut WorkQueue<C, N>) -> usize {
    let mark = get(ctx).seq_mark();
    let mut ran = 0;
    while let Some((h, f)) = get(ctx).pop(mark) {
        f(ctx, h);
        ran += 1;
    }
    ran
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ctx {
        wq: WorkQueue<Ctx, 4>,
        log: Vec<usize>,
        requeue: bool,
    }

    fn ctx() -> Ctx {
        Ctx { wq: WorkQueue::new(), log: Vec::new(), requeue: false }
    }

    fn wq(c: &mut Ctx) -> &mut WorkQueue<Ctx, 4> {
        &mut c.wq
    }

    fn record(c: &mut Ctx, h: WorkHandle) {
        // Panics instead of hanging if a pass ever runs re-queued work.
        assert!(c.log.len() < 50, "self-requeued work ran within one pass");
        assert!(!c.wq.pending(h), "pending must be clear while the function runs");
        let d = c.wq.data(h).unwrap();
        c.log.push(d);
        if c.requeue {
            assert_eq!(c.wq.queue(h), Ok(true));
        }
    }

    #[test]
    fn fifo_order_and_pending_semantics() {
        let mut c = ctx();
        let a = c.wq.init(record, 1).unwrap();
        let b = c.wq.init(record, 2).unwrap();
        let d = c.wq.init(record, 3).unwrap();
        assert_eq!(c.wq.queue(b), Ok(true));
        assert_eq!(c.wq.queue(a), Ok(true));
        assert_eq!(c.wq.queue(b), Ok(false), "already pending");
        assert_eq!(c.wq.queue(d), Ok(true));
        assert_eq!(c.wq.queued(), 3);
        assert_eq!(run_pending(&mut c, wq), 3);
        assert_eq!(c.log, vec![2, 1, 3]);
        assert!(!c.wq.pending(a));
    }

    #[test]
    fn cancel_removes_from_the_middle() {
        let mut c = ctx();
        let hs: Vec<_> = (0..4).map(|i| c.wq.init(record, i).unwrap()).collect();
        for &h in &hs {
            c.wq.queue(h).unwrap();
        }
        assert_eq!(c.wq.cancel(hs[1]), Ok(true));
        assert_eq!(c.wq.cancel(hs[1]), Ok(false));
        run_pending(&mut c, wq);
        assert_eq!(c.log, vec![0, 2, 3]);
    }

    #[test]
    fn self_requeue_runs_once_per_pass() {
        let mut c = ctx();
        let h = c.wq.init(record, 9).unwrap();
        c.requeue = true;
        c.wq.queue(h).unwrap();
        assert_eq!(run_pending(&mut c, wq), 1);
        assert!(c.wq.pending(h));
        c.requeue = false;
        assert_eq!(run_pending(&mut c, wq), 1);
        assert_eq!(run_pending(&mut c, wq), 0);
        assert_eq!(c.log, vec![9, 9]);
    }

    #[test]
    fn ring_wraps_without_losing_order() {
        let mut c = ctx();
        let hs: Vec<_> = (0..4).map(|i| c.wq.init(record, i).unwrap()).collect();
        for round in 0..5 {
            for k in 0..4 {
                c.wq.queue(hs[(k + round) % 4]).unwrap();
            }
            run_pending(&mut c, wq);
        }
        let expect: Vec<usize> = (0..5).flat_map(|r| (0..4).map(move |k| (k + r) % 4)).collect();
        assert_eq!(c.log, expect);
    }

    #[test]
    fn delayed_state_machine() {
        let mut c = ctx();
        let h = c.wq.init(record, 5).unwrap();
        assert_eq!(c.wq.mark_delayed(h), Ok(true));
        assert!(c.wq.pending(h));
        assert_eq!(c.wq.queue(h), Ok(false), "delayed counts as pending");
        assert_eq!(c.wq.mark_delayed(h), Ok(false));
        assert_eq!(run_pending(&mut c, wq), 0);
        assert_eq!(c.wq.delay_elapsed(h), Ok(true));
        assert_eq!(c.wq.state(h), Some(WorkState::Queued));
        assert_eq!(run_pending(&mut c, wq), 1);
        // Cancelled before the timer fires: the late timer is a no-op.
        c.wq.mark_delayed(h).unwrap();
        assert_eq!(c.wq.cancel(h), Ok(true));
        assert_eq!(c.wq.delay_elapsed(h), Ok(false));
        assert_eq!(run_pending(&mut c, wq), 0);
    }

    #[test]
    fn freed_handle_is_rejected_and_full_is_reported() {
        let mut c = ctx();
        let hs: Vec<_> = (0..4).map(|i| c.wq.init(record, i).unwrap()).collect();
        assert_eq!(c.wq.init(record, 9), Err(WorkError::Full));
        c.wq.queue(hs[0]).unwrap();
        assert_eq!(c.wq.free(hs[0]), Ok(None));
        assert_eq!(c.wq.queued(), 0, "free unlinks a queued item");
        let n = c.wq.init(record, 7).unwrap();
        assert_eq!(n.index(), hs[0].index());
        assert_eq!(c.wq.queue(hs[0]), Err(WorkError::BadHandle));
        assert_eq!(c.wq.bad_handles(), 1);
        assert_eq!(c.wq.full_errors(), 1);
    }
}

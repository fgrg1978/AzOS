// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Notify/wait: a futex-shaped primitive on a `u32` inside a shared-memory
//! region (`SYS_NOTIFY_WAIT` 592 / `SYS_NOTIFY_WAKE` 593).
//!
//! # The key is (region, offset), never an address
//!
//! A waiter is filed under the packed `(index, generation)` reference of the
//! shm region and the byte offset of the word inside it. Two tasks that map
//! the same region at different user addresses therefore meet on the same
//! key, and nothing here names a physical address: the kernel reads the word
//! through the region's own page list.
//!
//! The syscall layer finds the region from the caller's RECORDED MAPPING of
//! it (`shm::shm_resolve_mapped`), not from a `Cap<Shm>` handle. A mapping is
//! only ever recorded by `SYS_SHM_MAP_TYPED`, which demands `READ` on a
//! `Cap<Shm>`, so the authority is the same; the reason it is not the handle
//! is that capabilities MOVE (`cap_store::move_cap`, owner decision 38): a
//! creator that gives its region to a peer keeps the mapping and loses the
//! handle, and a handle-keyed wait would leave it unable to wait on or wake
//! its own ring. The check is made on every call (`shm_resolve_mapped` runs
//! under the shm table lock each time), so a released mapping stops
//! resolving at once.
//!
//! # Lost wakeups
//!
//! The classic futex argument, on one lock ([`TABLE`]):
//!
//! * WAIT reads the word and files the waiter under the lock.
//! * WAKE takes the same lock — even when it finds nobody — and marks the
//!   waiters it takes before releasing it.
//!
//! A WAKE that ran before the WAIT's lock released it has already published
//! the store the waker made before calling WAKE, so the WAIT reads the new
//! value and returns `ValueChanged` instead of sleeping. A WAKE that runs
//! after finds the waiter filed.
//!
//! The wake itself goes through `scheduler::wake_task_by_tid`, AFTER the lock
//! is released (the `port.rs` pattern): a waiter that has filed itself but
//! not yet committed to `Blocked` is stamped (K-C9) and its block consumes
//! the stamp.
//!
//! # The wait reason, and why it is `Timer`
//!
//! A waiter blocks on `WaitReason::Timer(deadline)` — `u64::MAX` for no
//! timeout. That is the path the timer interrupt already serves
//! (`wake_expired_timers`: the sleeper heap, or the per-tick sweep without
//! `sched-timer-heap`), so a timed wait needs no timer of its own. WAKE addresses the
//! waiter by TID with the predicate `Timer(d) if d == deadline`, the value
//! the waiter filed. No new `WaitReason` variant, so the scheduler is
//! untouched.
//!
//! # IRQs
//!
//! [`TABLE`] is only ever taken with `lock_irqsave`, so an interrupt handler
//! may call [`notify_wake_key`] (the wake side is ISR-safe:
//! `wake_task_by_tid` is already reached from the PLIC handler through
//! `wait::wake_port_waiter`). The wait side runs in a syscall with IRQs on
//! (O3.1); it holds no lock across the block.
//!
//! # Robust words (owner-died, wave 11)
//!
//! A word can carry a lock protocol in user space (Linux's robust futex
//! layout: owner TID in the low 30 bits, [`ROBUST_OWNER_DIED`],
//! [`ROBUST_WAITERS`]). The kernel cannot see an uncontended acquire, so the
//! holder REGISTERS the word ([`robust_add`], `SYS_NOTIFY_WAIT` op 1): the
//! registration is kept here, kernel side, keyed `(tid, region, offset)` like
//! a waiter — never a user address, never a list in user memory the kernel
//! would have to walk. When the task exits or execs, [`notify_robust_exit`]
//! takes every row of the task and, for each word whose TID bits are still the
//! task's, writes `(word & WAITERS) | OWNER_DIED` with the TID cleared, THEN
//! wakes every waiter on the word with [`WaitResult::OwnerDied`]. Write
//! before wake: a waiter that reads the word under [`TABLE`] after the write
//! sees it changed and never sleeps; one that filed itself before is found by
//! the wake. A word whose TID bits name someone else (released, or taken by
//! another task) is left alone and nobody is woken.
//!
//! The next owner takes the word with a CAS from `OWNER_DIED [| WAITERS]` to
//! its own TID and learns from the bit that the data the word guarded may be
//! inconsistent (glibc's `EOWNERDEAD`); `azos_libsys::robust_lock` does
//! exactly that.

use azos_sync::SpinLock;

/// One waiter per task can exist at a time (a task blocks in one call), so
/// the table never needs more rows than there are tasks.
pub const MAX_NOTIFY_WAITERS: usize = azos_limits::MAX_TASKS;

/// `timeout_ns` meaning "no timeout".
pub const NOTIFY_FOREVER: u64 = u64::MAX;

const FREE: u8 = 0;
const WAITING: u8 = 1;
const WOKEN: u8 = 2;
/// Taken by the exit sweep of a robust word's owner ([`notify_robust_exit`]).
const WOKEN_DIED: u8 = 3;

#[derive(Clone, Copy)]
struct Waiter {
    state: u8,
    tid: u32,
    region: u32,
    offset: u32,
    deadline: u64,
}

const EMPTY: Waiter = Waiter { state: FREE, tid: 0, region: 0, offset: 0, deadline: 0 };

/// The waiter table. Pure data and pure methods, so the host suite drives
/// every transition without a scheduler.
pub struct NotifyTable {
    w: [Waiter; MAX_NOTIFY_WAITERS],
    /// Rows in `WAITING`. A wake that finds none returns without scanning:
    /// that is the path a ring producer takes when its flag read raced a
    /// consumer that had already woken.
    waiting: usize,
}

/// What [`NotifyTable::settle`] found for a waiter that came back from a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Settle {
    /// A WAKE took it. The row is freed.
    Woken,
    /// The exit sweep of the word's owner took it. The row is freed.
    OwnerDied,
    /// Still filed: a spurious return (a stamp from another reason, the
    /// timer sweep for an earlier deadline). The row is kept.
    Waiting,
}

impl NotifyTable {
    pub const fn new() -> Self {
        Self { w: [EMPTY; MAX_NOTIFY_WAITERS], waiting: 0 }
    }

    /// File `tid` as waiting on `(region, offset)` until `deadline`. `None`
    /// when every row is taken — unreachable while each task has at most one
    /// waiter, answered rather than assumed.
    pub fn register(&mut self, tid: u32, region: u32, offset: u32, deadline: u64) -> Option<usize> {
        let slot = self.w.iter().position(|x| x.state == FREE)?;
        self.w[slot] = Waiter { state: WAITING, tid, region, offset, deadline };
        self.waiting += 1;
        Some(slot)
    }

    /// Mark up to `n` waiters on `(region, offset)` woken, in table order,
    /// writing each one's `(tid, deadline)` into `out`. Returns how many.
    /// A row already woken is not counted again: `n` counts distinct waiters.
    pub fn wake(
        &mut self, region: u32, offset: u32, n: u32,
        out: &mut [(u32, u64)],
    ) -> usize {
        self.wake_as(region, offset, n, out, false)
    }

    /// [`wake`](Self::wake), marking each waiter taken as woken by the
    /// owner's death when `died` (it settles as [`Settle::OwnerDied`]).
    pub fn wake_as(
        &mut self, region: u32, offset: u32, n: u32,
        out: &mut [(u32, u64)], died: bool,
    ) -> usize {
        let mut k = 0usize;
        if self.waiting == 0 { return 0; }
        let mark = if died { WOKEN_DIED } else { WOKEN };
        for x in self.w.iter_mut() {
            if k as u64 >= n as u64 || k == out.len() { break; }
            if x.state == WAITING && x.region == region && x.offset == offset {
                x.state = mark;
                out[k] = (x.tid, x.deadline);
                k += 1;
            }
        }
        self.waiting -= k;
        k
    }

    /// The waiter in `slot` came back from its block. `tid` guards against a
    /// caller passing somebody else's slot.
    pub fn settle(&mut self, slot: usize, tid: u32) -> Settle {
        let x = &mut self.w[slot];
        if x.tid != tid || x.state == FREE {
            // Not ours any more — cannot happen while only the filing task
            // frees its row; treated as woken so the caller returns.
            return Settle::Woken;
        }
        if x.state == WOKEN {
            *x = EMPTY;
            return Settle::Woken;
        }
        if x.state == WOKEN_DIED {
            *x = EMPTY;
            return Settle::OwnerDied;
        }
        Settle::Waiting
    }

    /// Withdraw the waiter in `slot` (timeout, refused block). Returns
    /// whether a WAKE had taken it first, in which case the caller reports a
    /// wake: the waker already counted it.
    pub fn cancel(&mut self, slot: usize, tid: u32) -> bool {
        self.cancel_settle(slot, tid) != Settle::Waiting
    }

    /// [`cancel`](Self::cancel), saying which wake took the waiter first:
    /// [`Settle::Waiting`] when none did (the row was withdrawn).
    pub fn cancel_settle(&mut self, slot: usize, tid: u32) -> Settle {
        let x = &mut self.w[slot];
        if x.tid != tid || x.state == FREE {
            return Settle::Woken;
        }
        let r = match x.state {
            WOKEN => Settle::Woken,
            WOKEN_DIED => Settle::OwnerDied,
            _ => {
                self.waiting -= 1;
                Settle::Waiting
            }
        };
        *x = EMPTY;
        r
    }

    /// Rows in use (host tests; the kernel does not need it).
    pub fn in_use(&self) -> usize {
        self.w.iter().filter(|x| x.state != FREE).count()
    }
}

/// The one table, under the one lock the lost-wakeup argument needs.
static TABLE: SpinLock<NotifyTable> = SpinLock::new(NotifyTable::new());

/// How a wait ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitResult {
    /// A WAKE on the same key took this waiter.
    Woken,
    /// The exit sweep of the word's robust owner took this waiter
    /// (`SYS_NOTIFY_WAIT` answers `2`).
    OwnerDied,
    /// The deadline passed first.
    TimedOut,
    /// The word did not hold `expected` when read under the lock: nothing
    /// was filed and the caller did not block.
    ValueChanged,
    /// The scheduler refused to block (K-C29, preemption disabled on this
    /// hart). Nothing is left filed.
    Refused,
    /// Every waiter row is in use.
    NoSpace,
}

/// What the wait and wake need from the rest of the kernel.
///
/// A trait rather than direct calls so this file depends on nothing but the
/// lock: the kernel's implementation (`crates/core/syscall/src/vdso_notify.rs`,
/// `KernelNotifyEnv`) blocks on `WaitReason::Timer(deadline)` and wakes by
/// TID, and the host suite below drives the same loop with a scripted one.
pub trait NotifyEnv {
    /// The timebase counter, in the units `deadline` is in.
    fn now(&self) -> u64;
    /// Block the calling task on `WaitReason::Timer(deadline)`; `true` when
    /// the scheduler refused to block (K-C29).
    fn block(&self, deadline: u64) -> bool;
    /// Wake `tid` if it is blocked on `WaitReason::Timer(deadline)` (stamping
    /// it if it has not blocked yet). Must be callable from an interrupt.
    fn wake(&self, tid: u32, deadline: u64);
}

/// Wait on the word at kernel address `word_kva`, keyed `(region, offset)`.
///
/// # Safety
/// `word_kva` must be the kernel-visible address of a 4-byte-aligned word in
/// a page of `region` that stays allocated for the whole call (the caller
/// holds a mapping, hence a reference, of the region).
pub unsafe fn notify_wait_key<E: NotifyEnv>(
    env: &E, tid: u32, region: u32, offset: u32, word_kva: usize, expected: u32, deadline: u64,
) -> WaitResult {
    use core::sync::atomic::{AtomicU32, Ordering};

    // SAFETY: per the contract above; `AtomicU32` has the layout of `u32`.
    let word = unsafe { &*(word_kva as *const AtomicU32) };
    let slot = {
        let mut t = TABLE.lock_irqsave();
        if word.load(Ordering::Acquire) != expected {
            return WaitResult::ValueChanged;
        }
        match t.register(tid, region, offset, deadline) {
            Some(s) => s,
            None => return WaitResult::NoSpace,
        }
    };
    loop {
        let refused = env.block(deadline);
        let mut t = TABLE.lock_irqsave();
        match t.settle(slot, tid) {
            Settle::Woken => return WaitResult::Woken,
            Settle::OwnerDied => return WaitResult::OwnerDied,
            Settle::Waiting => {}
        }
        if refused {
            // Blocking again would be refused again: withdraw, never spin
            // (an infinite timeout would otherwise hang this hart).
            return withdrawn(t.cancel_settle(slot, tid), WaitResult::Refused);
        }
        if deadline != u64::MAX && env.now() >= deadline {
            return withdrawn(t.cancel_settle(slot, tid), WaitResult::TimedOut);
        }
        // Spurious: still filed, deadline ahead. Block again.
    }
}

/// What a withdrawn wait reports: the wake that beat the withdrawal, or
/// `otherwise` when none did.
fn withdrawn(s: Settle, otherwise: WaitResult) -> WaitResult {
    match s {
        Settle::Woken => WaitResult::Woken,
        Settle::OwnerDied => WaitResult::OwnerDied,
        Settle::Waiting => otherwise,
    }
}

/// Wake up to `n` waiters on `(region, offset)`. Returns how many were taken.
///
/// ISR-safe when `env.wake` is: one `lock_irqsave` hold, then TID-directed
/// wakes after it is released. Takes the lock even when nobody waits — the
/// ordering argument in the module doc depends on it.
pub fn notify_wake_key<E: NotifyEnv>(env: &E, region: u32, offset: u32, n: u32) -> u32 {
    notify_wake_key_as(env, region, offset, n, false)
}

/// [`notify_wake_key`], marking the waiters it takes as woken by the owner's
/// death when `died` (their wait answers [`WaitResult::OwnerDied`]).
fn notify_wake_key_as<E: NotifyEnv>(env: &E, region: u32, offset: u32, n: u32, died: bool) -> u32 {
    // In batches of `WAKE_BATCH`, each taken under one hold and woken after
    // it: a full-table array here was a 1 KiB zero-fill on every call, most
    // of which wake one waiter or none. Every batch still takes the lock, so
    // the empty case keeps the ordering the module doc relies on.
    const WAKE_BATCH: usize = 8;
    let mut total = 0u32;
    loop {
        let mut out = [(0u32, 0u64); WAKE_BATCH];
        let k = TABLE.lock_irqsave().wake_as(region, offset, n - total, &mut out, died);
        for &(tid, deadline) in &out[..k] {
            env.wake(tid, deadline);
        }
        total += k as u32;
        if k < WAKE_BATCH || total >= n {
            return total;
        }
    }
}

// ── Robust words (owner-died) ───────────────────────────────────────────────

pub use azos_abi::syscall_nr::{ROBUST_OWNER_DIED, ROBUST_TID_MASK, ROBUST_WAITERS};

/// Robust registrations the whole machine may hold. Each is three `u32`s.
pub const MAX_ROBUST_WORDS: usize = 64;

/// Robust registrations ONE task may hold: half the table, the per-task
/// quota rule `MAX_SHM_REGIONS_PER_TASK` and `MAX_LEASES_PER_LESSOR` follow
/// (minting without a per-task quota is exhaustion, RFC-0003 addendum). It
/// also bounds the exit sweep's stack buffer.
pub const MAX_ROBUST_PER_TASK: usize = MAX_ROBUST_WORDS / 2;

/// One registration. `tid == 0` is a free row: 0 is never a live task's TID
/// (`cap_store::NO_OWNER`).
#[derive(Clone, Copy)]
struct RobustRow {
    tid: u32,
    region: u32,
    offset: u32,
}

const NO_ROBUST: RobustRow = RobustRow { tid: 0, region: 0, offset: 0 };

/// Why [`RobustTable::add`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RobustError {
    /// The task already holds [`MAX_ROBUST_PER_TASK`] rows.
    Quota,
    /// Every row of the table is taken.
    Full,
    /// TID 0, or a TID wider than [`ROBUST_TID_MASK`]: the word could not
    /// name it, so the sweep could never match it.
    BadTid,
}

/// The registrations. Pure data, driven directly by the host suite.
pub struct RobustTable {
    rows: [RobustRow; MAX_ROBUST_WORDS],
}

impl RobustTable {
    pub const fn new() -> Self {
        Self { rows: [NO_ROBUST; MAX_ROBUST_WORDS] }
    }

    /// Register `(region, offset)` for `tid`. A second registration of the
    /// same word by the same task is the first one (`Ok`, nothing added).
    pub fn add(&mut self, tid: u32, region: u32, offset: u32) -> Result<(), RobustError> {
        if tid == 0 || tid > ROBUST_TID_MASK {
            return Err(RobustError::BadTid);
        }
        let mut mine = 0usize;
        let mut free = None;
        for (i, r) in self.rows.iter().enumerate() {
            if r.tid == tid {
                if r.region == region && r.offset == offset {
                    return Ok(());
                }
                mine += 1;
            } else if r.tid == 0 && free.is_none() {
                free = Some(i);
            }
        }
        if mine >= MAX_ROBUST_PER_TASK {
            return Err(RobustError::Quota);
        }
        let i = free.ok_or(RobustError::Full)?;
        self.rows[i] = RobustRow { tid, region, offset };
        Ok(())
    }

    /// Drop `tid`'s registration of `(region, offset)`; `false` if it had none.
    pub fn remove(&mut self, tid: u32, region: u32, offset: u32) -> bool {
        if tid == 0 {
            return false;
        }
        for r in self.rows.iter_mut() {
            if r.tid == tid && r.region == region && r.offset == offset {
                *r = NO_ROBUST;
                return true;
            }
        }
        false
    }

    /// Remove every row of `tid`, writing `(region, offset)` of each into
    /// `out`. Returns how many. `out` holds the per-task quota, so nothing
    /// is dropped.
    pub fn take_task(&mut self, tid: u32, out: &mut [(u32, u32); MAX_ROBUST_PER_TASK]) -> usize {
        let mut n = 0usize;
        if tid == 0 {
            return 0;
        }
        for r in self.rows.iter_mut() {
            if r.tid == tid && n < MAX_ROBUST_PER_TASK {
                out[n] = (r.region, r.offset);
                n += 1;
                *r = NO_ROBUST;
            }
        }
        n
    }

    /// Rows in use (host tests).
    pub fn in_use(&self) -> usize {
        self.rows.iter().filter(|r| r.tid != 0).count()
    }
}

/// The robust registrations. Its own lock, never held with [`TABLE`]: the
/// sweep takes its rows out in one hold and wakes afterwards.
static ROBUST: SpinLock<RobustTable> = SpinLock::new(RobustTable::new());

/// Register `(region, offset)` as a robust word of `tid` (`SYS_NOTIFY_WAIT`
/// op 1). The syscall layer has already resolved the key from the caller's
/// own writable mapping.
pub fn robust_add(tid: u32, region: u32, offset: u32) -> Result<(), RobustError> {
    ROBUST.lock_irqsave().add(tid, region, offset)
}

/// Drop a registration (`SYS_NOTIFY_WAIT` op 2); `false` if there was none.
pub fn robust_remove(tid: u32, region: u32, offset: u32) -> bool {
    ROBUST.lock_irqsave().remove(tid, region, offset)
}

/// If `word`'s TID bits are `tid`'s, replace them with [`ROBUST_OWNER_DIED`]
/// (keeping [`ROBUST_WAITERS`]) and return `true`. A word another task holds,
/// or nobody does, is left as it is. One CAS loop: user space may be setting
/// `WAITERS` concurrently, and that bit must survive.
pub fn mark_owner_died(word: &core::sync::atomic::AtomicU32, tid: u32) -> bool {
    use core::sync::atomic::Ordering;
    let me = tid & ROBUST_TID_MASK;
    if me == 0 {
        return false;
    }
    let mut v = word.load(Ordering::Acquire);
    loop {
        if v & ROBUST_TID_MASK != me {
            return false;
        }
        let new = (v & ROBUST_WAITERS) | ROBUST_OWNER_DIED;
        match word.compare_exchange_weak(v, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(x) => v = x,
        }
    }
}

/// The exit (and exec) sweep: take every robust row of `tid`; for each word
/// `resolve` can still reach (`Some(kernel address)`), mark it owner-died if
/// `tid` still holds it and wake every waiter on it with
/// [`WaitResult::OwnerDied`]. Returns how many words were marked.
///
/// `resolve(region, offset)` answers the kernel-visible address of the word
/// while `tid` still maps the region, `None` otherwise (a region it released,
/// or a reissued one: the key's generation no longer resolves). The wake runs
/// after the rows are out of [`ROBUST`] and outside [`TABLE`]'s hold, like
/// every wake here.
///
/// # Safety
/// Every address `resolve` returns must be a 4-byte-aligned word of a page
/// that stays allocated for the rest of this call (the dying task's own
/// mapping holds it: the kernel calls this before the task's shared-memory
/// references are released).
pub unsafe fn notify_robust_exit<E: NotifyEnv>(
    env: &E, tid: u32, resolve: impl Fn(u32, u32) -> Option<usize>,
) -> u32 {
    let mut rows = [(0u32, 0u32); MAX_ROBUST_PER_TASK];
    let n = ROBUST.lock_irqsave().take_task(tid, &mut rows);
    let mut marked = 0u32;
    for &(region, offset) in &rows[..n] {
        let Some(kva) = resolve(region, offset) else { continue };
        // SAFETY: per this function's contract.
        let word = unsafe { &*(kva as *const core::sync::atomic::AtomicU32) };
        if mark_owner_died(word, tid) {
            marked += 1;
            notify_wake_key_as(env, region, offset, u32::MAX, true);
        }
    }
    marked
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: u32 = 0x0001_0003; // any packed reference
    const FOREVER: u64 = NOTIFY_FOREVER;

    #[test]
    fn wake_takes_only_the_waiters_on_the_same_offset() {
        let mut t = NotifyTable::new();
        let a = t.register(10, R, 0, FOREVER).unwrap();
        let b = t.register(11, R, 4, FOREVER).unwrap();
        let mut out = [(0u32, 0u64); MAX_NOTIFY_WAITERS];
        assert_eq!(t.wake(R, 0, u32::MAX, &mut out), 1);
        assert_eq!(out[0].0, 10);
        assert_eq!(t.settle(a, 10), Settle::Woken);
        assert_eq!(t.settle(b, 11), Settle::Waiting);
    }

    #[test]
    fn wake_takes_only_the_waiters_on_the_same_region() {
        let mut t = NotifyTable::new();
        let a = t.register(10, R, 0, FOREVER).unwrap();
        let _b = t.register(11, R + 1, 0, FOREVER).unwrap();
        let mut out = [(0u32, 0u64); MAX_NOTIFY_WAITERS];
        assert_eq!(t.wake(R, 0, u32::MAX, &mut out), 1);
        assert_eq!(t.settle(a, 10), Settle::Woken);
    }

    #[test]
    fn wake_counts_distinct_waiters_and_honours_n() {
        let mut t = NotifyTable::new();
        for tid in 1..=3 { t.register(tid, R, 8, FOREVER).unwrap(); }
        let mut out = [(0u32, 0u64); MAX_NOTIFY_WAITERS];
        assert_eq!(t.wake(R, 8, 2, &mut out), 2);
        // The two already woken are not taken again.
        assert_eq!(t.wake(R, 8, 2, &mut out), 1);
        assert_eq!(t.wake(R, 8, 2, &mut out), 0);
    }

    #[test]
    fn a_wake_that_raced_a_timeout_is_reported_as_a_wake() {
        let mut t = NotifyTable::new();
        let a = t.register(10, R, 0, 1234).unwrap();
        let mut out = [(0u32, 0u64); MAX_NOTIFY_WAITERS];
        assert_eq!(t.wake(R, 0, 1, &mut out), 1);
        assert_eq!(out[0], (10, 1234));
        assert!(t.cancel(a, 10), "the waker counted it; the waiter must too");
        assert_eq!(t.in_use(), 0);
    }

    #[test]
    fn cancel_frees_the_row_and_a_later_wake_finds_nobody() {
        let mut t = NotifyTable::new();
        let a = t.register(10, R, 0, 5).unwrap();
        assert!(!t.cancel(a, 10));
        let mut out = [(0u32, 0u64); MAX_NOTIFY_WAITERS];
        assert_eq!(t.wake(R, 0, 1, &mut out), 0);
        assert_eq!(t.in_use(), 0);
    }

    #[test]
    fn the_table_holds_one_waiter_per_task() {
        let mut t = NotifyTable::new();
        for tid in 0..MAX_NOTIFY_WAITERS as u32 {
            assert!(t.register(tid + 1, R, 0, FOREVER).is_some());
        }
        assert!(t.register(9999, R, 0, FOREVER).is_none());
    }

    // ── The wait loop, driven through a scripted environment ────────────────
    //
    // `TABLE` is one static shared by every test that reaches it, so each of
    // these uses its own region value and they cannot see each other's rows.

    use core::cell::{Cell, RefCell};

    struct Script {
        now: Cell<u64>,
        /// Run on each block: what happened while the caller slept.
        on_block: RefCell<Box<dyn FnMut(&Script)>>,
        blocks: Cell<u32>,
        wakes: RefCell<Vec<(u32, u64)>>,
        refuse: bool,
    }
    impl NotifyEnv for Script {
        fn now(&self) -> u64 { self.now.get() }
        fn block(&self, _deadline: u64) -> bool {
            self.blocks.set(self.blocks.get() + 1);
            let mut f = self.on_block.borrow_mut();
            (f)(self);
            self.refuse
        }
        fn wake(&self, tid: u32, deadline: u64) { self.wakes.borrow_mut().push((tid, deadline)); }
    }
    fn script(refuse: bool, f: impl FnMut(&Script) + 'static) -> Script {
        Script { now: Cell::new(100), on_block: RefCell::new(Box::new(f)), blocks: Cell::new(0),
                 wakes: RefCell::new(Vec::new()), refuse }
    }

    #[test]
    fn a_changed_word_returns_without_blocking_or_filing() {
        let word = core::sync::atomic::AtomicU32::new(7);
        let env = script(false, |_| panic!("must not block"));
        let r = unsafe { notify_wait_key(&env, 1, 0xA1, 0, &word as *const _ as usize, 6, FOREVER) };
        assert_eq!(r, WaitResult::ValueChanged);
        assert_eq!(TABLE.lock_irqsave().wake(0xA1, 0, 1, &mut [(0, 0); MAX_NOTIFY_WAITERS]), 0);
    }

    #[test]
    fn a_wake_on_the_key_ends_the_wait() {
        let word = core::sync::atomic::AtomicU32::new(0);
        let env = script(false, |e| {
            // Another task wakes the key while this one sleeps.
            assert_eq!(notify_wake_key(e, 0xA2, 8, 1), 1);
        });
        let r = unsafe { notify_wait_key(&env, 5, 0xA2, 8, &word as *const _ as usize, 0, FOREVER) };
        assert_eq!(r, WaitResult::Woken);
        assert_eq!(env.blocks.get(), 1);
        assert_eq!(*env.wakes.borrow(), vec![(5, FOREVER)]);
    }

    #[test]
    fn a_wake_on_another_offset_does_not_end_the_wait() {
        let word = core::sync::atomic::AtomicU32::new(0);
        let env = script(false, |e| {
            assert_eq!(notify_wake_key(e, 0xA3, 4, 1), 0, "offset 4 has no waiter");
            e.now.set(e.now.get() + 1_000);
        });
        let r = unsafe { notify_wait_key(&env, 6, 0xA3, 0, &word as *const _ as usize, 0, 500) };
        assert_eq!(r, WaitResult::TimedOut);
        assert!(env.wakes.borrow().is_empty());
    }

    #[test]
    fn spurious_returns_block_again_until_the_deadline() {
        let word = core::sync::atomic::AtomicU32::new(0);
        let env = script(false, |e| e.now.set(e.now.get() + 10));
        let r = unsafe { notify_wait_key(&env, 7, 0xA4, 0, &word as *const _ as usize, 0, 150) };
        assert_eq!(r, WaitResult::TimedOut);
        assert_eq!(env.blocks.get(), 5, "100 -> 150 in steps of 10");
        assert_eq!(TABLE.lock_irqsave().wake(0xA4, 0, 1, &mut [(0, 0); MAX_NOTIFY_WAITERS]), 0,
            "a timed-out waiter leaves no row behind");
    }

    #[test]
    fn a_refused_block_withdraws_instead_of_spinning_forever() {
        let word = core::sync::atomic::AtomicU32::new(0);
        let env = script(true, |_| {});
        let r = unsafe { notify_wait_key(&env, 8, 0xA5, 0, &word as *const _ as usize, 0, FOREVER) };
        assert_eq!(r, WaitResult::Refused);
        assert_eq!(env.blocks.get(), 1);
    }

    #[test]
    fn a_wake_of_more_than_one_batch_takes_every_waiter_once() {
        let env = script(false, |_| {});
        {
            let mut t = TABLE.lock_irqsave();
            for tid in 100..120 { t.register(tid, 0xA6, 0, FOREVER).unwrap(); }
        }
        assert_eq!(notify_wake_key(&env, 0xA6, 0, u32::MAX), 20);
        assert_eq!(notify_wake_key(&env, 0xA6, 0, u32::MAX), 0);
        let mut tids: Vec<u32> = env.wakes.borrow().iter().map(|w| w.0).collect();
        tids.sort();
        assert_eq!(tids, (100..120).collect::<Vec<_>>());
        // Free the rows the woken waiters would have settled.
        let mut t = TABLE.lock_irqsave();
        for i in 0..MAX_NOTIFY_WAITERS { if t.w[i].region == 0xA6 { t.w[i] = EMPTY; } }
    }

    #[test]
    fn a_wake_with_nobody_waiting_anywhere_takes_nobody() {
        let mut t = NotifyTable::new();
        let mut out = [(0u32, 0u64); 4];
        assert_eq!(t.wake(R, 0, 1, &mut out), 0);
        let a = t.register(1, R, 0, FOREVER).unwrap();
        assert!(!t.cancel(a, 1));
        assert_eq!(t.wake(R, 0, 1, &mut out), 0, "the waiting count went back to zero");
    }

    // ── Robust words (owner-died) ───────────────────────────────────────────

    #[test]
    fn robust_add_is_idempotent_and_remove_drops_it() {
        let mut t = RobustTable::new();
        assert_eq!(t.add(5, R, 0), Ok(()));
        assert_eq!(t.add(5, R, 0), Ok(()), "a second add of the same word");
        assert_eq!(t.in_use(), 1, "is the same registration");
        assert!(t.remove(5, R, 0));
        assert!(!t.remove(5, R, 0), "nothing left to remove");
        assert!(!t.remove(6, R, 4), "another task's word was never there");
    }

    #[test]
    fn robust_quota_is_per_task_and_the_table_still_fills() {
        let mut t = RobustTable::new();
        for off in 0..MAX_ROBUST_PER_TASK as u32 {
            assert_eq!(t.add(7, R, off * 4), Ok(()));
        }
        assert_eq!(t.add(7, R, 0x400), Err(RobustError::Quota));
        for off in 0..(MAX_ROBUST_WORDS - MAX_ROBUST_PER_TASK) as u32 {
            assert_eq!(t.add(8 + off / 8, R, off * 4), Ok(()), "other tasks still register");
        }
        assert_eq!(t.add(99, R, 0), Err(RobustError::Full));
    }

    #[test]
    fn robust_refuses_a_tid_the_word_cannot_name() {
        let mut t = RobustTable::new();
        assert_eq!(t.add(0, R, 0), Err(RobustError::BadTid));
        assert_eq!(t.add(ROBUST_TID_MASK + 1, R, 0), Err(RobustError::BadTid));
        assert_eq!(t.add(ROBUST_TID_MASK, R, 0), Ok(()));
    }

    #[test]
    fn take_task_removes_only_that_tasks_rows() {
        let mut t = RobustTable::new();
        t.add(3, R, 0).unwrap();
        t.add(4, R, 4).unwrap();
        t.add(3, R + 1, 8).unwrap();
        let mut out = [(0u32, 0u32); MAX_ROBUST_PER_TASK];
        assert_eq!(t.take_task(3, &mut out), 2);
        assert_eq!(&out[..2], &[(R, 0), (R + 1, 8)]);
        assert_eq!(t.in_use(), 1, "task 4's row stays");
        assert_eq!(t.take_task(3, &mut out), 0);
    }

    #[test]
    fn mark_owner_died_only_touches_the_dying_holders_word() {
        use core::sync::atomic::{AtomicU32, Ordering};
        let w = AtomicU32::new(42 | ROBUST_WAITERS);
        assert!(mark_owner_died(&w, 42));
        assert_eq!(w.load(Ordering::Relaxed), ROBUST_OWNER_DIED | ROBUST_WAITERS,
            "TID cleared, WAITERS kept, OWNER_DIED set");
        let w = AtomicU32::new(43);
        assert!(!mark_owner_died(&w, 42), "another task holds it");
        assert_eq!(w.load(Ordering::Relaxed), 43);
        let w = AtomicU32::new(0);
        assert!(!mark_owner_died(&w, 42), "nobody holds it");
        assert_eq!(w.load(Ordering::Relaxed), 0);
        let w = AtomicU32::new(ROBUST_OWNER_DIED);
        assert!(!mark_owner_died(&w, 0), "TID 0 names nobody");
    }

    /// The property: a waiter asleep on a robust word whose holder dies is
    /// woken with `OwnerDied`, and the word says so. Canary: drop the
    /// `notify_wake_key_as` call in `notify_robust_exit` and the wait ends
    /// `TimedOut` with the word still marked (the sleeper is stranded).
    #[test]
    fn a_holders_exit_wakes_the_sleeper_with_owner_died() {
        use core::sync::atomic::{AtomicU32, Ordering};
        const HOLDER: u32 = 0x1A0;
        const SLEEPER: u32 = 0x1A1;
        const REG: u32 = 0xB1;
        let word = std::boxed::Box::leak(std::boxed::Box::new(AtomicU32::new(HOLDER | ROBUST_WAITERS)));
        let kva = word as *const AtomicU32 as usize;
        robust_add(HOLDER, REG, 12).unwrap();
        let env = script(false, move |e| {
            // The holder dies while the sleeper is blocked.
            let n = unsafe { notify_robust_exit(e, HOLDER, |r, o| (r == REG && o == 12).then_some(kva)) };
            assert_eq!(n, 1);
            e.now.set(e.now.get() + 1_000_000);
        });
        let r = unsafe { notify_wait_key(&env, SLEEPER, REG, 12, kva, HOLDER | ROBUST_WAITERS, 10_000) };
        assert_eq!(r, WaitResult::OwnerDied);
        assert_eq!(word.load(Ordering::Relaxed), ROBUST_OWNER_DIED | ROBUST_WAITERS);
        assert_eq!(*env.wakes.borrow(), vec![(SLEEPER, 10_000)]);
        assert_eq!(ROBUST.lock_irqsave().take_task(HOLDER, &mut [(0, 0); MAX_ROBUST_PER_TASK]), 0,
            "the sweep removed the holder's rows");
    }

    #[test]
    fn a_word_the_dead_task_no_longer_holds_wakes_nobody() {
        use core::sync::atomic::{AtomicU32, Ordering};
        const DEAD: u32 = 0x1B0;
        const NEXT: u32 = 0x1B1;
        const REG: u32 = 0xB2;
        // `DEAD` registered the word, released it, and `NEXT` took it.
        let word = std::boxed::Box::leak(std::boxed::Box::new(AtomicU32::new(NEXT)));
        let kva = word as *const AtomicU32 as usize;
        robust_add(DEAD, REG, 0).unwrap();
        {
            let mut t = TABLE.lock_irqsave();
            t.register(0x1B2, REG, 0, FOREVER).unwrap();
        }
        let env = script(false, |_| {});
        assert_eq!(unsafe { notify_robust_exit(&env, DEAD, |_, _| Some(kva)) }, 0);
        assert_eq!(word.load(Ordering::Relaxed), NEXT, "the live holder's word is untouched");
        assert!(env.wakes.borrow().is_empty(), "nobody woken");
        // Free the waiter row this test filed.
        assert_eq!(TABLE.lock_irqsave().wake(REG, 0, 1, &mut [(0, 0); 1]), 1);
        let mut t = TABLE.lock_irqsave();
        for i in 0..MAX_NOTIFY_WAITERS { if t.w[i].region == REG { t.w[i] = EMPTY; } }
    }

    #[test]
    fn an_unresolvable_word_is_dropped_without_a_write() {
        const DEAD: u32 = 0x1C0;
        robust_add(DEAD, 0xB3, 0).unwrap();
        let env = script(false, |_| {});
        assert_eq!(unsafe { notify_robust_exit(&env, DEAD, |_, _| None) }, 0);
        assert_eq!(ROBUST.lock_irqsave().take_task(DEAD, &mut [(0, 0); MAX_ROBUST_PER_TASK]), 0);
    }

    #[test]
    fn a_plain_wake_still_settles_as_woken() {
        let mut t = NotifyTable::new();
        let a = t.register(10, R, 0, FOREVER).unwrap();
        let b = t.register(11, R, 4, FOREVER).unwrap();
        let mut out = [(0u32, 0u64); 2];
        assert_eq!(t.wake_as(R, 0, 1, &mut out, false), 1);
        assert_eq!(t.wake_as(R, 4, 1, &mut out, true), 1);
        assert_eq!(t.settle(a, 10), Settle::Woken);
        assert_eq!(t.cancel_settle(b, 11), Settle::OwnerDied, "a died wake that beat a timeout");
    }
}

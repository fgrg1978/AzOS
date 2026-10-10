// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PI futexes on the wait graph (wave 15 N10): the seam between the futex
//! table's per-bucket `pi_state` slot (N9) and the graph (N7).
//!
//! N10 implements [`PiFutexOps`] ([`PI_FUTEX`]) over a static pool of
//! `pi_state`s; N9's bucket code calls it through [`PiBucket`] and runs it
//! from its [`PiTable`], which the Linux personality reaches through
//! [`sys_futex_pi`]. Kconfig `FUTEX_PI` (default n, depends on
//! `WAIT_GRAPH`): n, the pool is empty and the PI operations return
//! `ENOSYS` exactly as today.
//!
//! # The word (Linux protocol, bit-exact)
//!
//! `TID | FUTEX_WAITERS | FUTEX_OWNER_DIED`. 0 is free. User space takes a
//! free word with `cmpxchg(0 -> TID)` and releases an uncontended one with
//! `cmpxchg(TID -> 0)`; the kernel is entered only when that fails. The
//! kernel sets `FUTEX_WAITERS` before a waiter sleeps, so the owner's
//! user-space release fails and enters `UNLOCK_PI`. Constants equal
//! `azos_abi::ROBUST_*` and `azos_linux_abi::robust::FUTEX_*` (N10 adds the
//! `const` assertion where both crates are visible).
//!
//! # Operations (Linux semantics, `man 2 futex`)
//!
//! * `LOCK_PI`: no TID in the word -> take it (`TID | (word & OWNER_DIED)`:
//!   the bit is kept, user space reports `EOWNERDEAD` from it), return 0.
//!   Owned -> attach/create the `pi_state` (owner = word's TID, `ESRCH` if
//!   no such task in the caller's futex namespace), set `FUTEX_WAITERS`,
//!   block on the graph (`EdgeKind::FutexPi`), sleep; `EDEADLK` on a cycle
//!   or when the caller is the owner; `ETIMEDOUT` (absolute
//!   `CLOCK_REALTIME`, or `CLOCK_MONOTONIC` for `LOCK_PI2`); `EINTR` never
//!   (the call restarts).
//! * `TRYLOCK_PI`: as `LOCK_PI` without sleeping: `EAGAIN` if owned. Also
//!   takes over an `OWNER_DIED` word with no live owner.
//! * `UNLOCK_PI`: caller must own the word (`EPERM` otherwise). No waiters
//!   -> word = 0. Waiters -> ownership passes to the top waiter **in the
//!   kernel**: word = `new TID | FUTEX_WAITERS if more remain` (Linux
//!   always sets the bit; here a handover to the last waiter also retires
//!   the `pi_state`, so the new owner's release stays in user space), the graph
//!   unboosts the caller, the new owner wakes already holding the lock.
//! * `WAIT_REQUEUE_PI` (cond var wait, `uaddr` -> PI `uaddr2`) and
//!   `CMP_REQUEUE_PI` (`nr_wake` must be 1, `uaddr != uaddr2`, else
//!   `EINVAL`): the waker atomically tries to take `uaddr2` for the top
//!   waiter (it wakes owning it), and moves the rest onto `uaddr2`'s
//!   `pi_state` as graph waiters without waking them (no thundering herd).
//! * Owner died: the exit path's robust-list walk calls
//!   [`PiFutexOps::owner_died`] for every PI word the dying task owns: the
//!   word gets `FUTEX_OWNER_DIED`, ownership passes to the top waiter as in
//!   `UNLOCK_PI` (it returns with the bit set; user space sees
//!   `EOWNERDEAD`), or the word stays `OWNER_DIED` with no TID when nobody
//!   waits.
//!
//! # Locking
//!
//! Bucket SpinLock (N9) -> `PiWaiters` wait lock (N7) -> per-task PI lock ->
//! run-queue lock. The enqueue happens under the bucket lock
//! (`waitgraph::block_prepare`), the walk after it is dropped
//! (`waitgraph::block_commit`), the sleep last. A `pi_state` is freed only
//! after a grace period (`call_rcu`) once its last waiter left.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::spinlock::SpinLock;
use crate::waitgraph::{self, EdgeKind, PendingBlock, PiWaiters, TaskId, UnblockReason, WaitError};

/// Kconfig `FUTEX_PI`.
pub const ENABLED: bool = azos_limits::FUTEX_PI;

/// The owner's TID (Linux `FUTEX_TID_MASK`).
pub const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;
/// The last owner died holding the word (Linux `FUTEX_OWNER_DIED`).
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// Someone may sleep on the word; unlock must enter the kernel (Linux
/// `FUTEX_WAITERS`).
pub const FUTEX_WAITERS: u32 = 0x8000_0000;

/// The owner TID a word names, `None` for 0.
#[inline]
pub const fn word_owner(w: u32) -> Option<u32> {
    let t = w & FUTEX_TID_MASK;
    if t == 0 { None } else { Some(t) }
}

/// The word an in-kernel handover writes: the new owner, `FUTEX_WAITERS` if
/// more waiters remain, and `FUTEX_OWNER_DIED` only for a handover from
/// [`PiFutexOps::owner_died`] (`UNLOCK_PI` clears it, as Linux does).
#[inline]
pub const fn handover_word(new_owner: u32, more_waiters: bool, owner_died: bool) -> u32 {
    (new_owner & FUTEX_TID_MASK)
        | if more_waiters { FUTEX_WAITERS } else { 0 }
        | if owner_died { FUTEX_OWNER_DIED } else { 0 }
}

/// A `pi_state` in N10's pool: what N9's per-bucket slot stores. Raw value
/// 0 is reserved for "empty", so N9 may keep the slot as a plain `u32`
/// (`PiStateId::from_raw`/`raw`) or as `Option<PiStateId>`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PiStateId(core::num::NonZeroU32);

impl PiStateId {
    pub const fn from_raw(v: u32) -> Option<Self> {
        match core::num::NonZeroU32::new(v) {
            Some(n) => Some(PiStateId(n)),
            None => None,
        }
    }

    pub const fn raw(self) -> u32 {
        self.0.get()
    }
}

/// A fault reading or writing the user word (unmapped, not writable):
/// `EFAULT` to user space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UserFault;

/// What N9 lends the PI code for one futex key, **under its bucket lock**.
/// N9 implements it on its bucket guard; N10 never sees the bucket layout.
pub trait PiBucket {
    /// The `pi_state` slot of THIS futex key (0 = none): one per key/entry
    /// in the bucket, never one shared by the whole bucket.
    fn pi_slot(&mut self) -> &mut u32;
    /// Atomic read of the user word, faults reported, no sleep (the bucket
    /// lock is a SpinLock: N9 pre-faults the page before taking it, as
    /// Linux's `fault_in_user_writeable` retry loop does).
    fn read_word(&self) -> Result<u32, UserFault>;
    /// Atomic compare-and-exchange on the user word; returns the value seen.
    fn cmpxchg_word(&mut self, expected: u32, new: u32) -> Result<u32, UserFault>;
    /// The TID of a task in the caller's futex namespace, as a scheduler
    /// slot, or `None` (`ESRCH`).
    fn task_of_tid(&self, tid: u32) -> Option<TaskId>;
}

/// Result of the under-lock half of `LOCK_PI` / `WAIT_REQUEUE_PI`.
#[must_use]
pub enum LockPiStep {
    /// The caller owns the word now; return 0.
    Acquired,
    /// The caller is enqueued; N9 drops the bucket lock, then calls
    /// `waitgraph::block_commit(pending)`, then sleeps until woken or the
    /// timeout, then calls [`PiFutexOps::lock_pi_finish`].
    Block(PendingBlock),
    /// Return `-errno` (EAGAIN for TRYLOCK_PI owned, EDEADLK, ESRCH,
    /// EFAULT, EINVAL).
    Err(i32),
}

/// The PI futex operations N9's dispatcher calls. **Implemented by N10.**
///
/// Every `&mut dyn PiBucket` argument is valid only under that bucket's
/// lock; no method sleeps; each is O(1) plus the graph's O(W) enqueue.
pub trait PiFutexOps: Sync {
    /// `LOCK_PI`, `LOCK_PI2` and `TRYLOCK_PI` (`try_only`), under the lock.
    fn lock_pi_prepare(&self, b: &mut dyn PiBucket, me: TaskId, try_only: bool) -> LockPiStep;

    /// After the sleep, under the bucket lock again: if the caller now owns
    /// the word, fix the word (`TID | WAITERS if more`, `OWNER_DIED` kept
    /// when the handover came from `owner_died`) and return 0; on timeout
    /// leave the graph (`UnblockReason::Timeout`) and return `-ETIMEDOUT`
    /// (unless ownership arrived meanwhile: then 0, as Linux).
    fn lock_pi_finish(&self, b: &mut dyn PiBucket, me: TaskId, timed_out: bool) -> i32;

    /// `UNLOCK_PI`, under the lock. Returns the task to wake (the new
    /// owner), which N9 wakes after dropping the lock, or `-errno`.
    fn unlock_pi(&self, b: &mut dyn PiBucket, me: TaskId) -> Result<Option<TaskId>, i32>;

    /// `CMP_REQUEUE_PI` with both buckets locked (N9 locks them in address
    /// order). `cmpval` is checked against `from`'s word first (`EAGAIN`).
    /// Returns (woken-and-owning, requeued) counts, or `-errno`.
    fn cmp_requeue_pi(
        &self,
        from: &mut dyn PiBucket,
        to: &mut dyn PiBucket,
        cmpval: u32,
        nr_requeue: u32,
    ) -> Result<(u32, u32), i32>;

    /// The robust-list walk found a PI word `dead` owned: set
    /// `FUTEX_OWNER_DIED` and hand over as `UNLOCK_PI` does. Returns the
    /// task to wake. Called from the exit path, task context, bucket locked.
    fn owner_died(&self, b: &mut dyn PiBucket, dead: TaskId) -> Result<Option<TaskId>, i32>;
}

// ── Errnos (Linux numbers, positive; the methods return them negated) ────

pub const EPERM: i32 = 1;
pub const ESRCH: i32 = 3;
/// `lock_pi_finish` woke without owning the word and without a timeout (a
/// signal, a spurious wake): the dispatcher restarts the operation (Linux
/// `-ERESTARTNOINTR`); user space never sees it.
pub const EINTR: i32 = 4;
pub const EAGAIN: i32 = 11;
/// The `pi_state` pool (`MAX_TASKS` entries) is exhausted. Linux's errno
/// for a failed `pi_state` allocation.
pub const ENOMEM: i32 = 12;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
pub const EDEADLK: i32 = 35;
pub const ENOSYS: i32 = 38;
pub const ETIMEDOUT: i32 = 110;

// ── The word state machine (pure; host-tested) ───────────────────────────

/// What `LOCK_PI` / `TRYLOCK_PI` does with the word it read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockWord {
    /// No owner TID: `cmpxchg(word -> new)` takes it. `FUTEX_OWNER_DIED`
    /// is kept (user space reports `EOWNERDEAD` from it), `FUTEX_WAITERS`
    /// is not (the caller adds it back if a `pi_state` still has waiters).
    Take { new: u32 },
    /// The caller's own TID is in the word: `EDEADLK`.
    SelfOwned,
    /// Owned by `tid`. `marked` is the word with `FUTEX_WAITERS` set, the
    /// value written before the caller sleeps (equal to the word when the
    /// bit is already there).
    Owned { tid: u32, marked: u32 },
}

/// Decide `LOCK_PI` on `word` for the caller `my_tid` (Linux
/// `futex_lock_pi_atomic`).
#[inline]
pub const fn lock_word(word: u32, my_tid: u32) -> LockWord {
    match word_owner(word) {
        None => LockWord::Take { new: (my_tid & FUTEX_TID_MASK) | (word & FUTEX_OWNER_DIED) },
        Some(t) if t == my_tid & FUTEX_TID_MASK => LockWord::SelfOwned,
        Some(t) => LockWord::Owned { tid: t, marked: word | FUTEX_WAITERS },
    }
}

/// The word an owner whose TID no longer names a task leaves behind:
/// taken over by `my_tid` when the word says `FUTEX_OWNER_DIED` (the bit
/// kept, `FUTEX_WAITERS` kept), else `None` (`ESRCH`).
#[inline]
pub const fn takeover_word(word: u32, my_tid: u32) -> Option<u32> {
    if word & FUTEX_OWNER_DIED == 0 {
        return None;
    }
    Some((my_tid & FUTEX_TID_MASK) | (word & (FUTEX_OWNER_DIED | FUTEX_WAITERS)))
}

/// `UNLOCK_PI`'s owner check: the caller's TID must be the word's.
#[inline]
pub const fn may_unlock(word: u32, my_tid: u32) -> bool {
    match word_owner(word) {
        Some(t) => t == my_tid & FUTEX_TID_MASK,
        None => false,
    }
}

/// The word the robust exit leaves when nobody waits on the `pi_state`:
/// `FUTEX_OWNER_DIED`, no TID, `FUTEX_WAITERS` kept (Linux
/// `handle_futex_death`).
#[inline]
pub const fn death_word(word: u32) -> u32 {
    (word & FUTEX_WAITERS) | FUTEX_OWNER_DIED
}

// ── The pi_state pool ────────────────────────────────────────────────────

/// One contended PI word: the graph object its waiters block on. Static
/// storage (never unmapped); recycled only after a grace period once it has
/// no waiters, so a walk inside a QSBR read section never sees it reused.
#[repr(C)]
pub struct PiState {
    /// First field: `rcu_free` recovers the entry from the head's address.
    rcu: core::cell::UnsafeCell<crate::qsbr::RcuHead>,
    waiters: PiWaiters,
    /// Tasks enqueued through `lock_pi_prepare` and not yet handed the word
    /// or gone on a timeout. It decides the handover's `FUTEX_WAITERS` bit
    /// only: a waiter the graph dequeues on `EDEADLK` (N9's commit) is not
    /// subtracted, so it can only err high, which costs one extra
    /// `UNLOCK_PI` (Linux always sets the bit). Under the bucket lock.
    nwait: AtomicU32,
}

// SAFETY: the `RcuHead` is touched only by `call_rcu` once per retirement;
// the rest is atomics and the graph's own object.
unsafe impl Sync for PiState {}

impl PiState {
    const fn new() -> Self {
        PiState {
            rcu: core::cell::UnsafeCell::new(crate::qsbr::RcuHead::new()),
            waiters: PiWaiters::new(EdgeKind::FutexPi),
            nwait: AtomicU32::new(0),
        }
    }

    /// The graph object, for diagnostics and ktests.
    pub fn waiters(&self) -> &PiWaiters {
        &self.waiters
    }
}

/// Pool size: one `pi_state` per task at most (a task waits on one word at
/// a time; a word needs a `pi_state` only while someone waits). 0 when
/// `FUTEX_PI` is n, so nothing is reserved.
pub const POOL_LEN: usize = if ENABLED { azos_limits::MAX_TASKS } else { 0 };

static POOL: [PiState; POOL_LEN] = [const { PiState::new() }; POOL_LEN];

/// Free stack: `head` is the last freed index + 1 (0 = empty), `NEXT[i]`
/// links it; `bump` hands out never-used entries first. O(1) both ways.
struct Free {
    head: u32,
    bump: u32,
}
static FREE: SpinLock<Free> = SpinLock::new(Free { head: 0, bump: 0 });
static NEXT: [AtomicU32; POOL_LEN] = [const { AtomicU32::new(0) }; POOL_LEN];
static IN_USE: AtomicU32 = AtomicU32::new(0);

fn alloc() -> Option<PiStateId> {
    let mut f = FREE.lock();
    let i = if f.head != 0 {
        let i = f.head - 1;
        f.head = NEXT[i as usize].load(Ordering::Relaxed);
        i
    } else if (f.bump as usize) < POOL_LEN {
        f.bump += 1;
        f.bump - 1
    } else {
        return None;
    };
    drop(f);
    POOL[i as usize].nwait.store(0, Ordering::Relaxed);
    IN_USE.fetch_add(1, Ordering::Relaxed);
    PiStateId::from_raw(i + 1)
}

fn free_now(i: usize) {
    let mut f = FREE.lock();
    NEXT[i].store(f.head, Ordering::Relaxed);
    f.head = i as u32 + 1;
    drop(f);
    IN_USE.fetch_sub(1, Ordering::Relaxed);
}

unsafe fn rcu_free(h: *mut crate::qsbr::RcuHead) {
    let base = POOL.as_ptr() as usize;
    free_now((h as usize - base) / core::mem::size_of::<PiState>());
}

/// The slot drops the state now; the entry is reused after a grace period.
fn retire(slot: &mut u32) {
    let Some(id) = PiStateId::from_raw(*slot) else { return };
    *slot = 0;
    let i = id.raw() as usize - 1;
    // No waiters: drop the owner too, so the graph keeps no stale edge.
    POOL[i].waiters.set_owner(None);
    // SAFETY: the entry left its slot just now and is retired once; it
    // returns to the free stack only from `rcu_free`.
    unsafe { crate::qsbr::call_rcu(POOL[i].rcu.get(), rcu_free) };
}

fn state_of(slot: u32) -> Option<&'static PiState> {
    PiStateId::from_raw(slot).and_then(|id| POOL.get(id.raw() as usize - 1))
}

/// `pi_state` entries in use (ktest, diagnostics). Relaxed.
pub fn states_in_use() -> u32 {
    IN_USE.load(Ordering::Relaxed)
}

// ── Hooks installed at boot ──────────────────────────────────────────────

/// A `&'static` trait object written once at boot, read lock-free after.
struct Once<T: ?Sized + 'static> {
    set: AtomicBool,
    v: core::cell::UnsafeCell<Option<&'static T>>,
}
// SAFETY: written once before `set` is published (Release), read after it
// is observed (Acquire); a second write panics.
unsafe impl<T: ?Sized + Sync> Sync for Once<T> {}
impl<T: ?Sized + Sync> Once<T> {
    const fn new() -> Self {
        Once { set: AtomicBool::new(false), v: core::cell::UnsafeCell::new(None) }
    }
    fn put(&self, v: &'static T) {
        assert!(!self.set.load(Ordering::Acquire), "pi_futex: hook registered twice");
        // SAFETY: single boot-time writer, no reader before `set`.
        unsafe { *self.v.get() = Some(v) };
        self.set.store(true, Ordering::Release);
    }
    fn get(&self) -> Option<&'static T> {
        if self.set.load(Ordering::Acquire) {
            // SAFETY: published above, never written again.
            unsafe { *self.v.get() }
        } else {
            None
        }
    }
}

static OPS: Once<dyn PiFutexOps> = Once::new();
static TABLE: Once<dyn PiTable> = Once::new();
/// The scheduler's slot -> TID map (`scheduler::tid_for_idx`): the word
/// holds TIDs, the graph and [`PiBucket`] speak scheduler slots.
static TID_OF: AtomicUsize = AtomicUsize::new(0);
/// Runtime canary `futex-pi-no-edge`.
static CANARY_NO_EDGE: AtomicBool = AtomicBool::new(false);

/// Install the slot -> TID map. Boot, once, before the first PI call.
pub fn register_tid_of(f: fn(TaskId) -> Option<u32>) {
    TID_OF.store(f as usize, Ordering::Release);
}

fn tid_of(t: TaskId) -> Option<u32> {
    let raw = TID_OF.load(Ordering::Acquire);
    if raw == 0 {
        return None;
    }
    // SAFETY: only `register_tid_of` stores, and it stores a `fn` of this type.
    let f: fn(TaskId) -> Option<u32> = unsafe { core::mem::transmute(raw) };
    f(t).filter(|&t| t != 0 && t <= FUTEX_TID_MASK)
}

/// Gate canary `futex-pi-no-edge`: [`block_commit`] drops the walk, so a
/// PI waiter never boosts the owner (the inversion program measures the
/// inversion; Linux's same binary does not).
pub fn canary_no_edge() {
    CANARY_NO_EDGE.store(true, Ordering::Relaxed);
}

/// What N9's PI dispatcher calls after `LockPiStep::Block`, with the bucket
/// lock dropped: `waitgraph::block_commit`, unless the `futex-pi-no-edge`
/// canary is armed (the waiter stays enqueued, the owner is never boosted).
pub fn block_commit(p: PendingBlock) -> Result<(), WaitError> {
    if CANARY_NO_EDGE.load(Ordering::Relaxed) {
        return Ok(());
    }
    waitgraph::block_commit(p)
}

// ── The implementation ───────────────────────────────────────────────────

/// N10's [`PiFutexOps`]. Boot registers `&PI_FUTEX`.
pub struct PiFutex;
pub static PI_FUTEX: PiFutex = PiFutex;

/// A raced `cmpxchg` on the word: re-read and decide again.
const RETRY: i32 = i32::MIN;

impl PiFutex {
    /// `from` gives the word up (UNLOCK_PI, `died` false; the robust exit,
    /// `died` true), `seen` being the word it owns. With waiters, the top
    /// one is handed the word in the kernel; else the word becomes
    /// `idle_word` (0, or the robust exit's [`death_word`]) and the state
    /// retires. The word is written first, so a fault leaves the graph
    /// untouched (Linux `wake_futex_pi`). `Err(RETRY)` on a raced word.
    fn give_up(
        &self,
        b: &mut dyn PiBucket,
        from: TaskId,
        seen: u32,
        died: bool,
        idle_word: u32,
    ) -> Result<Option<TaskId>, i32> {
        let ps = state_of(*b.pi_slot());
        let top = match ps {
            Some(p) if p.waiters.has_waiters() => waitgraph::top_waiter(&p.waiters).map(|(t, _)| (p, t)),
            _ => None,
        };
        let new = match top {
            Some((p, t)) => {
                let Some(top_tid) = tid_of(t) else { return Err(-ESRCH) };
                handover_word(top_tid, p.nwait.load(Ordering::Relaxed) > 1, died)
            }
            None => idle_word,
        };
        match b.cmpxchg_word(seen, new) {
            Err(UserFault) => return Err(-EFAULT),
            Ok(v) if v != seen => return Err(RETRY),
            Ok(_) => {}
        }
        let Some((p, t)) = top else {
            retire(b.pi_slot());
            return Ok(None);
        };
        let _ = waitgraph::release(from, &p.waiters);
        waitgraph::unblock(t, &p.waiters, UnblockReason::Acquired);
        p.nwait.fetch_sub(1, Ordering::Relaxed);
        p.waiters.set_owner(Some(t));
        if !p.waiters.has_waiters() {
            retire(b.pi_slot());
        }
        Ok(Some(t))
    }
}

impl PiFutexOps for PiFutex {
    fn lock_pi_prepare(&self, b: &mut dyn PiBucket, me: TaskId, try_only: bool) -> LockPiStep {
        let Some(my_tid) = tid_of(me) else { return LockPiStep::Err(-ESRCH) };
        loop {
            let w = match b.read_word() {
                Ok(w) => w,
                Err(UserFault) => return LockPiStep::Err(-EFAULT),
            };
            let (owner, marked) = match lock_word(w, my_tid) {
                LockWord::SelfOwned => return LockPiStep::Err(-EDEADLK),
                LockWord::Take { new } => {
                    let ps = state_of(*b.pi_slot());
                    let busy = ps.is_some_and(|p| p.waiters.has_waiters());
                    let new = if busy { new | FUTEX_WAITERS } else { new };
                    match b.cmpxchg_word(w, new) {
                        Err(UserFault) => return LockPiStep::Err(-EFAULT),
                        Ok(v) if v != w => continue,
                        Ok(_) => {}
                    }
                    match ps {
                        Some(p) if busy => p.waiters.set_owner(Some(me)),
                        Some(_) => retire(b.pi_slot()),
                        None => {}
                    }
                    return LockPiStep::Acquired;
                }
                LockWord::Owned { tid, marked } => match b.task_of_tid(tid) {
                    Some(t) if t == me => return LockPiStep::Err(-EDEADLK),
                    Some(t) => (t, marked),
                    // The owner is gone: an OWNER_DIED word is taken over.
                    None => {
                        let Some(new) = takeover_word(w, my_tid) else { return LockPiStep::Err(-ESRCH) };
                        match b.cmpxchg_word(w, new) {
                            Err(UserFault) => return LockPiStep::Err(-EFAULT),
                            Ok(v) if v != w => continue,
                            Ok(_) => {}
                        }
                        if let Some(p) = state_of(*b.pi_slot()) {
                            if p.waiters.has_waiters() {
                                p.waiters.set_owner(Some(me));
                            } else {
                                retire(b.pi_slot());
                            }
                        }
                        return LockPiStep::Acquired;
                    }
                },
            };
            if try_only {
                return LockPiStep::Err(-EAGAIN);
            }
            // Attach to (or create) the key's pi_state, owned by the word's TID.
            let ps = match state_of(*b.pi_slot()) {
                Some(p) => p,
                None => {
                    let Some(id) = alloc() else { return LockPiStep::Err(-ENOMEM) };
                    *b.pi_slot() = id.raw();
                    let p = &POOL[id.raw() as usize - 1];
                    p.waiters.set_owner(Some(owner));
                    p
                }
            };
            if ps.waiters.owner() != Some(owner) {
                ps.waiters.set_owner(Some(owner));
            }
            if marked != w {
                match b.cmpxchg_word(w, marked) {
                    Err(UserFault) => return LockPiStep::Err(-EFAULT),
                    Ok(v) if v != w => continue,
                    Ok(_) => {}
                }
            }
            match waitgraph::block_prepare(me, &ps.waiters) {
                Ok(p) => {
                    ps.nwait.fetch_add(1, Ordering::Relaxed);
                    return LockPiStep::Block(p);
                }
                Err(WaitError::NoOwner) => continue,
                Err(e) => return LockPiStep::Err(-e.errno()),
            }
        }
    }

    fn lock_pi_finish(&self, b: &mut dyn PiBucket, me: TaskId, timed_out: bool) -> i32 {
        let Some(my_tid) = tid_of(me) else { return -ESRCH };
        // Ownership is decided on the word alone: a handover wrote it.
        let w = match b.read_word() {
            Ok(w) => w,
            Err(UserFault) => return -EFAULT,
        };
        if may_unlock(w, my_tid) {
            return 0;
        }
        if let Some(ps) = state_of(*b.pi_slot()) {
            let why = if timed_out { UnblockReason::Timeout } else { UnblockReason::Interrupted };
            waitgraph::unblock(me, &ps.waiters, why);
            ps.nwait.fetch_sub(1, Ordering::Relaxed);
            if !ps.waiters.has_waiters() {
                retire(b.pi_slot());
            }
        }
        if timed_out { -ETIMEDOUT } else { -EINTR }
    }

    fn unlock_pi(&self, b: &mut dyn PiBucket, me: TaskId) -> Result<Option<TaskId>, i32> {
        let Some(my_tid) = tid_of(me) else { return Err(-EPERM) };
        loop {
            let w = b.read_word().map_err(|_| -EFAULT)?;
            if !may_unlock(w, my_tid) {
                return Err(-EPERM);
            }
            match self.give_up(b, me, w, false, 0) {
                Err(RETRY) => continue,
                r => return r,
            }
        }
    }

    fn cmp_requeue_pi(
        &self,
        _from: &mut dyn PiBucket,
        _to: &mut dyn PiBucket,
        _cmpval: u32,
        _nr_requeue: u32,
    ) -> Result<(u32, u32), i32> {
        // Part (b) of N10: the seam cannot yet dequeue `from`'s plain
        // waiters nor walk after both bucket locks drop. Today's answer.
        Err(-ENOSYS)
    }

    fn owner_died(&self, b: &mut dyn PiBucket, dead: TaskId) -> Result<Option<TaskId>, i32> {
        // An unknown TID: the word is left to the robust walk's own update.
        let Some(dead_tid) = tid_of(dead) else { return Err(-ESRCH) };
        loop {
            let w = b.read_word().map_err(|_| -EFAULT)?;
            if !may_unlock(w, dead_tid) {
                return Ok(None);
            }
            match self.give_up(b, dead, w, true, death_word(w)) {
                Err(RETRY) => continue,
                r => return r,
            }
        }
    }
}

/// Install N10's implementation. Called once at boot when `FUTEX_PI` is y;
/// N9's dispatcher reads [`ops`] and returns `ENOSYS` while it is `None`.
pub fn register(ops: &'static dyn PiFutexOps) {
    if ENABLED {
        OPS.put(ops);
    }
}

/// The registered implementation, if any. Any context. O(1).
pub fn ops() -> Option<&'static dyn PiFutexOps> {
    if !ENABLED {
        return None;
    }
    OPS.get()
}

// ── The system-call seam (N9 implements PiTable) ─────────────────────────

/// A decoded PI `futex` operation (the Linux personality decodes, N9's
/// table runs it under the key's bucket lock).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PiCmd {
    /// `FUTEX_LOCK_PI` / `FUTEX_LOCK_PI2`: absolute deadline in timer
    /// ticks (`None`: wait forever).
    Lock { deadline: Option<u64> },
    /// `FUTEX_TRYLOCK_PI`.
    TryLock,
    /// `FUTEX_UNLOCK_PI`.
    Unlock,
}

/// The futex table's PI entry points. **Implemented by N9** on its table:
/// find the key of `uaddr` in the caller's process (or `proc_id`'s), lock
/// its bucket, run [`PiFutexOps`] (on `Block`: drop the lock,
/// [`block_commit`], sleep to the deadline, relock, `lock_pi_finish`,
/// restart on `-EINTR`), wake what the ops return after unlocking.
pub trait PiTable: Sync {
    /// One PI `futex` call by the current task. Returns 0 or `-errno`.
    fn call(&self, uaddr: u64, cmd: PiCmd) -> i64;
    /// The robust-list walk of the exiting task `dead` (process `proc_id`)
    /// found the PI word at `uaddr`: [`PiFutexOps::owner_died`] under the
    /// bucket lock, then wake the new owner. `Some(woke)` once the word was
    /// decided there; `None` when it was left untouched (no such key, an
    /// `Err` from `owner_died`), so the walk writes `FUTEX_OWNER_DIED` itself.
    fn owner_died(&self, proc_id: u32, uaddr: u64, dead: TaskId) -> Option<bool>;
}

/// Install N9's table. Boot, once.
pub fn register_table(t: &'static dyn PiTable) {
    if ENABLED {
        TABLE.put(t);
    }
}

/// The Linux personality's PI `futex` entry: `-ENOSYS` while `FUTEX_PI` is
/// n or nothing is registered (today's answer).
pub fn sys_futex_pi(uaddr: u64, cmd: PiCmd) -> i64 {
    match (ops(), TABLE.get()) {
        (Some(_), Some(t)) if ENABLED => t.call(uaddr, cmd),
        _ => -(ENOSYS as i64),
    }
}

/// The robust exit's PI word: `None` when PI futexes are off or not
/// registered or the word was left untouched (the walk keeps its own word
/// update), else whether a waiter was handed the word.
pub fn robust_owner_died(proc_id: u32, uaddr: u64, dead: TaskId) -> Option<bool> {
    match (ops(), TABLE.get()) {
        (Some(_), Some(t)) if ENABLED => t.owner_died(proc_id, uaddr, dead),
        _ => None,
    }
}

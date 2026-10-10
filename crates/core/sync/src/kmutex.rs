// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sleeping adaptive kernel mutex (wave 15 N8), the first client of the
//! wait graph (`waitgraph`, N7). Kconfig `KMUTEX` (default n, depends on
//! `WAIT_GRAPH`) gates the call-site migration, not this type.
//!
//! # Semantics
//!
//! * Owner-held, not recursive, released by the owner only. The owner word
//!   ([`word`]) lives in the mutex, outside the graph node: the caller's TID
//!   (`waitqueue::caller_tid`, never 0) plus a WAITERS bit.
//! * **Fast path**: one compare-and-swap of the owner word (0 -> TID), no
//!   graph call, no lockdep beyond the held-stack push. Unlock: one load and
//!   one CAS back to 0 while WAITERS is clear.
//! * **Adaptive spin**: on contention, spin at most `KMUTEX_ADAPTIVE_SPIN`
//!   spin-hint iterations, and only while the owner is on a CPU (the
//!   registered [`Probes::on_cpu`]), nobody sleeps on the mutex yet, and
//!   the spinner has no pending reschedule (`preempt::need_resched`). 0, or
//!   no probes registered, never spins. An RT spinner and an RT owner on
//!   different CPUs is the F7 case: lockdep `RT_CROSS_CPU` reports it,
//!   nothing forbids it (owner question F7).
//! * **Slow path**: set WAITERS; with `WAIT_GRAPH` y and the probes
//!   registered, enter the wait graph behind the owner (`EdgeKind::Mutex`;
//!   the owner is boosted along the chain); sleep on the mutex's hashed
//!   park queue (Kconfig `KMUTEX_PARK_BUCKETS`) while the word still reads
//!   "that owner, with waiters"; on wake leave the graph and retry. The
//!   re-check runs under the queue's lock and the unlocker wakes under the
//!   same lock after it cleared the word, so a wake is never lost.
//! * **Unlock with WAITERS**: clear the word, `waitgraph::release` (unboost),
//!   wake the bucket; the woken waiters compete. Part (b), not yet here:
//!   only a task strictly more urgent than the top waiter may take the lock
//!   first (rt_mutex stealing); today any newcomer may, as with Linux's
//!   non-RT `mutex`.
//! * **F1 (owner, 09-10)**: a mutex is never held across a device wait. A
//!   path that waits for a device in the middle of a critical section
//!   releases the mutex around the wait with [`MutexGuard::unlocked_for_io`]
//!   or [`MutexGuard::unlock_for_io`] / [`IoUnlocked::relock`]; the critical
//!   section revalidates what it read before the wait.
//!   `lockdep::might_wait_device` notes a `Mutex` still held there
//!   (`lockdep::Kind::Mutex`). RT tasks do no block I/O at all
//!   (`RT_BLOCK_IO_CHECK` at the block layer's entry).
//!
//! # Graph protocol
//!
//! The graph's owner is set lazily by the first waiter, never by the fast
//! path. A waiter records the owner and enqueues (`block_prepare`) under the
//! bucket's graph lock after re-checking the word; the owner's slow unlock
//! clears the word and calls `waitgraph::release` under the same lock. A
//! marked word (WAITERS) forces the owner's slow unlock, so a recorded
//! owner is always cleared by its own unlock. The walk (`block_commit`)
//! runs after the lock is dropped (the graph's one-SpinLock rule).
//!
//! # Context
//!
//! `lock` and the guard's relock: task context, preemption on, no SpinLock
//! held (`lockdep::might_sleep`). `try_lock`: also with SpinLocks held and
//! preemption off, never in an interrupt handler (an interrupt has no
//! owner identity to boost). Unlock: wherever the lock was taken.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use crate::spinlock::SpinLock;
use crate::waitgraph::{self, EdgeKind, PiWaiters, UnblockReason, WaitError};
use crate::waitqueue::WaitQueue;

/// Kconfig `KMUTEX_ADAPTIVE_SPIN`: the most spin-hint iterations a
/// contender spends while the owner runs before it blocks. 0: block at once.
pub const ADAPTIVE_SPIN: usize = azos_limits::KMUTEX_ADAPTIVE_SPIN;

/// Kconfig `KMUTEX`: call sites use `Mutex` instead of `PiMutex` and the
/// FAT32/virtio-blk SpinLocks. n: this type exists but nothing uses it.
pub const ENABLED: bool = azos_limits::KMUTEX;

/// Kconfig `KMUTEX_PARK_BUCKETS`: the hashed sleep queues.
pub const PARK_BUCKETS: usize = azos_limits::KMUTEX_PARK_BUCKETS;

/// The owner word: pure encode/decode, host-tested.
pub mod word {
    /// No owner, no waiters.
    pub const FREE: u32 = 0;
    /// Some task sleeps (or is about to) on this mutex: the unlock takes the
    /// slow path and wakes the bucket.
    pub const WAITERS: u32 = 1 << 31;
    /// The owner bits.
    pub const OWNER_MASK: u32 = !WAITERS;
    /// The owner recorded before the scheduler names tasks (boot context,
    /// `caller_tid() == u32::MAX`). Never a real TID.
    pub const BOOT_OWNER: u32 = OWNER_MASK;

    /// The word that records `tid` as owner (no waiters). `tid` 0 is no
    /// task; it and TIDs past the mask fold into [`BOOT_OWNER`].
    #[inline]
    pub const fn owned_by(tid: u32) -> u32 {
        if tid == 0 || tid >= OWNER_MASK { BOOT_OWNER } else { tid }
    }

    /// The owner, if any.
    #[inline]
    pub const fn owner(w: u32) -> Option<u32> {
        let o = w & OWNER_MASK;
        if o == 0 { None } else { Some(o) }
    }

    /// The unlock may take the one-CAS path: nobody is marked as waiting.
    #[inline]
    pub const fn fast_unlockable(w: u32) -> bool {
        owner(w).is_some() && w & WAITERS == 0
    }

    /// A contender that read `w` sleeps on it: owned, waiters marked.
    #[inline]
    pub const fn sleep_on(w: u32) -> bool {
        owner(w).is_some() && w & WAITERS != 0
    }
}

/// The scheduler facts a mutex needs and the sync crate cannot read itself.
/// Registered once at boot by the kernel ([`set_probes`]); until then the
/// mutex never spins and never enters the wait graph (it still excludes and
/// sleeps). Both run in task context.
pub struct Probes {
    /// Task `tid` is executing on some CPU right now (may be stale by one
    /// switch; a hint for the adaptive spin). Lock-free, O(NR_CPUS) at most.
    pub on_cpu: fn(tid: u32) -> bool,
    /// The wait-graph id (`waitgraph::TaskId`, the scheduler slot) of task
    /// `tid`, `None` when it names no live task. Lock-free.
    pub graph_id: fn(tid: u32) -> Option<waitgraph::TaskId>,
}

static PROBES: AtomicPtr<Probes> = AtomicPtr::new(core::ptr::null_mut());

/// Install the scheduler probes (kernel boot, once, before any contention).
pub fn set_probes(p: &'static Probes) {
    PROBES.store(p as *const Probes as *mut Probes, Ordering::Release);
}

#[inline]
fn probes() -> Option<&'static Probes> {
    // SAFETY: only `set_probes` stores, and only from a `&'static`.
    unsafe { PROBES.load(Ordering::Acquire).as_ref() }
}

/// Runtime canary `canary=kmutex-io-held`: [`MutexGuard::unlocked_for_io`]
/// keeps the mutex across the device wait (rule F1 broken). The ktest
/// `kmutex_unlocked_for_io` goes red and lockdep notes the Mutex held
/// across `might_wait_device`.
static CANARY_IO_HELD: AtomicBool = AtomicBool::new(false);

/// Arm the `kmutex-io-held` canary (boot, from the command line).
pub fn canary_io_held() {
    CANARY_IO_HELD.store(true, Ordering::Relaxed);
}

#[allow(clippy::declare_interior_mutable_const)]
const PARK_INIT: WaitQueue = WaitQueue::new();
/// Where contended tasks sleep, hashed by mutex address.
static PARK: [WaitQueue; PARK_BUCKETS] = [PARK_INIT; PARK_BUCKETS];
#[allow(clippy::declare_interior_mutable_const)]
const GRAPH_LOCK_INIT: SpinLock<()> = SpinLock::new(());
/// Serialises the graph's owner record against the owner's slow unlock
/// (module doc, graph protocol). Taken only with `WAIT_GRAPH` y.
static GRAPH_LOCK: [SpinLock<()>; PARK_BUCKETS] = [GRAPH_LOCK_INIT; PARK_BUCKETS];

#[inline]
fn bucket(addr: usize) -> usize {
    // Fibonacci hash of the address; neighbouring statics spread out.
    let h = (addr as u64 >> 3).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    ((h >> 40) as usize) % PARK_BUCKETS
}

/// The caller's owner identity (its TID, or [`word::BOOT_OWNER`]).
#[inline]
fn me() -> u32 {
    word::owned_by(crate::waitqueue::caller_tid())
}

/// A sleeping, priority-inheriting, adaptive mutual-exclusion lock.
pub struct Mutex<T: ?Sized> {
    /// [`word`]: owner TID | WAITERS. The fast path's one CAS.
    pub(crate) owner: AtomicU32,
    /// The object's node in the wait graph (`EdgeKind::Mutex`).
    waiters: PiWaiters,
    /// Lockdep class: the constructor's call site (`lockdep` feature only).
    #[cfg(feature = "lockdep")]
    class: crate::lockdep::LockClass,
    /// Lockdep (rule F7): the holder's CPU and RT-ness, `lockdep::holder_word`.
    #[cfg(feature = "lockdep")]
    ld_holder: AtomicU32,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialised by the owner word (contract above).
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// An unlocked mutex holding `v`. `const`, so a `static` needs no init.
    /// The lockdep class is the caller's site.
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Mutex {
            owner: AtomicU32::new(word::FREE),
            waiters: PiWaiters::new(EdgeKind::Mutex),
            #[cfg(feature = "lockdep")]
            class: crate::lockdep::LockClass::here(crate::lockdep::Kind::Mutex),
            #[cfg(feature = "lockdep")]
            ld_holder: AtomicU32::new(0),
            data: UnsafeCell::new(v),
        }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    #[inline]
    fn addr(&self) -> usize {
        self as *const Self as *const u8 as usize
    }

    /// One CAS FREE -> `me`. The fast path, `try_lock` and the spin.
    #[inline]
    fn try_take(&self, me: u32) -> bool {
        self.owner
            .compare_exchange(word::FREE, me, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    #[inline]
    #[track_caller]
    fn guard(&self) -> MutexGuard<'_, T> {
        #[cfg(feature = "lockdep")]
        {
            crate::lockdep::acquired(&self.class, self.addr(), crate::lockdep::Kind::Mutex, false,
                core::panic::Location::caller());
            self.ld_holder.store(crate::lockdep::holder_word(), Ordering::Relaxed);
        }
        MutexGuard { lock: self, _not_send: core::marker::PhantomData }
    }

    /// Acquire, sleeping if needed (fast path, adaptive spin, slow path as
    /// in the module doc). Task context, no SpinLock held. Cost: fast path
    /// one CAS; slow path one graph block, O(PI_MAX_DEPTH).
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        #[cfg(feature = "lockdep")]
        {
            crate::lockdep::might_sleep("Mutex::lock");
            crate::lockdep::check(&self.class, self.addr(), crate::lockdep::Kind::Mutex,
                core::panic::Location::caller());
        }
        let me = me();
        if !self.try_take(me) {
            self.lock_slow(me);
        }
        self.guard()
    }

    #[cold]
    #[inline(never)]
    #[track_caller]
    fn lock_slow(&self, me: u32) {
        let mut w = self.owner.load(Ordering::Relaxed);
        debug_assert!(
            me == word::BOOT_OWNER || word::owner(w) != Some(me),
            "kmutex: recursive Mutex::lock"
        );
        #[cfg(feature = "lockdep")]
        crate::lockdep::contended(&self.class, self.addr(), crate::lockdep::Kind::Mutex,
            self.ld_holder.load(Ordering::Relaxed));
        if self.spin(me) {
            return;
        }
        let park = &PARK[bucket(self.addr())];
        loop {
            let Some(owner) = word::owner(w) else {
                // Free. Keep a lingering WAITERS so the next unlock wakes.
                match self.owner.compare_exchange(w, me | (w & word::WAITERS),
                    Ordering::Acquire, Ordering::Relaxed)
                {
                    Ok(_) => return,
                    Err(now) => { w = now; continue; }
                }
            };
            if w & word::WAITERS == 0 {
                if let Err(now) = self.owner.compare_exchange(w, w | word::WAITERS,
                    Ordering::Relaxed, Ordering::Relaxed)
                {
                    w = now;
                    continue;
                }
                w |= word::WAITERS;
            }
            let in_graph = self.graph_block(me, owner, w);
            park.wait_if(|| self.owner.load(Ordering::SeqCst) == w);
            if let Some(id) = in_graph {
                waitgraph::unblock(id, &self.waiters, UnblockReason::Acquired);
            }
            w = self.owner.load(Ordering::Relaxed);
        }
    }

    /// The adaptive spin: true if the lock was taken while spinning.
    #[inline]
    fn spin(&self, me: u32) -> bool {
        if ADAPTIVE_SPIN == 0 {
            return false;
        }
        let Some(p) = probes() else { return false };
        for _ in 0..ADAPTIVE_SPIN {
            let w = self.owner.load(Ordering::Relaxed);
            if w == word::FREE {
                if self.try_take(me) {
                    return true;
                }
            } else if !word::fast_unlockable(w) {
                // Sleepers are queued: join them, do not overtake.
                return false;
            } else if !(p.on_cpu)(w) || crate::preempt::need_resched() {
                return false;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Enter the wait graph behind `owner`, the word still being `w`. Only
    /// with `WAIT_GRAPH` y and the probes registered. Returns the waiter's
    /// graph id when it is enqueued (the caller unblocks after it wakes);
    /// `None` when skipped or the owner left (the caller still sleeps on
    /// the word: exclusion never depends on the graph).
    #[inline]
    fn graph_block(&self, me: u32, owner: u32, w: u32) -> Option<waitgraph::TaskId> {
        if !waitgraph::ENABLED {
            return None;
        }
        let p = probes()?;
        let id = (p.graph_id)(me)?;
        let oid = (p.graph_id)(owner)?;
        let pending = {
            let _g = GRAPH_LOCK[bucket(self.addr())].lock();
            if self.owner.load(Ordering::Relaxed) != w {
                return None;
            }
            if self.waiters.owner() != Some(oid) {
                self.waiters.set_owner(Some(oid));
            }
            match waitgraph::block_prepare(id, &self.waiters) {
                Ok(pb) => pb,
                Err(WaitError::NoOwner) => return None,
                Err(e) => panic!("kmutex: the wait graph refused a Mutex block: {:?}", e),
            }
        };
        match waitgraph::block_commit(pending) {
            Ok(()) | Err(WaitError::NoOwner) => Some(id),
            Err(e) => panic!("kmutex: the wait graph refused a Mutex block: {:?}", e),
        }
    }

    /// Acquire only if free right now; never spins or sleeps. Any context
    /// but an interrupt handler. One CAS.
    #[track_caller]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self.try_take(me()) { Some(self.guard()) } else { None }
    }

    /// Owned by someone right now (racy hint; diagnostics and asserts).
    pub fn is_locked(&self) -> bool {
        word::owner(self.owner.load(Ordering::Relaxed)).is_some()
    }

    /// The wait-graph node, for clients that name this mutex in a
    /// `blocked_on` report or a trace.
    pub fn wait_node(&self) -> &PiWaiters {
        &self.waiters
    }

    /// Exclusive access without locking (the borrow proves no guard exists).
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Release: one CAS while no waiter is marked, else the slow unlock.
    #[inline]
    fn unlock(&self) {
        #[cfg(feature = "lockdep")]
        {
            self.ld_holder.store(0, Ordering::Relaxed);
            crate::lockdep::release(self.addr(), crate::lockdep::Kind::Mutex);
        }
        let w = self.owner.load(Ordering::Relaxed);
        if !word::fast_unlockable(w)
            || self.owner.compare_exchange(w, word::FREE, Ordering::Release, Ordering::Relaxed).is_err()
        {
            self.unlock_slow();
        }
    }

    #[cold]
    #[inline(never)]
    fn unlock_slow(&self) {
        let b = bucket(self.addr());
        let old = if waitgraph::ENABLED {
            let _g = GRAPH_LOCK[b].lock();
            let old = self.owner.swap(word::FREE, Ordering::Release);
            let id = word::owner(old).and_then(|o| probes().and_then(|p| (p.graph_id)(o)));
            if let Some(id) = id {
                if self.waiters.owner() == Some(id) {
                    let _ = waitgraph::release(id, &self.waiters);
                    self.waiters.set_owner(None);
                }
            }
            old
        } else {
            self.owner.swap(word::FREE, Ordering::Release)
        };
        debug_assert!(word::owner(old).is_some(), "kmutex: unlock of a free Mutex");
        debug_assert!(
            old & word::OWNER_MASK == word::BOOT_OWNER || word::owner(old) == Some(me()),
            "kmutex: Mutex released by a task that does not own it"
        );
        if old & word::WAITERS != 0 {
            PARK[b].wake_all();
        }
    }
}

/// Proof that the current task owns a [`Mutex`]. Unlocks on drop. Not
/// `Send`: the owner releases it.
pub struct MutexGuard<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<'a, T: ?Sized> MutexGuard<'a, T> {
    /// F1: release the mutex, run `wait` (a device wait: block I/O
    /// completion, a virtio queue drain), and re-acquire before returning.
    /// The `&mut self` borrow means no reference into the data survives the
    /// gap; the caller revalidates any state it read before. Task context,
    /// no other lock held during `wait`. Cost: one unlock + one lock.
    #[track_caller]
    pub fn unlocked_for_io<R>(&mut self, what: &'static str, wait: impl FnOnce() -> R) -> R {
        if CANARY_IO_HELD.load(Ordering::Relaxed) {
            crate::lockdep::might_wait_device(what);
            return wait();
        }
        self.lock.unlock();
        crate::lockdep::might_wait_device(what);
        let r = wait();
        // Re-acquired: this guard owns it again.
        core::mem::forget(self.lock.lock());
        r
    }

    /// F1, split form for waits that cannot be a closure: release now; the
    /// returned token re-acquires with [`IoUnlocked::relock`]. Dropping the
    /// token without relocking is allowed (the critical section ended).
    pub fn unlock_for_io(self) -> IoUnlocked<'a, T> {
        let lock = self.lock;
        drop(self);
        IoUnlocked { lock }
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves ownership.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard proves exclusive ownership.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    /// Unlock: fast path one load + one CAS; with waiters,
    /// `waitgraph::release` and a wake of the bucket.
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

/// A [`Mutex`] released around a device wait by [`MutexGuard::unlock_for_io`].
#[must_use = "relock() it, or drop it if the critical section is over"]
pub struct IoUnlocked<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
}

impl<'a, T: ?Sized> IoUnlocked<'a, T> {
    /// Re-acquire (may sleep, same contract as `Mutex::lock`).
    #[track_caller]
    pub fn relock(self) -> MutexGuard<'a, T> {
        self.lock.lock()
    }
}

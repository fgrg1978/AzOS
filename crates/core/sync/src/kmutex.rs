// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sleeping adaptive kernel mutex (wave 15 N8), the first client of the
//! wait graph (`waitgraph`, N7). It is the kernel's only sleeping lock with
//! priority inheritance. Its holder is counted per task in [`crate::held`]
//! (the panic policy's `mutex-held` check).
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
//!   different CPUs is the F7 case: lockdep `RT_CROSS_CPU` notes it,
//!   nothing forbids it (owner decision F7: report-only).
//! * **Slow path**: set WAITERS; with `WAIT_GRAPH` y and the probes
//!   registered, enter the wait graph behind the owner (`EdgeKind::Mutex`;
//!   the owner is boosted along the chain); sleep on the mutex's hashed
//!   park queue (Kconfig `KMUTEX_PARK_BUCKETS`) while the word still reads
//!   "that owner, with waiters" and the bucket's wake generation is the one
//!   sampled before that word was read; on wake leave the graph and retry.
//!   The re-check runs under the queue's lock and the unlocker bumps the
//!   generation, then wakes under the same lock, after it moved the word, so
//!   a wake is never lost, not even when the word has come back to the same
//!   value (the steal rule's ownerless WAITERS after taken-and-released).
//! * **Unlock with WAITERS**: `waitgraph::release` (unboost), wake the
//!   bucket. With `KMUTEX_STEAL_RULE` y and a waiter still queued in the
//!   graph, the word becomes WAITERS without an owner instead of FREE: the
//!   one-CAS fast path fails, and the slow path lets a task take the lock
//!   only if it is the graph's top waiter or strictly more urgent than it
//!   ([`may_take`], `waitgraph::PiAttr`; rt_mutex lock stealing). Others
//!   sleep until the next unlock. n: any newcomer may take it ahead of the
//!   woken waiters, as with Linux's non-RT `mutex`.
//! * A newcomer the steal rule holds back joins the graph before it sleeps
//!   (`waitgraph::block_prepare_ownerless`: the released object has no
//!   owner yet), so whoever takes the mutex next inherits from it as well
//!   (owner decision 10-10, N7b).
//! * A graph waiter stays queued across its wake-ups and leaves the graph
//!   only once it owns the mutex, so the top waiter a stealer is compared
//!   with is the one that was woken. A task that takes the mutex while
//!   waiters remain queued records itself as the graph owner at once, so
//!   the sleepers keep boosting whoever holds it.
//! * **Owner died (owner decision 10-10)**: a task that exits holding a
//!   Mutex with sleepers queued in the graph is a kernel bug, but the chain
//!   must not hang on it. The graph calls [`OWNER_DIED_HOOK`] (registered by
//!   [`register_owner_died`]): under the bucket's graph lock the word loses
//!   its dead owner (WAITERS without owner under the steal rule, else FREE,
//!   exactly as `unlock_slow` leaves it) and the bucket is woken, so the
//!   top waiter takes the mutex through the normal slow path. Counted in
//!   [`owner_died_count`]; the data is handed over as the dead owner left it,
//!   and the next owner learns it from [`MutexGuard::owner_died`] (owner
//!   decision 10-10; `lock`'s signature is unchanged). The hook leaves the
//!   word marked WAITERS, so that owner's unlock takes the slow path, which
//!   clears the flag: the fast paths never read it.
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
use crate::waitgraph::{self, EdgeKind, PiAttr, PiWaiters, UnblockReason, WaitError};
use crate::waitqueue::WaitQueue;

/// Kconfig `KMUTEX_ADAPTIVE_SPIN`: the most spin-hint iterations a
/// contender spends while the owner runs before it blocks. 0: block at once.
pub const ADAPTIVE_SPIN: usize = azos_limits::KMUTEX_ADAPTIVE_SPIN;

/// Kconfig `KMUTEX_STEAL_RULE`: after a contended release only the top
/// waiter, or a strictly more urgent task, takes the mutex ([`may_take`]).
pub const STEAL_RULE: bool = azos_limits::KMUTEX_STEAL_RULE;

/// The steal rule as a pure decision (host-tested). A caller of effective
/// attribute `me` finds the mutex free; `top` is the graph's top waiter's
/// effective attribute (`None`: nobody is queued), `me_is_top` says the
/// caller is that waiter. It may take the mutex if nobody is queued, if it
/// is the top waiter, or if it is strictly more urgent (`PiAttr`'s order:
/// greater = more urgent). A caller without an attribute (no scheduler
/// slot) never overtakes a queued waiter. O(1).
#[inline]
pub fn may_take(me: Option<PiAttr>, top: Option<PiAttr>, me_is_top: bool) -> bool {
    match (top, me) {
        (None, _) => true,
        _ if me_is_top => true,
        (Some(t), Some(m)) => m > t,
        (Some(_), None) => false,
    }
}

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

    /// The task the held-lock count ([`crate::held`]) charges for the owner
    /// in `w`: its TID, or `u32::MAX` for the boot owner (and for no owner).
    #[inline]
    pub const fn held_key(w: u32) -> u32 {
        match owner(w) {
            Some(o) if o != BOOT_OWNER => o,
            _ => u32::MAX,
        }
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
    /// The effective wait-graph attribute of task `tid` (its boost if the
    /// graph holds one, else its base attribute from the scheduler's
    /// classes), `None` when it names no live task. The steal rule's
    /// comparison. Lock-free.
    pub attr: fn(tid: u32) -> Option<PiAttr>,
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

/// Runtime canary `canary=kmutex-steal-any`: the slow unlock frees the
/// word even with a waiter queued, so any newcomer overtakes it (the steal
/// rule broken). With `WAIT_GRAPH` y the ktest
/// `kmutex_steal_rule_holds_for_top_waiter` goes red.
static CANARY_STEAL_ANY: AtomicBool = AtomicBool::new(false);

/// Arm the `kmutex-steal-any` canary (boot, from the command line).
pub fn canary_steal_any() {
    CANARY_STEAL_ANY.store(true, Ordering::Relaxed);
}

/// Runtime canary `canary=kmutex-park-aba`: a newcomer the steal rule holds
/// back spins until the word has moved and come back before it parks, and
/// its park ignores the bucket's wake generation ([`WAKE_GEN`]), so the
/// word's ABA (`WAITERS` -> taken -> `WAITERS`, the wake already gone) parks
/// it for good. With `WAIT_GRAPH` y the ktest
/// `kmutex_held_back_newcomer_is_in_the_graph` goes red.
static CANARY_PARK_ABA: AtomicBool = AtomicBool::new(false);

/// Arm the `kmutex-park-aba` canary (boot, from the command line).
pub fn canary_park_aba() {
    CANARY_PARK_ABA.store(true, Ordering::Relaxed);
}

/// The `kmutex-park-aba` window's bound, in spin iterations.
const CANARY_WINDOW_SPINS: u32 = 1 << 27;

#[allow(clippy::declare_interior_mutable_const)]
const GEN_INIT: AtomicU32 = AtomicU32::new(0);
/// Per-bucket wake generation, bumped before every wake of [`PARK`]
/// ([`wake_bucket`]). A sleeper parks only while both its word and the
/// generation it sampled with that word are unchanged: the word alone has an
/// ABA (a release leaves `WAITERS` again, the steal rule's ownerless hold),
/// and a wake that ran before the sleeper enqueued would be lost.
static WAKE_GEN: [AtomicU32; PARK_BUCKETS] = [GEN_INIT; PARK_BUCKETS];

/// Wake bucket `b`'s sleepers, after the caller moved a word in it.
#[inline]
fn wake_bucket(b: usize) {
    // SeqCst RMW after the word's Release swap: a sleeper whose Acquire
    // sample reads the new generation also reads the moved word.
    WAKE_GEN[b].fetch_add(1, Ordering::SeqCst);
    PARK[b].wake_all();
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

/// Offset of a Mutex's graph node from its owner word (the same for every
/// `T`: `repr(C)` and both fields precede everything `T`-dependent).
const WAITERS_OFFSET: usize = core::mem::offset_of!(Mutex<()>, waiters);
/// Offset of a Mutex's owner-died flag (same argument as `WAITERS_OFFSET`).
const DIED_OFFSET: usize = core::mem::offset_of!(Mutex<()>, died);

/// Mutexes whose owner exited holding them with sleepers queued.
static OWNER_DIED: AtomicU32 = AtomicU32::new(0);

/// How many Mutexes were handed over from a dead owner (ktests, panic
/// reports). Relaxed.
pub fn owner_died_count() -> u32 {
    OWNER_DIED.load(Ordering::Relaxed)
}

/// The graph's [`waitgraph::OwnerDiedHook`] for `EdgeKind::Mutex`.
pub struct OwnerDiedHook;

/// Registered by [`register_owner_died`].
pub static OWNER_DIED_HOOK: OwnerDiedHook = OwnerDiedHook;

/// Install the owner-died hook (kernel boot, once, with `WAIT_GRAPH` y).
/// Every `EdgeKind::Mutex` node in the kernel's graph is then a
/// `Mutex`'s own (tests use their own graphs).
pub fn register_owner_died() {
    if waitgraph::ENABLED {
        waitgraph::register_owner_died(EdgeKind::Mutex, &OWNER_DIED_HOOK);
    }
}

impl waitgraph::OwnerDiedHook for OwnerDiedHook {
    fn owner_died(&self, obj: &PiWaiters, dead: waitgraph::TaskId) {
        let addr = obj as *const PiWaiters as usize - WAITERS_OFFSET;
        // SAFETY: in the kernel graph an `EdgeKind::Mutex` node is only ever
        // the `waiters` field of a `Mutex` (`register_owner_died`), at
        // `WAITERS_OFFSET` after its `owner` word; it has waiters, so it is
        // live (the graph's lifetime contract).
        let word_ref = unsafe { &*(addr as *const AtomicU32) };
        let b = bucket(addr);
        let old = {
            let _g = GRAPH_LOCK[b].lock();
            let cur = word_ref.load(Ordering::Relaxed);
            let Some(o) = word::owner(cur) else { return };
            // Only the dead task's word: a TID that no longer resolves is
            // the dead one too (the slot is still a Zombie at this point).
            // Between the graph's detach and this lock a contender's
            // `graph_block` may re-record the dead owner (the word still
            // names it); the graph's exit loop then pops the object again
            // and this second call finds the word no longer the dead
            // task's and returns (so `owner_died` may count one extra). No
            // re-record is possible once the word is freed below.
            match probes().and_then(|p| (p.graph_id)(o)) {
                Some(id) if id != dead => return,
                _ => {}
            }
            // SAFETY: as `word_ref`; `died` is the field after `owner`.
            let died = unsafe { &*((addr + DIED_OFFSET) as *const AtomicBool) };
            died.store(true, Ordering::Relaxed);
            // Always marked (WAITERS, no owner), whatever the steal rule:
            // the next owner's unlock then takes the slow path, which clears
            // `died`; a free marked word is taken through the slow path.
            word_ref.swap(word::WAITERS, Ordering::Release)
        };
        OWNER_DIED.fetch_add(1, Ordering::Relaxed);
        if old & word::WAITERS != 0 {
            wake_bucket(b);
        }
    }
}

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
///
/// `repr(C)`: `owner` at offset 0 and `waiters` at [`WAITERS_OFFSET`] for
/// every `T`, so the owner-died hook finds the word from the graph node.
#[repr(C)]
pub struct Mutex<T: ?Sized> {
    /// [`word`]: owner TID | WAITERS. The fast path's one CAS.
    pub(crate) owner: AtomicU32,
    /// The previous owner exited holding it (owner-died hook); cleared by
    /// the next owner's unlock ([`MutexGuard::owner_died`]). Sits in the
    /// padding before `waiters`.
    died: AtomicBool,
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
            died: AtomicBool::new(false),
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
    fn guard(&self, me: u32) -> MutexGuard<'_, T> {
        #[cfg(feature = "lockdep")]
        {
            crate::lockdep::acquired(&self.class, self.addr(), crate::lockdep::Kind::Mutex, false,
                core::panic::Location::caller());
            self.ld_holder.store(crate::lockdep::holder_word(), Ordering::Relaxed);
        }
        crate::held::held_raise(word::held_key(me), self.addr());
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
        self.guard(me)
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
        let b = bucket(self.addr());
        let park = &PARK[b];
        // Every `w` is sampled after a generation `g`: `park` sleeps only
        // while both are unchanged (an older `g` only wakes more often).
        let gen = &WAKE_GEN[b];
        let aba = CANARY_PARK_ABA.load(Ordering::Relaxed);
        let sleep = |w: u32, g: u32, aba: bool| self.owner.load(Ordering::SeqCst) == w
            && (aba || gen.load(Ordering::Relaxed) == g);
        let mut g = gen.load(Ordering::Acquire);
        w = self.owner.load(Ordering::Relaxed);
        // The graph id while this task is queued in the wait graph: it stays
        // queued across wake-ups and leaves only once it owns the mutex.
        let mut in_graph: Option<waitgraph::TaskId> = None;
        loop {
            let Some(owner) = word::owner(w) else {
                // Free. Keep a lingering WAITERS so the next unlock wakes.
                match self.take_free(me, w, in_graph) {
                    Take::Taken => return,
                    Take::Changed(now) => { w = now; continue; }
                    Take::Defer(queued) => {
                        // The steal rule: a queued waiter goes first. Sleep
                        // until the next unlock (the word keeps WAITERS),
                        // queued in the graph so the taker inherits from
                        // this task too (owner decision 10-10, N7b).
                        in_graph = queued;
                        if aba {
                            self.canary_window(w);
                        }
                        park.wait_if(|| sleep(w, g, aba));
                        g = gen.load(Ordering::Acquire);
                        w = self.owner.load(Ordering::Relaxed);
                        continue;
                    }
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
            in_graph = self.graph_block(me, owner, w, in_graph);
            park.wait_if(|| sleep(w, g, false));
            g = gen.load(Ordering::Acquire);
            w = self.owner.load(Ordering::Relaxed);
        }
    }

    /// The free-word branch of the slow path: take the mutex (word `w`, no
    /// owner) unless the steal rule defers to a queued waiter. A graph
    /// waiter (`in_graph`) leaves the graph once it owns the mutex; a taker
    /// that leaves waiters queued becomes their graph owner. The decision,
    /// the CAS and the graph update run under the bucket's graph lock, so
    /// the top waiter compared with is the queued one.
    fn take_free(&self, me: u32, w: u32, in_graph: Option<waitgraph::TaskId>) -> Take {
        let next = me | (w & word::WAITERS);
        let p = if waitgraph::ENABLED { probes() } else { None };
        let Some(p) = p else {
            return match self.owner.compare_exchange(w, next, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => Take::Taken,
                Err(now) => Take::Changed(now),
            };
        };
        let my_id = in_graph.or_else(|| (p.graph_id)(me));
        let _g = GRAPH_LOCK[bucket(self.addr())].lock();
        if STEAL_RULE {
            let top = waitgraph::top_waiter(&self.waiters);
            let me_is_top = top.is_some_and(|(t, _)| Some(t) == my_id);
            let mine = if top.is_some() && !me_is_top { (p.attr)(me) } else { None };
            if !may_take(mine, top.map(|(_, a)| a), me_is_top) {
                let now = self.owner.load(Ordering::Relaxed);
                if now != w {
                    return Take::Changed(now);
                }
                // Held back: join the ownerless object's waiters (no walk
                // yet, no owner); the taker's `set_owner` links and boosts.
                if in_graph.is_some() {
                    return Take::Defer(in_graph);
                }
                let Some(id) = my_id else { return Take::Defer(None) };
                return match waitgraph::block_prepare_ownerless(id, &self.waiters) {
                    // Ownerless: the commit has no cycle to find, no walk to
                    // run; it only closes the pending block.
                    Ok(pb) => Take::Defer(waitgraph::block_commit(pb).ok().map(|()| id)),
                    Err(_) => Take::Defer(None),
                };
            }
        }
        if let Err(now) = self.owner.compare_exchange(w, next, Ordering::Acquire, Ordering::Relaxed) {
            return Take::Changed(now);
        }
        if let Some(id) = in_graph {
            waitgraph::unblock(id, &self.waiters, UnblockReason::Acquired);
        }
        if self.waiters.has_waiters() {
            // The sleepers boost the new owner (re-attach and walk).
            self.waiters.set_owner(my_id);
        }
        Take::Taken
    }

    /// Canary `kmutex-park-aba`: spin (preemptible) until the word left `w`
    /// and came back, or the bound runs out.
    #[cold]
    fn canary_window(&self, w: u32) {
        let mut moved = false;
        for _ in 0..CANARY_WINDOW_SPINS {
            if self.owner.load(Ordering::Relaxed) != w {
                moved = true;
            } else if moved {
                return;
            }
            core::hint::spin_loop();
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
    /// `queued`: the waiter is already in the graph from an earlier pass;
    /// only the owner record is refreshed (a newcomer may have taken the
    /// mutex through the fast path, which records nothing).
    #[inline]
    fn graph_block(&self, me: u32, owner: u32, w: u32, queued: Option<waitgraph::TaskId>)
        -> Option<waitgraph::TaskId>
    {
        if !waitgraph::ENABLED {
            return None;
        }
        let Some(p) = probes() else { return queued };
        let Some(oid) = (p.graph_id)(owner) else { return queued };
        if let Some(id) = queued {
            let _g = GRAPH_LOCK[bucket(self.addr())].lock();
            if self.owner.load(Ordering::Relaxed) == w && self.waiters.owner() != Some(oid) {
                self.waiters.set_owner(Some(oid));
            }
            return Some(id);
        }
        let id = (p.graph_id)(me)?;
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

    /// Acquire only if free right now; never spins or sleeps. Fails while
    /// the steal rule holds a released mutex for its queued top waiter. Any context
    /// but an interrupt handler. One CAS.
    #[track_caller]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let me = me();
        if self.try_take(me) { Some(self.guard(me)) } else { None }
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
        let w = self.owner.load(Ordering::Relaxed);
        crate::held::held_lower(word::held_key(w));
        #[cfg(feature = "lockdep")]
        {
            self.ld_holder.store(0, Ordering::Relaxed);
            crate::lockdep::release(self.addr(), crate::lockdep::Kind::Mutex);
        }
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
        // The owner that inherited a dead owner's Mutex releases it: the
        // next owner sees a normal hand-over. Ordered by the swap below.
        if self.died.load(Ordering::Relaxed) {
            self.died.store(false, Ordering::Relaxed);
        }
        let old = if waitgraph::ENABLED {
            let _g = GRAPH_LOCK[b].lock();
            let cur = self.owner.load(Ordering::Relaxed);
            let id = word::owner(cur).and_then(|o| probes().and_then(|p| (p.graph_id)(o)));
            if let Some(id) = id {
                if self.waiters.owner() == Some(id) {
                    let _ = waitgraph::release(id, &self.waiters);
                    self.waiters.set_owner(None);
                }
            }
            // Steal rule: a queued graph waiter keeps the word marked and
            // ownerless, so the fast path cannot overtake it.
            let hold = STEAL_RULE && !CANARY_STEAL_ANY.load(Ordering::Relaxed);
            let free = if hold && self.waiters.has_waiters() { word::WAITERS } else { word::FREE };
            self.owner.swap(free, Ordering::Release)
        } else {
            self.owner.swap(word::FREE, Ordering::Release)
        };
        debug_assert!(word::owner(old).is_some(), "kmutex: unlock of a free Mutex");
        debug_assert!(
            old & word::OWNER_MASK == word::BOOT_OWNER || word::owner(old) == Some(me()),
            "kmutex: Mutex released by a task that does not own it"
        );
        if old & word::WAITERS != 0 {
            wake_bucket(b);
        }
    }
}

/// The free-word branch's outcome ([`Mutex::take_free`]).
enum Take {
    /// The caller owns the mutex.
    Taken,
    /// The word moved; retry with this value.
    Changed(u32),
    /// The steal rule defers to the queued top waiter; the caller's graph
    /// id while it is queued in the graph (it joins it if it was not).
    Defer(Option<waitgraph::TaskId>),
}

/// Proof that the current task owns a [`Mutex`]. Unlocks on drop. Not
/// `Send`: the owner releases it.
pub struct MutexGuard<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<'a, T: ?Sized> MutexGuard<'a, T> {
    /// The previous owner exited holding this mutex (`EOWNERDEAD`, owner
    /// decision 10-10): the data is as it left it, possibly half-updated,
    /// and the caller should revalidate it. Cleared by this owner's unlock.
    /// One load.
    pub fn owner_died(&self) -> bool {
        self.lock.died.load(Ordering::Relaxed)
    }

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

    /// Exit-path ktests only: leave the mutex locked and counted as a task
    /// that dies holding it does, dropping only the lockdep entry (a lockdep
    /// report is not the property those tests check).
    #[doc(hidden)]
    pub fn leak(self) {
        crate::lockdep::release(self.lock.addr(), crate::lockdep::Kind::Mutex);
        core::mem::forget(self);
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

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Priority Inheritance Mutex — prevents priority inversion.
///
/// When a high-priority task blocks on a PiMutex held by a lower-priority
/// task, the owner's priority is temporarily boosted to the waiter's level.
/// This prevents unbounded priority inversion in the RT pipeline.
///
/// If no priority callbacks are registered (kernel init hasn't run yet),
/// PiMutex degrades gracefully to a plain spinlock.
///
/// # Priority convention
///
/// Throughout the scheduler, **a lower number is a higher priority**
/// (`PerCpu::ready_bitmap.trailing_zeros()` picks the winner, and
/// `sched::pi_boost_task` only ever writes `new_prio` when
/// `new_prio < task.priority`). Every comparison below follows that.
///
/// # Donation protocol (K-A14)
///
/// Edge-triggered and counted. A waiter donates **at most once** per
/// acquisition; the mutex counts donations in `donations`, and `release()`
/// issues exactly one restore per donation recorded.
///
///   * A waiter reads the current owner and calls the boost callback for it
///     while holding [`PiMutex::pi_state`], then increments `donations`.
///   * The owner's `release()` takes the same `pi_state`, drains `donations`,
///     and de-boosts that many times.
///
/// Holding `pi_state` across the owner read + boost is what makes the
/// protocol safe: without it a waiter can read owner `O`, `O` can release
/// and de-boost itself, and only then does the waiter's boost land — leaving
/// `O` permanently elevated with nobody left to restore it.
///
/// Because the donation is owned by the mutex and undone by the owner, a
/// waiter that is killed or preempted forever mid-wait leaks nothing.
///
/// # Lock order
///
/// The boost callback (`sched::pi_boost_task`) runs while `donate` holds
/// `pi_state`, and it re-buckets a Ready owner at its new priority: it takes
/// the owner's donation lock and then the `CPU_LOCKS` entry of the queue the
/// owner sits in (`cpu_remove_anywhere` / `cpu_enqueue_locked`). So the
/// order is
///
/// ```text
/// PiMutex::pi_state  ->  donation lock (per task)  ->  CPU_LOCKS[cpu]
/// ```
///
/// the same chain `crates/core/sched/src/scheduler.rs` states at `DONATION_LOCKS`.
/// The restore side takes a shorter one: `release()` drops `pi_state` before
/// it calls the restore callback, so a de-boost is donation lock ->
/// `CPU_LOCKS` with no `pi_state` held. The chain stays acyclic only while
/// nothing takes a `pi_state` (that is, locks or releases a `PiMutex`) with a
/// donation lock or a CPU lock held: `crates/core/sched` uses no `PiMutex`, and a
/// new caller under a scheduler lock would close the cycle. There is no
/// run-time lock-order checker; this note and the one in `scheduler.rs` are
/// the record.
///
/// # Waiting yields, it does not spin to completion
///
/// A contended waiter spins briefly and then calls the registered yield
/// callback. This is not a performance tweak — spinning to completion made
/// inheritance useless whenever two contenders shared a hart: the
/// higher-priority waiter never released the CPU, so the owner it had just
/// boosted could not run, and the contention hung no matter how correct the
/// donation was. Yielding is what lets the boost do its work; owner and
/// waiter then sit at the same priority and share the hart until the critical
/// section ends.
///
/// Yielding rather than blocking on a `WaitQueue` is deliberate. Blocking
/// would need the release-and-sleep to be atomic against the owner's
/// wake — `WaitQueue::wait()` cannot be split that way, so the owner can
/// release and wake an empty queue just before the waiter enqueues, leaving it
/// asleep forever with the mutex free. Yielding re-checks every pass and has
/// no such window.
///
/// # Known limitations
///
///   * Donation reads the waiter's priority through the registered
///     per-CPU accessor, which returns the live `Task::priority` — so a
///     waiter that is itself carrying a boost donates the boosted value.
///     Before the accessor existed it read [`CURRENT_PRIO`], see below.
///   * Not recursive: re-acquiring a PiMutex this task already owns loops
///     forever yielding, with no diagnostic — `donate()` skips
///     `owner == my_tid`, so not even a self-boost is attempted. The hart is
///     no longer monopolised (other tasks still run), which makes this a live
///     lock rather than a hard hang, but it is still a bug in the caller.
///   * **WARNING:** do not take a PiMutex from an interrupt handler (same
///     hazard as `SpinLock::lock`). Once the scheduler is running,
///     [`CURRENT_TID`] names the *interrupted* task, so a handler contending
///     for a mutex that task holds sees `owner == my_tid` and declines to
///     donate — and yielding from an interrupt context is not valid either.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::spinlock::SpinLock;

/// Function pointer for boosting a task's priority: fn(tid, new_priority).
/// Stored as AtomicUsize (pointer-sized).
pub static PI_BOOST_FN:  AtomicUsize = AtomicUsize::new(0);

/// Function pointer for restoring a task's priority: fn(tid, original_priority).
pub static PI_RESTORE_FN: AtomicUsize = AtomicUsize::new(0);

/// Register priority boost/restore callbacks.
/// Must be called once during kernel init, before any PiMutex contention.
///
/// `tid_fn` and `prio_fn` name the CALLER: the task running on the calling
/// hart and its current priority, read per CPU. They are what `try_acquire`
/// stores and what a waiter donates. See [`CURRENT_TID`] for why the global
/// pair they replace is wrong the moment a second hart exists.
pub fn pi_set_callbacks(
    boost:   fn(u32, u32),
    restore: fn(u32, u32),
    yield_fn: fn(),
    tid_fn:  fn() -> u32,
    prio_fn: fn() -> u32,
) {
    PI_TID_FN.store(tid_fn as usize, Ordering::Release);
    PI_PRIO_FN.store(prio_fn as usize, Ordering::Release);
    PI_BOOST_FN.store(boost as usize, Ordering::Release);
    PI_RESTORE_FN.store(restore as usize, Ordering::Release);
    PI_YIELD_FN.store(yield_fn as usize, Ordering::Release);
}

/// Per-CPU "who is calling" accessors, registered with the callbacks above.
/// `0` until then, and the global pair below is the pre-registration
/// fallback (early boot, one hart, nothing to contend with).
static PI_TID_FN: AtomicUsize = AtomicUsize::new(0);
static PI_PRIO_FN: AtomicUsize = AtomicUsize::new(0);

/// Yield callback. Registered together with boost/restore; absent before the
/// scheduler exists, in which case the acquire loop degrades to a plain spin
/// (correct, because with no scheduler there is nothing to yield to).
static PI_YIELD_FN: AtomicUsize = AtomicUsize::new(0);

fn yield_callback() -> Option<fn()> {
    let p = PI_YIELD_FN.load(Ordering::Acquire);
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, fn()>(p) }) }
}

/// Load the boost callback, or `None` if kernel init hasn't registered one.
#[inline]
fn boost_callback() -> Option<fn(u32, u32)> {
    let p = PI_BOOST_FN.load(Ordering::Acquire);
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, fn(u32, u32)>(p) }) }
}

/// Load the restore callback, or `None` if kernel init hasn't registered one.
#[inline]
fn restore_callback() -> Option<fn(u32, u32)> {
    let p = PI_RESTORE_FN.load(Ordering::Acquire);
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, fn(u32, u32)>(p) }) }
}

/// A no-owner sentinel for `owner_tid`.
const NO_OWNER: u32 = u32::MAX;

/// Entries of a [`HeldTable`].
const PI_HELD_SLOTS: usize = 64;

/// Locks acquired and not yet released, per task, for the panic policy's
/// containment predicate (RFC-0052 §5.2 check 4): a task that panics while
/// it holds a lock nobody else would release cannot be parked. One table
/// for `PiMutex`es ([`held_by`]), one for the sleeping locks without PI
/// (`crate::sleep_lock::held_by`, owner rule F1: the kind held across a
/// device wait).
///
/// Keyed by the exact TID: each entry packs `tid << 32 | count`, and an entry
/// whose count is 0 is free whatever TID it last carried. An acquisition
/// probes from `tid % PI_HELD_SLOTS` and raises the first entry that is its
/// own, or claims the first free one; a release lowers the first entry that
/// is its own. Both are one compare-and-swap on the packed word, so a claim,
/// a raise and a drop to zero cannot interleave. Before wave 13 the table was
/// `count[tid % 64]`: two live tasks 64 TIDs apart shared a word, and TIDs
/// only grow, so after enough task churn a culprit that held nothing read as
/// holding its neighbour's lock and a containable panic became a reset.
///
/// A task can end up with two entries (its first one was freed and re-claimed
/// by another TID while the task held a second lock further along the probe
/// sequence). [`HeldTable::held_by`] sums every entry with the TID and a
/// release lowers any one of them, so the total stays exact. When every entry
/// is taken by another TID the acquisition is counted in `overflow`, which
/// [`HeldTable::held_by`] adds for EVERY TID: an over-count, the reset path,
/// the safe direction — never an under-count.
pub(crate) struct HeldTable {
    slots:    [AtomicU64; PI_HELD_SLOTS],
    overflow: AtomicU32,
}

#[inline(always)]
const fn held_tid(e: u64) -> u32 {
    (e >> 32) as u32
}

#[inline(always)]
const fn held_count(e: u64) -> u32 {
    e as u32
}

impl HeldTable {
    pub(crate) const fn new() -> Self {
        Self { slots: [const { AtomicU64::new(0) }; PI_HELD_SLOTS], overflow: AtomicU32::new(0) }
    }

    /// Count one acquisition by `tid`: the entry and its new count, or
    /// `None` when it overflowed.
    #[inline(always)]
    pub(crate) fn raise(&self, tid: u32) -> Option<(usize, u32)> {
        let home = tid as usize % PI_HELD_SLOTS;
        let mut k = 0;
        while k < PI_HELD_SLOTS {
            let i = (home + k) % PI_HELD_SLOTS;
            let slot = &self.slots[i];
            let mut e = slot.load(Ordering::Acquire);
            loop {
                let next = if held_count(e) == 0 {
                    (tid as u64) << 32 | 1
                } else if held_tid(e) == tid {
                    e + 1
                } else {
                    break;
                };
                match slot.compare_exchange_weak(e, next, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return Some((i, held_count(next))),
                    Err(now) => e = now,
                }
            }
            k += 1;
        }
        self.overflow.fetch_add(1, Ordering::AcqRel);
        None
    }

    /// Undo one [`HeldTable::raise`] by `tid`.
    #[inline(always)]
    pub(crate) fn lower(&self, tid: u32) {
        let home = tid as usize % PI_HELD_SLOTS;
        let mut k = 0;
        while k < PI_HELD_SLOTS {
            let slot = &self.slots[(home + k) % PI_HELD_SLOTS];
            let mut e = slot.load(Ordering::Acquire);
            while held_count(e) != 0 && held_tid(e) == tid {
                match slot.compare_exchange_weak(e, e - 1, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return,
                    Err(now) => e = now,
                }
            }
            k += 1;
        }
        // Not in the table: the raise overflowed.
        let _ = self.overflow.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |n| n.checked_sub(1));
    }

    /// Acquisitions task `tid` has not released. Exact, unless an
    /// acquisition by any task overflowed the table (then an over-count,
    /// never an under-count). O(`PI_HELD_SLOTS`): the panic path's question.
    pub(crate) fn held_by(&self, tid: u32) -> u32 {
        let mut n = self.overflow.load(Ordering::Acquire);
        for slot in self.slots.iter() {
            let e = slot.load(Ordering::Acquire);
            if held_count(e) != 0 && held_tid(e) == tid {
                n = n.saturating_add(held_count(e));
            }
        }
        n
    }

    /// `(entry, count)` of each entry task `tid` has.
    #[cfg(feature = "pi-held-trace")]
    fn entries_of(&self, tid: u32, mut f: impl FnMut(usize, u32)) {
        for (i, slot) in self.slots.iter().enumerate() {
            let e = slot.load(Ordering::Acquire);
            if held_count(e) != 0 && held_tid(e) == tid { f(i, held_count(e)); }
        }
    }
}

/// The `PiMutex` acquisitions ([`HeldTable`]).
static PI_HELD: HeldTable = HeldTable::new();

/// `pi-held-trace` (diagnostics, the `lat-fat` smoke): the address of each
/// `PiMutex` a task holds, by nesting depth, beside its [`PI_HELD`] entry.
/// Only the first `PI_TRACE_DEPTH` levels are kept. Off: nothing compiled.
#[cfg(feature = "pi-held-trace")]
const PI_TRACE_DEPTH: usize = azos_limits::PI_TRACE_DEPTH;
#[cfg(feature = "pi-held-trace")]
static PI_HELD_ADDR: [[AtomicUsize; PI_TRACE_DEPTH]; PI_HELD_SLOTS] =
    [const { [const { AtomicUsize::new(0) }; PI_TRACE_DEPTH] }; PI_HELD_SLOTS];

/// The `PiMutex`es task `tid` holds, outermost first (at most `out.len()`
/// and the trace depth); returns how many were written.
#[cfg(feature = "pi-held-trace")]
pub fn held_addrs(tid: u32, out: &mut [usize]) -> usize {
    let mut n = 0;
    PI_HELD.entries_of(tid, |i, count| {
        for d in 0..(count as usize).min(PI_TRACE_DEPTH) {
            if n < out.len() {
                out[n] = PI_HELD_ADDR[i][d].load(Ordering::Relaxed);
                n += 1;
            }
        }
    });
    n
}

/// Count one acquisition by `tid` (of the mutex at `_addr`).
#[inline(always)]
fn held_raise(tid: u32, _addr: usize) {
    let _r = PI_HELD.raise(tid);
    #[cfg(feature = "pi-held-trace")]
    if let Some((i, count)) = _r {
        let d = count as usize - 1;
        if d < PI_TRACE_DEPTH {
            PI_HELD_ADDR[i][d].store(_addr, Ordering::Relaxed);
        }
    }
}

/// Undo one [`held_raise`] by `tid`.
#[inline(always)]
fn held_lower(tid: u32) {
    PI_HELD.lower(tid);
}

/// `PiMutex` acquisitions task `tid` has not released. Exact, unless an
/// acquisition by any task overflowed the table (then an over-count, never
/// an under-count). O([`PI_HELD_SLOTS`]): the panic path's question.
pub fn held_by(tid: u32) -> u32 {
    PI_HELD.held_by(tid)
}

/// Plain-load spins between yields while waiting.
///
/// Purely a backoff knob now, not a correctness bound: the acquire loop no
/// longer re-asserts inheritance, so nothing depends on coming back around
/// within any particular window. Small, because the point of the loop is to
/// reach the yield promptly and let the (boosted) owner run.
const SPINS_PER_YIELD: u32 = 64;

/// Priority Inheritance Mutex protecting data of type `T`.
///
/// Owner bookkeeping stays in separate atomics (rather than inside the
/// `SpinLock`) so the spin loop can read `owner_tid` cheaply; `pi_state`
/// exists only to order the read-modify-write sequences that must not
/// interleave.
pub struct PiMutex<T> {
    data:               UnsafeCell<T>,
    locked:             AtomicBool,
    owner_tid:          AtomicU32,
    /// Priority snapshot taken at acquire time.
    ///
    /// CAVEAT: this is [`CURRENT_PRIO`], which the scheduler writes on
    /// context switch from `next.priority` — a value that may *already*
    /// carry an inherited boost. It is therefore not reliably the owner's
    /// base priority. Harmless today only because `sched::pi_restore_task`
    /// ignores its second argument and restores `Task::base_priority`. If
    /// that ever changes, this field must be replaced by a real
    /// base-priority read callback.
    owner_orig_priority: AtomicU32,
    /// How many donations the current owner carries *through this mutex*.
    ///
    /// A count, not a flag: with several waiters each donating once, the
    /// owner's release must undo exactly as many boosts as were made, or the
    /// scheduler's per-task donation counter drifts and the task never returns
    /// to its base priority. Reset to 0 by `try_acquire`, incremented under
    /// `pi_state` by `donate`, drained under `pi_state` by `release`.
    donations:          AtomicU32,
    /// Acquisition count, bumped by `try_acquire` under `pi_state`. A waiter
    /// donates once per value of this, not once per `lock()` call — see the
    /// loop in `lock()`.
    epoch:              AtomicU32,
    /// Serialises {read owner → boost} in `lock()` against
    /// {read owner → clear → de-boost} in `release()`, and makes the CAS on
    /// `locked` and the owner record one step (`try_acquire`). Held across
    /// the boost callback, which takes scheduler locks: see "Lock order" in
    /// the module doc.
    pi_state:           SpinLock<()>,
    /// Lockdep class: the constructor's call site (`lockdep` feature only).
    #[cfg(feature = "lockdep")]
    class:              crate::lockdep::LockClass,
    /// Lockdep (rule F7): the holder's CPU and RT-ness, `lockdep::holder_word`.
    #[cfg(feature = "lockdep")]
    ld_holder:          AtomicU32,
}

// Safety: PiMutex provides exclusive access; data is only reachable through
// the guard, which requires acquiring the lock.
unsafe impl<T: Send> Send for PiMutex<T> {}
unsafe impl<T: Send> Sync for PiMutex<T> {}

impl<T> PiMutex<T> {
    /// Create a new unlocked PiMutex. With lockdep compiled in, the call
    /// site is its class (and its `pi_state`'s, as a SpinLock).
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub const fn new(data: T) -> Self {
        PiMutex {
            data:               UnsafeCell::new(data),
            locked:             AtomicBool::new(false),
            owner_tid:          AtomicU32::new(NO_OWNER),
            owner_orig_priority: AtomicU32::new(0),
            donations:          AtomicU32::new(0),
            epoch:              AtomicU32::new(0),
            pi_state:           SpinLock::new(()),
            #[cfg(feature = "lockdep")]
            class:              crate::lockdep::LockClass::here(crate::lockdep::Kind::PiMutex),
            #[cfg(feature = "lockdep")]
            ld_holder:          AtomicU32::new(0),
        }
    }

    /// Lockdep: record the lock held by the caller.
    #[cfg(feature = "lockdep")]
    #[inline(always)]
    #[track_caller]
    fn ld_acquired(&self) {
        crate::lockdep::acquired(&self.class, self as *const Self as usize,
            crate::lockdep::Kind::PiMutex, false, core::panic::Location::caller());
        self.ld_holder.store(crate::lockdep::holder_word(), Ordering::Relaxed);
    }

    /// Acquire the mutex, spinning until available.
    ///
    /// While spinning, if a priority boost callback is registered, the
    /// current task's priority is propagated to the lock owner to prevent
    /// priority inversion: once per acquisition of the lock, so a new owner
    /// (or the same owner taking it again) gets its own donation.
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn lock(&self) -> PiMutexGuard<'_, T> {
        // Lockdep (Linux's `might_sleep` in `mutex_lock`): a PiMutex may
        // wait, so it is checked whether or not this call does.
        #[cfg(feature = "lockdep")]
        {
            crate::lockdep::might_sleep("PiMutex::lock");
            crate::lockdep::check(&self.class, self as *const Self as usize,
                crate::lockdep::Kind::PiMutex, core::panic::Location::caller());
        }
        // Fast path: try to acquire immediately
        if self.try_acquire() {
            #[cfg(feature = "lockdep")]
            self.ld_acquired();
            return PiMutexGuard { mutex: self };
        }

        // Slow path: contention — apply priority inheritance.
        #[cfg(feature = "lockdep")]
        crate::lockdep::contended(&self.class, self as *const Self as usize,
            crate::lockdep::Kind::PiMutex, self.ld_holder.load(Ordering::Relaxed));
        //
        // Identity is sampled once: this task cannot migrate or change base
        // priority underneath itself while it is the one executing here.
        let my_tid  = current_task_tid();
        let my_prio = current_task_priority();

        // Donate at most once per ACQUISITION — per `epoch`, not per call.
        // The old loop re-asserted the boost periodically, which forced
        // `pi_boost_task` to stay idempotent and therefore uncounted — and
        // uncounted donations are exactly why two contended PiMutexes could
        // not compose. One donation per acquisition keeps the protocol
        // edge-triggered and countable; `release()` undoes precisely as many
        // boosts as were made on the acquisition it ends.
        //
        // **Per acquisition, not once per `lock()` call.** Once per call lost
        // the donation whenever the owner released and took the lock again
        // before this waiter's CAS: the release undid the boost, the new
        // acquisition started with none, and this waiter, having "already
        // donated", never gave it one. On one hart that is a livelock, not a
        // delay — the waiter outranks the unboosted owner, so every yield
        // below comes straight back to the waiter. Measured with
        // `pi-flush-smoke`: `sys-wdt` (11) waiting on `LOG_FILE` while a
        // priority-14 flusher on its hart re-took it flush after flush; the
        // owner was named correctly and still sat at 14, Ready, forever.
        let mut donated_to: Option<u32> = None;

        loop {
            // (1) Donate to whoever owns the lock, once per acquisition we
            //     observe (`try_acquire` records the owner in the same step
            //     that takes the lock, so a held lock always names one).
            if let Some(e) = self.donate(my_tid, my_prio, donated_to) {
                donated_to = Some(e);
            }

            // (2) Brief spin, then YIELD. Spinning to completion was the
            //     fundamental flaw: with two contenders on one hart the
            //     higher-priority waiter never released the CPU, so the owner
            //     it had just boosted could not run and the contention hung
            //     regardless of inheritance. Yielding is what lets the boost
            //     do its job — owner and waiter now sit at the same priority
            //     and share the hart until the critical section ends.
            let mut spins: u32 = 0;
            while self.locked.load(Ordering::Relaxed) && spins < SPINS_PER_YIELD {
                core::hint::spin_loop();
                spins += 1;
            }
            if self.locked.load(Ordering::Relaxed) {
                match yield_callback() {
                    // No scheduler yet: nothing to yield to, so a plain spin is
                    // both the only option and the correct one.
                    None    => core::hint::spin_loop(),
                    Some(y) => y(),
                }
            }

            // (3) Try to acquire.
            if self.try_acquire() {
                #[cfg(feature = "lockdep")]
                self.ld_acquired();
                return PiMutexGuard { mutex: self };
            }
        }
    }

    /// Donate `my_prio` to the current owner, if there is one.
    ///
    /// Runs entirely under `pi_state` so that `release()` cannot clear the
    /// owner and de-boost in between our read of `owner_tid` and the boost
    /// call — that interleaving is what leaks a permanent boost onto a task
    /// that no longer holds the lock.
    ///
    /// No filtering on `my_prio` here: `sched::pi_boost_task` already applies
    /// the `new_prio < owner.priority` test, and priority 0 (the top RT band)
    /// is precisely the level that most needs to donate.
    ///
    /// Returns the acquisition (`epoch`) donated to, or `None` if nothing was
    /// donated — no owner yet, or `already` is the current acquisition.
    fn donate(&self, my_tid: u32, my_prio: u32, already: Option<u32>) -> Option<u32> {
        // A context with no scheduled task (early boot, IRQ before the
        // scheduler starts) has no priority to give away.
        if my_tid == NO_OWNER {
            return None;
        }
        // Cheap unlocked pre-checks to keep the uncontended-owner case, and
        // the already-donated case, off the state lock; re-validated below
        // under the lock.
        if self.owner_tid.load(Ordering::Acquire) == NO_OWNER {
            return None;
        }
        if already == Some(self.epoch.load(Ordering::Acquire)) {
            return None;
        }
        let boost = boost_callback()?; // no scheduler callbacks — plain spinlock

        // IRQ-safe: an interrupt handler contending for the same PiMutex
        // would otherwise deadlock against this hart's own state lock.
        let _st = self.pi_state.lock_irqsave();
        let owner = self.owner_tid.load(Ordering::Acquire);
        let epoch = self.epoch.load(Ordering::Acquire);
        if owner != NO_OWNER && owner != my_tid && already != Some(epoch) {
            boost(owner, my_prio);
            // Counted under `pi_state`, so the matching `release()` — which
            // drains the counter under the same lock — sees every donation.
            self.donations.fetch_add(1, Ordering::AcqRel);
            return Some(epoch);
        }
        None
    }

    /// Try to acquire the mutex without spinning.
    /// Returns `None` if already held.
    ///
    /// Never donates: a caller that does not wait suffers no inversion.
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn try_lock(&self) -> Option<PiMutexGuard<'_, T>> {
        if self.try_acquire() {
            #[cfg(feature = "lockdep")]
            self.ld_acquired();
            Some(PiMutexGuard { mutex: self })
        } else {
            None
        }
    }

    /// Take the lock and record the caller as its owner, as ONE step.
    ///
    /// **One step, under `pi_state` with interrupts off, and that is the fix
    /// for a livelock.** The CAS used to come first and `record_owner` after
    /// it, and `release` cleared the owner before it cleared `locked`. A tick
    /// in either gap left the lock held with no owner recorded, and a waiter
    /// preempting the holder on its hart then had no one to donate to: it
    /// yielded, the unboosted holder lost every yield to it, and neither ran
    /// again. Measured with `pi-flush-smoke` once the other two holes were
    /// closed: `LOG_FILE.locked = 1`, `owner_tid = NO_OWNER`, the flusher
    /// Ready at its base priority inside `release`. Now `locked` and the
    /// owner change together, so a waiter that sees the lock taken sees who
    /// took it.
    fn try_acquire(&self) -> bool {
        let tid  = current_task_tid();
        let prio = current_task_priority();

        let _st = self.pi_state.lock_irqsave();
        if self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        self.owner_tid.store(tid, Ordering::Release);
        self.owner_orig_priority.store(prio, Ordering::Release);
        held_raise(tid, self as *const Self as usize);
        // A fresh owner starts with no donations: `release()` drained the
        // counter under this same lock.
        self.donations.store(0, Ordering::Release);
        // A new acquisition: a waiter that donated to the previous one gives
        // this one its own donation (see `lock()`).
        self.epoch.fetch_add(1, Ordering::AcqRel);
        true
    }

    /// Release the lock and undo any priority donated through this mutex.
    fn release(&self) {
        // Clear the owner and consume the donation flag atomically with
        // respect to `donate()`. After this section a waiter observes
        // NO_OWNER and will not boost us, so no donation can land after our
        // de-boost.
        let (tid, orig_prio, boosted) = {
            let _st = self.pi_state.lock_irqsave();
            let tid       = self.owner_tid.load(Ordering::Acquire);
            let orig_prio = self.owner_orig_priority.load(Ordering::Acquire);
            let boosted   = self.donations.swap(0, Ordering::AcqRel);
            // The TID `try_acquire` counted, so the table balances even for a
            // pre-scheduler acquisition recorded as `NO_OWNER`.
            held_lower(tid);
            self.owner_tid.store(NO_OWNER, Ordering::Release);
            self.owner_orig_priority.store(0, Ordering::Release);
            // Drop the mutex BEFORE de-boosting, and in the same section that
            // clears the owner (see `try_acquire`). De-boosting first would
            // leave us running at base priority while still holding the lock,
            // so a mid-priority task could preempt us in that window and
            // reopen the very inversion the donation paid to avoid. Running
            // one extra instant at the inherited priority after unlocking is
            // bounded and harmless by comparison.
            self.locked.store(false, Ordering::Release);
            (tid, orig_prio, boosted)
        };

        // Undo exactly as many boosts as were donated through *this* mutex —
        // no more, no fewer. One restore per donation is what keeps the
        // scheduler's per-task donation counter balanced, and that balance is
        // what lets a second donation source (an outer PiMutex, the lease PI)
        // stay intact across our unlock: the count only reaches zero, and the
        // task only returns to base priority, when the LAST donor leaves.
        if tid != NO_OWNER && boosted > 0 {
            if let Some(restore) = restore_callback() {
                for _ in 0..boosted {
                    restore(tid, orig_prio);
                }
            }
        }
    }
}

/// RAII guard that releases the PiMutex and restores priority on drop.
pub struct PiMutexGuard<'a, T> {
    mutex: &'a PiMutex<T>,
}

impl<T> core::ops::Deref for PiMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> core::ops::DerefMut for PiMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for PiMutexGuard<'_, T> {
    fn drop(&mut self) {
        #[cfg(feature = "lockdep")]
        {
            self.mutex.ld_holder.store(0, Ordering::Relaxed);
            crate::lockdep::release(self.mutex as *const PiMutex<T> as usize, crate::lockdep::Kind::PiMutex);
        }
        self.mutex.release();
    }
}

// ── Stubs for task identity / priority ───────────────────────────────────────
// These read from atomics that the scheduler sets.  If no scheduler is running
// (early boot), they return safe defaults (tid=MAX, prio=0) which cause the
// PI logic to gracefully no-op.

/// Atomic holding the TID of the task the LAST context switch on ANY hart
/// dispatched. Defaults to NO_OWNER so PI is a no-op before the scheduler
/// starts.
///
/// **Not the caller's identity on SMP, and this mutex no longer reads it once
/// the scheduler registers its per-CPU accessors.** Every hart's switch
/// overwrites the same word, so with more than one hart the acquire path
/// stored whatever task another hart had just switched to, and a waiter
/// donated to that task instead of the owner. The real owner, preempted on
/// the waiter's hart at its base priority, then lost every `task_yield` to
/// the waiter (a voluntary yield does not switch to a less urgent task) and
/// neither ran again. Measured with `pi-flush-smoke`: `sys-wdt` (11) spinning
/// on `LOG_FILE` on hart 2, `owner_tid` = `autorun` on hart 3 (boosted to 11
/// over its base 24), the flusher that really held it Ready at 14 — 3 boots
/// of 3. `waitqueue` hit the same global first (see its `WQ_TID_FN`). Kept as
/// the pre-registration fallback and for the host tests that drive it.
pub static CURRENT_TID:  AtomicU32 = AtomicU32::new(NO_OWNER);
/// Priority of the task the last switch on any hart dispatched. Same caveat
/// as [`CURRENT_TID`].
pub static CURRENT_PRIO: AtomicU32 = AtomicU32::new(0);

/// The caller's TID: the registered per-CPU accessor when there is one, the
/// global only before registration. The accessor answers `0` when no task is
/// current on this hart, which is `NO_OWNER` here.
fn current_task_tid() -> u32 {
    let p = PI_TID_FN.load(Ordering::Acquire);
    if p == 0 {
        return CURRENT_TID.load(Ordering::Relaxed);
    }
    let f: fn() -> u32 = unsafe { core::mem::transmute::<usize, fn() -> u32>(p) };
    match f() {
        0 => NO_OWNER,
        tid => tid,
    }
}

/// The caller's current (possibly boosted) priority, per CPU once registered.
fn current_task_priority() -> u32 {
    let p = PI_PRIO_FN.load(Ordering::Acquire);
    if p == 0 {
        return CURRENT_PRIO.load(Ordering::Relaxed);
    }
    let f: fn() -> u32 = unsafe { core::mem::transmute::<usize, fn() -> u32>(p) };
    f()
}

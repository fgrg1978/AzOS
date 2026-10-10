// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Spinlock (TTAS pattern) over the arch-api spin primitives.
///
/// Wraps data in a `SpinLock<T>` to ensure exclusive access. The lock word
/// is a `u32` (0 free, 1 held): acquired with `SpinWait::cas32` (Zacas
/// `amocas.w`, LSE `CASA`, `LOCK CMPXCHG`, or the LR/SC / LL/SC fallback,
/// per config/Kconfig.arch) and waited on with `SpinWait::wait_while32`
/// (Zawrs `wrs.nto`, `LDAXR`+`WFE`, WAITPKG `UMWAIT`, or `cpu_relax`). A
/// 32-bit word, not a byte: riscv64 has no sub-word CAS without Zabha.
///
/// Two acquisition modes:
/// - `lock()`         — standard spinlock, interrupts unchanged.
/// - `lock_irqsave()` — disables interrupts on the local hart before
///                       acquiring, preventing deadlock when an IRQ handler
///                       contends for the same lock. Returns an `IrqSaveGuard`
///                       that restores the previous interrupt state on drop.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};
use azos_arch::{CasOrder, Interrupts, InterruptState, SpinWait, ARCH};
use crate::preempt::{critical_section, PreemptGuard};

/// The lock word's two values.
const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;

/// The contended half of `SpinLock::acquire_spin`: wait, reading only,
/// until the word is no longer `LOCKED`, then CAS again. On the word, not
/// the lock, so every `SpinLock<T>` shares one copy.
#[cold]
#[inline(never)]
fn acquire_contended(locked: &AtomicU32) {
    loop {
        ARCH.wait_while32(locked, LOCKED);
        if ARCH.cas32(locked, UNLOCKED, LOCKED, CasOrder::Acquire).is_ok() {
            return;
        }
    }
}

/// A simple test-and-set spinlock protecting data of type `T`.
pub struct SpinLock<T> {
    locked: AtomicU32,
    /// Lockdep class: the constructor's call site (`lockdep` feature only).
    #[cfg(feature = "lockdep")]
    class: crate::lockdep::LockClass,
    data: UnsafeCell<T>,
}

// Safety: SpinLock provides exclusive access via lock/unlock.
unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Create a new unlocked SpinLock. With lockdep compiled in, the call
    /// site is the lock's class (`#[track_caller]`).
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicU32::new(UNLOCKED),
            #[cfg(feature = "lockdep")]
            class: crate::lockdep::LockClass::here(crate::lockdep::Kind::Spin),
            data: UnsafeCell::new(data),
        }
    }

    /// Lockdep: check and record this acquisition (before the spin).
    #[cfg(feature = "lockdep")]
    #[inline(always)]
    #[track_caller]
    fn ld_acquire(&self, irqsave: bool) {
        crate::lockdep::acquire(&self.class, self as *const Self as usize,
            crate::lockdep::Kind::Spin, irqsave, core::panic::Location::caller());
    }

    /// Lockdep: record a `try_lock` that succeeded.
    #[cfg(feature = "lockdep")]
    #[inline(always)]
    #[track_caller]
    fn ld_acquired(&self, irqsave: bool) {
        crate::lockdep::acquired(&self.class, self as *const Self as usize,
            crate::lockdep::Kind::Spin, irqsave, core::panic::Location::caller());
    }

    /// Core spin loop — shared by both lock variants. TTAS: CAS 0→1
    /// (Acquire); on failure wait, reading only, until the word is no
    /// longer 1, then CAS again. The first CAS is inline; the waiting is
    /// out of line (`acquire_contended`, one copy for every `T`), so the
    /// uncontended acquire is the CAS and its branch, with no wait-loop
    /// setup hoisted in front of it.
    #[inline(always)]
    fn acquire_spin(&self) {
        if !self.try_acquire() {
            acquire_contended(&self.locked);
        }
    }

    /// One CAS 0→1 (Acquire): the `try_lock` attempt.
    #[inline(always)]
    fn try_acquire(&self) -> bool {
        ARCH.cas32(&self.locked, UNLOCKED, LOCKED, CasOrder::Acquire).is_ok()
    }

    /// Acquire the lock, spinning until it is available.
    /// Returns a guard that releases the lock on drop.
    ///
    /// **WARNING:** If this lock may be taken from an interrupt handler,
    /// use `lock_irqsave()` instead — otherwise the IRQ can preempt the
    /// holder on the same hart and deadlock.
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        // Preemption off BEFORE the spin, not after it. Disabling after the
        // CAS leaves exactly the window this exists to close: the tick lands
        // between acquiring and disabling, deschedules the holder, and a
        // higher-priority task on the same hart then spins on a lock whose
        // owner cannot run. Linux takes the count first for the same reason.
        let _preempt = critical_section();
        #[cfg(feature = "lockdep")]
        self.ld_acquire(false);
        self.acquire_spin();
        SpinLockGuard { lock: self, _preempt }
    }

    /// Acquire the lock with interrupts disabled on the local hart.
    ///
    /// Saves the previous `sstatus.SIE` state, clears it (disables
    /// supervisor interrupts), then spins for the lock. The returned
    /// `IrqSaveGuard` restores the original interrupt state on drop.
    ///
    /// Use this when the lock is (or may be) shared with an IRQ handler.
    /// Lockdep's class key for this lock (`lockdep::class_info`).
    #[cfg(feature = "lockdep")]
    pub fn lockdep_key(&self) -> u32 {
        self.class.key()
    }

    /// [`lock`](Self::lock) for `scope::Object` of `level`: lockdep also
    /// checks the level order (`paired`: the second lock of a `lock_pair`).
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    #[inline(always)]
    #[allow(dead_code)] // used by `scope`, which the host tests do not pull in
    pub(crate) fn lock_level(&self, _level: u8, _paired: bool) -> SpinLockGuard<'_, T> {
        let _preempt = critical_section();
        #[cfg(feature = "lockdep")]
        crate::lockdep::acquire_level(&self.class, self as *const Self as usize,
            crate::lockdep::Kind::Spin, false, _level, _paired, core::panic::Location::caller());
        self.acquire_spin();
        SpinLockGuard { lock: self, _preempt }
    }

    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn lock_irqsave(&self) -> IrqSaveGuard<'_, T> {
        // Through `arch-api`, not `sstatus` directly: the ISA owns what the
        // enable state IS (`sstatus.SIE` here, `DAIF.I` on aarch64 — and with
        // the opposite polarity), this file owns only the ordering around it.
        let prev_sstatus = ARCH.disable_all();

        // After SIE is off -- an interrupt cannot arrive here anyway, so the
        // count is pure arithmetic in this order -- but still before the spin.
        let _preempt = critical_section();
        #[cfg(feature = "lockdep")]
        self.ld_acquire(true);
        self.acquire_spin();
        IrqSaveGuard {
            lock: self,
            prev_sstatus,
            #[cfg(feature = "lat-trace")]
            site: core::panic::Location::caller(),
            _preempt,
        }
    }

    /// Try to acquire the lock without spinning.
    /// Returns `None` if the lock is already held.
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        // Taken before the attempt and dropped on failure. Dropping it may
        // fire a deferred reschedule, which is legal: this is task context and
        // no lock is held.
        let _preempt = critical_section();
        if self.try_acquire() {
            #[cfg(feature = "lockdep")]
            self.ld_acquired(false);
            Some(SpinLockGuard { lock: self, _preempt })
        } else {
            None
        }
    }

    /// Try to acquire the lock with IRQ save, without spinning.
    /// Returns `None` (and restores interrupts) if the lock is already held.
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn try_lock_irqsave(&self) -> Option<IrqSaveGuard<'_, T>> {
        let prev_sstatus = ARCH.disable_all();

        let _preempt = critical_section();
        if self.try_acquire() {
            #[cfg(feature = "lockdep")]
            self.ld_acquired(true);
            Some(IrqSaveGuard {
                lock: self,
                prev_sstatus,
                #[cfg(feature = "lat-trace")]
                site: core::panic::Location::caller(),
                _preempt,
            })
        } else {
            // Failed — drop the count, then restore interrupts. Dropping first
            // means the fire predicate sees SIE still off and defers, which is
            // what we want: a failed `try_lock` is no place to reschedule.
            drop(_preempt);
            // This wrote the saved `sstatus` back wholesale while the Drop
            // impl below restored only `SIE` — two idioms in one file. Both
            // are `ARCH.restore` now, which is the careful one.
            ARCH.restore(prev_sstatus);
            None
        }
    }

    /// Unsafe: get a mutable reference without locking.
    /// Only use during single-threaded init before SMP starts.
    ///
    /// Also (intentionally) used after SMP is up by panic-path `*_panic`
    /// helpers (e.g. `motor::motor_stop_panic`, `gpio::gpio_write_panic`,
    /// `pwm::pwm_set_duty_pct_panic`) that must never block on a lock
    /// another hart might be holding at panic time — see those functions'
    /// doc comments for the "torn state is fine, a hung panic handler is
    /// not" rationale. Not a bug if you see it called from there.
    ///
    /// # Safety
    /// Caller must ensure no concurrent access, OR (panic path only)
    /// accept a possible torn read/write racing a concurrent lock holder.
    pub unsafe fn get_mut_unchecked(&self) -> &mut T {
        &mut *self.data.get()
    }

    /// Release the lock (used internally by guards).
    #[inline(always)]
    fn release(&self) {
        #[cfg(feature = "lockdep")]
        crate::lockdep::release(self as *const Self as usize, crate::lockdep::Kind::Spin);
        self.locked.store(UNLOCKED, Ordering::Release);
    }
}

// ── Standard guard (no IRQ save) ────────────────────────────────────────────

/// RAII guard that releases the spinlock when dropped.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    /// Declared LAST, and that is load-bearing. Rust runs `Drop::drop` first
    /// and then drops fields in declaration order, so the lock is released
    /// before preemption is re-enabled. The other order would let a deferred
    /// switch land on a hart whose outgoing task still holds the lock.
    _preempt: PreemptGuard,
}

impl<T> core::ops::Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> core::ops::DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.release();
    }
}

// ── IRQ-save guard ──────────────────────────────────────────────────────────

/// RAII guard that releases the spinlock AND restores the previous
/// interrupt enable state (`sstatus.SIE`) when dropped.
///
/// Drop order matters: unlock first (Release store), then restore
/// interrupts. This ensures that a pending IRQ that fires immediately
/// after re-enable sees the lock as free.
pub struct IrqSaveGuard<'a, T> {
    lock: &'a SpinLock<T>,
    prev_sstatus: InterruptState,
    /// Where the guard was taken: the masked-window tracer's end site when
    /// dropping it re-enables interrupts.
    #[cfg(feature = "lat-trace")]
    site: &'static core::panic::Location<'static>,
    /// Last again, so the order is: release the lock, restore SIE, then enable
    /// preemption. Restoring SIE first is what lets the fire predicate see
    /// task context and actually pay a deferred tick here.
    _preempt: PreemptGuard,
}

impl<T> core::ops::Deref for IrqSaveGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> core::ops::DerefMut for IrqSaveGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for IrqSaveGuard<'_, T> {
    fn drop(&mut self) {
        // Release lock first, then restore interrupt state.
        self.lock.release();
        #[cfg(feature = "lat-trace")]
        azos_arch::lat_hook::irq_restore_at(self.prev_sstatus.0, self.site);
        // Restore only the enable state, never the whole register — the
        // contract `Interrupts::restore` states, and what these four lines
        // used to open-code.
        ARCH.restore(self.prev_sstatus);
    }
}

/// N2 evidence (ktest builds only): one uncontended acquire and release of
/// a `SpinLock`'s word, the path this file owns (no preemption count, no
/// lockdep). Not inlined, under a fixed name, so its disassembly is the
/// per-ISA instruction count of the acquire; ktest
/// `spin_uncontended_acquire` calls it.
#[cfg(feature = "ktest")]
#[inline(never)]
#[no_mangle]
pub fn azos_spin_acquire_release(l: &SpinLock<u64>) {
    l.acquire_spin();
    l.locked.store(UNLOCKED, Ordering::Release);
}

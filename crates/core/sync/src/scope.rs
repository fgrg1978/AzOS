// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Lock scopes as types (owner decision 09-10; `rfcs/survey/MUTEX.md` §5.1,
//! flag F6).
//!
//! Who may touch a piece of state is part of its type:
//!
//! | Scope          | Who                                   | Waiting                          |
//! |----------------|---------------------------------------|----------------------------------|
//! | [`PerCpu`]     | its own CPU only, preemption off      | none: no lock                    |
//! | [`CpuOwned`]   | its CPU; another CPU from task context only | a SpinLock per CPU (bounded) |
//! | [`Global`]     | any CPU                               | a SpinLock, never an unbounded IRQs-off spin |
//! | [`Object`]     | any CPU, in a fixed level order       | a SpinLock per object            |
//!
//! What a type cannot say, lockdep checks at run time (Kconfig
//! LOCKDEP_SCOPE_CHECKS, compiled out with lockdep): another CPU's
//! `CpuOwned` locked in interrupt context; a `PerCpu` reached with
//! preemption on (its token assumed, not earned); an `Object` taken under
//! one of an equal or higher level outside [`Object::lock_pair`]; a
//! `Global` or `CpuOwned` held past LOCK_MAX_HOLD_US (the hold histogram).
//!
//! Context tokens: a [`PreemptOff`] is any value that proves preemption off
//! on this CPU while it lives — a [`PreemptGuard`], a SpinLock guard, an
//! [`IrqOff`]. None is `Send`, so none can prove it for another CPU.
//!
//! The storage is `azos_percpu::PerCpuRemote` (any CPU's instance from any
//! CPU); these wrap it and expose only what their scope allows. Each is laid
//! out exactly as what it wraps and every method is `#[inline(always)]`:
//! without lockdep a scoped access compiles to the bare one.

use core::marker::PhantomData;

use azos_arch::{Cpu as _, Interrupts as _, InterruptState, ARCH};
use azos_percpu::{PerCpuRemote, PerCpuVar};

use crate::preempt::PreemptGuard;
use crate::spinlock::{IrqSaveGuard, SpinLock, SpinLockGuard};

// ── Context tokens ───────────────────────────────────────────────────────

/// Proof that preemption is off on this CPU while the value lives.
///
/// # Safety
/// Implement only for a type whose live values keep this CPU from being
/// preempted (and that is not `Send`).
pub unsafe trait PreemptOff {}

// SAFETY: each holds preemption off (`critical_section`) while it lives; none is Send.
unsafe impl PreemptOff for PreemptGuard {}
unsafe impl<T> PreemptOff for SpinLockGuard<'_, T> {}
unsafe impl<T> PreemptOff for IrqSaveGuard<'_, T> {}
unsafe impl PreemptOff for IrqOff {}

/// Interrupts off on this CPU (so preemption too) while it lives.
pub struct IrqOff {
    /// What [`IrqOff::new`] masked, restored on drop; `None` for an
    /// [`IrqOff::assume`] token, which restores nothing.
    prev: Option<InterruptState>,
    _not_send: PhantomData<*mut ()>,
}

impl IrqOff {
    /// Mask interrupts on this CPU until the value is dropped.
    #[inline(always)]
    #[must_use = "interrupts are restored the instant the token is dropped"]
    pub fn new() -> Self {
        IrqOff { prev: Some(ARCH.disable_all()), _not_send: PhantomData }
    }

    /// A token for code that already runs with interrupts off (an interrupt
    /// handler, a section that masked them by hand). Lockdep checks the
    /// claim at each scoped access it is used for.
    ///
    /// # Safety
    /// Interrupts are off on this CPU for as long as the token lives.
    #[inline(always)]
    pub unsafe fn assume() -> Self {
        IrqOff { prev: None, _not_send: PhantomData }
    }
}

impl Default for IrqOff {
    fn default() -> Self { Self::new() }
}

impl Drop for IrqOff {
    #[inline(always)]
    fn drop(&mut self) {
        if let Some(p) = self.prev {
            ARCH.restore(p);
        }
    }
}

// ── PerCpu<T>: this CPU's instance, no lock ──────────────────────────────

/// One instance per CPU, used only by its own CPU with preemption off: no
/// lock, no remote access. `REMOTE_READ` variables (per-CPU counters)
/// also allow relaxed, lock-free reads of another CPU's instance
/// ([`PerCpu::remote_read`], F6) and give their own CPU only `&T`; the
/// others give their CPU `&mut T` under interrupts off ([`PerCpu::with_mut`]).
#[repr(transparent)]
pub struct PerCpu<T, const REMOTE_READ: bool = false> {
    v: PerCpuRemote<T>,
}

impl<T, const R: bool> PerCpu<T, R> {
    /// A variable whose initial value is all zero bytes.
    ///
    /// # Safety
    /// All-zero bytes must be a valid `T`.
    pub const unsafe fn zeroed() -> Self {
        // SAFETY: the caller's contract.
        PerCpu { v: unsafe { PerCpuRemote::zeroed() } }
    }

    /// A variable `init` initialises in place when its CPU's area is attached.
    pub const fn with_init(init: unsafe fn(*mut T)) -> Self {
        PerCpu { v: PerCpuRemote::with_init(init) }
    }

    /// Has `cpu` got an instance yet (the boot attaches the areas)?
    #[inline(always)]
    pub fn attached(&self, cpu: usize) -> bool {
        self.v.attached(cpu)
    }

    /// This CPU's instance, shared.
    #[inline(always)]
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn with<X>(&self, _p: &impl PreemptOff, f: impl FnOnce(&T) -> X) -> X {
        crate::lockdep::scope_per_cpu();
        // SAFETY: this CPU's instance (attached before any task runs, never
        // freed), shared: the only `&mut` is `with_mut`, under IrqOff.
        f(unsafe { &*self.v.ptr(ARCH.hart_id()) })
    }

    /// The type-erased handle the boot's `setup_per_cpu_areas` attaches.
    pub fn var(&self) -> &dyn PerCpuVar where T: 'static {
        &self.v
    }

    /// The storage, for a Kconfig variant that collapses the variable to
    /// one instance shared by every CPU behind a lock of its own (a Global
    /// scope, documented at the user).
    ///
    /// # Safety
    /// The caller provides the exclusion the shared instance needs.
    #[inline(always)]
    pub unsafe fn storage(&self) -> &PerCpuRemote<T> {
        &self.v
    }
}

impl<T> PerCpu<T, false> {
    /// This CPU's instance, exclusive: interrupts are off, so nothing else
    /// on this CPU runs, and no other CPU reaches it.
    #[inline(always)]
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn with_mut<X>(&self, _irq: &IrqOff, f: impl FnOnce(&mut T) -> X) -> X {
        crate::lockdep::scope_per_cpu();
        // SAFETY: see above; one `with_mut` at a time per CPU (do not nest
        // two on one variable).
        f(unsafe { &mut *self.v.ptr(ARCH.hart_id()) })
    }

    /// [`with_mut`](Self::with_mut) for the instance of `cpu`, which the
    /// caller read as this CPU's under the same `IrqOff` (a hart id it
    /// keeps). Lockdep checks that it is.
    #[inline(always)]
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn with_mut_on<X>(&self, _irq: &IrqOff, cpu: usize, f: impl FnOnce(&mut T) -> X) -> X {
        crate::lockdep::scope_per_cpu_on(cpu);
        // SAFETY: as `with_mut`; `cpu` is this CPU (the caller's contract,
        // checked by lockdep).
        f(unsafe { &mut *self.v.ptr(cpu) })
    }
}

impl<T: Sync> PerCpu<T, true> {
    /// Another CPU's instance, read without a lock (F6: per-CPU counters
    /// summed by a reader). `T`'s fields are atomics read `Relaxed`; the
    /// owner CPU only ever has `&T` too. `None` for a CPU without an area.
    #[inline(always)]
    pub fn remote_read<X>(&self, cpu: usize, f: impl FnOnce(&T) -> X) -> Option<X> {
        // SAFETY: attached instances are never freed; everyone has `&T`.
        self.v.get(cpu).map(|p| f(unsafe { &*p }))
    }
}

impl<T: 'static, const R: bool> PerCpuVar for PerCpu<T, R> {
    fn size(&self) -> usize { self.v.size() }
    fn align(&self) -> usize { self.v.align() }
    fn attached(&self, cpu: usize) -> bool { PerCpuVar::attached(&self.v, cpu) }
    unsafe fn attach(&self, cpu: usize, p: *mut u8) {
        // SAFETY: the caller's contract, passed through.
        unsafe { self.v.attach(cpu, p) }
    }
}

// ── CpuOwned<T>: a lock per CPU ──────────────────────────────────────────

/// One instance per CPU, each behind its own SpinLock, owned by its CPU:
/// locked locally, or by another CPU from task context only (a bounded
/// wait). Interrupt context reaches only its own CPU's (remote work from an
/// interrupt goes through the deferred list and an IPI). Always locked
/// with interrupts off (`lock_irqsave`): the owner's interrupt handler
/// takes it too.
#[repr(transparent)]
pub struct CpuOwned<T> {
    v: PerCpuRemote<SpinLock<T>>,
}

impl<T> CpuOwned<T> {
    /// `init` writes each CPU's `SpinLock<T>` in place when its area is
    /// attached (`p.write(SpinLock::new(..))`: one constructor site, so one
    /// lockdep class for every CPU's lock).
    pub const fn with_init(init: unsafe fn(*mut SpinLock<T>)) -> Self {
        CpuOwned { v: PerCpuRemote::with_init(init) }
    }

    /// Has `cpu` got an instance yet?
    #[inline(always)]
    pub fn attached(&self, cpu: usize) -> bool {
        self.v.attached(cpu)
    }

    /// Lock CPU `cpu`'s instance, interrupts off. Another CPU's only from
    /// task context (lockdep reports it from an interrupt).
    /// `cpu` must have an area (`attached`).
    #[inline(always)]
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn lock_on(&self, cpu: usize) -> IrqSaveGuard<'_, T> {
        crate::lockdep::scope_cpu_owned(cpu);
        // SAFETY: the caller's contract: attached, never freed.
        unsafe { &*self.v.ptr(cpu) }.lock_irqsave()
    }

    /// Lock this CPU's instance, interrupts off: `(cpu, guard)`. The CPU id
    /// is read with interrupts already masked, so it is the one locked.
    #[inline(always)]
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn lock_local(&self) -> (usize, IrqSaveGuard<'_, T>, IrqOff) {
        let irq = IrqOff::new();
        let cpu = ARCH.hart_id();
        // SAFETY: this CPU runs, so its area is attached.
        (cpu, unsafe { &*self.v.ptr(cpu) }.lock_irqsave(), irq)
    }

    /// The type-erased handle the boot's `setup_per_cpu_areas` attaches.
    pub fn var(&self) -> &dyn PerCpuVar where T: 'static {
        &self.v
    }
}

impl<T: 'static> PerCpuVar for CpuOwned<T> {
    fn size(&self) -> usize { self.v.size() }
    fn align(&self) -> usize { self.v.align() }
    fn attached(&self, cpu: usize) -> bool { PerCpuVar::attached(&self.v, cpu) }
    unsafe fn attach(&self, cpu: usize, p: *mut u8) {
        // SAFETY: the caller's contract, passed through.
        unsafe { self.v.attach(cpu, p) }
    }
}

// ── Global<T> ────────────────────────────────────────────────────────────

/// State any CPU may take: a SpinLock today (N3 makes it MCS-queued, N5's
/// QSBR gives it lock-free reads). `lock_irqsave` is for classes taken in
/// interrupt context too; lockdep's hold histogram keeps every hold under
/// LOCK_MAX_HOLD_US ("never an unbounded IRQs-off spin").
#[repr(transparent)]
pub struct Global<T> {
    l: SpinLock<T>,
}

impl<T> Global<T> {
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub const fn new(v: T) -> Self {
        Global { l: SpinLock::new(v) }
    }

    #[inline(always)]
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        self.l.lock()
    }

    #[inline(always)]
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn lock_irqsave(&self) -> IrqSaveGuard<'_, T> {
        self.l.lock_irqsave()
    }
}

// ── Object<T, LEVEL> ─────────────────────────────────────────────────────

/// A lock per object, in a fixed level order (MODERN-OS-PLAN §2 #3:
/// AS -> MemObj -> frame; object wait_lock -> owner pi_lock -> run queue):
/// an Object of level L is taken only while every held Object is of a
/// lower level. [`Object::lock_under`] proves the order at compile time;
/// [`Object::lock`] has lockdep check it; two of one level go through
/// [`Object::lock_pair`] (address order).
#[repr(transparent)]
pub struct Object<T, const LEVEL: u8> {
    l: SpinLock<T>,
}

/// An [`Object`] held: its level travels in the type.
pub struct ObjectGuard<'a, T, const LEVEL: u8> {
    g: SpinLockGuard<'a, T>,
}

impl<T, const LEVEL: u8> core::ops::Deref for ObjectGuard<'_, T, LEVEL> {
    type Target = T;
    fn deref(&self) -> &T { &self.g }
}

impl<T, const LEVEL: u8> core::ops::DerefMut for ObjectGuard<'_, T, LEVEL> {
    fn deref_mut(&mut self) -> &mut T { &mut self.g }
}

// SAFETY: it holds a SpinLock guard, which holds preemption off.
unsafe impl<T, const LEVEL: u8> PreemptOff for ObjectGuard<'_, T, LEVEL> {}

impl<T, const LEVEL: u8> Object<T, LEVEL> {
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub const fn new(v: T) -> Self {
        const { assert!(LEVEL > 0, "Object levels start at 1") };
        Object { l: SpinLock::new(v) }
    }

    /// Take it; lockdep reports a held Object of level >= LEVEL.
    #[inline(always)]
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn lock(&self) -> ObjectGuard<'_, T, LEVEL> {
        ObjectGuard { g: self.l.lock_level(LEVEL, false) }
    }

    /// Take it under `outer`, an Object of a lower level: the order is a
    /// compile-time fact.
    #[inline(always)]
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn lock_under<U, const OUTER: u8>(&self, _outer: &ObjectGuard<'_, U, OUTER>) -> ObjectGuard<'_, T, LEVEL> {
        const { assert!(OUTER < LEVEL, "Object level order: the outer lock's level must be lower") };
        ObjectGuard { g: self.l.lock_level(LEVEL, false) }
    }

    /// Two objects of this level, lower address first (the illumos/seL4
    /// order; lockdep allows the second's equal level).
    #[inline(always)]
    #[cfg_attr(any(feature = "lat-trace", feature = "lockdep"), track_caller)]
    pub fn lock_pair<'a>(a: &'a Self, b: &'a Self) -> (ObjectGuard<'a, T, LEVEL>, ObjectGuard<'a, T, LEVEL>) {
        assert!(!core::ptr::eq(a, b), "lock_pair of one object");
        if (a as *const Self as usize) < (b as *const Self as usize) {
            let ga = ObjectGuard { g: a.l.lock_level(LEVEL, false) };
            let gb = ObjectGuard { g: b.l.lock_level(LEVEL, true) };
            (ga, gb)
        } else {
            let gb = ObjectGuard { g: b.l.lock_level(LEVEL, false) };
            let ga = ObjectGuard { g: a.l.lock_level(LEVEL, true) };
            (ga, gb)
        }
    }
}

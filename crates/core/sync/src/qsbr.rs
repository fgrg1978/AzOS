// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Quiescent-state-based read-copy-update (Kconfig RCU_QSBR, wave 15 N4;
//! `rfcs/survey/MUTEX.md` §5.5, owner answer Q2: QSBR only, callbacks off
//! the RT CPUs).
//!
//! **Readers** take no lock: [`read`] (or [`read_in`] with a
//! [`PreemptOff`] token already in hand) holds preemption off on this CPU
//! for the section, and nothing else. A reader must not sleep in the
//! section (lockdep reports it: the section is a held entry of kind
//! [`Kind::Rcu`](crate::lockdep::Kind::Rcu)); a reader that must block takes
//! a reference on what it found first (rule F5; the capability tables' answer
//! is an index plus a generation, re-checked by the object's pool).
//!
//! **Writers** publish the new version, then free the old one only after a
//! grace period: [`call_rcu`] (any context; the callback runs later in the
//! callback task) or [`synchronize_rcu`] (task context, sleeps).
//!
//! **Quiescent states.** Two words per CPU, written only by that CPU:
//!
//! * `eqs`, odd while the CPU runs kernel code and even while it is in an
//!   extended quiescent state (idle, or user mode on an RT CPU); every
//!   transition adds to it, and so does a context switch (+2, staying odd).
//!   A CPU whose `eqs` was even when a grace period started, or has moved
//!   since, holds no reader from before it.
//! * `qs`, the grace-period number current when the CPU last returned to
//!   user mode from an interrupt (the tick's return included). At or past a
//!   grace period's number: passed.
//!
//! | event                                       | hook |
//! |---------------------------------------------|------|
//! | interrupt entry (from idle or an RT CPU's user mode: even → odd, fence; idle re-enters at its next `idle_enter`) | [`TrapBoundary::irq`] |
//! | return to user mode from an interrupt (`qs`; an RT CPU: odd → even)  | [`TrapBoundary::irq`] |
//! | syscall or exception entry / return on an RT CPU (odd ↔ even)       | [`TrapBoundary::exception`] |
//! | idle entry / exit (odd → even / even → odd, fence)                  | [`idle_enter`] / [`idle_exit`] |
//! | context switch (+2)                                                 | [`switch`] |
//!
//! A syscall's return on any other CPU reports nothing (that would cost
//! every syscall instructions for a report the next tick makes anyway): a
//! CPU running user code passes a quiescent state at its next tick, a
//! tickless idle CPU and an RT CPU in user mode without a tick are
//! quiescent without being woken (F5). No IPI is ever sent for a grace
//! period. A grace period ends when every online CPU but the waiter's own
//! has passed ([`Gp`]; the waiter is not in a read section: lockdep checks
//! [`synchronize_rcu`]'s caller).
//!
//! **Callbacks.** [`call_rcu`] pushes onto this CPU's lock-free list. One
//! kernel task, pinned to the lowest CPU outside RCU_NOCBS_CPUS
//! ([`callback_cpu`]), takes every CPU's list, waits one grace period and
//! runs them: no callback ever runs on a CPU in the mask.
//!
//! **Stalls.** A grace period older than RCU_STALL_TIMEOUT_MS is counted
//! once ([`stalls`]) with the first CPU still holding it
//! ([`last_stall_cpu`]).
//!
//! Off (Kconfig RCU_QSBR=n): [`ON`] is false, every hook is an empty inline
//! function, and the per-CPU table has no entries.

#[cfg(feature = "lockdep")]
use core::panic::Location;
use core::sync::atomic::{fence, AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use azos_arch::{Cpu as _, Interrupts as _, ARCH};

use crate::preempt::{critical_section, PreemptGuard};
use crate::qsbr_core as core_;
use crate::qsbr_core::DONE;
use crate::scope::PreemptOff;
use crate::waitqueue::WaitQueue;

/// Kconfig RCU_QSBR.
pub const ON: bool = azos_limits::RCU_QSBR;
/// Kconfig RCU_NOCBS_CPUS: CPUs that never run a callback.
pub const NOCBS_CPUS: usize = azos_limits::RCU_NOCBS_CPUS;
/// Kconfig RCU_STALL_TIMEOUT_MS.
pub const STALL_TIMEOUT_MS: u64 = azos_limits::RCU_STALL_TIMEOUT_MS as u64;
/// Kconfig RCU_GP_POLL_MS.
pub const GP_POLL_MS: u64 = azos_limits::RCU_GP_POLL_MS as u64;

const NCPU: usize = if ON { azos_limits::NR_CPUS } else { 0 };

#[repr(C, align(64))]
struct CpuState {
    /// Odd: in the kernel. Even: idle, or user mode on an RT CPU.
    eqs: AtomicU64,
    /// The grace-period number at this CPU's last interrupt return to user.
    qs: AtomicU64,
    /// This CPU's callbacks, newest first.
    cbs: AtomicPtr<RcuHead>,
}

/// Every CPU starts in the kernel (odd): the boot CPU runs `kernel_main`,
/// a secondary its bring-up.
static CPUS: [CpuState; NCPU] = [const { CpuState {
    eqs: AtomicU64::new(1),
    qs: AtomicU64::new(0),
    cbs: AtomicPtr::new(core::ptr::null_mut()),
} }; NCPU];

/// The current grace period's number (0: none started yet).
static GP_SEQ: AtomicU64 = AtomicU64::new(0);
static GPS_STARTED: AtomicU64 = AtomicU64::new(0);
static GPS_DONE: AtomicU64 = AtomicU64::new(0);
static STALLS: AtomicU32 = AtomicU32::new(0);
static LAST_STALL_CPU: AtomicU32 = AtomicU32::new(u32::MAX);
static QUEUED: AtomicU64 = AtomicU64::new(0);
static INVOKED: AtomicU64 = AtomicU64::new(0);
static NO_GRACE: AtomicBool = AtomicBool::new(false);
/// The kernel's clock and sleep (`set_hooks`): `fn() -> u64` and `fn(u64)`.
static NOW_MS: AtomicUsize = AtomicUsize::new(0);
static SLEEP_MS: AtomicUsize = AtomicUsize::new(0);
/// The callback task waits here for work.
static WORK: WaitQueue = WaitQueue::new();
/// Lockdep's class of a read section (a held entry, never ordered).
#[cfg(feature = "lockdep")]
static READ_CLASS: crate::lockdep::LockClass = crate::lockdep::LockClass::here(crate::lockdep::Kind::Rcu);
/// The address lockdep records a read section under.
#[cfg(feature = "lockdep")]
static READ_MARK: u8 = 0;

#[inline(always)]
fn this_cpu() -> usize {
    ARCH.hart_id()
}

#[inline(always)]
fn state(cpu: usize) -> Option<&'static CpuState> {
    CPUS.get(cpu)
}

// ── Quiescent-state hooks ────────────────────────────────────────────────

/// Whether `cpu` is an RT CPU (Kconfig RCU_NOCBS_CPUS): its user mode is an
/// extended quiescent state. A constant `false` when the mask is 0.
#[inline(always)]
fn rt_cpu(cpu: usize) -> bool {
    NOCBS_CPUS != 0 && cpu < usize::BITS as usize && NOCBS_CPUS & (1 << cpu) != 0
}

/// Leave an extended quiescent state if this CPU is in one: even → odd,
/// then a full fence, so no read below is satisfied before a grace-period
/// waiter can see the CPU in the kernel. Interrupts off, or the pinned
/// idle task ([`idle_exit`]). Returns whether it left one.
#[inline(always)]
fn eqs_exit() -> bool {
    let Some(s) = state(this_cpu()) else { return false };
    match core_::enter(s.eqs.load(Ordering::Relaxed)) {
        Some(v) => {
            s.eqs.store(v, Ordering::Relaxed);
            fence(Ordering::SeqCst);
            true
        }
        None => false,
    }
}

/// Enter an extended quiescent state: odd → even, a release (every read
/// this CPU did in the kernel is ordered before a waiter sees it even).
///
/// Unmasked, for a context that cannot move to another CPU (the pinned
/// idle task): an interrupt
/// between the load and the store may switch tasks and back, and the store
/// then writes a stale value. That is safe: it runs in idle code, outside
/// any read section, after the switch that already was a quiescent state,
/// and a waiter that sees a value it snapshotted again only waits longer.
#[inline(always)]
fn eqs_enter_here() {
    if let Some(s) = state(this_cpu()) {
        if let Some(v) = core_::leave(s.eqs.load(Ordering::Relaxed)) {
            s.eqs.store(v, Ordering::Release);
        }
    }
}

/// [`eqs_enter_here`] with interrupts masked around it, for a task that
/// may migrate (an RT CPU's return to user mode): a preemption between
/// reading the CPU and writing its word would write another CPU's.
#[inline(always)]
fn eqs_enter() {
    let prev = ARCH.disable_all();
    eqs_enter_here();
    ARCH.restore(prev);
}

/// Report a quiescent state for every grace period started so far (a
/// return to user mode). Needs no masking: a task preempted between the
/// two accesses writes, into the CPU it left, a number that CPU's own
/// switch away already satisfied, and an older number than a later report
/// only delays a waiter.
#[inline(always)]
fn report_qs() {
    if let Some(s) = state(this_cpu()) {
        s.qs.store(GP_SEQ.load(Ordering::Acquire), Ordering::Release);
    }
}

/// QSBR at a trap handler's boundary, as a guard armed at its top. With
/// RCU_QSBR off it holds nothing and does nothing.
///
/// An interrupt that took the CPU out of idle's extended quiescent state
/// does not put it back on its return: the idle loop does, at its next
/// [`idle_enter`], before it waits again (the only kernel context that is
/// ever in the state is the idle task's wait). Until then the CPU counts as
/// in the kernel, which only makes a waiter wait the length of that loop.
pub struct TrapBoundary {
    to_user: bool,
}

impl TrapBoundary {
    /// An interrupt: leaves idle's (or an RT CPU's user) extended quiescent
    /// state on entry; on the return to user mode reports a quiescent state
    /// (an RT CPU: enters the extended one again).
    #[inline(always)]
    pub fn irq(from_user: impl FnOnce() -> bool) -> Self {
        if ON {
            let _ = eqs_exit();
            TrapBoundary { to_user: from_user() }
        } else {
            TrapBoundary { to_user: false }
        }
    }

    /// A syscall or another exception. Only an RT CPU (RCU_NOCBS_CPUS)
    /// does anything: its user mode is an extended quiescent state, left on
    /// entry and entered on the return. With the mask 0 this is nothing, on
    /// every syscall.
    #[inline(always)]
    pub fn exception(from_user: impl FnOnce() -> bool) -> Self {
        if ON && NOCBS_CPUS != 0 && rt_cpu(this_cpu()) {
            let _ = eqs_exit();
            TrapBoundary { to_user: from_user() }
        } else {
            TrapBoundary { to_user: false }
        }
    }
}

impl Drop for TrapBoundary {
    #[inline(always)]
    fn drop(&mut self) {
        if ON && self.to_user {
            if NOCBS_CPUS != 0 && rt_cpu(this_cpu()) {
                eqs_enter();
            } else {
                report_qs();
            }
        }
    }
}

/// The idle task is about to wait for an interrupt: an extended quiescent
/// state (odd → even). The idle task is pinned to its CPU, so no masking
/// (`eqs_enter_here`).
#[inline(always)]
pub fn idle_enter() {
    if ON {
        eqs_enter_here();
    }
}

/// The idle task's wait returned: even → odd, then a full fence. Unmasked
/// for the same reason; a stale store here leaves the CPU odd (in the
/// kernel), which is what it is.
#[inline(always)]
pub fn idle_exit() {
    if ON {
        let _ = eqs_exit();
    }
}

/// A context switch on this CPU (interrupts off): a quiescent state, +2
/// (or +1 and a fence if the CPU was, wrongly, even: a switch runs in the
/// kernel).
#[inline(always)]
pub fn switch() {
    if ON {
        if let Some(s) = state(this_cpu()) {
            let v = s.eqs.load(Ordering::Relaxed);
            s.eqs.store(core_::switch(v), Ordering::Release);
            if core_::quiescent(v) {
                fence(Ordering::SeqCst);
            }
        }
    }
}

/// `cpu`'s two words, `(eqs, qs)` (diagnostics and tests).
pub fn counters(cpu: usize) -> (u64, u64) {
    state(cpu).map_or((0, 0), |s| (s.eqs.load(Ordering::Relaxed), s.qs.load(Ordering::Relaxed)))
}

// ── Read sections ────────────────────────────────────────────────────────

/// A read section: preemption is off on this CPU while it lives, so the
/// CPU passes no quiescent state and nothing read under it is freed. With
/// lockdep, a held entry (sleeping in it, or returning to user mode with
/// it, is reported; it orders against no lock).
pub struct ReadGuard<'a> {
    _preempt: Option<PreemptGuard>,
    _token: core::marker::PhantomData<&'a ()>,
}

/// Open a read section (takes its own preemption guard).
#[inline(always)]
#[must_use = "the read section ends when the guard is dropped"]
#[cfg_attr(feature = "lockdep", track_caller)]
pub fn read() -> ReadGuard<'static> {
    let g = critical_section();
    lockdep_enter();
    ReadGuard { _preempt: Some(g), _token: core::marker::PhantomData }
}

/// Open a read section under a token that already holds preemption off
/// (a SpinLock guard, an `IrqOff`): no second guard.
#[inline(always)]
#[must_use = "the read section ends when the guard is dropped"]
#[cfg_attr(feature = "lockdep", track_caller)]
pub fn read_in<'a>(_t: &'a impl PreemptOff) -> ReadGuard<'a> {
    lockdep_enter();
    ReadGuard { _preempt: None, _token: core::marker::PhantomData }
}

impl Drop for ReadGuard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        #[cfg(feature = "lockdep")]
        crate::lockdep::release(&READ_MARK as *const u8 as usize, crate::lockdep::Kind::Rcu);
    }
}

#[inline(always)]
#[cfg_attr(feature = "lockdep", track_caller)]
fn lockdep_enter() {
    #[cfg(feature = "lockdep")]
    crate::lockdep::acquired(&READ_CLASS, &READ_MARK as *const u8 as usize, crate::lockdep::Kind::Rcu,
                             false, Location::caller());
}

// ── Grace periods ────────────────────────────────────────────────────────

/// One grace period's snapshot (a waiter's own; any number may be open).
pub struct Gp {
    seq: u64,
    snap: [u64; NCPU],
    start_ms: u64,
    stalled: bool,
}

impl Gp {
    /// Start a grace period at `now_ms`: everything published before this
    /// call is what the readers it waits for may still hold. `self_cpu` is
    /// the caller's CPU, not waited for.
    pub fn start(now_ms: u64, self_cpu: usize) -> Gp {
        // Order the caller's unpublish before the counter reads below (and
        // pair with the fence of a CPU leaving an extended quiescent state).
        let seq = GP_SEQ.fetch_add(1, Ordering::SeqCst) + 1;
        fence(Ordering::SeqCst);
        GPS_STARTED.fetch_add(1, Ordering::Relaxed);
        let mut snap = [DONE; NCPU];
        let n = azos_percpu::nr_cpu_ids().min(NCPU);
        for (cpu, e) in snap.iter_mut().enumerate().take(n) {
            if cpu == self_cpu || !azos_percpu::cpu_online(cpu) {
                continue;
            }
            *e = core_::snapshot(CPUS[cpu].eqs.load(Ordering::Acquire));
        }
        Gp { seq, snap, start_ms: now_ms, stalled: false }
    }

    /// Check every CPU still waited for; `true` once none is. Past
    /// RCU_STALL_TIMEOUT_MS, a stall is counted (once per grace period).
    pub fn poll(&mut self, now_ms: u64) -> bool {
        self.poll_within(now_ms, STALL_TIMEOUT_MS)
    }

    /// [`poll`](Self::poll) with a stall timeout of `timeout_ms` (a test of
    /// the detector, which cannot wait RCU_STALL_TIMEOUT_MS).
    pub fn poll_within(&mut self, now_ms: u64, timeout_ms: u64) -> bool {
        let mut first = None;
        for (cpu, e) in self.snap.iter_mut().enumerate() {
            if *e == DONE {
                continue;
            }
            if core_::passed(*e, CPUS[cpu].eqs.load(Ordering::Acquire))
                || CPUS[cpu].qs.load(Ordering::Acquire) >= self.seq
            {
                *e = DONE;
            } else if first.is_none() {
                first = Some(cpu);
            }
        }
        match first {
            None => {
                // Order every reader's section (seen ended above) before
                // what the caller frees next.
                fence(Ordering::SeqCst);
                GPS_DONE.fetch_add(1, Ordering::Relaxed);
                true
            }
            Some(cpu) => {
                if !self.stalled && core_::stalled(self.start_ms, now_ms, timeout_ms) {
                    self.stalled = true;
                    STALLS.fetch_add(1, Ordering::Relaxed);
                    LAST_STALL_CPU.store(cpu as u32, Ordering::Relaxed);
                }
                false
            }
        }
    }

    /// How many CPUs this grace period still waits for (at its start: the
    /// CPUs that were in the kernel; the others were quiescent).
    pub fn waiting(&self) -> usize {
        self.snap.iter().filter(|&&e| e != DONE).count()
    }

    /// The first CPU still waited for, if any (diagnostics).
    pub fn waiting_on(&self) -> Option<usize> {
        self.snap.iter().position(|&e| e != DONE)
    }
}

/// The kernel's millisecond clock and its sleep, for [`synchronize_rcu`]
/// and the callback task. Boot, once.
pub fn set_hooks(now_ms: fn() -> u64, sleep_ms: fn(u64)) {
    NOW_MS.store(now_ms as usize, Ordering::Release);
    SLEEP_MS.store(sleep_ms as usize, Ordering::Release);
}

fn now_ms() -> u64 {
    let raw = NOW_MS.load(Ordering::Acquire);
    if raw == 0 {
        return 0;
    }
    // SAFETY: only `set_hooks` stores here, a `fn() -> u64`.
    let f: fn() -> u64 = unsafe { core::mem::transmute::<usize, fn() -> u64>(raw) };
    f()
}

fn sleep_ms(ms: u64) {
    let raw = SLEEP_MS.load(Ordering::Acquire);
    if raw == 0 {
        core::hint::spin_loop();
        return;
    }
    // SAFETY: only `set_hooks` stores here, a `fn(u64)`.
    let f: fn(u64) = unsafe { core::mem::transmute::<usize, fn(u64)>(raw) };
    f(ms)
}

/// Wait for a grace period, sleeping RCU_GP_POLL_MS between checks. Task
/// context, never in a read section, never with a SpinLock held (lockdep
/// reports both). `limit_ms`: give up after this long (`false`); `None`
/// waits as long as it takes.
#[cfg_attr(feature = "lockdep", track_caller)]
pub fn synchronize_rcu_for(limit_ms: Option<u64>) -> bool {
    if !ON {
        return true;
    }
    crate::lockdep::might_sleep("qsbr::synchronize_rcu");
    let t0 = now_ms();
    let mut gp = Gp::start(t0, this_cpu());
    loop {
        let now = now_ms();
        if gp.poll(now) {
            return true;
        }
        if limit_ms.is_some_and(|l| now.wrapping_sub(t0) > l) {
            return false;
        }
        sleep_ms(GP_POLL_MS);
    }
}

/// [`synchronize_rcu_for`] with no limit.
#[cfg_attr(feature = "lockdep", track_caller)]
pub fn synchronize_rcu() {
    let _ = synchronize_rcu_for(None);
}

// ── Callbacks ────────────────────────────────────────────────────────────

/// The link a [`call_rcu`] object embeds (Linux's `rcu_head`).
#[repr(C)]
pub struct RcuHead {
    next: *mut RcuHead,
    func: Option<unsafe fn(*mut RcuHead)>,
}

impl RcuHead {
    pub const fn new() -> Self {
        RcuHead { next: core::ptr::null_mut(), func: None }
    }
}

impl Default for RcuHead {
    fn default() -> Self { Self::new() }
}

/// Run `f(head)` after a grace period, in the callback task (never on a CPU
/// in RCU_NOCBS_CPUS). Any context; no lock, no allocation: a push onto
/// this CPU's list and, if the callback task sleeps, a wake.
///
/// # Safety
/// `head` stays valid, and is not passed here again, until `f` has run.
pub unsafe fn call_rcu(head: *mut RcuHead, f: unsafe fn(*mut RcuHead)) {
    // Kconfig RCU_QSBR off, or the gate canary `rcu-free-no-grace`: now.
    if !ON || NO_GRACE.load(Ordering::Relaxed) {
        f(head);
        return;
    }
    (*head).func = Some(f);
    let cpu = this_cpu().min(NCPU.saturating_sub(1));
    let list = &CPUS[cpu].cbs;
    let mut old = list.load(Ordering::Relaxed);
    loop {
        (*head).next = old;
        match list.compare_exchange_weak(old, head, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => break,
            Err(cur) => old = cur,
        }
    }
    QUEUED.fetch_add(1, Ordering::Relaxed);
    if !WORK.is_empty() {
        WORK.wake_all();
    }
}

fn any_queued() -> bool {
    CPUS.iter().any(|s| !s.cbs.load(Ordering::Relaxed).is_null())
}

/// The CPU the callback task is pinned to: the lowest possible CPU outside
/// RCU_NOCBS_CPUS; `None` if every possible CPU is in it (the caller pins
/// to CPU 0 and says so).
pub fn callback_cpu() -> Option<usize> {
    core_::callback_cpu(azos_percpu::nr_cpu_ids(), NOCBS_CPUS, azos_percpu::cpu_possible)
}

/// The callback task's body: wait for queued callbacks, take every CPU's
/// list, wait a grace period, run them. Never returns.
pub fn callback_task() -> ! {
    loop {
        WORK.wait_if(|| !any_queued());
        let mut batch: *mut RcuHead = core::ptr::null_mut();
        for s in CPUS.iter() {
            let mut h = s.cbs.swap(core::ptr::null_mut(), Ordering::Acquire);
            // Append this CPU's list to the batch.
            while !h.is_null() {
                // SAFETY: a queued head stays valid until its callback ran.
                let next = unsafe { (*h).next };
                unsafe { (*h).next = batch };
                batch = h;
                h = next;
            }
        }
        if batch.is_null() {
            continue;
        }
        synchronize_rcu();
        while !batch.is_null() {
            // SAFETY: as above; `f` may free `batch`, so read `next` first.
            let next = unsafe { (*batch).next };
            if let Some(f) = unsafe { (*batch).func } {
                unsafe { f(batch) };
            }
            INVOKED.fetch_add(1, Ordering::Relaxed);
            batch = next;
        }
    }
}

/// Gate canary `rcu-free-no-grace`: [`call_rcu`] runs its callback at once.
pub fn canary_free_without_grace() {
    NO_GRACE.store(true, Ordering::Relaxed);
}

// ── Counters ─────────────────────────────────────────────────────────────

/// Grace-period stalls reported since boot.
pub fn stalls() -> u32 { STALLS.load(Ordering::Relaxed) }
/// The first CPU still holding the last stalled grace period.
pub fn last_stall_cpu() -> Option<usize> {
    match LAST_STALL_CPU.load(Ordering::Relaxed) {
        u32::MAX => None,
        c => Some(c as usize),
    }
}
/// Grace periods started and completed.
pub fn grace_periods() -> (u64, u64) {
    (GPS_STARTED.load(Ordering::Relaxed), GPS_DONE.load(Ordering::Relaxed))
}
/// Callbacks queued and run.
pub fn callbacks() -> (u64, u64) {
    (QUEUED.load(Ordering::Relaxed), INVOKED.load(Ordering::Relaxed))
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Futex wait, wake and requeue (wave 13, THREADS; wave 15 N9): the kernel
//! side of the table in [`crate::futex_table`].
//!
//! The native calls (`SYS_FUTEX_WAIT`/`WAKE`) and the Linux `futex` with
//! `FUTEX_PRIVATE_FLAG` file a [`Key::Private`] under the caller's process
//! id; a Linux futex without the flag on a word of a shm region files a
//! [`Key::Shared`] (Kconfig `FUTEX_SHARED`), the key the native notify calls
//! use, so both meet. The no-lost-wake argument is the table's.
//!
//! A waiter blocks on `WaitReason::Timer(deadline)` and a wake addresses it
//! by TID with that reason. A forced stop (`exit_group`, a kill) wakes it
//! through the same wake; it answers `EINTR` and the stop takes it at its
//! syscall boundary. Under the Linux personality a signal to deliver ends
//! the wait with `EINTR` as well, as on Linux.

use core::sync::atomic::{AtomicBool, Ordering};

pub use crate::futex_table::{Key, Look};
use crate::futex_table::{self as ft, FutexEnv, WaitResult};
use crate::scheduler::attrib::Src;
use crate::task::WaitReason;

/// Linux errno values the calls answer with (the native ABI uses the same).
pub const EAGAIN: i64 = 11;
pub const EINTR: i64 = 4;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const ENOSYS: i64 = 38;
pub const ETIMEDOUT: i64 = 110;

/// The kernel's environment: block on the timer reason, wake by TID.
struct KernelEnv;

impl FutexEnv for KernelEnv {
    fn now(&self) -> u64 {
        azos_drv_sys::timebase::now()
    }
    fn block(&self, deadline: u64) -> bool {
        crate::wait::task_block_outcome(WaitReason::Timer(deadline)) == crate::wait::BlockOutcome::Refused
    }
    fn wake(&self, tid: u32, _deadline: u64) {
        crate::scheduler::wake_task_by_tid_as(tid, &|r| matches!(r, WaitReason::Timer(_)), Src::Futex);
    }
    fn stopped(&self) -> bool {
        // A forced stop, or (Linux personality) a signal to deliver: Linux
        // ends a futex wait with EINTR then (plan note CB 09-10).
        crate::scheduler::current_stop_request().is_some()
            || (azos_limits::LINUX_ABI && crate::scheduler::signal::current_deliverable())
    }
}

/// [`KernelEnv`] for a word of a shm region (a notify word, `Key::Shared`): the
/// same environment, but the wake is logged as a notify (`wake` attribution).
struct NotifyEnv;

impl FutexEnv for NotifyEnv {
    fn now(&self) -> u64 {
        KernelEnv.now()
    }
    fn block(&self, deadline: u64) -> bool {
        KernelEnv.block(deadline)
    }
    fn wake(&self, tid: u32, _deadline: u64) {
        crate::scheduler::wake_task_by_tid_as(tid, &|r| matches!(r, WaitReason::Timer(_)), Src::Notify);
    }
    fn stopped(&self) -> bool {
        KernelEnv.stopped()
    }
}

/// Runtime canary `canary=futex-requeue-wake-all`: a requeue wakes every
/// waiter and moves none (the herd a requeue exists to avoid).
static CANARY_REQUEUE_WAKE_ALL: AtomicBool = AtomicBool::new(false);

/// Arm the `futex-requeue-wake-all` canary (boot only).
pub fn canary_requeue_wake_all() {
    CANARY_REQUEUE_WAKE_ALL.store(true, Ordering::Relaxed);
}

/// The calling task's private key for user address `addr`.
pub fn private_key(addr: u64) -> Option<Key> {
    let idx = crate::scheduler::current_slot()?;
    let tid = crate::scheduler::current_task_tid();
    Some(Key::Private { domain: crate::group::proc_of(idx, tid), addr })
}

fn errno(r: WaitResult) -> i64 {
    match r {
        WaitResult::Woken | WaitResult::Requeued | WaitResult::PiOwner => 0,
        WaitResult::Proxied => 0,
        WaitResult::Invalid => -EINVAL,
        WaitResult::TimedOut => -ETIMEDOUT,
        WaitResult::ValueChanged | WaitResult::NoSpace => -EAGAIN,
        WaitResult::Fault => -EFAULT,
        WaitResult::Refused | WaitResult::Stopped => -EINTR,
    }
}

/// Wait on the word `look` names (its key and value, [`Look`]) while it holds
/// `expected`, until a wake, the absolute deadline (timer ticks; `None`:
/// none) or a forced stop. Returns 0 (woken), `-EAGAIN` (the word differs),
/// `-ETIMEDOUT`, `-EINTR` or `-EFAULT`. The waiter is filed under the key of
/// the look, which is taken once, with the table locked. A caller waiting on a
/// user word reads it once before (`azos_syscall::vdso_notify::futex_precheck`:
/// an unreadable or differing word is answered without the table, and the
/// look under the lock is then at a page already resolved).
pub fn wait(look: Look, expected: u32, deadline: Option<u64>) -> i64 {
    let tid = crate::scheduler::current_task_tid();
    errno(ft::wait_key(&KernelEnv, tid, look, expected, deadline.unwrap_or(u64::MAX)))
}

/// Wake at most `n` waiters on `key`. Returns how many were woken, or
/// `-EINVAL` with nobody woken when a `FUTEX_WAIT_REQUEUE_PI` waiter is
/// among them (owner decision 10-10, as Linux; never with Kconfig
/// `FUTEX_PI` n).
pub fn wake_key(key: Key, n: u32) -> i64 {
    // Gate canary only: a wake that wakes nobody (the joins and the contended
    // locks of the thread rows never return).
    if cfg!(feature = "futex-wake-noop-canary") {
        return 0;
    }
    let woken = match key {
        Key::Private { .. } => ft::wake_key_checked(&KernelEnv, key, n),
        Key::Shared { .. } => ft::wake_key_checked(&NotifyEnv, key, n),
    };
    match woken {
        Ok(k) => k as i64,
        Err(r) => errno(r),
    }
}

/// [`wake_key`] for process `proc_id` (the exit path's clear-tid wake, which runs
/// as the exiting member). A word of a shm region wakes its region's key
/// (owner decision 10-10, Linux `mm_release` keys it shared): the lookup in
/// [`robust_key`] runs here, before `wake_key` takes the table lock.
pub fn wake_in(proc_id: u32, addr: u64, n: u32) -> i64 {
    wake_key(robust_key(proc_id, addr), n)
}

azos_common::ro_hook! {
    /// The sched -> ipc lookup (owner decision 10-10): `(region, offset)` of
    /// the word at `addr` when process `proc_id` maps it from a shm region
    /// (`azos_ipc::memobj::memobj_resolve_mapped`). Boot registers it; unset = none.
    static SHM_WORD_OF: fn(u32, u64) -> Option<(u32, u32)>;
}

/// Install the shm lookup the exit wakes (robust walk, clear-tid) key their
/// words with. Boot, once.
/// The lookup takes `MEMOBJS` and must never take the futex table:
/// it runs before, never under, the table lock (order TABLE -> MEMOBJS).
pub fn register_shm_word_of(f: fn(u32, u64) -> Option<(u32, u32)>) {
    SHM_WORD_OF.set(f);
}

/// The key the exit wakes (robust walk, clear-tid) use for a word at `addr` (process
/// `proc_id`; owner decision 10-10, Linux `handle_futex_death` keys the
/// word shared): a word of a shm region is `Key::Shared { region, offset }`
/// (Kconfig `FUTEX_SHARED`), the key N9's shared waiters and N10b's shared
/// PI words sleep on; any other word is the process's private key.
pub fn robust_key(proc_id: u32, addr: u64) -> Key {
    let shm = match SHM_WORD_OF.get() {
        Some(f) if ft::SHARED => f(proc_id, addr),
        _ => None,
    };
    ft::exit_word_key(proc_id, addr, shm)
}

/// Linux `FUTEX_REQUEUE` (`cmp` `None`) / `FUTEX_CMP_REQUEUE`: wake up to
/// `nr_wake` waiters on the word `look` names (`from`), move up to
/// `nr_requeue` more to `to`. Returns `(woken, moved)`, `-EAGAIN` when the
/// word does not hold `cmp`, `-ENOSYS` with Kconfig `FUTEX_REQUEUE` off,
/// `-EINVAL` with nothing done when the two keys differ in kind or a
/// `FUTEX_WAIT_REQUEUE_PI` waiter is among those it would take (owner
/// decision 10-10, as Linux).
pub fn requeue(look: Look, to: Key, nr_wake: u32, nr_requeue: u32, cmp: Option<u32>) -> Result<(u32, u32), i64> {
    if !ft::REQUEUE {
        return Err(-ENOSYS);
    }
    let wake_all = CANARY_REQUEUE_WAKE_ALL.load(Ordering::Relaxed);
    ft::requeue_key(&KernelEnv, look, to, nr_wake, nr_requeue, cmp, wake_all).map_err(errno)
}

// ── The PI seam (interface §4): one key's slot, lent under the table lock ──

use azos_sync::pi_futex::{PiBucket, UserFault};
use azos_sync::waitgraph::TaskId;

/// The user word of a PI key, as the PI code reads and swaps it.
pub trait PiWord {
    fn read(&self) -> Result<u32, UserFault>;
    fn cmpxchg(&self, expected: u32, new: u32) -> Result<u32, UserFault>;
    /// Make the word writable with no lock held (a copy-on-write or not
    /// yet committed user page); `false`: nothing to do, or it cannot be.
    fn fault_in(&self) -> bool {
        false
    }
}

/// A word reached at a kernel address (a shm region's page, or a word the
/// caller pinned and translated).
pub struct KvaWord(pub &'static core::sync::atomic::AtomicU32);

impl PiWord for KvaWord {
    fn read(&self) -> Result<u32, UserFault> {
        Ok(self.0.load(Ordering::Acquire))
    }
    fn cmpxchg(&self, expected: u32, new: u32) -> Result<u32, UserFault> {
        Ok(match self.0.compare_exchange(expected, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(v) | Err(v) => v,
        })
    }
}

/// One futex key's PI view, valid only while the table lock is held:
/// what `azos_sync::pi_futex::PiFutexOps` receives as its bucket.
pub struct PiKeyGuard<'a> {
    table: &'a mut ft::FutexTable,
    entry: usize,
    key: Key,
    word: &'a dyn PiWord,
}

impl PiBucket for PiKeyGuard<'_> {
    fn pi_slot(&mut self) -> &mut u32 {
        self.table.pi_slot(self.entry)
    }
    fn read_word(&self) -> Result<u32, UserFault> {
        self.word.read()
    }
    fn cmpxchg_word(&mut self, expected: u32, new: u32) -> Result<u32, UserFault> {
        self.word.cmpxchg(expected, new)
    }
    // Owner decision 10-10: a slot mid-exit (`TASK_EXITING`) never becomes
    // a PI word's owner; the locker retries (`LockPiStep::Retry`).
    fn task_of_tid(&self, tid: u32) -> Option<TaskId> {
        crate::scheduler::live_idx_for_tid(tid).map(|i| i as TaskId)
    }
    fn tid_exiting(&self, tid: u32) -> bool {
        crate::scheduler::tid_is_exiting(tid)
    }
    fn key_rec(&self) -> [u64; 2] {
        self.key.to_rec()
    }
}

/// Run `f` on `key`'s PI view under the table lock; the key's entry is
/// given back afterwards if `f` left its slot empty. `None` when no entry
/// is free (or Kconfig `FUTEX_PI` is n): the caller answers `ENOMEM` /
/// `ENOSYS`. The PI code (N10) is the only caller.
pub fn with_pi_key<R>(key: Key, word: &dyn PiWord, f: impl FnOnce(&mut dyn PiBucket) -> R) -> Option<R> {
    let mut t = ft::TABLE.lock_irqsave();
    let entry = t.pi_entry(key)?;
    let r = {
        let mut g = PiKeyGuard { table: &mut t, entry, key, word };
        f(&mut g)
    };
    t.pi_put(key, entry);
    Some(r)
}

/// A PI word of the CURRENT address space, translated on every access
/// (`process::user_cas_u32_nofault`: a page-table walk, no fault, no
/// allocation, no TLB shootdown under the table lock), so a relock after
/// the sleep never trusts a translation taken before it. A copy-on-write
/// or not yet committed page answers `UserFault`; the call faults it in
/// with the lock dropped and retries (Linux `fault_in_user_writeable`).
pub struct UserWord(pub u64);

impl PiWord for UserWord {
    fn fault_in(&self) -> bool {
        crate::process::fault_in_user_writable(self.0 as usize)
    }
    fn read(&self) -> Result<u32, UserFault> {
        crate::UserPtr::<u32>::new(self.0).read().map_err(|_| UserFault)
    }
    fn cmpxchg(&self, expected: u32, new: u32) -> Result<u32, UserFault> {
        match crate::UserPtr::<u32>::new(self.0).cas_resident(expected, new) {
            Ok(()) => Ok(expected),
            Err(Some(seen)) => Ok(seen),
            Err(None) => Err(UserFault),
        }
    }
}

/// Wake the PI task in scheduler slot `t` (a new owner), lock dropped.
fn pi_wake(t: TaskId) {
    if let Some(tid) = crate::scheduler::tid_for_idx(t as usize) {
        KernelEnv.wake(tid, 0);
    }
}

/// Kconfig `FUTEX_PI_EXIT_RETRY_US` in timer ticks (at least one).
const EXIT_RETRY_TICKS: u64 = {
    let t = azos_drv_sys::timebase::TIMER_FREQ as u64 * azos_limits::FUTEX_PI_EXIT_RETRY_US as u64 / 1_000_000;
    if t == 0 { 1 } else { t }
};

/// One PI `futex` operation by the current task on `key`, whose user word
/// `word` reads and swaps (interface §4, the dispatcher's loop). `LOCK_PI`:
/// prepare under the table lock; on `Block`, drop it, run
/// `pi_futex::block_commit` (the wrapper: it holds the `futex-pi-no-edge`
/// canary; `EDEADLK` ends the call there), sleep on
/// `WaitReason::Timer(deadline)` with no lock held, relock and finish; a
/// spurious wake (`-EINTR` from the finish, no stop, no refused block)
/// restarts at the prepare. Returns 0 or `-errno` (`-ENOSYS` while
/// Kconfig `FUTEX_PI` is n or nothing is registered).
pub fn pi_call_key(key: Key, word: &dyn PiWord, cmd: azos_sync::pi_futex::PiCmd) -> i64 {
    use azos_sync::pi_futex::{self as pf, LockPiStep, PiCmd};
    let Some(ops) = pf::ops() else { return -ENOSYS };
    let Some(me) = crate::scheduler::current_slot() else { return -(pf::ESRCH as i64) };
    let me = me as TaskId;
    let (deadline, try_only) = match cmd {
        PiCmd::Unlock => {
            return match with_pi_key(key, word, |b| ops.unlock_pi(b, me)) {
                None => -(pf::ENOMEM as i64),
                Some(Err(e)) => e as i64,
                Some(Ok(woken)) => {
                    if let Some(t) = woken {
                        pi_wake(t);
                    }
                    0
                }
            };
        }
        PiCmd::TryLock => (u64::MAX, true),
        PiCmd::Lock { deadline } => (deadline.unwrap_or(u64::MAX), false),
    };
    loop {
        let p = match with_pi_key(key, word, |b| ops.lock_pi_prepare(b, me, try_only)) {
            None => return -(pf::ENOMEM as i64),
            Some(LockPiStep::Acquired) => return 0,
            Some(LockPiStep::Err(e)) => return e as i64,
            Some(LockPiStep::Block(p)) => p,
            // The owner is mid-exit: sleep Kconfig FUTEX_PI_EXIT_RETRY_US,
            // lock dropped, so its exit hands the word over; prepare again.
            Some(LockPiStep::Retry) => {
                let now = KernelEnv.now();
                if deadline != u64::MAX && now >= deadline {
                    return -(pf::ETIMEDOUT as i64);
                }
                if KernelEnv.stopped() {
                    return -(pf::EINTR as i64);
                }
                let _ = KernelEnv.block(now.saturating_add(EXIT_RETRY_TICKS).min(deadline));
                continue;
            }
        };
        // The table lock is dropped: walk (boost the owner chain), then sleep.
        if let Err(e) = pf::block_commit(p) {
            return -(e.errno() as i64);
        }
        let past = |now: u64| deadline != u64::MAX && now >= deadline;
        let stopped = KernelEnv.stopped();
        let refused = if stopped || past(KernelEnv.now()) { false } else { KernelEnv.block(deadline) };
        let timed_out = past(KernelEnv.now());
        let r = match with_pi_key(key, word, |b| ops.lock_pi_finish(b, me, timed_out)) {
            None => return -(pf::ENOMEM as i64),
            Some(r) => r,
        };
        if r == -pf::EINTR && !refused && !stopped && !KernelEnv.stopped() {
            continue;
        }
        return r as i64;
    }
}

/// Runtime canary `canary=futex-requeue-pi-plain`: `FUTEX_CMP_REQUEUE_PI`
/// takes no PI word for the top waiter and wakes every waiter as a plain
/// wake, so `FUTEX_WAIT_REQUEUE_PI` returns `EAGAIN` owning nothing.
static CANARY_REQUEUE_PI_PLAIN: AtomicBool = AtomicBool::new(false);

/// Arm the `futex-requeue-pi-plain` canary (boot only).
pub fn canary_requeue_pi_plain() {
    CANARY_REQUEUE_PI_PLAIN.store(true, Ordering::Relaxed);
}

/// Runtime canary `canary=futex-requeue-pi-no-proxy`: `FUTEX_CMP_REQUEUE_PI`
/// enqueues nobody on the PI word's graph object; every waiter but a
/// proxy-locking top wakes requeued and runs its own `LOCK_PI` (wave 15
/// N10d), so the owner is not boosted while they sleep.
static CANARY_REQUEUE_PI_NO_PROXY: AtomicBool = AtomicBool::new(false);

/// Arm the `futex-requeue-pi-no-proxy` canary (boot only).
pub fn canary_requeue_pi_no_proxy() {
    CANARY_REQUEUE_PI_NO_PROXY.store(true, Ordering::Relaxed);
}

/// Linux `FUTEX_WAIT_REQUEUE_PI` (wave 15 N10d, Kconfig `FUTEX_PI`): wait
/// on the word `look` names (`from`) while it holds `expected`, as a waiter that only
/// `FUTEX_CMP_REQUEUE_PI` to the PI word `to` (`to_word`) takes. Returns 0
/// owning `to`: the requeuer gave it the free word; or it enqueued it on
/// `to`'s graph object by proxy and it slept on until the handover (N10e;
/// it finishes the lock, Linux `rt_mutex_wait_proxy_lock`); or, woken
/// requeued or spuriously, it ran its own `LOCK_PI` on `to` with the same
/// absolute `deadline`. Otherwise `-EAGAIN` (the word differs, or a wake that was not a
/// requeue-PI took it), `-ETIMEDOUT`, `-EINTR`, `-EFAULT`, `-EDEADLK`
/// and `LOCK_PI`'s other answers; `-EINVAL` when `from == to`, `-ENOSYS`
/// while `FUTEX_PI` is n or nothing is registered.
pub fn wait_requeue_pi(look: Look, to: Key, expected: u32, deadline: Option<u64>, to_word: &dyn PiWord) -> i64 {
    use azos_sync::pi_futex::{self as pf, PiCmd};
    if !pf::ENABLED || pf::ops().is_none() {
        return -ENOSYS;
    }
    // `from == to` is refused under the lock, by the look's key. The caller
    // read the user word once before, as for [`wait`].
    let tid = crate::scheduler::current_task_tid();
    let until = deadline.unwrap_or(u64::MAX);
    let r = ft::wait_requeue_pi_key(&KernelEnv, tid, look, to, expected, until);
    if r == WaitResult::Proxied {
        // Enqueued on `to` by proxy while it slept: whatever woke it, finish
        // the lock there (owner, heir of an exited owner, or leave the graph
        // on a timeout or stop); a spurious wake locks it afresh below.
        let Some(ops) = pf::ops() else { return -ENOSYS };
        let Some(me) = crate::scheduler::current_slot() else { return -(pf::ESRCH as i64) };
        let past = until != u64::MAX && KernelEnv.now() >= until;
        let fin = with_pi_key(to, to_word, |b| ops.lock_pi_finish(b, me as TaskId, past));
        match fin {
            None => return -(pf::ENOMEM as i64),
            Some(e) if e == -pf::EINTR && !KernelEnv.stopped() => {}
            Some(e) => return e as i64,
        }
    }
    match r {
        WaitResult::PiOwner => 0,
        WaitResult::Requeued | WaitResult::Proxied => {
            let cmd = PiCmd::Lock { deadline };
            let r = pi_call_key(to, to_word, cmd);
            if r == -EFAULT && to_word.fault_in() {
                return pi_call_key(to, to_word, cmd);
            }
            r
        }
        // Woken without a requeue-PI (Linux: -EWOULDBLOCK).
        WaitResult::Woken => -EAGAIN,
        r => errno(r),
    }
}

/// Linux `FUTEX_CMP_REQUEUE_PI` (wave 15 N10d, Kconfig `FUTEX_PI`): when
/// the word `look` names (`from`) holds `cmpval`, take the top waiter and up
/// to `nr_requeue` more from `from`, every one a `FUTEX_WAIT_REQUEUE_PI` waiter bound for
/// the PI word `to` (`to_word`): the top wakes owning `to` if it was free
/// (`pi_futex::proxy_lock`, under the table lock); the rest are enqueued
/// on `to`'s graph object on their behalf, unwoken, boosting its owner at
/// once (`pi_futex::proxy_enqueue`, owner decision 10-10, Linux
/// `rt_mutex_start_proxy_lock`; [`ft::requeue_pi_key`]). Returns how many
/// were taken (Linux: woken + requeued), `-EAGAIN` (cmpval), `-EINVAL`
/// (a waiter is plain or bound elsewhere; `from == to`), `-EFAULT`,
/// `-ENOSYS` while `FUTEX_PI` is n or nothing is registered.
pub fn cmp_requeue_pi(look: Look, to: Key, nr_requeue: u32, cmpval: u32, to_word: &dyn PiWord) -> i64 {
    use azos_sync::pi_futex as pf;
    use ft::RequeuePiError as E;
    if !pf::ENABLED || pf::ops().is_none() {
        return -ENOSYS;
    }
    // `from == to` is refused under the lock, by the look's key.
    let plain = CANARY_REQUEUE_PI_PLAIN.load(Ordering::Relaxed);
    let n = nr_requeue.saturating_add(1);
    let mut proxy = |t: &mut ft::FutexTable, top: u32, more: bool| -> Result<bool, i32> {
        let Some(entry) = t.pi_entry(to) else { return Err(-(pf::ENOMEM)) };
        let r = {
            let mut g = PiKeyGuard { table: &mut *t, entry, key: to, word: to_word };
            pf::proxy_lock(&mut g, top, more)
        };
        t.pi_put(to, entry);
        r
    };
    let no_proxy = CANARY_REQUEUE_PI_NO_PROXY.load(Ordering::Relaxed);
    let mut enqueue = |t: &mut ft::FutexTable, tid: u32| -> bool {
        if no_proxy {
            return false;
        }
        let Some(entry) = t.pi_entry(to) else { return false };
        let r = {
            let mut g = PiKeyGuard { table: &mut *t, entry, key: to, word: to_word };
            pf::proxy_enqueue(&mut g, tid)
        };
        t.pi_put(to, entry);
        r
    };
    let mut retried = false;
    loop {
        return match ft::requeue_pi_key(&KernelEnv, look, to, n, cmpval, plain, &mut proxy, &mut enqueue) {
            Ok(k) => k as i64,
            Err(E::Fault) => -EFAULT,
            Err(E::ValueChanged) => -EAGAIN,
            Err(E::Invalid) => -EINVAL,
            // The PI word's page faulted under the lock: fault it in with
            // the lock dropped and run once more (nothing was taken).
            Err(E::Pi(e)) if e == -pf::EFAULT && !retried && to_word.fault_in() => {
                retried = true;
                continue;
            }
            Err(E::Pi(e)) => e as i64,
        };
    }
}

/// The futex table's [`azos_sync::pi_futex::PiTable`] (wave 15 N9/N10):
/// the Linux personality's private PI calls keyed by the caller's process
/// (a shm word without `FUTEX_PRIVATE_FLAG` is keyed by its region in
/// `azos_syscall::linux`), and the robust exit's PI words ([`robust_key`]).
pub struct FutexPiTable;
/// Boot registers it with `pi_futex::register_table` (Kconfig `FUTEX_PI`).
pub static PI_TABLE: FutexPiTable = FutexPiTable;

impl azos_sync::pi_futex::PiTable for FutexPiTable {
    fn call(&self, uaddr: u64, cmd: azos_sync::pi_futex::PiCmd) -> i64 {
        if uaddr & 3 != 0 {
            return -EINVAL;
        }
        let word = UserWord(uaddr);
        // Fault outside the lock: an unreadable word never reaches the table.
        if word.read().is_err() {
            return -EFAULT;
        }
        let Some(key) = private_key(uaddr) else { return -EFAULT };
        let r = pi_call_key(key, &word, cmd);
        // A copy-on-write (or untouched) page: the CAS under the lock does
        // not fault; break it here, lock dropped, and retry once.
        if r == -EFAULT && crate::process::fault_in_user_writable(uaddr as usize) {
            return pi_call_key(key, &word, cmd);
        }
        r
    }

    fn owner_died(&self, proc_id: u32, uaddr: u64, dead: TaskId) -> Option<bool> {
        let ops = azos_sync::pi_futex::ops()?;
        let word = UserWord(uaddr);
        // A shm word is keyed by its region (owner decision 10-10), resolved
        // here, before the table lock: TABLE is never held over MEMOBJS
        // here. The walk runs in the dying task's space, so the word is
        // still reached through `uaddr` (shm pages are never copy-on-write).
        let key = robust_key(proc_id, uaddr);
        // `Ok(None)` is both "nobody waits: the word is now OWNER_DIED" and
        // "the word is not the dead task's": the word itself tells them apart.
        let r = with_pi_key(key, &word, |b| {
            let before = b.read_word().ok()?;
            match ops.owner_died(b, dead) {
                Ok(Some(t)) => Some(Some(t)),
                Ok(None) if b.read_word().ok()? != before => Some(None),
                _ => None,
            }
        })??;
        if let Some(t) = r {
            pi_wake(t);
        }
        Some(r.is_some())
    }
}

/// A word the owner-exit hook never reads: `exit_handover` decides on the
/// state alone (the heir writes the word in its own address space).
struct NoWord;

impl PiWord for NoWord {
    fn read(&self) -> Result<u32, UserFault> {
        Err(UserFault)
    }
    fn cmpxchg(&self, _expected: u32, _new: u32) -> Result<u32, UserFault> {
        Err(UserFault)
    }
}

/// The graph's owner-exit hook for `EdgeKind::FutexPi` (owner decision
/// 10-10, Linux `exit_pi_state_list`): a task exits owning a PI word with
/// waiters that the robust walk did not hand over (no robust list, or the
/// word was not on it). Under the key the `pi_state` recorded, its top
/// waiter becomes the owner and is woken; it writes `TID | FUTEX_WAITERS`
/// itself (`OWNER_DIED` kept only if the robust walk set it). Boot
/// registers it when `WAIT_GRAPH` and `FUTEX_PI` are y.
impl azos_sync::waitgraph::OwnerDiedHook for FutexPiTable {
    fn owner_died(&self, obj: &azos_sync::waitgraph::PiWaiters, _dead: TaskId) {
        use azos_sync::pi_futex as pf;
        let Some((_, ps)) = pf::state_of_waiters(obj) else { return };
        let Some(key) = Key::from_rec(ps.key_rec()) else { return };
        if let Some(Some(t)) = with_pi_key(key, &NoWord, |b| pf::exit_handover(b, obj)) {
            pi_wake(t);
        }
    }
}

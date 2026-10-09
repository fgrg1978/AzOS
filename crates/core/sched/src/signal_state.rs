// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 13: the per-task signal words (RFC-0047 P3).
//!
//! **Which tasks have them.** A slot has signal state only once the Linux
//! personality attaches it ([`attach`], at the task's creation or fork).
//! The native ABI stays signal-free (owner decision P3, rounds 10-12): a
//! signal aimed at a native task is not posted here at all; the caller maps
//! it onto the stop request the native ABI already has (`task_stop`).
//!
//! **Lock-free on purpose.** A signal is posted from a syscall of another
//! task, from an exit (`SIGCHLD`) and from the console's receive interrupt
//! (`^C`): the words are atomics, and posting is a `fetch_or`, a counter and
//! the same TID wake a stop request uses. What a signal DOES (handler, mask,
//! default action) is decided only by the task itself, at its own return to
//! user mode (`azos_syscall::linux::on_return_to_user`).
//!
//! **The return-to-user check is one load.** [`WORK`] counts the slots with
//! anything pending (a posted signal, or a `rt_sigreturn` to apply); the trap
//! paths test it and call out of line only when it is not zero, so a task
//! that never sees a signal pays one load and a branch per return.
//!
//! **Threads (wave 13).** Every word here is per TASK (thread): the pending
//! set and the mask are a thread's own, as on Linux. The dispositions are the
//! process's (`CLONE_SIGHAND`: one personality entry per process), so the
//! discarded set is written to every member at once ([`set_current_ignored`]).
//! A thread-directed signal (`tkill`/`tgkill`) is posted to its TID as it is
//! ([`post_thread`]); a process-directed one ([`post`]: `kill`, `SIGCHLD`,
//! the console's `^C`) goes to a member that does not block it, the leader
//! first ([`deliver_to`]). Linux keeps a process-directed signal in a shared
//! pending set any member may later take; here it is posted to the member
//! chosen at that moment (to the leader when every member blocks it).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::{idx_for_tid, current_slot, wake_task_by_tid, MAX_TASKS};
use crate::task::WaitReason;

/// The TID the words of a slot belong to; 0 when the slot has no signal
/// state (a native task, or nothing attached yet).
static TID: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];
/// Posted, not yet taken (bit `n - 1` for signal `n`).
static PENDING: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
/// The task's signal mask (`rt_sigprocmask`).
static BLOCKED: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
/// Signals whose disposition discards them on arrival: `SIG_IGN`, or
/// `SIG_DFL` where the default is to ignore. Never `SIGKILL`.
static IGNORED: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
/// The TID that sent the latest signal (`si_pid`), 0 for the kernel.
static SENDER: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];
/// A `rt_sigreturn` waits to be applied at this slot's return to user mode.
static RESTORE: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];
/// Where that `rt_sigreturn` found its frame (the user stack pointer).
static RESTORE_SP: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
/// The `a0`/`x0` a restartable call was entered with, valid while
/// [`RESTART_SET`] is 1. Written when such a call returns `-EINTR` for a
/// signal; taken at that same return to user mode.
static RESTART: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
static RESTART_SET: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];
/// Signals posted, and taken for delivery, machine-wide (diagnostics).
static POSTED: AtomicU32 = AtomicU32::new(0);
static DELIVERED: AtomicU32 = AtomicU32::new(0);

/// Slots with work at their next return to user mode: a signal pending that
/// the mask lets through, or a sigreturn. The trap paths' one load. A signal
/// held back by its mask is NOT counted: a task that blocks one and has it
/// posted must not put every return to user mode, machine-wide, on the slow
/// path until it unblocks it ([`resync`]).
pub static WORK: AtomicU32 = AtomicU32::new(0);
/// Is this slot's deliverable set counted in [`WORK`]?
static COUNTED: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];

/// Bring slot `idx`'s place in [`WORK`] in line with its deliverable set
/// (pending and not blocked). Called after every change to either word, by
/// whoever made it (the poster on another hart, or the task itself): each
/// swap of [`COUNTED`] moves the count once, and the set is read again after
/// the swap, so two racing calls end with the count matching the last state
/// either of them saw.
fn resync(idx: usize) {
    loop {
        let d = PENDING[idx].load(Ordering::Acquire) & !BLOCKED[idx].load(Ordering::Acquire) != 0;
        if d {
            if COUNTED[idx].swap(1, Ordering::AcqRel) == 0 {
                WORK.fetch_add(1, Ordering::AcqRel);
            }
        } else if COUNTED[idx].swap(0, Ordering::AcqRel) != 0 {
            WORK.fetch_sub(1, Ordering::AcqRel);
        }
        let now = PENDING[idx].load(Ordering::Acquire) & !BLOCKED[idx].load(Ordering::Acquire) != 0;
        if now == d {
            return;
        }
    }
}

/// Is there signal work anywhere? One relaxed load: what the return-to-user
/// paths ask before calling out of line.
#[inline(always)]
pub fn work_pending() -> bool {
    WORK.load(Ordering::Relaxed) != 0
}

const fn bit(sig: u32) -> u64 {
    if sig == 0 || sig > 64 { 0 } else { 1u64 << (sig - 1) }
}
const SIGKILL: u32 = 9;
const UNBLOCKABLE: u64 = bit(9) | bit(19);

fn slot_of(tid: u32) -> Option<usize> {
    let idx = idx_for_tid(tid)?;
    (TID[idx].load(Ordering::Acquire) == tid).then_some(idx)
}

/// Give live task `tid` signal state: mask `blocked`, discarded set
/// `ignored`, nothing pending. A fork child passes its parent's mask and
/// dispositions; anything left in the slot from a previous occupant goes.
pub fn attach(tid: u32, blocked: u64, ignored: u64) -> bool {
    let Some(idx) = idx_for_tid(tid) else { return false };
    detach_slot(idx);
    BLOCKED[idx].store(blocked & !UNBLOCKABLE, Ordering::Relaxed);
    IGNORED[idx].store(ignored & !bit(SIGKILL), Ordering::Relaxed);
    TID[idx].store(tid, Ordering::Release);
    true
}

fn detach_slot(idx: usize) {
    TID[idx].store(0, Ordering::Release);
    PENDING[idx].store(0, Ordering::Release);
    resync(idx);
    if RESTORE[idx].swap(0, Ordering::AcqRel) != 0 {
        WORK.fetch_sub(1, Ordering::AcqRel);
    }
    RESTART_SET[idx].store(0, Ordering::Relaxed);
}

/// `tid` is exiting: its slot's words go, so the counter does not keep every
/// later return to user mode on the slow path.
pub fn detach(tid: u32) {
    if let Some(idx) = slot_of(tid) {
        detach_slot(idx);
    }
}

/// What a post did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posted {
    /// The target has no signal state: a native task (or none at all). The
    /// caller decides what the native ABI does instead.
    NotLinux,
    /// Its disposition discards the signal.
    Discarded,
    /// Pending; it is delivered at the target's next return to user mode.
    Pending,
    /// `SIGKILL`: ended through the forced-stop path (`128 + 9`).
    Killed,
}

/// The member of `tid`'s process that takes process-directed signal `sig`:
/// the leader if it does not block it, else the first member that does not,
/// else the leader. `tid` itself when its process has no other threads (one
/// load while no process has any).
pub fn deliver_to(tid: u32, sig: u32) -> u32 {
    // Gate canary only: the process's leader takes it, blocked or not.
    if !crate::group::any_groups() || cfg!(feature = "linux-sig-thread-canary") {
        return tid;
    }
    let lead = crate::group::proc_tid(tid);
    let b = bit(sig);
    let open = |t: u32| slot_of(t).is_some_and(|i| BLOCKED[i].load(Ordering::Acquire) & b == 0);
    if open(lead) {
        return lead;
    }
    let mut members = [0u32; crate::group::GROUP_THREADS_MAX as usize];
    let n = crate::group::members_of(lead, lead, &mut members).min(members.len());
    members[..n].iter().copied().find(|&t| open(t)).unwrap_or(lead)
}

/// Post process-directed `sig` (1..=64) to `tid`'s process from `sender`
/// (0: the kernel): a member that does not block it takes it
/// ([`deliver_to`]). Lock-free: callable from a syscall, an exit and an
/// interrupt handler.
pub fn post(tid: u32, sig: u32, sender: u32) -> Posted {
    post_thread(deliver_to(tid, sig), sig, sender)
}

/// Post `sig` to exactly thread `tid` (`tkill`/`tgkill`): if it blocks it,
/// it stays pending on that thread.
pub fn post_thread(tid: u32, sig: u32, sender: u32) -> Posted {
    let Some(idx) = slot_of(tid) else { return Posted::NotLinux };
    let b = bit(sig);
    if b == 0 {
        return Posted::Discarded;
    }
    if sig == SIGKILL {
        return if super::task_stop(tid, true, SIGKILL as u8) { Posted::Killed } else { Posted::NotLinux };
    }
    if IGNORED[idx].load(Ordering::Acquire) & b != 0 {
        return Posted::Discarded;
    }
    SENDER[idx].store(sender, Ordering::Relaxed);
    PENDING[idx].fetch_or(b, Ordering::AcqRel);
    resync(idx);
    POSTED.fetch_add(1, Ordering::Relaxed);
    if BLOCKED[idx].load(Ordering::Acquire) & b == 0 && tid != super::current_task_tid() {
        // The interruptible waits are `Timer` waits (console, pipe, sleep,
        // child exit), re-tested after each wake, as a stop request's.
        wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(_)));
    }
    Posted::Pending
}

/// Has the current task a signal pending that its mask does not block? What
/// every interruptible wait re-tests (and answers `-EINTR` to).
pub fn current_deliverable() -> bool {
    let Some(idx) = current_slot() else { return false };
    PENDING[idx].load(Ordering::Acquire) & !BLOCKED[idx].load(Ordering::Relaxed) != 0
}

/// Take the lowest pending signal the current task does not block:
/// `(signal, sender)`. The caller is the task itself, at its return to user
/// mode.
pub fn take_current() -> Option<(u32, u32)> {
    let idx = current_slot()?;
    let tid = unsafe { super::TASKS[idx].tid };
    if TID[idx].load(Ordering::Acquire) != tid {
        return None;
    }
    loop {
        let p = PENDING[idx].load(Ordering::Acquire);
        let ready = p & !BLOCKED[idx].load(Ordering::Relaxed);
        if ready == 0 {
            return None;
        }
        let sig = ready.trailing_zeros() + 1;
        let b = bit(sig);
        if PENDING[idx].compare_exchange(p, p & !b, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            resync(idx);
            DELIVERED.fetch_add(1, Ordering::Relaxed);
            return Some((sig, SENDER[idx].load(Ordering::Relaxed)));
        }
    }
}

/// The current task's mask; `None` without signal state.
pub fn current_blocked() -> Option<u64> {
    let idx = current_slot()?;
    (TID[idx].load(Ordering::Acquire) != 0).then(|| BLOCKED[idx].load(Ordering::Relaxed))
}

/// Set the current task's mask (`SIGKILL`/`SIGSTOP` never blocked). A signal
/// it unblocks is counted in [`WORK`] here, so it is delivered at this same
/// return to user mode.
pub fn set_current_blocked(mask: u64) {
    if let Some(idx) = current_slot() {
        BLOCKED[idx].store(mask & !UNBLOCKABLE, Ordering::Release);
        resync(idx);
    }
}

/// The current task's pending set (`rt_sigpending`).
pub fn current_pending() -> u64 {
    current_slot().map_or(0, |idx| PENDING[idx].load(Ordering::Acquire))
}

/// Set the discarded set (from the dispositions) of the current task and of
/// every other thread of its process: the dispositions are the process's. A
/// pending signal now discarded is dropped, as Linux drops it when `SIG_IGN`
/// is set.
pub fn set_current_ignored(ignored: u64) {
    let Some(idx) = current_slot() else { return };
    let ign = ignored & !bit(SIGKILL);
    let set = |i: usize| {
        IGNORED[i].store(ign, Ordering::Release);
        PENDING[i].fetch_and(!ign, Ordering::AcqRel);
        resync(i);
    };
    set(idx);
    let lead = crate::group::lead_of_idx(idx);
    if lead != 0 {
        let me = super::current_task_tid();
        let mut members = [0u32; crate::group::GROUP_THREADS_MAX as usize];
        let n = crate::group::members_of(lead, me, &mut members).min(members.len());
        for &t in &members[..n] {
            if let Some(i) = slot_of(t) {
                set(i);
            }
        }
    }
}

// ── How a child ended, for a Linux parent's `wait4` ─────────────────────────

/// Per slot: the signal that is ending this task (its default action, a
/// forced stop, a fault, a seccomp kill), 0 for an exit. Cleared when the
/// slot is filled again ([`clear_slot_signalled`]).
static SIGNALLED: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];

/// The current task is ending by signal `sig` (the caller exits right
/// after). A member of a thread group marks its leader too, whose exit
/// carries the process's end (the first mark wins, as the group's exit code
/// does).
pub fn mark_current_signalled(sig: u32) {
    let Some(idx) = current_slot() else { return };
    let _ = SIGNALLED[idx].compare_exchange(0, sig, Ordering::AcqRel, Ordering::Acquire);
    let lead = crate::group::lead_of_idx(idx);
    if lead != 0 {
        if let Some(l) = idx_for_tid(lead) {
            let _ = SIGNALLED[l].compare_exchange(0, sig, Ordering::AcqRel, Ordering::Acquire);
        }
    }
}

/// Slot `idx` is filled with a new task.
pub(crate) fn clear_slot_signalled(idx: usize) {
    if idx < MAX_TASKS {
        SIGNALLED[idx].store(0, Ordering::Relaxed);
    }
}

/// Children whose end was a signal, recorded for a Linux parent: `(child,
/// signal)`, oldest overwritten. TIDs are never reused, so a stale entry
/// names no other child.
static KILLED: azos_sync::SpinLock<[(u32, u32); 32]> = azos_sync::SpinLock::new([(0, 0); 32]);
static KILLED_NEXT: AtomicU32 = AtomicU32::new(0);

/// `note_exit`: the task in slot `idx` (`child`) is leaving with an exit
/// notice for `parent`. If it ended by a signal and `parent` is a Linux
/// task, remember which, for that parent's `wait4` ([`take_killed`]).
pub(crate) fn note_child_end(idx: usize, child: u32, parent: u32) {
    if idx >= MAX_TASKS {
        return;
    }
    let sig = SIGNALLED[idx].swap(0, Ordering::AcqRel);
    if sig == 0 || slot_of(parent).is_none() {
        return;
    }
    let i = KILLED_NEXT.fetch_add(1, Ordering::Relaxed) as usize % 32;
    KILLED.lock()[i] = (child, sig);
}

/// The signal child `child` ended by, if it did (taken once).
pub fn take_killed(child: u32) -> Option<u32> {
    if child == 0 {
        return None;
    }
    let mut k = KILLED.lock();
    let e = k.iter_mut().find(|e| e.0 == child)?;
    let sig = e.1;
    *e = (0, 0);
    Some(sig)
}

/// `rt_sigreturn` found its frame at `sp`: count it, so this return to user
/// mode takes the slow path and reads the frame back there.
pub fn set_current_restore(sp: u64) {
    if let Some(idx) = current_slot() {
        RESTORE_SP[idx].store(sp, Ordering::Relaxed);
        if RESTORE[idx].swap(1, Ordering::AcqRel) == 0 {
            WORK.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// Take the current task's pending sigreturn, if any: its frame's address.
pub fn take_current_restore() -> Option<u64> {
    let idx = current_slot()?;
    if RESTORE[idx].swap(0, Ordering::AcqRel) != 0 {
        WORK.fetch_sub(1, Ordering::AcqRel);
        return Some(RESTORE_SP[idx].load(Ordering::Relaxed));
    }
    None
}

/// A restartable call of the current task was interrupted: remember the
/// first argument it was entered with.
pub fn set_current_restart(a0: u64) {
    if let Some(idx) = current_slot() {
        RESTART[idx].store(a0, Ordering::Relaxed);
        RESTART_SET[idx].store(1, Ordering::Release);
    }
}

/// Take the current task's interrupted call's first argument, if one was
/// remembered since the last take.
pub fn take_current_restart() -> Option<u64> {
    let idx = current_slot()?;
    if RESTART_SET[idx].swap(0, Ordering::AcqRel) != 0 {
        return Some(RESTART[idx].load(Ordering::Relaxed));
    }
    None
}

/// `(posted, delivered)` since boot, machine-wide.
pub fn counts() -> (u32, u32) {
    (POSTED.load(Ordering::Relaxed), DELIVERED.load(Ordering::Relaxed))
}

/// Wave 15 (plan 4a): an exec from a thread that is not its process's leader
/// hands the leader's identity (`from`, the leader's slot) to the exec'ing
/// thread (`to`): the slot's signal words follow the TID. The process's
/// pending signals and its ignored set move to `to`; `to` keeps its own mask
/// and its own pending signals (Linux keeps the exec'ing thread's), and
/// `from`, about to end as a thread, keeps nothing.
pub(crate) fn hand_over(from: usize, to: usize) {
    if from >= MAX_TASKS || to >= MAX_TASKS {
        return;
    }
    let (ft, tt) = (TID[from].load(Ordering::Acquire), TID[to].load(Ordering::Acquire));
    TID[to].store(ft, Ordering::Release);
    TID[from].store(tt, Ordering::Release);
    // Canary `exec-sig-handover-canary` (gate rows `linux: exec-sig
    // handover canary`): the leader's pending set is dropped, not handed over.
    let moved = PENDING[from].swap(0, Ordering::AcqRel);
    if !cfg!(feature = "exec-sig-handover-canary") {
        PENDING[to].fetch_or(moved, Ordering::AcqRel);
    }
    IGNORED[to].store(IGNORED[from].load(Ordering::Acquire), Ordering::Release);
    SENDER[to].store(SENDER[from].load(Ordering::Acquire), Ordering::Release);
    resync(from);
    resync(to);
}

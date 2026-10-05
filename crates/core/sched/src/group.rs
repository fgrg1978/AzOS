// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Thread groups (wave 13, THREADS): tasks that share one address space, one
//! capability table and one descriptor table.
//!
//! A group is named by its leader's TID (the process id; Linux's tgid). Every
//! member is an ordinary task with its own TID, kernel stack, registers and
//! scheduling state. What it shares is reached through the leader:
//!
//! * the address space: every member runs on the leader's `satp`/TTBR0 (same
//!   root, same ASID), so the root-based TLB shootdown already reaches every
//!   hart running a member;
//! * the capability table: `cap_store` resolves a member's TID to the
//!   leader's table (`lead_of_idx`);
//! * the descriptor table: a descriptor's owner is the process id
//!   (`current_proc_tid`), and the Linux personality's per-process state is
//!   keyed by it;
//! * the program break, the shm/MMIO window reservations and the frame budget
//!   live on the leader's slot (`scheduler::proc_slot`).
//!
//! # Lifetime
//!
//! The leader's slot outlives every other member: a leader that exits while
//! members live waits in its exit path (`leader_wait_alone`) until it is the
//! last, and only then releases the shared resources and posts its exit
//! notice, which carries the group's exit code. A member's exit releases only
//! what is its own (its kernel stack, its slot, objects booked to its TID),
//! clears and wakes its clear-tid word (`CLONE_CHILD_CLEARTID`,
//! `set_tid_address`), and posts no notice: a thread is nobody's child.
//!
//! # Lock order
//!
//! Outermost: the group's layout lock ([`mm_lock`]), taken first by a call
//! that changes the shared address space (break, `mmap`/`munmap`, window
//! maps, a fork of the group) and held across what that call does: frame
//! allocation, page tables, the refcount table, a fork's capability tables,
//! descriptor table and pipe pool (`natfork`). It waits by yielding, so it
//! is never taken under a spinlock. Faults never take it: they install
//! entries by compare-and-swap (`vmm::walk`, `demand`, `cow`).
//!
//! `GROUPS` is a leaf: taken alone, never while holding the pool lock, a
//! capability table or the futex table; nothing it protects is read from an
//! interrupt. The futex table (`futex.rs`) is also a leaf; a futex wait reads
//! the user word under it (a fault there resolves without any lock this
//! module holds).
//!
//! A member's capability table and descriptors are its leader's, reached
//! through `cap_store::slot_for` and the descriptor owner (the process id):
//! no lock of their own, the existing per-table and `KERNEL_FD_TABLE` locks
//! serve every member.
//!
//! # Signals
//!
//! Thread-directed delivery belongs to the SIGNALS front. The hooks here are
//! [`members_of`] (who a process-directed signal may land on) and the
//! per-member TID every signal call already takes.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use azos_sync::spinlock::SpinLock;

use crate::task::MAX_TASKS;

/// Most live members of one group, the leader included. A create past it is
/// refused (`EAGAIN`), never dropped.
pub const GROUP_THREADS_MAX: u32 = azos_abi::syscall_nr::GROUP_THREADS_MAX as u32;
/// Most groups with more than one member at once. A create that would form
/// one more is refused (`EAGAIN`).
pub const GROUPS_MAX: usize = azos_abi::syscall_nr::GROUPS_MAX as usize;

/// Per pool slot: the leader TID of the slot's group; 0 for a task in no
/// group (its own process). The leader's own entry holds its own TID while
/// it has members.
static LEAD: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];

/// Per pool slot: the task is ending only itself (Linux `exit`, the native
/// thread exit), not its process. Read and cleared by the exit path.
static THREAD_ONLY: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];

/// The current task's next exit ends only itself.
pub(crate) fn mark_thread_only(idx: usize) {
    if idx < MAX_TASKS {
        THREAD_ONLY[idx].store(true, Ordering::Release);
    }
}

/// Take the thread-only mark of slot `idx`.
pub(crate) fn take_thread_only(idx: usize) -> bool {
    idx < MAX_TASKS && THREAD_ONLY[idx].swap(false, Ordering::AcqRel)
}

/// Per pool slot: the user address of the 32-bit word cleared and woken when
/// the task exits (`CLONE_CHILD_CLEARTID`, `set_tid_address`, the native
/// create's `ctid`); 0 for none. Updatable: musl's `pthread_exit` points it
/// at its thread-list lock right before exiting.
static CLEAR_TID: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];

#[derive(Clone, Copy)]
struct Group {
    /// Leader TID; 0 = free entry.
    leader: u32,
    /// Live members, the leader included.
    live: u32,
    /// `exit_group` (or a fault, a forced stop) ended the group: every member
    /// is being stopped and the leader reports `code`.
    exiting: bool,
    code: i32,
    /// The member holding the group's memory lock (`mm_lock`), 0 if none, and
    /// how many times it holds it.
    mm_owner: u32,
    mm_depth: u32,
}

const GROUP_FREE: Group = Group { leader: 0, live: 0, exiting: false, code: 0, mm_owner: 0, mm_depth: 0 };

static GROUPS: SpinLock<[Group; GROUPS_MAX]> = SpinLock::new([GROUP_FREE; GROUPS_MAX]);

/// A slot is being (re)used: it belongs to no group and clears nothing.
pub(crate) fn slot_reset(idx: usize) {
    if idx < MAX_TASKS {
        LEAD[idx].store(0, Ordering::Relaxed);
        CLEAR_TID[idx].store(0, Ordering::Relaxed);
        THREAD_ONLY[idx].store(false, Ordering::Relaxed);
    }
}

/// Groups with more than one member right now. While it is 0 (the common
/// case: no process has threads) [`lead_of_idx`] answers without touching
/// the per-slot table.
static GROUPS_LIVE: AtomicU32 = AtomicU32::new(0);

/// Does any process have threads right now? One load: what the capability
/// table resolution asks before it looks a slot's leader up.
#[inline(always)]
pub fn any_groups() -> bool {
    GROUPS_LIVE.load(Ordering::Relaxed) != 0
}

/// The leader TID of the group the task in slot `idx` belongs to, 0 for
/// none. What `cap_store::slot_for` asks on every typed call: one load while
/// no process has threads, two otherwise. Relaxed: a slot's entry is written
/// before its task can run (`join` precedes the hand-off's release), and a
/// group forms (`GROUPS_LIVE` rises) before any member's entry is written.
#[inline(always)]
pub fn lead_of_idx(idx: usize) -> u32 {
    if GROUPS_LIVE.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    match LEAD.get(idx) {
        Some(l) => l.load(Ordering::Relaxed),
        None => 0,
    }
}

/// The leader whose capability table the task in slot `idx` uses: what
/// `cap_store` resolves a TID through ([`lead_of_idx`], except in the gate
/// canary `threads-private-table-canary`, where every thread keeps a table of
/// its own).
#[inline(always)]
pub fn table_lead_of_idx(idx: usize) -> u32 {
    if cfg!(feature = "threads-private-table-canary") {
        return 0;
    }
    lead_of_idx(idx)
}

/// The process id of task `tid` in slot `idx`: its leader's TID, or its own.
#[inline(always)]
pub fn proc_of(idx: usize, tid: u32) -> u32 {
    let l = lead_of_idx(idx);
    if l == 0 { tid } else { l }
}

/// The process id of live task `tid` (`tid` itself when it is in no group or
/// gone).
pub fn proc_tid(tid: u32) -> u32 {
    match crate::scheduler::idx_for_tid(tid) {
        Some(idx) => proc_of(idx, tid),
        None => tid,
    }
}

/// Is live task `tid` a member of a group other than its leader? Its
/// capability table and descriptors are then the leader's, and its exit must
/// not release them.
pub fn shares_tables(tid: u32) -> bool {
    match crate::scheduler::idx_for_tid(tid) {
        Some(idx) => {
            let l = lead_of_idx(idx);
            l != 0 && l != tid
        }
        None => false,
    }
}

/// Set the clear-tid word of the task in slot `idx`.
pub fn set_clear_tid(idx: usize, addr: u64) {
    if idx < MAX_TASKS {
        CLEAR_TID[idx].store(addr, Ordering::Release);
    }
}

/// Set the current task's clear-tid word (`set_tid_address`).
pub fn set_current_clear_tid(addr: u64) {
    if let Some(idx) = crate::scheduler::current_slot() {
        set_clear_tid(idx, addr);
    }
}

/// Take the clear-tid word of the task in slot `idx` (0 for none).
pub(crate) fn take_clear_tid(idx: usize) -> u64 {
    if idx < MAX_TASKS { CLEAR_TID[idx].swap(0, Ordering::AcqRel) } else { 0 }
}

/// Admit one more member into `leader`'s group, forming the group when
/// `leader` has none yet. `false` when the group is full or no group entry
/// is free. On `true` the caller must either [`join`] the new member or
/// [`unadmit`].
pub(crate) fn admit(leader: u32, leader_idx: usize) -> bool {
    let mut g = GROUPS.lock();
    if let Some(e) = g.iter_mut().find(|e| e.leader == leader) {
        if e.live >= GROUP_THREADS_MAX || e.exiting {
            return false;
        }
        e.live += 1;
        return true;
    }
    let Some(e) = g.iter_mut().find(|e| e.leader == 0) else { return false };
    *e = Group { leader, live: 2, ..GROUP_FREE };
    GROUPS_LIVE.fetch_add(1, Ordering::Relaxed);
    LEAD[leader_idx].store(leader, Ordering::Release);
    true
}

/// Undo an [`admit`] whose task was never created.
pub(crate) fn unadmit(leader: u32, leader_idx: usize) {
    let mut g = GROUPS.lock();
    if let Some(e) = g.iter_mut().find(|e| e.leader == leader) {
        e.live = e.live.saturating_sub(1);
        if e.live <= 1 {
            *e = GROUP_FREE;
            LEAD[leader_idx].store(0, Ordering::Release);
            GROUPS_LIVE.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// The new member in slot `idx` belongs to `leader`'s group. Before it can
/// run (the slot is parked until its hand-off is published).
pub(crate) fn join(idx: usize, leader: u32) {
    if idx < MAX_TASKS {
        LEAD[idx].store(leader, Ordering::Release);
    }
}

/// Live members of `leader`'s group (1 when it has no group).
pub fn live_members(leader: u32) -> u32 {
    GROUPS.lock().iter().find(|e| e.leader == leader).map_or(1, |e| e.live)
}

/// Is `leader`'s group ending (exit_group, a fault, a forced stop), and
/// with which code?
pub fn exiting(leader: u32) -> Option<i32> {
    GROUPS.lock().iter().find(|e| e.leader == leader && e.exiting).map(|e| e.code)
}

/// Is the current task a member of a thread group that is ending? A forced
/// stop it takes then needs no console line.
pub fn current_group_ending() -> bool {
    crate::scheduler::current_slot().is_some_and(|i| {
        let l = lead_of_idx(i);
        l != 0 && exiting(l).is_some()
    })
}

/// A member (not the leader) of `leader`'s group has gone. Returns the
/// members left. Releases the group's memory lock if the member held it (a
/// member killed inside a memory call must not leave its siblings spinning).
pub(crate) fn member_gone(leader: u32, tid: u32) -> u32 {
    let mut g = GROUPS.lock();
    let Some(e) = g.iter_mut().find(|e| e.leader == leader) else { return 1 };
    e.live = e.live.saturating_sub(1);
    if e.mm_owner == tid {
        e.mm_owner = 0;
        e.mm_depth = 0;
    }
    let live = e.live;
    // The leader is alone again and the group is not ending: it is a plain
    // process once more (what it shared was its own all along). An ending
    // group stays until its leader's exit, which reads the group's code.
    // Safe to drop the group here, in the last member's exit: that member has
    // already cleared its word, run its exit hook and left the shared root
    // (`scheduler::member_exit`), so it can no longer fault on the address
    // space; no other member exists. A fork the leader starts afterwards is
    // a single-threaded fork again (`fork_cow` stores plainly).
    if live <= 1 && !e.exiting {
        *e = GROUP_FREE;
        drop(g);
        if let Some(i) = crate::scheduler::idx_for_tid(leader) {
            LEAD[i].store(0, Ordering::Release);
        }
        GROUPS_LIVE.fetch_sub(1, Ordering::Relaxed);
    }
    live
}

/// The group of `leader` ends: mark it so (first code wins) and return
/// whether this call started it.
pub(crate) fn begin_exit(leader: u32, code: i32) -> bool {
    let mut g = GROUPS.lock();
    match g.iter_mut().find(|e| e.leader == leader) {
        Some(e) if !e.exiting => {
            e.exiting = true;
            e.code = code;
            true
        }
        _ => false,
    }
}

/// The leader is the last member and is leaving: its group is dissolved.
pub(crate) fn dissolve(leader: u32, leader_idx: usize) {
    let mut g = GROUPS.lock();
    if let Some(e) = g.iter_mut().find(|e| e.leader == leader) {
        *e = GROUP_FREE;
        GROUPS_LIVE.fetch_sub(1, Ordering::Relaxed);
    }
    drop(g);
    if leader_idx < MAX_TASKS {
        LEAD[leader_idx].store(0, Ordering::Release);
    }
}

/// The live members of `leader`'s group other than `except`, into `out`;
/// how many. The hook a process-directed signal and `exit_group` use.
pub fn members_of(leader: u32, except: u32, out: &mut [u32]) -> usize {
    let mut n = 0;
    for idx in 0..MAX_TASKS {
        if LEAD[idx].load(Ordering::Acquire) != leader {
            continue;
        }
        let Some(tid) = crate::scheduler::tid_for_idx(idx) else { continue };
        if tid == except || tid == 0 {
            continue;
        }
        if n < out.len() {
            out[n] = tid;
        }
        n += 1;
    }
    n
}

// ── The group's memory lock ────────────────────────────────────────────────

/// Held across a call that changes the shared address space's layout (the
/// program break, `mmap`/`munmap`, a window map, a fork of the group): two
/// members must not both read the break and map the same pages. Re-entrant
/// for its holder. A task in no group takes nothing (one load).
pub struct MmGuard {
    leader: u32,
}

/// Take the current task's group memory lock (nothing for a task in no
/// group). Waits by yielding the hart, so a holder on the same hart runs.
pub fn mm_lock() -> MmGuard {
    let Some(idx) = crate::scheduler::current_slot() else { return MmGuard { leader: 0 } };
    let leader = lead_of_idx(idx);
    if leader == 0 {
        return MmGuard { leader: 0 };
    }
    let me = crate::scheduler::current_task_tid();
    loop {
        {
            let mut g = GROUPS.lock();
            match g.iter_mut().find(|e| e.leader == leader) {
                Some(e) if e.mm_owner == 0 || e.mm_owner == me => {
                    e.mm_owner = me;
                    e.mm_depth += 1;
                    return MmGuard { leader };
                }
                Some(_) => {}
                // Dissolved meanwhile: this task is alone again.
                None => return MmGuard { leader: 0 },
            }
        }
        crate::task_yield();
    }
}

impl Drop for MmGuard {
    fn drop(&mut self) {
        if self.leader == 0 {
            return;
        }
        let mut g = GROUPS.lock();
        if let Some(e) = g.iter_mut().find(|e| e.leader == self.leader) {
            e.mm_depth = e.mm_depth.saturating_sub(1);
            if e.mm_depth == 0 {
                e.mm_owner = 0;
            }
        }
    }
}

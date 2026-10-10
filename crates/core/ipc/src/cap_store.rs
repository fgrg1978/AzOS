// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-task capability tables, indexed by **task pool slot**.
//!
//! Each task gets its own [`crate::cap::CapTable`]; the kernel reaches
//! it through this module's accessors. The table is **dense**: a fixed
//! `[SpinLock<CapTable>; MAX_TASKS]` lives in BSS and survives the
//! lifetime of the kernel.
//!
//! Memory cost: `MAX_TASKS × sizeof(CapTable)` ≈ 64 × ~2 KiB = 128 KiB
//! on default builds; configs that lower `MAX_TASKS` scale down linearly.
//!
//! # Why slot-indexed and not TID-indexed (W3-F4)
//!
//! These tables used to be indexed by TID, guarded by
//! `is_valid_tid(tid) = (tid as usize) < MAX_TASKS`. TIDs are **monotone**:
//! `scheduler.rs` does `NEXT_TID = NEXT_TID.wrapping_add(1)` and never
//! reissues a low value until it has wrapped 2^32. `MAX_TASKS` is 64. So
//! from the 64th task creation onward — trivially reached, `fork()` is
//! unprivileged — every `grant` / `get` / `with_table` returned `None` and
//! every typed-cap syscall answered `EINVAL`. Fail-closed, so not an
//! escalation; but it silently *disabled the better mechanism*: the typed
//! `Cap<T>` path that carries the Kani proofs became unreachable on any
//! long-running robot, and everything fell back to the legacy global handle
//! table with its guessable indices.
//!
//! The pool slot index (`0..MAX_TASKS`) is the quantity that is actually
//! bounded by `MAX_TASKS`, so that is what indexes the array. The cost is a
//! `azos_sched::idx_for_tid` lookup — an O(64) unsynchronised scan of
//! `TASK_VALID`/`TASKS`, the same scan the APS dispatch path already does —
//! on every capability operation. No locks and no interrupt toggling, unlike
//! the legacy handle-table scan it replaces.
//!
//! # Slot reuse
//!
//! Slot indices, unlike TIDs, *are* recycled. [`OWNER`] records which TID a
//! slot's table currently belongs to and every accessor lazily wipes the
//! table when it finds a mismatch — so a new task can never inherit the
//! previous occupant's caps, even on a path that skips [`reset`]. This is
//! deliberate belt-and-braces: `crates/core/sched`'s task-creation path cannot be
//! modified from here, so correctness must not depend on it calling us.
//!
//! # Lifecycle
//!
//! - Every pool slot has an always-present, initially-empty `CapTable`
//!   from boot.
//! - `task_exit` calls [`crate::task_release_all`], which calls [`reset`]
//!   — see that function's doc for the ordering constraint that makes it
//!   land on the right slot.
//! - Any accessor that observes a slot whose recorded owner differs from
//!   the TID being looked up wipes it first (see above).
//!
//! # Concurrency
//!
//! One spinlock per slot. Different tasks acquiring different slots
//! never contend. The same task's syscall path is single-threaded
//! per CPU, so contention on a single slot is rare.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use azos_sched::task::MAX_TASKS;
use azos_sync::spinlock::SpinLock;

use crate::cap::{Cap, CapError, CapHandle, CapPerms, CapTable, CapTarget};

/// A task-pool slot's capability table and the lock its writers take.
///
/// The lock sits beside the table rather than around it: the table's slots
/// are atomic words (`CapTable`'s docs), so a reader holding no lock
/// ([`read_table`], Kconfig RCU_QSBR) and a writer holding this one never
/// alias a `&mut`. Writers still exclude each other, as before.
struct TableCell {
    lock: SpinLock<()>,
    table: CapTable,
}

/// A locked table: writes through it are serialised with every other
/// writer of that table.
struct Locked {
    _g: azos_sync::SpinLockGuard<'static, ()>,
    t: &'static CapTable,
}

impl core::ops::Deref for Locked {
    type Target = CapTable;
    #[inline(always)]
    fn deref(&self) -> &CapTable {
        self.t
    }
}

impl TableCell {
    #[inline(always)]
    fn lock(&'static self) -> Locked {
        Locked { _g: self.lock.lock(), t: &self.table }
    }
}

/// Static per-slot capability tables.
const FRESH_TABLE: TableCell = TableCell { lock: SpinLock::new(()), table: CapTable::empty() };
static CAP_TABLES: [TableCell; MAX_TASKS] = [FRESH_TABLE; MAX_TASKS];

/// TID currently owning each slot's table. `NO_OWNER` = never used.
///
/// TID 0 is the "no current task" sentinel returned by
/// `current_task_tid()`, and `NEXT_TID` starts at 1 and skips 0 on wrap, so
/// 0 can never be a live task's TID and is safe as the vacant marker.
const NO_OWNER: u32 = 0;
const FRESH_OWNER: AtomicU32 = AtomicU32::new(NO_OWNER);
static OWNER: [AtomicU32; MAX_TASKS] = [FRESH_OWNER; MAX_TASKS];

/// Wave 15 (plan 4a): per slot, the process id whose table [`hand_over`]
/// moved out of it (0 for none). That process id still resolves to this slot
/// until the scheduler swaps the two slots' TIDs, a moment later: a caller
/// that resolves it here meanwhile must resolve again ([`claim_stale`], [`slot_owner`]), and
/// a caller that resolved it before the move must not write into the table
/// it locks afterwards ([`still_owned`]). Stale once the swap is done (the
/// process id never names this slot again; TIDs are never reused), and
/// cleared when the slot is claimed by its next occupant.
static HANDING: [AtomicU32; MAX_TASKS] = [FRESH_OWNER; MAX_TASKS];

/// What happened to a capability, as the [`CapEventHook`] is told (wave 11,
/// LEASE3). `slot` is a table's task-pool slot index, the identity a holder
/// has here; `resource` is the slot's packed resource as stored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapEvent {
    /// The capability left `slot`'s table without moving anywhere: a
    /// [`revoke`] or a [`revoke_moved`].
    Revoked { slot: usize, kind: crate::cap::CapKind, perms: crate::cap::CapPerms, resource: u32 },
    /// The capability moved from `from`'s table into `to`'s ([`move_cap`]).
    /// `perms` are the ones it had in `from`'s table.
    Moved { from: usize, to: usize, kind: crate::cap::CapKind, perms: crate::cap::CapPerms, resource: u32 },
    /// Every capability in `slot`'s table went: the exit [`reset`], or the
    /// lazy wipe of a reused slot.
    Wiped { slot: usize },
}

/// Told about every [`CapEvent`], with the affected table lock(s) still held,
/// so no later operation on the same capability can run between the change
/// and the hook. It may take a pool lock (table → pool is the established
/// nesting, `port_destroy_cap`'s), must not take a cap-table lock, and must
/// not block. The kernel registers `port::port_cap_event`: a port binding
/// made through a capability dies when that capability is revoked and
/// follows it when it moves.
pub type CapEventHook = fn(CapEvent);

static CAP_EVENT_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Register the [`CapEventHook`]. Boot, once (host suites per test).
pub fn set_cap_event_hook(f: CapEventHook) {
    CAP_EVENT_HOOK.store(f as usize, Ordering::Release);
}

#[inline]
fn cap_event(e: CapEvent) {
    let raw = CAP_EVENT_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only `set_cap_event_hook` stores here, and it stores a
        // `CapEventHook`.
        let f: CapEventHook = unsafe { core::mem::transmute::<usize, CapEventHook>(raw) };
        f(e);
    }
}

/// The task-pool slot `tid`'s table lives in: the binder identity a
/// [`CapEvent`] names. `None` for a TID with no live task.
pub fn table_slot(tid: u32) -> Option<usize> {
    slot_for(tid)
}

/// Resolve `tid` to its task-pool slot index, wiping the slot's table first
/// if it still belongs to a previous occupant.
///
/// Returns `None` for a TID with no live task — including TID 0 (idle /
/// "no current task"). That is fail-closed and correct: nothing in
/// `kernel/src` grants typed caps before the first task exists.
///
/// **On the unsynchronised scan.** `idx_for_tid` reads `TASK_VALID`/`TASKS`
/// without `PoolGuard`, by the same convention the APS dispatch path and
/// the TID-directed wakes already use — this change puts that read on every
/// typed-cap syscall, so the reasoning deserves to be written down.
/// `alloc_slot` sets `TASK_VALID[i] = true` *before* `task.tid` is assigned,
/// so a concurrent scan can see a claimed slot still carrying its previous
/// occupant's TID. That is harmless here only because TIDs are **monotone**:
/// a slot is freed by `do_schedule` after the exiting task is left for good,
/// so a stale slot value is always a dead TID, and `slot_for` is only ever
/// called with a live one (`current_task_tid()`, or the exiting TID at hook
/// time while its slot is still valid). Correctness rests on that
/// monotonicity, not on the read being atomic — so the 2^32 TID wrap that
/// `scheduler.rs` already documents as accepted is the one case where a scan
/// could match the wrong slot.
///
/// Was split into a side-effect-free lookup half (`resolve_only`) plus this
/// claiming half so that the former `delegate` path could cross-check a
/// caller-chosen target TID before either of its two resolutions was allowed
/// to wipe a table. `delegate` and `SYS_CAP_GRANT` were removed 2026-09-03
/// (boot-only caps, RFC-0003); every remaining caller here always names a
/// live TID it already trusts (`current_task_tid()`, or the exiting TID at
/// hook time), so the split's reason is gone and the two halves are merged
/// back.
fn slot_for(tid: u32) -> Option<usize> {
    if tid == NO_OWNER {
        return None;
    }
    let idx = azos_sched::idx_for_tid(tid)?;
    if idx >= MAX_TASKS {
        return None; // defensive; idx_for_tid already bounds this
    }
    // Wave 13 (THREADS): the members of a thread group share their leader's
    // table. One load while no process has threads; the rest out of line.
    if azos_sched::group::any_groups() {
        return slot_for_member(idx, tid);
    }
    // Lazy reset on slot reuse. `swap` makes the claim atomic against
    // another hart resolving the same slot concurrently: exactly one caller
    // observes the stale owner and performs the wipe.
    let prev = OWNER[idx].swap(tid, Ordering::AcqRel);
    if prev != tid {
        return claim_stale(idx, prev, tid, tid);
    }
    Some(idx)
}

/// [`slot_for`] while thread groups exist: a member resolves to its leader's
/// slot. Out of line so the common path keeps its registers.
#[inline(never)]
fn slot_for_member(idx: usize, tid: u32) -> Option<usize> {
    let (idx, owner) = member_owner(idx, tid)?;
    let prev = OWNER[idx].swap(owner, Ordering::AcqRel);
    if prev != owner {
        return claim_stale(idx, prev, owner, tid);
    }
    Some(idx)
}

/// The slot whose table a task in slot `idx` (TID `tid`) uses, and the TID
/// that owns it: its thread group's leader's, or its own.
#[inline]
fn member_owner(idx: usize, tid: u32) -> Option<(usize, u32)> {
    let lead = azos_sched::group::table_lead_of_idx(idx);
    let (idx, owner) = if lead != 0 && lead != tid {
        (azos_sched::idx_for_tid(lead)?, lead)
    } else {
        (idx, tid)
    };
    (idx < MAX_TASKS).then_some((idx, owner))
}

/// A claim for `owner` (the table owner `tid` resolves to) found slot `idx`
/// held by `prev`: wipe the previous occupant's table, or (wave 15) resolve `tid` again
/// when its table was just handed away from `idx` ([`hand_over`]). Out of
/// line: `slot_for` runs on every typed-capability syscall, and inlining
/// this grew it on that path (measured, wave 11 LEASE3: +5 instructions per
/// typed call on riscv64). Not `#[cold]`, which reshapes the hot caller.
#[inline(never)]
fn claim_stale(idx: usize, prev: u32, owner: u32, tid: u32) -> Option<usize> {
    if wipe_claimed(idx, prev, owner) {
        Some(idx)
    } else {
        slot_owner(tid).map(|(idx, _)| idx)
    }
}

/// [`slot_for`], with the TID that owns the table it resolved to (`tid`, or
/// its thread group's leader). For the calls that write into another task's
/// table and re-check it under the lock ([`still_owned`]). Resolves again,
/// spinning, while the table it finds has just been handed away
/// ([`hand_over`]): the scheduler swaps the TIDs with interrupts off on that
/// hart, so the wait is the length of that swap.
fn slot_owner(tid: u32) -> Option<(usize, u32)> {
    if tid == NO_OWNER {
        return None;
    }
    loop {
        let idx = azos_sched::idx_for_tid(tid)?;
        if idx >= MAX_TASKS {
            return None;
        }
        let (idx, owner) = if azos_sched::group::any_groups() {
            member_owner(idx, tid)?
        } else {
            (idx, tid)
        };
        let prev = OWNER[idx].swap(owner, Ordering::AcqRel);
        if prev == owner || wipe_claimed(idx, prev, owner) {
            return Some((idx, owner));
        }
        core::hint::spin_loop();
    }
}

/// After locking `idx`'s table, resolved for `owner`: is it still `owner`'s?
/// `false` when [`hand_over`] moved it away in between, or moved it before
/// and the swap that re-points `owner` has not happened yet: the caller must
/// not write into the (now empty) table, and resolves again. For the calls that
/// write into another task's table ([`grant`], [`move_cap`], [`revoke`]);
/// a task's calls on its own table cannot race its own hand-over (every
/// other thread of the process has gone, and the exec'ing one is waiting).
#[inline]
fn still_owned(idx: usize, owner: u32) -> bool {
    OWNER[idx].load(Ordering::Acquire) == owner && HANDING[idx].load(Ordering::Acquire) != owner
}

/// Wipe slot `idx`'s table for its new owner `tid` (its previous occupant
/// was `prev`): `false`, wiping nothing, when `tid`'s own table was just
/// handed away from `idx` ([`hand_over`]) and `tid` must resolve again.
#[inline(never)]
fn wipe_claimed(idx: usize, prev: u32, tid: u32) -> bool {
    // Wave 15: `tid`'s table left this slot ([`hand_over`]); its TID is about
    // to name the slot it went to. Nothing to wipe, nothing to claim.
    if HANDING[idx].load(Ordering::Acquire) == tid {
        return false;
    }
    let table = CAP_TABLES[idx].lock();
    HANDING[idx].store(NO_OWNER, Ordering::Release);
    table.clear_all();
    if prev != NO_OWNER {
        cap_event(CapEvent::Wiped { slot: idx });
    }
    drop(table);
    notices();
    true
}

/// Post the endpoint notices the last change left pending
/// (`cap::senders`), with no table lock held. One load when none is.
#[inline(always)]
fn notices() {
    crate::cap::senders::flush();
}

/// Returns `true` iff `tid` currently maps to a live task-pool slot.
///
/// Kept under the historical name so existing callers compile, but the
/// meaning changed with W3-F4: it is no longer "the integer is small
/// enough", it is "this TID names a live task".
#[inline]
pub fn is_valid_tid(tid: u32) -> bool {
    slot_for(tid).is_some()
}

/// Look up a capability for the named task.
///
/// Wraps [`CapTable::get`]; returns `Err(CapError::Stale)` if `tid`
/// does not name a live task. Lock-free with Kconfig RCU_QSBR
/// ([`read_table`]): one slot word, read once.
#[inline]
pub fn get<T: CapTarget>(
    tid: u32,
    cap: Cap<T>,
    need: CapPerms,
) -> Result<u32, CapError> {
    match read_table(tid, |t| t.get(cap, need)) {
        Some(r) => r,
        None => Err(CapError::Stale),
    }
}

/// Run `f` on `tid`'s table **for reading**, without its lock when Kconfig
/// RCU_QSBR is on (wave 15 N4).
///
/// What makes it safe without the lock: each slot is one atomic word
/// (`CapTable`), so `f` sees every slot it reads whole, as of some instant
/// between a writer's stores; the tables are static, never freed; and what
/// a slot names is an id, or an index plus a generation the object's pool
/// re-checks, so an answer read just before a concurrent revoke is the
/// answer the lock would have given a moment earlier.
///
/// **No read section.** Nothing a table holds is reclaimed, so there is
/// nothing for a grace period to protect, and the read costs no preemption
/// guard (measured: about 30 instructions on riscv64, on every typed
/// syscall). A closure that goes on to dereference memory freed through
/// `call_rcu` opens its own `azos_sync::qsbr::read()` (the endpoint objects
/// of N5 are the first such memory).
///
/// For a task's own table (`current_task_tid()`), or any table whose owner
/// is not being handed over: a slot whose recorded owner is not `tid`'s
/// (a reused slot not yet claimed, a hand-over in flight) takes the locked
/// path ([`with_table`]), which claims or resolves again exactly as before.
/// With RCU_QSBR off it is [`with_table`].
#[inline]
pub fn read_table<R>(tid: u32, f: impl FnOnce(&CapTable) -> R) -> Option<R> {
    if azos_limits::RCU_QSBR {
        if let Some(idx) = read_slot(tid) {
            return Some(f(&CAP_TABLES[idx].table));
        }
    }
    read_locked(tid, f)
}

/// [`read_table`] for the task running on this CPU (SYS_CAP_LOOKUP): its
/// slot comes from the scheduler with its TID, so no search by TID.
#[inline]
pub fn read_own_table<R>(f: impl FnOnce(&CapTable) -> R) -> Option<R> {
    let (idx, tid) = azos_sched::current_task_slot()?;
    if azos_limits::RCU_QSBR {
        if let Some(idx) = owned_now(idx, tid) {
            return Some(f(&CAP_TABLES[idx].table));
        }
    }
    read_locked(tid, f)
}

/// [`with_table`] as the read paths' fallback, out of line: the lock-free
/// path keeps a small frame (measured: the inlined fallback's registers
/// were saved on every SYS_CAP_LOOKUP).
#[inline(never)]
fn read_locked<R>(tid: u32, f: impl FnOnce(&CapTable) -> R) -> Option<R> {
    with_table(tid, |t| f(t))
}

/// [`slot_for`] without the claim: the slot `tid` (or its thread group's
/// leader) owns right now, or `None` when only the locked path can say
/// (no live task, a slot not yet claimed by `tid`, a hand-over in flight).
/// Two loads where `slot_for` swaps: a reader writes no shared line.
#[inline(always)]
fn read_slot(tid: u32) -> Option<usize> {
    if tid == NO_OWNER {
        return None;
    }
    // The caller's own TID (the common case: `current_task_tid()`) names
    // the slot the scheduler already knows.
    let idx = match azos_sched::current_task_slot() {
        Some((i, t)) if t == tid => i,
        _ => azos_sched::idx_for_tid(tid)?,
    };
    owned_now(idx, tid)
}

/// The slot whose table task `tid` (in pool slot `idx`) uses, if it is
/// claimed for it and not being handed over: its own, or (thread groups)
/// its leader's.
#[inline(always)]
fn owned_now(idx: usize, tid: u32) -> Option<usize> {
    if tid == NO_OWNER {
        return None;
    }
    if azos_sched::group::any_groups() {
        return owned_now_member(idx, tid);
    }
    owned_by(idx, tid)
}

/// [`owned_now`] while thread groups exist (a member reads its leader's
/// table). Out of line, as [`slot_for_member`] is.
#[inline(never)]
fn owned_now_member(idx: usize, tid: u32) -> Option<usize> {
    let (idx, owner) = member_owner(idx, tid)?;
    owned_by(idx, owner)
}

#[inline(always)]
fn owned_by(idx: usize, owner: u32) -> Option<usize> {
    if idx < MAX_TASKS
        && OWNER[idx].load(Ordering::Acquire) == owner
        && HANDING[idx].load(Ordering::Relaxed) != owner
    {
        Some(idx)
    } else {
        None
    }
}

/// Mint a new typed capability into `tid`'s table.
///
/// Returns `None` if the slot table is full or `tid` names no live task.
pub fn grant<T: CapTarget>(
    tid: u32,
    perms: CapPerms,
    resource: u32,
) -> Option<Cap<T>> {
    loop {
        let (idx, owner) = slot_owner(tid)?;
        let table = CAP_TABLES[idx].lock();
        if still_owned(idx, owner) {
            let cap = table.grant(perms, resource);
            drop(table);
            notices();
            return cap;
        }
    }
}

/// Revoke a single cap.
pub fn revoke<T: CapTarget>(tid: u32, cap: Cap<T>) {
    let (idx, table) = loop {
        let Some((idx, owner)) = slot_owner(tid) else { return };
        let table = CAP_TABLES[idx].lock();
        if still_owned(idx, owner) {
            break (idx, table);
        }
    };
    let held = table.peek_raw(cap.raw());
    table.revoke(cap);
    if let Some((kind, perms, resource)) = held {
        cap_event(CapEvent::Revoked { slot: idx, kind, perms, resource });
    }
    drop(table);
    notices();
}

/// Wipe the whole table for a task — called from task exit via
/// [`crate::task_release_all`].
///
/// **Ordering constraint (W3-F7):** this resolves `tid` through
/// `idx_for_tid`, which only succeeds while the task's pool slot is still
/// `TASK_VALID`. `scheduler::task_exit` fires the exit hook *before* marking
/// the task `Zombie`, and `do_schedule` is what actually frees the slot —
/// so the lookup succeeds and the wipe lands on the right slot. If the hook
/// is ever moved after the slot is freed, this becomes a silent no-op and
/// typed caps stop being revoked on exit. The [`OWNER`] lazy-reset above is
/// the backstop for exactly that failure, but do not rely on it: a slot that
/// is never reused would keep a dead task's caps live indefinitely.
pub fn reset(tid: u32) {
    // Wave 13: a thread group member's table is its leader's, wiped when the
    // leader (the last member) exits, never by a member's exit.
    if azos_sched::group::shares_tables(tid) {
        return;
    }
    let idx = match slot_for(tid) {
        Some(i) => i,
        None => return,
    };
    let table = CAP_TABLES[idx].lock();
    table.clear_all();
    cap_event(CapEvent::Wiped { slot: idx });
    // Release the slot claim so the next occupant re-registers cleanly.
    OWNER[idx].store(NO_OWNER, Ordering::Release);
    drop(table);
    // The task's send capabilities went with the table: an endpoint left
    // with none tells its server (wave 15 N5b).
    notices();
}

/// Wave 15 (plan 4a): an exec'ing thread takes its process's identity from
/// the leader (`azos_sched::scheduler::exec_take_over`): the table in slot
/// `from` (the leader's) becomes slot `to`'s, owned by `tid` (the process
/// id, which the scheduler moves to `to` right after, interrupts off on its
/// hart throughout), and `from` is left empty and unowned. Both locks in
/// index order.
///
/// No capability granted into the process meanwhile is lost: a writer that
/// locked `from` before this ran wrote into the table that moved; one that
/// resolved `from` before and locks it after finds it no longer `tid`'s
/// ([`still_owned`]) and resolves again; one that resolves `tid` to `from`
/// before the swap is turned back by [`claim_stale`] and [`slot_owner`] ([`HANDING`]) until the
/// swap makes `tid` name `to`, which already holds the table.
pub fn hand_over(from: usize, to: usize, tid: u32) {
    if from >= MAX_TASKS || to >= MAX_TASKS || from == to {
        return;
    }
    let (lo, hi) = if from < to { (from, to) } else { (to, from) };
    let a = CAP_TABLES[lo].lock();
    let b = CAP_TABLES[hi].lock();
    let (src, dst): (&CapTable, &CapTable) = if from < to { (&a, &b) } else { (&b, &a) };
    // Moved, then the source wiped, as `reset` wipes a table.
    dst.take_from(src);
    OWNER[to].store(tid, Ordering::Release);
    HANDING[to].store(NO_OWNER, Ordering::Release);
    // Before the TIDs are swapped: until then `tid` still resolves to
    // `from`, and every caller that does is sent to resolve again
    // (`claim_stale`, `slot_owner`, `still_owned`) instead of writing into the empty table.
    HANDING[from].store(tid, Ordering::Release);
    OWNER[from].store(NO_OWNER, Ordering::Release);
}

/// Borrow the cap-table for the given task and run a closure on it.
///
/// Used by syscall handlers that need direct access (e.g. to compute
/// multiple cap_table.get() calls atomically without re-locking).
///
/// A closure that writes the table (the fork copy, an exec's revoke) may
/// leave an endpoint notice pending; it is posted after the lock is released.
pub fn with_table<R>(tid: u32, f: impl FnOnce(&CapTable) -> R) -> Option<R> {
    let idx = slot_for(tid)?;
    let table = CAP_TABLES[idx].lock();
    let r = f(&table);
    drop(table);
    notices();
    Some(r)
}

/// Move one capability from `from_tid`'s table into `to_tid`'s.
///
/// RFC-0040 gap 2 stage 4, under owner decision 38 (2026-09-15): this is a
/// **move, as `zx_handle_replace` is** — the sender's entry is removed in the
/// same step that installs the receiver's. Nothing here duplicates a
/// capability.
///
/// # `DUP` gates transfer (owner decision 2026-09-26, O3.4)
///
/// A capability whose slot permissions do not include `CapPerms::DUP` cannot
/// be moved to a DIFFERENT task at all — refused with `MissingPerms` before
/// either table is touched. This is what makes a fork-minted `Cap<Endpoint>`
/// (`endpoint_inherit_at_fork`, `WRITE` only, deliberately never `DUP`)
/// non-transferable: "the child may reach its parent" stays exactly that,
/// never "and so may anyone the child can reach", so `CAPS.TOML` remains the
/// whole authority graph. A task moving a capability to itself (`from_tid ==
/// to_tid`, resolving to the same table slot — the "serves its own endpoint"
/// case) is not a transfer to anyone new and is exempt.
///
/// `rights` is what the receiver gets: `None` keeps the sender's, and
/// `Some(p)` lowers to exactly `p`. They may be **kept or lowered, never
/// raised** — a `Some(p)` carrying a bit the sender does not hold is refused
/// outright rather than silently masked, because a caller asking for authority
/// it cannot give is a bug in that caller and masking it would hide the bug
/// behind a working call.
///
/// `None` is a distinct intent from `Some(the sender's own perms)` only to the
/// caller: the syscall path has not read the sender's slot and cannot name
/// them, and making it peek first would cost a second table round trip on the
/// path this project measures.
///
/// Returns the handle the capability took **in the receiver's table** — a
/// fresh generation, so the sender's old handle is detectably stale from the
/// instant this returns.
///
/// # The lock order, which is NEW in this file
///
/// Every other accessor here takes exactly one table lock; the file's own
/// rule is "one table lock at a time, never nested". This is the first code
/// that holds two, so it carries the whole burden of keeping the lock graph
/// acyclic:
///
/// 1. **Ordered acquire.** The two tables are locked by SLOT INDEX, lowest
///    first, never in caller order. Two harts moving capabilities in opposite
///    directions therefore cannot cycle.
/// 2. **No pool lock while both are held.** The established nesting elsewhere
///    is table → pool (`with_table(tid, |t| port_destroy_cap(t, cap))`).
///    table → table → pool stays acyclic with it; taking a pool lock in here
///    would break that, and nothing in this function does.
/// 3. **The same-slot case is branched before the acquire.** A task moving a
///    capability to an endpoint it serves itself resolves both TIDs to one
///    slot, and "lock both" would then take one non-reentrant spinlock twice.
///    That is not a failed syscall — it is a hung hart, and on this board a
///    hung hart is a robot that stopped answering.
///
/// # Why the receiver is checked first
///
/// `has_free_slot` is asked on the receiver **before** the sender's entry is
/// touched. Decision 38 leaves no half-moved state to roll back from, so the
/// only way to keep that promise is to refuse before removing anything.
pub fn move_cap(
    from_tid: u32,
    to_tid: u32,
    handle: CapHandle,
    rights: Option<CapPerms>,
) -> Result<CapHandle, CapError> {
    loop {
        if let Some(r) = move_cap_once(from_tid, to_tid, handle, rights) {
            // A move that lowered `RW` to `WRITE`, or took `WRITE` away, changed
            // an endpoint's count of send capabilities.
            notices();
            return r;
        }
    }
}

/// One attempt of [`move_cap`]: `None` when a table it resolved was handed
/// to another slot before it was locked (wave 15): resolve again.
fn move_cap_once(
    from_tid: u32,
    to_tid: u32,
    handle: CapHandle,
    rights: Option<CapPerms>,
) -> Option<Result<CapHandle, CapError>> {
    let Some((from_idx, from_owner)) = slot_owner(from_tid) else { return Some(Err(CapError::Stale)) };
    let Some((to_idx, to_owner)) = slot_owner(to_tid) else { return Some(Err(CapError::Stale)) };

    // (3) Same table: one lock, or this deadlocks on itself. Taking the
    // capability out and putting it straight back would also churn a
    // generation for nothing, so the whole move is a no-op that still has to
    // validate the handle and the rights — otherwise a self-move would be the
    // one path that accepts a stale handle or a rights escalation.
    if from_idx == to_idx {
        let table = CAP_TABLES[from_idx].lock();
        if !still_owned(from_idx, from_owner) {
            return None;
        }
        let Some((_, perms, _)) = table.peek_raw(handle) else { return Some(Err(CapError::Stale)) };
        if let Some(want) = rights {
            if !perms.contains(want) {
                return Some(Err(CapError::MissingPerms));
            }
        }
        return Some(Ok(handle));
    }

    // (1) Ordered acquire: lowest slot index first, whichever way the
    // capability is travelling.
    let (lo, hi) = if from_idx < to_idx { (from_idx, to_idx) } else { (to_idx, from_idx) };
    let lo_tab = CAP_TABLES[lo].lock();
    let hi_tab = CAP_TABLES[hi].lock();
    if !still_owned(from_idx, from_owner) || !still_owned(to_idx, to_owner) {
        return None;
    }
    let (sender, receiver) = if from_idx == lo {
        (&*lo_tab, &*hi_tab)
    } else {
        (&*hi_tab, &*lo_tab)
    };
    Some(move_locked(sender, receiver, from_idx, to_idx, handle, rights))
}

/// The move itself, both tables locked and still their owners'.
fn move_locked(
    sender: &CapTable,
    receiver: &CapTable,
    from_idx: usize,
    to_idx: usize,
    handle: CapHandle,
    rights: Option<CapPerms>,
) -> Result<CapHandle, CapError> {
    let (kind, perms, resource) = sender.peek_raw(handle).ok_or(CapError::Stale)?;
    // The badge travels with the capability; the parent link is table-local.
    let ext = crate::cap::CapExt { parent: 0, ..sender.ext_of(handle).ok_or(CapError::Stale)? };
    // `DUP` gates transfer to a different task (O3.4): checked before
    // anything is touched, same as the free-slot check below.
    if !perms.contains(crate::cap::CapPerms::DUP) {
        return Err(CapError::MissingPerms);
    }
    // Kept or lowered, never raised.
    let granted = match rights {
        None => perms,
        Some(want) if perms.contains(want) => want,
        Some(_) => return Err(CapError::MissingPerms),
    };
    // Refuse before the sender loses anything.
    if !receiver.has_free_slot() {
        return Err(CapError::NoSpace);
    }

    // The single step. `revoke_raw` answering false would mean the slot
    // changed under a lock we hold, which cannot happen — asserting it here
    // is how that assumption stops being silent if the locking ever changes.
    if !sender.revoke_raw(handle) {
        return Err(CapError::Stale);
    }
    let moved = receiver
        .grant_raw_ext(kind, granted, resource, ext)
        .ok_or(CapError::NoSpace)?;
    // Both locks still held: a revoke of the moved capability in the
    // receiver's table cannot run before its bindings follow it there.
    cap_event(CapEvent::Moved { from: from_idx, to: to_idx, kind, perms, resource });
    Ok(moved)
}

/// Revoke a capability by kind-erased handle.
///
/// RFC-0040 gap 2 stage 4. The mover has no `T` to be generic over, for the
/// same reason [`move_cap`] does not: the capability carries whatever kind the
/// sender held.
///
/// Returns whether a slot was actually cleared. Used when a moved capability
/// must be destroyed rather than returned — the message it travelled with will
/// never be delivered and its sender is gone, so there is nobody to move it
/// back to. Destroying is the fail-closed half of that pair.
pub fn revoke_moved(tid: u32, handle: CapHandle) -> bool {
    let idx = match slot_for(tid) {
        Some(i) => i,
        None => return false,
    };
    let table = CAP_TABLES[idx].lock();
    let held = table.peek_raw(handle);
    let cleared = table.revoke_raw(handle);
    if let (true, Some((kind, perms, resource))) = (cleared, held) {
        cap_event(CapEvent::Revoked { slot: idx, kind, perms, resource });
    }
    drop(table);
    notices();
    cleared
}

/// Revoke every capability of `kind` whose packed resource names index `idx`,
/// walking every per-task table by index. Returns how many were revoked.
///
/// **WHY a walk by index (RFC-0040 gap 1, revised).** A per-slot generation
/// wrap (`objref::sweep_index`) must reach a stale capability at this index
/// wherever it sits, whichever path minted it. Every other accessor here
/// resolves a live TID through [`slot_for`], and resolving any TID but the
/// slot's own occupant wipes that table, so a sweep cannot go through them.
/// This touches no [`OWNER`] claim: a table of a slot no live task holds may
/// still carry a previous occupant's capabilities until its next claim wipes
/// it, and revoking those is harmless.
///
/// **Lock order.** One table lock at a time, never nested, and no pool lock
/// may be held by the caller (`port_destroy_cap` and its siblings take a
/// table lock and then a pool lock). O(`MAX_TASKS` × `MAX_CAPS_PER_TASK`),
/// once per generation wrap of one pool slot — not once per generation wrap
/// of the whole kind, the cost the deleted pool-wide sweep paid.
pub fn revoke_index_in_every_table(kind: crate::cap::CapKind, idx: u32) -> usize {
    let mut revoked = 0;
    for table in CAP_TABLES.iter() {
        revoked += table.lock().revoke_kind_at_index(kind, idx);
    }
    revoked
}

/// Number of occupied slots for the named task.
pub fn occupied(tid: u32) -> usize {
    match slot_for(tid) {
        Some(idx) => CAP_TABLES[idx].lock().occupied(),
        None => 0,
    }
}

/// Number of occupied slots at a raw pool index, bypassing TID validity.
///
/// **Diagnostics only — no production caller should want this.** Every
/// other accessor in this file resolves a TID through [`slot_for`]
/// deliberately, so a dead task's leftover table is never read as if it
/// were live: `scheduler::do_schedule` frees `TASK_VALID` for a Zombie's
/// slot on the very same context switch that leaves its stack (see that
/// function's own K-C6 comment) — essentially immediately after
/// `task_exit`, not after some later reaping pass — so `occupied(tid)`
/// reads `0` within a few instructions of exit REGARDLESS of whether
/// `reset()` ever actually ran. That makes `occupied(tid)` useless for
/// proving the exit hook revoked anything: both "revoked" and "hook never
/// registered" converge on the same `0`. A caller that captured the pool
/// index while the task was still alive (`azos_sched::idx_for_tid`)
/// can use this instead to read the table's true content at that slot,
/// independent of whether the TID that used to own it still resolves.
pub fn occupied_at_slot(idx: usize) -> usize {
    CAP_TABLES[idx].lock().occupied()
}

// ── Wave 15 N11: the capabilities of one message, all or nothing ────────────

/// Kconfig `IPC_MSG_MAX_CAPS`: capabilities one message may carry.
pub const MSG_MAX_CAPS: usize = azos_limits::IPC_MSG_MAX_CAPS as usize;
const _: () = assert!(
    MSG_MAX_CAPS <= azos_abi::ipc_msg::MSG_CAPS_MAX
        && azos_limits::IPC_MSG_INLINE_WORDS as usize <= azos_abi::ipc_msg::MSG_WORDS_MAX,
    "Kconfig IPC_MSG_MAX_CAPS / IPC_MSG_INLINE_WORDS past the descriptor's ABI ceilings"
);

/// One capability of a message descriptor, as the kernel takes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapXfer {
    /// The sender's handle.
    pub handle: CapHandle,
    /// `false`: MOVE (the sender's handle goes stale). `true`: DUP, a copy
    /// the sender keeps holding too.
    pub dup: bool,
    /// What the receiver gets: `None` the sender's rights, `Some(r)` a
    /// subset of them (never more).
    pub rights: Option<CapPerms>,
}

/// Transfer every capability `xs` names from `from_tid`'s table to
/// `to_tid`'s, or none of them (wave 15 N11, the message descriptor's rule).
/// The receiver's handles go to `out[..xs.len()]`, in order.
///
/// Everything is checked, under both tables' locks, before the sender loses
/// anything: each handle live, each carrying `DUP` (any transfer to another
/// task needs it), the rights asked a subset of those held, no slot named
/// twice, and as many free slots in the receiver as entries. Then every
/// entry lands. The badge travels with each capability (its extension word);
/// the parent link does not (it is table-local).
///
/// On a refusal nothing is installed in the receiver. Without `keep` the
/// MOVE entries that were live are consumed (revoked from the sender), so a
/// failed send cannot leave the sender holding authority it meant to give
/// away; with `keep` the sender's table is untouched. A sender and receiver
/// that are the same task, or more than [`MSG_MAX_CAPS`] entries, are refused
/// (`MissingPerms`) with nothing consumed.
pub fn move_caps(
    from_tid: u32,
    to_tid: u32,
    xs: &[CapXfer],
    keep: bool,
    out: &mut [CapHandle],
) -> Result<usize, CapError> {
    if xs.len() > MSG_MAX_CAPS || out.len() < xs.len() {
        return Err(CapError::MissingPerms);
    }
    if xs.is_empty() {
        return Ok(0);
    }
    loop {
        let Some((from_idx, from_owner)) = slot_owner(from_tid) else { return Err(CapError::Stale) };
        let Some((to_idx, to_owner)) = slot_owner(to_tid) else { return Err(CapError::Stale) };
        if from_idx == to_idx {
            return Err(CapError::MissingPerms);
        }
        let (lo, hi) = if from_idx < to_idx { (from_idx, to_idx) } else { (to_idx, from_idx) };
        let lo_tab = CAP_TABLES[lo].lock();
        let hi_tab = CAP_TABLES[hi].lock();
        if !still_owned(from_idx, from_owner) || !still_owned(to_idx, to_owner) {
            continue;
        }
        let (sender, receiver) = if from_idx == lo { (&*lo_tab, &*hi_tab) } else { (&*hi_tab, &*lo_tab) };
        let r = move_caps_locked(sender, receiver, from_idx, to_idx, xs, out);
        if r.is_err() && !keep {
            for x in xs.iter().filter(|x| !x.dup) {
                if let Some((kind, perms, resource)) = sender.peek_raw(x.handle) {
                    if sender.revoke_raw(x.handle) {
                        cap_event(CapEvent::Revoked { slot: from_idx, kind, perms, resource });
                    }
                }
            }
        }
        return r;
    }
}

/// [`move_caps`] with both tables locked and still their owners'.
fn move_caps_locked(
    sender: &CapTable,
    receiver: &CapTable,
    from_idx: usize,
    to_idx: usize,
    xs: &[CapXfer],
    out: &mut [CapHandle],
) -> Result<usize, CapError> {
    // Phase 1: check every entry; nothing changes.
    for (i, x) in xs.iter().enumerate() {
        let (_, perms, _) = sender.peek_raw(x.handle).ok_or(CapError::Stale)?;
        if !perms.contains(CapPerms::DUP) {
            return Err(CapError::MissingPerms);
        }
        if let Some(want) = x.rights {
            if !perms.contains(want) {
                return Err(CapError::MissingPerms);
            }
        }
        if xs[..i].iter().any(|y| y.handle.slot() == x.handle.slot()) {
            return Err(CapError::MissingPerms);
        }
    }
    if receiver.free_slots() < xs.len() {
        return Err(CapError::NoSpace);
    }
    // Phase 2: every entry lands. Each step below was checked above under
    // the locks still held, so none can fail; a failure would mean the
    // locking changed, and is reported rather than assumed away.
    for (x, o) in xs.iter().zip(out.iter_mut()) {
        let (kind, perms, resource) = sender.peek_raw(x.handle).ok_or(CapError::Stale)?;
        let ext = crate::cap::CapExt { parent: 0, ..sender.ext_of(x.handle).ok_or(CapError::Stale)? };
        if !x.dup && !sender.revoke_raw(x.handle) {
            return Err(CapError::Stale);
        }
        *o = receiver
            .grant_raw_ext(kind, x.rights.unwrap_or(perms), resource, ext)
            .ok_or(CapError::NoSpace)?;
        if !x.dup {
            cap_event(CapEvent::Moved { from: from_idx, to: to_idx, kind, perms, resource });
        }
    }
    Ok(xs.len())
}

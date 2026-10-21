// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-domain capability tables, indexed by **domain slot**.
//!
//! Each domain (`azos_sched::domain`: a process and its threads) owns one
//! [`crate::cap::CapTable`]; the kernel reaches it through this module's
//! accessors, which resolve a TID to its task's domain. The table is
//! **dense**: a fixed `[SpinLock<CapTable>; MAX_TASKS]` lives in BSS and
//! survives the lifetime of the kernel (one domain per task slot at most).
//!
//! Memory cost: `MAX_TASKS × sizeof(CapTable)` ≈ 64 × ~2 KiB = 128 KiB
//! on default builds; configs that lower `MAX_TASKS` scale down linearly.
//!
//! # Why slot-indexed and not TID-indexed
//!
//! TIDs are **monotone**: `scheduler.rs` does
//! `NEXT_TID = NEXT_TID.wrapping_add(1)` and never reissues a low value until
//! it has wrapped 2^32, while `MAX_TASKS` is small. A table indexed by TID
//! would run out of index space at the `MAX_TASKS`-th task creation, which an
//! unprivileged `fork()` loop reaches, and every typed-cap call would answer
//! `EINVAL` from then on (fail-closed, but the capability path would be dead
//! on any long-running system).
//!
//! The domain slot index (`0..MAX_TASKS`) is the quantity that is actually
//! bounded by `MAX_TASKS`, so that is what indexes the array. The cost is a
//! `azos_sched::idx_for_tid` lookup — an O(64) unsynchronised scan of
//! `TASK_VALID`/`TASKS` — and one load of the task's domain key on every
//! capability operation, with no lock and no interrupt toggling.
//!
//! # Threads, exec and slot reuse
//!
//! Every thread of a process is in its domain, so they resolve to one table
//! with no leader indirection; an exec by a thread that takes its process
//! over changes TIDs and task slots, not the domain, so the table does not
//! move. Domain slots, unlike TIDs, *are* recycled. [`OWNER`] records which
//! domain key (slot and generation) a table currently belongs to and every
//! accessor lazily wipes the table when it finds a mismatch — so a new
//! domain can never inherit the previous one's caps, even on a path that
//! skips [`reset`]. This is deliberate belt-and-braces:
//! `crates/core/sched`'s task-creation path cannot be modified from here, so
//! correctness must not depend on it calling us.
//!
//! # Lifecycle
//!
//! - Every domain slot has an always-present, initially-empty `CapTable`
//!   from boot.
//! - `task_exit` calls [`crate::task_release_all`], which calls [`reset`]
//!   — see that function's doc for the ordering constraint that makes it
//!   land on the right table. A thread's exit leaves the table alone; the
//!   last member's wipes it.
//! - Any accessor that observes a table whose recorded owner differs from
//!   the domain being looked up wipes it first (see above).
//!
//! # The warrant tree (owner decision D3/L4)
//!
//! Every slot records the slot it was derived from (`cap::Warrant`): a dup
//! transfer ([`move_caps`]) and a badged mint ([`mint_badged`]) derive, with
//! rights, deadline and quota only narrowing; a move keeps the warrant it
//! carries. **Delete is not revoke (owner decision 20-10, seL4's rule).** A
//! capability that a task closes, or that goes with the task's exit, frees its
//! own slot and nothing else: what was derived from it, in any domain, stays
//! alive and keeps what it maps, hung under the freed slot's own parent (a
//! root's copies become roots), with the rights, deadline, quota and caveats
//! of its own warrant. Only an explicit revoke ([`revoke`], `SYS_CAP_REVOKE`
//! through [`revoke_derived`]) frees the subtree below a slot, across domains:
//! the slots that were derived from it are found by [`sweep`], and each holder
//! is told (the table's pending notice, delivered as the `Revoked` answer to
//! the next refused use of a dead handle).
//!
//! | how a slot is freed | its copies |
//! |---|---|
//! | `SYS_CAP_CLOSE` (`CapTable::delete`), an exec's `delete_where`, the exit wipe ([`reset`], a table claimed over its previous owner), [`delete_moved`] | stay, under the slot's parent |
//! | a MOVE out of the slot ([`move_cap`], [`move_caps`]) | stay, under the capability's new slot |
//! | [`revoke`], [`revoke_derived`], the generation-wrap sweep ([`revoke_index_in_every_table`]) | go |
//! | the sweep's own free of a slot below a revoked one | go |
//!
//! A slot only knows its parent, so a delete that leaves copies behind records
//! a re-parent row (`cap::forward_push`): the freed slot's reference and the
//! reference its copies now hang under. The row lets the chain walk and the
//! sweep treat the deleted slot as the link it was until the sweep has
//! re-parented every copy and retires it ([`sweep`]). The row table is
//! bounded; a delete that finds it full revokes its copies instead (fails
//! closed). A copy installed while a row stands names the live ancestor, not
//! the deleted link (`warrant_settle`).
//!
//! **Weak warrants (owner decision 16-10).** A warrant with `Warrant::WEAK`
//! and everything derived from it resolves with its rights masked to `READ`
//! and `MAP` (`slot_word::perms`); a derive or move keeps the bit and nothing
//! clears it. A weak slot has neither `DUP` nor `TRANSFER` to give, so it
//! cannot be delegated away. A shadow
//! task's table is marked ([`mark_weak`]) so that every slot granted into it,
//! by any minter, is weak.
//!
//! **Caveats (macaroon-style attenuation).** A warrant also carries up to four
//! conditions on a use (`cap::Caveats`: expiry, quota, op mask, a receipt the
//! device must have left, and the kinds reserved for node identity and
//! declassification). A dup, a move and a badged mint (with caveats of its own:
//! [`mint_badged_caveated`], the derive a verified remote token becomes a
//! local capability through) copy the source's list whole and a transfer
//! ([`CapXfer::caveats`]) may only append to it, so a copy is never less
//! restricted than its source; a transfer whose receiver has no free caveat
//! block is refused before the sender loses anything.
//!
//! **Use is checked, the sweep cleans up.** A capability derived from a
//! revoked one is refused on its next use even before the sweep has freed it:
//! `cap::revocation_in_flight` (two relaxed loads) says whether some revocation
//! is not yet confirmed swept, and only then does a resolve walk the parent
//! chain of the slot it is trusting ([`warrant_step`], at most
//! `WARRANT_DEPTH_MAX` links, each a lock-free read of the ancestor's owner,
//! slot word and parent). While one is in flight the resolve cache
//! (`CapTable::word_grants`) grants nothing, so the full resolve decides. With
//! none in flight a resolve is what it was plus the two loads. The sweep is
//! what frees the slots, tells their holders, and confirms the window shut.
//!
//! The sweep is iterative and bounded. A slot only knows its parent, so the
//! descendants are found by scanning; one pass over the tables, one lock at a
//! time, frees every slot whose parent is dead (the parent's domain no longer
//! owns its table, or the slot no longer holds the referenced generation) and
//! hangs every slot whose parent was deleted under the deleted slot's own
//! parent. Passes repeat until one changes nothing, which confirms the
//! revocations it started from and retires the re-parent rows it covered. A
//! chain is at most `WARRANT_DEPTH_MAX` links, so that is at most
//! `WARRANT_DEPTH_MAX + 1` passes of `MAX_TASKS x MAX_CAPS_PER_TASK` slot
//! loads, and a table with no derived slot costs one load. It is correct
//! against a concurrent derive because a derive holds both tables' locks and
//! checks its source alive. A delete of a slot with copies (a close, an exec's
//! `delete_where`, the exit wipe) owes the sweep through the same flag, without
//! opening the revocation window: nothing is refused for it.
//!
//! A move out of a slot something was derived from takes the copies along (the
//! capability, with its place in the tree, is the receiver's now): they hang
//! under its new slot, and the moved capability keeps its own parent, so
//! revoking an ancestor, or the capability itself where it is now, still
//! reaches them.
//!
//! # Concurrency
//!
//! One spinlock per table. Different domains acquiring different tables
//! never contend. The same task's syscall path is single-threaded
//! per CPU, so contention on a single table is rare.

use core::sync::atomic::{AtomicU32, Ordering};

use azos_sched::task::MAX_TASKS;
use azos_sync::spinlock::SpinLock;

use azos_decision::{warrant_ref, Rule, Verdict};

use crate::cap::{
    derive_warrant, narrow_warrant, Cap, CapError, CapExt, CapHandle, CapPerms, CapTable, CapTarget, DeriveSpec,
    Caveats, Fate, Quota, Warrant, MAX_CAPS_PER_TASK, WARRANT_DEPTH_MAX,
};

/// A domain slot's capability table and the lock its writers take.
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

/// Domain key currently owning each table. `NO_OWNER` = never used or
/// released.
///
/// Key 0 names no domain (`azos_sched::domain::NONE`), so it is safe as the
/// vacant marker.
const NO_OWNER: u32 = 0;
const FRESH_OWNER: AtomicU32 = AtomicU32::new(NO_OWNER);
static OWNER: [AtomicU32; MAX_TASKS] = [FRESH_OWNER; MAX_TASKS];

// ── Kernel memory charged to the Domain (KMEM-CHARGE) ──────────────────────
//
// The kernel keeps memory for a Domain: this table, the endpoints it creates,
// the MemObjs it holds. Each is charged to the Domain's ledger
// (`azos_sched::domain::kmem_charge`), against the `kmem_kib` of its row. The
// ledger lives in `azos_sched`, which the host suites that pull this file
// replace with stand-ins; so the store, the endpoints and the MemObjs reach it
// through two hooks registered at boot (the pattern of [`MoveHook`]), and a
// harness without them charges nothing. A class is a byte, equal to
// `azos_mm::budget::KmemClass` (the kernel asserts it where it registers).

/// [`kmem_charge`] class: the Domain's capability table.
pub const KMEM_CAP_TABLE: u8 = 0;
/// [`kmem_charge`] class: one endpoint's slot and call queue.
pub const KMEM_EP_QUEUE: u8 = 1;
/// [`kmem_charge`] class: one MemObj region's metadata.
pub const KMEM_MEMOBJ_META: u8 = 2;

/// Charge `bytes` of `class` to the Domain `key` names, all or nothing:
/// `false` when its kernel-memory limit would be passed. A key that names no
/// Domain is not billed.
pub type KmemChargeHook = fn(key: u32, class: u8, bytes: u64) -> bool;
/// Give `bytes` of `class` back to the Domain `key` names.
pub type KmemDischargeHook = fn(key: u32, class: u8, bytes: u64);

azos_common::ro_hook! {
    static KMEM_CHARGE_HOOK: KmemChargeHook;
}
azos_common::ro_hook! {
    static KMEM_DISCHARGE_HOOK: KmemDischargeHook;
}

/// Register the kernel-memory hooks. Boot, once.
pub fn set_kmem_hooks(charge: KmemChargeHook, discharge: KmemDischargeHook) {
    KMEM_DISCHARGE_HOOK.set(discharge);
    KMEM_CHARGE_HOOK.set(charge);
}

/// Charge `bytes` of `class` to the Domain `key` names. The ledger itself is
/// lock-free, but a refusal writes a decision record that may flush to the
/// medium: call this BEFORE taking a spinlock, never under one
/// (`azos_sched::domain` documents the order). `true` with no hook registered.
#[inline]
pub fn kmem_charge(key: u32, class: u8, bytes: u64) -> bool {
    match KMEM_CHARGE_HOOK.get() {
        Some(f) => f(key, class, bytes),
        None => true,
    }
}

/// Give `bytes` of `class` back to the Domain `key` names. Atomic
/// subtractions only: safe under any lock.
#[inline]
pub fn kmem_discharge(key: u32, class: u8, bytes: u64) {
    if let Some(f) = KMEM_DISCHARGE_HOOK.get() {
        f(key, class, bytes);
    }
}

/// The key of the Domain task `tid` runs in; `0` (no Domain, nothing billed)
/// for a TID with no live task, the kernel's own owners among them.
pub fn domain_key_of(tid: u32) -> u32 {
    azos_sched::idx_for_tid(tid).map_or(azos_sched::domain::NONE, azos_sched::task_domain)
}

/// A kernel-memory ledger for the host suites that pull this file: per
/// `(key, class)` bytes, a limit per key, the hooks installed once. A suite
/// that never calls [`install`](kmem_fake::install) charges nothing.
#[cfg(test)]
pub mod kmem_fake {
    use std::sync::Mutex;

    static LEDGER: Mutex<Vec<(u32, u8, u64)>> = Mutex::new(Vec::new());
    static LIMITS: Mutex<Vec<(u32, u64)>> = Mutex::new(Vec::new());

    fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn charge(key: u32, class: u8, bytes: u64) -> bool {
        let mut l = lock(&LEDGER);
        let used: u64 = l.iter().filter(|e| e.0 == key).map(|e| e.2).sum();
        let limit = lock(&LIMITS).iter().find(|e| e.0 == key).map_or(0, |e| e.1);
        if limit != 0 && used + bytes > limit {
            return false;
        }
        match l.iter_mut().find(|e| e.0 == key && e.1 == class) {
            Some(e) => e.2 += bytes,
            None => l.push((key, class, bytes)),
        }
        true
    }

    fn discharge(key: u32, class: u8, bytes: u64) {
        if let Some(e) = lock(&LEDGER).iter_mut().find(|e| e.0 == key && e.1 == class) {
            e.2 = e.2.saturating_sub(bytes);
        }
    }

    /// Register the fake hooks (idempotent).
    pub fn install() {
        super::set_kmem_hooks(charge, discharge);
    }

    /// Bytes of `class` charged to `key`.
    pub fn used(key: u32, class: u8) -> u64 {
        lock(&LEDGER).iter().find(|e| e.0 == key && e.1 == class).map_or(0, |e| e.2)
    }

    /// Bytes charged to `key`, all classes.
    pub fn total(key: u32) -> u64 {
        lock(&LEDGER).iter().filter(|e| e.0 == key).map(|e| e.2).sum()
    }

    /// Declare `key`'s limit in bytes (0 = none).
    pub fn set_limit(key: u32, bytes: u64) {
        let mut l = lock(&LIMITS);
        l.retain(|e| e.0 != key);
        l.push((key, bytes));
    }

    /// Forget `key`'s charges and limit (the domain the key named is gone).
    pub fn forget(key: u32) {
        lock(&LEDGER).retain(|e| e.0 != key);
        lock(&LIMITS).retain(|e| e.0 != key);
    }

    /// Bytes a capability table costs its Domain.
    pub const TABLE_BYTES: u64 = super::KMEM_TABLE_BYTES;
}

/// Bytes a Domain is charged for owning a capability table.
const KMEM_TABLE_BYTES: u64 = core::mem::size_of::<TableCell>() as u64;

/// What happened to a capability, as the [`CapEventHook`] is told (wave 11).
/// `slot` is a table's index (its domain's slot), the identity a holder
/// has here; `resource` is the slot's packed resource as stored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapEvent {
    /// The capability left `slot`'s table without moving anywhere: a
    /// [`revoke`] or a [`delete_moved`].
    Revoked { slot: usize, kind: crate::cap::CapType, perms: crate::cap::CapPerms, resource: u32 },
    /// The capability moved from `from`'s table into `to`'s ([`move_cap`]).
    /// `perms` are the ones it has in `to`'s table.
    Moved { from: usize, to: usize, kind: crate::cap::CapType, perms: crate::cap::CapPerms, resource: u32 },
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

/// The object half of a MOVE: called once for every MOVE entry of a
/// transfer that landed (not for a DUP entry, and not for a self-move), after
/// both tables are unlocked, with the kind and resource of the capability that
/// moved and the TIDs of the tables it went between. A MemObj hands its
/// references, charge and ownership to the receiver and drops the sender's
/// mapping (`memobj::memobj_moved`). Registered once at boot; a harness that
/// does not register one moves capabilities only.
pub type MoveHook = fn(kind: crate::cap::CapType, resource: u32, from_tid: u32, to_tid: u32);

azos_common::ro_hook! {
    static MOVE_HOOK: MoveHook;
}

/// Register the [`MoveHook`]. Boot, once.
pub fn set_move_hook(f: MoveHook) {
    MOVE_HOOK.set(f);
}

/// Forget the registered [`MoveHook`]: host-test hygiene, the hook is process-wide.
#[cfg(not(target_os = "none"))]
pub fn __clear_move_hook_for_tests() {
    MOVE_HOOK.clear_for_tests();
}

fn run_move_hook(kind: crate::cap::CapType, resource: u32, from_tid: u32, to_tid: u32) {
    if let Some(f) = MOVE_HOOK.get() {
        f(kind, resource, from_tid, to_tid);
    }
}

/// The object half of a swept warrant: called once for every `Cap<Shm>` slot
/// a [`sweep`] revoked (the descendants of a warrant that was revoked, or of a
/// capability that went), after the table's lock is released, with the
/// packed reference the slot named and the key of the Domain whose table it was
/// in. A MemObj takes the Domain's holders out of the object: their mappings
/// are unmapped on every hart and their references given back
/// (`memobj::memobj_warrant_swept`), so a revoked share leaves nothing the
/// holder can still read. Registered once at boot; a harness that does not
/// register one revokes capabilities only.
pub type SweptHook = fn(resource: u32, owner: u32);

azos_common::ro_hook! {
    static SWEPT_HOOK: SweptHook;
}

/// Register the [`SweptHook`]. Boot, once.
pub fn set_swept_hook(f: SweptHook) {
    SWEPT_HOOK.set(f);
}

/// Forget the registered [`SweptHook`]: host-test hygiene, the hook is process-wide.
#[cfg(not(target_os = "none"))]
pub fn __clear_swept_hook_for_tests() {
    SWEPT_HOOK.clear_for_tests();
}

/// The `Cap<Shm>` slots one pass of the sweep revoked in one table, collected
/// under its lock and handed to the [`SweptHook`] after it. A table has
/// `MAX_CAPS_PER_TASK` slots, so none is dropped.
struct SweptSet {
    n: usize,
    e: [u32; MAX_CAPS_PER_TASK],
}

impl SweptSet {
    const fn new() -> Self {
        SweptSet { n: 0, e: [0; MAX_CAPS_PER_TASK] }
    }
    fn push(&mut self, kind: crate::cap::CapType, resource: u32) {
        if kind == crate::cap::ty::SHM && self.n < self.e.len() {
            self.e[self.n] = resource;
            self.n += 1;
        }
    }
    /// Forget the objects the table still names by a capability of its own: a
    /// Domain can hold two `Cap<Shm>` slots to one object from warrant trees
    /// that have nothing to do with each other, and the sweep took only one of
    /// them. Asked with the table locked, after the sweep cleared its slots: the
    /// answer is the table's own at the moment the slot went, not a look taken
    /// after the unlock.
    ///
    /// Canary `memobj-sweep-no-retain-canary`: the answer is not asked, every
    /// swept object reaches the hook.
    fn retain_unheld(&mut self, t: &CapTable) {
        if cfg!(feature = "memobj-sweep-no-retain-canary") {
            return;
        }
        let mut kept = 0;
        for k in 0..self.n {
            let r = self.e[k];
            if !t.holds_packed_ref(crate::cap::ty::SHM, r, CapPerms::NONE) {
                self.e[kept] = r;
                kept += 1;
            }
        }
        self.n = kept;
    }
    /// Canary `memobj-sweep-no-hook-canary`: the hook is not called, as if boot
    /// had not registered it.
    fn run(&self, owner: u32) {
        if cfg!(feature = "memobj-sweep-no-hook-canary") {
            return;
        }
        if let Some(f) = SWEPT_HOOK.get() {
            for &resource in &self.e[..self.n] {
                f(resource, owner);
            }
        }
    }
}

/// The MOVE entries of a transfer, collected under the locks and handed to
/// the [`MoveHook`] after them.
struct MovedSet {
    n: usize,
    e: [(crate::cap::CapType, u32); MSG_MAX_CAPS],
}

impl MovedSet {
    const fn new() -> Self {
        MovedSet { n: 0, e: [(crate::cap::ty::SHM, 0); MSG_MAX_CAPS] }
    }
    fn push(&mut self, kind: crate::cap::CapType, resource: u32) {
        if self.n < MSG_MAX_CAPS {
            self.e[self.n] = (kind, resource);
            self.n += 1;
        }
    }
    fn run(&self, from_tid: u32, to_tid: u32) {
        for &(kind, resource) in &self.e[..self.n] {
            run_move_hook(kind, resource, from_tid, to_tid);
        }
    }
}

azos_common::ro_hook! {
    static CAP_EVENT_HOOK: CapEventHook;
}

/// Register the [`CapEventHook`]. Boot, once (host suites per test).
pub fn set_cap_event_hook(f: CapEventHook) {
    CAP_EVENT_HOOK.set(f);
}

#[inline]
fn cap_event(e: CapEvent) {
    if let Some(f) = CAP_EVENT_HOOK.get() {
        f(e);
    }
}

/// The index of the table `tid`'s domain owns: the binder identity a
/// [`CapEvent`] names. `None` for a TID with no live task.
pub fn table_slot(tid: u32) -> Option<usize> {
    slot_for(tid)
}

/// Resolve `tid` to the index of its domain's table, wiping the table first
/// if it still belongs to a previous domain.
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
/// (boot-only caps); every remaining caller here always names a
/// live TID it already trusts (`current_task_tid()`, or the exiting TID at
/// hook time), so the split's reason is gone and the two halves are merged
/// back.
fn slot_for(tid: u32) -> Option<usize> {
    slot_owner(tid).map(|(table, _)| table)
}

/// [`slot_for`], with the key of the domain that owns the table it resolved
/// to. For the calls that write into another task's table and re-check it
/// under the lock ([`still_owned`]).
///
/// Lazy reset on reuse: `swap` makes the claim atomic against another hart
/// resolving the same table concurrently, so exactly one caller observes the
/// stale owner and performs the wipe.
#[inline]
fn slot_owner(tid: u32) -> Option<(usize, u32)> {
    if tid == NO_OWNER {
        return None;
    }
    let idx = azos_sched::idx_for_tid(tid)?;
    let key = azos_sched::task_domain(idx);
    let table = azos_sched::domain::index(key);
    if key == azos_sched::domain::NONE || table >= MAX_TASKS {
        return None;
    }
    claim_table(table, key).then_some((table, key))
}

/// Make `key` the owner of table `table`, wiping what the previous owner left.
/// KMEM-CHARGE: the table is kernel memory kept for the Domain, charged ONCE,
/// by the claim that wins, before the table's lock is taken; `false`, nothing
/// claimed and the table untouched, when the Domain's ledger refuses it
/// (the caller then fails like it does for a task with no Domain). A claim
/// that loses the race to another thread of the same Domain gives its charge
/// back and finds the table claimed. The table's charge is not given back
/// at the Domain's end: its ledger dies with it.
#[inline]
fn claim_table(table: usize, key: u32) -> bool {
    let mut prev = OWNER[table].load(Ordering::Acquire);
    while prev != key {
        if !kmem_charge(key, KMEM_CAP_TABLE, KMEM_TABLE_BYTES) {
            return false;
        }
        match OWNER[table].compare_exchange(prev, key, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                wipe_claimed(table, key, prev);
                return true;
            }
            Err(now) => {
                kmem_discharge(key, KMEM_CAP_TABLE, KMEM_TABLE_BYTES);
                prev = now;
            }
        }
    }
    true
}

/// After locking table `table`, resolved for the domain `owner`: is it still
/// `owner`'s? `false` when the domain's last member exited in between
/// ([`reset`]) or another domain took the table: the caller must not write
/// into it, and resolves again. For the calls that write into another task's
/// table ([`grant`], [`move_cap`], [`revoke`]).
#[inline]
fn still_owned(table: usize, owner: u32) -> bool {
    OWNER[table].load(Ordering::Acquire) == owner
}

/// Wipe table `table` for its new owner `key` (its previous one was `prev`).
#[inline(never)]
fn wipe_claimed(table: usize, key: u32, prev: u32) {
    let t = CAP_TABLES[table].lock();
    t.clear_all();
    t.set_owner(key);
    if prev != NO_OWNER {
        cap_event(CapEvent::Wiped { slot: table });
    }
    drop(t);
    notices();
}

/// Post the endpoint notices the last change left pending
/// (`cap::senders`) and run the subtree sweep it owes ([`sweep`]), with no
/// table lock held. One load each when none is.
#[inline(always)]
fn notices() {
    crate::cap::senders::flush();
    if crate::cap::sweep_pending() {
        sweep();
    }
}

/// `warrant_ref` of the capability `h` names in the table of domain `key`.
#[inline(always)]
fn wref(key: u32, h: CapHandle) -> u64 {
    warrant_ref(key, h.slot(), h.generation())
}

/// One link of a warrant chain ([`CapTable::chain_alive`]): the parent
/// reference `r` names, resolved. `Some(next)` when the slot is still the one
/// it named (its domain owns its table, the slot holds the referenced
/// generation), `next` being that slot's own parent (0 at a root); `None` when
/// it is not. A reference with no domain has nothing to outlive. A slot that
/// was DELETED, not revoked, is still a link of the chain for as long as its
/// children are not hung under its own parent yet (a re-parent row): the link
/// is then the slot they will hang under. Lock-free reads, and the row table's
/// leaf lock for a dead reference.
pub(crate) fn warrant_step(r: u64) -> Option<u64> {
    match step_slot(r) {
        Some(next) => Some(next),
        None => step_deleted(r),
    }
}

/// [`warrant_step`] for a reference that names a live slot, else `None`.
fn step_slot(r: u64) -> Option<u64> {
    let key = (r >> 32) as u32;
    if key == NO_OWNER {
        return Some(0);
    }
    let table = azos_sched::domain::index(key);
    if table < MAX_TASKS && OWNER[table].load(Ordering::Acquire) == key {
        CAP_TABLES[table].table.parent_of((r >> 16) as u16, r as u16)
    } else {
        None
    }
}

/// The warrant depth of the live slot the reference `r` names (0 for no
/// domain: a root), `None` when it names none. What a slot re-parented under
/// it is one link below.
pub(crate) fn ref_depth(r: u64) -> Option<u8> {
    let key = (r >> 32) as u32;
    if key == NO_OWNER {
        return Some(0);
    }
    let table = azos_sched::domain::index(key);
    if table < MAX_TASKS && OWNER[table].load(Ordering::Acquire) == key {
        CAP_TABLES[table].table.depth_of((r >> 16) as u16, r as u16)
    } else {
        None
    }
}

/// The links a chain of deleted slots can have: one per derivation level.
const DELETED_HOPS: usize = WARRANT_DEPTH_MAX + 1;

/// [`warrant_step`] for a reference whose slot is gone: follow the re-parent
/// rows to the first slot still alive and answer its parent; `Some(0)` when
/// the rows lead to a root, `None` when a link is revoked (no row names it).
fn step_deleted(r: u64) -> Option<u64> {
    let mut p = r;
    for _ in 0..DELETED_HOPS {
        let to = crate::cap::forward_lookup(p)?;
        if to == 0 {
            return Some(0);
        }
        if let Some(next) = step_slot(to) {
            return Some(next);
        }
        p = to;
    }
    None
}

/// What the sweep does with a slot whose parent reference is `parent`:
/// nothing when it is alive, hang it under the first live ancestor when it was
/// deleted, free it when it was revoked.
fn fate_of(parent: u64) -> Fate {
    if step_slot(parent).is_some() {
        return Fate::Keep;
    }
    let mut p = parent;
    for _ in 0..DELETED_HOPS {
        let Some(to) = crate::cap::forward_lookup(p) else { return Fate::Free };
        if to == 0 || step_slot(to).is_some() {
            return Fate::Reparent(to);
        }
        p = to;
    }
    Fate::Free
}

/// `p` as a new copy of a warrant should name it: the live ancestor a deleted
/// parent's children hang under, else `p` as it is (alive, or revoked: a copy
/// of a revoked link is swept like the original).
pub(crate) fn warrant_settle(p: u64) -> u64 {
    match fate_of(p) {
        Fate::Reparent(to) => to,
        Fate::Keep | Fate::Free => p,
    }
}

/// What the last [`sweep`] did: passes run, slots examined, slots revoked.
/// Diagnostics, and the bound the host suite checks.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SweepStats {
    pub passes: u32,
    pub examined: u32,
    pub revoked: u32,
}

static SWEEP_PASSES: AtomicU32 = AtomicU32::new(0);
static SWEEP_EXAMINED: AtomicU32 = AtomicU32::new(0);
static SWEEP_REVOKED: AtomicU32 = AtomicU32::new(0);

/// The last [`sweep`]'s numbers (a sweep that found nothing owed leaves them).
pub fn last_sweep() -> SweepStats {
    SweepStats {
        passes: SWEEP_PASSES.load(Ordering::Relaxed),
        examined: SWEEP_EXAMINED.load(Ordering::Relaxed),
        revoked: SWEEP_REVOKED.load(Ordering::Relaxed),
    }
}

/// Settle the warrant tree after slots were freed, until nothing changes: a
/// slot whose parent was REVOKED is freed (the subtree below whatever was
/// revoked, see the module doc), one whose parent was DELETED is hung under
/// the first live ancestor of the deleted slot (a re-parent row says which),
/// and the rows are retired after a pass that found none left to apply. No
/// table lock may be held. Each slot revoked is told to the hook
/// ([`CapEvent::Revoked`]), recorded (`Rule::CapRevoke`, the descendant flag
/// set) and left as a notice for its holder.
pub fn sweep() {
    if !crate::cap::sweep_take() {
        return;
    }
    // Every revocation counted here has its clear stored: the passes below
    // find the subtrees of all of them. Every row pushed up to `rows` is in
    // the table.
    let epoch = crate::cap::sweep_epoch();
    let rows = crate::cap::forward_mark();
    let mut st = SweepStats::default();
    for pass in 0..=WARRANT_DEPTH_MAX {
        let mut changed = 0;
        let mut revoked = 0;
        for (idx, cell) in CAP_TABLES.iter().enumerate() {
            if cell.table.derived() == 0 {
                continue;
            }
            let t = cell.lock();
            let key = OWNER[idx].load(Ordering::Acquire);
            let mut swept = SweptSet::new();
            let (examined, n, moved) = t.sweep_dead(fate_of, |h, kind, perms, resource, parent| {
                cap_event(CapEvent::Revoked { slot: idx, kind, perms, resource });
                azos_decision::record(Rule::CapRevoke, Verdict::Deny, key, [wref(key, h), parent, 1]);
                swept.push(kind, resource);
            });
            swept.retain_unheld(&t);
            drop(t);
            if key != NO_OWNER {
                swept.run(key);
            }
            st.examined += examined as u32;
            revoked += n;
            changed += n + moved;
        }
        st.passes += 1;
        st.revoked += revoked as u32;
        if changed == 0 {
            // A pass that changed nothing: no slot with a dead ancestor is
            // left, so the lazy-revocation window those revocations opened is
            // shut, and no slot names a deleted one, so its row can go.
            crate::cap::sweep_confirmed(epoch);
            crate::cap::forward_retire(rows);
            break;
        }
        if pass == WARRANT_DEPTH_MAX {
            // A derive raced the sweep past the depth bound's worth of
            // passes: owe it again rather than loop.
            crate::cap::sweep_owed();
        }
    }
    SWEEP_PASSES.store(st.passes, Ordering::Relaxed);
    SWEEP_EXAMINED.store(st.examined, Ordering::Relaxed);
    SWEEP_REVOKED.store(st.revoked, Ordering::Relaxed);
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
/// For a task's own table (`current_task_tid()`), or any other: a table
/// whose recorded owner is not the task's domain (a reused table not yet
/// claimed) takes the locked path ([`with_table`]), which claims it.
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

/// [`read_table`] for the task running on this CPU (SYS_CAP_INFO): its
/// slot comes from the scheduler with its TID, so no search by TID.
#[inline]
pub fn read_own_table<R>(f: impl FnOnce(&CapTable) -> R) -> Option<R> {
    let (idx, tid) = azos_sched::current_task_slot()?;
    if azos_limits::RCU_QSBR {
        if let Some(idx) = owned_now(idx) {
            return Some(f(&CAP_TABLES[idx].table));
        }
    }
    read_locked(tid, f)
}

/// [`with_table`] as the read paths' fallback, out of line: the lock-free
/// path keeps a small frame (measured: the inlined fallback's registers
/// were saved on every SYS_CAP_INFO).
#[inline(never)]
fn read_locked<R>(tid: u32, f: impl FnOnce(&CapTable) -> R) -> Option<R> {
    with_table(tid, |t| f(t))
}

/// [`slot_for`] without the claim: the table `tid`'s domain owns right now,
/// or `None` when only the locked path can say (no live task, a table not
/// yet claimed by the domain). Two loads where `slot_for` swaps: a reader
/// writes no shared line.
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
    owned_now(idx)
}

/// The table the domain of the task in pool slot `idx` owns, if it is
/// claimed for that domain. Two loads, and no write to a shared line.
#[inline(always)]
fn owned_now(idx: usize) -> Option<usize> {
    let key = azos_sched::task_domain(idx);
    let table = azos_sched::domain::index(key);
    (key != azos_sched::domain::NONE && table < MAX_TASKS && OWNER[table].load(Ordering::Acquire) == key)
        .then_some(table)
}

/// The table slot `tid` reads right now, without the lock and without a
/// claim ([`read_slot`]): `None` when only the locked path can say. For the
/// endpoint resolve cache (`crate::endpoint::resolve_cache`), which keeps
/// it beside the word it compares.
#[inline]
pub fn table_of(tid: u32) -> Option<usize> {
    read_slot(tid)
}

/// The stored word of the slot `raw` names in table slot `table`
/// ([`CapTable::slot_word`]), lock-free as [`read_table`] reads; 0 for a
/// table index out of range.
#[inline(always)]
pub fn slot_word(table: usize, raw: CapHandle) -> u64 {
    match CAP_TABLES.get(table) {
        Some(c) => c.table.slot_word(raw),
        None => 0,
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

/// [`grant`] with a badge in the slot's extension word: the capability a
/// server sees as `badge` on every call made through it. `None` when the
/// badge is 0, Kconfig CAP_SLOT_EXT is off (a badge would be silently lost,
/// and a caller that relies on one must not be told it was granted), the
/// table is full or `tid` names no live task.
pub fn grant_badged<T: CapTarget>(
    tid: u32,
    perms: CapPerms,
    resource: u32,
    badge: u32,
) -> Option<Cap<T>> {
    if !crate::cap::SLOT_EXT || badge == 0 {
        return None;
    }
    loop {
        let (idx, owner) = slot_owner(tid)?;
        let table = CAP_TABLES[idx].lock();
        if still_owned(idx, owner) {
            let cap = table
                .grant_warranted(
                    T::TYPE,
                    perms,
                    resource,
                    crate::cap::CapExt { badge, ..crate::cap::CapExt::NONE },
                    crate::cap::Warrant::ROOT,
                )
                .map(Cap::from_raw);
            drop(table);
            notices();
            return cap;
        }
    }
}

/// [`grant_badged`] (a badge of 0 is no badge) for a capability whose
/// warrant carries an `OP_MASK` caveat of `ops`: the ops of the interface the
/// holder may call (`cap::caveat::OP_MASK`, on an endpoint the kernel hosts).
/// `None` when the table is full or `tid` names no live task, and for a badge
/// the build cannot stamp.
pub fn grant_op_masked<T: CapTarget>(
    tid: u32,
    perms: CapPerms,
    resource: u32,
    badge: u32,
    ops: u64,
) -> Option<Cap<T>> {
    use crate::cap::{caveat, Caveat, Caveats, CapExt, Warrant};
    if badge != 0 && !crate::cap::SLOT_EXT {
        return None;
    }
    let warrant = Warrant {
        caveats: Caveats::NONE.with(Caveat::new(caveat::OP_MASK, ops)).ok()?,
        ..Warrant::ROOT
    };
    loop {
        let (idx, owner) = slot_owner(tid)?;
        let table = CAP_TABLES[idx].lock();
        if still_owned(idx, owner) {
            let cap = table
                .grant_warranted(T::TYPE, perms, resource, CapExt { badge, ..CapExt::NONE }, warrant)
                .map(Cap::from_raw);
            drop(table);
            notices();
            return cap;
        }
    }
}

/// Make `tid`'s table a shadow task's (a topology row with `shadow = true`):
/// every capability in it, held now or granted later by any minter, is weak
/// (`Warrant::WEAK`) and resolves read-only; each use the mask refuses is
/// recorded as `Rule::ShadowRefusal`. Called before the row is seeded; the
/// mark lasts until the table is wiped for its next owner (the exit
/// [`reset`], or the lazy wipe of a reused slot). `false` for a TID with no
/// live task.
pub fn mark_weak(tid: u32) -> bool {
    loop {
        let Some((idx, owner)) = slot_owner(tid) else { return false };
        let table = CAP_TABLES[idx].lock();
        if still_owned(idx, owner) {
            return table.mark_weak(tid);
        }
    }
}

/// Revoke a warrant: the capability `cap` names in `tid`'s table, and with it
/// every capability derived from it, in any domain (the module doc's
/// sweep). A handle that names nothing live is a no-op.
pub fn revoke<T: CapTarget>(tid: u32, cap: Cap<T>) {
    let (idx, owner, table) = loop {
        let Some((idx, owner)) = slot_owner(tid) else { return };
        let table = CAP_TABLES[idx].lock();
        if still_owned(idx, owner) {
            break (idx, owner, table);
        }
    };
    let held = table.peek_stored(cap.raw());
    let parent = table.warrant_of(cap.raw()).map_or(0, |w| w.parent);
    table.revoke(cap);
    if let Some((kind, perms, resource)) = held {
        cap_event(CapEvent::Revoked { slot: idx, kind, perms, resource });
        azos_decision::record(Rule::CapRevoke, Verdict::Deny, owner, [wref(owner, cap.raw()), parent, 0]);
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
    // A domain's table is wiped when its last member exits, never by a
    // thread's exit.
    if azos_sched::domain_shared(tid) {
        return;
    }
    let idx = match slot_for(tid) {
        Some(i) => i,
        None => return,
    };
    let table = CAP_TABLES[idx].lock();
    table.clear_all();
    cap_event(CapEvent::Wiped { slot: idx });
    // Release the claim so the next domain re-registers cleanly.
    OWNER[idx].store(NO_OWNER, Ordering::Release);
    drop(table);
    // The task's send capabilities went with the table: an endpoint left
    // with none tells its server (wave 15 N5b).
    notices();
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
/// Under owner decision 38 (2026-09-15) this is a
/// **move, as `zx_handle_replace` is** — the sender's entry is removed in the
/// same step that installs the receiver's. Nothing here duplicates a
/// capability.
///
/// # `TRANSFER` gates the move (owner decision 2026-09-26, O3.4; split from `DUP` 2026-10-17)
///
/// A capability whose slot permissions do not include `CapPerms::TRANSFER`
/// cannot be moved to a DIFFERENT task at all — refused with `MissingPerms`
/// before either table is touched. This is what makes a fork-minted
/// `Cap<Endpoint>` (`endpoint_inherit_at_fork`, `WRITE` only, deliberately
/// never `TRANSFER`) non-transferable: "the child may reach its parent" stays
/// exactly that, never "and so may anyone the child can reach", so
/// `CAPS.TOML` remains the whole authority graph. `DUP` is not asked: a move
/// copies nothing (the sender loses the capability in the same step), and
/// `DUP` is the right to copy ([`move_caps`]' DUP entries, `SYS_CAP_DERIVE`).
/// A task moving a capability to itself (`from_tid == to_tid`, resolving to
/// the same table slot — the "serves its own endpoint" case) is not a
/// transfer to anyone new and is exempt.
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
            return match r {
                Ok((h, Some((kind, resource)))) => {
                    run_move_hook(kind, resource, from_tid, to_tid);
                    Ok(h)
                }
                Ok((h, None)) => Ok(h),
                Err(e) => Err(e),
            };
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
) -> Option<Result<(CapHandle, Option<(crate::cap::CapType, u32)>), CapError>> {
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
        return Some(Ok((handle, None)));
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
    Some(move_locked(sender, receiver, (from_idx, from_owner), (to_idx, to_owner), handle, rights))
}

/// Tell the hook a capability moved from `from`'s table into `to`'s, with
/// `perms` there and `granted` here. A move that drops `READ` is, for a port
/// binding, the revoke of the capability the binding was made through (every
/// bind takes `READ`): the arriving capability could not have made it.
#[inline]
fn moved_event(from: usize, to: usize, kind: crate::cap::CapType, perms: CapPerms, granted: CapPerms, resource: u32) {
    if perms.contains(CapPerms::READ) && !granted.contains(CapPerms::READ) {
        cap_event(CapEvent::Revoked { slot: from, kind, perms, resource });
    } else {
        cap_event(CapEvent::Moved { from, to, kind, perms: granted, resource });
    }
}

/// The move itself, both tables locked and still their owners'.
fn move_locked(
    sender: &CapTable,
    receiver: &CapTable,
    (from_idx, sender_key): (usize, u32),
    (to_idx, receiver_key): (usize, u32),
    handle: CapHandle,
    rights: Option<CapPerms>,
) -> Result<(CapHandle, Option<(crate::cap::CapType, u32)>), CapError> {
    let (kind, perms, resource) = sender.peek_raw(handle).ok_or(CapError::Stale)?;
    // A capability past its deadline, or whose ancestor was revoked, moves no further.
    if sender.is_void(handle) {
        return Err(CapError::Revoked);
    }
    // The badge travels with the capability, and so does its place in the
    // warrant tree: the parent it was derived from stays its parent.
    let ext = sender.ext_of(handle).ok_or(CapError::Stale)?;
    let warrant = sender.warrant_of(handle).ok_or(CapError::Stale)?;
    // `TRANSFER` gates the move to a different task (O3.4): checked before
    // anything is touched, same as the free-slot check below.
    if !perms.contains(crate::cap::CapPerms::TRANSFER) {
        return Err(CapError::MissingPerms);
    }
    // Kept or lowered, never raised.
    let (granted, warrant) = narrow_warrant(perms, &warrant, &DeriveSpec { rights, ..DeriveSpec::SAME })?;
    // Refuse before the sender loses anything: a slot, and a caveat block if
    // the capability carries caveats.
    if !receiver.has_free_slot() || (!warrant.caveats.is_empty() && receiver.free_caveat_blocks() == 0) {
        return Err(CapError::NoSpace);
    }

    // The single step: the receiver takes the capability first (a free slot
    // was checked above, so nothing is lost on a refusal), then the sender's
    // slot goes. `take_out` answering false would mean the slot changed under
    // a lock we hold, which cannot happen — asserting it here is how that
    // assumption stops being silent if the locking ever changes.
    let kids = sender.has_children(handle);
    let moved = receiver
        .grant_warranted(kind, granted, resource, ext, warrant)
        .ok_or(CapError::NoSpace)?;
    if !take_out(sender, sender_key, handle, kids, receiver_key, receiver, moved) {
        receiver.delete_raw(moved);
        return Err(CapError::Stale);
    }
    // Both locks still held: a revoke of the moved capability in the
    // receiver's table cannot run before its bindings follow it there.
    moved_event(from_idx, to_idx, kind, perms, granted, resource);
    Ok((moved, Some((kind, resource))))
}

/// Take the capability `handle` out of `sender`, where it was just granted at
/// `moved` in `receiver` (the domain `to_key`): a MOVE. What was derived from
/// it (`kids`) follows the capability: it hangs under the new slot, which is
/// marked as having children, so that revoking the capability where it is now
/// still reaches them. The row goes in while the sender's slot is alive and
/// takes effect once it is gone ([`crate::cap::forward_push`]). Both tables are
/// locked. `false` when the sender's slot was not there to take.
fn take_out(
    sender: &CapTable,
    from_key: u32,
    handle: CapHandle,
    kids: bool,
    to_key: u32,
    receiver: &CapTable,
    moved: CapHandle,
) -> bool {
    let from = wref(from_key, handle);
    let handed = kids && {
        receiver.note_child(moved);
        crate::cap::forward_push(from, wref(to_key, moved))
    };
    let taken = sender.take_out_raw(handle);
    if kids {
        if handed {
            crate::cap::forward_commit(from);
        } else {
            crate::cap::forward_refused();
        }
    }
    taken
}

/// Delete a capability by kind-erased handle.
///
/// The mover has no `T` to be generic over, for the
/// same reason [`move_cap`] does not: the capability carries whatever kind the
/// sender held.
///
/// Returns whether a slot was actually cleared. Used when a moved capability
/// must be destroyed rather than returned — the message it travelled with will
/// never be delivered and its sender is gone, so there is nobody to move it
/// back to. Destroying is the fail-closed half of that pair. A delete: a copy
/// made from it, if any, stays (module doc), but a capability that never
/// reached its receiver has none.
pub fn delete_moved(tid: u32, handle: CapHandle) -> bool {
    let (idx, owner) = match slot_owner(tid) {
        Some(i) => i,
        None => return false,
    };
    let table = CAP_TABLES[idx].lock();
    let held = table.peek_stored(handle);
    let parent = table.warrant_of(handle).map_or(0, |w| w.parent);
    let cleared = table.delete_raw(handle);
    if let (true, Some((kind, perms, resource))) = (cleared, held) {
        cap_event(CapEvent::Revoked { slot: idx, kind, perms, resource });
        azos_decision::record(Rule::CapRevoke, Verdict::Deny, owner, [wref(owner, handle), parent, 0]);
    }
    drop(table);
    notices();
    cleared
}

/// Revoke every capability of `kind` whose packed resource names index `idx`,
/// walking every per-task table by index. Returns how many were revoked.
///
/// **WHY a walk by index.** A per-slot generation
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
pub fn revoke_index_in_every_table(kind: crate::cap::CapType, idx: u32) -> usize {
    let mut revoked = 0;
    for table in CAP_TABLES.iter() {
        revoked += table.lock().revoke_kind_at_index(kind, idx);
    }
    notices();
    revoked
}

/// Mint, in `tid`'s table, a badged copy of its unbadged endpoint capability
/// `handle`: a derive (`CapTable::mint_badged`'s rules), the copy a child of
/// the source in the warrant tree, so revoking the source revokes it.
pub fn mint_badged(tid: u32, handle: CapHandle, badge: u32, rights: CapPerms) -> Result<CapHandle, CapError> {
    mint_badged_until(tid, handle, badge, rights, 0)
}

/// [`mint_badged`] with a deadline for the copy (`CapTable::mint_badged_until`).
pub fn mint_badged_until(
    tid: u32,
    handle: CapHandle,
    badge: u32,
    rights: CapPerms,
    expiry_ns: u64,
) -> Result<CapHandle, CapError> {
    mint_badged_caveated(tid, handle, badge, rights, expiry_ns, &Caveats::NONE)
}

/// [`mint_badged_until`] with caveats for the copy
/// (`CapTable::mint_badged_caveated`): they follow the source's and can only
/// narrow.
pub fn mint_badged_caveated(
    tid: u32,
    handle: CapHandle,
    badge: u32,
    rights: CapPerms,
    expiry_ns: u64,
    caveats: &Caveats,
) -> Result<CapHandle, CapError> {
    mint_badged_issued(tid, handle, badge, rights, expiry_ns, caveats, 0)
}

/// [`mint_badged_caveated`] with a declassification warrant for the label
/// bits `declassify` on the copy (`CapTable::mint_badged_issued`). The rule
/// for who may ask is `endpoint::mint_badged_issued`'s.
pub fn mint_badged_issued(
    tid: u32,
    handle: CapHandle,
    badge: u32,
    rights: CapPerms,
    expiry_ns: u64,
    caveats: &Caveats,
    declassify: u32,
) -> Result<CapHandle, CapError> {
    loop {
        let Some((idx, owner)) = slot_owner(tid) else { return Err(CapError::Stale) };
        let table = CAP_TABLES[idx].lock();
        if !still_owned(idx, owner) {
            continue;
        }
        let r = table.mint_badged_issued(owner, handle, badge, rights, expiry_ns, caveats, declassify);
        if let Ok(h) = r {
            if let Some(w) = table.warrant_of(h) {
                azos_decision::record(Rule::CapDerive, Verdict::Admit, owner, [wref(owner, h), w.parent, w.expiry_ns]);
            }
        }
        drop(table);
        notices();
        return r;
    }
}

/// Revoke everything derived from `handle` (a badged copy, a copy lent or
/// moved to another task, theirs in turn) and keep the capability itself.
///
/// The slot is cleared and the same capability granted again with the same
/// rights, extension word and warrant: the grant takes the next generation, so
/// every warrant that names the old `(slot, generation)` as its parent is
/// dangling and the sweep (`notices`) revokes it wherever it sits. The old
/// handle is stale; the caller's replacement is the returned one.
///
/// Refused: a stale handle (`Stale`); a capability past its deadline
/// (`Revoked`); no slot to grant into (`NoSpace`, which cannot happen on a
/// table that just freed one, and loses nothing the sweep did not already).
pub fn revoke_derived(tid: u32, handle: CapHandle) -> Result<CapHandle, CapError> {
    loop {
        let Some((idx, owner)) = slot_owner(tid) else { return Err(CapError::Stale) };
        let table = CAP_TABLES[idx].lock();
        if !still_owned(idx, owner) {
            continue;
        }
        let r = (|| {
            let (kind, perms, resource) = table.peek_stored(handle).ok_or(CapError::Stale)?;
            if table.is_void(handle) {
                return Err(CapError::Revoked);
            }
            let ext = table.ext_of(handle).ok_or(CapError::Stale)?;
            let warrant = table.warrant_of(handle).ok_or(CapError::Stale)?;
            table.revoke_raw(handle);
            table.grant_warranted(kind, perms, resource, ext, warrant).ok_or(CapError::NoSpace)
        })();
        drop(table);
        notices();
        return r;
    }
}

/// Number of occupied slots for the named task.
pub fn occupied(tid: u32) -> usize {
    match slot_for(tid) {
        Some(idx) => CAP_TABLES[idx].lock().occupied(),
        None => 0,
    }
}

/// Number of occupied slots at a raw table index, bypassing TID validity.
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
/// registered" converge on the same `0`. A caller that captured the table
/// index while the task was still alive ([`table_slot`]) can use this
/// instead to read the table's true content, independent of whether the TID
/// that used to own it still resolves.
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
    /// A deadline for the receiver's copy (monotonic nanoseconds; 0 keeps the
    /// sender's, if any); never later than the sender's. The v2 descriptor's
    /// `CapDesc::expiry_ns` fills it.
    pub expiry_ns: u64,
    /// A quota for the receiver's copy; `Quota::NONE` keeps the sender's, if
    /// any; never more than the sender's. Passed as `NONE` by the syscall path.
    pub quota: Quota,
    /// Caveats added to the receiver's copy, after the sender's, which it
    /// keeps whole. Passed as `NONE` by the syscall path.
    pub caveats: Caveats,
}

impl CapXfer {
    /// A transfer of `handle` with the sender's rights, deadline, quota and
    /// caveats, and nothing added.
    pub const fn new(handle: CapHandle, dup: bool) -> Self {
        CapXfer { handle, dup, rights: None, expiry_ns: 0, quota: Quota::NONE, caveats: Caveats::NONE }
    }
}

/// Transfer every capability `xs` names from `from_tid`'s table to
/// `to_tid`'s, or none of them (wave 15 N11, the message descriptor's rule).
/// The receiver's handles go to `out[..xs.len()]`, in order.
///
/// Everything is checked, under both tables' locks, before the sender loses
/// anything: each handle live, each carrying `TRANSFER` (any transfer to
/// another task needs it) and, for a DUP entry, `DUP`, the rights asked a subset of those held, no slot named
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
        let mut moved = MovedSet::new();
        let r = move_caps_locked(sender, receiver, (from_idx, from_owner), (to_idx, to_owner), xs, out, true, &mut moved);
        if r.is_err() && !keep {
            for x in xs.iter().filter(|x| !x.dup) {
                if let Some((kind, perms, resource)) = sender.peek_stored(x.handle) {
                    if sender.delete_raw(x.handle) {
                        cap_event(CapEvent::Revoked { slot: from_idx, kind, perms, resource });
                    }
                }
            }
        }
        drop(lo_tab);
        drop(hi_tab);
        notices();
        if r.is_ok() {
            moved.run(from_tid, to_tid);
        }
        return r;
    }
}

/// What the receiver gets for entry `x` of a transfer out of the table of the
/// domain `from_key`: the slot's kind, resource and extension word, the rights
/// it gets and its warrant. A DUP entry derives a new link of the chain
/// ([`derive_warrant`]); a MOVE entry keeps the place it has
/// ([`narrow_warrant`]). Nothing is changed; any refusal is the transfer's.
fn xfer_plan(
    sender: &CapTable,
    from_key: u32,
    x: &CapXfer,
    need_transfer: bool,
) -> Result<(crate::cap::CapType, CapPerms, u32, CapExt, CapPerms, Warrant), CapError> {
    let (kind, perms, resource) = sender.peek_raw(x.handle).ok_or(CapError::Stale)?;
    if sender.is_void(x.handle) {
        return Err(CapError::Revoked);
    }
    // A task's transfer needs `TRANSFER` on every entry, and `DUP` as well on
    // a DUP entry (it makes a copy the sender keeps).
    if need_transfer && (!perms.contains(CapPerms::TRANSFER) || (x.dup && !perms.contains(CapPerms::DUP))) {
        return Err(CapError::MissingPerms);
    }
    let sw = sender.warrant_of(x.handle).ok_or(CapError::Stale)?;
    let ext = sender.ext_of(x.handle).ok_or(CapError::Stale)?;
    let spec = DeriveSpec { rights: x.rights, expiry_ns: x.expiry_ns, quota: x.quota, caveats: x.caveats };
    let (granted, w) = if x.dup {
        derive_warrant(wref(from_key, x.handle), perms, &sw, &spec)?
    } else {
        narrow_warrant(perms, &sw, &spec)?
    };
    Ok((kind, perms, resource, ext, granted, w))
}

/// [`move_caps`] with both tables locked and still their owners' (`from` and
/// `to` are each a table index and the domain key that owns it).
/// `need_transfer`: a task's transfer, which needs `TRANSFER` on every entry
/// (and `DUP` on a DUP entry); [`undo_move_caps`] passes `false` (the kernel
/// putting a capability back where it came from is no transfer by a task).
fn move_caps_locked(
    sender: &CapTable,
    receiver: &CapTable,
    (from_idx, from_key): (usize, u32),
    (to_idx, to_key): (usize, u32),
    xs: &[CapXfer],
    out: &mut [CapHandle],
    need_transfer: bool,
    moved: &mut MovedSet,
) -> Result<usize, CapError> {
    // Phase 1: check every entry; nothing changes.
    let mut blocks = 0;
    for (i, x) in xs.iter().enumerate() {
        let plan = xfer_plan(sender, from_key, x, need_transfer)?;
        blocks += usize::from(!plan.5.caveats.is_empty());
        if xs[..i].iter().any(|y| y.handle.slot() == x.handle.slot()) {
            return Err(CapError::MissingPerms);
        }
    }
    if receiver.free_slots() < xs.len() || receiver.free_caveat_blocks() < blocks {
        return Err(CapError::NoSpace);
    }
    // Phase 2: every entry lands. Each step below was checked above under
    // the locks still held, so none can fail; a failure would mean the
    // locking changed, and is reported rather than assumed away.
    for (x, o) in xs.iter().zip(out.iter_mut()) {
        let (kind, perms, resource, ext, granted, w) = xfer_plan(sender, from_key, x, need_transfer)?;
        let kids = !x.dup && sender.has_children(x.handle);
        *o = receiver.grant_warranted(kind, granted, resource, ext, w).ok_or(CapError::NoSpace)?;
        if x.dup {
            // The copy is a link of the sender's chain: revoking the slot it
            // came from revokes the copy.
            sender.note_child(x.handle);
            azos_decision::record(Rule::CapDerive, Verdict::Admit, to_key, [wref(to_key, *o), w.parent, w.expiry_ns]);
        } else {
            if !take_out(sender, from_key, x.handle, kids, to_key, receiver, *o) {
                receiver.delete_raw(*o);
                return Err(CapError::Stale);
            }
            moved_event(from_idx, to_idx, kind, perms, granted, resource);
            moved.push(kind, resource);
        }
    }
    Ok(xs.len())
}

/// Undo a [`move_caps`] from `sender` to `holder` whose message went nowhere
/// (a call refused or withdrawn before a server took it, a reply its caller
/// never collects): `xs` are the entries the sender asked for and `got[k]`
/// the handle `xs[k]` took in `holder`'s table.
///
/// A DUP entry's copy is destroyed: the sender kept its own handle, so
/// giving the copy back would leave it holding two. A MOVE entry goes back
/// to the sender (a fresh handle, the rights the holder's copy carries),
/// without the `TRANSFER` check a task's transfer needs: the copy may have been
/// attenuated below `TRANSFER`, and putting it back is the kernel's, not a
/// transfer. When the MOVE entries cannot go back (the sender gone, or its
/// table full) they are destroyed too, so that no capability stays in a
/// table whose task never accepted it. Returns how many of those were lost
/// to the sender (0 when every MOVE entry went back).
pub fn undo_move_caps(sender: u32, holder: u32, xs: &[CapXfer], got: &[CapHandle]) -> usize {
    let n = xs.len().min(got.len()).min(MSG_MAX_CAPS);
    let mut back = [CapXfer::new(CapHandle(0), false); MSG_MAX_CAPS];
    let mut nb = 0;
    for (x, h) in xs.iter().zip(got.iter()).take(n) {
        if x.dup {
            delete_moved(holder, *h);
        } else {
            back[nb].handle = *h;
            nb += 1;
        }
    }
    if nb == 0 || move_back(holder, sender, &back[..nb]) {
        return 0;
    }
    for x in &back[..nb] {
        delete_moved(holder, x.handle);
    }
    nb
}

/// [`move_caps`] without the `TRANSFER` check and with `keep`: `true` when every
/// entry went from `from_tid` to `to_tid`.
fn move_back(from_tid: u32, to_tid: u32, xs: &[CapXfer]) -> bool {
    let mut out = [CapHandle(0); MSG_MAX_CAPS];
    loop {
        let Some((from_idx, from_owner)) = slot_owner(from_tid) else { return false };
        let Some((to_idx, to_owner)) = slot_owner(to_tid) else { return false };
        if from_idx == to_idx {
            return false;
        }
        let (lo, hi) = if from_idx < to_idx { (from_idx, to_idx) } else { (to_idx, from_idx) };
        let lo_tab = CAP_TABLES[lo].lock();
        let hi_tab = CAP_TABLES[hi].lock();
        if !still_owned(from_idx, from_owner) || !still_owned(to_idx, to_owner) {
            continue;
        }
        let (sender, receiver) = if from_idx == lo { (&*lo_tab, &*hi_tab) } else { (&*hi_tab, &*lo_tab) };
        let mut moved = MovedSet::new();
        let ok = move_caps_locked(
            sender,
            receiver,
            (from_idx, from_owner),
            (to_idx, to_owner),
            xs,
            &mut out[..xs.len()],
            false,
            &mut moved,
        )
        .is_ok();
        drop(lo_tab);
        drop(hi_tab);
        notices();
        if ok {
            moved.run(from_tid, to_tid);
        }
        return ok;
    }
}

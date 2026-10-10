// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sched`, reduced to the one thing
//! `crates/core/ipc/src/cap_store.rs` actually calls: the TID → task-pool-slot
//! lookup.
//!
//! **WHY this exists.** The real `azos_sched` is RV64-only (context
//! switch asm, CSRs, PLIC), so the `#[path]` host-test trick cannot pull it
//! in. But the whole point of these tests is `cap_store`'s behaviour *around*
//! that lookup, so the shim exposes a control surface the real scheduler has
//! no reason to expose: [`shim_bind`] / [`shim_kill`] make a TID live or dead
//! at a chosen slot, which is what
//! `cap_store_tests::a_reused_slot_wipes_the_previous_owners_table` needs to
//! put a dead task's slot under a live heir.
//!
//! **History.** This shim used to also support `cap_store::delegate`'s
//! ring-3-chosen-TID resolution: `shim_bind` called twice on one slot (two
//! live TIDs aliasing it — the wrong-slot race `idx_for_tid` can hit under
//! `alloc_slot`) and a one-shot `shim_stale_once` that proved the
//! delegation-only confirmation pass actually refused a stale match. Both
//! `delegate` and `SYS_CAP_GRANT` were removed 2026-09-03 (boot-only caps,
//! RFC-0003), and `shim_stale_once`/`shim_clear_stale` were removed with
//! their only callers. `shim_bind` aliasing one slot twice still works — the
//! surviving test does not need it, but nothing here forbids it.
//!
//! Pulled in under the name `azos_sched` via a Cargo dependency rename.
//! The kernel never sees it.

use std::sync::Mutex;

/// `cap_store.rs` uses `azos_sched::task::MAX_TASKS`. Taken from the real
/// generated constant so the shim cannot drift from `.config`.
pub mod task {
    pub use azos_limits::MAX_TASKS;
}

#[derive(Default)]
struct FakePool {
    /// Live `(tid, slot)` bindings. A `Vec` and not a `[u32; MAX_TASKS]`
    /// because two TIDs sharing one slot is representable and, historically,
    /// exercised.
    live: Vec<(u32, usize)>,
}

static POOL: Mutex<Option<FakePool>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut FakePool) -> R) -> R {
    let mut g = POOL.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(FakePool::default))
}

// ── Test-only control surface ──────────────────────────────────────────────

/// Forget every binding. Call at the start of every test.
pub fn shim_reset() {
    let mut g = POOL.lock().unwrap_or_else(|e| e.into_inner());
    *g = Some(FakePool::default());
}

/// Make `tid` resolve to `slot`. Two TIDs may share a slot on purpose.
pub fn shim_bind(tid: u32, slot: usize) {
    with(|p| {
        p.live.retain(|(t, _)| *t != tid);
        p.live.push((tid, slot));
    });
}

/// Make `tid` resolve to nothing — a dead task.
pub fn shim_kill(tid: u32) {
    with(|p| p.live.retain(|(t, _)| *t != tid));
}

// ── The `azos_sched` surface `cap_store` calls ─────────────────────────

/// Translate a TID to a task-pool slot index.
pub fn idx_for_tid(tid: u32) -> Option<usize> {
    with(|p| p.live.iter().find(|(t, _)| *t == tid).map(|(_, s)| *s))
}

/// Wave 13 (THREADS): `azos_sched::group` as host tests see it: a world
/// with no thread groups, every task its own process.
pub mod group {
    pub fn lead_of_idx(_idx: usize) -> u32 { 0 }
    pub fn table_lead_of_idx(_idx: usize) -> u32 { 0 }
    pub fn any_groups() -> bool { false }
    pub fn proc_of(_idx: usize, tid: u32) -> u32 { tid }
    pub fn proc_tid(tid: u32) -> u32 { tid }
    pub fn shares_tables(_tid: u32) -> bool { false }
    pub fn live_members(_leader: u32) -> u32 { 1 }
    pub fn current_group_ending() -> bool { false }
    pub fn set_current_clear_tid(_addr: u64) {}
    pub struct MmGuard;
    pub fn mm_lock() -> MmGuard { MmGuard }
}

/// N4 shim: no task runs here, so no current slot (`cap_store` then
/// resolves by TID, as the kernel does for another task's TID).
pub fn current_task_slot() -> Option<(usize, u32)> {
    None
}

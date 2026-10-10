// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sched`, reduced to the one thing
//! `crates/core/ipc/src/cap_store.rs` actually calls: the TID → task-pool-slot
//! lookup.
//!
//! Identical in shape to `tests/host/cap-tests/shims/sched` (copied, not
//! path-shared — see that crate's copy for the full rationale on why the
//! real scheduler cannot be used here). This crate's tests only need the
//! "make a TID live at a slot" half of the control surface
//! ([`shim_bind`]); the stale/alias-race helpers are carried along so a
//! future addition to this suite does not need to touch the shim again.

use std::sync::Mutex;

/// `cap_store.rs` uses `azos_sched::task::MAX_TASKS`. Taken from the
/// real generated constant so the shim cannot drift from `.config`.
pub mod task {
    pub use azos_limits::MAX_TASKS;
}

/// `channel.rs` (mounted since RFC-0040 gap 1: `cap_seed`'s Channel arm reads
/// the channel's generation) calls these from its `#[cfg(not(test))]`
/// `caller_ctx`. The suite runs the `#[cfg(test)]` variant, driven by
/// `channel::test_ctx`; these only let the plain lib target type-check. "No
/// current task, kernel context", as in `tests/host/ipc-chan-tests`' shim.
pub fn current_task_tid() -> u32 {
    0
}

/// The calling process (wave 15): a host task is its own process.
pub fn current_proc_tid() -> u32 {
    current_task_tid()
}

/// See [`current_task_tid`].
pub fn current_user_pt() -> usize {
    0
}

#[derive(Default)]
struct FakePool {
    live: Vec<(u32, usize)>,
    stale_once: Option<(u32, usize)>,
}

static POOL: Mutex<Option<FakePool>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut FakePool) -> R) -> R {
    let mut g = POOL.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(FakePool::default))
}

/// Forget every binding.
pub fn shim_reset() {
    let mut g = POOL.lock().unwrap_or_else(|e| e.into_inner());
    *g = Some(FakePool::default());
}

/// Make `tid` resolve to `slot`.
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

/// Answer the *next* lookup of `tid` with `slot`, then go back to the truth.
pub fn shim_stale_once(tid: u32, slot: usize) {
    with(|p| p.stale_once = Some((tid, slot)));
}

/// Drop an unconsumed [`shim_stale_once`].
pub fn shim_clear_stale() {
    with(|p| p.stale_once = None);
}

/// Translate a TID to a task-pool slot index.
pub fn idx_for_tid(tid: u32) -> Option<usize> {
    with(|p| {
        if let Some((t, slot)) = p.stale_once {
            if t == tid {
                p.stale_once = None;
                return Some(slot);
            }
        }
        p.live.iter().find(|(t, _)| *t == tid).map(|(_, s)| *s)
    })
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

/// N4 shim: the running task's pool slot and TID (`azos_sched::current_task_slot`).
pub fn current_task_slot() -> Option<(usize, u32)> {
    let tid = current_task_tid();
    idx_for_tid(tid).map(|i| (i, tid))
}

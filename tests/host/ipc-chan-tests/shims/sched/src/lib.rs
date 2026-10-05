// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for the two `azos_sched` accessors that
//! `crates/core/ipc/src/{channel,pipe,signal}.rs` call from `caller_ctx`.
//!
//! The real crate is RV64-only (per-hart state, `context_switch.S`, CSR
//! access). Its library name is reused here (`[lib] name = "azos_sched"`)
//! so the kernel sources compile unedited.
//!
//! **These bodies are never exercised by the tests.** Each module's
//! `caller_ctx` has a `#[cfg(test)]` variant driven by `test_ctx` atomics,
//! and that is the one the suite runs. This shim exists only so the
//! `#[cfg(not(test))]` arm still *type-checks* when Cargo builds the plain
//! `lib` target alongside the test target. The values below therefore say
//! "kernel task, no current task", which is the safe reading if anything ever
//! did call them.

/// Always 0 — "no current task".
pub fn current_task_tid() -> u32 {
    0
}

/// Always 0 — "kernel task, no user address space".
pub fn current_user_pt() -> usize {
    0
}

/// `cap_store.rs`, which comes along with `cap.rs`'s `objref`, sizes its
/// tables with `task::MAX_TASKS`. Taken from the generated constant so it
/// cannot drift from `.config`.
pub mod task {
    pub use azos_limits::MAX_TASKS;
}

/// `cap_store.rs` resolves a TID to a task-pool slot. No test in this crate
/// reaches it; identity mapping with 0 refused, as in
/// `tests/host/ipc-lease-tests`' shim.
pub fn idx_for_tid(tid: u32) -> Option<usize> {
    if tid == 0 || tid as usize >= task::MAX_TASKS {
        return None;
    }
    Some(tid as usize)
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

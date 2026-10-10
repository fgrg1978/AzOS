// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sched`, as seen from `crates/core/ipc`'s
//! `cap_store.rs` and `channel.rs` (pulled real into
//! `tests/host/syscall-tests/shims/ipc`). `cap_store.rs` needs `idx_for_tid` and
//! `task::MAX_TASKS`, reused verbatim from `tests/host/cap-tests`'s shim of the
//! same name (same surface, same reasons).
//!
//! **The caller identity is forwarded, not stubbed.** `channel.rs` is compiled
//! here as a dependency, so its `#[cfg(not(test))]` `caller_ctx` is the one
//! that runs, and it reads `current_task_tid` / `current_user_pt`. Both
//! forward to this crate's `shims/sched` — the registers `handlers.rs` itself
//! reads and every test sets with `set_current_task_tid` /
//! `set_current_user_pt`. In the kernel `channel.rs` and the handlers ask one
//! scheduler; a second, independent identity here would let a test that set
//! only the handlers' caller create a channel owned by TID 0, and a "stranger
//! is refused" assertion would then pass because 0 is not the owner rather
//! than because the stranger is not. One source removes that. The typed
//! channel create and close (`src/ipc_destroy.rs`, `src/typed_ipc.rs`) reach it.
//!
//! The task POOL is still `cap_test_sched`'s (`idx_for_tid`, `shim_bind`):
//! that is a slot table, not an identity, and `ring3_with_table` binds it.

pub use cap_test_sched::*;
/// The futex table `notify.rs` files into (wave 15 N9).
pub use syscall_test_sched::futex_table;

pub fn current_task_tid() -> u32 {
    syscall_test_sched::current_task_tid()
}

/// The calling process (wave 15): a host task is its own process unless a
/// test says otherwise (`syscall_test_sched::set_current_proc_tid`).
pub fn current_proc_tid() -> u32 {
    syscall_test_sched::current_proc_tid()
}

pub fn current_user_pt() -> usize {
    syscall_test_sched::current_user_pt()
}

/// RFC-0049 M1: `shm.rs` and `io_ring.rs` charge their frames to the creator.
/// Forwarded to the one budget stand-in `handlers.rs` also charges.
pub fn mm_charge(pages: u32) -> bool {
    syscall_test_sched::mm_charge(pages)
}

pub fn mm_discharge(pages: u32) {
    syscall_test_sched::mm_discharge(pages)
}

pub fn mm_discharge_tid(tid: u32, pages: u32) {
    syscall_test_sched::mm_discharge_tid(tid, pages)
}

/// `azos_sched::wait`, for the wake `port.rs` names by module path.
pub mod wait {
    /// Wake a registered waiter of an event port, by TID (RFC-0040 gap 1:
    /// `port.rs` wakes each waiter it detaches when it queues an event on the
    /// port or destroys or releases it). Recorded as `(tid, port_ref)`: the
    /// addressee and the exact `WaitReason::Port` value its predicate matches.
    pub fn wake_port_waiter(tid: u32, port_ref: u32) {
        super::PORT_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push((tid, port_ref));
    }

    /// Wake a registered port waiter that blocks with a deadline
    /// (`WaitReason::Timer`), by TID (`port.rs`, wave 11). Recorded, in
    /// order; see `shim_port_timed_wakes`.
    pub fn wake_port_timed_waiter(tid: u32) {
        super::PORT_TIMED_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push(tid);
    }

    /// Wake the registered waiter of a wake-task IRQ binding (`irq_bind.rs`).
    /// Nothing in this crate reaches it with a registered waiter: the
    /// blocking half of `SYS_DRV_IRQ_WAIT` is not driven here.
    pub fn wake_irq_waiter(_tid: u32, _irq: u32) {}

    /// Wake a lessee blocked in `SYS_IPC_LEASE_ACCEPT` on `(lessee, lessor)`
    /// (`lease.rs`, after a grant). Recorded, in order, as those two TIDs.
    pub fn wake_lease_acceptor(lessee: u32, lessor: u32) {
        super::LEASE_ACCEPT_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push((lessee, lessor));
    }
}

// What the real `lease.rs` (pulled into `shims/ipc` for `SYS_IPC_LEASE_*`)
// needs from the scheduler besides `wait::wake_lease_acceptor`. The wakes are
// recorded; the lessor's priority-inheritance wait (`lease_wait_return`) is
// not a syscall this crate reaches, so its block is `todo!()` and the
// priority calls answer "no priority known", which skips the boost.

static LEASE_ACCEPT_WAKES: std::sync::Mutex<Vec<(u32, u32)>> = std::sync::Mutex::new(Vec::new());
static WQ_WAKES: std::sync::Mutex<Vec<u32>> = std::sync::Mutex::new(Vec::new());

/// `(lessee, lessor)` pairs passed to `wait::wake_lease_acceptor` since the
/// last call, oldest first.
pub fn shim_take_lease_accept_wakes() -> Vec<(u32, u32)> {
    std::mem::take(&mut *LEASE_ACCEPT_WAKES.lock().unwrap_or_else(|e| e.into_inner()))
}

/// TIDs passed to [`wq_wake_by_tid`] since the last call, oldest first.
pub fn shim_take_wq_wakes() -> Vec<u32> {
    std::mem::take(&mut *WQ_WAKES.lock().unwrap_or_else(|e| e.into_inner()))
}

pub fn wq_wake_by_tid(tid: u32) {
    WQ_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push(tid);
}

pub fn wq_block_current() {
    todo!("not reached by any test in this crate")
}

/// No forced stop is ever pending in this crate's tests.
pub fn current_task_killed() -> bool {
    false
}

pub fn task_priority(_tid: u32) -> Option<u32> {
    None
}

pub fn boost_ready_task(_tid: u32, _new_prio: u32) {
    todo!("not reached by any test in this crate")
}

pub fn restore_ready_task(_tid: u32) {
    todo!("not reached by any test in this crate")
}

pub fn donate_priority(_donor: u32, _target: u32) -> bool {
    todo!("not reached by any test in this crate")
}

pub fn return_donation(_target: u32) {
    todo!("not reached by any test in this crate")
}

/// `(tid, port_ref)` pairs passed to `wait::wake_port_waiter`, in order.
pub fn shim_port_waiter_wakes() -> Vec<(u32, u32)> {
    PORT_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

static PORT_WAITER_WAKES: std::sync::Mutex<Vec<(u32, u32)>> = std::sync::Mutex::new(Vec::new());


/// TIDs passed to `wait::wake_port_timed_waiter` since the last call, oldest
/// first (the record is drained).
pub fn shim_take_port_timed_wakes() -> Vec<u32> {
    std::mem::take(&mut *PORT_TIMED_WAKES.lock().unwrap_or_else(|e| e.into_inner()))
}

static PORT_TIMED_WAKES: std::sync::Mutex<Vec<u32>> = std::sync::Mutex::new(Vec::new());

/// Wave 13 (THREADS): `azos_sched::group` as host tests see it: a world
/// with no thread groups, every task its own process — unless a test makes
/// one task a thread of another (`syscall_test_sched::group::shim_set_member`,
/// wave 15), whose capability table it then shares.
pub mod group {
    pub fn lead_of_idx(_idx: usize) -> u32 { 0 }
    pub fn table_lead_of_idx(idx: usize) -> u32 { syscall_test_sched::group::table_lead_of_idx(idx) }
    pub fn any_groups() -> bool { syscall_test_sched::group::any_groups() }
    pub fn proc_of(_idx: usize, tid: u32) -> u32 { tid }
    pub fn proc_tid(tid: u32) -> u32 { syscall_test_sched::group::proc_tid(tid) }
    pub fn shares_tables(_tid: u32) -> bool { false }
    pub fn live_members(_leader: u32) -> u32 { 1 }
    pub fn current_group_ending() -> bool { false }
    pub fn set_current_clear_tid(_addr: u64) {}
    pub struct MmGuard;
    pub fn mm_lock() -> MmGuard { MmGuard }
}

/// N4: the calling task's pool slot and TID, as the kernel's scheduler
/// answers it (`cap_store::read_own_table`); shadows `cap_test_sched`'s,
/// which has no calling task.
pub fn current_task_slot() -> Option<(usize, u32)> {
    let tid = current_task_tid();
    cap_test_sched::idx_for_tid(tid).map(|i| (i, tid))
}

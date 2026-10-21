// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sched`, as seen from `crates/core/ipc`'s
//! `cap_store.rs` (pulled real into `tests/host/syscall-tests/shims/ipc`).
//! `cap_store.rs` needs `idx_for_tid` and `task::MAX_TASKS`, reused verbatim
//! from `tests/host/cap-tests`'s shim of the same name (same surface, same
//! reasons).
//!
//! **The caller identity is forwarded, not stubbed.** `current_task_tid` /
//! `current_user_pt` forward to this crate's `shims/sched` -- the registers
//! `handlers.rs` itself reads and every test sets with `set_current_task_tid`
//! / `set_current_user_pt`. In the kernel the pulled ipc modules and the
//! handlers ask one scheduler; a second, independent identity here would let
//! a test that set only the handlers' caller act as TID 0, and a "stranger is
//! refused" assertion would then pass because 0 is not the owner rather than
//! because the stranger is not. One source removes that.
//!
//! The task POOL is still `cap_test_sched`'s (`idx_for_tid`, `shim_bind`):
//! that is a slot table, not an identity, and `ring3_with_table` binds it.

pub use cap_test_sched::*;
/// The wake attribution's announcement of an interrupt delivery
/// (`azos_sched::wake_irq_enter`): nothing is logged on the host.
pub fn wake_irq_enter(_line: u32) {}
pub fn wake_irq_leave() {}

pub fn current_task_tid() -> u32 {
    syscall_test_sched::current_task_tid()
}

/// The calling process (wave 15): a host task is its own process unless a
/// test says otherwise (`syscall_test_sched::set_current_proc_tid`).
pub fn current_proc_tid() -> u32 {
    syscall_test_sched::current_proc_tid()
}

/// The futex as `memobj.rs`'s pipe section wakes it: the one `syscall_test_sched`
/// models, so a wake the section rings reaches a sleeper a test parked there.
pub mod futex {
    pub use syscall_test_sched::futex::{wake_key, Key};
}

pub fn current_user_pt() -> usize {
    syscall_test_sched::current_user_pt()
}

/// Memory admission: `memobj.rs` and `io_ring.rs` charge their frames to the creator.
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

/// Is `key` the Domain of the running task? The stand-in budget is that
/// task's alone; a Domain of any other task has no budget here (a charge to it
/// is not counted and never refused).
fn is_current_domain(key: u32) -> bool {
    cap_test_sched::idx_for_tid(syscall_test_sched::current_task_tid()).is_some_and(|i| task_domain(i) == key)
}

/// `azos_sched::mm_charge_domain`, over the one budget stand-in.
pub fn mm_charge_domain(key: u32, pages: u32) -> bool {
    !is_current_domain(key) || syscall_test_sched::mm_charge(pages)
}

/// `azos_sched::mm_discharge_domain`, over the one budget stand-in.
pub fn mm_discharge_domain(key: u32, pages: u32) {
    if is_current_domain(key) {
        syscall_test_sched::mm_discharge(pages)
    }
}

/// `azos_sched::rt`, for the reservation `irq_bind.rs` serves lines on. The
/// host's `.config` is a profile's (`IRQ_THREADED` on for the real-time ones),
/// so every task here holds a hard reservation on one CPU, [`set_reservation_cpu`]
/// (0 until a test says); the reservation's own refusals (none, soft, a CPU
/// other than the asked one, throttled) are the binding table's suite
/// (`tests/host/ipc-tests`). Without `IRQ_THREADED` the functions are not
/// reached.
pub mod rt {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The real enum's twin.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum IrqScRefusal {
        NoReservation,
        Soft,
    }

    static CPU: AtomicUsize = AtomicUsize::new(0);

    /// The CPU every host task's reservation runs on.
    pub fn set_reservation_cpu(cpu: usize) {
        CPU.store(cpu, Ordering::SeqCst);
    }

    pub fn irq_attach(_tid: u32) -> Result<(usize, bool), IrqScRefusal> {
        Ok((CPU.load(Ordering::SeqCst), false))
    }
    pub fn irq_detach(_tid: u32) {}
}

/// `azos_sched::wait`, for the wake `port.rs` names by module path.
pub mod wait {
    /// Wake a registered waiter of an event port, by TID (typed port calls:
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

}

// What the real ipc modules (pulled into `shims/ipc`) need from the scheduler.
// The wakes are recorded; a block is `todo!()` and the priority calls answer
// "no priority known", which skips the boost.

static WQ_WAKES: std::sync::Mutex<Vec<u32>> = std::sync::Mutex::new(Vec::new());

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
    pub fn any_groups() -> bool { syscall_test_sched::group::any_groups() }
    pub fn proc_of(_idx: usize, tid: u32) -> u32 { tid }
    pub fn proc_tid(tid: u32) -> u32 { syscall_test_sched::group::proc_tid(tid) }
    pub fn live_members(_leader: u32) -> u32 { 1 }
    pub fn current_group_ending() -> bool { false }
    pub fn set_current_clear_tid(_addr: u64) {}
    pub struct MmGuard;
    pub fn mm_lock() -> MmGuard { MmGuard }
}

/// D2 (domains): every task is its own domain, whose capability table is the
/// one at its pool slot, unless a test made the task a thread of another
/// (`syscall_test_sched::group::shim_set_member`): it then resolves to its
/// leader's table, as a thread joining its leader's domain does.
pub fn task_domain(idx: usize) -> u32 {
    let lead = syscall_test_sched::group::table_lead_of_idx(idx);
    let table = if lead != 0 { cap_test_sched::idx_for_tid(lead).unwrap_or(idx) } else { idx };
    // The generation is the TID that owns the table, as a fresh domain's is.
    let owner = if lead != 0 { lead } else { cap_test_sched::tid_at_slot(idx) };
    ((owner & 0xFFFF).max(1) << 16) | table as u32
}

/// D2: no task is the last of a shared domain in this world.
pub fn domain_shared(_tid: u32) -> bool {
    false
}

/// The slice of `azos_sched::domain` the capability store reads.
pub mod domain {
    pub const NONE: u32 = 0;
    pub const fn index(key: u32) -> usize {
        (key & 0xFFFF) as usize
    }
}

/// N4: the calling task's pool slot and TID, as the kernel's scheduler
/// answers it (`cap_store::read_own_table`); shadows `cap_test_sched`'s,
/// which has no calling task.
pub fn current_task_slot() -> Option<(usize, u32)> {
    let tid = current_task_tid();
    cap_test_sched::idx_for_tid(tid).map(|i| (i, tid))
}

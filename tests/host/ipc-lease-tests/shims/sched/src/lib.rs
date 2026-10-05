// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sched`.
//!
//! **WHY this exists.** `crates/core/ipc/src/lease.rs` calls into the scheduler to
//! wake a blocked lessor and to apply lease priority inheritance, and
//! `crates/core/ipc/src/cap_store.rs` resolves TIDs to task-pool slots. The real
//! `azos_sched` is RV64-only (context switch asm, CSRs, PLIC), so the
//! `#[path]` host-test trick cannot pull it in. This crate provides the same
//! surface, plus **observability the real scheduler has no reason to expose**:
//! every wake is recorded so a test can assert that the lessor was actually
//! woken, not merely that a state bit flipped. That distinction is the whole
//! point of these tests — the project's recurring failure mode has been
//! validating the decision and never the actuation.
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
struct FakeSched {
    current_tid: u32,
    user_pt: usize,
    /// TIDs passed to `wq_wake_by_tid`, in order.
    wq_wakes: Vec<u32>,
    /// TIDs passed to `wake_fast_ipc_server`, in order.
    fast_ipc_wakes: Vec<u32>,
    /// `(lessee, lessor)` pairs passed to `wait::wake_lease_acceptor`, in
    /// order. Its own vector because `SYS_IPC_LEASE_ACCEPT` parks the lessee on
    /// `WaitReason::LeaseAccept(lessee, lessor)`, and a wake aimed at
    /// `FastIpcServer(lessee)` would leave it asleep while a test asserting
    /// "the lessee was woken" still passed.
    lease_accept_wakes: Vec<(u32, u32)>,
    /// `(tid, prio)` pairs passed to `boost_ready_task`.
    boosts: Vec<(u32, u32)>,
    /// TIDs passed to `restore_ready_task`.
    restores: Vec<u32>,
    /// Priority reported by `task_priority`, per TID. Absent = task gone.
    priorities: Vec<(u32, u32)>,
    /// RFC-0049 M1: pages charged per TID (`mm_charge` / `mm_discharge` /
    /// `mm_discharge_tid`), and each TID's limit (absent = no limit).
    charged: Vec<(u32, u32)>,
    limits: Vec<(u32, u32)>,
}

static SCHED: Mutex<Option<FakeSched>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut FakeSched) -> R) -> R {
    let mut g = SCHED.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(FakeSched::default))
}

// ── Test-only control surface ──────────────────────────────────────────────

/// Wipe all recorded state. Call at the start of every test.
pub fn shim_reset() {
    let mut g = SCHED.lock().unwrap_or_else(|e| e.into_inner());
    *g = Some(FakeSched::default());
}

/// Pretend the given task is running. `user_pt == 0` means "kernel task",
/// which is the house convention for a privileged caller.
pub fn shim_set_current(tid: u32, user_pt: usize) {
    with(|s| {
        s.current_tid = tid;
        s.user_pt = user_pt;
    });
}

pub fn shim_set_priority(tid: u32, prio: u32) {
    with(|s| {
        s.priorities.retain(|(t, _)| *t != tid);
        s.priorities.push((tid, prio));
    });
}

pub fn shim_wq_wakes() -> Vec<u32> {
    with(|s| s.wq_wakes.clone())
}

pub fn shim_fast_ipc_wakes() -> Vec<u32> {
    with(|s| s.fast_ipc_wakes.clone())
}

pub fn shim_lease_accept_wakes() -> Vec<(u32, u32)> {
    with(|s| s.lease_accept_wakes.clone())
}

pub fn shim_boosts() -> Vec<(u32, u32)> {
    with(|s| s.boosts.clone())
}

pub fn shim_restores() -> Vec<u32> {
    with(|s| s.restores.clone())
}

/// Every TID woken by ANY path, order-insensitively.
///
/// There are three TID wake vectors on this shim and this must name all three
/// (for `lease_accept_wakes`, the lessee half of each pair: that is the task
/// the wake addresses); a vector left out makes a "was woken" assertion read
/// false and a "was NOT woken" one pass without proving anything.
pub fn shim_was_woken(tid: u32) -> bool {
    with(|s| s.wq_wakes.contains(&tid)
          || s.fast_ipc_wakes.contains(&tid)
          || s.lease_accept_wakes.iter().any(|(lessee, _)| *lessee == tid))
}

/// RFC-0049 M1: give `tid` a frame budget of `pages` (0 = none).
pub fn shim_set_limit(tid: u32, pages: u32) {
    with(|s| {
        s.limits.retain(|(t, _)| *t != tid);
        s.limits.push((tid, pages));
    });
}

/// Pages currently charged to `tid`.
pub fn shim_charged(tid: u32) -> u32 {
    with(|s| s.charged.iter().find(|(t, _)| *t == tid).map_or(0, |(_, n)| *n))
}

fn charged_mut(s: &mut FakeSched, tid: u32) -> &mut u32 {
    if let Some(i) = s.charged.iter().position(|(t, _)| *t == tid) {
        return &mut s.charged[i].1;
    }
    s.charged.push((tid, 0));
    &mut s.charged.last_mut().unwrap().1
}

// ── The `azos_sched` surface the ipc modules actually call ─────────────

/// Same contract as the kernel's: all or nothing against a nonzero limit.
pub fn mm_charge(pages: u32) -> bool {
    with(|s| {
        let tid = s.current_tid;
        let limit = s.limits.iter().find(|(t, _)| *t == tid).map_or(0, |(_, l)| *l);
        let c = charged_mut(s, tid);
        let next = c.saturating_add(pages);
        if limit != 0 && next > limit {
            return false;
        }
        *c = next;
        true
    })
}

pub fn mm_discharge(pages: u32) {
    with(|s| {
        let tid = s.current_tid;
        let c = charged_mut(s, tid);
        *c = c.saturating_sub(pages);
    })
}

pub fn mm_discharge_tid(tid: u32, pages: u32) {
    with(|s| {
        let c = charged_mut(s, tid);
        *c = c.saturating_sub(pages);
    })
}

pub fn current_task_tid() -> u32 {
    with(|s| s.current_tid)
}

pub fn current_user_pt() -> usize {
    with(|s| s.user_pt)
}

pub fn task_priority(tid: u32) -> Option<u32> {
    with(|s| s.priorities.iter().find(|(t, _)| *t == tid).map(|(_, p)| *p))
}

pub fn boost_ready_task(tid: u32, new_prio: u32) {
    with(|s| s.boosts.push((tid, new_prio)));
}

pub fn restore_ready_task(tid: u32) {
    with(|s| s.restores.push(tid));
}

/// The real donation rule, pulled from `crates/core/sched/src/donation.rs`, so
/// `lease_wait_return`'s decision is the kernel's own and not a restatement.
#[allow(dead_code)]
#[path = "../../../../../../crates/core/sched/src/donation.rs"]
mod donation;

/// `azos_sched::donate_priority`, over this fake: the real rule on the
/// recorded priorities, then the recorded boost.
pub fn donate_priority(donor: u32, target: u32) -> bool {
    // Floor 0: this fake's tasks are all kernel tasks (the ring-3 floor is
    // pinned by `donation.rs`'s own tests).
    match donation::donation_for(donor, task_priority(donor), target, task_priority(target), 0) {
        Some((p, _floored)) => { boost_ready_task(target, p); true }
        None => false,
    }
}

/// `azos_sched::return_donation`: recorded as a restore.
pub fn return_donation(target: u32) {
    restore_ready_task(target);
}

pub fn wq_wake_by_tid(tid: u32) {
    with(|s| s.wq_wakes.push(tid));
}

pub fn wake_fast_ipc_server(tid: u32) {
    with(|s| s.fast_ipc_wakes.push(tid));
}

/// `azos_sched::wait`, for the one wake `lease.rs` names by module path.
pub mod wait {
    /// Wake a lessee blocked on `WaitReason::LeaseAccept(lessee, lessor)`.
    /// Recorded as a pair so a test can assert which lessor the wake named.
    pub fn wake_lease_acceptor(lessee: u32, lessor: u32) {
        super::with(|s| s.lease_accept_wakes.push((lessee, lessor)));
    }

    /// Wake a registered waiter of an event port, by TID (`port.rs`). Recorded
    /// as `(tid, port_ref)` in `super::PORT_WAITER_WAKES`; see
    /// `shim_port_waiter_wakes`.
    pub fn wake_port_waiter(tid: u32, port_ref: u32) {
        super::PORT_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push((tid, port_ref));
    }

    /// Wake a registered port waiter that blocks with a deadline
    /// (`WaitReason::Timer`), by TID (`port.rs`, wave 11). Recorded in
    /// `super::PORT_TIMED_WAKES`; see `shim_port_timed_wakes`.
    pub fn wake_port_timed_waiter(tid: u32) {
        super::PORT_TIMED_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push(tid);
    }

    /// Wake the registered waiter of a wake-task IRQ binding, by TID
    /// (`irq_bind.rs`). Recorded as `(tid, irq)`; see `shim_irq_waiter_wakes`.
    pub fn wake_irq_waiter(tid: u32, irq: u32) {
        super::IRQ_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push((tid, irq));
    }
}

static IRQ_WAITER_WAKES: std::sync::Mutex<Vec<(u32, u32)>> = std::sync::Mutex::new(Vec::new());

/// `(tid, irq)` pairs passed to `wait::wake_irq_waiter`, in order, since the
/// last call (the record is drained).
pub fn shim_take_irq_waiter_wakes() -> Vec<(u32, u32)> {
    std::mem::take(&mut *IRQ_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Never called by the tests — `lease_wait_return` blocks, and a host stand-in
/// has nothing to block on. Present so the module compiles.
pub fn wq_block_current() {
    panic!(
        "wq_block_current() reached in a host test: lease_wait_return() would \
         spin forever here. Test the guard paths, not the blocking loop."
    );
}

/// `cap_store::slot_for` maps TID → task-pool slot. Identity-ish mapping is
/// enough for the port tests: distinct TIDs get distinct slots.
pub fn idx_for_tid(tid: u32) -> Option<usize> {
    if tid == 0 || tid as usize >= task::MAX_TASKS {
        return None;
    }
    Some(tid as usize)
}

// ── Port wakes (RFC-0040 gap 1) ────────────────────────────────────────────
//
// Kept outside `FakeSched` on purpose: its own record and reset, so
// `shim_reset()` and the TID-keyed wake vectors above are unchanged, and
// `shim_was_woken` does not consult it. `port.rs` wakes each registered waiter
// it detaches through `wait::wake_port_waiter(tid, port_ref)`; the record keeps
// both the addressee and the exact `WaitReason::Port` value (the port's packed
// `(index, generation)` reference) its predicate matches.

static PORT_WAITER_WAKES: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());

/// `(tid, port_ref)` pairs passed to `wait::wake_port_waiter`, in order.
pub fn shim_port_waiter_wakes() -> Vec<(u32, u32)> {
    PORT_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Forget the recorded port wakes, both kinds.
pub fn shim_reset_port_wakes() {
    PORT_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    PORT_TIMED_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

static PORT_TIMED_WAKES: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// TIDs passed to `wait::wake_port_timed_waiter`, in order: the waiters that
/// block on `WaitReason::Timer` (a deadline), kept apart from the `Port`
/// wakes so a test can tell which reason a wake would have matched.
pub fn shim_port_timed_wakes() -> Vec<u32> {
    PORT_TIMED_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clone()
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

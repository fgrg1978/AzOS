// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sched`.
//!
//! **WHY this exists.** `crates/core/ipc/src/port.rs` calls into the scheduler to
//! wake a blocked waiter, and
//! `crates/core/ipc/src/cap_store.rs` resolves TIDs to task-pool slots. The real
//! `azos_sched` is RV64-only (context switch asm, CSRs, PLIC), so the
//! `#[path]` host-test trick cannot pull it in. This crate provides the same
//! surface, plus **observability the real scheduler has no reason to expose**:
//! every wake is recorded so a test can assert that the waiter was actually
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
    /// Memory admission: pages charged per TID (`mm_charge` / `mm_discharge` /
    /// `mm_discharge_tid`), and each TID's limit (absent = no limit).
    charged: Vec<(u32, u32)>,
    limits: Vec<(u32, u32)>,
    /// `(region, offset)` of each `futex::wake_key` on a shared word, in order.
    futex_wakes: Vec<(u32, u32)>,
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

/// The futex of the real scheduler, as far as `memobj.rs`'s pipe section uses
/// it: a wake of the sleepers on a word of a shared region, recorded.
pub mod futex {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Key {
        Shared { obj: u32, offset: u32 },
    }

    pub fn wake_key(key: Key, _n: u32) -> i64 {
        let Key::Shared { obj, offset } = key;
        super::with(|s| s.futex_wakes.push((obj, offset)));
        0
    }
}

/// `(region, offset)` of the futex wakes since the last call, in order.
pub fn shim_take_futex_wakes() -> Vec<(u32, u32)> {
    with(|s| std::mem::take(&mut s.futex_wakes))
}

/// Memory admission: give `tid` a frame budget of `pages` (0 = none). The budget
/// is its Domain's (D2): `task_domain(tid)` names it, as it does in the kernel.
pub fn shim_set_limit(tid: u32, pages: u32) {
    let key = task_domain(tid as usize);
    with(|s| {
        s.limits.retain(|(t, _)| *t != key);
        s.limits.push((key, pages));
    });
}

/// Pages currently charged to `tid`'s Domain.
pub fn shim_charged(tid: u32) -> u32 {
    shim_charged_domain(task_domain(tid as usize))
}

/// Pages currently charged to the Domain `key`.
pub fn shim_charged_domain(key: u32) -> u32 {
    with(|s| s.charged.iter().find(|(t, _)| *t == key).map_or(0, |(_, n)| *n))
}

fn charged_mut(s: &mut FakeSched, key: u32) -> &mut u32 {
    if let Some(i) = s.charged.iter().position(|(t, _)| *t == key) {
        return &mut s.charged[i].1;
    }
    s.charged.push((key, 0));
    &mut s.charged.last_mut().unwrap().1
}

// ── The `azos_sched` surface the ipc modules actually call ─────────────

/// Same contract as the kernel's: all or nothing against a nonzero limit.
pub fn mm_charge(pages: u32) -> bool {
    mm_charge_domain(task_domain(with(|s| s.current_tid) as usize), pages)
}

pub fn mm_discharge(pages: u32) {
    mm_discharge_domain(task_domain(with(|s| s.current_tid) as usize), pages)
}

pub fn mm_discharge_tid(tid: u32, pages: u32) {
    mm_discharge_domain(task_domain(tid as usize), pages)
}

/// `azos_sched::mm_charge_domain`: the Domain `key` names, all or nothing.
pub fn mm_charge_domain(key: u32, pages: u32) -> bool {
    with(|s| {
        let limit = s.limits.iter().find(|(t, _)| *t == key).map_or(0, |(_, l)| *l);
        let c = charged_mut(s, key);
        let next = c.saturating_add(pages);
        if limit != 0 && next > limit {
            return false;
        }
        *c = next;
        true
    })
}

/// `azos_sched::mm_discharge_domain`. Applied at once here (the kernel posts
/// it for the Domain's next charge to fold in; the observable is the same).
pub fn mm_discharge_domain(key: u32, pages: u32) {
    with(|s| {
        let c = charged_mut(s, key);
        *c = c.saturating_sub(pages);
    })
}

pub fn current_task_tid() -> u32 {
    with(|s| s.current_tid)
}

/// The calling process (wave 15): a host task is its own process.
pub fn current_proc_tid() -> u32 {
    current_task_tid()
}

pub fn current_user_pt() -> usize {
    with(|s| s.user_pt)
}

/// `azos_sched::wait`, for the wakes the ipc modules name by module path.
pub mod wait {
    /// Wake a registered waiter of an event port, by TID (`port.rs`). Recorded
    /// as `(tid, port_ref)` in `super::PORT_WAITER_WAKES`; see
    /// `shim_port_waiter_wakes`.
    pub fn wake_port_waiter(tid: u32, port_ref: u32) {
        super::PORT_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push((tid, port_ref));
        super::note_irq_wake(tid);
    }

    /// Wake a registered port waiter that blocks with a deadline
    /// (`WaitReason::Timer`), by TID (`port.rs`, wave 11). Recorded in
    /// `super::PORT_TIMED_WAKES`; see `shim_port_timed_wakes`.
    pub fn wake_port_timed_waiter(tid: u32) {
        super::PORT_TIMED_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push(tid);
        super::note_irq_wake(tid);
    }
}

/// `azos_sched::rt`, for the reservation `irq_bind.rs` serves lines on
/// (`irq_attach` / `irq_detach`). A test gives a task a reservation with
/// [`shim_rt_set`]; the shim counts the lines attached to it
/// ([`shim_rt_attached`]) the way the SC does.
pub mod rt {
    /// Why a task cannot serve an interrupt line (the real enum's twin).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum IrqScRefusal {
        NoReservation,
        Soft,
    }

    /// `(cpu, throttled)` of a hard reservation, or why not.
    pub fn irq_attach(tid: u32) -> Result<(usize, bool), IrqScRefusal> {
        super::RT.lock().unwrap_or_else(|e| e.into_inner()).iter_mut()
            .find(|r| r.tid == tid)
            .ok_or(IrqScRefusal::NoReservation)
            .and_then(|r| {
                let (cpu, throttled) = r.res?;
                r.attached += 1;
                Ok((cpu, throttled))
            })
    }

    pub fn irq_detach(tid: u32) {
        if let Some(r) = super::RT.lock().unwrap_or_else(|e| e.into_inner()).iter_mut().find(|r| r.tid == tid) {
            r.attached = r.attached.saturating_sub(1);
        }
    }
}

struct RtTask {
    tid: u32,
    res: Result<(usize, bool), rt::IrqScRefusal>,
    attached: u32,
}

static RT: std::sync::Mutex<Vec<RtTask>> = std::sync::Mutex::new(Vec::new());

/// Forget every reservation `shim_rt_set` gave.
pub fn shim_rt_reset() {
    RT.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Give `tid` a reservation (`Ok((cpu, throttled))`) or a refusal.
pub fn shim_rt_set(tid: u32, res: Result<(usize, bool), rt::IrqScRefusal>) {
    let mut g = RT.lock().unwrap_or_else(|e| e.into_inner());
    g.retain(|r| r.tid != tid);
    g.push(RtTask { tid, res, attached: 0 });
}

/// Lines attached to `tid`'s SC.
pub fn shim_rt_attached(tid: u32) -> u32 {
    RT.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|r| r.tid == tid).map_or(0, |r| r.attached)
}

/// `cap_store::slot_for` maps TID → task-pool slot. Identity-ish mapping is
/// enough for the port tests: distinct TIDs get distinct slots.
pub fn idx_for_tid(tid: u32) -> Option<usize> {
    if tid == 0 || tid as usize >= task::MAX_TASKS {
        return None;
    }
    Some(tid as usize)
}

/// Publish `tid` at `slot`. This shim is identity-mapped, so the only binding
/// it can honour is `slot == tid`, and that one needs no state. It exists
/// because `crates/core/ipc/src/endpoint.rs`'s suite binds its fixed TIDs
/// explicitly: `tests/host/topology-tests` mounts the same file over a shim
/// that resolves only bound TIDs.
pub fn shim_bind(tid: u32, slot: usize) {
    assert_eq!(tid as usize, slot, "identity-mapped shim: slot must equal tid");
}

// ── Port wakes ────────────────────────────────────────────
//
// Kept outside `FakeSched` on purpose: its own record and reset, so
// `shim_reset()` is unchanged. `port.rs` wakes each registered waiter
// it detaches through `wait::wake_port_waiter(tid, port_ref)`; the record keeps
// both the addressee and the exact `WaitReason::Port` value (the port's packed
// `(index, generation)` reference) its predicate matches.

static PORT_WAITER_WAKES: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());

/// `(tid, port_ref)` pairs passed to `wait::wake_port_waiter`, in order.
pub fn shim_port_waiter_wakes() -> Vec<(u32, u32)> {
    PORT_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The scheduler's wake attribution (`azos_sched::wake_irq_enter`): the line
/// of the delivery in flight, as the last `irq_dispatch` announced it.
static WAKE_IRQ: Mutex<Option<u32>> = Mutex::new(None);
/// `(tid, line)` of each port wake made while a line's delivery was in flight.
static IRQ_WAKES: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());

pub fn wake_irq_enter(line: u32) {
    *WAKE_IRQ.lock().unwrap_or_else(|e| e.into_inner()) = Some(line);
}

pub fn wake_irq_leave() {
    *WAKE_IRQ.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// The line announced and not yet left; `None` outside a delivery.
pub fn shim_wake_irq_in_flight() -> Option<u32> {
    *WAKE_IRQ.lock().unwrap_or_else(|e| e.into_inner())
}

/// `(tid, line)` of the wakes a delivery made while its line was announced.
pub fn shim_irq_wakes() -> Vec<(u32, u32)> {
    IRQ_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Forget the recorded port wakes, both kinds, and the lines they were made under.
pub fn shim_reset_port_wakes() {
    PORT_WAITER_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    PORT_TIMED_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    IRQ_WAKES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    *WAKE_IRQ.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn note_irq_wake(tid: u32) {
    if let Some(line) = *WAKE_IRQ.lock().unwrap_or_else(|e| e.into_inner()) {
        IRQ_WAKES.lock().unwrap_or_else(|e| e.into_inner()).push((tid, line));
    }
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
    pub fn any_groups() -> bool { false }
    pub fn proc_of(_idx: usize, tid: u32) -> u32 { tid }
    pub fn proc_tid(tid: u32) -> u32 { tid }
    pub fn live_members(_leader: u32) -> u32 { 1 }
    pub fn current_group_ending() -> bool { false }
    pub fn set_current_clear_tid(_addr: u64) {}
    pub struct MmGuard;
    pub fn mm_lock() -> MmGuard { MmGuard }
}

/// D2 (domains): every task is its own domain here, and its capability table
/// is the one at its pool slot, so the table index a test sees is the slot.
/// This shim is identity-mapped (TID == slot), so the TID is the generation.
pub fn task_domain(idx: usize) -> u32 {
    ((idx as u32 & 0xFFFF).max(1) << 16) | idx as u32
}

/// D2: no task shares a domain in this world.
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

/// N4 shim: the running task's pool slot and TID (`azos_sched::current_task_slot`).
pub fn current_task_slot() -> Option<(usize, u32)> {
    let tid = current_task_tid();
    idx_for_tid(tid).map(|i| (i, tid))
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Scheduling policies — RFC-0004.
//!
//! Each policy is a self-contained module implementing the [`Policy`]
//! trait. The Adaptive Partitioning combinator
//! (`super::partitions::Aps`) selects a class; that class's policy
//! then picks the next runnable task within the class.
//!
//! ## Design notes
//!
//! - All policies use **bounded** queues (no `alloc`); the maximum
//!   number of runnable tasks per class is set at compile time.
//! - All time math is **integer microseconds**; no floats. This keeps
//!   us cert-safe (no FPU state in the safety scheduler path) and
//!   lets us run on harts without floating-point.
//! - Tasks are referenced by `tid: u32`. Per-task scheduler-relevant
//!   metadata (deadline, priority, time-slice remainder) lives in
//!   `super::task::Task`.

pub mod cfs;
pub mod edf_cbs;
pub mod fifo;
pub mod null;
pub mod rr;
pub mod sporadic;

use crate::class::SchedClass;
use cfs::Cfs;
use edf_cbs::EdfCbs;
use fifo::Fifo;
use rr::RoundRobin;
use sporadic::Sporadic;

/// Sum of every policy's `CAPACITY`. Bounds the stale-entry retry loop in
/// `scheduler::aps_pick_ready` (U02-1 fix): each retry either returns a
/// validated pick or drops exactly one entry from exactly one policy, so no
/// more than this many retries can ever be needed to drain every policy's
/// runqueue empty.
pub const TOTAL_CAPACITY: usize = fifo::FIFO_CAPACITY
    + edf_cbs::EDF_CAPACITY
    + rr::RR_CAPACITY
    + cfs::CFS_CAPACITY
    + sporadic::SPORADIC_CAPACITY;

/// Per-task metadata that policies consume. The scheduler maintains
/// this in the `Task` struct (W4.4 will extend `Task` with these
/// fields); for the standalone-policy unit tests we pass an explicit
/// `TaskMeta` instance.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TaskMeta {
    /// The task's unique identifier.
    pub tid: u32,
    /// Class assignment (from CAPS.TOML / SCHED.TOML).
    pub class: SchedClass,
    /// Static priority within the class (0 = highest, 31 = lowest).
    pub priority: u8,
    /// Earliest deadline in monotonic microseconds (only used by EDF).
    /// `None` ⇒ no deadline (the policy treats this as "lowest urgency"
    /// for EDF-class tasks; for non-EDF policies the field is ignored).
    pub deadline_us: Option<u64>,
    /// Time-slice quantum in microseconds (only used by RR).
    pub time_slice_us: u32,
    /// Virtual runtime in microseconds (only used by CFS).
    pub vruntime_us: u64,
}

impl TaskMeta {
    /// Construct a new metadata struct with all the optional fields
    /// at default values.
    pub const fn new(tid: u32, class: SchedClass, priority: u8) -> Self {
        Self {
            tid,
            class,
            priority,
            deadline_us: None,
            time_slice_us: 0,
            vruntime_us: 0,
        }
    }
}

/// Common interface implemented by every scheduling policy.
///
/// Policies are stateful (each owns its runqueue). The kernel holds
/// one instance of each policy per CPU; tasks register / deregister as
/// they become runnable / blocked.
pub trait Policy {
    /// Maximum tasks this policy can hold simultaneously. Static so
    /// the runqueue can be a fixed array.
    const CAPACITY: usize;

    /// Insert a runnable task. Returns `Err(meta)` echoing the input
    /// if the runqueue is full.
    fn enqueue(&mut self, meta: TaskMeta) -> Result<(), TaskMeta>;

    /// Remove `tid` from the runqueue. No-op if not present.
    fn dequeue(&mut self, tid: u32) -> Option<TaskMeta>;

    /// Pick the next task to run. `now_us` is the current monotonic
    /// time. Returns `None` if the runqueue is empty.
    fn pick_next(&mut self, now_us: u64) -> Option<TaskMeta>;

    /// Number of runnable tasks currently in this policy's runqueue.
    fn len(&self) -> usize;

    /// Convenience: `true` iff `len() == 0`.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Notify the policy that `dt_us` microseconds have elapsed since
    /// the last tick (called from the timer ISR). Default impl is a
    /// no-op; only RR / CFS override.
    fn tick(&mut self, _tid_running: u32, _dt_us: u32) {}

    /// Refill any per-period capacity bucket at a replenishment
    /// boundary (U02-1: driven by `Aps::tick`'s window roll-over).
    /// Default impl is a no-op; only `Sporadic` overrides.
    fn replenish(&mut self) {}
}

/// Innovation (audit axis 9): the enum-dispatch policy table.
///
/// Before this, `aps_state::CpuSchedV2` held one named field per policy
/// and every operation (`enqueue_task_for_class`, `dequeue_task_for_class`,
/// `pick_next`, `account`) was its own hand-written `match class { ... }`
/// scattered across that file — 22 `SchedClass::` matches in one 248-line
/// file, and adding a policy meant editing every one of them plus
/// `class.rs`, `runtime/registry.rs`, Kconfig, and the source-text test
/// asserts (U02-2). `Backend` collapses all of that into ONE `match` per
/// trait method, defined ONCE, here — `aps_state` and `scheduler::
/// do_schedule` (via `aps_state::pick_next`/`account`) both consume a
/// `[Backend; SchedClass::COUNT]` uniformly and never match on `SchedClass`
/// to reach a policy again.
///
/// **No `dyn`.** `lto = false` means an unreached `dyn Policy` vtable slot
/// is not free the way it would be with LTO — see the audit's own
/// reasoning. An enum big enough to hold the largest variant costs a
/// fixed, known size and one indirection-free `match` per call; that is
/// the trade this project's build config already made for `TaskState`,
/// `WaitReason`, etc.
///
/// **What this does NOT achieve: a policy added from OUTSIDE this crate
/// with zero edits here.** A closed `enum` cannot gain a variant from a
/// downstream crate — that is a `dyn`-shaped problem this design
/// deliberately opted out of. What it DOES achieve, verified by
/// `policies::null::Null` (a trivial always-empty policy added entirely
/// within this file) and the `sched-policy-tests` proof next to it:
/// adding a real policy touches **this file alone** — one new
/// `policies/<name>.rs`, one `Backend` variant, one arm in each of the
/// six delegating methods below, and (if it becomes a class's default)
/// one line in `default_table`. Zero edits to `aps_state.rs`,
/// `scheduler.rs`, `class.rs`, or `runtime/registry.rs` — those used to
/// be 4 of the 8-9 files U02-2 counted.
#[allow(clippy::large_enum_variant)]
pub enum Backend {
    Fifo(Fifo),
    EdfCbs(EdfCbs),
    RoundRobin(RoundRobin),
    Cfs(Cfs),
    Sporadic(Sporadic),
    /// Proof-of-extension variant (see this enum's doc). Not used by
    /// [`default_table`]; `sched-policy-tests` swaps a class onto it to
    /// prove the table, not the dispatcher, is what changes.
    Null(null::Null),
}

impl Policy for Backend {
    // Not load-bearing (`grep -rn "::CAPACITY" crates/core/sched` has no
    // generic consumer): each variant's `enqueue` still enforces its OWN
    // concrete `CAPACITY` internally, so a caller relying on `Err` for
    // "full" is unaffected by this associated const's value. Set to the
    // largest variant's capacity as the least-surprising single number.
    const CAPACITY: usize = fifo::FIFO_CAPACITY;

    fn enqueue(&mut self, meta: TaskMeta) -> Result<(), TaskMeta> {
        match self {
            Backend::Fifo(p) => p.enqueue(meta),
            Backend::EdfCbs(p) => p.enqueue(meta),
            Backend::RoundRobin(p) => p.enqueue(meta),
            Backend::Cfs(p) => p.enqueue(meta),
            Backend::Sporadic(p) => p.enqueue(meta),
            Backend::Null(p) => p.enqueue(meta),
        }
    }

    fn dequeue(&mut self, tid: u32) -> Option<TaskMeta> {
        match self {
            Backend::Fifo(p) => p.dequeue(tid),
            Backend::EdfCbs(p) => p.dequeue(tid),
            Backend::RoundRobin(p) => p.dequeue(tid),
            Backend::Cfs(p) => p.dequeue(tid),
            Backend::Sporadic(p) => p.dequeue(tid),
            Backend::Null(p) => p.dequeue(tid),
        }
    }

    fn pick_next(&mut self, now_us: u64) -> Option<TaskMeta> {
        match self {
            Backend::Fifo(p) => p.pick_next(now_us),
            Backend::EdfCbs(p) => p.pick_next(now_us),
            Backend::RoundRobin(p) => p.pick_next(now_us),
            Backend::Cfs(p) => p.pick_next(now_us),
            Backend::Sporadic(p) => p.pick_next(now_us),
            Backend::Null(p) => p.pick_next(now_us),
        }
    }

    fn len(&self) -> usize {
        match self {
            Backend::Fifo(p) => p.len(),
            Backend::EdfCbs(p) => p.len(),
            Backend::RoundRobin(p) => p.len(),
            Backend::Cfs(p) => p.len(),
            Backend::Sporadic(p) => p.len(),
            Backend::Null(p) => p.len(),
        }
    }

    fn tick(&mut self, tid_running: u32, dt_us: u32) {
        match self {
            Backend::Fifo(p) => p.tick(tid_running, dt_us),
            Backend::EdfCbs(p) => p.tick(tid_running, dt_us),
            Backend::RoundRobin(p) => p.tick(tid_running, dt_us),
            Backend::Cfs(p) => p.tick(tid_running, dt_us),
            Backend::Sporadic(p) => p.tick(tid_running, dt_us),
            Backend::Null(p) => p.tick(tid_running, dt_us),
        }
    }

    fn replenish(&mut self) {
        match self {
            Backend::Fifo(p) => p.replenish(),
            Backend::EdfCbs(p) => p.replenish(),
            Backend::RoundRobin(p) => p.replenish(),
            Backend::Cfs(p) => p.replenish(),
            Backend::Sporadic(p) => p.replenish(),
            Backend::Null(p) => p.replenish(),
        }
    }
}

/// RFC-0004's reference class→policy assignment, as a table instead of
/// five named struct fields. Reassigning a class to a DIFFERENT existing
/// policy is exactly one line here — see
/// `sched-policy-tests::backend_table_tests::idle_can_be_reassigned_to_fifo`
/// for the zero-other-edits proof.
pub const fn default_table() -> [Backend; SchedClass::COUNT] {
    [
        Backend::Fifo(Fifo::new()),
        Backend::EdfCbs(EdfCbs::new()),
        Backend::RoundRobin(RoundRobin::new()),
        Backend::Cfs(Cfs::new()),
        Backend::Sporadic(Sporadic::new()),
    ]
}

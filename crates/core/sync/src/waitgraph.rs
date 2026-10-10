// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The wait graph (wave 15 N7): one priority-inheritance core for every
//! object a task can block on while another task owns it.
//!
//! **Interface only.** The bodies are `todo!()`; front N7 implements them.
//! Nothing calls into this module while Kconfig `WAIT_GRAPH` is n (the
//! default until N7 lands): [`ENABLED`] is a compile-time `false`, and every
//! client tests it before taking the graph path.
//!
//! # Model (SCHED-SYNC §2.4, owner answer Q4)
//!
//! * A task is blocked on at most one object: the scheduler's frozen field
//!   `blocked_on` (N6a) holds an `Option<`[`WaitObj`]`>`.
//! * Each object embeds a [`PiWaiters`]: its owner and its waiters ordered by
//!   effective attribute ([`PiAttr`]), most urgent first. Each owner keeps
//!   the set of objects it owns that have waiters (the graph's per-task
//!   state, not a scheduler field).
//! * The **effective attribute** of a task is the most urgent of its base
//!   attribute and the top waiter of every object it owns.
//! * Edge kinds ([`EdgeKind`]): kernel mutex (N8), PI futex (N10), IPC call
//!   (L9), lease (RFC-0031) and user-driver proxy. A new client adds a
//!   variant; the walk does not change.
//!
//! **Stage 1 (this interface):** classic PI. The owner runs on its own
//! scheduling context, boosted to the effective attribute; a DL donor makes
//! the owner inherit the donor's absolute deadline ([`PiAttr::Dl`]).
//! **Stage 2 (later, L9):** proxy execution, the donor's SC pays. Stage 2
//! changes only the scheduler's pick, never this API.
//!
//! # The walk
//!
//! A block, an unblock, a release and an attribute change start a chain
//! walk at the affected owner: recompute its effective attribute; if it
//! changed and the owner is itself blocked, re-sort it in that object's
//! waiters and continue at that object's owner. The walk stops when nothing
//! changes, at a task that is not blocked, or after [`PI_MAX_DEPTH`] steps.
//!
//! * **Cycle** (the walk reaches the task that started it, or an object it
//!   already visited): [`WaitError::Deadlock`] (`EDEADLK`), and the blocking
//!   call is undone before returning. lockdep builds also record the cycle.
//! * **Depth cap** reached: boosting stops there (decision log, Q4: "at max
//!   depth stop boosting"); the block itself succeeds and the cap is
//!   counted ([`stats`]). Owner question recorded in INTERFACES.md: the Q4
//!   table row says `EDEADLK` at the cap, the decision log says stop.
//!
//! # Lock order and context
//!
//! `PiWaiters` wait lock -> the owner's per-task PI lock (graph-owned) ->
//! the run-queue lock (inside [`SchedPi`] calls). Each lock is dropped
//! before the next step takes the next object's wait lock (Linux rt_mutex
//! pattern; illumos-style trylock-and-restart when a step would invert the
//! order). Task references stay valid across the drops because the walk runs
//! inside a QSBR read section (`qsbr::read`): a task slot is reused only
//! after a grace period. Every entry point below is **task context only**
//! (never an interrupt handler, never with interrupts off).
//!
//! **One rule for SpinLocks around a walk:** a walk may run with at most ONE
//! client SpinLock held, the object's own (a futex bucket lock, an endpoint
//! lock), never two, never another object's wait lock. A client that wants
//! the walk outside its lock uses `block_prepare` under it and
//! `block_commit` after dropping it.
//!
//! # Priority convention
//!
//! As everywhere in the scheduler, a lower RT priority **number** is more
//! urgent. [`PiAttr`]'s `Ord` hides this: `a > b` means `a` is more urgent.

use core::ptr::NonNull;

/// Kconfig `WAIT_GRAPH`: the graph is compiled into the lock paths. n: every
/// client keeps its pre-N7 path and nothing here is reached.
pub const ENABLED: bool = azos_limits::WAIT_GRAPH;

/// Kconfig `PI_MAX_DEPTH` (Q4: 16): the longest chain a walk follows. Bounds
/// the cost of every block/unblock to `PI_MAX_DEPTH` steps.
pub const PI_MAX_DEPTH: usize = azos_limits::PI_MAX_DEPTH;

/// A task as the scheduler names it: its slot index, `< MAX_TASKS`. The
/// same number `PiMutex` and lockdep use.
pub type TaskId = u32;

/// What kind of object a task is blocked on. Part of [`PiWaiters`]; the
/// walk treats every kind the same, a client only adds a variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EdgeKind {
    /// `kmutex::Mutex` (N8).
    Mutex = 1,
    /// A PI futex's `pi_state` (N10).
    FutexPi = 2,
    /// A call blocked on an endpoint's server (L9; today PIFAST donation).
    IpcCall = 3,
    /// A lease held by its lessee (RFC-0031 lease PI, migrated by N7).
    Lease = 4,
    /// A user-mode driver serving a kernel proxy request (migrated by N7).
    DriverProxy = 5,
}

/// A task's scheduling attribute as the graph compares it. The scheduler
/// (N6a) converts its SchedContext into this; the graph never reads the SC.
///
/// Order (most urgent first, the fixed class precedence of N6):
/// `Stop > Dl > Rt > Fair > Idle`; inside `Dl` the earlier absolute deadline
/// wins; inside `Rt` the lower priority number wins. `Fair` and `Idle` carry
/// nothing: a fair donor does not boost a fair owner (no weight
/// inheritance in stage 1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PiAttr {
    Idle,
    Fair,
    /// Real-time priority, lower number more urgent.
    Rt { prio: u8 },
    /// Deadline class, absolute deadline in nanoseconds of the monotonic
    /// clock. A boosted owner **inherits this deadline** (Q4 stage 1).
    Dl { deadline_ns: u64 },
    Stop,
}

impl PiAttr {
    const fn rank(self) -> u8 {
        match self {
            PiAttr::Idle => 0,
            PiAttr::Fair => 1,
            PiAttr::Rt { .. } => 2,
            PiAttr::Dl { .. } => 3,
            PiAttr::Stop => 4,
        }
    }

    /// The more urgent of `self` and `o` (the effective-attribute rule).
    #[inline]
    pub fn max_urgent(self, o: PiAttr) -> PiAttr {
        if o > self { o } else { self }
    }
}

impl Ord for PiAttr {
    /// `a > b` iff `a` is more urgent than `b`.
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        match self.rank().cmp(&o.rank()) {
            Ordering::Equal => match (*self, *o) {
                (PiAttr::Rt { prio: a }, PiAttr::Rt { prio: b }) => b.cmp(&a),
                (PiAttr::Dl { deadline_ns: a }, PiAttr::Dl { deadline_ns: b }) => b.cmp(&a),
                _ => Ordering::Equal,
            },
            r => r,
        }
    }
}

impl PartialOrd for PiAttr {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// The waiter side of one blockable object. Embedded in the object (a
/// `Mutex`, a futex `pi_state`, an endpoint's call record, a lease); the
/// graph owns its contents.
///
/// Layout is private to N7 and may change; the contract is: `const`
/// constructible, at most 32 bytes, no allocation, and an object with
/// waiters or named by any task's `blocked_on` is not freed (an object that
/// can be freed retires through `call_rcu`, so a walk in its read section
/// never sees freed memory).
pub struct PiWaiters {
    kind: EdgeKind,
    _state: [u32; 6],
}

impl PiWaiters {
    /// An object of `kind` with no owner and no waiters.
    pub const fn new(kind: EdgeKind) -> Self {
        PiWaiters { kind, _state: [0; 6] }
    }

    /// The kind given at construction.
    pub fn kind(&self) -> EdgeKind {
        self.kind
    }

    /// The owner, if any. Lock-free relaxed read: a hint for adaptive
    /// spinning and diagnostics; decisions are taken under the wait lock.
    /// Any context. O(1).
    pub fn owner(&self) -> Option<TaskId> {
        todo!("N7")
    }

    /// The client records a new owner (lock acquired, futex word taken over,
    /// call accepted by a server, lease granted) or none. Re-attaches the
    /// object's waiters to the new owner's PI set and walks from both the old
    /// and the new owner. Task context; the caller may hold its own object
    /// SpinLock (futex bucket lock) but no other wait lock. Cost: one walk
    /// per changed owner, O(PI_MAX_DEPTH).
    pub fn set_owner(&self, _owner: Option<TaskId>) {
        todo!("N7")
    }

    /// True when at least one task is enqueued. Any context. O(1).
    pub fn has_waiters(&self) -> bool {
        todo!("N7")
    }
}

/// A handle to a [`PiWaiters`]: what a task's `blocked_on` holds.
/// Comparison is identity. Valid while the task is enqueued (see the
/// lifetime contract on `PiWaiters`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WaitObj(NonNull<PiWaiters>);

// SAFETY: a `WaitObj` is an address compared and dereferenced only under the
// graph's protocol (wait lock + QSBR read section); it owns nothing.
unsafe impl Send for WaitObj {}
unsafe impl Sync for WaitObj {}

impl WaitObj {
    pub fn of(w: &PiWaiters) -> Self {
        WaitObj(NonNull::from(w))
    }

    /// The object's address, for lockdep reports and traces.
    pub fn addr(self) -> usize {
        self.0.as_ptr() as usize
    }
}

/// Why a walk refused or undid a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitError {
    /// The block would close a cycle: `EDEADLK` (Linux errno 35).
    Deadlock,
    /// The object has no owner any more (released between the client's
    /// check and the enqueue): retry the acquire. Not an error to user space.
    NoOwner,
    /// `waiter` is the owner (recursive acquire): `EDEADLK` for a PI futex,
    /// a kernel bug (panic in debug builds) for a kernel mutex.
    SelfOwned,
}

impl WaitError {
    /// The Linux errno a system call returns for this error (negated by the
    /// caller). `NoOwner` never reaches user space.
    pub const fn errno(self) -> i32 {
        match self {
            WaitError::Deadlock | WaitError::SelfOwned => 35,
            WaitError::NoOwner => 11,
        }
    }
}

/// Why a waiter leaves an object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnblockReason {
    /// It became the owner.
    Acquired,
    /// Its timeout expired.
    Timeout,
    /// A signal or a kill interrupted the wait.
    Interrupted,
    /// The object went away (owner died with `FUTEX_OWNER_DIED` handled by
    /// the client, endpoint revoked, lease revoked).
    ObjectGone,
}

/// The scheduler's side of PI. **Implemented by N6a's class code**
/// (crates/core/sched), registered once at boot with [`register_sched`];
/// the graph calls nothing else in the scheduler.
///
/// Every method is called with the graph's per-task PI lock of `t` held and
/// may take the run-queue lock of `t`'s CPU (the innermost lock). None may
/// sleep, block, or call back into the graph. Each must be O(1) apart from
/// the run-queue re-sort its class does anyway.
pub trait SchedPi: Sync {
    /// `t`'s own attribute from its SchedContext, ignoring any boost.
    fn base_attr(&self, t: TaskId) -> PiAttr;

    /// Raise `t` to `to` (strictly more urgent than its current effective
    /// attribute). If `t` is queued, the class re-queues it at the new
    /// position; if it runs on another CPU, that CPU is asked to reschedule.
    /// A `Dl` value installs the donor's absolute deadline on `t` (stage 1,
    /// `t` still burns its own budget).
    fn boost(&self, t: TaskId, to: PiAttr);

    /// Lower `t` to `to` (its base attribute, or a smaller remaining boost).
    /// Same re-queue duty as `boost`; may set need-resched on `t`'s CPU.
    fn unboost(&self, t: TaskId, to: PiAttr);

    /// Write the frozen `blocked_on` field (N6a). `Some` before the waiter
    /// sleeps, `None` after it leaves the object.
    fn set_blocked_on(&self, t: TaskId, on: Option<WaitObj>);

    /// Read `blocked_on`.
    fn blocked_on(&self, t: TaskId) -> Option<WaitObj>;

    /// The frozen `on_cpu` field: `t` is executing right now on some CPU.
    /// Read lock-free by adaptive spinning (N8); may be stale by one switch.
    fn on_cpu(&self, t: TaskId) -> bool;
}

/// Install the scheduler's hooks. Called once by the scheduler's init,
/// before the first task can block; a second call panics. Task context.
pub fn register_sched(_hooks: &'static dyn SchedPi) {
    todo!("N7")
}

/// `waiter` (the current task) blocks on `obj`, owned by someone else:
/// enqueue it by its effective attribute, set its `blocked_on`, and walk
/// from the owner boosting along the chain. The caller sleeps afterwards
/// (it owns the sleep, the wake and the timeout) and calls [`unblock`] when
/// it wakes for any reason.
///
/// Task context, preemption on; at most the object's own client SpinLock
/// held (the module's one rule); the caller's sleep needs none (`might_sleep`).
/// Cost: O(W) enqueue (W = waiters on `obj`) + one walk, O(PI_MAX_DEPTH).
/// On `Err` nothing was changed: not enqueued, `blocked_on` still `None`.
pub fn block_on(waiter: TaskId, obj: &PiWaiters) -> Result<(), WaitError> {
    let pending = block_prepare(waiter, obj)?;
    block_commit(pending)
}

/// First half of [`block_on`] for clients that must enqueue under their own
/// SpinLock (a futex bucket, an endpoint lock) so that a wake cannot slip
/// between the check and the enqueue: enqueue and set `blocked_on`, no walk.
/// **May be called with one client SpinLock held.** O(W).
pub fn block_prepare(_waiter: TaskId, _obj: &PiWaiters) -> Result<PendingBlock, WaitError> {
    todo!("N7")
}

/// Second half of [`block_on`]: the walk. Called before the waiter sleeps,
/// normally after the client dropped its SpinLock (at most the object's own
/// client lock may still be held, the module's one rule). On
/// `Err(Deadlock)` the waiter has been dequeued again. O(PI_MAX_DEPTH).
pub fn block_commit(_p: PendingBlock) -> Result<(), WaitError> {
    todo!("N7")
}

/// A block enqueued by [`block_prepare`] and not yet walked. Must be passed
/// to [`block_commit`]; dropping it unwalked leaves the owner unboosted, so
/// the type is `#[must_use]`.
#[must_use]
pub struct PendingBlock {
    pub waiter: TaskId,
    pub obj: WaitObj,
}

/// `waiter` leaves `obj` (`why`): dequeue, clear `blocked_on`, and walk from
/// the owner lowering the boost it no longer earns. Called by the waiter
/// itself after it wakes, or by the waker on its behalf (timeout and signal
/// paths). Task context; at most the object's own client SpinLock held (the
/// module's one rule). O(W + PI_MAX_DEPTH).
pub fn unblock(_waiter: TaskId, _obj: &PiWaiters, _why: UnblockReason) {
    todo!("N7")
}

/// The owner gives `obj` up: clears its PI contribution from `obj`, unboosts
/// the owner, and returns the top waiter (the client wakes it; the client,
/// not the graph, decides whether it hands ownership over or lets the
/// woken waiter compete). Task context; at most the object's own client
/// SpinLock held (the module's one rule). O(owned objects with waiters) for
/// the unboost plus one walk.
pub fn release(_owner: TaskId, _obj: &PiWaiters) -> Option<TaskId> {
    todo!("N7")
}

/// The most urgent waiter of `obj` and its effective attribute. Any
/// context except an interrupt handler; takes `obj`'s wait lock. O(1).
pub fn top_waiter(_obj: &PiWaiters) -> Option<(TaskId, PiAttr)> {
    todo!("N7")
}

/// The scheduler changed `t`'s base attribute (`sched_setattr`, `schedctl`,
/// a DL replenishment that moved the deadline): re-sort `t` where it waits
/// and walk. Called by N6a without any run-queue lock held. O(depth).
pub fn attr_changed(_t: TaskId) {
    todo!("N7")
}

/// `t` is exiting: it must own nothing with waiters (each client released
/// its objects first: robust futexes through the robust list, mutexes are a
/// kernel bug, leases through revoke). Debug builds verify and panic.
pub fn task_exit(_t: TaskId) {
    todo!("N7")
}

/// Counters for vsbench and ktest: walks, total steps, depth-cap hits,
/// deadlocks refused. Relaxed reads.
pub fn stats() -> WalkStats {
    todo!("N7")
}

#[derive(Clone, Copy, Default, Debug)]
pub struct WalkStats {
    pub walks: u64,
    pub steps: u64,
    pub depth_capped: u64,
    pub deadlocks: u64,
}

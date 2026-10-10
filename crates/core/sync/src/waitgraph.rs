// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The wait graph (wave 15 N7): one priority-inheritance core for every
//! object a task can block on while another task owns it.
//!
//! Stage 1, implemented by N7 ([`Graph`]). Nothing calls into this module
//! while Kconfig `WAIT_GRAPH` is n (the default): [`ENABLED`] is a
//! compile-time `false`, every client tests it before taking the graph
//! path, and the kernel's graph then has zero slots.
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
//! after a grace period. **Stage 1 implements this with one graph lock**
//! held across the whole operation (see [`Graph`]): the same order with the
//! first two locks fused, no drops, so no restart is needed yet. Every entry
//! point below is **task context only**
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
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::spinlock::SpinLock;

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

/// "No task" in the slot fields of [`PiWaiters`] and the graph's links.
const NONE: u32 = u32::MAX;

/// The waiter side of one blockable object. Embedded in the object (a
/// `Mutex`, a futex `pi_state`, an endpoint's call record, a lease); the
/// graph owns its contents.
///
/// Layout is private to N7 and may change; the contract is: `const`
/// constructible, at most 32 bytes, no allocation, and an object with
/// waiters or named by any task's `blocked_on` is not freed (an object that
/// can be freed retires through `call_rcu`, so a walk in its read section
/// never sees freed memory).
///
/// Every field is written only under the graph lock; the atomics let
/// [`owner`](Self::owner) and [`has_waiters`](Self::has_waiters) read
/// without it.
pub struct PiWaiters {
    kind: EdgeKind,
    /// Owner slot, [`NONE`] = none.
    owner: AtomicU32,
    /// First (most urgent) waiter, [`NONE`] = no waiter. The rest are
    /// linked through the graph's per-task `next` array, most urgent first,
    /// FIFO among equals.
    head: AtomicU32,
    /// Number of waiters.
    count: AtomicU32,
    /// Next object in the owner's set of owned objects with waiters
    /// (address, 0 = end). Linked iff `owner` and `head` are both set.
    next_owned: AtomicUsize,
}

impl PiWaiters {
    /// An object of `kind` with no owner and no waiters.
    pub const fn new(kind: EdgeKind) -> Self {
        PiWaiters {
            kind,
            owner: AtomicU32::new(NONE),
            head: AtomicU32::new(NONE),
            count: AtomicU32::new(0),
            next_owned: AtomicUsize::new(0),
        }
    }

    /// The kind given at construction.
    pub fn kind(&self) -> EdgeKind {
        self.kind
    }

    /// The owner, if any. Lock-free relaxed read: a hint for adaptive
    /// spinning and diagnostics; decisions are taken under the wait lock.
    /// Any context. O(1).
    pub fn owner(&self) -> Option<TaskId> {
        slot(self.owner.load(Ordering::Relaxed))
    }

    /// The client records a new owner (lock acquired, futex word taken over,
    /// call accepted by a server, lease granted) or none. Re-attaches the
    /// object's waiters to the new owner's PI set and walks from both the old
    /// and the new owner. Task context; the caller may hold its own object
    /// SpinLock (futex bucket lock) but no other wait lock. Cost: one walk
    /// per changed owner, O(PI_MAX_DEPTH).
    pub fn set_owner(&self, owner: Option<TaskId>) {
        GRAPH.set_owner(self, owner)
    }

    /// True when at least one task is enqueued. Any context. O(1).
    pub fn has_waiters(&self) -> bool {
        self.head.load(Ordering::Relaxed) != NONE
    }

    fn linked(&self) -> bool {
        self.owner.load(Ordering::Relaxed) != NONE && self.head.load(Ordering::Relaxed) != NONE
    }
}

#[inline]
fn slot(raw: u32) -> Option<TaskId> {
    (raw != NONE).then_some(raw)
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

    /// The object's address, for lockdep reports and traces, and what the
    /// scheduler's `blocked_on` field stores.
    pub fn addr(self) -> usize {
        self.0.as_ptr() as usize
    }

    /// The inverse of [`addr`](Self::addr): `0` is `None`. Only for an
    /// address `addr` produced (the scheduler's `blocked_on` field).
    pub fn from_addr(addr: usize) -> Option<WaitObj> {
        NonNull::new(addr as *mut PiWaiters).map(WaitObj)
    }

    /// SAFETY: the object outlives every `blocked_on` naming it and every
    /// owned set linking it (the `PiWaiters` lifetime contract); called only
    /// under the graph lock.
    unsafe fn get<'a>(self) -> &'a PiWaiters {
        unsafe { &*self.0.as_ptr() }
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

/// `canary=pi-depth-1`: every walk stops after this many steps instead of
/// [`PI_MAX_DEPTH`]. 0 = no override.
static DEPTH_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

/// Arm the depth canary (boot, once): walks follow one owner only, so a
/// transitive chain is not boosted past its first link (ktest
/// `waitgraph_transitive_chain` goes red).
/// `0` disarms it (host tests).
pub fn canary_cap_depth(depth: usize) {
    DEPTH_OVERRIDE.store(depth, Ordering::Relaxed);
}

fn depth_cap() -> usize {
    match DEPTH_OVERRIDE.load(Ordering::Relaxed) {
        0 => PI_MAX_DEPTH,
        d => d.min(PI_MAX_DEPTH),
    }
}

/// The per-task state of a graph, `N` slots. Graph-owned, never a
/// scheduler field.
struct State<const N: usize> {
    hooks: Option<&'static dyn SchedPi>,
    /// The effective attribute last computed for the task (`None`: never
    /// computed since its slot was (re)used; its base attribute stands).
    eff: [Option<PiAttr>; N],
    /// Next waiter on the object the task waits on, [`NONE`] = last.
    next: [u32; N],
    /// First object of the task's owned set (address, 0 = empty).
    owned: [usize; N],
}

/// One wait graph over `N` task slots.
///
/// **Stage 1 locking.** One graph lock (a SpinLock taken with interrupts
/// saved off) serialises every mutation: the object's waiter list, the
/// per-task effective attribute and owned set, and the walk. It stands in
/// for the per-object wait lock + per-task PI lock pair of the contract and
/// keeps its order (graph lock -> the scheduler's donation lock -> run-queue
/// lock, inside [`SchedPi`]); task references stay valid because a slot is
/// not reused while it is linked in the graph (`task_exit`). The split into
/// per-object locks with trylock-and-restart is a later step that does not
/// change this API.
///
/// The kernel has one instance ([`GRAPH`], sized by `WAIT_GRAPH`); ktests
/// and host tests build their own with a recording [`SchedPi`].
pub struct Graph<const N: usize> {
    st: SpinLock<State<N>>,
    walks: AtomicU64,
    steps: AtomicU64,
    depth_capped: AtomicU64,
    deadlocks: AtomicU64,
}

/// The kernel's graph: `MAX_TASKS` slots with `WAIT_GRAPH`, none without
/// (nothing reaches it then, and it costs no `.bss`).
const SLOTS: usize = if ENABLED { azos_limits::MAX_TASKS } else { 0 };
static GRAPH: Graph<SLOTS> = Graph::new();

impl<const N: usize> Default for Graph<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Graph<N> {
    pub const fn new() -> Self {
        Graph {
            st: SpinLock::new(State { hooks: None, eff: [None; N], next: [NONE; N], owned: [0; N] }),
            walks: AtomicU64::new(0),
            steps: AtomicU64::new(0),
            depth_capped: AtomicU64::new(0),
            deadlocks: AtomicU64::new(0),
        }
    }

    /// See [`register_sched`]. Panics on a second call.
    pub fn register_sched(&self, hooks: &'static dyn SchedPi) {
        let mut st = self.st.lock_irqsave();
        assert!(st.hooks.is_none(), "waitgraph: scheduler registered twice");
        st.hooks = Some(hooks);
    }

    /// See [`block_on`].
    pub fn block_on(&self, waiter: TaskId, obj: &PiWaiters) -> Result<(), WaitError> {
        let p = self.block_prepare(waiter, obj)?;
        self.block_commit(p)
    }

    /// See [`block_prepare`].
    pub fn block_prepare(&self, waiter: TaskId, obj: &PiWaiters) -> Result<PendingBlock, WaitError> {
        if waiter as usize >= N {
            return Err(WaitError::NoOwner);
        }
        let mut st = self.st.lock_irqsave();
        let h = hooks(&st);
        let owner = obj.owner.load(Ordering::Relaxed);
        if owner == NONE || owner as usize >= N {
            return Err(WaitError::NoOwner);
        }
        if owner == waiter {
            return Err(WaitError::SelfOwned);
        }
        debug_assert!(h.blocked_on(waiter).is_none(), "waitgraph: a task blocks on two objects");
        let e = st.compute_eff(h, waiter);
        st.eff[waiter as usize] = Some(e);
        let was_linked = obj.linked();
        st.insert(h, obj, waiter, e);
        h.set_blocked_on(waiter, Some(WaitObj::of(obj)));
        if !was_linked {
            st.link_owned(owner, obj);
        }
        Ok(PendingBlock { waiter, obj: WaitObj::of(obj) })
    }

    /// See [`block_commit`].
    pub fn block_commit(&self, p: PendingBlock) -> Result<(), WaitError> {
        let mut st = self.st.lock_irqsave();
        let h = hooks(&st);
        // SAFETY: `p.obj` is enqueued-on by `p.waiter` (the lifetime contract).
        let obj = unsafe { p.obj.get() };
        if h.blocked_on(p.waiter) != Some(p.obj) {
            // Unblocked (woken, timed out) between prepare and commit.
            return Ok(());
        }
        if st.closes_cycle(h, p.waiter, p.obj) {
            // Undo before any boost was applied: both tasks unchanged.
            st.dequeue(h, p.waiter, obj);
            self.deadlocks.fetch_add(1, Ordering::Relaxed);
            return Err(WaitError::Deadlock);
        }
        if let Some(owner) = obj.owner() {
            self.walk(&mut st, h, owner);
        }
        Ok(())
    }

    /// See [`unblock`].
    pub fn unblock(&self, waiter: TaskId, obj: &PiWaiters, _why: UnblockReason) {
        if waiter as usize >= N {
            return;
        }
        let mut st = self.st.lock_irqsave();
        let h = hooks(&st);
        st.dequeue(h, waiter, obj);
        if let Some(owner) = obj.owner() {
            self.walk(&mut st, h, owner);
        }
    }

    /// See [`release`].
    pub fn release(&self, owner: TaskId, obj: &PiWaiters) -> Option<TaskId> {
        let mut st = self.st.lock_irqsave();
        let h = hooks(&st);
        if obj.owner.load(Ordering::Relaxed) != owner {
            debug_assert!(false, "waitgraph: release by a task that is not the owner");
            return slot(obj.head.load(Ordering::Relaxed));
        }
        if obj.linked() {
            st.unlink_owned(owner, obj);
        }
        obj.owner.store(NONE, Ordering::Relaxed);
        if (owner as usize) < N {
            self.walk(&mut st, h, owner);
        }
        slot(obj.head.load(Ordering::Relaxed))
    }

    /// See [`PiWaiters::set_owner`].
    pub fn set_owner(&self, obj: &PiWaiters, owner: Option<TaskId>) {
        let new = match owner {
            Some(t) if (t as usize) < N => t,
            _ => NONE,
        };
        let mut st = self.st.lock_irqsave();
        let old = obj.owner.load(Ordering::Relaxed);
        if old == new {
            return;
        }
        if obj.linked() {
            st.unlink_owned(old, obj);
        }
        obj.owner.store(new, Ordering::Relaxed);
        if obj.linked() {
            st.link_owned(new, obj);
        }
        // Before registration nothing can be enqueued: no walk to run.
        let Some(h) = st.hooks else { return };
        if old != NONE {
            self.walk(&mut st, h, old);
        }
        if new != NONE {
            self.walk(&mut st, h, new);
        }
    }

    /// See [`top_waiter`].
    pub fn top_waiter(&self, obj: &PiWaiters) -> Option<(TaskId, PiAttr)> {
        let st = self.st.lock_irqsave();
        let t = slot(obj.head.load(Ordering::Relaxed))?;
        let h = st.hooks?;
        Some((t, st.eff_of(h, t)))
    }

    /// See [`attr_changed`]. A no-op before registration.
    pub fn attr_changed(&self, t: TaskId) {
        if t as usize >= N {
            return;
        }
        let mut st = self.st.lock_irqsave();
        let Some(h) = st.hooks else { return };
        // The scheduler may have written the new base over a live boost:
        // put the boost back first, then let the walk move the chain.
        let e = st.compute_eff(h, t);
        if e > h.base_attr(t) {
            h.boost(t, e);
        }
        self.walk(&mut st, h, t);
    }

    /// See [`task_exit`].
    pub fn task_exit(&self, t: TaskId) {
        if t as usize >= N {
            return;
        }
        let mut st = self.st.lock_irqsave();
        debug_assert!(st.owned[t as usize] == 0, "waitgraph: a task exits owning objects with waiters");
        st.eff[t as usize] = None;
        st.next[t as usize] = NONE;
    }

    /// The effective attribute the graph last computed for `t` (`None`:
    /// not in the graph, its base stands). For ktests and `schedctl`.
    pub fn effective(&self, t: TaskId) -> Option<PiAttr> {
        if t as usize >= N {
            return None;
        }
        self.st.lock_irqsave().eff[t as usize]
    }

    /// See [`stats`].
    pub fn stats(&self) -> WalkStats {
        WalkStats {
            walks: self.walks.load(Ordering::Relaxed),
            steps: self.steps.load(Ordering::Relaxed),
            depth_capped: self.depth_capped.load(Ordering::Relaxed),
            deadlocks: self.deadlocks.load(Ordering::Relaxed),
        }
    }

    /// The chain walk from `start`: recompute its effective attribute; if it
    /// moved, tell the scheduler, re-sort it where it waits and continue at
    /// that object's owner. Stops when nothing changes, at a task that is
    /// not blocked or an object without owner, or after the depth cap
    /// (counted). O(depth_cap) steps, each O(W + owned).
    fn walk(&self, st: &mut State<N>, h: &dyn SchedPi, start: TaskId) {
        self.walks.fetch_add(1, Ordering::Relaxed);
        let cap = depth_cap();
        let mut t = start;
        for _ in 0..cap {
            self.steps.fetch_add(1, Ordering::Relaxed);
            let old = st.eff_of(h, t);
            let new = st.compute_eff(h, t);
            st.eff[t as usize] = Some(new);
            if new == old {
                return;
            }
            // `boost` installs an attribute above the base, `unboost` goes
            // back towards it (the base itself may have moved: attr_changed).
            if new > h.base_attr(t) {
                h.boost(t, new);
            } else {
                h.unboost(t, new);
            }
            let Some(o) = h.blocked_on(t) else { return };
            // SAFETY: `t` is enqueued on `o` (the lifetime contract).
            let obj = unsafe { o.get() };
            if st.remove(obj, t) {
                st.insert(h, obj, t, new);
            }
            match obj.owner() {
                Some(next) if (next as usize) < N && next != start => t = next,
                _ => return,
            }
        }
        // Out of steps: counted only if the next owner had something left
        // to inherit (a chain exactly `cap` long is not capped).
        if st.compute_eff(h, t) != st.eff_of(h, t) {
            self.depth_capped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn hooks<const N: usize>(st: &State<N>) -> &'static dyn SchedPi {
    st.hooks.expect("waitgraph: used before register_sched")
}

impl<const N: usize> State<N> {
    fn eff_of(&self, h: &dyn SchedPi, t: TaskId) -> PiAttr {
        self.eff[t as usize].unwrap_or_else(|| h.base_attr(t))
    }

    /// max(base, the top waiter of every object `t` owns).
    fn compute_eff(&self, h: &dyn SchedPi, t: TaskId) -> PiAttr {
        let mut e = h.base_attr(t);
        let mut a = self.owned[t as usize];
        while let Some(o) = WaitObj::from_addr(a) {
            // SAFETY: linked objects are live (the lifetime contract).
            let obj = unsafe { o.get() };
            if let Some(w) = slot(obj.head.load(Ordering::Relaxed)) {
                e = e.max_urgent(self.eff_of(h, w));
            }
            a = obj.next_owned.load(Ordering::Relaxed);
        }
        e
    }

    /// Sorted insert: after every waiter at least as urgent (FIFO among
    /// equals). O(W).
    fn insert(&mut self, h: &dyn SchedPi, obj: &PiWaiters, t: TaskId, e: PiAttr) {
        let mut prev = NONE;
        let mut cur = obj.head.load(Ordering::Relaxed);
        while cur != NONE && self.eff_of(h, cur) >= e {
            prev = cur;
            cur = self.next[cur as usize];
        }
        self.next[t as usize] = cur;
        if prev == NONE {
            obj.head.store(t, Ordering::Relaxed);
        } else {
            self.next[prev as usize] = t;
        }
        obj.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Unlink `t` from `obj`'s waiters. O(W).
    fn remove(&mut self, obj: &PiWaiters, t: TaskId) -> bool {
        let mut prev = NONE;
        let mut cur = obj.head.load(Ordering::Relaxed);
        while cur != NONE && cur != t {
            prev = cur;
            cur = self.next[cur as usize];
        }
        if cur == NONE {
            return false;
        }
        let after = self.next[t as usize];
        if prev == NONE {
            obj.head.store(after, Ordering::Relaxed);
        } else {
            self.next[prev as usize] = after;
        }
        self.next[t as usize] = NONE;
        obj.count.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// `t` leaves `obj`: off its waiters, `blocked_on` cleared, and `obj`
    /// out of its owner's set if that was the last waiter. No walk.
    fn dequeue(&mut self, h: &dyn SchedPi, t: TaskId, obj: &PiWaiters) {
        let was_linked = obj.linked();
        self.remove(obj, t);
        if h.blocked_on(t) == Some(WaitObj::of(obj)) {
            h.set_blocked_on(t, None);
        }
        if was_linked && !obj.linked() {
            self.unlink_owned(obj.owner.load(Ordering::Relaxed), obj);
        }
    }

    fn link_owned(&mut self, owner: u32, obj: &PiWaiters) {
        if owner as usize >= N {
            return;
        }
        obj.next_owned.store(self.owned[owner as usize], Ordering::Relaxed);
        self.owned[owner as usize] = WaitObj::of(obj).addr();
    }

    /// O(objects `owner` owns with waiters).
    fn unlink_owned(&mut self, owner: u32, obj: &PiWaiters) {
        if owner as usize >= N {
            return;
        }
        let target = WaitObj::of(obj).addr();
        let after = obj.next_owned.load(Ordering::Relaxed);
        if self.owned[owner as usize] == target {
            self.owned[owner as usize] = after;
        } else {
            let mut a = self.owned[owner as usize];
            while let Some(o) = WaitObj::from_addr(a) {
                // SAFETY: linked objects are live.
                let cur = unsafe { o.get() };
                let n = cur.next_owned.load(Ordering::Relaxed);
                if n == target {
                    cur.next_owned.store(after, Ordering::Relaxed);
                    break;
                }
                a = n;
            }
        }
        obj.next_owned.store(0, Ordering::Relaxed);
    }

    /// Would `waiter`, now enqueued on `obj`, close a cycle? Follows owner
    /// -> blocked_on for at most [`PI_MAX_DEPTH`] links: a cycle is the walk
    /// reaching `waiter` or an object already visited. Beyond the cap no
    /// cycle is reported (the block succeeds; owner question Q4).
    fn closes_cycle(&self, h: &dyn SchedPi, waiter: TaskId, obj: WaitObj) -> bool {
        let mut seen = [0usize; PI_MAX_DEPTH];
        let mut o = obj;
        for k in 0..PI_MAX_DEPTH {
            seen[k] = o.addr();
            // SAFETY: objects on a chain are named by a `blocked_on`.
            let Some(owner) = (unsafe { o.get() }).owner() else { return false };
            if owner == waiter {
                return true;
            }
            if owner as usize >= N {
                return false;
            }
            let Some(next) = h.blocked_on(owner) else { return false };
            if seen[..=k].contains(&next.addr()) {
                return true;
            }
            o = next;
        }
        false
    }
}

/// Install the scheduler's hooks. Called once by the scheduler's init,
/// before the first task can block; a second call panics. Task context.
pub fn register_sched(hooks: &'static dyn SchedPi) {
    GRAPH.register_sched(hooks)
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
pub fn block_prepare(waiter: TaskId, obj: &PiWaiters) -> Result<PendingBlock, WaitError> {
    GRAPH.block_prepare(waiter, obj)
}

/// Second half of [`block_on`]: the walk. Called before the waiter sleeps,
/// normally after the client dropped its SpinLock (at most the object's own
/// client lock may still be held, the module's one rule). On
/// `Err(Deadlock)` the waiter has been dequeued again. O(PI_MAX_DEPTH).
pub fn block_commit(p: PendingBlock) -> Result<(), WaitError> {
    GRAPH.block_commit(p)
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
pub fn unblock(waiter: TaskId, obj: &PiWaiters, why: UnblockReason) {
    GRAPH.unblock(waiter, obj, why)
}

/// The owner gives `obj` up: clears its PI contribution from `obj`, unboosts
/// the owner, and returns the top waiter (the client wakes it; the client,
/// not the graph, decides whether it hands ownership over or lets the
/// woken waiter compete). The object is left without owner: the client
/// names the next one with [`PiWaiters::set_owner`]. Task context; at most
/// the object's own client SpinLock held (the module's one rule).
/// O(owned objects with waiters) for the unboost plus one walk.
pub fn release(owner: TaskId, obj: &PiWaiters) -> Option<TaskId> {
    GRAPH.release(owner, obj)
}

/// The most urgent waiter of `obj` and its effective attribute. Any
/// context except an interrupt handler; takes `obj`'s wait lock. O(1).
pub fn top_waiter(obj: &PiWaiters) -> Option<(TaskId, PiAttr)> {
    GRAPH.top_waiter(obj)
}

/// The scheduler changed `t`'s base attribute (`sched_setattr`, `schedctl`,
/// a DL replenishment that moved the deadline): re-sort `t` where it waits
/// and walk. Called by N6a without any run-queue lock held. O(depth).
/// A no-op before [`register_sched`] (slot creation runs earlier).
pub fn attr_changed(t: TaskId) {
    GRAPH.attr_changed(t)
}

/// `t` is exiting: it must own nothing with waiters (each client released
/// its objects first: robust futexes through the robust list, mutexes are a
/// kernel bug, leases through revoke). Debug builds verify and panic.
pub fn task_exit(t: TaskId) {
    GRAPH.task_exit(t)
}

/// The effective attribute the graph holds for `t` (`None`: its base
/// stands). Where a boosted owner's inherited absolute deadline is read.
pub fn effective(t: TaskId) -> Option<PiAttr> {
    GRAPH.effective(t)
}

/// Counters for vsbench and ktest: walks, total steps, depth-cap hits,
/// deadlocks refused. Relaxed reads.
pub fn stats() -> WalkStats {
    GRAPH.stats()
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct WalkStats {
    pub walks: u64,
    pub steps: u64,
    pub depth_capped: u64,
    pub deadlocks: u64,
}

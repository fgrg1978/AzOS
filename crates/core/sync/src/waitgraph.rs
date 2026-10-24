// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The wait graph (wave 15 N7): one priority-inheritance core for every
//! object a task can block on while another task owns it.
//!
//! Stage 1, implemented by N7 ([`Graph`]). Nothing calls into this module
//! while Kconfig `WAIT_GRAPH` is n: [`ENABLED`] is a compile-time `false`,
//! every client tests it before taking the graph path, and the kernel's
//! graph then has zero slots. `WAIT_GRAPH` is y on every preset, and the
//! cycle check below is not tied to a debug or lockdep build.
//!
//! # Model
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
//!   (L9), user-driver proxy and FAT32 claim. A new client adds a
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
//!   call is undone before returning. A `wait-cycle`
//!   decision record (`azos_decision::Rule::WaitCycle`, a refusal: durable
//!   with `DECISION_REFUSALS_DURABLE`, y on every preset) is written after
//!   the undo, with the graph lock dropped.
//! * **Depth cap** reached: boosting stops there (owner decision: at max
//!   depth stop boosting, no `EDEADLK`); the block itself succeeds and the
//!   cap is counted ([`stats`]).
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
use core::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::spinlock::SpinLock;

/// Kconfig `WAIT_GRAPH`: the graph is compiled into the lock paths. n: every
/// client keeps its pre-N7 path and nothing here is reached.
pub const ENABLED: bool = azos_limits::WAIT_GRAPH;

/// N7e, the donor migration's node selector: the wait-graph node a priority
/// donor (fast IPC call, driver proxy) embeds in its object is
/// [`PiWaiters`] with `WAIT_GRAPH` y and `()` with n, so an object that
/// embeds a [`DonorNode`] keeps its n layout and code. It is a const
/// generic on [`ENABLED`], not a cfg: a `cargo:rustc-cfg` printed by
/// `azos_limits`' build script reaches only `azos_limits` itself, never the
/// crates that would embed the node.
pub struct NodeSel<const Y: bool>;

/// What [`NodeSel`] selects: the node type and one initializer per donor
/// kind (a fresh value at each use, as any `const`).
pub trait SelectNode {
    /// `PiWaiters` (y) or `()` (n).
    type Node;
    /// The node of a call blocked on an endpoint's server.
    const IPC_CALL: Self::Node;
    /// The node of a user-mode driver serving a kernel proxy request.
    const DRIVER_PROXY: Self::Node;
    /// The node of a FAT32 claim held by its owner.
    const CLAIM: Self::Node;
}

#[allow(clippy::declare_interior_mutable_const)]
impl SelectNode for NodeSel<true> {
    type Node = PiWaiters;
    const IPC_CALL: PiWaiters = PiWaiters::new(EdgeKind::IpcCall);
    const DRIVER_PROXY: PiWaiters = PiWaiters::new(EdgeKind::DriverProxy);
    const CLAIM: PiWaiters = PiWaiters::new(EdgeKind::Claim);
}

impl SelectNode for NodeSel<false> {
    type Node = ();
    const IPC_CALL: () = ();
    const DRIVER_PROXY: () = ();
    const CLAIM: () = ();
}

/// The node this build's donors embed ([`NodeSel`]): zero-sized with n.
pub type DonorNode = <NodeSel<ENABLED> as SelectNode>::Node;

/// Kconfig `PI_MAX_DEPTH` (Q4: 16): the longest chain a walk follows. Bounds
/// the cost of every block/unblock to `PI_MAX_DEPTH` steps.
pub const PI_MAX_DEPTH: usize = azos_limits::PI_MAX_DEPTH;

/// A task as the scheduler names it: its slot index, `< MAX_TASKS`. The
/// same number lockdep uses.
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
    // 4 was `Lease`, removed: not reused, because the code is recorded in
    // the `wait-cycle` decision (`kind`), so a recorded value keeps its meaning.
    /// A user-mode driver serving a kernel proxy request (migrated by N7).
    DriverProxy = 5,
    /// A FAT32 claim (FAT sector or write-back) held by its owner while the
    /// owner does the claim's device I/O (FX12).
    Claim = 6,
}

impl EdgeKind {
    /// The kinds [`block_on_lazy`] records lazily: their clients never ask
    /// the graph for waiters. Any other kind takes [`block_on`] there.
    #[inline(always)]
    pub const fn lazy_capable(self) -> bool {
        matches!(self, EdgeKind::IpcCall)
    }
}

pub use crate::pi_attr::{quiet_le, PiAttr, QUIET_DL};

/// "No task" in the slot fields of [`PiWaiters`] and the graph's links.
const NONE: u32 = u32::MAX;

/// The waiter side of one blockable object. Embedded in the object (a
/// `Mutex`, a futex `pi_state`, an endpoint's call record); the
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
    #[inline]
    pub fn owner(&self) -> Option<TaskId> {
        slot(self.owner.load(Ordering::Relaxed))
    }

    /// The client records a new owner (lock acquired, futex word taken over,
    /// call accepted by a server) or none. Re-attaches the
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
    /// the client, endpoint revoked).
    ObjectGone,
    /// The owner exited still owning the object (owner decision 10-10, the
    /// `EOWNERDEAD` equivalent): the graph detached it and called the
    /// kind's [`OwnerDiedHook`], which wakes the waiters; the one that takes
    /// the object next leaves with this reason.
    OwnerDied,
}

/// A client's answer to an owner that exits still owning one of its objects
/// with waiters (owner decision 10-10). Registered per [`EdgeKind`] with
/// [`register_owner_died`]; a kind with no hook keeps the pre-10-10 rule:
/// the object is detached, counted in [`WalkStats::orphaned`], and its
/// waiters stay queued until the client wakes them (robust list, revoke).
pub trait OwnerDiedHook: Sync {
    /// `obj` was owned by `dead`, which is exiting. The graph has already
    /// detached it (no owner, `dead` unboosted) and dropped its own lock;
    /// the waiters are still queued in the graph, most urgent first. The
    /// hook makes the object takeable and wakes the waiters through the
    /// client's own queue; whoever takes it records itself with
    /// `set_owner` and sees [`UnblockReason::OwnerDied`] in the client's
    /// terms. Called in the exiting task's context, interrupts on, no
    /// graph lock held: the hook may take the client's own lock (which
    /// orders before the graph lock) and call back into the graph.
    fn owner_died(&self, obj: &PiWaiters, dead: TaskId);
}

/// Hook slots, indexed by `EdgeKind as usize`.
const KINDS: usize = 7;

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

    /// [`base_attr`](Self::base_attr) as [`PiAttr::quiet_key`], what the
    /// lock-free quiet test of [`block_on_lazy`] and [`block_on_quiet`]
    /// compares. An implementation that keeps it per task instead (the
    /// kernel's lock-free hooks) stores the new key before it reports the
    /// change with [`attr_changed`]: that call's fence is what orders it
    /// against a lazy call.
    #[inline(always)]
    fn quiet_key(&self, t: TaskId) -> u32 {
        self.base_attr(t).quiet_key()
    }

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
/// transitive chain is not boosted past its first link (ktests
/// `waitgraph_transitive_chain`, `waitgraph_dl_donor_and_attr_changed` and
/// `waitgraph_depth_cap` go red).
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
    /// [`OwnerDiedHook`] per [`EdgeKind`].
    died_hooks: [Option<&'static dyn OwnerDiedHook>; KINDS],
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
    /// Per task: its edge is LAZY ([`block_on_lazy`]): named by its
    /// `blocked_on` only, not in its object's waiter list. Cleared by
    /// whoever claims the edge first (compare-and-swap): the lock-free
    /// unblock, or a locked path that materializes it into the list.
    lazy: [AtomicBool; N],
    /// Per task: the graph last left it above its base attribute (a live
    /// boost). Written under the graph lock, read lock-free by
    /// [`block_on_lazy`]: a raised caller takes the locked path.
    raised: [AtomicBool; N],
    walks: AtomicU64,
    steps: AtomicU64,
    depth_capped: AtomicU64,
    deadlocks: AtomicU64,
    orphaned: AtomicU64,
    owner_died: AtomicU64,
    lazy_edges: AtomicU64,
    materialized: AtomicU64,
}

/// `canary=pi-lazy-no-materialize` (host tests): a locked path that finds a
/// lazy edge leaves it lazy, so a caller raised after its lazy call (or a
/// server lowered under one) does not boost the server; the host test
/// `wait_graph_stage1`'s lazy section goes red.
static CANARY_LAZY_NO_MATERIALIZE: AtomicBool = AtomicBool::new(false);

/// Arm (or, `false`, disarm) the lazy-materialization canary.
pub fn canary_lazy_no_materialize(on: bool) {
    CANARY_LAZY_NO_MATERIALIZE.store(on, Ordering::Relaxed);
}

/// `canary=wait-cycle-unchecked` (host tests): the cycle check at block time
/// reports nothing, so a block that closes a cycle is accepted and sleeps
/// for good; the host test `deadlock_refused_with_record` goes red.
static CANARY_NO_CYCLE_CHECK: AtomicBool = AtomicBool::new(false);

/// Arm (or, `false`, disarm) the cycle-check canary.
pub fn canary_no_cycle_check(on: bool) {
    CANARY_NO_CYCLE_CHECK.store(on, Ordering::Relaxed);
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
            st: SpinLock::new(State {
                hooks: None,
                eff: [None; N],
                next: [NONE; N],
                owned: [0; N],
                died_hooks: [None; KINDS],
            }),
            lazy: [const { AtomicBool::new(false) }; N],
            raised: [const { AtomicBool::new(false) }; N],
            walks: AtomicU64::new(0),
            steps: AtomicU64::new(0),
            depth_capped: AtomicU64::new(0),
            deadlocks: AtomicU64::new(0),
            orphaned: AtomicU64::new(0),
            owner_died: AtomicU64::new(0),
            lazy_edges: AtomicU64::new(0),
            materialized: AtomicU64::new(0),
        }
    }

    /// A block that [`State::closes_cycle`] refused has been dequeued: count it and
    /// leave its decision record. Called with the graph lock DROPPED (the
    /// durable sink wakes the log flusher), after the undo.
    #[cold]
    fn refused(&self, waiter: TaskId, obj: &PiWaiters, c: Cycle) -> WaitError {
        self.deadlocks.fetch_add(1, Ordering::Relaxed);
        azos_decision::record(
            azos_decision::Rule::WaitCycle,
            azos_decision::Verdict::Refuse,
            waiter,
            [obj.kind() as u64, c.closer as u64, c.links as u64],
        );
        WaitError::Deadlock
    }

    /// See [`register_owner_died`]. A second call for a kind replaces the
    /// first (host tests swap recorders).
    pub fn register_owner_died(&self, kind: EdgeKind, hook: &'static dyn OwnerDiedHook) {
        self.st.lock_irqsave().died_hooks[kind as usize] = Some(hook);
    }

    /// See [`register_sched`]. Panics on a second call.
    pub fn register_sched(&self, hooks: &'static dyn SchedPi) {
        let mut st = self.st.lock_irqsave();
        assert!(st.hooks.is_none(), "waitgraph: scheduler registered twice");
        st.hooks = Some(hooks);
    }

    /// One more lazy edge in [`WalkStats::lazy_edges`] (host builds only).
    #[inline(always)]
    fn count_lazy(&self) {
        if cfg!(not(target_os = "none")) {
            self.lazy_edges.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// See [`block_on_lazy`]. The quiet case inline (no callee-saved
    /// spill for the locked fallback), everything else out of line.
    /// `h` is the registered scheduler (a concrete type, so its accessors
    /// inline).
    #[inline]
    pub fn block_on_lazy<H: SchedPi>(&self, h: &H, waiter: TaskId, obj: &PiWaiters) -> Result<(), WaitError> {
        let owner = obj.owner.load(Ordering::Relaxed);
        let Some(lazy) = self.lazy.get(waiter as usize) else {
            return self.block_on(waiter, obj);
        };
        if !obj.kind.lazy_capable() {
            return self.block_on(waiter, obj);
        }
        if owner == NONE || owner as usize >= N || owner == waiter {
            return self.block_on(waiter, obj);
        }
        // Publish the edge first, then read what decides it (Dekker with
        // the locked paths: they write `raised`, a base attribute or a
        // `blocked_on`, fence, then read `lazy`): either this side sees
        // their write and takes the locked path, or they see the edge and
        // materialize it.
        h.set_blocked_on(waiter, Some(WaitObj::of(obj)));
        lazy.store(true, Ordering::Release);
        fence(Ordering::SeqCst);
        // Linux rt_mutex: no PI work when the owner already runs at least at
        // the waiter's priority. Here the owner's BASE (not its effective
        // attribute): a lazy waiter is not in the list, so it must not
        // matter once another boost of the owner goes. An owner blocked on
        // anything could close a cycle or carry a chain: locked path. A DL
        // waiter or owner is never quiet (`quiet_le`): its order is a
        // deadline read on its own hart.
        let quiet = obj.owner.load(Ordering::Relaxed) == owner
            && !self.raised[waiter as usize].load(Ordering::Relaxed)
            && h.blocked_on(owner).is_none()
            && quiet_le(h.quiet_key(waiter), h.quiet_key(owner));
        if quiet {
            self.count_lazy();
            return Ok(());
        }
        self.block_on_lazy_undo(h, waiter, obj)
    }

    /// See [`block_on_quiet`]: [`block_on_lazy`]'s quiet case, and nothing
    /// else.
    #[inline]
    pub fn block_on_quiet<H: SchedPi>(&self, h: &H, waiter: TaskId, obj: &PiWaiters) -> bool {
        let owner = obj.owner.load(Ordering::Relaxed);
        let Some(lazy) = self.lazy.get(waiter as usize) else { return false };
        if !obj.kind.lazy_capable() || owner == NONE || owner as usize >= N || owner == waiter {
            return false;
        }
        // The edge and the predicate exactly as `block_on_lazy` (the same
        // Dekker with the locked paths).
        h.set_blocked_on(waiter, Some(WaitObj::of(obj)));
        lazy.store(true, Ordering::Release);
        fence(Ordering::SeqCst);
        let quiet = obj.owner.load(Ordering::Relaxed) == owner
            && !self.raised[waiter as usize].load(Ordering::Relaxed)
            && h.blocked_on(owner).is_none()
            && quiet_le(h.quiet_key(waiter), h.quiet_key(owner));
        if quiet {
            self.count_lazy();
            return true;
        }
        self.block_on_quiet_undo(h, waiter, obj);
        false
    }

    /// [`block_on_quiet`] when the call is not quiet: take the edge back,
    /// through the lock only if a locked path materialized it meanwhile.
    #[inline(never)]
    fn block_on_quiet_undo<H: SchedPi>(&self, h: &H, waiter: TaskId, obj: &PiWaiters) {
        if self.lazy[waiter as usize].compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            h.set_blocked_on(waiter, None);
            return;
        }
        self.unblock(waiter, obj, UnblockReason::ObjectGone);
    }

    /// See [`edge_is_quiet`].
    #[inline(always)]
    pub fn edge_is_quiet<H: SchedPi>(&self, h: &H, waiter: TaskId) -> bool {
        match self.lazy.get(waiter as usize) {
            Some(lazy) => lazy.load(Ordering::Acquire) || h.blocked_on(waiter).is_none(),
            None => true,
        }
    }

    /// [`block_on_lazy`] when the call is not quiet: take the edge back and
    /// block through the lock, unless a locked path claimed it first.
    #[inline(never)]
    fn block_on_lazy_undo<H: SchedPi>(&self, h0: &H, waiter: TaskId, obj: &PiWaiters) -> Result<(), WaitError> {
        let lazy = &self.lazy[waiter as usize];
        if lazy.compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            h0.set_blocked_on(waiter, None);
            return self.block_on(waiter, obj);
        }
        // A locked path materialized the edge meanwhile: it is in the list
        // and walked, but no cycle check ran on it.
        let mut st = self.st.lock_irqsave();
        let h = hooks(&st);
        if h.blocked_on(waiter) == Some(WaitObj::of(obj)) {
            if let Some(c) = st.closes_cycle(h, waiter, WaitObj::of(obj)) {
                st.dequeue(h, waiter, obj);
                if let Some(o) = obj.owner() {
                    self.walk(&mut st, h, o);
                }
                drop(st);
                return Err(self.refused(waiter, obj, c));
            }
        }
        Ok(())
    }

    /// Claim `t`'s lazy edge, if it has one, and put it in its object's
    /// waiter list at `e` (linking the object to its owner). Returns the
    /// owner to walk. Graph lock held, after a `SeqCst` fence.
    fn materialize(&self, st: &mut State<N>, h: &dyn SchedPi, t: TaskId, e: PiAttr) -> Option<TaskId> {
        let lazy = self.lazy.get(t as usize)?;
        if !lazy.load(Ordering::Acquire) || CANARY_LAZY_NO_MATERIALIZE.load(Ordering::Relaxed) {
            return None;
        }
        if lazy.compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            return None;
        }
        let o = h.blocked_on(t)?;
        // SAFETY: `t` is blocked on `o` (the lifetime contract).
        let obj = unsafe { o.get() };
        st.eff[t as usize] = Some(e);
        let was_linked = obj.linked();
        st.insert(h, obj, t, e);
        let owner = obj.owner.load(Ordering::Relaxed);
        if !was_linked && owner != NONE {
            st.link_owned(owner, obj);
        }
        self.materialized.fetch_add(1, Ordering::Relaxed);
        slot(owner).filter(|&o| (o as usize) < N)
    }

    /// Materialize every lazy edge on an object `owner` owns: its base is
    /// about to be re-read, and a lazy waiter is only harmless while the
    /// owner's base is at least as urgent. O(N); `attr_changed` only.
    fn materialize_waiters_of(&self, st: &mut State<N>, h: &dyn SchedPi, owner: TaskId) {
        for w in 0..N {
            if !self.lazy[w].load(Ordering::Acquire) {
                continue;
            }
            let Some(o) = h.blocked_on(w as TaskId) else { continue };
            // SAFETY: `w` is blocked on `o` (the lifetime contract).
            if unsafe { o.get() }.owner() == Some(owner) {
                let e = st.compute_eff(h, w as TaskId);
                self.materialize(st, h, w as TaskId, e);
            }
        }
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

    /// See [`block_prepare_ownerless`].
    pub fn block_prepare_ownerless(&self, waiter: TaskId, obj: &PiWaiters) -> Result<PendingBlock, WaitError> {
        if waiter as usize >= N {
            return Err(WaitError::NoOwner);
        }
        let mut st = self.st.lock_irqsave();
        let h = hooks(&st);
        let owner = obj.owner.load(Ordering::Relaxed);
        if owner == waiter {
            return Err(WaitError::SelfOwned);
        }
        debug_assert!(h.blocked_on(waiter).is_none(), "waitgraph: a task blocks on two objects");
        let e = st.compute_eff(h, waiter);
        st.eff[waiter as usize] = Some(e);
        let was_linked = obj.linked();
        st.insert(h, obj, waiter, e);
        h.set_blocked_on(waiter, Some(WaitObj::of(obj)));
        if !was_linked && owner != NONE {
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
        if let Some(c) = st.closes_cycle(h, p.waiter, p.obj) {
            // Undo before any boost was applied: both tasks unchanged.
            st.dequeue(h, p.waiter, obj);
            drop(st);
            return Err(self.refused(p.waiter, obj, c));
        }
        if let Some(owner) = obj.owner() {
            self.walk(&mut st, h, owner);
        }
        Ok(())
    }

    /// See [`unblock_lazy`]: a lazy edge inline, the rest is [`unblock`].
    #[inline]
    pub fn unblock_lazy<H: SchedPi>(&self, h: &H, waiter: TaskId, obj: &PiWaiters, why: UnblockReason) {
        // A lazy edge (never in the list, never boosted anything): O(1).
        if let Some(lazy) = self.lazy.get(waiter as usize) {
            if lazy.load(Ordering::Acquire)
                && h.blocked_on(waiter) == Some(WaitObj::of(obj))
                && lazy.compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed).is_ok()
            {
                h.set_blocked_on(waiter, None);
                return;
            }
        }
        self.unblock(waiter, obj, why)
    }

    /// See [`unblock`].
    #[inline(never)]
    pub fn unblock(&self, waiter: TaskId, obj: &PiWaiters, _why: UnblockReason) {
        if waiter as usize >= N {
            return;
        }
        let mut st = self.st.lock_irqsave();
        let h = hooks(&st);
        // A lazy edge is in no list: claimed here, the dequeue only clears
        // its `blocked_on`.
        let _ = self.lazy[waiter as usize].compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed);
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
        // A lazy waiter was harmless only under the old owner's base: it
        // joins the list before the new owner is walked. Dekker with
        // `block_on_lazy` (owner, fence, lazy flags here; edge, fence, owner
        // re-read there). Only the kinds that take lazy edges pay it.
        if obj.kind.lazy_capable() {
            fence(Ordering::SeqCst);
            for w in 0..N {
                if self.lazy[w].load(Ordering::Acquire) && h.blocked_on(w as TaskId) == Some(WaitObj::of(obj)) {
                    let e = st.compute_eff(h, w as TaskId);
                    self.materialize(&mut st, h, w as TaskId, e);
                }
            }
        }
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
        // The new base was written before this call: after the fence a
        // lazy call on or by `t` either is seen here or saw the new base.
        fence(Ordering::SeqCst);
        self.materialize_waiters_of(&mut st, h, t);
        // The scheduler may have written the new base over a live boost:
        // put the boost back first, then let the walk move the chain.
        let e = st.compute_eff(h, t);
        let raised = e > h.base_attr(t);
        if raised {
            h.boost(t, e);
        }
        self.raised[t as usize].store(raised, Ordering::Relaxed);
        // `t`'s own lazy call: its server re-reads `t` from the list.
        let up = self.materialize(&mut st, h, t, e);
        self.walk(&mut st, h, t);
        if let Some(o) = up {
            self.walk(&mut st, h, o);
        }
    }

    /// See [`task_exit`].
    pub fn task_exit(&self, t: TaskId) {
        self.exit_inner(t, true)
    }

    /// See [`task_reset`].
    pub fn task_reset(&self, t: TaskId) {
        self.exit_inner(t, false)
    }

    fn exit_inner(&self, t: TaskId, dispatch: bool) {
        if t as usize >= N {
            return;
        }
        // Lazy waiters on what `t` owns join their lists first, so the
        // owner loop below detaches those objects too (a lazy-only call node
        // is not linked and would keep naming the dead slot, which a reused
        // slot then inherits). Dekker with `block_on_lazy` as in set_owner.
        {
            let mut st = self.st.lock_irqsave();
            if let Some(h) = st.hooks {
                fence(Ordering::SeqCst);
                self.materialize_waiters_of(&mut st, h, t);
            }
        }
        // The owner role: no live object names a dead owner. Each object
        // still owned (it has waiters) is detached one at a time under the
        // lock, then handed to its kind's OwnerDiedHook with the lock
        // DROPPED: a hook takes the client's lock, which orders before the
        // graph lock (owner decision 10-10, EOWNERDEAD). Without a hook the
        // waiters stay queued (robust list, revoke) and the next
        // `set_owner` re-links the object and walks. Boost flows waiter ->
        // owner, so nothing the waiters hold changes here. The object stays
        // live across the drop: it still has waiters (lifetime contract).
        loop {
            let (obj, hook) = {
                let mut st = self.st.lock_irqsave();
                let Some(o) = WaitObj::from_addr(st.owned[t as usize]) else { break };
                // SAFETY: linked objects are live (the lifetime contract).
                let obj = unsafe { o.get() };
                st.unlink_owned(t, obj);
                obj.owner.store(NONE, Ordering::Relaxed);
                let hook = if !dispatch || CANARY_OWNER_DIED_SILENT.load(Ordering::Relaxed) {
                    None
                } else {
                    st.died_hooks[obj.kind as usize]
                };
                (obj, hook)
            };
            match hook {
                Some(hk) => {
                    self.owner_died.fetch_add(1, Ordering::Relaxed);
                    hk.owner_died(obj, t);
                }
                None => {
                    self.orphaned.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let mut st = self.st.lock_irqsave();
        // A lazy edge is in no list: the dequeue below only clears it.
        self.lazy[t as usize].store(false, Ordering::Relaxed);
        self.raised[t as usize].store(false, Ordering::Relaxed);
        // The waiter role (a task torn down while parked): off the list,
        // `blocked_on` cleared, and its old owner walked down.
        if let Some(h) = st.hooks {
            if let Some(o) = h.blocked_on(t) {
                // SAFETY: `t` is enqueued on `o` (the lifetime contract).
                let obj = unsafe { o.get() };
                st.dequeue(h, t, obj);
                if let Some(owner) = obj.owner() {
                    if (owner as usize) < N {
                        self.walk(&mut st, h, owner);
                    }
                }
            }
        }
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
            orphaned: self.orphaned.load(Ordering::Relaxed),
            owner_died: self.owner_died.load(Ordering::Relaxed),
            lazy_edges: self.lazy_edges.load(Ordering::Relaxed),
            materialized: self.materialized.load(Ordering::Relaxed),
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
            let raised = new > h.base_attr(t);
            if raised {
                h.boost(t, new);
            } else {
                h.unboost(t, new);
            }
            self.raised[t as usize].store(raised, Ordering::Relaxed);
            // Dekker with `block_on_lazy`: `raised` before `lazy`.
            fence(Ordering::SeqCst);
            if let Some(next) = self.materialize(st, h, t, new) {
                if next == start {
                    return;
                }
                t = next;
                continue;
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
    /// cycle is reported (the block succeeds; owner decision). The
    /// answer names the task that closes the cycle and the links followed.
    fn closes_cycle(&self, h: &dyn SchedPi, waiter: TaskId, obj: WaitObj) -> Option<Cycle> {
        if CANARY_NO_CYCLE_CHECK.load(Ordering::Relaxed) {
            return None;
        }
        // Dekker with `block_on_lazy`: the waiter's `blocked_on` (written by
        // the prepare) before the owners' (a lazy edge's, read below).
        fence(Ordering::SeqCst);
        let mut seen = [0usize; PI_MAX_DEPTH];
        let mut o = obj;
        for k in 0..PI_MAX_DEPTH {
            seen[k] = o.addr();
            // SAFETY: objects on a chain are named by a `blocked_on`.
            let owner = (unsafe { o.get() }).owner()?;
            if owner == waiter {
                return Some(Cycle { closer: owner, links: k as u8 + 1 });
            }
            if owner as usize >= N {
                return None;
            }
            let next = h.blocked_on(owner)?;
            if seen[..=k].contains(&next.addr()) {
                return Some(Cycle { closer: owner, links: k as u8 + 1 });
            }
            o = next;
        }
        None
    }
}

/// Where a refused block's cycle closed: [`Graph::closes_cycle`]'s answer.
#[derive(Clone, Copy)]
struct Cycle {
    /// The task whose object the chain ran into again: the waiter itself,
    /// or the owner of an object the chain met twice.
    closer: TaskId,
    /// Owner links followed to find it.
    links: u8,
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

/// [`block_on`] without the graph lock in the common case (wave 15 GIPC,
/// the `IpcCall` edge): when the waiter carries no boost, the owner is not
/// blocked on anything, and the waiter's base attribute is not more urgent
/// than the owner's base (neither of them `Dl`: [`quiet_le`] over
/// [`SchedPi::quiet_key`]), the edge is recorded LAZILY: `blocked_on` is set,
/// the waiter is not put in `obj`'s list, nothing is walked (Linux rt_mutex
/// does no PI work when the owner already runs at least at the waiter's
/// priority). Any locked path that would make it matter materializes it
/// first: a walk raising the waiter, `attr_changed` of the waiter or of the
/// owner. Otherwise exactly [`block_on`] (transitive chain, ring-3 floor,
/// `EDEADLK` on a cycle). The matching [`unblock`] of a lazy edge is O(1)
/// and lock-free.
///
/// **Only for objects whose client never asks the graph for its waiters**
/// ([`top_waiter`], [`release`], [`PiWaiters::has_waiters`] do not see a
/// lazy waiter), the kinds [`EdgeKind::lazy_capable`] names (any other is
/// [`block_on`]): the IPC call node, unblocked through [`unblock_lazy`].
/// `h` is the scheduler registered with [`register_sched`] (passed as its
/// concrete type so the quiet case inlines it). Same context rule as
/// [`block_on`].
/// Cost (lazy): two `blocked_on` accesses, two key reads, one fence.
#[inline]
pub fn block_on_lazy<H: SchedPi>(h: &H, waiter: TaskId, obj: &PiWaiters) -> Result<(), WaitError> {
    GRAPH.block_on_lazy(h, waiter, obj)
}

/// [`block_on_lazy`]'s quiet case only, for a caller that has another way
/// on (the IPC fast path, Kconfig IPC_FASTPATH: its ordinary path): `true`
/// with the lazy edge recorded exactly as [`block_on_lazy`] records it
/// (`blocked_on`, the lazy flag, the fence, the same predicate), `false` with
/// no edge at all, when it would boost, chain or need the cycle check (or
/// `obj` takes no lazy edge, or has no owner). Never takes the graph lock
/// but to take back an edge a locked path materialized between the publish
/// and the predicate. Undone by [`unblock_lazy`].
#[inline]
pub fn block_on_quiet<H: SchedPi>(h: &H, waiter: TaskId, obj: &PiWaiters) -> bool {
    GRAPH.block_on_quiet(h, waiter, obj)
}

/// Is `waiter`'s edge, if it has one, still lazy (in no waiter list, so it
/// boosts nothing and [`unblock_lazy`] drops it without the graph lock)?
/// `true` with no edge. A hint: a walk may materialize it right after, and
/// [`unblock_lazy`] then takes the lock.
#[inline(always)]
pub fn edge_is_quiet<H: SchedPi>(h: &H, waiter: TaskId) -> bool {
    GRAPH.edge_is_quiet(h, waiter)
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

/// [`block_prepare`] for an object that may have no owner right now: a
/// released object held for its queued top waiter (the kmutex steal rule).
/// The waiter is enqueued and `blocked_on` set either way; with no owner
/// nothing is linked and [`block_commit`] walks nothing, and the next
/// [`PiWaiters::set_owner`] links the object and boosts the taker. Same
/// context rule and cost as [`block_prepare`]; never `NoOwner` for a valid
/// waiter.
pub fn block_prepare_ownerless(waiter: TaskId, obj: &PiWaiters) -> Result<PendingBlock, WaitError> {
    GRAPH.block_prepare_ownerless(waiter, obj)
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

/// [`unblock`] for an edge [`block_on_lazy`] may have recorded lazily: a
/// lazy one is dropped in O(1) without the graph lock (it boosted nothing,
/// so nothing walks); any other goes through [`unblock`]. `h` as for
/// [`block_on_lazy`].
#[inline]
pub fn unblock_lazy<H: SchedPi>(h: &H, waiter: TaskId, obj: &PiWaiters, why: UnblockReason) {
    GRAPH.unblock_lazy(h, waiter, obj, why)
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

/// `t` is exiting (the scheduler's exit path, and again when its slot is
/// reused): its graph state goes. Each object it still owns with waiters
/// (robust PI futexes were handed over by the robust walk before this runs)
/// is detached from it; if the object's kind registered an
/// [`OwnerDiedHook`], the hook wakes the waiters with
/// [`UnblockReason::OwnerDied`] (counted in [`WalkStats::owner_died`]),
/// else they stay queued for their client (counted in
/// [`WalkStats::orphaned`]). A task torn down while blocked leaves its
/// object and its old owner is walked down. Idempotent. Task context,
/// interrupts on, no SpinLock held (a hook may take its client's lock).
pub fn task_exit(t: TaskId) {
    GRAPH.task_exit(t)
}

/// [`task_exit`] for a slot being reused: the same cleanup, but an object
/// still owned is only detached (counted in [`WalkStats::orphaned`]), never
/// handed to an [`OwnerDiedHook`]: the slot's new task is not running yet,
/// and waking the waiters for an owner that died is the exit path's.
/// Normally a no-op for the owner role, as the exit path's `task_exit`
/// drained it. Task context, no SpinLock held.
pub fn task_reset(t: TaskId) {
    GRAPH.task_reset(t)
}

/// Install `kind`'s [`OwnerDiedHook`] (boot, once per kind, before any task
/// can exit owning such an object).
pub fn register_owner_died(kind: EdgeKind, hook: &'static dyn OwnerDiedHook) {
    GRAPH.register_owner_died(kind, hook)
}

/// Runtime canary `canary=owner-died-silent`: [`task_exit`] skips every
/// [`OwnerDiedHook`] and only detaches (the pre-10-10 rule), so waiters on
/// a dead owner's object are never woken. The ktest
/// `kmutex_owner_died_wakes_waiter` goes red.
static CANARY_OWNER_DIED_SILENT: AtomicBool = AtomicBool::new(false);

/// Arm the `owner-died-silent` canary (boot, from the command line; host
/// tests pass `false` to disarm).
pub fn canary_owner_died_silent(on: bool) {
    CANARY_OWNER_DIED_SILENT.store(on, Ordering::Relaxed);
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
    /// Objects detached from an exiting owner that still had waiters and
    /// whose kind has no [`OwnerDiedHook`]: the waiters stay queued.
    pub orphaned: u64,
    /// Objects detached from an exiting owner and handed to their kind's
    /// [`OwnerDiedHook`] (`EOWNERDEAD` wakes).
    pub owner_died: u64,
    /// Edges [`block_on_lazy`] recorded without the graph lock. Counted on
    /// the host suites only, its one reader (`tests/host/sync-tests`): on
    /// the kernel targets (`target_os = "none"`) the quiet IPC call pays no
    /// atomic add for it, and it stays 0.
    pub lazy_edges: u64,
    /// Lazy edges a locked path put into their object's list (a raised
    /// caller, a lowered owner).
    pub materialized: u64,
}

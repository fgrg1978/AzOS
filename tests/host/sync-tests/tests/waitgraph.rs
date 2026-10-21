// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! N7: the wait graph's stage-1 semantics, on a private `Graph` driven by a
//! recording scheduler (the kernel's instance is sized 0 with `WAIT_GRAPH`
//! n). Its own test binary: the graph lock moves the host preempt counter,
//! which the library's preempt tests read, so it must not share their
//! process. One test function: the depth canary is a global.

use azos_sync_tests::waitgraph::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const N: usize = 64;

struct Rec {
    base: Mutex<[PiAttr; N]>,
    cur: Mutex<[PiAttr; N]>,
    on: [AtomicUsize; N],
}

impl Rec {
    const fn new() -> Self {
        Rec {
            base: Mutex::new([PiAttr::Fair; N]),
            cur: Mutex::new([PiAttr::Fair; N]),
            on: [const { AtomicUsize::new(0) }; N],
        }
    }
    fn set_base(&self, t: TaskId, a: PiAttr) {
        self.base.lock().unwrap()[t as usize] = a;
        self.cur.lock().unwrap()[t as usize] = a;
    }
    fn cur(&self, t: TaskId) -> PiAttr {
        self.cur.lock().unwrap()[t as usize]
    }
}

impl SchedPi for Rec {
    fn base_attr(&self, t: TaskId) -> PiAttr { self.base.lock().unwrap()[t as usize] }
    fn boost(&self, t: TaskId, to: PiAttr) {
        assert!(to > self.base_attr(t), "boost below base");
        self.cur.lock().unwrap()[t as usize] = to;
    }
    fn unboost(&self, t: TaskId, to: PiAttr) { self.cur.lock().unwrap()[t as usize] = to; }
    fn set_blocked_on(&self, t: TaskId, on: Option<WaitObj>) {
        self.on[t as usize].store(on.map_or(0, WaitObj::addr), Ordering::Relaxed);
    }
    fn blocked_on(&self, t: TaskId) -> Option<WaitObj> {
        WaitObj::from_addr(self.on[t as usize].load(Ordering::Relaxed))
    }
    fn on_cpu(&self, _t: TaskId) -> bool { false }
}

static S: Rec = Rec::new();
static G: Graph<N> = Graph::new();
static O: [PiWaiters; 48] = [const { PiWaiters::new(EdgeKind::Mutex) }; 48];

const RT: fn(u8) -> PiAttr = |p| PiAttr::Rt { prio: p };

/// A (1) owns O0, B (2) owns O1 and waits on O0, C (3) waits on O1.
fn chain() {
    S.set_base(1, PiAttr::Fair);
    S.set_base(2, RT(20));
    S.set_base(3, RT(5));
    G.set_owner(&O[0], Some(1));
    G.set_owner(&O[1], Some(2));
    G.block_on(2, &O[0]).unwrap();
    G.block_on(3, &O[1]).unwrap();
}

static S2: Rec = Rec::new();
static G2: Graph<N> = Graph::new();
static P: [PiWaiters; 4] = [const { PiWaiters::new(EdgeKind::Mutex) }; 4];

/// N7b, on a second graph (depth-independent, runs before the canary):
/// an ownerless enqueue boosts the next owner; `task_exit` detaches what a
/// dead owner still holds and takes a dead waiter off its object.
fn exit_and_ownerless() {
    G2.register_sched(&S2);
    // A newcomer queued on a released (ownerless) object: no NoOwner, no
    // boost yet; the taker inherits at `set_owner`.
    S2.set_base(1, PiAttr::Fair);
    S2.set_base(2, RT(3));
    assert_eq!(G2.block_on(2, &P[0]), Err(WaitError::NoOwner), "block_on must still refuse an ownerless object");
    G2.block_commit(G2.block_prepare_ownerless(2, &P[0]).unwrap()).unwrap();
    assert!(P[0].has_waiters() && S2.blocked_on(2).is_some(), "the held-back newcomer is not in the graph");
    G2.set_owner(&P[0], Some(1));
    assert_eq!(S2.cur(1), RT(3), "the taker did not inherit from the ownerless waiter");

    // Owner exits holding P0 with a waiter: P0 is detached (no dead owner
    // named), the waiter stays queued, the exit is counted.
    let orphaned = G2.stats().orphaned;
    G2.task_exit(1);
    assert_eq!(P[0].owner(), None, "a dead task still owns an object");
    assert!(P[0].has_waiters(), "the waiters of a dead owner were dropped");
    assert_eq!(G2.effective(1), None, "the dead owner's effective attribute survived");
    assert_eq!(G2.stats().orphaned, orphaned + 1);
    // The next taker re-links and inherits.
    S2.set_base(4, PiAttr::Fair);
    G2.set_owner(&P[0], Some(4));
    assert_eq!(S2.cur(4), RT(3));

    // A waiter torn down while parked: off the object, its owner walked
    // back to base.
    G2.task_exit(2);
    assert!(!P[0].has_waiters() && S2.blocked_on(2).is_none(), "a dead waiter is still queued");
    assert_eq!(S2.cur(4), PiAttr::Fair, "the owner kept a dead waiter's boost");
    assert_eq!(G2.effective(2), None);
    G2.task_exit(2); // idempotent
}

static S3: Rec = Rec::new();
static G3: Graph<N> = Graph::new();
static Q: [PiWaiters; 2] = [const { PiWaiters::new(EdgeKind::Mutex) }; 2];

/// Records each call and, like kmutex, hands the object to its top waiter
/// by calling back into the graph (the hook runs with the graph lock
/// dropped: a re-entry would deadlock otherwise).
struct DiedRec {
    calls: Mutex<Vec<(usize, TaskId)>>,
}
impl OwnerDiedHook for DiedRec {
    fn owner_died(&self, obj: &PiWaiters, dead: TaskId) {
        self.calls.lock().unwrap().push((obj as *const PiWaiters as usize, dead));
        assert_eq!(obj.owner(), None, "the hook saw the dead owner still recorded");
        let (top, _) = G3.top_waiter(obj).expect("the hook ran with no waiter queued");
        G3.unblock(top, obj, UnblockReason::OwnerDied);
        if obj.has_waiters() {
            G3.set_owner(obj, Some(top));
        }
    }
}
static DIED: DiedRec = DiedRec { calls: Mutex::new(Vec::new()) };

/// Owner decision 10-10: an owner that exits holding an object with
/// waiters makes the graph call the kind's OwnerDiedHook (EOWNERDEAD); the
/// canary `owner-died-silent` falls back to detach-only.
fn owner_died_hook() {
    G3.register_sched(&S3);
    G3.register_owner_died(EdgeKind::Mutex, &DIED);
    S3.set_base(1, PiAttr::Fair);
    S3.set_base(2, RT(3));
    S3.set_base(3, RT(9));
    G3.set_owner(&Q[0], Some(1));
    G3.block_on(2, &Q[0]).unwrap();
    G3.block_on(3, &Q[0]).unwrap();
    assert_eq!(S3.cur(1), RT(3));
    G3.task_exit(1);
    let calls = DIED.calls.lock().unwrap().clone();
    assert_eq!(calls, vec![(&Q[0] as *const PiWaiters as usize, 1)], "the hook was not called once for Q0");
    assert_eq!(G3.stats().owner_died, 1);
    assert_eq!(G3.stats().orphaned, 0);
    assert_eq!(Q[0].owner(), Some(2), "the top waiter did not take the dead owner's object");
    assert!(S3.blocked_on(2).is_none(), "the new owner is still blocked");
    assert_eq!(S3.cur(2), RT(3), "the new owner lost its own attribute");
    assert!(S3.blocked_on(3).is_some(), "the second waiter left too");

    // Canary: detach only, the hook is skipped and the waiter stays queued.
    canary_owner_died_silent(true);
    G3.task_exit(2);
    canary_owner_died_silent(false);
    assert_eq!(DIED.calls.lock().unwrap().len(), 1, "the canary did not skip the hook");
    assert_eq!(G3.stats().orphaned, 1);
    assert_eq!(Q[0].owner(), None);
    assert!(S3.blocked_on(3).is_some());

    // An object handed over before the exit (the robust walk's order) is
    // no longer the dead task's: no hook, no orphan.
    G3.set_owner(&Q[1], Some(4));
    G3.block_on(5, &Q[1]).unwrap();
    let _ = G3.release(4, &Q[1]);
    G3.unblock(5, &Q[1], UnblockReason::Acquired);
    G3.task_exit(4);
    assert_eq!(DIED.calls.lock().unwrap().len(), 1, "a handed-over object reached the hook");
    assert_eq!(G3.stats().orphaned, 1);
}

static S4: Rec = Rec::new();
static G4: Graph<N> = Graph::new();
static OL: [PiWaiters; 8] = [const { PiWaiters::new(EdgeKind::IpcCall) }; 8];
static O4M: PiWaiters = PiWaiters::new(EdgeKind::Mutex);

/// Wave 15 GIPC: `block_on_lazy`. The quiet call records only the edge;
/// every way it could come to matter materializes it.
fn lazy() {
    G4.register_sched(&S4);
    canary_lazy_no_materialize(false);
    let st = || G4.stats();
    // Quiet: fair caller 1 calls fair server 2. No walk, not in the list.
    G4.set_owner(&OL[0], Some(2));
    let s0 = st();
    G4.block_on_lazy(&S4, 1, &OL[0]).unwrap();
    assert_eq!(st().lazy_edges, s0.lazy_edges + 1, "a quiet call took the locked path");
    assert_eq!(st().walks, s0.walks, "a quiet call walked");
    assert_eq!(S4.blocked_on(1), Some(WaitObj::of(&OL[0])));
    assert!(!OL[0].has_waiters());
    G4.unblock_lazy(&S4, 1, &OL[0], UnblockReason::Acquired);
    assert!(S4.blocked_on(1).is_none());
    assert_eq!(st().walks, s0.walks, "a lazy unblock walked");
    // The locked unblock (exit, abort) of a lazy edge claims it too.
    G4.block_on_lazy(&S4, 1, &OL[0]).unwrap();
    G4.unblock(1, &OL[0], UnblockReason::ObjectGone);
    assert!(S4.blocked_on(1).is_none());
    G4.attr_changed(2);
    assert_eq!(st().materialized, s0.materialized, "a left lazy edge was materialized");

    // Boost case: an RT caller boosts its fair server, and gives it back.
    S4.set_base(3, RT(5));
    G4.block_on_lazy(&S4, 3, &OL[0]).unwrap();
    assert_eq!(st().lazy_edges, s0.lazy_edges + 2, "a boosting call was lazy");
    assert_eq!(S4.cur(2), RT(5), "the RT caller did not boost the server");
    G4.unblock_lazy(&S4, 3, &OL[0], UnblockReason::Acquired);
    assert_eq!(S4.cur(2), PiAttr::Fair);

    // The caller raised after its lazy call (a waiter on an object it owns):
    // the walk materializes the edge and reaches the server.
    let canary_hole_a = || {
        G4.block_on_lazy(&S4, 4, &OL[0]).unwrap();
        G4.set_owner(&OL[1], Some(4));
        S4.set_base(5, RT(3));
        G4.block_on(5, &OL[1]).unwrap();
        let got = (S4.cur(4), S4.cur(2));
        G4.unblock_lazy(&S4, 5, &OL[1], UnblockReason::Acquired);
        G4.unblock_lazy(&S4, 4, &OL[0], UnblockReason::Acquired);
        got
    };
    let m0 = st().materialized;
    assert_eq!(canary_hole_a(), (RT(3), RT(3)), "a raised lazy caller did not boost its server");
    assert_eq!(st().materialized, m0 + 1);
    assert_eq!((S4.cur(4), S4.cur(2)), (PiAttr::Fair, PiAttr::Fair), "a boost outlived its edge");

    // attr_changed of a lazy caller.
    G4.block_on_lazy(&S4, 6, &OL[0]).unwrap();
    S4.set_base(6, RT(4));
    G4.attr_changed(6);
    assert_eq!(S4.cur(2), RT(4), "attr_changed of a lazy caller did not boost its server");
    G4.unblock_lazy(&S4, 6, &OL[0], UnblockReason::Acquired);
    assert_eq!(S4.cur(2), PiAttr::Fair);
    S4.set_base(6, PiAttr::Fair);

    // attr_changed of the server under a lazy caller: lowered below it.
    S4.set_base(7, RT(10));
    S4.set_base(8, RT(20));
    G4.set_owner(&OL[2], Some(7));
    let l = st().lazy_edges;
    G4.block_on_lazy(&S4, 8, &OL[2]).unwrap();
    assert_eq!(st().lazy_edges, l + 1, "RT 20 calling RT 10 was not lazy");
    S4.set_base(7, PiAttr::Fair);
    G4.attr_changed(7);
    assert_eq!(S4.cur(7), RT(20), "a lowered server lost its lazy caller's priority");
    G4.unblock_lazy(&S4, 8, &OL[2], UnblockReason::Acquired);
    assert_eq!(S4.cur(7), PiAttr::Fair);

    // A new owner under a lazy waiter (a server slot reused): the waiter
    // joins the list and boosts the new owner.
    S4.set_base(13, RT(10));
    S4.set_base(14, PiAttr::Fair);
    S4.set_base(15, RT(20));
    G4.set_owner(&OL[7], Some(13));
    let l = st().lazy_edges;
    G4.block_on_lazy(&S4, 15, &OL[7]).unwrap();
    assert_eq!(st().lazy_edges, l + 1);
    G4.set_owner(&OL[7], Some(14));
    assert_eq!(S4.cur(14), RT(20), "a new owner missed its lazy waiter");
    G4.unblock_lazy(&S4, 15, &OL[7], UnblockReason::Acquired);
    assert_eq!(S4.cur(14), PiAttr::Fair);

    // The server exits under a lazy caller: the node is detached from the
    // dead slot as a listed one is (the caller's blocked_on still names it).
    S4.set_base(17, PiAttr::Fair);
    S4.set_base(18, PiAttr::Fair);
    G4.set_owner(&OL[1], Some(17));
    G4.block_on_lazy(&S4, 18, &OL[1]).unwrap();
    G4.task_exit(17);
    assert!(OL[1].owner().is_none(), "a dead server kept its lazily called node");
    assert_eq!(S4.blocked_on(18), Some(WaitObj::of(&OL[1])));
    G4.unblock_lazy(&S4, 18, &OL[1], UnblockReason::OwnerDied);
    assert!(S4.blocked_on(18).is_none() && !OL[1].has_waiters());

    // Only a lazy-capable kind takes a lazy edge.
    let l = st().lazy_edges;
    G4.set_owner(&O4M, Some(13));
    G4.block_on_lazy(&S4, 16, &O4M).unwrap();
    assert_eq!(st().lazy_edges, l, "a mutex waiter was recorded lazily");
    assert!(O4M.has_waiters());
    G4.unblock_lazy(&S4, 16, &O4M, UnblockReason::Acquired);

    // Cycles: the server blocking on its lazy caller's object, and a lazy
    // call to a server blocked on the caller's object, are both EDEADLK.
    G4.set_owner(&OL[3], Some(9));
    G4.set_owner(&OL[4], Some(10));
    G4.block_on_lazy(&S4, 10, &OL[3]).unwrap();
    assert_eq!(G4.block_on(9, &OL[4]), Err(WaitError::Deadlock));
    G4.unblock_lazy(&S4, 10, &OL[3], UnblockReason::Acquired);
    G4.set_owner(&OL[5], Some(11));
    G4.set_owner(&OL[6], Some(12));
    G4.block_on(11, &OL[6]).unwrap();
    assert_eq!(G4.block_on_lazy(&S4, 12, &OL[5]), Err(WaitError::Deadlock));
    assert!(S4.blocked_on(12).is_none(), "a refused lazy call kept its edge");
    G4.unblock_lazy(&S4, 11, &OL[6], UnblockReason::Acquired);

    // Canary (pi-lazy-no-materialize): the raised caller's server stays
    // unboosted. Bucket "fails when broken".
    canary_lazy_no_materialize(true);
    S4.set_base(5, RT(3));
    assert_eq!(canary_hole_a(), (RT(3), PiAttr::Fair), "the canary still materialized");
    canary_lazy_no_materialize(false);
    G4.task_exit(4);
}

static OQ: [PiWaiters; 3] = [const { PiWaiters::new(EdgeKind::IpcCall) }; 3];

/// Chain E (the IPC fast path under WAIT_GRAPH): `block_on_quiet` is
/// `block_on_lazy`'s quiet case and nothing else. Quiet: the same lazy edge.
/// Not quiet (a boost, an owner already blocked, no owner, a kind that takes
/// no lazy edge): `false`, no edge left, nothing boosted or walked.
/// `edge_is_quiet` tells a lazy edge (or none) from a listed one.
fn quiet() {
    let st = || G4.stats();
    for t in 20..=24 {
        S4.set_base(t, PiAttr::Fair);
    }
    G4.set_owner(&OQ[0], Some(21));
    let s0 = st();
    assert!(G4.block_on_quiet(&S4, 20, &OQ[0]), "a quiet call was refused");
    assert_eq!(st().lazy_edges, s0.lazy_edges + 1);
    assert_eq!(st().walks, s0.walks, "a quiet call walked");
    assert_eq!(S4.blocked_on(20), Some(WaitObj::of(&OQ[0])));
    assert!(!OQ[0].has_waiters() && G4.edge_is_quiet(&S4, 20));
    G4.unblock_lazy(&S4, 20, &OQ[0], UnblockReason::Acquired);
    assert!(S4.blocked_on(20).is_none() && G4.edge_is_quiet(&S4, 20));

    // A call that would boost: refused, no edge, the server not boosted.
    S4.set_base(22, RT(5));
    assert!(!G4.block_on_quiet(&S4, 22, &OQ[0]), "a boosting call was quiet");
    assert!(S4.blocked_on(22).is_none(), "a refused quiet call kept its edge");
    assert_eq!(S4.cur(21), PiAttr::Fair);
    assert_eq!((st().lazy_edges, st().walks), (s0.lazy_edges + 1, s0.walks), "a refused quiet call walked");
    // The same call through block_on_lazy is listed: not quiet any more.
    G4.block_on_lazy(&S4, 22, &OQ[0]).unwrap();
    assert!(!G4.edge_is_quiet(&S4, 22), "a listed edge read as quiet");
    G4.unblock_lazy(&S4, 22, &OQ[0], UnblockReason::Acquired);
    assert_eq!(S4.cur(21), PiAttr::Fair);

    // A server blocked on something (a chain to carry, a cycle to check).
    G4.set_owner(&OQ[1], Some(23));
    G4.block_on_lazy(&S4, 21, &OQ[1]).unwrap();
    assert!(!G4.block_on_quiet(&S4, 20, &OQ[0]), "a call to a blocked server was quiet");
    assert!(S4.blocked_on(20).is_none());
    G4.unblock_lazy(&S4, 21, &OQ[1], UnblockReason::Acquired);

    // No owner, and a kind that takes no lazy edge.
    assert!(!G4.block_on_quiet(&S4, 24, &OQ[2]));
    G4.set_owner(&O4M, Some(23));
    assert!(!G4.block_on_quiet(&S4, 24, &O4M), "a mutex waiter was recorded quietly");
    assert!(S4.blocked_on(24).is_none() && !O4M.has_waiters());
}

#[test]
fn wait_graph_stage1() {
    G.register_sched(&S);
    canary_cap_depth(0);
    lazy();
    quiet();
    exit_and_ownerless();
    owner_died_hook();

    // Transitive chain: A inherits C's attribute through B; each release
    // gives back exactly what it no longer earns.
    chain();
    assert_eq!(S.cur(2), RT(5), "B not boosted to C");
    assert_eq!(S.cur(1), RT(5), "A not boosted transitively to C");
    assert_eq!(G.release(1, &O[0]), Some(2));
    assert_eq!(S.cur(1), PiAttr::Fair, "A kept a boost after its release");
    G.set_owner(&O[0], Some(2));
    G.unblock(2, &O[0], UnblockReason::Acquired);
    assert_eq!(S.cur(2), RT(5), "B lost C's boost on acquiring O0");
    assert!(S.blocked_on(2).is_none() && !O[0].has_waiters());
    assert_eq!(G.release(2, &O[1]), Some(3));
    assert_eq!(S.cur(2), RT(20), "B kept C's boost after releasing O1");
    G.unblock(3, &O[1], UnblockReason::Acquired);
    assert_eq!(G.release(2, &O[0]), None);

    // A waiter leaving early (timeout) unboosts the chain.
    S.set_base(4, PiAttr::Fair);
    S.set_base(5, RT(7));
    G.set_owner(&O[2], Some(4));
    G.block_on(5, &O[2]).unwrap();
    assert_eq!(S.cur(4), RT(7));
    G.unblock(5, &O[2], UnblockReason::Timeout);
    assert_eq!(S.cur(4), PiAttr::Fair, "timeout left the owner boosted");

    // Cycle: D waits on E's object; E waiting on D's is EDEADLK and both
    // tasks are as they were.
    S.set_base(6, RT(30));
    S.set_base(7, RT(10));
    G.set_owner(&O[3], Some(6));
    G.set_owner(&O[4], Some(7));
    G.block_on(6, &O[4]).unwrap();
    let (d6, d7) = (S.cur(6), S.cur(7));
    let before = G.stats().deadlocks;
    assert_eq!(G.block_on(7, &O[3]), Err(WaitError::Deadlock));
    assert_eq!(WaitError::Deadlock.errno(), 35);
    assert_eq!(G.stats().deadlocks, before + 1);
    assert!(S.blocked_on(7).is_none() && !O[3].has_waiters(), "the refused block stayed enqueued");
    assert_eq!((S.cur(6), S.cur(7)), (d6, d7), "a refused block moved a priority");
    assert_eq!(G.block_on(6, &O[3]), Err(WaitError::SelfOwned));
    assert_eq!(G.block_on(6, &O[5]), Err(WaitError::NoOwner));
    G.unblock(6, &O[4], UnblockReason::Interrupted);

    // DL donor: the owner inherits the donor's absolute deadline.
    S.set_base(8, RT(30));
    S.set_base(9, PiAttr::Dl { deadline_ns: 1_000 });
    G.set_owner(&O[6], Some(8));
    G.block_on(9, &O[6]).unwrap();
    assert_eq!(S.cur(8), PiAttr::Dl { deadline_ns: 1_000 });
    assert_eq!(G.top_waiter(&O[6]), Some((9, PiAttr::Dl { deadline_ns: 1_000 })));
    // A more urgent waiter goes first; FIFO among equals.
    S.set_base(10, PiAttr::Dl { deadline_ns: 500 });
    G.block_on(10, &O[6]).unwrap();
    assert_eq!(G.top_waiter(&O[6]).map(|w| w.0), Some(10));
    assert_eq!(S.cur(8), PiAttr::Dl { deadline_ns: 500 });

    // attr_changed of a waiter re-boosts the owner (and re-sorts it).
    S.set_base(11, PiAttr::Fair);
    S.set_base(12, RT(40));
    G.set_owner(&O[7], Some(11));
    G.block_on(12, &O[7]).unwrap();
    assert_eq!(S.cur(11), RT(40));
    S.set_base(12, RT(3));
    G.attr_changed(12);
    assert_eq!(S.cur(11), RT(3), "attr_changed of a waiter did not re-boost its owner");
    S.set_base(12, RT(60));
    G.attr_changed(12);
    assert_eq!(S.cur(11), RT(60), "a waiter's lowered attribute left the owner over-boosted");
    // The scheduler writes a new base over a live boost: put back.
    S.set_base(11, PiAttr::Fair);
    G.attr_changed(11);
    assert_eq!(S.cur(11), RT(60), "attr_changed of a boosted owner dropped its boost");

    // Depth cap: a chain PI_MAX_DEPTH owners long is boosted to its end;
    // one more link stops boosting there and is counted.
    let depth = |links: usize, first: u32, obj0: usize| {
        for k in 0..=links as u32 {
            S.set_base(first + k, PiAttr::Fair);
        }
        for k in 0..links {
            G.set_owner(&O[obj0 + k], Some(first + k as u32));
        }
        for k in 1..links {
            G.block_on(first + k as u32, &O[obj0 + k - 1]).unwrap();
        }
        S.set_base(first + links as u32, RT(1));
        G.block_on(first + links as u32, &O[obj0 + links - 1]).unwrap();
    };
    let capped = G.stats().depth_capped;
    depth(PI_MAX_DEPTH, 13, 8);
    assert_eq!(S.cur(13), RT(1), "a chain PI_MAX_DEPTH long was not boosted to its end");
    assert_eq!(G.stats().depth_capped, capped, "a chain exactly at the cap was counted");
    let t0 = 13 + PI_MAX_DEPTH as u32 + 1;
    assert!((t0 as usize) + PI_MAX_DEPTH + 2 <= 60 && 8 + 2 * PI_MAX_DEPTH + 1 <= 46, "raise N and O for this PI_MAX_DEPTH");
    depth(PI_MAX_DEPTH + 1, t0, 8 + PI_MAX_DEPTH);
    assert_eq!(G.stats().depth_capped, capped + 1, "the depth cap was not counted");
    assert_eq!(S.cur(t0), PiAttr::Fair, "a walk boosted past PI_MAX_DEPTH");
    assert_eq!(S.cur(t0 + 1), RT(1));

    // Canary (canary=pi-depth-1): one step per walk, the chain's root is
    // not boosted. Bucket "fails when broken" for the first scenario.
    canary_cap_depth(1);
    S.set_base(60, PiAttr::Fair);
    S.set_base(61, PiAttr::Fair);
    S.set_base(62, RT(2));
    G.set_owner(&O[46], Some(60));
    G.set_owner(&O[47], Some(61));
    G.block_on(61, &O[46]).unwrap();
    G.block_on(62, &O[47]).unwrap();
    assert_eq!(S.cur(61), RT(2));
    assert_eq!(S.cur(60), PiAttr::Fair, "the depth-1 canary still boosted transitively");
    canary_cap_depth(0);
}

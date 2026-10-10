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

#[test]
fn wait_graph_stage1() {
    G.register_sched(&S);
    canary_cap_depth(0);

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

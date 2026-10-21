// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! S3: a wait that would close a cycle of owners is refused in every build
//! (the check is not tied to a debug or lockdep build) and leaves a
//! `wait-cycle` decision record. Two real `kmutex::Mutex` nodes on a private
//! `Graph` driven by a recording scheduler (the kernel's instance cannot run
//! on the host: host threads share one TID). Its own test binary: the
//! decision ring and the canary are process globals, and the graph lock moves
//! the host preempt counter. One test function.

use azos_decision::{lookup, query, Filter, Rule, Verdict};
use azos_sync_tests::kmutex::Mutex;
use azos_sync_tests::waitgraph::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const N: usize = 8;

struct Sched {
    on: [AtomicUsize; N],
}

impl SchedPi for Sched {
    fn base_attr(&self, _t: TaskId) -> PiAttr { PiAttr::Fair }
    fn boost(&self, _t: TaskId, _to: PiAttr) {}
    fn unboost(&self, _t: TaskId, _to: PiAttr) {}
    fn set_blocked_on(&self, t: TaskId, on: Option<WaitObj>) {
        self.on[t as usize].store(on.map_or(0, WaitObj::addr), Ordering::Relaxed);
    }
    fn blocked_on(&self, t: TaskId) -> Option<WaitObj> {
        WaitObj::from_addr(self.on[t as usize].load(Ordering::Relaxed))
    }
    fn on_cpu(&self, _t: TaskId) -> bool { false }
}

static S: Sched = Sched { on: [const { AtomicUsize::new(0) }; N] };
static G: Graph<N> = Graph::new();
static M1: Mutex<u32> = Mutex::new(0);
static M2: Mutex<u32> = Mutex::new(0);
static M3: Mutex<u32> = Mutex::new(0);

fn records() -> Vec<azos_decision::ProvenanceRecord> {
    let f = Filter { rule: Some(Rule::WaitCycle as u8), verdict: None, subject: None, after: 0 };
    let mut ids = [0u64; 16];
    let n = query(&f, &mut ids);
    ids[..n].iter().filter_map(|&i| lookup(i)).collect()
}

#[test]
fn deadlock_refused_with_record() {
    G.register_sched(&S);
    // Task 1 holds M1 and task 2 holds M2 (the graph's owner record, which
    // the real `Mutex` sets lazily at the first waiter).
    G.set_owner(M1.wait_node(), Some(1));
    G.set_owner(M2.wait_node(), Some(2));
    assert!(records().is_empty());

    // Task 1 waits on M2 (owned by task 2): fine, task 2 is not blocked.
    G.block_on(1, M2.wait_node()).expect("a wait behind a running owner");
    let before = G.stats().deadlocks;

    // Task 2 waits on M1 (owned by task 1, who waits on M2, owned by task
    // 2): the second wait is refused, and nothing of it is left behind.
    assert_eq!(G.block_on(2, M1.wait_node()), Err(WaitError::Deadlock));
    assert_eq!(WaitError::Deadlock.errno(), 35, "EDEADLK");
    assert_eq!(G.stats().deadlocks, before + 1);
    assert!(S.blocked_on(2).is_none() && !M1.wait_node().has_waiters(), "the refused wait stayed enqueued");
    assert_eq!(G.top_waiter(M2.wait_node()).map(|(t, _)| t), Some(1), "the first wait was disturbed");

    // The decision record: the refusal, the waiter, the object's kind, the
    // task that closes the cycle and the links followed.
    let r = records();
    assert_eq!(r.len(), 1, "one refusal, one record");
    assert_eq!((r[0].rule, r[0].verdict, r[0].subject), (Rule::WaitCycle as u8, Verdict::Refuse as u8, 2));
    assert_eq!(r[0].n, [EdgeKind::Mutex as u64, 2, 2]);
    let info = &azos_decision::RULES[Rule::WaitCycle as usize];
    assert_eq!((info.name, info.fields), ("wait-cycle", ["kind", "owner", "links"]));

    // A ring of three: 1 waits on M2 (task 2), 2 waits on M3 (task 3), and
    // 3 waiting on M1 (task 1) would close it.
    G.set_owner(M3.wait_node(), Some(3));
    G.block_on(2, M3.wait_node()).expect("2 waits on 3");
    assert_eq!(G.block_on(3, M1.wait_node()), Err(WaitError::Deadlock), "3 -> 1 -> 2 -> 3");
    let r = records();
    assert_eq!(r.len(), 2);
    assert_eq!((r[1].subject, r[1].n[1], r[1].n[2]), (3, 3, 3));

    // Canary (canary=wait-cycle-unchecked): the check reports nothing, so
    // the same wait is accepted and the task would sleep for good.
    canary_no_cycle_check(true);
    let n = G.stats().deadlocks;
    let accepted = G.block_on(3, M1.wait_node());
    canary_no_cycle_check(false);
    assert_eq!(accepted, Ok(()), "canary: the unchecked wait was still refused");
    assert_eq!(G.stats().deadlocks, n, "canary: a refusal was counted");
    assert_eq!(records().len(), 2, "canary: a refusal left a record");
}

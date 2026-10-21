// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! S3, the kernel-mutex path: two tasks that take two real `kmutex::Mutex`es
//! in opposite order (ABBA) close a cycle in the wait graph. The task whose
//! wait closes it gets `Err(Deadlock)` from `Mutex::lock_checked` and holds
//! nothing of the refused wait; `Mutex::lock` (infallible) panics on the same
//! refusal; both leave a `wait-cycle` record. Real threads act as tasks (the
//! thread-local TID answers `caller_tid`); a thread "sleeps" on a flag that
//! `wake` sets. The kernel's own graph is the one in use. Its own test
//! binary: the graph, the probes and the decision ring are process globals.

use azos_decision::{lookup, query, Filter, Rule, Verdict};
use azos_sync_tests::kmutex::{set_probes, Mutex, Probes};
use azos_sync_tests::waitgraph::*;
use azos_sync_tests::waitqueue::wq_set_callbacks;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

thread_local! { static TID: Cell<u32> = const { Cell::new(u32::MAX) }; }
static WOKEN: [AtomicBool; N] = [const { AtomicBool::new(false) }; N];

fn tid() -> u32 { TID.with(Cell::get) }
fn block() {
    let me = tid() as usize;
    // A sleep nothing wakes is the deadlock itself: fail the test, not hang.
    let t0 = std::time::Instant::now();
    while !WOKEN[me].swap(false, Ordering::AcqRel) {
        assert!(t0.elapsed().as_secs() < 5, "task {me} slept for good: the cycle was accepted");
        std::thread::yield_now();
    }
}
fn wake(t: u32) { WOKEN[t as usize].store(true, Ordering::Release); }

fn graph_id(t: u32) -> Option<TaskId> { (t < N as u32).then_some(t as TaskId) }
fn attr(_t: u32) -> Option<PiAttr> { Some(PiAttr::Fair) }
fn on_cpu(_w: u32) -> bool { false }
static PROBES: Probes = Probes { on_cpu, graph_id, attr };

static M1: Mutex<u32> = Mutex::new(0);
static M2: Mutex<u32> = Mutex::new(0);
static M3: Mutex<u32> = Mutex::new(0);
static M4: Mutex<u32> = Mutex::new(0);

fn records() -> Vec<azos_decision::ProvenanceRecord> {
    let f = Filter { rule: Some(Rule::WaitCycle as u8), verdict: None, subject: None, after: 0 };
    let mut ids = [0u64; 16];
    let n = query(&f, &mut ids);
    ids[..n].iter().filter_map(|&i| lookup(i)).collect()
}

fn spin_until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..2_000_000 {
        if f() { return; }
        std::thread::yield_now();
    }
    panic!("timed out waiting for {what}");
}

/// Run `f` as task `t` on its own thread.
fn task<R: Send + 'static>(t: u32, f: impl FnOnce() -> R + Send + 'static)
    -> std::thread::JoinHandle<R>
{
    std::thread::spawn(move || { TID.with(|c| c.set(t)); f() })
}

/// ABBA on `(a, b)`: task `t1` holds `a`, task `t2` holds `b`; `t1` waits for
/// `b` (fine: `t2` runs), then `t2` asks for `a` through `second`, closing
/// the cycle. Returns what `second` answered (`Err`: it panicked). `t2` then
/// lets `b` go and `t1` must get it: the refused wait disturbed nothing.
fn abba(a: &'static Mutex<u32>, b: &'static Mutex<u32>, t1: u32, t2: u32,
        second: fn(&'static Mutex<u32>) -> Option<WaitError>)
    -> std::thread::Result<Option<WaitError>>
{
    use std::sync::Arc;
    let t1_has_a = Arc::new(AtomicBool::new(false));
    let t2_has_b = Arc::new(AtomicBool::new(false));
    let t1_done = Arc::new(AtomicBool::new(false));
    let h1 = {
        let (t1_has_a, t2_has_b, t1_done) = (t1_has_a.clone(), t2_has_b.clone(), t1_done.clone());
        task(t1, move || {
            let ga = a.lock();
            t1_has_a.store(true, Ordering::SeqCst);
            spin_until("t2 holds b", || t2_has_b.load(Ordering::SeqCst));
            let gb = b.lock(); // sleeps behind t2 until t2 lets b go
            t1_done.store(true, Ordering::SeqCst);
            drop(gb);
            drop(ga);
        })
    };
    let h2 = task(t2, move || {
        spin_until("t1 holds a", || t1_has_a.load(Ordering::SeqCst));
        let gb = b.lock();
        t2_has_b.store(true, Ordering::SeqCst);
        spin_until("t1 queued on b", || b.wait_node().has_waiters());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| second(a)));
        drop(gb); // wakes t1
        r
    });
    let r = h2.join().expect("task 2 thread");
    h1.join().expect("task 1 thread");
    assert!(t1_done.load(Ordering::SeqCst), "t1 never got b after t2 let it go");
    assert!(!a.is_locked() && !b.is_locked());
    r
}

#[test]
fn kernel_mutex_abba_returns_deadlock_and_lock_panics() {
    register_sched(&S);
    set_probes(&PROBES);
    wq_set_callbacks(block, wake, tid);
    assert!(records().is_empty());

    // lock_checked: the caller gets EDEADLK and holds nothing.
    let r = abba(&M1, &M2, 1, 2, |a| a.lock_checked().err());
    assert_eq!(r.expect("lock_checked panicked"), Some(WaitError::Deadlock));
    let rec = records();
    assert_eq!(rec.len(), 1, "one refusal, one record");
    assert_eq!((rec[0].rule, rec[0].verdict, rec[0].subject), (Rule::WaitCycle as u8, Verdict::Refuse as u8, 2));
    assert!(S.blocked_on(2).is_none(), "the refused wait stayed registered");

    // lock: the same refusal is a kernel bug and panics (record written).
    let r = abba(&M3, &M4, 3, 4, |a| { let _g = a.lock(); None });
    assert!(r.is_err(), "Mutex::lock returned from a refused wait");
    let rec = records();
    assert_eq!(rec.len(), 2);
    assert_eq!((rec[1].subject, rec[1].verdict), (4, Verdict::Refuse as u8));
}

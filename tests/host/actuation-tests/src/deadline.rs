// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for deadline-or-safe-state (innovation B2): the admission
//! in `effect_gate.rs`, the watch, the sweep and the compensation in
//! `safe_state.rs`, both pulled in with `#[path]` over the real flight
//! recorder and the real decision journal.
//!
//! The device is a model with two hosts:
//!
//! * **kernel-hosted**: the device op is a direct call in the caller's
//!   context. "Stalled" means the call does not come back; the watchdog's
//!   pass runs on another hart while it is stuck. The model has the op itself
//!   advance the clock and run the pass, which is the same interleaving made
//!   deterministic.
//! * **ring-3-hosted**: the driver is another task; the op waits for its
//!   reply. "Stalled" means the reply does not come: a real thread blocks on
//!   a channel while the test plays the watchdog, one pass every 500 ms of
//!   test time. The kernel drives the device through its own hold on it
//!   (`MockDevice::drive`), never through the driver, which the test checks.
//!
//! The properties and the test that holds each:
//!
//! * an unreachable deadline is refused with a receipt before anything is
//!   recorded or issued; the boundary is admitted; a stop is never refused:
//!   `an_unreachable_deadline_is_refused_with_a_receipt_and_nothing_is_issued`;
//! * a stalled kernel-hosted driver reaches the safe state with ONE record:
//!   `a_stalled_kernel_hosted_driver_reaches_its_safe_state_with_one_record`;
//! * a stalled ring-3 driver reaches it within `deadline + one pass`, with
//!   ONE record, and the driver is never asked:
//!   `a_stalled_ring3_driver_reaches_its_safe_state_within_one_pass`;
//! * the completion and the sweep never both record, over 300 races:
//!   `a_missed_deadline_is_handled_by_exactly_one_party`;
//! * the device then takes stops only, and no stop lifts the hold:
//!   `a_held_device_takes_stops_only_and_a_stop_does_not_release_it`;
//! * a full watch table refuses (fail closed): `a_full_watch_table_refuses_the_effect`;
//! * a failed effect is compensated, with a record either way:
//!   `a_failed_effect_is_compensated_by_the_kernel`.
//!
//! **Canaries** (the repository's host gate rows are cargo features of the
//! code under test; these three are mutations, run by hand and not shipped as
//! features): deleting the admission comparison in `issue` fails the first
//! test; making `sweep` skip `handle_miss` fails the kernel and ring-3 tests;
//! deleting the `compensate` call in `issue` fails the compensation test.

use crate::effect_gate::{self, Class, Effect, Timing, Why, KIND_MOTOR};
use crate::logger::*;
use crate::safe_state::{self, CAUSE_DEADLINE, CAUSE_HELD, COMP_NO_INVERSE, COMP_RAN, COMP_REFUSED, STATE_COMMANDED, STATE_SAFE};
use crate::tests::{effect, fresh};
use azos_decision::{Record, Rule, Verdict};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

const MS: u64 = 10_000; // timer ticks per millisecond (the shim's 10 MHz)
const T0: u64 = 1_000_000_000;

/// The op codes the model device understands (a kind's driver defines them).
const OP_COAST: u8 = 1;
const OP_STOP: u8 = 2;
/// An op the model refuses (a device with no such state).
const OP_UNSUPPORTED: u8 = 99;

/// What the kernel did to the model device, in order: `(what, subject, op)`.
static LOG: Mutex<Vec<(&'static str, u16, u8)>> = Mutex::new(Vec::new());
/// The model device's state: 0 running, 1 in its safe state.
static DEVICE_SAFE: AtomicBool = AtomicBool::new(false);
/// The ring-3 driver was asked to do something (it must never be, to reach a
/// safe state).
static DRIVER_ASKED: AtomicU32 = AtomicU32::new(0);

fn mock_safe(subject: u16, op: u8) -> bool {
    LOG.lock().unwrap_or_else(|e| e.into_inner()).push(("safe", subject, op));
    if op == OP_UNSUPPORTED {
        return false;
    }
    DEVICE_SAFE.store(true, Ordering::SeqCst);
    true
}

fn mock_comp(subject: u16, op: u8) -> bool {
    LOG.lock().unwrap_or_else(|e| e.into_inner()).push(("comp", subject, op));
    op != OP_UNSUPPORTED
}

fn log() -> Vec<(&'static str, u16, u8)> {
    LOG.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn count(what: &str) -> usize {
    log().iter().filter(|(w, _, _)| *w == what).count()
}

/// Puts the clock and the model back, and registers the model driver.
struct Scene;

impl Scene {
    fn new() -> Scene {
        LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
        DEVICE_SAFE.store(false, Ordering::SeqCst);
        DRIVER_ASKED.store(0, Ordering::SeqCst);
        safe_state::register(KIND_MOTOR, mock_safe, mock_comp, |_| true);
        azos_drv_sys::clint::set_test_time(T0);
        // Nothing held or watched from an earlier test.
        safe_state::clear_holds_for_test();
        assert_eq!(safe_state::watching(), 0, "an earlier test left a watch armed");
        Scene
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_drv_sys::clint::clear_test_time();
    }
}

fn at(t: u64) {
    azos_drv_sys::clint::set_test_time(t);
}

/// Decision records of `rule` written after sequence `base`.
fn records(base: u64, rule: Rule) -> Vec<Record> {
    let mut out = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq > base && r.rule == rule as u8 {
            out.push(*r);
        }
    });
    out
}

const EFFECT_WORD: u64 = (KIND_MOTOR as u64) << 8 | Class::Reversible as u64;
const DEVICE_ID: u32 = (KIND_MOTOR as u32) << 16 | 1;

/// A kernel-hosted motor: 2 ms deadline, a 200 us server bound, 500 us to commit.
fn kernel_timing() -> Timing {
    Timing { deadline_ns: 2_000_000, placement_ns: 200_000, commit_ns: 500_000, safe_op: OP_COAST, compensate_op: OP_STOP }
}

/// The same op on a ring-3 driver: its row's call budget is the placement.
fn ring3_timing() -> Timing {
    Timing { placement_ns: 800_000, ..kernel_timing() }
}

#[test]
fn an_unreachable_deadline_is_refused_with_a_receipt_and_nothing_is_issued() {
    let _g = fresh();
    let _s = Scene::new();
    let base = azos_decision::total();
    let queued = logger_ring_len();
    let ran = AtomicU32::new(0);
    let op = || { ran.fetch_add(1, Ordering::SeqCst); ((), true) };

    // 1.5 ms of placement and 1 ms to commit cannot meet 2 ms.
    let t = Timing { deadline_ns: 2_000_000, placement_ns: 1_500_000, commit_ns: 1_000_000, ..kernel_timing() };
    let r = effect_gate::issue(&effect(Class::Reversible, 1), &t, op);
    let Err(refusal) = r else { panic!("an unreachable deadline was admitted") };
    assert_eq!(refusal.why, Why::Deadline);
    assert_eq!(ran.load(Ordering::SeqCst), 0, "a refused effect reached the device");
    assert_eq!(logger_ring_len(), queued, "a refused effect left a record on the ring");
    assert_eq!(safe_state::watching(), 0, "a refused effect left a watch armed");
    let rec = azos_decision::lookup(refusal.receipt).expect("the receipt is a decision record");
    assert_eq!(rec.rule, Rule::EffectDeadline as u8);
    assert_eq!(rec.verdict, Verdict::Refuse as u8);
    assert_eq!((rec.subject, rec.n), (7, [EFFECT_WORD, 2_000_000, 2_500_000]));
    assert_eq!(records(base, Rule::EffectDeadline).len(), 1);

    // Exactly the deadline is admitted; one nanosecond short is not.
    let exact = Timing { deadline_ns: 1_700_000, placement_ns: 1_200_000, commit_ns: 500_000, ..kernel_timing() };
    effect_gate::issue(&effect(Class::Reversible, 2), &exact, op).expect("needed == deadline fits");
    let short = Timing { deadline_ns: 1_699_999, ..exact };
    assert!(effect_gate::issue(&effect(Class::Reversible, 3), &short, op).is_err());

    // No deadline declared: nothing to check, whatever the device needs.
    let none = Timing { deadline_ns: 0, commit_ns: u64::MAX, ..kernel_timing() };
    effect_gate::issue(&effect(Class::Reversible, 4), &none, op).expect("no deadline, no admission");

    // A stop is never refused, impossible timing or not.
    effect_gate::issue(&effect(Class::Safe, 5), &t, op).expect("a stop is never refused");
    assert_eq!(ran.load(Ordering::SeqCst), 3);
    assert_eq!(safe_state::watching(), 0);
}

#[test]
fn a_stalled_kernel_hosted_driver_reaches_its_safe_state_with_one_record() {
    let _g = fresh();
    let _s = Scene::new();
    let base = azos_decision::total();
    let t = kernel_timing();

    let mut swept = 0;
    let r = effect_gate::issue(&effect(Class::Reversible, 1), &t, || {
        // The op does not come back. 2 ms and a tick later the watchdog's
        // pass, on another hart, finds the watch overdue.
        assert_eq!(safe_state::watching(), 1);
        at(T0 + 2 * MS + 1);
        swept = safe_state::sweep(T0 + 2 * MS + 1);
        assert!(DEVICE_SAFE.load(Ordering::SeqCst), "the pass did not reach the safe state");
        // ... and later it does come back: it may have written after the drive.
        ((), true)
    });
    r.expect("the effect was admitted");
    assert_eq!(swept, 1);
    let recs = records(base, Rule::SafeState);
    assert_eq!(recs.len(), 1, "one miss, one record");
    assert_eq!(recs[0].verdict, Verdict::Admit as u8);
    assert_eq!((recs[0].subject, recs[0].n), (DEVICE_ID, [STATE_COMMANDED, STATE_SAFE, 7 << 8 | CAUSE_DEADLINE]));
    // The kernel drove it once in the pass and once more when the stalled op
    // finally returned (its last write may have landed after the first).
    assert_eq!(log(), vec![("safe", 1, OP_COAST), ("safe", 1, OP_COAST)]);
    assert!(safe_state::held(KIND_MOTOR, 1));
    assert_eq!(safe_state::watching(), 0);

    // An op that returns late without any pass having run: the caller finds
    // its own watch overdue and drives AFTER its op, one record.
    safe_state::clear_holds_for_test();
    LOG.lock().unwrap().clear();
    DEVICE_SAFE.store(false, Ordering::SeqCst);
    let base = azos_decision::total();
    effect_gate::issue(&effect(Class::Reversible, 2), &t, || {
        at(T0 + 10 * MS);
        assert!(!DEVICE_SAFE.load(Ordering::SeqCst), "driven before the op returned");
        ((), true)
    }).expect("admitted");
    assert!(DEVICE_SAFE.load(Ordering::SeqCst));
    assert_eq!(records(base, Rule::SafeState).len(), 1);
    assert_eq!(log(), vec![("safe", 1, OP_COAST)]);
}

#[test]
fn a_stalled_ring3_driver_reaches_its_safe_state_within_one_pass() {
    const PASS: u64 = 500 * MS;
    let t = ring3_timing();
    // The watchdog's phase against the effect's start: the first pass after
    // the deadline falls anywhere in a pass period.
    for phase_ms in [0u64, 1, 3, 77, 250, 499] {
        let _g = fresh();
        let _s = Scene::new();
        let base = azos_decision::total();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let e = effect(Class::Reversible, 9);
        let worker = std::thread::spawn(move || {
            // The reply from the driver: never, until the test says so.
            effect_gate::issue(&e, &t, || { started_tx.send(()).unwrap(); rx.recv().unwrap(); ((), true) })
        });
        // The op is running: the watch is ARMED with its deadline. Waiting on
        // `watching()` alone sees the slot while it is still CLAIMED, and a pass
        // swept then skips it.
        started_rx.recv().unwrap();
        assert_eq!(safe_state::watching(), 1);

        let mut reached: Option<u64> = None;
        let mut now = T0;
        let mut next_pass = T0 + phase_ms * MS + 1;
        while reached.is_none() && now < T0 + 2 * PASS {
            now = next_pass;
            at(now);
            safe_state::sweep(now);
            if DEVICE_SAFE.load(Ordering::SeqCst) {
                reached = Some(now);
            }
            next_pass += PASS;
        }
        let reached = reached.expect("a stalled driver never reached the safe state");
        let deadline = T0 + t.deadline_ns / 100; // ns to 100 ns ticks
        assert!(reached > deadline, "driven before the deadline (phase {phase_ms})");
        assert!(reached <= deadline + PASS, "phase {phase_ms}: reached {} ticks after the deadline, one pass is {PASS}", reached - deadline);
        assert_eq!(DRIVER_ASKED.load(Ordering::SeqCst), 0, "the stalled driver was asked to stop itself");
        assert_eq!(records(base, Rule::SafeState).len(), 1);
        // Later passes do not repeat it.
        safe_state::sweep(now + PASS);
        safe_state::sweep(now + 2 * PASS);
        assert_eq!(records(base, Rule::SafeState).len(), 1, "a later pass recorded the same miss again");
        assert_eq!(count("safe"), 1);

        // The driver finally answers; the caller's op has landed late, so the
        // device is driven once more, silently.
        tx.send(()).unwrap();
        worker.join().unwrap().expect("admitted");
        assert_eq!(records(base, Rule::SafeState).len(), 1);
        assert_eq!(count("safe"), 2);
        assert_eq!(safe_state::watching(), 0);
    }
}

#[test]
fn an_effect_that_commits_in_time_leaves_no_trace() {
    let _g = fresh();
    let _s = Scene::new();
    let base = azos_decision::total();
    effect_gate::issue(&effect(Class::Reversible, 1), &kernel_timing(), || {
        assert_eq!(safe_state::watching(), 1);
        at(T0 + 2 * MS); // exactly the deadline is still in time
        ((), true)
    }).expect("admitted");
    assert_eq!(safe_state::watching(), 0);
    assert_eq!(safe_state::sweep(T0 + 100 * MS), 0, "a completed watch was swept");
    assert!(!safe_state::held(KIND_MOTOR, 1));
    assert!(log().is_empty());
    assert!(records(base, Rule::SafeState).is_empty());
    assert!(records(base, Rule::Compensation).is_empty());
}

#[test]
fn a_missed_deadline_is_handled_by_exactly_one_party() {
    let _g = fresh();
    let _s = Scene::new();
    let stop = AtomicBool::new(false);
    let t = kernel_timing();
    let mut total_records = 0;
    /// Stops the pass thread when the loop ends, panicking or not (the scope
    /// would otherwise wait for it for ever).
    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    std::thread::scope(|sc| {
        let _stop = Stop(&stop);
        // The watchdog's pass, as fast as it can go.
        sc.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                safe_state::sweep(T0 + 10 * MS);
            }
        });
        for i in 0..300u32 {
            safe_state::clear_holds_for_test();
            at(T0);
            let base = azos_decision::total();
            effect_gate::issue(&effect(Class::Reversible, i), &t, || {
                // Overdue, with the pass spinning on the other thread.
                at(T0 + 10 * MS);
                std::thread::yield_now();
                ((), true)
            }).expect("admitted");
            // The pass may still be writing its record when the caller is
            // back; its slot is busy until it has.
            while safe_state::watching() != 0 {
                std::thread::yield_now();
            }
            let n = records(base, Rule::SafeState).len();
            assert_eq!(n, 1, "iteration {i}: {n} records for one missed effect");
            total_records += n;
            // Each committed effect record is pinned until the flusher takes it.
            logger_flusher_pass();
        }
    });
    assert_eq!(total_records, 300);
}

#[test]
fn a_held_device_takes_stops_only_and_a_stop_does_not_release_it() {
    let _g = fresh();
    let _s = Scene::new();
    let t = kernel_timing();
    effect_gate::issue(&effect(Class::Reversible, 1), &t, || { at(T0 + 5 * MS); ((), true) }).unwrap();
    assert!(safe_state::held(KIND_MOTOR, 1));
    assert!(!safe_state::held(KIND_MOTOR, 0), "another wheel is held too");

    // A motion op on the held wheel is refused with a SafeState receipt, and
    // nothing of it reaches the ring or the device.
    at(T0);
    let base = azos_decision::total();
    let queued = logger_ring_len();
    let r = effect_gate::issue(&effect(Class::Reversible, 2), &t, || -> ((), bool) { panic!("a held device was commanded") });
    let Err(refusal) = r else { panic!("a held device took a motion op") };
    assert_eq!(refusal.why, Why::Held);
    let rec = azos_decision::lookup(refusal.receipt).unwrap();
    assert_eq!((rec.rule, rec.verdict), (Rule::SafeState as u8, Verdict::Refuse as u8));
    assert_eq!((rec.subject, rec.n), (DEVICE_ID, [STATE_SAFE, STATE_COMMANDED, 7 << 8 | CAUSE_HELD]));
    assert_eq!(logger_ring_len(), queued);
    assert_eq!(records(base, Rule::SafeState).len(), 1);

    // The other wheel is unaffected.
    let other = Effect { subject: 0, ..effect(Class::Reversible, 3) };
    effect_gate::issue(&other, &t, || ((), true)).expect("a held wheel held its neighbour");

    // A stop, failed or landed, does not release it (owner decision 16-10):
    // only `safe_state::release` does (`held.rs`).
    effect_gate::issue(&effect(Class::Safe, 4), &t, || ((), false)).expect("a stop is never refused");
    assert!(safe_state::held(KIND_MOTOR, 1), "a failed stop released a device");
    effect_gate::issue(&effect(Class::Safe, 5), &t, || ((), true)).expect("a stop is never refused");
    assert!(safe_state::held(KIND_MOTOR, 1), "a stop released a device");
    assert!(effect_gate::issue(&effect(Class::Reversible, 6), &t, || -> ((), bool) { panic!("a held device was commanded") }).is_err());
}

#[test]
fn a_full_watch_table_refuses_the_effect() {
    let _g = fresh();
    let _s = Scene::new();
    let e = effect(Class::Reversible, 1);
    let mut held = Vec::new();
    while let Some(k) = safe_state::arm(&e, 2_000_000, OP_COAST) {
        held.push(k);
        assert!(held.len() <= 64);
    }
    assert!(!held.is_empty());
    let queued = logger_ring_len();
    let r = effect_gate::issue(&e, &kernel_timing(), || -> ((), bool) { panic!("an effect that cannot be watched was issued") });
    assert_eq!(r.err().map(|x| x.why), Some(Why::NoWatch));
    assert_eq!(logger_ring_len(), queued, "an effect that could not be watched was recorded");
    // A stop needs no watch.
    effect_gate::issue(&effect(Class::Safe, 2), &kernel_timing(), || ((), true)).expect("a stop is never refused");
    // An effect with no deadline needs none either.
    effect_gate::issue(&e, &Timing { deadline_ns: 0, ..kernel_timing() }, || ((), true)).expect("unwatched");
    for k in held {
        safe_state::cancel(k);
    }
    assert_eq!(safe_state::watching(), 0);
    effect_gate::issue(&e, &kernel_timing(), || ((), true)).expect("a free slot admits again");
}

#[test]
fn a_failed_effect_is_compensated_by_the_kernel() {
    let _g = fresh();
    let _s = Scene::new();
    let t = kernel_timing();

    // Took: nothing to undo.
    let base = azos_decision::total();
    effect_gate::issue(&effect(Class::Reversible, 1), &t, || ((), true)).unwrap();
    assert!(log().is_empty() && records(base, Rule::Compensation).is_empty());

    // Failed, the row declares an inverse: the kernel runs it, one record.
    effect_gate::issue(&effect(Class::Reversible, 2), &t, || ((), false)).unwrap();
    assert_eq!(log(), vec![("comp", 1, OP_STOP)]);
    let recs = records(base, Rule::Compensation);
    assert_eq!(recs.len(), 1);
    assert_eq!((recs[0].verdict, recs[0].subject, recs[0].n), (Verdict::Admit as u8, 7, [EFFECT_WORD, OP_STOP as u64, COMP_RAN]));

    // Failed, no inverse declared: nothing runs; the refusal is recorded.
    LOG.lock().unwrap().clear();
    let base = azos_decision::total();
    let no_inverse = Timing { compensate_op: 0, ..t };
    effect_gate::issue(&effect(Class::Reversible, 3), &no_inverse, || ((), false)).unwrap();
    assert!(log().is_empty());
    let recs = records(base, Rule::Compensation);
    assert_eq!((recs.len(), recs[0].verdict, recs[0].n), (1, Verdict::Refuse as u8, [EFFECT_WORD, 0, COMP_NO_INVERSE]));

    // Failed, the kind's driver refuses the inverse: recorded as refused.
    let base = azos_decision::total();
    let refused = Timing { compensate_op: OP_UNSUPPORTED, ..t };
    effect_gate::issue(&effect(Class::Reversible, 4), &refused, || ((), false)).unwrap();
    let recs = records(base, Rule::Compensation);
    assert_eq!((recs.len(), recs[0].verdict, recs[0].n[2]), (1, Verdict::Refuse as u8, COMP_REFUSED));

    // A failed stop has nothing to undo; a refused effect never ran.
    LOG.lock().unwrap().clear();
    let base = azos_decision::total();
    effect_gate::issue(&effect(Class::Safe, 5), &t, || ((), false)).unwrap();
    let impossible = Timing { commit_ns: 5_000_000, ..t };
    assert!(effect_gate::issue(&effect(Class::Reversible, 6), &impossible, || ((), false)).is_err());
    assert!(log().is_empty());
    assert!(records(base, Rule::Compensation).is_empty());
}

#[test]
fn a_miss_the_kernel_cannot_drive_is_recorded_as_refused() {
    let _g = fresh();
    let _s = Scene::new();
    let base = azos_decision::total();
    let t = Timing { safe_op: OP_UNSUPPORTED, ..kernel_timing() };
    effect_gate::issue(&effect(Class::Reversible, 1), &t, || { at(T0 + 5 * MS); ((), true) }).unwrap();
    let recs = records(base, Rule::SafeState);
    assert_eq!((recs.len(), recs[0].verdict), (1, Verdict::Refuse as u8), "a drive that failed must not read as success");
    assert!(!DEVICE_SAFE.load(Ordering::SeqCst));
    // The device is held all the same: it did not commit and could not be stopped.
    assert!(safe_state::held(KIND_MOTOR, 1));
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The placement controller (`azos_topology::placement::Elastic`): when a
//! driver row moves between hosts, what it is admitted against, and the record
//! every move leaves.

use azos_decision::{ProvenanceRecord, Rule, Verdict};
use azos_topology::placement::{Cause, Decision, Elastic, Host, Move, PlaceSpec, Policy, Reason, Receipt, WINDOW};
use std::sync::Mutex;

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000 * MS;
/// 250 us budget, in ns.
const BUDGET: u64 = 250_000;
const ROW: u32 = 6;

static GUARD: Mutex<()> = Mutex::new(());
static SINK: Mutex<Vec<ProvenanceRecord>> = Mutex::new(Vec::new());

fn sink(p: &ProvenanceRecord) {
    SINK.lock().unwrap().push(*p);
}

/// Take the process-wide statics for one test and empty the sink.
fn begin() -> std::sync::MutexGuard<'static, ()> {
    let g = GUARD.lock().unwrap_or_else(|e| e.into_inner());
    azos_decision::set_durable_sink(sink);
    SINK.lock().unwrap().clear();
    g
}

fn records() -> Vec<ProvenanceRecord> {
    SINK.lock().unwrap().iter().filter(|p| p.rule == Rule::Placement as u8).copied().collect()
}

const POLICY: Policy = Policy { misses: 4, holdoff_ns: 300 * SEC };

fn spec(host: Host, stateless: bool, budget_us: u32) -> PlaceSpec {
    PlaceSpec { host, stateless, call_budget_us: budget_us }
}

fn elastic(host: Host) -> Elastic {
    Elastic::new(ROW, spec(host, true, 250), POLICY)
}

/// Feed `n` calls of `cost` at `t`; the last decision.
fn feed(e: &mut Elastic, n: usize, cost: u64, t: u64) -> Decision {
    let mut d = Decision::Stay;
    for _ in 0..n {
        d = e.observe(cost, t);
    }
    d
}

fn mv(from: Host, to: Host, reason: Reason) -> Move {
    Move { from, to, reason }
}

/// Four slow calls of the last sixteen, a kernel host that fits: the move is
/// admitted at the fourth, not before, and committing it leaves exactly one
/// durable `Place` record with the row, the move word, the worst cost seen and
/// the budget.
///
/// **Canary.** Build with `placement-norecord-canary`: `commit` changes the
/// host and writes nothing; the record assertions go red.
#[test]
fn a_move_leaves_exactly_one_record() {
    let _g = begin();
    let mut e = elastic(Host::Ring3);
    e.set_kernel_cost(40_000);
    assert_eq!(feed(&mut e, 3, 900_000, SEC), Decision::Stay, "three misses are not a deadline miss");
    let Decision::Move(r) = e.observe(900_000, SEC) else { panic!("the fourth miss asks for a move") };
    assert_eq!(r.mv, mv(Host::Ring3, Host::Kernel, Reason::Deadline));
    assert_eq!((r.measured_ns, r.limit_ns), (900_000, BUDGET));
    assert!(records().is_empty(), "deciding is not moving: no record yet");
    assert_eq!(e.host(), Host::Ring3);
    e.commit(r);
    assert_eq!(e.host(), Host::Kernel);
    let recs = records();
    assert_eq!(recs.len(), 1, "a move without its record: {recs:?}");
    let p = recs[0];
    assert_eq!((p.verdict, p.subject, p.topology_row_id), (Verdict::Place as u8, ROW, ROW + 1));
    assert_eq!(p.n, [r.mv.pack(None), 900_000, BUDGET]);
    assert_eq!(Move::unpack(p.n[0]), Some((r.mv, None)));
}

/// Misses must be four of the last sixteen: slow calls spread thin, or
/// diluted by fast ones, never ask.
#[test]
fn the_window_is_the_last_sixteen_calls() {
    let _g = begin();
    let mut e = elastic(Host::Ring3);
    e.set_kernel_cost(40_000);
    // Three slow, then plenty of fast ones: the slow ones age out.
    feed(&mut e, 3, 900_000, SEC);
    feed(&mut e, WINDOW, 10_000, SEC);
    assert_eq!(feed(&mut e, 3, 900_000, SEC), Decision::Stay, "3 of 16 again");
    // A call exactly at the budget is not over it.
    let mut e = elastic(Host::Ring3);
    e.set_kernel_cost(40_000);
    assert_eq!(feed(&mut e, 20, BUDGET, SEC), Decision::Stay);
    assert!(records().is_empty());
}

/// A promotion is admitted against the kernel host's measured cost: an
/// unmeasured host admits nothing, one that costs more than the budget is
/// refused with the cost as the counter-offer, and the refusal is a record,
/// written once per spell over the threshold, not once per call.
#[test]
fn a_promotion_is_admitted_against_the_kernel_hosts_measured_cost() {
    let _g = begin();
    let mut e = elastic(Host::Ring3);
    assert_eq!(feed(&mut e, 4, 900_000, SEC), Decision::Refused(Cause::Unmeasured));
    assert_eq!(feed(&mut e, 5, 900_000, SEC), Decision::Refused(Cause::Unmeasured));
    let recs = records();
    assert_eq!(recs.len(), 1, "one receipt for the spell, not one per call");
    assert_eq!(recs[0].verdict, Verdict::Refuse as u8);
    let (m, cause) = Move::unpack(recs[0].n[0]).unwrap();
    assert_eq!((m, cause), (mv(Host::Ring3, Host::Kernel, Reason::Deadline), Some(Cause::Unmeasured)));

    // The kernel host measured, and slower than the budget: the counter-offer.
    e.set_kernel_cost(400_000);
    SINK.lock().unwrap().clear();
    // Still latched from the spell above: no second record until it ends.
    assert_eq!(feed(&mut e, 1, 900_000, SEC), Decision::Refused(Cause::HostCost));
    assert!(records().is_empty());
    feed(&mut e, WINDOW, 10_000, SEC); // the spell ends
    assert_eq!(feed(&mut e, 4, 900_000, SEC), Decision::Refused(Cause::HostCost));
    let recs = records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].n[1..], [900_000, 400_000], "the third number is what the budget would have had to be");
    assert_eq!(e.host(), Host::Ring3);
}

/// Only a `stateless` row with a budget moves for cost; nothing else does.
#[test]
fn only_a_stateless_row_with_a_budget_is_promoted() {
    let _g = begin();
    for sp in [spec(Host::Ring3, false, 250), spec(Host::Ring3, true, 0)] {
        let mut e = Elastic::new(ROW, sp, POLICY);
        e.set_kernel_cost(1);
        assert_eq!(feed(&mut e, 40, 900_000, SEC), Decision::Stay, "{sp:?}");
    }
    assert!(records().is_empty());
}

/// A kernel host that faulted restarts in ring 3 (a `stateless` row only),
/// recorded with the fault as its reason; a row that is not `stateless` is
/// the supervisor's to restart where it is.
#[test]
fn a_fault_in_the_kernel_host_demotes_a_stateless_row() {
    let _g = begin();
    let mut e = elastic(Host::Kernel);
    let Decision::Move(r) = e.fault(10 * SEC) else { panic!("a stateless row moves on a fault") };
    assert_eq!(r.mv, mv(Host::Kernel, Host::Ring3, Reason::Fault));
    e.commit(r);
    assert_eq!(e.host(), Host::Ring3);
    let recs = records();
    assert_eq!(recs.len(), 1);
    assert_eq!((recs[0].verdict, Move::unpack(recs[0].n[0])), (Verdict::Place as u8, Some((r.mv, None))));

    let mut plain = Elastic::new(ROW, spec(Host::Kernel, false, 0), POLICY);
    assert_eq!(plain.fault(10 * SEC), Decision::Stay);
    // A fault in ring 3 is the supervisor's restart in ring 3, not a move.
    let mut in3 = elastic(Host::Ring3);
    assert_eq!(in3.fault(10 * SEC), Decision::Stay);
    assert_eq!(records().len(), 1);
}

/// The code that just failed is not the destination of a promotion until the
/// hold-off has passed; then it is.
#[test]
fn a_driver_is_not_promoted_back_into_the_code_that_just_faulted() {
    let _g = begin();
    let mut e = elastic(Host::Kernel);
    e.set_kernel_cost(40_000);
    let Decision::Move(r) = e.fault(10 * SEC) else { panic!() };
    e.commit(r);
    assert_eq!(feed(&mut e, 4, 900_000, 20 * SEC), Decision::Refused(Cause::RecentFault));
    let (m, cause) = Move::unpack(records().last().unwrap().n[0]).unwrap();
    assert_eq!((m.reason, cause), (Reason::Deadline, Some(Cause::RecentFault)));
    // The hold-off later (and the spell restarted): admitted.
    feed(&mut e, WINDOW, 10_000, 20 * SEC);
    assert!(matches!(feed(&mut e, 4, 900_000, 10 * SEC + POLICY.holdoff_ns + SEC), Decision::Move(_)));
}

/// A move that was admitted and could not be done is a refusal record, and
/// the driver stays; a promotion that failed is not asked for again until the
/// hold-off has passed.
#[test]
fn a_move_that_failed_is_recorded_and_the_driver_stays() {
    let _g = begin();
    let mut e = elastic(Host::Kernel);
    let Decision::Move(r) = e.fault(SEC) else { panic!() };
    e.failed(r, SEC);
    assert_eq!(e.host(), Host::Kernel);
    let recs = records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].verdict, Verdict::Refuse as u8);
    assert_eq!(Move::unpack(recs[0].n[0]), Some((r.mv, Some(Cause::Failed))));
}

/// The record words: a move word is its four bytes, and anything else is not
/// a move.
#[test]
fn the_move_word_round_trips() {
    for from in [Host::Kernel, Host::Ring3] {
        for reason in [Reason::Fault, Reason::Deadline] {
            for cause in [None, Some(Cause::HostCost), Some(Cause::Failed)] {
                let m = Move { from, to: from.other(), reason };
                assert_eq!(Move::unpack(m.pack(cause)), Some((m, cause)));
            }
        }
    }
    assert_eq!(Move::unpack(0), None);
    assert_eq!(Move::unpack(1 << 16 | 3 << 8 | 1), None, "host 3 is none");
    assert_eq!(Move::unpack(9 << 24 | 1 << 16 | 1 << 8 | 2), None, "cause 9 is none");
    let r = Receipt { mv: mv(Host::Ring3, Host::Kernel, Reason::Deadline), measured_ns: 1, limit_ns: 2 };
    assert_eq!(r, r);
}

/// A promotion whose kernel host would not start is a `Failed` refusal, and the
/// next slow calls do not ask again within the hold-off (a refusal for the
/// recent failure, once), then do.
#[test]
fn a_promotion_that_failed_is_not_asked_for_again_at_once() {
    let _g = begin();
    let mut e = elastic(Host::Ring3);
    e.set_kernel_cost(40_000);
    let Decision::Move(r) = feed(&mut e, 4, 900_000, SEC) else { panic!() };
    e.failed(r, SEC);
    assert_eq!(e.host(), Host::Ring3);
    assert_eq!(feed(&mut e, 8, 900_000, 2 * SEC), Decision::Refused(Cause::RecentFault));
    let recs = records();
    assert_eq!(recs.len(), 2, "the failure, then one refusal for the spell: {recs:?}");
    assert_eq!(Move::unpack(recs[0].n[0]).map(|(_, c)| c), Some(Some(Cause::Failed)));
    assert_eq!(Move::unpack(recs[1].n[0]).map(|(_, c)| c), Some(Some(Cause::RecentFault)));
    feed(&mut e, WINDOW, 10_000, 3 * SEC);
    assert!(matches!(feed(&mut e, 4, 900_000, SEC + POLICY.holdoff_ns + SEC), Decision::Move(_)));
}

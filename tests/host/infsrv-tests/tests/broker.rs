// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The broker's admission against the signed cost table: which variant, when
//! nothing fits and why, what each context may spend, and what an overrun
//! costs.

use azos_decision::{Rule, Verdict};
use azos_decisions::{Filter, Source};
use azos_devif::outcome::{BUSY, REFUSED, UNSUPPORTED};
use azos_infsrv_tests::*;
use infsrv::broker::{reason, Admitted, Broker, Limits, Refusal, Request};
use infsrv::config::{CONTEXTS, JOURNAL_ENTRIES};
use infsrv::load::{Arena, Model};

const T0: u64 = 5_000_000_000;

fn model_of(file: &[u8], k: [u8; 32]) -> Model {
    let mut buf = vec![0u8; 64 * 1024];
    load_with(file, k, &mut Arena::new(&mut buf), 512).unwrap().model
}

fn broker(lim: Limits) -> (Broker, u64) {
    let (file, k) = three();
    let m = model_of(&file, k);
    let mut b = Broker::new(lim);
    b.add(m).unwrap();
    (b, m.model_ref)
}

fn req(model_ref: u64, badge: u32, budget_us: Option<u32>) -> Request {
    Request { badge, model_ref, low_energy: false, budget_us, now_ns: T0 }
}

fn ok(r: Result<Admitted, Option<Refusal>>) -> Admitted {
    r.unwrap_or_else(|e| panic!("refused: {e:?}"))
}

fn refused(r: Result<Admitted, Option<Refusal>>) -> Refusal {
    match r {
        Err(Some(f)) => f,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The first variant of the publisher's list whose signed worst case fits the
/// time left is the one that runs; no deadline takes the first of all.
///
/// **Canary.** Compare `wcet_us` with `>=` in `admit`: the 800 us row (a worst
/// case of exactly the budget) is red.
#[test]
fn the_first_variant_whose_worst_case_fits_the_deadline_runs() {
    let (mut b, m) = broker(limits());
    for (budget, want) in [(None, 1), (Some(5000), 1), (Some(2000), 1), (Some(1999), 2), (Some(800), 2), (Some(799), 3), (Some(300), 3)] {
        assert_eq!(ok(b.admit(&req(m, 1, budget))).slot.v.id, want, "budget {budget:?}");
    }
}

/// Nothing fits the time: refused now, `REFUSED`, with the reason and a
/// receipt that is a decision record of Rule `accel-admission` naming the
/// context, the model, the candidate and the numbers it was compared on. A
/// deadline already passed (a budget of 0) is the same refusal.
///
/// **Canary.** Return `reason::ENERGY` for the deadline refusal: the reason
/// row is red.
#[test]
fn a_call_that_cannot_make_its_deadline_is_refused_with_a_receipt() {
    let (mut b, m) = broker(limits());
    for budget in [299, 100, 0] {
        let f = refused(b.admit(&req(m, 41, Some(budget))));
        assert_eq!((f.code, f.reason), (REFUSED, reason::DEADLINE), "budget {budget}");
        assert!(f.receipt != 0);
        let rec = b.journal.view(Some(41)).lookup(f.receipt).expect("the receipt reads back");
        assert_eq!((rec.rule, rec.verdict, rec.subject), (Rule::AccelAdmission as u8, Verdict::Refuse as u8, 41));
        assert_eq!(rec.seq, f.receipt);
        assert_eq!(rec.image_hash_prefix, m, "the model");
        // The candidate is the first variant that got as far as the time check.
        assert_eq!(f.candidate, Some((1, 1)));
        assert_eq!(rec.n, [1 << 32 | 1, 8, 16 | (reason::DEADLINE as u64) << 32]);
        assert_eq!(rec.clock_ns, T0);
    }
}

/// The energy hint takes the lowest signed energy among the variants that
/// fit, the earlier of a tie; a deadline narrows the set first.
///
/// **Canary.** Ignore `low_energy` in `admit`: the first row takes id 1.
#[test]
fn the_low_energy_hint_takes_the_cheapest_variant_that_fits() {
    let (mut b, m) = broker(limits());
    let low = |budget| Request { low_energy: true, ..req(m, 1, budget) };
    assert_eq!(ok(b.admit(&low(None))).slot.v.id, 3);
    assert_eq!(ok(b.admit(&low(Some(1000)))).slot.v.id, 3);
    assert_eq!(refused(b.admit(&low(Some(100)))).reason, reason::DEADLINE);
    // A tie goes to the earlier of the list.
    let (file, k) = bundle("tie", &[gguf(5, 500, 50, 1024), gguf(6, 300, 50, 1024)], None);
    let mut b = Broker::new(limits());
    let model = model_of(&file, k);
    b.add(model).unwrap();
    let r = Request { low_energy: true, ..req(model.model_ref, 1, None) };
    assert_eq!(ok(b.admit(&r)).slot.v.id, 5);
}

/// Working memory is the signed `mem_bytes` against what a run may use:
/// variants that need more are passed over, and when every variant needs more
/// the call is `BUSY` now.
#[test]
fn a_variant_that_needs_more_memory_than_a_run_may_use_is_passed_over() {
    let (mut b, m) = broker(Limits { work_bytes: 2048, ..limits() });
    assert_eq!(ok(b.admit(&req(m, 1, None))).slot.v.id, 3);
    let (mut b, m) = broker(Limits { work_bytes: 512, ..limits() });
    let f = refused(b.admit(&req(m, 1, None)));
    assert_eq!((f.code, f.reason), (BUSY, reason::NO_MEMORY));
    let rec = b.journal.view(Some(1)).lookup(f.receipt).unwrap();
    assert_eq!(rec.n[2], 0 | (reason::NO_MEMORY as u64) << 32, "free_kib 0 at 512 bytes, then the reason");
}

/// A bundle none of whose variants has a backend or a blob is `UNSUPPORTED`,
/// with a receipt, whatever the deadline.
#[test]
fn a_model_with_no_runnable_variant_is_unsupported() {
    let spirv = Var { backend: "spirv", id: 7, blob: vec![1; 64], wcet_us: 100, energy_uj: 10, mem_bytes: 1024 };
    let (file, k) = bundle("gpu-only", &[spirv], None);
    let model = model_of(&file, k);
    let mut b = Broker::new(limits());
    b.add(model).unwrap();
    for budget in [None, Some(1_000_000)] {
        let f = refused(b.admit(&req(model.model_ref, 1, budget)));
        assert_eq!((f.code, f.reason), (UNSUPPORTED, reason::NO_BACKEND));
        assert!(f.receipt != 0);
    }
}

/// A call for a model nobody holds is nobody's admission: no refusal record,
/// nothing in the journal.
#[test]
fn an_unknown_model_is_no_decision() {
    let (mut b, m) = broker(limits());
    assert_eq!(b.admit(&req(m ^ 1, 1, None)).unwrap_err(), None);
    assert_eq!(b.journal.total(), 0);
}

/// A context has a quota per window. Each admission reserves the signed
/// energy; the broker degrades to a cheaper variant as the quota runs down,
/// refuses when not even the cheapest fits, and the next window starts afresh.
/// An admission is recorded when the variant changes, not on every call.
///
/// **Canary.** Reserve nothing in `admit` (drop the `charge`): the third call
/// still takes id 1, the degrade row is red.
#[test]
fn a_contexts_energy_quota_degrades_then_refuses_then_renews() {
    let (mut b, m) = broker(Limits { quota_uj: 1000, ..limits() });
    let mut got = vec![];
    for _ in 0..5 {
        got.push(ok(b.admit(&req(m, 7, None))).slot.v.id);
    }
    // 400, 400 (800), then 200 left: id 2 (120, 920), then 80 left: id 3
    // (40, 960; 1000).
    assert_eq!(got, [1, 1, 2, 3, 3]);
    let f = refused(b.admit(&req(m, 7, None)));
    assert_eq!((f.code, f.reason), (REFUSED, reason::ENERGY));
    let rec = b.journal.view(Some(7)).lookup(f.receipt).unwrap();
    assert_eq!(rec.n[0], 1 << 32 | 1, "the publisher's first choice: the first to get as far as the energy check");

    // Three admissions (first, two degrades) and one refusal were recorded.
    let verdicts: Vec<u8> = (1..=b.journal.total()).map(|i| b.journal.view(Some(7)).lookup(i).unwrap().verdict).collect();
    let a = Verdict::Admit as u8;
    assert_eq!(verdicts, [a, a, a, Verdict::Refuse as u8]);

    // The window ends: the account is empty again, and the model goes back to
    // its first choice (recorded: it is a change).
    let later = Request { now_ns: T0 + 1_000_000_000, ..req(m, 7, None) };
    assert_eq!(ok(b.admit(&later)).slot.v.id, 1);
    assert_eq!(b.journal.total(), 5);
}

/// Quotas are per context: one tenant spending its own does not touch another's.
///
/// **Canary.** Let `slot_of` match any live slot instead of the badge's: the
/// second context is refused.
#[test]
fn contexts_do_not_share_a_quota() {
    let (mut b, m) = broker(Limits { quota_uj: 400, ..limits() });
    assert_eq!(ok(b.admit(&req(m, 1, None))).slot.v.id, 1);
    // Context 1 has spent all 400; not even the cheapest (40) fits.
    assert_eq!(refused(b.admit(&req(m, 1, None))).reason, reason::ENERGY);
    // Context 2 has its own.
    let a = ok(b.admit(&req(m, 2, None)));
    assert_eq!(a.slot.v.id, 1);
    // And context 1's slot is still its own.
    assert_eq!(b.context(1), b.context(1));
    assert!(b.context(1) != b.context(2));
}

/// A run's cost is settled when it ends. On time it costs the signed energy;
/// past its signed worst case it is charged for the excess at the variant's own
/// rate, and the context's account shows it: the next call finds less left.
///
/// **Canary.** Return `extra = 0` from `settle`: the overrun row reports 120
/// uJ and the second call takes id 2 instead of id 3.
#[test]
fn an_overrun_is_charged_back() {
    // Quota 300. Id 2: wcet 800 us, 120 uJ.
    let (mut b, m) = broker(Limits { quota_uj: 300, ..limits() });
    let r = Request { low_energy: false, ..req(m, 1, Some(1000)) };
    let a = ok(b.admit(&r));
    assert_eq!(a.slot.v.id, 2);
    // On time: the signed figure.
    let s = b.settle(&a, true, 500_000);
    assert_eq!((s.latency_us, s.overrun_us, s.energy_uj), (500, 0, 120));
    // Rounded up to the microsecond, and the excess of one microsecond over 800
    // costs 120 * 1 / 800 = 0 uJ at integer precision.
    let a = ok(b.admit(&r));
    let s = b.settle(&a, true, 800_001);
    assert_eq!((s.latency_us, s.overrun_us, s.energy_uj), (801, 1, 120));
    // Twice its worst case: the signed energy again on top. Used so far: 240.
    let (mut b, m) = broker(Limits { quota_uj: 300, ..limits() });
    let r = req(m, 1, Some(1000));
    let a = ok(b.admit(&r));
    let s = b.settle(&a, true, 1_600_000);
    assert_eq!((s.latency_us, s.overrun_us, s.energy_uj), (1600, 800, 240));
    // 300 - 240 = 60 left: the next call can only afford id 3. Without the
    // charge it would still afford id 2.
    assert_eq!(ok(b.admit(&r)).slot.v.id, 3);
}

/// A run that did not happen gives its reservation back; one that did not
/// even start does not leave the account short.
///
/// **Canary.** Skip the refund in `settle`: the second admission is refused.
#[test]
fn a_run_that_failed_costs_nothing() {
    let (mut b, m) = broker(Limits { quota_uj: 400, ..limits() });
    let r = req(m, 1, None);
    let a = ok(b.admit(&r));
    assert_eq!(a.slot.v.id, 1);
    let s = b.settle(&a, false, 123_456);
    assert_eq!((s.latency_us, s.energy_uj, s.overrun_us), (0, 0, 0));
    assert_eq!(ok(b.admit(&r)).slot.v.id, 1, "the 400 uJ are back");
}

/// The context table never evicts: the badge after the last free slot is told
/// `BUSY` with a receipt, and the badges in the table are served as before.
///
/// **Canary.** Let `slot_of` match any live slot: a new badge shares an old
/// one's account instead of being refused, and the refusal row is red.
#[test]
fn a_full_context_table_refuses_a_new_badge_and_keeps_the_others() {
    let (mut b, m) = broker(limits());
    for badge in 0..CONTEXTS as u32 {
        ok(b.admit(&req(m, 100 + badge, None)));
    }
    let f = refused(b.admit(&req(m, 999, None)));
    assert_eq!((f.code, f.reason, f.ctx), (BUSY, reason::CONTEXTS, None));
    assert!(f.receipt != 0);
    for badge in 0..CONTEXTS as u32 {
        ok(b.admit(&req(m, 100 + badge, None)));
    }
}

/// The journal keeps the last `DECISION_JOURNAL_ENTRIES` records; an id that
/// has been overwritten reads back as nothing, ids ascend from 1 and a query
/// pages by `after` through what is held, filtered by verdict.
///
/// **Canary.** Index the ring by `id` instead of `id - 1`: the first record
/// held after a wrap is the wrong one.
#[test]
fn the_journal_keeps_the_last_records_and_answers_queries() {
    let (mut b, m) = broker(limits());
    let n = JOURNAL_ENTRIES + 3;
    for _ in 0..n {
        refused(b.admit(&req(m, 1, Some(0))));
    }
    assert_eq!(b.journal.total(), n as u64);
    let j = b.journal.view(Some(1));
    assert_eq!(j.total(), JOURNAL_ENTRIES as u64, "the view counts the records held");
    assert!(j.lookup(0).is_none() && j.lookup(1).is_none() && j.lookup(3).is_none());
    assert_eq!(j.lookup(4).unwrap().seq, 4);
    assert_eq!(j.lookup(n as u64).unwrap().seq, n as u64);
    assert!(j.lookup(n as u64 + 1).is_none());

    let mut ids = [0u64; 5];
    let k = j.query(&Filter { rule: Some(Rule::AccelAdmission as u8), ..Filter::ANY }, &mut ids);
    assert_eq!((k, ids[..k].to_vec()), (5, vec![4, 5, 6, 7, 8]), "oldest held first");
    let k = j.query(&Filter { after: 10, verdict: Some(Verdict::Refuse as u8), ..Filter::ANY }, &mut ids);
    assert_eq!(ids[..k].to_vec(), vec![11, 12, 13, 14, 15]);
    let k = j.query(&Filter { verdict: Some(Verdict::Admit as u8), ..Filter::ANY }, &mut ids);
    assert_eq!(k, 0);
}

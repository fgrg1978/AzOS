// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The decision layer's copies to the sealed security log's ring (Kconfig
//! `SEC_LOG`): what `record` writes there, what the per-Domain bucket and the
//! rate cap hold back, and that they are counted. Run with a configuration
//! with `SEC_LOG` on (the gate row `decisions(seclog)`).
//!
//! **Canaries.** `canary-no-security-copy` (nothing is copied): every test
//! that reads the ring red; `canary-global-security-bucket` (no subject share,
//! no reserve): the two tests of the shared bucket red.

use azos_decision::{Rule, SecClass, Verdict};
use azos_seclog::{kind, Event};
use std::sync::atomic::{AtomicU64, Ordering};

/// The events in the security ring from sequence number `from`: `(class,
/// rule, verdict, subject)`, and the ring's head.
fn events(from: u64) -> (Vec<(u8, u8, u8, u32)>, u64) {
    let ring = azos_records::reader(azos_records::SOURCE_SECURITY).expect("a security ring: SEC_LOG on");
    let (mut c, mut env, mut p) = (from, azos_records::record::Envelope::default(), [0u8; azos_seclog::PAYLOAD]);
    let mut v = Vec::new();
    while ring.read(&mut c, &mut env, &mut p) == azos_records::record::Read::Record {
        if env.kind == kind::EVENT {
            let e = Event::decode(&p).unwrap();
            v.push((e.class as u8, e.rule, e.verdict, e.subject));
        }
    }
    (v, ring.head())
}

fn head() -> u64 {
    azos_records::reader(azos_records::SOURCE_SECURITY).map_or(0, |r| r.head())
}

static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The decision clock of these tests: milliseconds, moved by hand.
static TIME: AtomicU64 = AtomicU64::new(1);

fn clock() {
    azos_decision::set_clock(|| TIME.load(Ordering::Relaxed), 1000);
}

#[test]
fn seclog_a_security_rules_record_is_copied_with_its_class() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    clock();
    assert!(azos_records::SECURITY, "run with SEC_LOG on");
    let from = head();
    azos_decision::record(Rule::AudioCapture, Verdict::Admit, 7, [1, 2, 3]);
    azos_decision::record(Rule::Placement, Verdict::Place, 8, [0, 0, 0]);
    let (ev, _) = events(from);
    assert_eq!(ev, vec![(SecClass::Microphone as u8, Rule::AudioCapture as u8, Verdict::Admit as u8, 7)], "the placement is not a security record");
}

/// More copies of one class a task can raise in a loop than its share of the
/// cap: the rest are held back and counted, and a microphone's record still
/// goes in.
#[test]
fn seclog_the_rate_cap_holds_a_flood_back_and_counts_it() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    clock();
    let from = head();
    let (_, held0, _) = azos_decision::security_tally();
    // A denial of a rule that is not paced by the durable bucket: Neverallow.
    for i in 0..(azos_limits::SEC_LOG_PER_S as u32) {
        azos_decision::record(Rule::Neverallow, Verdict::Refuse, 100 + i, [0, 0, 0]);
    }
    azos_decision::record(Rule::CamCapture, Verdict::Admit, 9, [0, 0, 0]);
    let (ev, _) = events(from);
    let denials = ev.iter().filter(|e| e.0 == SecClass::CapDenial as u8).count() as u32;
    assert!(denials <= azos_limits::SEC_LOG_PER_S as u32 / 4, "{denials} denials copied");
    assert!(ev.contains(&(SecClass::Camera as u8, Rule::CamCapture as u8, Verdict::Admit as u8, 9)), "{ev:?}");
    let (copied, held, top) = azos_decision::security_tally();
    assert!(top.iter().any(|t| t.1 > 0), "the subjects held back: {top:?}");
    assert!(held[SecClass::CapDenial as usize] > held0[SecClass::CapDenial as usize]);
    assert!(copied[SecClass::Camera as usize] >= 1);
    // A second later every class's share has refilled, the drained one's
    // too, even when another class is asked first.
    TIME.store(TIME.load(Ordering::Relaxed) + 1000, Ordering::Relaxed);
    let from = head();
    azos_decision::record(Rule::EnvelopeEgress, Verdict::Admit, 10, [1, 3, 0]);
    azos_decision::record(Rule::Neverallow, Verdict::Refuse, 300, [0, 0, 0]);
    let (ev, _) = events(from);
    assert!(ev.contains(&(SecClass::Egress as u8, Rule::EnvelopeEgress as u8, Verdict::Admit as u8, 10)), "{ev:?}");
    assert!(ev.contains(&(SecClass::CapDenial as u8, Rule::Neverallow as u8, Verdict::Refuse as u8, 300)), "the denials' share refilled: {ev:?}");
}

/// A flood of one Domain's capability denials: the per-Domain bucket of the
/// durable receipts admits its burst and holds the rest back; what it holds
/// back is not copied, and its `RefusalLimited` report is (class `limited`).
#[test]
fn seclog_what_the_durable_bucket_holds_back_is_its_report() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    clock();
    azos_decision::set_durable_sink(|_| {});
    TIME.store(TIME.load(Ordering::Relaxed) + 10_000, Ordering::Relaxed);
    let from = head();
    for _ in 0..(azos_limits::DECISION_DENY_DURABLE_BURST as u32 + 4) {
        azos_decision::record(Rule::CapDenial, Verdict::Refuse, 4242, [0, 0, 0]);
    }
    let (ev, _) = events(from);
    let denials = ev.iter().filter(|e| e.0 == SecClass::CapDenial as u8 && e.3 == 4242).count() as u64;
    assert!(denials <= azos_limits::DECISION_DENY_DURABLE_BURST as u64, "{denials} copied: the held ones too");
    assert!(
        ev.iter().any(|e| e.0 == SecClass::Limited as u8 && e.1 == Rule::RefusalLimited as u8 && e.3 == 4242),
        "the bucket's report of what it held back: {ev:?}"
    );
}

/// The refill keeps what an integer division would drop: at any spacing of
/// the calls, a second refills a second's worth. A 1 GHz clock, the
/// timebase of a fast core; one task's egress admits every 1 ms, 100 us and
/// 20 us for a second each, then a microphone record.
#[test]
fn seclog_the_cap_refills_at_its_rate_whatever_the_spacing() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    static NS: AtomicU64 = AtomicU64::new(0);
    azos_decision::set_clock(|| NS.load(Ordering::Relaxed), 1_000_000_000);
    let share = azos_limits::SEC_LOG_PER_S as usize / 4;
    for (spacing, subject) in [(1_000_000u64, 7001u32), (100_000, 7002), (20_000, 7003)] {
        // A quiet second first: every bucket full again.
        NS.fetch_add(2_000_000_000, Ordering::Relaxed);
        let from = head();
        let calls = 1_000_000_000 / spacing;
        for i in 0..calls {
            NS.fetch_add(spacing, Ordering::Relaxed);
            azos_decision::record(Rule::EnvelopeEgress, Verdict::Admit, subject, [i, 3, 0]);
        }
        azos_decision::record(Rule::AudioCapture, Verdict::Admit, subject, [0, 0, 0]);
        let (ev, _) = events(from);
        let egress = ev.iter().filter(|e| e.0 == SecClass::Egress as u8 && e.3 == subject).count();
        // The share it starts with and a second's refill of it.
        assert!(egress >= 2 * share - 1, "{spacing} ns apart: {egress} egress copied, want about {}", 2 * share);
        assert!(ev.contains(&(SecClass::Microphone as u8, Rule::AudioCapture as u8, Verdict::Admit as u8, subject)), "{spacing} ns apart: the microphone record was held");
    }
}

/// One task's egress cannot spend another's: a task that floods its own
/// share leaves a second task's first destination recorded; and a socket
/// alternating two destinations is two records, not a flood.
#[test]
fn seclog_each_task_has_its_own_egress_share() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    clock();
    TIME.store(TIME.load(Ordering::Relaxed) + 10_000, Ordering::Relaxed);
    let from = head();
    for i in 0..64u64 {
        azos_decision::record(Rule::EnvelopeEgress, Verdict::Admit, 8001, [1000 + i, 3, 0]);
    }
    azos_decision::record(Rule::EnvelopeEgress, Verdict::Admit, 8002, [42, 3, 0]);
    for _ in 0..64 {
        azos_decision::record(Rule::EnvelopeEgress, Verdict::Admit, 8003, [7, 3, 0]);
        azos_decision::record(Rule::EnvelopeEgress, Verdict::Admit, 8003, [8, 3, 0]);
    }
    let (ev, _) = events(from);
    let of = |s: u32| ev.iter().filter(|e| e.0 == SecClass::Egress as u8 && e.3 == s).count();
    assert!(of(8001) <= azos_limits::SEC_LOG_PER_S as usize / 4, "{} copied for the flooding task", of(8001));
    assert_eq!(of(8002), 1, "the other task's destination");
    assert_eq!(of(8003), 2, "two destinations, alternated");
}

/// The share is the Domain's, whatever tasks it runs: 40 tasks of one Domain
/// flooding together get one share, and another Domain's first destination
/// is recorded. A destination the cap held back is recorded once there is
/// room: it is no repeat.
#[test]
fn seclog_the_egress_share_is_the_domains() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    clock();
    TIME.store(TIME.load(Ordering::Relaxed) + 10_000, Ordering::Relaxed);
    let from = head();
    for i in 0..400u64 {
        azos_decision::record_keyed(Rule::EnvelopeEgress, Verdict::Admit, 9000 + (i % 40) as u32, 77, [5000 + i, 3, 0]);
    }
    azos_decision::record_keyed(Rule::EnvelopeEgress, Verdict::Admit, 9100, 78, [42, 3, 0]);
    let (ev, _) = events(from);
    let flood = ev.iter().filter(|e| e.0 == SecClass::Egress as u8 && (9000..9040).contains(&e.3)).count();
    assert!(flood <= azos_limits::SEC_LOG_PER_S as usize / 4, "{flood} copied for one Domain's 40 tasks");
    assert!(ev.iter().any(|e| e.0 == SecClass::Egress as u8 && e.3 == 9100), "the other Domain's destination: {ev:?}");
    // The last destination the flood asked for was held; a second later it is copied.
    TIME.store(TIME.load(Ordering::Relaxed) + 1_000, Ordering::Relaxed);
    let from = head();
    azos_decision::record_keyed(Rule::EnvelopeEgress, Verdict::Admit, 9039, 77, [5399, 3, 0]);
    let (ev, _) = events(from);
    assert!(ev.iter().any(|e| e.0 == SecClass::Egress as u8 && e.3 == 9039), "a held destination is no repeat: {ev:?}");
}

const RESERVED: [(Rule, SecClass); 5] = [
    (Rule::CamCapture, SecClass::Camera),
    (Rule::ExecGrant, SecClass::ImageLoad),
    (Rule::PackageInstall, SecClass::Update),
    (Rule::UsbAuthorize, SecClass::Usb),
    (Rule::HardeningFallback, SecClass::Hardening),
];

/// One task's refused microphone opens spend its own share: the records of
/// every other task, whatever their class, are still copied, and the flood's
/// subject is the one the held count names.
#[test]
fn seclog_one_subjects_refusals_do_not_hold_back_other_tasks_records() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    clock();
    TIME.store(TIME.load(Ordering::Relaxed) + 10_000, Ordering::Relaxed);
    let from = head();
    for _ in 0..(4 * azos_limits::SEC_LOG_PER_S as u32) {
        azos_decision::record(Rule::AudioCapture, Verdict::Refuse, 6001, [0, 0, 0]);
    }
    for (i, (rule, _)) in RESERVED.iter().enumerate() {
        azos_decision::record(*rule, Verdict::Admit, 6100 + i as u32, [0, 0, 0]);
    }
    let (ev, _) = events(from);
    for (i, (rule, class)) in RESERVED.iter().enumerate() {
        assert!(ev.contains(&(*class as u8, *rule as u8, Verdict::Admit as u8, 6100 + i as u32)), "{class:?} held back by one task's flood: {ev:?}");
    }
    let mine = ev.iter().filter(|e| e.0 == SecClass::Microphone as u8 && e.3 == 6001).count();
    assert!(mine <= azos_limits::SEC_LOG_PER_S as usize / 4, "{mine} microphone records copied for one task");
    let (_, _, top) = azos_decision::security_tally();
    assert!(top.iter().any(|t| t.0 == 6001 && t.1 > 0), "the flooding task is named: {top:?}");
}

/// Floods of every class a task can raise, from many tasks at once, leave
/// the classes it cannot raise in a loop their reserved share.
#[test]
fn seclog_the_reserve_outlasts_a_flood_of_every_loopable_class() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    clock();
    TIME.store(TIME.load(Ordering::Relaxed) + 10_000, Ordering::Relaxed);
    let from = head();
    for i in 0..200u32 {
        let s = 20_000 + i;
        azos_decision::record(Rule::AudioCapture, Verdict::Refuse, s, [0, 0, 0]);
        azos_decision::record(Rule::Neverallow, Verdict::Refuse, s, [0, 0, 0]);
        azos_decision::record(Rule::EnvelopeEgress, Verdict::Admit, s, [u64::from(i), 3, 0]);
        azos_decision::record(Rule::Login, Verdict::Refuse, s, [0, 0, 0]);
    }
    for (i, (rule, _)) in RESERVED.iter().enumerate() {
        azos_decision::record(*rule, Verdict::Admit, 30_000 + i as u32, [0, 0, 0]);
    }
    let (ev, _) = events(from);
    for (i, (rule, class)) in RESERVED.iter().enumerate() {
        assert!(ev.contains(&(*class as u8, *rule as u8, Verdict::Admit as u8, 30_000 + i as u32)), "{class:?} lost its reserve: {ev:?}");
    }
}

/// The subjects held back are the heaviest ones, whatever order they came
/// in.
#[test]
fn seclog_the_held_table_names_the_heaviest_subjects() {
    let mut top = [(0u32, 0u32); azos_seclog::Held::SUBJECTS];
    for s in 1..=4u32 {
        azos_decision::hold_noted(&mut top, s);
    }
    for _ in 0..50 {
        azos_decision::hold_noted(&mut top, 99);
        azos_decision::hold_noted(&mut top, 99);
        for s in 10..14u32 {
            azos_decision::hold_noted(&mut top, s);
        }
    }
    assert!(top.iter().any(|t| t.0 == 99 && t.1 >= 100), "{top:?}");
}

/// A subject held back more often than a count holds stays at the top of
/// its range, and so does the count it hands on to a newcomer.
#[test]
fn seclog_a_held_count_saturates() {
    let mut top = [(7u32, u32::MAX); azos_seclog::Held::SUBJECTS];
    azos_decision::hold_noted(&mut top, 7);
    azos_decision::hold_noted(&mut top, 8);
    assert!(top.iter().all(|t| t.1 == u32::MAX), "{top:?}");
    assert!(top.iter().any(|t| t.0 == 8), "{top:?}");
}

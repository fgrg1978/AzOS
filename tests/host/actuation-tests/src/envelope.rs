// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the envelope kinds: the effect gate (`effect_gate.rs`)
//! holds `KIND_STORAGE_DELETE`, `KIND_NET_EGRESS`, `KIND_CONFIG_WRITE`,
//! `KIND_OTA_APPLY` and `KIND_RT_TIME` to the Domain's `[envelope.NAME]` row,
//! asked through the envelope probe. The probe here is a model of the kernel's (task, then the
//! topology row of its class, then the row's level); the ceiling tables are
//! the real ones (`azos_common::envelope`).
//!
//! **Canary.** `--features envelope-row-canary` (the gate ignores the rows):
//! `a_contained_delete_row_refuses_every_delete_with_a_receipt`,
//! `an_egress_row_holds_a_domain_to_the_classes_its_level_reaches`,
//! `a_contained_config_row_refuses_every_key_with_a_receipt`,
//! `an_ota_row_stops_a_domain_at_the_step_its_level_reaches` and
//! `an_rt_time_row_caps_what_one_reservation_may_take` go red.

use crate::effect_gate::{
    self, Class, Effect, Timing, Why, ENVELOPE_FULL, KIND_CONFIG_WRITE, KIND_NET_EGRESS, KIND_OTA_APPLY,
    KIND_RT_TIME, KIND_STORAGE_DELETE,
};
use crate::logger::*;
use crate::tests::fresh;
use azos_common::envelope::{
    self, classify_v4, classify_v6, key_word, Ask, ConfigOp, DeleteOp, DestClass, OtaOp, RT_PPM,
};
use azos_decision::{Rule, Verdict};
use std::sync::atomic::{AtomicU32, Ordering};

/// The kinds an `[envelope.NAME]` row holds.
const ROW_KINDS: [u8; 5] = [KIND_STORAGE_DELETE, KIND_NET_EGRESS, KIND_CONFIG_WRITE, KIND_OTA_APPLY, KIND_RT_TIME];

/// The Domains of this scene: a sandboxed one (its rows say `contained`), a
/// cautious one, a slow one and a developer's (its rows say `full`).
const SANDBOX: u32 = 0xE0_0001;
const CAUTIOUS: u32 = 0xE0_0002;
const SLOW: u32 = 0xE0_0003;
const DEV: u32 = 0xE0_0004;
/// A task seeded from no row (the kernel's own work).
const KERNEL: u32 = 0xE0_0005;

/// The model of the kernel's probe: the level of the row for a Domain.
fn probe(tid: u32, kind: u8) -> u8 {
    assert!(ROW_KINDS.contains(&kind), "only the row kinds are asked");
    match tid {
        SANDBOX => 3,
        CAUTIOUS => 1,
        SLOW => 2,
        _ => 0,
    }
}

fn delete(tid: u32, op: DeleteOp, volume: u32) -> Effect {
    Effect { kind: KIND_STORAGE_DELETE, class: Class::Reversible, subject: op as u16, tid, a0: volume, a1: 0 }
}

fn egress(tid: u32, class: DestClass, dest: [u8; 4], port: u16) -> Effect {
    Effect {
        kind: KIND_NET_EGRESS,
        class: Class::Reversible,
        subject: port,
        tid,
        a0: u32::from_be_bytes(dest),
        a1: class as u32,
    }
}

fn run(e: &Effect, ran: &AtomicU32) -> Result<(), effect_gate::Refusal> {
    effect_gate::issue(e, &Timing::NONE, || { ran.fetch_add(1, Ordering::SeqCst); ((), true) })
}

fn records_of(rule: Rule, since: u64) -> u32 {
    let mut n = 0;
    azos_decision::for_each(|r| n += (r.seq > since && r.rule == rule as u8) as u32);
    n
}

/// A sandboxed Domain (`delete` row `contained`) is refused every delete with a
/// `Rule::EnvelopeDelete` record `[op, volume, level]` and a receipt `why`
/// finds; the op is not run and nothing is queued on the ring. **Canary.**
/// `envelope-row-canary`: the gate ignores the row, the delete goes, red.
#[test]
fn a_contained_delete_row_refuses_every_delete_with_a_receipt() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    let base = azos_decision::total();
    let queued = logger_ring_len();
    let ran = AtomicU32::new(0);
    for op in [DeleteOp::Truncate, DeleteOp::Replace, DeleteOp::Unlink, DeleteOp::SnapshotDrop] {
        let Err(refusal) = run(&delete(SANDBOX, op, 2), &ran) else {
            panic!("{op:?} passed a contained delete row")
        };
        assert_eq!(refusal.why, Why::Envelope);
        let rec = azos_decision::lookup(refusal.receipt).expect("the receipt is a decision record");
        assert_eq!((rec.rule, rec.verdict, rec.subject), (Rule::EnvelopeDelete as u8, Verdict::Refuse as u8, SANDBOX));
        assert_eq!(rec.n, [op as u64, 2, 3], "op, volume, level");
    }
    assert_eq!(ran.load(Ordering::SeqCst), 0, "a refused delete reached the volume");
    assert_eq!(logger_ring_len(), queued, "a refused delete left a record on the ring");
    assert_eq!(records_of(Rule::EnvelopeDelete, base), 4, "one record per refusal");
}

/// The ladder, through the gate: `cautious` stops the drop of a snapshot,
/// `slow` lets only a truncate through. What goes through is recorded
/// write-ahead (one ring record); what is refused leaves none.
#[test]
fn a_delete_row_is_a_ceiling_on_how_much_a_domain_may_destroy() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    let ran = AtomicU32::new(0);
    let admitted = |tid, op| run(&delete(tid, op, 0), &ran).is_ok();
    assert!(admitted(CAUTIOUS, DeleteOp::Truncate));
    assert!(admitted(CAUTIOUS, DeleteOp::Replace));
    assert!(admitted(CAUTIOUS, DeleteOp::Unlink));
    assert!(!admitted(CAUTIOUS, DeleteOp::SnapshotDrop));
    assert!(admitted(SLOW, DeleteOp::Truncate));
    assert!(!admitted(SLOW, DeleteOp::Replace));
    assert!(!admitted(SLOW, DeleteOp::Unlink));
    assert_eq!(ran.load(Ordering::SeqCst), 4);
    assert_eq!(logger_ring_len(), 4, "each admitted delete under a row is on the ring first");
}

/// A Domain whose rows say `full`, and a task seeded from no row, are held by
/// nothing: the op runs, no record is written (a full ring cannot refuse an
/// unlink on a dev image), no decision record either.
#[test]
fn a_full_row_holds_nothing_and_records_nothing() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    let base = azos_decision::total();
    let ran = AtomicU32::new(0);
    for tid in [DEV, KERNEL] {
        run(&delete(tid, DeleteOp::SnapshotDrop, 0), &ran).expect("full holds nothing");
        run(&egress(tid, DestClass::Public, [8, 8, 8, 8], 53), &ran).expect("full holds nothing");
    }
    assert_eq!(ran.load(Ordering::SeqCst), 4);
    assert_eq!(logger_ring_len(), 0);
    assert_eq!(azos_decision::total(), base);
    // The same with no probe installed at all: today's behaviour.
    effect_gate::clear_envelope_probe_for_test();
    run(&delete(SANDBOX, DeleteOp::Unlink, 0), &ran).expect("no probe, no row");
}

/// A full ring refuses what a row admits with a record to write (the gate's
/// contract for a reversible effect), and still refuses nothing for `full`.
#[test]
fn a_ring_at_its_limit_refuses_an_admitted_delete_under_a_row_only() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    let ran = AtomicU32::new(0);
    for _ in 0..ORDINARY_RING_LIMIT {
        run(&delete(CAUTIOUS, DeleteOp::Unlink, 0), &ran).expect("room left");
    }
    assert_eq!(logger_ring_len(), ORDINARY_RING_LIMIT, "each admitted delete under a row is on the ring first");
    let before = ran.load(Ordering::SeqCst);
    assert_eq!(run(&delete(CAUTIOUS, DeleteOp::Unlink, 0), &ran).err().map(|r| r.why), Some(Why::RingFull));
    run(&delete(DEV, DeleteOp::Unlink, 0), &ran).expect("a full row is not refused for a full ring");
    assert_eq!(ran.load(Ordering::SeqCst), before + 1);
}

/// The egress ladder: `cautious` reaches private networks and not the public
/// internet, `slow` the local link, `contained` nothing. A refusal is
/// `Rule::EnvelopeEgress` `[dest, class, level]` with a receipt; the packet
/// is not sent. **Canary.** `envelope-row-canary`: red.
#[test]
fn an_egress_row_holds_a_domain_to_the_classes_its_level_reaches() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    let base = azos_decision::total();
    let ran = AtomicU32::new(0);
    let to = |tid, dest: [u8; 4]| {
        let class = classify_v4(dest).expect("a destination off the node");
        run(&egress(tid, class, dest, 443), &ran)
    };
    assert!(to(CAUTIOUS, [10, 0, 2, 2]).is_ok());
    assert!(to(CAUTIOUS, [169, 254, 1, 1]).is_ok());
    let Err(r) = to(CAUTIOUS, [93, 184, 216, 34]) else { panic!("cautious reached the public internet") };
    assert_eq!(r.why, Why::Envelope);
    let rec = azos_decision::lookup(r.receipt).expect("receipt");
    assert_eq!((rec.rule, rec.verdict, rec.subject), (Rule::EnvelopeEgress as u8, Verdict::Refuse as u8, CAUTIOUS));
    assert_eq!(rec.n, [u32::from_be_bytes([93, 184, 216, 34]) as u64, DestClass::Public as u64, 1], "dest, class, level");
    assert!(to(SLOW, [224, 0, 0, 251]).is_ok(), "multicast is the local link");
    assert!(to(SLOW, [192, 168, 1, 7]).is_err());
    assert!(to(SANDBOX, [169, 254, 1, 1]).is_err());
    assert!(to(SANDBOX, [10, 0, 2, 2]).is_err());
    assert!(to(DEV, [93, 184, 216, 34]).is_ok());
    assert_eq!(ran.load(Ordering::SeqCst), 4);
    assert_eq!(records_of(Rule::EnvelopeEgress, base), 4);
}

/// The data's provenance holds a delete or a packet as well: the more
/// restrictive of the Domain's row and the meet decides, and a tie is the
/// data's (`Rule::ProvenanceMeet`).
#[test]
fn the_provenance_meet_holds_a_delete_too_and_a_tie_is_the_datas() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    fn meet_of(tid: u32) -> (u32, u8) {
        match tid {
            DEV => (1 << 3, 3),
            SLOW => (1 << 3, 2),
            SANDBOX => (1 << 3, 1),
            _ => (0, 0),
        }
    }
    effect_gate::set_provenance_probe(meet_of);
    let ran = AtomicU32::new(0);
    // A developer's Domain (row full) that worked on the agent's data (meet contained).
    let r = run(&delete(DEV, DeleteOp::Truncate, 0), &ran).unwrap_err();
    assert_eq!(r.why, Why::Provenance);
    assert_eq!(azos_decision::lookup(r.receipt).unwrap().rule, Rule::ProvenanceMeet as u8);
    // Row and meet equal (slow): the data's.
    let r = run(&delete(SLOW, DeleteOp::Unlink, 0), &ran).unwrap_err();
    assert_eq!(r.why, Why::Provenance);
    // The row (contained) is stricter than the meet (cautious): the row's.
    let r = run(&delete(SANDBOX, DeleteOp::Truncate, 0), &ran).unwrap_err();
    assert_eq!(r.why, Why::Envelope);
    assert_eq!(azos_decision::lookup(r.receipt).unwrap().rule, Rule::EnvelopeDelete as u8);
    effect_gate::set_provenance_probe(|_| (0, 0));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
}

/// A stop is a different class and never reaches these rows; and a kind the
/// rows do not name is not asked about at all.
#[test]
fn the_probe_is_asked_for_the_row_kinds_only() {
    let _g = fresh();
    fn strict(_tid: u32, kind: u8) -> u8 {
        assert!(ROW_KINDS.contains(&kind), "asked about kind {kind}");
        3
    }
    effect_gate::set_envelope_probe(strict);
    let ran = AtomicU32::new(0);
    let motor = Effect { kind: effect_gate::KIND_MOTOR, class: Class::Reversible, subject: 29, tid: SANDBOX, a0: 1, a1: 90 };
    run(&motor, &ran).expect("a motor effect is not held by a delete row");
    let clock = Effect { kind: effect_gate::KIND_CLOCK, class: Class::Reversible, subject: 29, tid: SANDBOX, a0: 1, a1: 90 };
    run(&clock, &ran).expect("nor a clock");
    effect_gate::set_envelope_probe(probe);
    assert_eq!(ENVELOPE_FULL, 0);
}

fn config(tid: u32, key: &[u8]) -> Effect {
    let (op, k) = (ConfigOp::of_key(key), key_word(key));
    Effect { kind: KIND_CONFIG_WRITE, class: Class::Reversible, subject: op as u16, tid, a0: k as u32, a1: (k >> 32) as u32 }
}

fn ota(tid: u32, op: OtaOp, slot: u8) -> Effect {
    Effect { kind: KIND_OTA_APPLY, class: Class::Reversible, subject: op as u16, tid, a0: slot as u32, a1: 0 }
}

fn rt(tid: u32, density_ppm: u32) -> Effect {
    Effect { kind: KIND_RT_TIME, class: Class::Reversible, subject: 0, tid, a0: density_ppm, a1: 0 }
}

/// A Domain whose `config` row says `contained` writes no key at all, and one
/// whose row says `cautious` writes every key but those that open a way in or
/// change what boots. A refusal is `Rule::EnvelopeConfig` `[op, key, level]`
/// with a receipt, and nothing is stored. **Canary.** `envelope-row-canary`:
/// the gate ignores the row, the write goes, red.
#[test]
fn a_contained_config_row_refuses_every_key_with_a_receipt() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    let base = azos_decision::total();
    let ran = AtomicU32::new(0);
    for key in [&b"sched_hz"[..], b"watchdog_ms", b"autorun"] {
        let Err(refusal) = run(&config(SANDBOX, key), &ran) else { panic!("{key:?} passed a contained config row") };
        assert_eq!(refusal.why, Why::Envelope);
        let rec = azos_decision::lookup(refusal.receipt).expect("the receipt is a decision record");
        assert_eq!((rec.rule, rec.verdict, rec.subject), (Rule::EnvelopeConfig as u8, Verdict::Refuse as u8, SANDBOX));
        assert_eq!(rec.n, [ConfigOp::of_key(key) as u64, key_word(key), 3], "op, key, level");
    }
    assert_eq!(ran.load(Ordering::SeqCst), 0, "a refused write reached the store");
    assert_eq!(records_of(Rule::EnvelopeConfig, base), 3);
    // The ladder: cautious stops the keys that open a way in, slow all but tuning.
    assert!(run(&config(CAUTIOUS, b"sched_hz"), &ran).is_ok());
    assert!(run(&config(CAUTIOUS, b"watchdog_ms"), &ran).is_ok());
    assert!(run(&config(CAUTIOUS, b"ota_auto_recv_port"), &ran).is_err());
    assert!(run(&config(SLOW, b"sched_hz"), &ran).is_ok());
    assert!(run(&config(SLOW, b"estop_gpio_pin"), &ran).is_err());
    assert_eq!(ran.load(Ordering::SeqCst), 3);
}

/// `cautious` lets a Domain stage an update and not switch to it; `slow` and
/// `contained` neither. A refusal is `Rule::EnvelopeOta` `[step, slot, level]`.
/// **Canary.** `envelope-row-canary`: red.
#[test]
fn an_ota_row_stops_a_domain_at_the_step_its_level_reaches() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    let base = azos_decision::total();
    let ran = AtomicU32::new(0);
    assert!(run(&ota(CAUTIOUS, OtaOp::Stage, 1), &ran).is_ok());
    let Err(r) = run(&ota(CAUTIOUS, OtaOp::Switch, 1), &ran) else { panic!("cautious switched") };
    let rec = azos_decision::lookup(r.receipt).expect("receipt");
    assert_eq!((rec.rule, rec.verdict, rec.subject), (Rule::EnvelopeOta as u8, Verdict::Refuse as u8, CAUTIOUS));
    assert_eq!(rec.n, [OtaOp::Switch as u64, 1, 1], "step, slot, level");
    assert!(run(&ota(SLOW, OtaOp::Stage, 1), &ran).is_err());
    assert!(run(&ota(SANDBOX, OtaOp::Stage, 0), &ran).is_err());
    assert!(run(&ota(DEV, OtaOp::Switch, 1), &ran).is_ok());
    assert!(run(&ota(KERNEL, OtaOp::Switch, 1), &ran).is_ok());
    assert_eq!(ran.load(Ordering::SeqCst), 3);
    assert_eq!(records_of(Rule::EnvelopeOta, base), 3);
}

/// A reservation is held to the share of a hart the row lets one take: half
/// under `cautious`, a tenth under `slow`, none under `contained`. A refusal is
/// `Rule::EnvelopeRtTime` `[asked_ppm, ceiling_ppm, level]`. **Canary.**
/// `envelope-row-canary`: red.
#[test]
fn an_rt_time_row_caps_what_one_reservation_may_take() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    let base = azos_decision::total();
    let ran = AtomicU32::new(0);
    assert!(run(&rt(CAUTIOUS, RT_PPM / 2), &ran).is_ok());
    let Err(r) = run(&rt(CAUTIOUS, RT_PPM / 2 + 1), &ran) else { panic!("cautious took more than half a hart") };
    let rec = azos_decision::lookup(r.receipt).expect("receipt");
    assert_eq!((rec.rule, rec.verdict, rec.subject), (Rule::EnvelopeRtTime as u8, Verdict::Refuse as u8, CAUTIOUS));
    assert_eq!(rec.n, [(RT_PPM / 2 + 1) as u64, (RT_PPM / 2) as u64, 1], "asked, ceiling, level");
    assert!(run(&rt(SLOW, RT_PPM / 10), &ran).is_ok());
    assert!(run(&rt(SLOW, RT_PPM / 10 + 1), &ran).is_err());
    assert!(run(&rt(SANDBOX, 1), &ran).is_err());
    assert!(run(&rt(DEV, RT_PPM), &ran).is_ok());
    assert!(run(&rt(KERNEL, RT_PPM), &ran).is_ok());
    assert_eq!(ran.load(Ordering::SeqCst), 4);
    assert_eq!(records_of(Rule::EnvelopeRtTime, base), 3, "one record per refusal");
}

/// `full` rows and tasks of no row hold none of the three: no record, no ring
/// slot, no decision record, even with the ring at its limit.
#[test]
fn a_full_row_holds_no_config_write_update_step_or_reservation() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    let base = azos_decision::total();
    let ran = AtomicU32::new(0);
    for _ in 0..ORDINARY_RING_LIMIT + 4 {
        for tid in [DEV, KERNEL] {
            run(&config(tid, b"autorun"), &ran).expect("full");
            run(&ota(tid, OtaOp::Switch, 1), &ran).expect("full");
            run(&rt(tid, RT_PPM), &ran).expect("full");
        }
    }
    assert_eq!(logger_ring_len(), 0);
    assert_eq!(azos_decision::total(), base);
}

/// The ask hook the sites below the gate call (`azos_common::envelope::asked`):
/// a gate that answers from the effect gate holds a configuration write by its
/// key's op, an update step and a reservation, and with no gate installed every
/// ask is let through. The model gate is what `envelope.rs` installs.
#[test]
fn the_ask_hook_carries_a_write_a_step_and_a_reservation_to_the_gate() {
    let _g = fresh();
    effect_gate::set_envelope_probe(probe);
    static CALLER: AtomicU32 = AtomicU32::new(0);
    fn model(ask: Ask) -> bool {
        let tid = CALLER.load(Ordering::SeqCst);
        let e = match ask {
            Ask::Config { op, key } => Effect {
                kind: KIND_CONFIG_WRITE, class: Class::Reversible, subject: op as u16, tid, a0: key as u32, a1: (key >> 32) as u32,
            },
            Ask::Ota { op, slot } => ota(tid, op, slot),
            Ask::RtTime { tid, density_ppm } => rt(tid, density_ppm),
        };
        effect_gate::record(&e).is_ok()
    }
    envelope::clear_ask_gate_for_test();
    assert!(envelope::config_write_admitted(b"autorun"), "no gate: today's behaviour");
    envelope::set_ask_gate(model);
    CALLER.store(CAUTIOUS, Ordering::SeqCst);
    assert!(envelope::config_write_admitted(b"watchdog_ms"));
    assert!(!envelope::config_write_admitted(b"autorun"));
    assert!(envelope::asked(Ask::Ota { op: OtaOp::Stage, slot: 1 }));
    assert!(!envelope::asked(Ask::Ota { op: OtaOp::Switch, slot: 1 }));
    assert!(!envelope::asked(Ask::RtTime { tid: SANDBOX, density_ppm: 1 }));
    assert!(envelope::asked(Ask::RtTime { tid: DEV, density_ppm: RT_PPM }));
    envelope::clear_ask_gate_for_test();
}

/// The ties to the sites that ask: the one body behind `config set` (console
/// and ring-3 interface alike) asks the `config` row before it stores a byte,
/// and the kernel's volume store answers the updater's `may_apply` by asking
/// the `ota` row for the step and the slot. **Canary.** Delete either call: red.
#[test]
fn the_config_store_and_the_updater_ask_the_gate_at_their_one_site() {
    let fam = include_str!("../../../../crates/core/recovery/src/families.rs");
    let body = &fam[fam.find("pub fn config_set(").expect("config_set")..];
    let body = &body[..body.find("\n}\n").expect("end of config_set")];
    let ask = body.find("config_write_admitted(key)").expect("the config row is asked");
    assert!(ask < body.find("cfg_set(").expect("the store"), "asked after the store");
    assert_eq!(body.matches("config_write_admitted(").count(), 1);

    let ota = include_str!("../../../../crates/core/ota/src/lib.rs");
    let body = &ota[ota.find("fn may_apply(").expect("the kernel store's may_apply")..];
    let body = &body[..body.find("\n    }\n").expect("end of may_apply")];
    assert!(body.contains("asked(Ask::Ota { op, slot })"), "{body}");
    let upd = include_str!("../../../../crates/core/ota/src/update.rs");
    assert_eq!(upd.matches("gate_open(store,").count(), 2, "one question in stage, one in switch");
}

/// The Domain's row has to be on record when the reservation is asked: the
/// probe finds it through `natfork::row_of`, and finds none (so lets the
/// reservation go) for a task the spawn has not recorded yet. A topology
/// task's reservation is made at spawn, so `spawn.rs` records the child's row
/// before it calls `rt::reserve`, and does so once for the one reservation it
/// makes there. The source is read with its whitespace removed.
///
/// **Canary.** Move the `record_row_named` call after the reservation, or
/// delete it (`seed_caps` records it later, which is too late): red.
#[test]
fn a_spawn_records_the_childs_row_before_it_reserves() {
    let src: String = include_str!("../../../../crates/core/syscall/src/spawn.rs").split_whitespace().collect();
    assert_eq!(src.matches("rt::reserve(").count(), 1, "one reservation at spawn");
    let reserve = src.find("rt::reserve(").unwrap();
    let record = src[..reserve].rfind("natfork::record_row_named(tid,").expect("the row is recorded before the reservation");
    // Nothing between the record and the reservation can change the child's slot.
    assert!(!src[record..reserve].contains("seed_caps("), "the capabilities are seeded between them");
    assert!(src[record..reserve].len() < 600, "the record is far from the reservation it serves");
}

mod ladders {
    use super::*;

    #[test]
    fn config_ota_and_rt_ladders() {
        let want: [[bool; 3]; 4] = [[true, true, true], [true, true, false], [true, false, false], [false, false, false]];
        for (level, row) in want.iter().enumerate() {
            for (op, &ok) in [ConfigOp::Tune, ConfigOp::Arm, ConfigOp::Open].iter().zip(row) {
                assert_eq!(op.permitted(level as u8), ok, "level {level} op {op:?}");
            }
        }
        assert!(!ConfigOp::Tune.permitted(200));
        let ota: [[bool; 2]; 4] = [[true, true], [true, false], [false, false], [false, false]];
        for (level, row) in ota.iter().enumerate() {
            for (op, &ok) in [OtaOp::Stage, OtaOp::Switch].iter().zip(row) {
                assert_eq!(op.permitted(level as u8), ok, "level {level} op {op:?}");
            }
        }
        for n in 0..6u8 {
            assert_eq!(ConfigOp::from_u8(n).is_some(), (1..=3).contains(&n));
            assert_eq!(OtaOp::from_u8(n).is_some(), (1..=2).contains(&n));
        }
        assert_eq!(
            [0u8, 1, 2, 3, 200].map(envelope::rt_ceiling_ppm),
            [RT_PPM, RT_PPM / 2, RT_PPM / 10, 0, 0]
        );
        assert!(envelope::rt_permitted(0, RT_PPM) && !envelope::rt_permitted(3, 1));
    }

    #[test]
    fn a_key_word_reads_back_the_key() {
        assert_eq!(&key_word(b"watchdog_ms").to_le_bytes(), b"watchdog");
        assert_eq!(&key_word(b"bench").to_le_bytes()[..5], b"bench");
        assert_eq!(key_word(b""), 0);
    }

    #[test]
    fn delete_ladder() {
        let ops = [DeleteOp::Truncate, DeleteOp::Replace, DeleteOp::Unlink, DeleteOp::SnapshotDrop];
        let want: [[bool; 4]; 4] = [
            [true, true, true, true],
            [true, true, true, false],
            [true, false, false, false],
            [false, false, false, false],
        ];
        for (level, row) in want.iter().enumerate() {
            for (op, &ok) in ops.iter().zip(row) {
                assert_eq!(op.permitted(level as u8), ok, "level {level} op {op:?}");
            }
        }
        assert!(!DeleteOp::Truncate.permitted(200), "past contained is contained");
        for n in 0..8u8 {
            assert_eq!(DeleteOp::from_u8(n).map(|o| o as u8).unwrap_or(0), if (1..=4).contains(&n) { n } else { 0 });
        }
    }

    #[test]
    fn egress_ladder() {
        let classes = [DestClass::Link, DestClass::Private, DestClass::Public];
        let want: [[bool; 3]; 4] =
            [[true, true, true], [true, true, false], [true, false, false], [false, false, false]];
        for (level, row) in want.iter().enumerate() {
            for (c, &ok) in classes.iter().zip(row) {
                assert_eq!(c.permitted(level as u8), ok, "level {level} class {c:?}");
            }
        }
        assert!(!DestClass::Link.permitted(200));
    }

    #[test]
    fn v4_classes() {
        assert_eq!(classify_v4([127, 0, 0, 1]), None);
        assert_eq!(classify_v4([127, 9, 9, 9]), None);
        assert_eq!(classify_v4([0, 0, 0, 0]), None);
        assert_eq!(classify_v4([169, 254, 1, 1]), Some(DestClass::Link));
        assert_eq!(classify_v4([224, 0, 0, 251]), Some(DestClass::Link));
        assert_eq!(classify_v4([255, 255, 255, 255]), Some(DestClass::Link));
        assert_eq!(classify_v4([10, 0, 2, 2]), Some(DestClass::Private));
        assert_eq!(classify_v4([172, 16, 0, 1]), Some(DestClass::Private));
        assert_eq!(classify_v4([172, 31, 255, 1]), Some(DestClass::Private));
        assert_eq!(classify_v4([172, 32, 0, 1]), Some(DestClass::Public));
        assert_eq!(classify_v4([192, 168, 1, 1]), Some(DestClass::Private));
        assert_eq!(classify_v4([100, 64, 0, 1]), Some(DestClass::Private));
        assert_eq!(classify_v4([100, 128, 0, 1]), Some(DestClass::Public));
        assert_eq!(classify_v4([8, 8, 8, 8]), Some(DestClass::Public));
    }

    #[test]
    fn v6_classes() {
        let mut a = [0u8; 16];
        assert_eq!(classify_v6(a), None);
        a[15] = 1;
        assert_eq!(classify_v6(a), None);
        let mut ll = [0u8; 16];
        ll[0] = 0xfe;
        ll[1] = 0x80;
        assert_eq!(classify_v6(ll), Some(DestClass::Link));
        ll[1] = 0xbf;
        assert_eq!(classify_v6(ll), Some(DestClass::Link));
        ll[1] = 0xc0;
        assert_eq!(classify_v6(ll), Some(DestClass::Public), "fec0::/10 is not link-local");
        let mut ula = [0u8; 16];
        ula[0] = 0xfd;
        assert_eq!(classify_v6(ula), Some(DestClass::Private));
        let mut mc = [0u8; 16];
        mc[0] = 0xff;
        assert_eq!(classify_v6(mc), Some(DestClass::Link));
        let mut g = [0u8; 16];
        g[0] = 0x20;
        g[1] = 0x01;
        assert_eq!(classify_v6(g), Some(DestClass::Public));
        let mut m = [0u8; 16];
        m[10] = 0xff;
        m[11] = 0xff;
        m[12..].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(classify_v6(m), Some(DestClass::Private), "mapped addresses follow their IPv4 half");
        m[12..].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(classify_v6(m), None);
    }
}

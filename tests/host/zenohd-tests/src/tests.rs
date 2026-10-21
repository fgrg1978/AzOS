// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::gw::{code, Gw, State, PUBLISH_BURST, PUBLISH_PERIOD_NS};
use crate::route::{export, route, sole_lendable, NoRoute};
use crate::world::*;
use azos_decision::{Rule, Verdict};
use azos_decisions::{DecisionsClient, ProvenanceRecord, VERDICTS, RULES};
use azos_idl::{header, MsgDesc, Transport};
use azos_zenoh::network::{
    Declaration, Declare, Encoding, Interest, InterestMode, InterestOptions, NetworkMsg, PushBody, Query, Request,
    ResponseBody, SourceInfo,
};
use azos_zenoh::transport::{Close, Transport as Msg};

// ── helpers ──────────────────────────────────────────────────────────────────

fn request(id: u32, key: &str, args: &[u64], timeout: Option<u64>, src: Option<azos_zenoh::Zid>) -> Vec<u8> {
    let body = words(args);
    let q = Query {
        consolidation: None,
        parameters: "",
        source_info: src.map(|z| SourceInfo { zid: z, eid: 0, sn: 0 }),
        body: if args.is_empty() { None } else { Some((Encoding { id: 0, schema: None }, &body)) },
        attachment: None,
    };
    router_frame(
        id as u64,
        &[NetworkMsg::Request(Request {
            id,
            key: plain(key),
            qos: None,
            timestamp: None,
            node_id: None,
            target: None,
            budget: None,
            timeout_ms: timeout,
            query: q,
        })],
    )
}

/// What the gateway answered: `(is_err, key, payload words)` of the RESPONSE,
/// and the ids of the RESPONSE_FINALs.
#[derive(Debug, PartialEq)]
struct Answer {
    err: bool,
    key: String,
    words: Vec<u64>,
    finals: Vec<u32>,
    responses: usize,
}

fn le_words(b: &[u8]) -> Vec<u64> {
    assert_eq!(b.len() % 8, 0, "payload is whole words");
    b.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
}

fn answer(batches: &[Vec<u8>]) -> Answer {
    with_nets(batches, |nets| {
        let mut a = Answer { err: false, key: String::new(), words: Vec::new(), finals: Vec::new(), responses: 0 };
        for n in nets {
            match n {
                NetworkMsg::Response(r) => {
                    a.responses += 1;
                    a.key = r.key.suffix.to_string();
                    match &r.body {
                        ResponseBody::Reply(rep) => match &rep.body {
                            PushBody::Put(p) => a.words = le_words(p.payload),
                            PushBody::Del(_) => panic!("a reply is a put"),
                        },
                        ResponseBody::Err(e) => {
                            a.err = true;
                            a.words = le_words(e.payload);
                        }
                    }
                }
                NetworkMsg::ResponseFinal(f) => a.finals.push(f.id),
                _ => {}
            }
        }
        a
    })
}

/// The decision record `id` as a client of the Decisions interface sees it.
fn record(k: &mut Kernel, id: u64) -> ProvenanceRecord {
    struct Via<'a>(std::cell::RefCell<&'a mut Kernel>);
    impl Transport for Via<'_> {
        fn call(&self, m: &mut MsgDesc) -> azos_idl::Result {
            crate::gw::Host::decisions(&mut **self.0.borrow_mut(), m).map_err(|e| azos_idl::IdlError::Transport(e as isize))
        }
    }
    let c = DecisionsClient::new(Via(std::cell::RefCell::new(k)));
    azos_decisions::fetch(&c, id).unwrap().expect("the receipt names a decision the journal holds")
}

fn pushes(batches: &[Vec<u8>]) -> Vec<(String, Vec<u8>)> {
    with_nets(batches, |nets| {
        nets.iter()
            .filter_map(|n| match n {
                NetworkMsg::Push(p) => match &p.body {
                    PushBody::Put(put) => Some((p.key.suffix.to_string(), put.payload.to_vec())),
                    PushBody::Del(_) => None,
                },
                _ => None,
            })
            .collect()
    })
}

// ── the session ──────────────────────────────────────────────────────────────

#[test]
fn the_first_message_is_the_init_the_specification_writes() {
    let (mut k, mut wire) = (Kernel::new(), Wire::default());
    let mut g = Gw::new(config(), lamp_exports());
    g.start(&mut k, &mut wire);
    assert_eq!(g.state(), State::InitSent);
    let b = wire.take();
    assert_eq!(b.len(), 1);
    // INIT | S, version 9, whatami client (2) with the ZenohID length - 1 (15)
    // in the high nibble, the 16 ID bytes, resolution 32/32 bits (0x0A), batch
    // size 2048 little-endian.
    let mut want = vec![0x41, 0x09, 0xF2];
    want.extend_from_slice(&MINE);
    want.extend_from_slice(&[0x0A, 0x00, 0x08]);
    assert_eq!(b[0], want);
}

#[test]
fn open_returns_the_cookie_and_the_queryables_follow_it() {
    let (mut k, mut wire) = (Kernel::new(), Wire::default());
    let mut g = Gw::new(config(), lamp_exports());
    g.start(&mut k, &mut wire);
    wire.take();
    g.on_bytes(&mut k, &mut wire, &init_ack(&[9, 8, 7]));
    assert_eq!(g.state(), State::OpenSent);
    let b = wire.take();
    match first_transport(&b[0]) {
        Msg::Open(o) => {
            assert_eq!(o.cookie, Some(&[9u8, 8, 7][..]), "the cookie of InitAck comes back in OpenSyn");
            assert_eq!(o.lease.millis(), 10_000, "the lease Kconfig states");
            assert!(!o.is_ack());
        }
        m => panic!("expected OPEN, got {m:?}"),
    }
    g.on_bytes(&mut k, &mut wire, &open_ack(10));
    assert_eq!(g.state(), State::Up);
    with_nets(&wire.take(), |nets| {
        assert_eq!(nets.len(), 1, "one queryable for the one export");
        match &nets[0] {
            NetworkMsg::Declare(Declare { body: Declaration::Queryable { id, key, complete, .. }, interest_id: None, .. }) => {
                assert_eq!((*id, key.suffix, *complete), (1, "azos/lamp/**", false));
            }
            m => panic!("expected a queryable declaration, got {m:?}"),
        }
    });
}

#[test]
fn a_router_that_speaks_another_version_is_refused() {
    let (mut k, mut wire) = (Kernel::new(), Wire::default());
    let mut g = Gw::new(config(), lamp_exports());
    g.start(&mut k, &mut wire);
    wire.take();
    let bad = router_msg(&Msg::Init(azos_zenoh::transport::Init {
        version: 0x0A,
        whatami: azos_zenoh::transport::WhatAmI::Router,
        zid: zid(0x11),
        size: None,
        cookie: Some(&[1]),
        qos: false,
        patch: 0,
    }));
    g.on_bytes(&mut k, &mut wire, &bad);
    assert_eq!(g.state(), State::Dead);
    assert!(matches!(first_transport(&wire.take()[0]), Msg::Close(Close { session: true, .. })));
}

#[test]
fn an_interest_in_queryables_is_answered_with_them_and_a_final() {
    let (mut g, mut k, mut wire) = up();
    let i = Interest {
        id: 77,
        mode: InterestMode::CurrentFuture,
        options: Some(InterestOptions { keyexprs: false, subscribers: false, queryables: true, tokens: false, aggregate: false, key: None }),
        qos: None,
        timestamp: None,
        node_id: None,
    };
    g.on_bytes(&mut k, &mut wire, &router_frame(1, &[NetworkMsg::Interest(i)]));
    with_nets(&wire.take(), |nets| {
        assert_eq!(nets.len(), 2);
        assert!(matches!(&nets[0], NetworkMsg::Declare(Declare { interest_id: Some(77), body: Declaration::Queryable { .. }, .. })));
        assert!(matches!(&nets[1], NetworkMsg::Declare(Declare { interest_id: Some(77), body: Declaration::Final, .. })));
    });
    // An interest in subscribers: nothing declared, but the list ends.
    let i = Interest {
        id: 78,
        mode: InterestMode::Current,
        options: Some(InterestOptions { keyexprs: false, subscribers: true, queryables: false, tokens: false, aggregate: false, key: None }),
        qos: None,
        timestamp: None,
        node_id: None,
    };
    g.on_bytes(&mut k, &mut wire, &router_frame(2, &[NetworkMsg::Interest(i)]));
    with_nets(&wire.take(), |nets| {
        assert_eq!(nets.len(), 1);
        assert!(matches!(&nets[0], NetworkMsg::Declare(Declare { interest_id: Some(78), body: Declaration::Final, .. })));
    });
}

#[test]
fn keepalive_runs_at_a_quarter_of_the_routers_lease_and_silence_ends_the_session() {
    let (mut g, mut k, mut wire) = up();
    // The router's lease is 10 s: a KEEP_ALIVE at 2.5 s of our silence.
    k.now += 2_400_000_000;
    g.tick(&mut k, &mut wire);
    assert!(wire.take().is_empty(), "not yet");
    k.now += 200_000_000;
    g.tick(&mut k, &mut wire);
    let b = wire.take();
    assert_eq!(b.len(), 1);
    assert!(matches!(first_transport(&b[0]), Msg::KeepAlive));
    // Our lease is 10 s of the router's silence; anything it sends renews it.
    k.now += 9_000_000_000;
    g.on_bytes(&mut k, &mut wire, &router_msg(&Msg::KeepAlive));
    k.now += 9_000_000_000;
    g.tick(&mut k, &mut wire);
    assert_eq!(g.state(), State::Up, "the router spoke 9 s ago");
    k.now += 2_000_000_000;
    g.tick(&mut k, &mut wire);
    assert_eq!(g.state(), State::Dead);
}

#[test]
fn a_message_that_does_not_decode_closes_the_session() {
    let (mut g, mut k, mut wire) = up();
    // A batch of one byte that is no transport message.
    g.on_bytes(&mut k, &mut wire, &[1, 0, 0x1F]);
    assert_eq!(g.state(), State::Dead);
    assert!(matches!(first_transport(&wire.take()[0]), Msg::Close(_)));
}

#[test]
fn a_lost_link_is_noticed_on_the_next_write() {
    let (mut g, mut k, mut wire) = up();
    wire.broken = true;
    g.on_bytes(&mut k, &mut wire, &request(1, "azos/lamp/get", &[], None, None));
    assert_eq!(g.state(), State::Dead);
}

// ── a query is one op ────────────────────────────────────────────────────────

#[test]
fn a_query_becomes_an_op_and_the_reply_carries_the_receipt() {
    let (mut g, mut k, mut wire) = up();
    g.on_bytes(&mut k, &mut wire, &request(42, "azos/lamp/set", &[7], Some(500), Some(zid(0x55))));
    let a = answer(&wire.take());
    assert!(!a.err, "{a:?}");
    assert_eq!(a.finals, vec![42], "the replies end");
    assert_eq!(a.key, "azos/lamp/set");
    // [code, receipt, rule | verdict << 8, status, the op's reply words].
    assert_eq!(a.words.len(), 5, "{a:?}");
    assert_eq!(a.words[0], code::SERVED);
    assert_eq!((a.words[3], a.words[4]), (0, 0), "served, and the level before was 0");
    assert_eq!(k.lamp.level, 7, "the op ran with the argument the query carried");
    assert_eq!(k.lamp.sets, 1);
    // The receipt is the kernel's record of the admission, found through the
    // Decisions interface, and says what it is.
    let receipt = a.words[1];
    assert_ne!(receipt, 0);
    let p = record(&mut k, receipt);
    assert_eq!((p.rule, p.verdict), (Rule::CapDerive as u8, Verdict::Admit as u8));
    assert_eq!(p.subject, DOMAIN, "the derive is written under the Domain, which is not the task id the refusals use");
    assert_eq!(a.words[2], p.rule as u64 | (p.verdict as u64) << 8);
    // The reader works too: the second query sees what the first did.
    g.on_bytes(&mut k, &mut wire, &request(43, "azos/lamp/get", &[], None, None));
    let a = answer(&wire.take());
    assert_eq!((a.err, a.words[0], a.words[4]), (false, code::SERVED, 7));
    assert_ne!(a.words[1], receipt, "each query has its own receipt");
    assert_eq!(g.stats.served, 2);
}

#[test]
fn a_refused_op_answers_with_the_refusal_receipt_and_never_reaches_the_server() {
    let (mut g, mut k, mut wire) = up();
    k.grant = false;
    g.on_bytes(&mut k, &mut wire, &request(9, "azos/lamp/set", &[1], None, None));
    let a = answer(&wire.take());
    assert!(a.err, "a refusal is an error reply: {a:?}");
    assert_eq!(a.finals, vec![9]);
    assert_eq!(a.words[0], code::REFUSED);
    assert_eq!(a.words[3] as i64, -1, "the kernel's code travels as a two's-complement word");
    let receipt = a.words[1];
    assert_ne!(receipt, 0, "the refusal has a receipt");
    let p = record(&mut k, receipt);
    assert_eq!((p.rule, p.verdict, p.subject), (Rule::CapDenial as u8, Verdict::Deny as u8, ME));
    assert_eq!(a.words[2], Rule::CapDenial as u64 | (Verdict::Deny as u64) << 8);
    assert_eq!((k.lamp.sets, k.lamp.level), (0, 0), "canary: the refused op did not run");
    assert_eq!((g.stats.refused, g.stats.served), (1, 0));
}

#[test]
fn the_receipt_is_this_gateways_not_another_tasks() {
    let (mut g, mut k, mut wire) = up();
    k.foreign_during_op = true;
    g.on_bytes(&mut k, &mut wire, &request(1, "azos/lamp/set", &[3], None, None));
    let a = answer(&wire.take());
    let p = record(&mut k, a.words[1]);
    assert_eq!((p.rule, p.subject), (Rule::CapDerive as u8, DOMAIN), "the gateway's own derive");
    assert_eq!(p.n[2], k.now + k.warrants[0].life_ns, "told by the expiry it asked for");
    assert!(k.journal.iter().any(|r| r.subject == ME + 1) && k.journal.iter().any(|r| r.subject == DOMAIN + 1),
        "the other task's refusal and derive are in the journal, after ours, and not taken");
    // Canary: the same run with the gateway believing it is the other task
    // finds that task's refusal (the newest record under its subject): the
    // subject filter is what keeps it out above.
    let mut cfg = config();
    cfg.me = ME + 1;
    let (mut g2, mut k2, mut wire2) = up_with(cfg, lamp_exports());
    k2.foreign_during_op = true;
    g2.on_bytes(&mut k2, &mut wire2, &request(1, "azos/lamp/set", &[3], None, None));
    let a2 = answer(&wire2.take());
    assert_eq!(record(&mut k2, a2.words[1]).subject, ME + 1);
}

#[test]
fn another_tasks_derive_older_than_ours_is_not_taken_for_ours() {
    let (mut g, mut k, mut wire) = up();
    k.foreign_derive_first = true;
    g.on_bytes(&mut k, &mut wire, &request(1, "azos/lamp/get", &[], None, None));
    let p = record(&mut k, answer(&wire.take()).words[1]);
    assert_eq!(p.subject, DOMAIN, "ours, though the other task's derive comes first in the journal");
    assert_eq!(p.n[2], k.now + k.warrants[0].life_ns);
}

#[test]
fn a_call_refused_after_the_warrant_was_minted_has_the_refusal_for_receipt() {
    let (mut g, mut k, mut wire) = up();
    k.refuse_call = true;
    g.on_bytes(&mut k, &mut wire, &request(1, "azos/lamp/set", &[3], None, None));
    let a = answer(&wire.take());
    assert!(a.err);
    let p = record(&mut k, a.words[1]);
    assert_eq!((p.rule, p.verdict, p.subject), (Rule::CapDenial as u8, Verdict::Deny as u8, ME));
    let derive = k.journal.iter().find(|r| r.rule == Rule::CapDerive as u8).unwrap().seq;
    assert!(p.seq > derive, "the refusal is newer than the derive that preceded it, and is the receipt");
    assert_eq!(k.lamp.sets, 0);
}

#[test]
fn where_the_kernel_keeps_no_admissions_an_admitted_op_has_no_receipt_and_a_refusal_has() {
    let (mut g, mut k, mut wire) = up();
    k.keep_admits = false;
    g.on_bytes(&mut k, &mut wire, &request(1, "azos/lamp/get", &[], None, None));
    let a = answer(&wire.take());
    assert_eq!((a.err, a.words[0], a.words[1], a.words[2]), (false, code::SERVED, 0, 0));
    k.grant = false;
    g.on_bytes(&mut k, &mut wire, &request(2, "azos/lamp/get", &[], None, None));
    let a = answer(&wire.take());
    assert_eq!((a.err, a.words[0]), (true, code::REFUSED));
    assert_ne!(a.words[1], 0, "refusals are always kept");
}

#[test]
fn the_warrant_is_the_gateways_id_of_the_query_and_the_querys_lifetime() {
    let (mut g, mut k, mut wire) = up();
    g.on_bytes(&mut k, &mut wire, &request(1, "azos/lamp/get", &[], Some(300), Some(zid(0x55))));
    g.on_bytes(&mut k, &mut wire, &request(2, "azos/lamp/get", &[], Some(300), Some(zid(0x55))));
    g.on_bytes(&mut k, &mut wire, &request(3, "azos/lamp/get", &[], Some(300), Some(zid(0x56))));
    // No source info: the id is the same kind.
    g.on_bytes(&mut k, &mut wire, &request(4, "azos/lamp/get", &[], None, None));
    // A timeout over the Kconfig limit is cut to it.
    g.on_bytes(&mut k, &mut wire, &request(5, "azos/lamp/get", &[], Some(60_000), None));
    let w = &k.warrants;
    assert_eq!(w.len(), 5);
    // The ZenohID a query carries is the querier's own claim: two queries that
    // name the same one get two ids, and one that names another's gets its own.
    for (i, x) in w.iter().enumerate() {
        assert_eq!(x.badge, i as u32 + 1, "the gateway counts its queries");
    }
    assert!(w.iter().all(|x| x.badge != 0), "badge 0 is no badge");
    assert_eq!(w[0].life_ns, 300_000_000, "the query's own timeout bounds the warrant");
    assert_eq!(w[3].life_ns, 2_000_000_000, "no timeout: the Kconfig limit");
    assert_eq!(w[4].life_ns, 2_000_000_000, "a timeout over the limit is cut to it");
    assert!(w.iter().all(|x| x.deadline_ns <= x.life_ns), "the call never outlives its warrant");
}

#[test]
fn arguments_that_do_not_fit_the_op_are_refused_before_the_kernel_hears_of_it() {
    let (mut g, mut k, mut wire) = up();
    for (id, args) in [(1u32, vec![]), (2, vec![1u64, 2])] {
        g.on_bytes(&mut k, &mut wire, &request(id, "azos/lamp/set", &args, None, None));
        let a = answer(&wire.take());
        assert!(a.err);
        assert_eq!((a.words[0], a.words[1]), (code::BAD_REQUEST, 0), "no receipt: nothing was asked of the kernel");
        assert_eq!(a.finals, vec![id]);
    }
    // And a reader that is handed an argument.
    g.on_bytes(&mut k, &mut wire, &request(3, "azos/lamp/get", &[1], None, None));
    assert_eq!(answer(&wire.take()).words[0], code::BAD_REQUEST);
    assert_eq!((k.invokes, k.lamp.sets), (0, 0));
    assert_eq!(g.stats.bad, 3);
}

#[test]
fn what_no_export_names_gets_no_reply_but_the_end() {
    let (mut g, mut k, mut wire) = up();
    for key in [
        "azos/other/get",    // outside the export
        "azos/lamp/blink",   // an op the interface does not have
        "azos/lamp/*",       // a wildcard names no op
        "azos/**",           // nor does this
        "azos/lamp/set/get", // deeper, and `get` is an op: served (below)
    ] {
        g.on_bytes(&mut k, &mut wire, &request(5, key, &[], None, None));
        let a = answer(&wire.take());
        assert_eq!(a.finals, vec![5], "{key}");
        if key == "azos/lamp/set/get" {
            assert_eq!(a.responses, 1, "`**` covers the deeper key, and its last chunk is an op");
        } else {
            assert_eq!(a.responses, 0, "{key}");
        }
    }
    assert_eq!(k.invokes, 1, "only the one that named an op reached the kernel");
}

#[test]
fn the_routers_key_ids_resolve_and_ours_do_not_exist() {
    let (mut g, mut k, mut wire) = up();
    // The router defines id 5 as `azos/lamp`; a query then names `5` + `/get`.
    let def = NetworkMsg::Declare(Declare {
        interest_id: None,
        qos: None,
        timestamp: None,
        node_id: None,
        body: Declaration::KeyExpr { id: 5, key: plain("azos/lamp") },
    });
    g.on_bytes(&mut k, &mut wire, &router_frame(1, &[def]));
    let q = |sender: bool, scope: u16| {
        router_frame(
            2,
            &[NetworkMsg::Request(Request {
                id: 8,
                key: azos_zenoh::network::WireExpr { scope, suffix: "/get", sender },
                qos: None,
                timestamp: None,
                node_id: None,
                target: None,
                budget: None,
                timeout_ms: None,
                query: Query { consolidation: None, parameters: "", source_info: None, body: None, attachment: None },
            })],
        )
    };
    g.on_bytes(&mut k, &mut wire, &q(true, 5));
    assert_eq!(answer(&wire.take()).responses, 1);
    // An id from the receiver's own table: this side declared none.
    g.on_bytes(&mut k, &mut wire, &q(false, 5));
    let a = answer(&wire.take());
    assert_eq!((a.responses, a.finals.clone()), (0, vec![8]));
    // An id the router never defined.
    g.on_bytes(&mut k, &mut wire, &q(true, 6));
    assert_eq!(answer(&wire.take()).responses, 0);
    // Undeclared, it is gone.
    let undef = NetworkMsg::Declare(Declare {
        interest_id: None,
        qos: None,
        timestamp: None,
        node_id: None,
        body: Declaration::UndeclareKeyExpr { id: 5 },
    });
    g.on_bytes(&mut k, &mut wire, &router_frame(3, &[undef]));
    g.on_bytes(&mut k, &mut wire, &q(true, 5));
    assert_eq!(answer(&wire.take()).responses, 0);
}

#[test]
fn queries_over_the_rate_are_answered_busy_without_reaching_the_kernel() {
    let mut cfg = config();
    cfg.query_rate = 2;
    let (mut g, mut k, mut wire) = up_with(cfg, lamp_exports());
    for id in 1..=3 {
        g.on_bytes(&mut k, &mut wire, &request(id, "azos/lamp/get", &[], None, None));
    }
    let a = answer(&wire.take());
    assert_eq!(a.finals, vec![1, 2, 3]);
    assert_eq!((k.invokes, g.stats.busy), (2, 1));
    // The third is the last answer in `a` (words of the last RESPONSE seen).
    assert_eq!((a.err, a.words[0]), (true, code::BUSY));
    // A new second, a new allowance.
    k.now += 1_000_000_000;
    g.on_bytes(&mut k, &mut wire, &request(4, "azos/lamp/get", &[], None, None));
    assert_eq!(answer(&wire.take()).words[0], code::SERVED);
}

#[test]
fn an_op_the_server_answers_with_an_idl_error_is_a_failed_query() {
    // The catalog says level 1; a server that serves level 0 answers LevelTooNew.
    static OLD: crate::route::Iface = crate::route::Iface { level: 2, ..crate::world::LAMP_COPY };
    let ex = vec![crate::route::Export { iface: &OLD, endpoint: 1, key: "azos/lamp/**".to_string() }];
    let (mut g, mut k, mut wire) = up_with(config(), ex);
    g.on_bytes(&mut k, &mut wire, &request(1, "azos/lamp/get", &[], None, None));
    let a = answer(&wire.take());
    assert!(a.err);
    assert_eq!(a.words[0], code::FAILED);
    assert_eq!(a.words[3], 3, "IdlError::LevelTooNew");
}

// ── the decision records as topics ───────────────────────────────────────────

#[test]
fn decision_records_are_published_as_they_appear_and_history_is_not() {
    let (mut k, mut wire) = (Kernel::new(), Wire::default());
    k.record(Rule::CapDenial, Verdict::Deny, 3); // before the session: history
    let mut g = Gw::new(config(), lamp_exports());
    g.start(&mut k, &mut wire);
    g.on_bytes(&mut k, &mut wire, &init_ack(&[1]));
    g.on_bytes(&mut k, &mut wire, &open_ack(10));
    wire.take();
    k.record(Rule::EffectRecord, Verdict::Refuse, 4);
    let last = k.record(Rule::CapDenial, Verdict::Deny, 5);
    k.now += PUBLISH_PERIOD_NS + 1;
    g.tick(&mut k, &mut wire);
    let p = pushes(&wire.take());
    assert_eq!(p.len(), 2, "the two new records, not the one before the session: {p:?}");
    let want = |r: Rule, v: Verdict| format!("azos/decisions/{}/{}", RULES[r as usize].name, VERDICTS[v as usize]);
    assert_eq!(p[0].0, want(Rule::EffectRecord, Verdict::Refuse));
    assert_eq!(p[1].0, want(Rule::CapDenial, Verdict::Deny));
    let rec = ProvenanceRecord::from_bytes(&p[1].1).expect("the payload is the record's binary form");
    assert_eq!((rec.seq, rec.subject, rec.rule), (last, 5, Rule::CapDenial as u8));
    assert_eq!(g.stats.published, 2);
    // Nothing new, nothing sent; and not before the period.
    k.now += PUBLISH_PERIOD_NS + 1;
    g.tick(&mut k, &mut wire);
    assert!(pushes(&wire.take()).is_empty());
    k.record(Rule::CapDenial, Verdict::Deny, 6);
    g.tick(&mut k, &mut wire);
    assert!(pushes(&wire.take()).is_empty(), "the period has not passed");
}

#[test]
fn a_burst_is_paced_and_records_that_were_overwritten_are_counted() {
    let (mut g, mut k, mut wire) = up();
    k.retain = 10;
    for i in 0..30 {
        k.record(Rule::CapDenial, Verdict::Deny, 100 + i);
    }
    // Only the newest 10 are held: 21..=30. The first read finds 21 where it
    // expected 1, so 20 were lost; PUBLISH_BURST go out per period.
    k.now += PUBLISH_PERIOD_NS + 1;
    g.tick(&mut k, &mut wire);
    let p = pushes(&wire.take());
    assert_eq!(p.len(), PUBLISH_BURST);
    assert_eq!(g.stats.lost, 20);
    k.now += PUBLISH_PERIOD_NS + 1;
    g.tick(&mut k, &mut wire);
    assert_eq!(pushes(&wire.take()).len(), 10 - PUBLISH_BURST);
    assert_eq!(g.stats.published as usize, 10);
}

#[test]
fn an_empty_topic_prefix_publishes_nothing_and_asks_nothing() {
    let mut cfg = config();
    cfg.topic = "";
    let (mut g, mut k, mut wire) = up_with(cfg, lamp_exports());
    let before = k.decisions_calls;
    k.record(Rule::CapDenial, Verdict::Deny, 3);
    k.now += PUBLISH_PERIOD_NS * 4;
    g.tick(&mut k, &mut wire);
    assert!(pushes(&wire.take()).is_empty());
    assert_eq!(k.decisions_calls, before);
}

// ── the export and the key rule ─────────────────────────────────────────────

static CATALOG: [crate::route::Iface; 1] = [crate::world::LAMP_COPY];

#[test]
fn an_export_is_built_only_from_a_key_expression() {
    let e = export(&CATALOG[0], 7, "azos/dec/**").unwrap();
    assert_eq!((e.endpoint, e.key.as_str()), (7, "azos/dec/**"));
    // Kconfig ZENOH_DECISIONS_KEY is whatever the builder typed: an empty
    // chunk, an empty string, a trailing slash and a `**` followed by a
    // wildcard chunk are refused, not served as something else.
    for bad in ["azos//dec", "", "azos/dec/", "azos/**/*"] {
        assert!(export(&CATALOG[0], 7, bad).is_none(), "{bad:?}");
    }
    // The exported key then routes: a query names the op by its last chunk.
    let ex = vec![e];
    assert_eq!(route(&ex, "azos/dec/set").unwrap().1.name, "set");
    assert_eq!(route(&ex, "azos/other/set").err(), Some(NoRoute::NoOp));
}

#[test]
fn a_key_names_the_op_by_its_last_chunk_in_the_first_export_that_includes_it() {
    let ex = vec![
        crate::route::Export { iface: &CATALOG[0], endpoint: 1, key: "a/lamp/**".to_string() },
        crate::route::Export { iface: &CATALOG[0], endpoint: 2, key: "a/**".to_string() },
    ];
    let (e, op) = route(&ex, "a/lamp/set").unwrap();
    assert_eq!((e.endpoint, op.name), (1, "set"), "the first of the exports that include the key");
    let (e, _) = route(&ex, "a/other/get").unwrap();
    assert_eq!(e.endpoint, 2);
    assert_eq!(route(&ex, "b/get").err(), Some(NoRoute::NoOp));
    assert_eq!(route(&ex, "a/lamp/blink").err(), Some(NoRoute::NoOp));
    for wild in ["a/*/get", "a/**", "a/lamp/g$*", "a/lamp/*"] {
        assert_eq!(route(&ex, wild).err(), Some(NoRoute::NotConcrete), "{wild}");
    }
    assert_eq!(route(&ex, "a//get").err(), Some(NoRoute::NotConcrete), "not a key expression");
    // A literal export key is one op.
    let one = vec![crate::route::Export { iface: &CATALOG[0], endpoint: 1, key: "a/lamp/get".to_string() }];
    assert!(route(&one, "a/lamp/get").is_ok());
    assert_eq!(route(&one, "a/lamp/set").err(), Some(NoRoute::NoOp));
}

#[test]
fn an_export_with_no_op_of_the_name_does_not_shadow_a_later_one() {
    // The first export's interface has no op `set`; the second has.
    static EMPTY: crate::route::Iface = crate::route::Iface { id: 1, level: 1, ops: &[] };
    let ex = vec![
        crate::route::Export { iface: &EMPTY, endpoint: 1, key: "a/**".to_string() },
        crate::route::Export { iface: &CATALOG[0], endpoint: 2, key: "a/**".to_string() },
    ];
    assert_eq!(route(&ex, "a/set").unwrap().0.endpoint, 2);
}

#[test]
fn the_catalog_op_table_matches_the_request_words_the_gateway_builds() {
    // The gateway builds header + args; the server decodes the same.
    let set = LAMP.op("set").unwrap();
    let mut m = MsgDesc { version: azos_idl::MSG_VERSION, n_words: set.req_words, ..MsgDesc::default() };
    m.words[0] = header(LAMP.id, LAMP.level, set.op);
    m.words[1] = 5;
    let mut rep = MsgDesc::default();
    let mut lamp = LampState::default();
    LampIdl::dispatch(&mut lamp, &m, &mut rep).unwrap();
    assert_eq!(lamp.level, 5);
}

/// The call right and the lend right, as the gateway asks for them
/// (`WRITE` 0b0010 + `DUP` 0b1000).
const LEND: u16 = 0b1010;

/// **Canary.** Make `sole_lendable` count a `READ`-only or a `WRITE`-only
/// endpoint (compare with `!= 0` instead of the whole mask): the second row
/// finds two and goes red; return the first match instead of counting: the
/// "more than one" row goes red.
#[test]
fn the_gateway_lends_from_exactly_one_endpoint() {
    // None: an empty row, and endpoints that lack one of the two rights.
    assert_eq!(sole_lendable([].into_iter(), LEND), Err(0));
    assert_eq!(sole_lendable([(0, 0b0010), (1, 0b1000), (2, 0b0001)].into_iter(), LEND), Err(0));
    // One, wherever it sits among others, with rights beyond the two.
    assert_eq!(sole_lendable([(0, 0b0010), (3, 0b1011), (5, 0b0001)].into_iter(), LEND), Ok(3));
    // Two (or more): refuses to guess, and says how many.
    assert_eq!(sole_lendable([(1, 0b1010), (4, 0b1110)].into_iter(), LEND), Err(2));
    assert_eq!(sole_lendable([(1, 0b1010), (2, 0b1010), (3, 0b1010)].into_iter(), LEND), Err(3));
}

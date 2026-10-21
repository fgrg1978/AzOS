// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::hex;
use azos_zenoh::network::*;
use azos_zenoh::{Error, Reader, Writer, Zid};

fn dec(b: &[u8]) -> NetworkMsg<'_> {
    let mut r = Reader::new(b);
    let m = NetworkMsg::decode(&mut r).unwrap();
    assert!(r.is_empty(), "bytes left over");
    m
}

fn enc(m: &NetworkMsg<'_>) -> Vec<u8> {
    let mut w = Writer::new();
    m.encode(&mut w).unwrap();
    w.into_vec()
}

/// Decode a canonical vector, require the codec to write the same bytes back.
fn canonical(s: &str) -> NetworkMsg<'static> {
    let b: &'static [u8] = Box::leak(hex(s).into_boxed_slice());
    let m = dec(b);
    assert_eq!(enc(&m), b, "re-encoding of {s} differs");
    m
}

/// A strict prefix of a network message is never a message.
fn no_prefix_decodes(s: &str) {
    let b = hex(s);
    for n in 0..b.len() {
        assert!(NetworkMsg::decode(&mut Reader::new(&b[..n])).is_err(), "{s} cut at {n}");
    }
}

fn zid(b: &[u8]) -> Zid {
    Zid::new(b).unwrap()
}

#[test]
fn push_put_with_text_encoding() {
    // 3D: PUSH | N (suffix present), M clear; scope 00; suffix 0C "demo/example";
    // 41: PUT | E; encoding 02 (id 1 << 1); payload <u8;z32> 05 "hello".
    let s = "3D 00 0C 64 65 6D 6F 2F 65 78 61 6D 70 6C 65 41 02 05 68 65 6C 6C 6F";
    let NetworkMsg::Push(p) = canonical(s) else { panic!() };
    assert_eq!(p.key, WireExpr { scope: 0, suffix: "demo/example", sender: false });
    let PushBody::Put(put) = p.body else { panic!() };
    assert_eq!(put.encoding, Some(Encoding { id: 1, schema: None }));
    assert_eq!(put.payload, b"hello");
    no_prefix_decodes(s);
}

#[test]
fn push_del_by_scope_only() {
    // 5D: PUSH | M (the scope is the sender's); scope 07; no suffix;
    // 02: DEL, nothing else.
    let NetworkMsg::Push(p) = canonical("5D 07 02") else { panic!() };
    assert_eq!(p.key, WireExpr { scope: 7, suffix: "", sender: true });
    assert_eq!(p.body, PushBody::Del(Del { timestamp: None, source_info: None, attachment: None }));
}

#[test]
fn push_extensions_qos_and_timestamp() {
    // BD: PUSH | N | Z; scope 00; suffix "a"; chain:
    //   A1 0D = Z | Z64 | id 1 (QoS), value 0x0D: priority 5, D bit (block);
    //   42 04 01 02 AA BB = ZBuf id 2 (Timestamp), 4 bytes: time 1, zid_len 2, AA BB;
    // 02: DEL.
    let s = "BD 00 01 61 A1 0D 42 04 01 02 AA BB 02";
    let NetworkMsg::Push(p) = canonical(s) else { panic!() };
    let q = p.qos.unwrap();
    assert_eq!((q.priority(), q.block(), q.express()), (5, true, false));
    assert_eq!(p.timestamp, Some(Timestamp { time: 1, zid: zid(&[0xAA, 0xBB]) }));
    assert_eq!(Qos::DEFAULT.priority(), 5);
    no_prefix_decodes(s);
}

#[test]
fn push_node_id_is_mandatory_and_decoded() {
    // 9D: PUSH | Z; scope 00; ext 33 07 = Z64 | M | id 3 (NodeId) = 7; DEL.
    let NetworkMsg::Push(p) = canonical("9D 00 33 07 02") else { panic!() };
    assert_eq!(p.node_id, Some(7));
    // A NodeId that does not fit 16 bits.
    let b = hex("9D 00 33 80 80 04 02");
    assert_eq!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::Overflow));
}

#[test]
fn put_extensions_source_info_and_attachment() {
    // 3D 00 01 6B: PUSH | N, suffix "k". Then PUT | T | Z (A1): timestamp 05 01 CC
    // (time 5, zid_len 1, zid CC); chain:
    //   C1 05 10 DD EE 02 09 = Z | ZBuf | id 1 (SourceInfo), 5 bytes: 10 (zid
    //   of 2 bytes), DD EE, eid 02, sn 09;
    //   43 03 61 62 63 = ZBuf | id 3 (Attachment) "abc";
    // payload 00 (empty).
    let s = "3D 00 01 6B \
             A1 05 01 CC \
             C1 05 10 DD EE 02 09 \
             43 03 61 62 63 \
             00";
    let NetworkMsg::Push(p) = canonical(s) else { panic!() };
    let PushBody::Put(put) = p.body else { panic!() };
    assert_eq!(put.timestamp, Some(Timestamp { time: 5, zid: zid(&[0xCC]) }));
    assert_eq!(put.source_info, Some(SourceInfo { zid: zid(&[0xDD, 0xEE]), eid: 2, sn: 9 }));
    assert_eq!(put.attachment, Some(&b"abc"[..]));
    assert_eq!(put.payload, b"");
    assert_eq!(put.encoding, None);
}

#[test]
fn an_ntp64_timestamp_takes_nine_bytes() {
    // PUSH, scope 00; PUT | T (21); timestamp: time 0xE000000000000000 as a VLE (eight
    // 0x80 bytes and the whole ninth byte E0), then the zid as <u8;z8> 01 CC;
    // payload 00. A reader that took E0 for "more" would eat the zid length.
    let s = "1D 00 21 80 80 80 80 80 80 80 80 E0 01 CC 00";
    let NetworkMsg::Push(p) = canonical(s) else { panic!() };
    let PushBody::Put(put) = p.body else { panic!() };
    assert_eq!(put.timestamp, Some(Timestamp { time: 0xE000_0000_0000_0000, zid: zid(&[0xCC]) }));
}

#[test]
fn encoding_with_schema() {
    // PUSH, scope 00; PUT | E (41); encoding 05 = id 2, schema flag; schema <u8;z8> 02 "xy"; payload "z".
    let s = "1D 00 41 05 02 78 79 01 7A";
    let NetworkMsg::Push(p) = canonical(s) else { panic!() };
    let PushBody::Put(put) = p.body else { panic!() };
    assert_eq!(put.encoding, Some(Encoding { id: 2, schema: Some(b"xy") }));
    assert_eq!(put.payload, b"z");
}

#[test]
fn a_shared_memory_put_is_refused() {
    // PUT | Z with the mandatory Shm unit extension (id 2, M): we do not do shm.
    let b = hex("1D 00 81 12 00");
    assert_eq!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::MandatoryExt(2)));
}

#[test]
fn request_with_target_budget_timeout_and_query() {
    // BC: REQUEST | N | Z; request id 2A; scope 00; suffix 06 "demo/*";
    //   B4 01 = Z | Z64 | M | id 4 (QueryTarget) = 1 (All);
    //   A5 03 = Z | Z64 | id 5 (Budget) = 3;
    //   26 E8 07 = Z64 | id 6 (Timeout) = 1000 ms;
    // 63: QUERY | P | C; consolidation 01 (None); parameters 03 "a=b".
    let s = "BC 2A 00 06 64 65 6D 6F 2F 2A B4 01 A5 03 26 E8 07 63 01 03 61 3D 62";
    let NetworkMsg::Request(r) = canonical(s) else { panic!() };
    assert_eq!(r.id, 0x2A);
    assert_eq!(r.key.suffix, "demo/*");
    assert_eq!(r.target, Some(QueryTarget::All));
    assert_eq!(r.budget, Some(3));
    assert_eq!(r.timeout_ms, Some(1000));
    assert_eq!(r.query.consolidation, Some(Consolidation::None));
    assert_eq!(r.query.parameters, "a=b");
    assert_eq!(r.query.body, None);
    no_prefix_decodes(s);
}

#[test]
fn plain_request_and_query_body() {
    // 1C: REQUEST; id 01; scope 03; 03: QUERY with nothing.
    let NetworkMsg::Request(r) = canonical("1C 01 03 03") else { panic!() };
    assert_eq!((r.id, r.key.scope), (1, 3));
    assert_eq!(r.query.parameters, "");
    // 83: QUERY | Z; ext 43 = ZBuf id 3 (QueryBody), len 5: encoding 02, payload 03 "xyz".
    let s = "1C 01 03 83 43 05 02 03 78 79 7A";
    let NetworkMsg::Request(r) = canonical(s) else { panic!() };
    assert_eq!(r.query.body, Some((Encoding { id: 1, schema: None }, &b"xyz"[..])));
    // An unknown consolidation byte.
    let b = hex("1C 01 03 23 09");
    assert!(matches!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::BadValue(_))));
}

#[test]
fn response_reply_put() {
    // 3B: RESPONSE | N; request id 2A; scope 00; suffix 06 "demo/a";
    // 04: REPLY; 01: PUT; payload 01 "x".
    let s = "3B 2A 00 06 64 65 6D 6F 2F 61 04 01 01 78";
    let NetworkMsg::Response(r) = canonical(s) else { panic!() };
    assert_eq!(r.id, 0x2A);
    assert_eq!(r.key.suffix, "demo/a");
    let ResponseBody::Reply(rep) = r.body else { panic!() };
    assert_eq!(rep.consolidation, None);
    assert!(matches!(rep.body, PushBody::Put(Put { payload: b"x", .. })));
    no_prefix_decodes(s);
}

#[test]
fn response_reply_del_with_consolidation_and_responder() {
    // 9B: RESPONSE | Z; id 2A; scope 00; ext 43 04 10 AA BB 05 = ZBuf id 3
    // (ResponderId): 10 -> 2-byte zid AA BB, eid 05; 24: REPLY | C, consolidation 03
    // (Latest); 02: DEL.
    let s = "9B 2A 00 43 04 10 AA BB 05 24 03 02";
    let NetworkMsg::Response(r) = canonical(s) else { panic!() };
    assert_eq!(r.responder, Some(ResponderId { zid: zid(&[0xAA, 0xBB]), eid: 5 }));
    let ResponseBody::Reply(rep) = r.body else { panic!() };
    assert_eq!(rep.consolidation, Some(Consolidation::Latest));
    assert!(matches!(rep.body, PushBody::Del(_)));
}

#[test]
fn response_err() {
    // 1B: RESPONSE; id 2A; scope 00; 45: ERR | E; encoding 02; payload 03 "bad".
    let NetworkMsg::Response(r) = canonical("1B 2A 00 45 02 03 62 61 64") else { panic!() };
    let ResponseBody::Err(e) = r.body else { panic!() };
    assert_eq!(e.payload, b"bad");
    assert_eq!(e.encoding, Some(Encoding { id: 1, schema: None }));
}

#[test]
fn response_final() {
    // 1A: RESPONSE_FINAL; request id 2A.
    let NetworkMsg::ResponseFinal(f) = canonical("1A 2A") else { panic!() };
    assert_eq!(f.id, 0x2A);
    // With the timestamp extension: 9A 2A 42 03 01 01 EE.
    let NetworkMsg::ResponseFinal(f) = canonical("9A 2A 42 03 01 01 EE") else { panic!() };
    assert_eq!(f.timestamp, Some(Timestamp { time: 1, zid: zid(&[0xEE]) }));
    // A request id wider than 32 bits is refused.
    let b = hex("1A 80 80 80 80 10");
    assert_eq!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::Overflow));
}

#[test]
fn declare_subscriber() {
    // 1E: DECLARE; 22: D_SUBSCRIBER | N; id 01; scope 00; suffix 07 "demo/**".
    let s = "1E 22 01 00 07 64 65 6D 6F 2F 2A 2A";
    let NetworkMsg::Declare(d) = canonical(s) else { panic!() };
    assert_eq!(d.interest_id, None);
    assert_eq!(
        d.body,
        Declaration::Subscriber { id: 1, key: WireExpr { scope: 0, suffix: "demo/**", sender: false } }
    );
    no_prefix_decodes(s);
}

#[test]
fn declarations_carry_the_mapping_flag() {
    // 62: D_SUBSCRIBER | N | M (the scope is the sender's); id 01; scope 05; suffix 02 "ab".
    let NetworkMsg::Declare(d) = canonical("1E 62 01 05 02 61 62") else { panic!() };
    assert_eq!(
        d.body,
        Declaration::Subscriber { id: 1, key: WireExpr { scope: 5, suffix: "ab", sender: true } }
    );
    // 42: M only, no suffix. The same for a queryable (44) and a token (46).
    let NetworkMsg::Declare(d) = canonical("1E 42 01 05") else { panic!() };
    assert!(matches!(d.body, Declaration::Subscriber { key: WireExpr { sender: true, .. }, .. }));
    let NetworkMsg::Declare(d) = canonical("1E 44 01 05") else { panic!() };
    assert!(matches!(d.body, Declaration::Queryable { key: WireExpr { sender: true, .. }, .. }));
    let NetworkMsg::Declare(d) = canonical("1E 46 01 05") else { panic!() };
    assert!(matches!(d.body, Declaration::Token { key: WireExpr { sender: true, .. }, .. }));
}

#[test]
fn declare_key_expression_and_its_undeclaration() {
    // 20: D_KEXPR | N; expr id 05; scope 00; suffix 04 "demo". No M flag exists
    // here: the scope is the declarer's own table.
    let NetworkMsg::Declare(d) = canonical("1E 20 05 00 04 64 65 6D 6F") else { panic!() };
    assert_eq!(
        d.body,
        Declaration::KeyExpr { id: 5, key: WireExpr { scope: 0, suffix: "demo", sender: true } }
    );
    // 01: U_KEXPR; expr id 05.
    let NetworkMsg::Declare(d) = canonical("1E 01 05") else { panic!() };
    assert_eq!(d.body, Declaration::UndeclareKeyExpr { id: 5 });
}

#[test]
fn undeclare_subscriber_with_the_wire_expr_extension() {
    // 83: U_SUBSCRIBER | Z; id 01; ext 5F = ZBuf (0x40) | M (0x10) | id 0F, len 6:
    //   flags 01 (N set, M clear), scope 00, suffix 03 "a/b".
    let s = "1E 83 01 5F 06 01 00 03 61 2F 62";
    let NetworkMsg::Declare(d) = canonical(s) else { panic!() };
    assert_eq!(
        d.body,
        Declaration::UndeclareSubscriber {
            id: 1,
            key: Some(WireExpr { scope: 0, suffix: "a/b", sender: false })
        }
    );
    // Without the extension.
    let NetworkMsg::Declare(d) = canonical("1E 03 01") else { panic!() };
    assert_eq!(d.body, Declaration::UndeclareSubscriber { id: 1, key: None });
    // Flags 02: the scope is the sender's (M), no suffix; scope 07.
    let NetworkMsg::Declare(d) = canonical("1E 83 01 5F 02 02 07") else { panic!() };
    assert_eq!(
        d.body,
        Declaration::UndeclareSubscriber {
            id: 1,
            key: Some(WireExpr { scope: 7, suffix: "", sender: true })
        }
    );
}

#[test]
fn declare_queryable_with_info_extension() {
    // A4: D_QUERYABLE | N | Z; id 02; scope 00; suffix 01 "q";
    // 21 = Z64 | id 1 (QueryableInfo); value (distance << 8) | complete, as
    // zenoh-rust and zenoh-pico write it: 3 << 8 | 1 = 0x301 = VLE 81 06.
    let s = "1E A4 02 00 01 71 21 81 06";
    let NetworkMsg::Declare(d) = canonical(s) else { panic!() };
    assert_eq!(
        d.body,
        Declaration::Queryable {
            id: 2,
            key: WireExpr { scope: 0, suffix: "q", sender: false },
            complete: true,
            distance: 3
        }
    );
    // The two fields do not mix: value 0x200 (VLE 80 04) = distance 2, not
    // complete; 01 = complete, distance 0.
    let NetworkMsg::Declare(d) = canonical("1E A4 02 00 01 71 21 80 04") else { panic!() };
    assert!(matches!(d.body, Declaration::Queryable { complete: false, distance: 2, .. }));
    let NetworkMsg::Declare(d) = canonical("1E A4 02 00 01 71 21 01") else { panic!() };
    assert!(matches!(d.body, Declaration::Queryable { complete: true, distance: 0, .. }));
    // Distance 500, not complete: 500 << 8 = 128000 = VLE 80 E8 07.
    let NetworkMsg::Declare(d) = canonical("1E A4 02 00 01 71 21 80 E8 07") else { panic!() };
    assert!(matches!(d.body, Declaration::Queryable { complete: false, distance: 500, .. }));
    // Complete and the largest distance: 0xFFFF << 8 | 1 = 0xFFFF01.
    let NetworkMsg::Declare(d) = canonical("1E A4 02 00 01 71 21 81 FE FF 07") else { panic!() };
    assert!(matches!(d.body, Declaration::Queryable { complete: true, distance: 0xFFFF, .. }));
    // Without the extension: not complete, distance 0.
    let NetworkMsg::Declare(d) = canonical("1E 24 02 00 01 71") else { panic!() };
    assert!(matches!(d.body, Declaration::Queryable { complete: false, distance: 0, .. }));
    no_prefix_decodes(s);
}

#[test]
fn declare_token_and_undeclarations() {
    // 26: D_TOKEN | N; id 03; scope 00; suffix 01 "x".
    let NetworkMsg::Declare(d) = canonical("1E 26 03 00 01 78") else { panic!() };
    assert!(matches!(d.body, Declaration::Token { id: 3, .. }));
    let NetworkMsg::Declare(d) = canonical("1E 07 03") else { panic!() };
    assert_eq!(d.body, Declaration::UndeclareToken { id: 3, key: None });
    let NetworkMsg::Declare(d) = canonical("1E 05 09") else { panic!() };
    assert_eq!(d.body, Declaration::UndeclareQueryable { id: 9, key: None });
}

#[test]
fn declare_final_answers_an_interest() {
    // 3E: DECLARE | I; interest id 07; 1A: D_FINAL.
    let NetworkMsg::Declare(d) = canonical("3E 07 1A") else { panic!() };
    assert_eq!(d.interest_id, Some(7));
    assert_eq!(d.body, Declaration::Final);
    // A declaration we do not know.
    let b = hex("1E 1B");
    assert_eq!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::Unsupported(0x1B)));
}

#[test]
fn interest() {
    // 39: INTEREST | mode Current (01 << 5); id 01; options 32 = S (0x02) | R (0x10) |
    // N (0x20); scope 00; suffix 07 "demo/**".
    let s = "39 01 32 00 07 64 65 6D 6F 2F 2A 2A";
    let NetworkMsg::Interest(i) = canonical(s) else { panic!() };
    assert_eq!((i.id, i.mode), (1, InterestMode::Current));
    let o = i.options.unwrap();
    assert!(o.subscribers && !o.queryables && !o.tokens && !o.keyexprs && !o.aggregate);
    assert_eq!(o.key, Some(WireExpr { scope: 0, suffix: "demo/**", sender: false }));
    no_prefix_decodes(s);

    // 79: mode CurrentFuture (11 << 5); id 02; options 0F = K | S | Q | T.
    let NetworkMsg::Interest(i) = canonical("79 02 0F") else { panic!() };
    assert_eq!(i.mode, InterestMode::CurrentFuture);
    let o = i.options.unwrap();
    assert!(o.keyexprs && o.subscribers && o.queryables && o.tokens && o.key.is_none());
    // Future with aggregation (A = 0x80), tokens only.
    let NetworkMsg::Interest(i) = canonical("59 03 88") else { panic!() };
    assert_eq!(i.mode, InterestMode::Future);
    assert!(i.options.unwrap().aggregate);

    // 19: mode Final; id 01: no options byte at all.
    let NetworkMsg::Interest(i) = canonical("19 01") else { panic!() };
    assert_eq!((i.mode, i.options), (InterestMode::Final, None));

    // N set without R.
    let b = hex("39 01 22 00");
    assert!(matches!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::BadValue(_))));
}

#[test]
fn an_interest_that_contradicts_its_mode_is_not_written() {
    let mut i = Interest {
        id: 1,
        mode: InterestMode::Final,
        options: Some(InterestOptions {
            keyexprs: true,
            subscribers: false,
            queryables: false,
            tokens: false,
            aggregate: false,
            key: None,
        }),
        qos: None,
        timestamp: None,
        node_id: None,
    };
    assert!(NetworkMsg::Interest(i.clone()).encode(&mut Writer::new()).is_err());
    i.mode = InterestMode::Current;
    i.options = None;
    assert!(NetworkMsg::Interest(i).encode(&mut Writer::new()).is_err());
}

#[test]
fn unsupported_and_unknown() {
    // 1F: OAM.
    let b = hex("1F 00 00");
    assert_eq!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::Unsupported(0x1F)));
    // A push whose body is neither PUT nor DEL.
    let b = hex("1D 00 05");
    assert_eq!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::Unsupported(5)));
    // A PUSH with an optional unknown extension (9D: Z; 08 = unit, id 8, M clear): skipped.
    let NetworkMsg::Push(_) = dec(&hex("9D 00 08 02")) else { panic!() };
    // The same extension mandatory: refused.
    let b = hex("9D 00 18 02");
    assert_eq!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::MandatoryExt(8)));
}

#[test]
fn utf8_and_sizes_are_checked() {
    // A suffix that is not UTF-8.
    let b = hex("3D 00 01 FF 02");
    assert_eq!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::BadUtf8));
    // A payload length longer than the input.
    let b = hex("1D 00 01 09 41");
    assert_eq!(NetworkMsg::decode(&mut Reader::new(&b)), Err(Error::Truncated));
    // An encoding id that does not fit 31 bits is not written.
    let m = NetworkMsg::Push(Push {
        key: WireExpr::plain(""),
        qos: None,
        timestamp: None,
        node_id: None,
        body: PushBody::Put(Put {
            timestamp: None,
            encoding: Some(Encoding { id: 1 << 31, schema: None }),
            source_info: None,
            attachment: None,
            payload: b"",
        }),
    });
    assert_eq!(m.encode(&mut Writer::new()), Err(Error::Overflow));
}

#[test]
fn full_messages_survive_a_round_trip() {
    let ts = Timestamp { time: u64::MAX >> 1, zid: zid(&[9; 16]) };
    let si = SourceInfo { zid: zid(&[1, 2, 3]), eid: u32::MAX, sn: 77 };
    let attach = [1u8, 2, 3];
    let msgs = vec![
        NetworkMsg::Push(Push {
            key: WireExpr { scope: 300, suffix: "s/x", sender: true },
            qos: Some(Qos(0x1D)),
            timestamp: Some(ts),
            node_id: Some(65535),
            body: PushBody::Put(Put {
                timestamp: Some(ts),
                encoding: Some(Encoding { id: 12, schema: Some(b"schema") }),
                source_info: Some(si),
                attachment: Some(&attach),
                payload: &[0xAB; 300],
            }),
        }),
        NetworkMsg::Request(Request {
            id: u32::MAX,
            key: WireExpr::plain("q/**"),
            qos: Some(Qos::DEFAULT),
            timestamp: Some(ts),
            node_id: Some(1),
            target: Some(QueryTarget::AllComplete),
            budget: Some(1),
            timeout_ms: Some(u64::MAX),
            query: Query {
                consolidation: Some(Consolidation::Monotonic),
                parameters: "x=1;y=2",
                source_info: Some(si),
                body: Some((Encoding { id: 3, schema: None }, &[1, 2, 3])),
                attachment: Some(&attach),
            },
        }),
        NetworkMsg::Response(Response {
            id: 5,
            key: WireExpr { scope: 9, suffix: "", sender: false },
            qos: None,
            timestamp: Some(ts),
            responder: Some(ResponderId { zid: zid(&[4; 5]), eid: 1000 }),
            body: ResponseBody::Err(ErrBody {
                encoding: Some(Encoding { id: 1, schema: None }),
                source_info: Some(si),
                payload: b"nope",
            }),
        }),
        NetworkMsg::Declare(Declare {
            interest_id: Some(3),
            qos: Some(Qos(0x20)),
            timestamp: Some(ts),
            node_id: Some(2),
            body: Declaration::Queryable {
                id: 8,
                key: WireExpr::plain("k"),
                complete: false,
                distance: 500,
            },
        }),
        NetworkMsg::Declare(Declare {
            interest_id: None,
            qos: None,
            timestamp: None,
            node_id: None,
            body: Declaration::UndeclareToken {
                id: 4,
                key: Some(WireExpr { scope: 2, suffix: "t", sender: true }),
            },
        }),
        NetworkMsg::ResponseFinal(ResponseFinal { id: 5, qos: Some(Qos(1)), timestamp: Some(ts) }),
        NetworkMsg::Interest(Interest {
            id: 6,
            mode: InterestMode::Future,
            options: Some(InterestOptions {
                keyexprs: true,
                subscribers: true,
                queryables: true,
                tokens: true,
                aggregate: true,
                key: Some(WireExpr { scope: 4, suffix: "i", sender: true }),
            }),
            qos: None,
            timestamp: Some(ts),
            node_id: Some(3),
        }),
    ];
    // All of them back to back in one buffer, as in a frame.
    let mut w = Writer::new();
    for m in &msgs {
        m.encode(&mut w).unwrap();
    }
    let mut r = Reader::new(w.as_slice());
    for m in &msgs {
        assert_eq!(&NetworkMsg::decode(&mut r).unwrap(), m);
    }
    assert!(r.is_empty());
}

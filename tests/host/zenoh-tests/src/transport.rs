// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::hex;
use azos_zenoh::network::{Push, PushBody, Put, Encoding, NetworkMsg, WireExpr};
use azos_zenoh::transport::*;
use azos_zenoh::{Error, Reader, Writer, Zid};

fn one(b: &[u8]) -> Transport<'_> {
    let mut r = Reader::new(b);
    let m = Transport::decode(&mut r).unwrap();
    assert!(r.is_empty(), "bytes left over");
    m
}

fn enc(m: &Transport<'_>) -> Vec<u8> {
    let mut w = Writer::new();
    m.encode(&mut w).unwrap();
    w.into_vec()
}

/// Decode, check, and re-encode to the same bytes.
fn canonical(b: &str) -> Transport<'static> {
    let bytes: &'static [u8] = Box::leak(hex(b).into_boxed_slice());
    let m = one(bytes);
    assert_eq!(enc(&m), bytes, "re-encoding differs");
    m
}

#[test]
fn init_syn_of_a_client() {
    // 41: id 1 | S (0x40); 09: version; 32: zid_len-1 = 3 in bits 7..4,
    // whatami client = 2; zid; 0A: resolution fsn=32 bit, rid=32 bit;
    // FF FF: batch size 65535 little-endian.
    let m = canonical("41 09 32 01 02 03 04 0A FF FF");
    let Transport::Init(i) = m else { panic!() };
    assert_eq!(i.version, VERSION);
    assert_eq!(i.whatami, WhatAmI::Client);
    assert_eq!(i.zid.as_slice(), [1, 2, 3, 4]);
    assert_eq!(i.size, Some(SizeParams::DEFAULT));
    assert!(!i.is_ack() && !i.qos && i.patch == 0);
}

#[test]
fn init_syn_without_size_block_and_with_extensions() {
    // 81: id 1 | Z, no S: the defaults apply; 1-byte zid AA, peer = 1; chain:
    // 81 = unit (QoS, id 1) with Z, then 27 = Z64 (0x20) | id 7 (patch), value 1.
    let m = canonical("81 09 01 AA 81 27 01");
    let Transport::Init(i) = m else { panic!() };
    assert_eq!(i.whatami, WhatAmI::Peer);
    assert_eq!(i.size, None);
    assert_eq!(i.size_or_default(), SizeParams::DEFAULT);
    assert_eq!(i.patch, 1);
    assert!(i.qos);
    // The chain in the other order decodes the same (A7: patch with Z, then 01: QoS).
    let b = hex("81 09 01 AA A7 01 01");
    let j = one(&b);
    assert_eq!(j, Transport::Init(i));
}

#[test]
fn init_syn_with_qos_extension() {
    // C1: id 1 | S | Z; ... 0A FF FF; then ext 01: unit, id 1 (QoS), M=0, no Z.
    let m = canonical("C1 09 00 07 0A FF FF 01");
    let Transport::Init(i) = m else { panic!() };
    assert_eq!(i.whatami, WhatAmI::Router);
    assert!(i.qos);
    assert_eq!(i.zid.as_slice(), [7]);
}

#[test]
fn init_ack_of_a_router() {
    // 61: id 1 | S | A; 70: zid_len-1 = 7, whatami router; 8-byte zid;
    // 0A; 00 04: batch size 1024; cookie <u8;z16>: 03 AA BB CC.
    let m = canonical("61 09 70 01 02 03 04 05 06 07 08 0A 00 04 03 AA BB CC");
    let Transport::Init(i) = m else { panic!() };
    assert!(i.is_ack());
    assert_eq!(i.cookie, Some(&[0xAA, 0xBB, 0xCC][..]));
    assert_eq!(i.size.unwrap().batch_size, 1024);
    assert_eq!(i.whatami, WhatAmI::Router);
    assert_eq!(i.zid.as_slice().len(), 8);
}

#[test]
fn init_refusals() {
    // whatami 0b11 is reserved.
    let b = hex("41 09 03 01 0A FF FF");
    assert!(matches!(Transport::decode(&mut Reader::new(&b)), Err(Error::BadValue(_))));
    // A mandatory extension nobody knows (unit, M = 0x10, id 9).
    let b = hex("C1 09 00 07 0A FF FF 19");
    assert_eq!(Transport::decode(&mut Reader::new(&b)), Err(Error::MandatoryExt(9)));
    // The same extension optional is skipped.
    let b = hex("C1 09 00 07 0A FF FF 09");
    assert!(Transport::decode(&mut Reader::new(&b)).is_ok());
    // Reserved extension encoding 0b11 (0x60).
    let b = hex("C1 09 00 07 0A FF FF 60");
    assert_eq!(Transport::decode(&mut Reader::new(&b)), Err(Error::BadExtEnc));
    // Cookie longer than the input.
    let b = hex("61 09 00 07 0A FF FF 05 AA");
    assert_eq!(Transport::decode(&mut Reader::new(&b)), Err(Error::Truncated));
}

#[test]
fn resolution_byte() {
    assert_eq!(Resolution::DEFAULT.to_byte(), 0x0A);
    let r = Resolution::from_byte(0x0A);
    assert_eq!((r.fsn, r.rid), (Bits::B32, Bits::B32));
    // fsn = bits 1..0, rid = bits 3..2.
    let r = Resolution::from_byte(0b0111);
    assert_eq!((r.fsn, r.rid), (Bits::B64, Bits::B16));
    assert_eq!(Bits::B16.mask(), 0xFFFF);
    // A responder may lower, never raise.
    let n = Resolution::DEFAULT.narrowest(Resolution { fsn: Bits::B16, rid: Bits::B64 });
    assert_eq!((n.fsn, n.rid), (Bits::B16, Bits::B32));
}

#[test]
fn open_syn_and_ack() {
    // 42: id 2 | T (lease in seconds); lease 10; initial_sn 300 = AC 02;
    // cookie 03 AA BB CC (present: A flag clear).
    let m = canonical("42 0A AC 02 03 AA BB CC");
    let Transport::Open(o) = m else { panic!() };
    assert!(!o.is_ack());
    assert_eq!(o.lease, Lease { value: 10, seconds: true });
    assert_eq!(o.lease.millis(), 10_000);
    assert_eq!(o.initial_sn, 300);
    assert_eq!(o.cookie, Some(&[0xAA, 0xBB, 0xCC][..]));

    // 22: id 2 | A (the ack: no cookie), no T: lease in milliseconds,
    // 10000 = 0x2710 -> 90 4E; initial_sn 0.
    let m = canonical("22 90 4E 00");
    let Transport::Open(o) = m else { panic!() };
    assert!(o.is_ack());
    assert_eq!(o.lease.millis(), 10_000);
    assert_eq!(o.initial_sn, 0);
    assert_eq!(o.cookie, None);

    // With the QoS extension (Z flag, unit id 1).
    let m = canonical("A2 90 4E 00 01");
    let Transport::Open(o) = m else { panic!() };
    assert!(o.qos);
}

#[test]
fn close_and_keep_alive() {
    // 23: id 3 | S (whole session); reason EXPIRED = 5.
    let m = canonical("23 05");
    assert_eq!(m, Transport::Close(Close { session: true, reason: reason::EXPIRED }));
    // 03: link only; reason GENERIC.
    let m = canonical("03 00");
    assert_eq!(m, Transport::Close(Close { session: false, reason: reason::GENERIC }));
    // 04: KEEP_ALIVE, nothing else.
    assert_eq!(canonical("04"), Transport::KeepAlive);
    // KEEP_ALIVE with an (optional) extension: skipped.
    let b = hex("84 01");
    assert_eq!(one(&b), Transport::KeepAlive);
    // CLOSE cut before its reason.
    assert_eq!(Transport::decode(&mut Reader::new(&[0x03])), Err(Error::Truncated));
}

const PUSH_HELLO: &str =
    // 3D: PUSH | N; scope 00; suffix <u8;z16> "demo/example"
    "3D 00 0C 64 65 6D 6F 2F 65 78 61 6D 70 6C 65 \
     41 02 05 68 65 6C 6C 6F"; // PUT | E; encoding id 1 (1<<1 = 02); payload "hello"

#[test]
fn frame_carries_network_messages() {
    // 25: FRAME | R; sn 1; then the PUSH.
    let b = hex(&format!("25 01 {PUSH_HELLO}"));
    let Transport::Frame(f) = one(&b) else { panic!() };
    assert!(f.reliable);
    assert_eq!(f.sn, 1);
    assert_eq!(f.priority, None);
    let msgs: Vec<_> = f.messages().collect::<Result<_, _>>().unwrap();
    assert_eq!(
        msgs,
        [NetworkMsg::Push(Push {
            key: WireExpr { scope: 0, suffix: "demo/example", sender: false },
            qos: None,
            timestamp: None,
            node_id: None,
            body: PushBody::Put(Put {
                timestamp: None,
                encoding: Some(Encoding { id: 1, schema: None }),
                source_info: None,
                attachment: None,
                payload: b"hello",
            }),
        })]
    );
    assert_eq!(enc(&Transport::Frame(f)), b);
}

#[test]
fn frame_with_qos_priority_extension() {
    // A5: FRAME | R | Z; sn 1; ext 31 = Z64 (0x20) | M (0x10) | id 1, value 5.
    let b = hex(&format!("A5 01 31 05 {PUSH_HELLO}"));
    let Transport::Frame(f) = one(&b) else { panic!() };
    assert_eq!(f.priority, Some(5));
    assert_eq!(f.messages().count(), 1);
    assert_eq!(enc(&Transport::Frame(f)), b);
    // Best-effort channel: no R.
    let b = hex("05 FF FF 03");
    let Transport::Frame(f) = one(&b) else { panic!() };
    assert!(!f.reliable);
    assert_eq!(f.sn, 0xFFFF);
    assert!(f.body.is_empty());
    // A mandatory frame extension we do not know refuses the frame.
    let b = hex("85 01 19");
    assert_eq!(Transport::decode(&mut Reader::new(&b)), Err(Error::MandatoryExt(9)));
}

#[test]
fn fragment() {
    // 66: FRAGMENT | R (0x20) | M (0x40, more follow); sn 3; the raw bytes.
    let b = hex("66 03 DE AD BE EF");
    let Transport::Fragment(f) = one(&b) else { panic!() };
    assert!(f.reliable && f.more && !f.first && !f.drop);
    assert_eq!(f.sn, 3);
    assert_eq!(f.data, [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(enc(&Transport::Fragment(f)), b);
    // Last fragment (no M), reliable, with Z: A6; the patch-1 "first" marker is ext 02 (unit, id 2).
    let b = hex("A6 04 02 11 22");
    let Transport::Fragment(f) = one(&b) else { panic!() };
    assert!(!f.more && f.first);
    assert_eq!(f.data, [0x11, 0x22]);
    assert_eq!(enc(&Transport::Fragment(f)), b);
}

#[test]
fn unsupported_transport_messages() {
    // 00: OAM, 07: JOIN (multicast).
    assert_eq!(Transport::decode(&mut Reader::new(&[0x00, 0x00])), Err(Error::Unsupported(0)));
    assert_eq!(Transport::decode(&mut Reader::new(&[0x07])), Err(Error::Unsupported(7)));
    assert_eq!(Transport::decode(&mut Reader::new(&[0x1F])), Err(Error::Unsupported(0x1F)));
}

#[test]
fn a_batch_is_messages_back_to_back() {
    // KEEP_ALIVE, then a FRAME that runs to the end of the batch.
    let b = hex(&format!("04 25 07 {PUSH_HELLO}"));
    let v: Vec<_> = decode_batch(&b).collect::<Result<_, _>>().unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0], Transport::KeepAlive);
    let Transport::Frame(f) = &v[1] else { panic!() };
    assert_eq!(f.sn, 7);

    // An error ends the iteration: nothing after a bad message is looked at.
    let b = hex("04 07 04 04");
    let v: Vec<_> = decode_batch(&b).collect();
    assert_eq!(v.len(), 2);
    assert_eq!(v[1], Err(Error::Unsupported(7)));
}

#[test]
fn encode_frame_of_messages_matches_the_hand_built_bytes() {
    let m = NetworkMsg::Push(Push {
        key: WireExpr { scope: 0, suffix: "demo/example", sender: false },
        qos: None,
        timestamp: None,
        node_id: None,
        body: PushBody::Put(Put {
            timestamp: None,
            encoding: Some(Encoding { id: 1, schema: None }),
            source_info: None,
            attachment: None,
            payload: b"hello",
        }),
    });
    let mut w = Writer::new();
    encode_frame(&mut w, true, 1, None, &[m.clone(), m]).unwrap();
    assert_eq!(w.as_slice(), hex(&format!("25 01 {PUSH_HELLO} {PUSH_HELLO}")));
}

#[test]
fn stream_links_prefix_each_batch_with_two_le_bytes() {
    assert_eq!(stream_prefix(0x0102), Ok([0x02, 0x01]));
    assert_eq!(stream_prefix(65535), Ok([0xFF, 0xFF]));
    assert_eq!(stream_prefix(65536), Err(Error::TooLong));

    let a = hex("03 00 23 05"); // one batch holding two CLOSEs
    let mut wire = vec![0x04, 0x00];
    wire.extend_from_slice(&a);
    wire.extend_from_slice(&[0x01, 0x00, 0x04]);
    // Two batches back to back, and a third that has not fully arrived.
    wire.extend_from_slice(&[0x05, 0x00, 0x04]);
    let (b1, rest) = split_stream(&wire).unwrap();
    assert_eq!(b1, a);
    let (b2, rest) = split_stream(rest).unwrap();
    assert_eq!(b2, [0x04]);
    assert!(split_stream(rest).is_none());
    assert!(split_stream(&[0x05]).is_none());
    assert!(split_stream(&[]).is_none());
}

#[test]
fn zid_lengths() {
    assert_eq!(Zid::new(&[]), Err(Error::BadZidLen));
    assert_eq!(Zid::new(&[0; 17]), Err(Error::BadZidLen));
    assert!(Zid::new(&[1; 16]).is_ok());
    // A 16-byte zid in INIT: nibble 15 | whatami peer.
    let mut b = hex("41 09 F1");
    b.extend_from_slice(&[7u8; 16]);
    b.extend_from_slice(&hex("0A FF FF"));
    let Transport::Init(i) = one(&b) else { panic!() };
    assert_eq!(i.zid.as_slice(), [7u8; 16]);
    assert_eq!(enc(&Transport::Init(i)), b);
}

#[test]
fn every_prefix_of_a_handshake_message_is_refused() {
    for s in [
        "41 09 32 01 02 03 04 0A FF FF",
        "61 09 70 01 02 03 04 05 06 07 08 0A 00 04 03 AA BB CC",
        "42 0A AC 02 03 AA BB CC",
        "22 90 4E 00",
        "23 05",
    ] {
        let b = hex(s);
        for n in 0..b.len() {
            assert!(Transport::decode(&mut Reader::new(&b[..n])).is_err(), "{s} cut at {n}");
        }
    }
}

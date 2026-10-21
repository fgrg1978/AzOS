// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Net` interface: its registry row, its op table, the bounded types it
//! carries (a name, an address, the client's status) and the generated client
//! and dispatcher over a mock stack.

use azos_devif::net::{FAMILY_V4, FAMILY_V6, NAME_MAX, NAME_WORDS};
use azos_devif::{
    by_key, by_name, key, outcome, parse_target, Address, Net, NetCall, NetClient, NetIdl, NtpStatus, Out, Query,
    NET_ID,
};
use azos_idl::{MsgDesc, Reader, Result as IdlResult, Transport, Wire, Writer, OP_IDEMPOTENT};
use std::cell::RefCell;

struct Loop<'a> {
    serve: &'a dyn Fn(&MsgDesc, &mut MsgDesc),
}

impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        let req = *msg;
        (self.serve)(&req, msg);
        Ok(())
    }
}

/// A stack with one name and one status.
struct Mock;

impl Net for Mock {
    fn resolve(&self, query: Query) -> Out<Address> {
        let mut name = [0u8; NAME_MAX];
        let n = query.name(&mut name);
        match (query.family, &name[..n]) {
            (FAMILY_V4, b"host.example") => Out::ok(Address::v4([93, 184, 216, 34])),
            (FAMILY_V6, b"host.example") => {
                Out::ok(Address::v6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
            }
            (FAMILY_V4 | FAMILY_V6, _) => Out::err(outcome::NO_RESOURCE),
            _ => Out::err(outcome::BAD_ARGUMENT),
        }
    }

    fn ntp_status(&self) -> Out<NtpStatus> {
        Out::ok(NtpStatus { server: 0x0A00_007C, synced: 1, last_unix_sec: 1_789_257_600, age_ms: 61_000, exchanges: 3, failures: 1 })
    }
}

/// The row: key 22, after `vcpu`, the id "NET ", no resource spelling.
///
/// **Canary.** Move the key, or give the row a resource: red.
#[test]
fn the_net_row_is_registered_after_vcpu_and_names_no_resource() {
    assert_eq!(key::NET, 22);
    assert_eq!(NET_ID.to_be_bytes(), *b"NET ");
    let i = by_name("net").expect("no row net");
    assert_eq!((i.key, i.id), (key::NET, NET_ID));
    assert_eq!(by_key(key::NET).map(|x| x.name), Some("net"));
    assert_eq!(parse_target("net").map(|(i, b)| (i.name, b)), Some(("net", 0)));
    assert!(parse_target("net.1").is_none(), "a Net endpoint has no resource");
    assert!(parse_target("net2").is_none());
}

/// Both ops can be retried (a lookup and a read of a counter change nothing),
/// and a request fills the message exactly: header, family and length, the
/// name's six words.
#[test]
fn the_ops_are_idempotent_and_the_request_fills_the_message() {
    for o in NetIdl::OPS.iter() {
        assert_eq!(o.flags, OP_IDEMPOTENT, "{}", o.name);
    }
    assert_eq!(NetIdl::REQ_WORDS_RESOLVE, 1 + 1 + NAME_WORDS);
    assert_eq!(NetIdl::REQ_WORDS_RESOLVE, 8, "the most a request holds");
    assert_eq!(NetIdl::REP_WORDS_RESOLVE, 1 + 1 + 3);
    assert_eq!(NetIdl::REP_WORDS_NTP_STATUS, 8, "status, outcome and the six words of NtpStatus");
}

/// A name of 1..=48 bytes is a query, and comes back byte for byte; a longer
/// one, or none, is not.
#[test]
fn a_query_carries_a_name_of_up_to_forty_eight_bytes() {
    for len in [1usize, 7, 8, 9, 47, 48] {
        let name: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
        let q = Query::new(FAMILY_V4, &name).unwrap();
        let mut out = [0u8; NAME_MAX];
        let n = q.name(&mut out);
        assert_eq!(&out[..n], &name[..], "{len} bytes");
    }
    assert!(Query::new(FAMILY_V4, b"").is_none());
    assert!(Query::new(FAMILY_V4, &[b'a'; NAME_MAX + 1]).is_none());
    // A length larger than the words hold is clamped when read, not trusted.
    let q = Query { family: FAMILY_V4, n: u32::MAX, w: [u64::MAX; NAME_WORDS] };
    let mut out = [0u8; NAME_MAX];
    assert_eq!(q.name(&mut out), NAME_MAX);
}

/// The family and the length share the first word of a query; nothing else
/// is lost on the wire.
#[test]
fn a_query_round_trips_with_family_and_length_in_one_word() {
    let q = Query::new(FAMILY_V6, b"www.example.org").unwrap();
    let mut m = MsgDesc::default();
    {
        let mut w = Writer::new(&mut m);
        q.put(&mut w);
        w.finish();
    }
    assert_eq!(m.n_words as usize, 1 + NAME_WORDS);
    assert_eq!(m.words[0], 15 | (FAMILY_V6 as u64) << 32);
    let mut r = Reader::new(&m);
    assert_eq!(Query::get(&mut r), q);
}

/// An address keeps its length and its bytes, network order.
#[test]
fn an_address_round_trips_for_both_families() {
    let v4 = Address::v4([10, 0, 2, 3]);
    let v6 = Address::v6([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
    let mut b = [0u8; 16];
    assert_eq!(v4.bytes(&mut b), 4);
    assert_eq!(&b[..4], &[10, 0, 2, 3]);
    assert_eq!(v6.bytes(&mut b), 16);
    assert_eq!(b[0], 0xFE);
    assert_eq!(b[15], 0xF0);
    let mut m = MsgDesc::default();
    {
        let mut w = Writer::new(&mut m);
        v6.put(&mut w);
        w.finish();
    }
    assert_eq!(Address::get(&mut Reader::new(&m)), v6);
    assert_eq!(Address::default().bytes(&mut b), 0, "no address says so");
}

/// Through the generated client and dispatcher: both families and the
/// refusals come back as the mock gave them, and the status keeps its six
/// fields.
#[test]
fn the_client_and_the_dispatcher_carry_both_ops() {
    let mock = RefCell::new(Mock);
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = NetIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let lp = Loop { serve: &serve };
    let c = NetClient::new(&lp);

    let r = c.resolve(Query::new(FAMILY_V4, b"host.example").unwrap()).unwrap();
    assert!(r.is_ok());
    let mut b = [0u8; 16];
    assert_eq!(r.value.bytes(&mut b), 4);
    assert_eq!(&b[..4], &[93, 184, 216, 34]);

    let r = c.resolve(Query::new(FAMILY_V6, b"host.example").unwrap()).unwrap();
    assert_eq!((r.code, r.value.bytes(&mut b)), (outcome::OK, 16));
    assert_eq!(b[0], 0x20);

    let r = c.resolve(Query::new(FAMILY_V4, b"nothing.example").unwrap()).unwrap();
    assert_eq!(r, Out::err(outcome::NO_RESOURCE));
    let r = c.resolve(Query::new(9, b"host.example").unwrap()).unwrap();
    assert_eq!(r, Out::err(outcome::BAD_ARGUMENT));

    let st = c.ntp_status().unwrap();
    assert_eq!(
        st,
        Out::ok(NtpStatus { server: 0x0A00_007C, synced: 1, last_unix_sec: 1_789_257_600, age_ms: 61_000, exchanges: 3, failures: 1 })
    );
}

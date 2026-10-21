// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `Net` interface (the stack's resolver and
// its SNTP client's state) -- `crates/core/syscall/src/net_host.rs::Server`,
// and `khost::serve` in front of it. The lookup itself (names, aliases, the
// wire) is `tests/host/net-tests`; this is the authority and the answers
// that need no packet: `net_poll` is a stand-in on this crate.
//
// Included inside `mod handlers { .. }` like `clock_guards.rs`.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::net::{FAMILY_V4, FAMILY_V6, NAME_MAX};
use azos_devif::{key, outcome, Net, NetIdl, NtpStatus, Out, Query};
use azos_idl::{header, MsgDesc, Writer, MSG_VERSION};
use crate::khost::Caller;

const SLOT: usize = 49;

fn setup() -> u32 {
    let tid = 0x7e45_0002;
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
    azos_net::ntp::reset_for_tests();
    tid
}

fn server(tid: u32, rights: CapPerms) -> crate::net_host::Server {
    crate::net_host::Server(Caller { tid, badge: 0, rights })
}

/// Both ops need `READ`; the refusal comes before the name is looked at.
/// **Canary:** skip the gate in `resolve`: the `WRITE`-only caller reaches
/// the resolver (and this crate's `net_poll` stand-in panics).
#[test]
fn both_ops_need_read_and_refuse_before_looking_at_anything() {
    let _g = serial();
    let tid = setup();
    let q = Query::new(FAMILY_V4, b"host.example").unwrap();
    for rights in [CapPerms::NONE, CapPerms::WRITE, CapPerms::EXEC] {
        assert_eq!(server(tid, rights).resolve(q), Out::err(outcome::DENIED), "resolve {rights:?}");
        assert_eq!(server(tid, rights).ntp_status().code, outcome::DENIED, "ntp_status {rights:?}");
    }
}

/// A family the interface does not name, and a name that is not text, are
/// `BAD_ARGUMENT` and send nothing.
#[test]
fn a_bad_query_is_refused_before_the_resolver() {
    let _g = serial();
    let tid = setup();
    let s = server(tid, CapPerms::READ);
    for family in [0, 5, 7, u32::MAX] {
        let q = Query::new(family, b"host.example").unwrap();
        assert_eq!(s.resolve(q), Out::err(outcome::BAD_ARGUMENT), "family {family}");
    }
    let not_text = Query::new(FAMILY_V6, &[0xFF, 0xFE, b'a']).unwrap();
    assert_eq!(s.resolve(not_text), Out::err(outcome::BAD_ARGUMENT), "not UTF-8");
    let empty = Query { family: FAMILY_V4, n: 0, w: [0; azos_devif::net::NAME_WORDS] };
    assert_eq!(s.resolve(empty), Out::err(outcome::BAD_ARGUMENT), "empty name");
}

/// A name over what the message carries cannot be built at all.
#[test]
fn a_name_longer_than_the_message_has_room_for_is_not_a_query() {
    assert!(Query::new(FAMILY_V4, &[b'a'; NAME_MAX]).is_some());
    assert!(Query::new(FAMILY_V4, &[b'a'; NAME_MAX + 1]).is_none());
    assert!(Query::new(FAMILY_V4, b"").is_none());
}

/// `ntp_status` reports what `azos_net::ntp` holds: nothing before a server
/// is set, the server (as a number, network order) after.
#[test]
fn ntp_status_reports_the_clients_server() {
    let _g = serial();
    let tid = setup();
    let s = server(tid, CapPerms::READ);
    assert_eq!(s.ntp_status(), Out::ok(NtpStatus::default()));
    azos_net::ntp::set_ntp_server([10, 0, 0, 124]);
    let st = s.ntp_status().value;
    assert_eq!((st.server, st.synced, st.exchanges, st.failures), (0x0A00_007C, 0, 0, 0));
}

/// Through the dispatcher: a request of eight words (header, family and
/// length, six of name) is taken, and `ntp_status` comes back as six words.
#[test]
fn the_wire_form_round_trips() {
    let _g = serial();
    let tid = setup();
    azos_net::ntp::set_ntp_server([10, 0, 0, 124]);
    let who = Caller { tid, badge: 0, rights: CapPerms::READ };

    // A refused family answers BAD_ARGUMENT through the whole request path:
    // eight words is the most a request holds, and `Query` fills them.
    let q = Query::new(5, b"a.example").unwrap();
    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut req);
        w.word(header(NetIdl::ID, NetIdl::LEVEL, NetIdl::OP_RESOLVE));
        w.word(q.n as u64 | (q.family as u64) << 32);
        for word in q.w {
            w.word(word);
        }
        w.finish();
    }
    assert_eq!(req.n_words, 8);
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::NET, &who, &req, &mut rep);
    assert_eq!((rep.words[0], rep.words[1] as u32), (azos_idl::STATUS_OK, outcome::BAD_ARGUMENT));

    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut req);
        w.word(header(NetIdl::ID, NetIdl::LEVEL, NetIdl::OP_NTP_STATUS));
        w.finish();
    }
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::NET, &who, &req, &mut rep);
    assert_eq!((rep.words[0], rep.words[1] as u32), (azos_idl::STATUS_OK, outcome::OK));
    assert_eq!(rep.words[2], 0x0A00_007C, "the server");
    assert_eq!(rep.n_words, 8, "status, outcome and six words of NtpStatus");
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The whole server against the test client: the handshake, a re-exchange,
//! strict key exchange, the channel and what it refuses.

use crate::harness::*;
use crate::server::*;
use crate::wire::*;

fn chan_msg(p: &[u8]) -> (u8, u32, Vec<u8>) {
    let mut r = Reader::new(p);
    let t = r.u8().unwrap();
    let c = r.u32().unwrap();
    (t, c, r.string().map(|s| s.to_vec()).unwrap_or_default())
}

#[test]
fn a_full_handshake_login_and_exec() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    assert_eq!(cl.host_key_seen, Some(cfg.host_public));
    assert_eq!(cl.server_version.as_deref(), Some(&b"SSH-2.0-AzOS_1"[..]));
    assert!(srv.is_authenticated());
    // The server raised the login.
    assert!(matches!(srv.pop_event(), Some(Event::Authenticated { .. })));
    cl.pty_req(0, 100, 30);
    cl.exec(0, b"echo hi");
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_CHANNEL_SUCCESS);
    cl.take_type(MSG_CHANNEL_SUCCESS);
    assert_eq!(srv.pop_event(), Some(Event::Pty { term: b"xterm".to_vec(), cols: 100, rows: 30 }));
    assert_eq!(srv.pop_event(), Some(Event::Exec(b"echo hi".to_vec())));
    // Output flows out, and the end of the command is exit-status, EOF, CLOSE.
    assert_eq!(srv.write(b"hi\n"), 3);
    srv.finish(7);
    exchange(&mut cl, &mut srv, &mut env);
    let d = cl.take_type(MSG_CHANNEL_DATA);
    assert_eq!(chan_msg(&d), (MSG_CHANNEL_DATA, 5, b"hi\n".to_vec()));
    let rq = cl.take_type(MSG_CHANNEL_REQUEST);
    let mut r = Reader::new(&rq);
    r.u8();
    assert_eq!(r.u32(), Some(5));
    assert_eq!(r.string(), Some(&b"exit-status"[..]));
    assert_eq!(r.boolean(), Some(false));
    assert_eq!(r.u32(), Some(7));
    cl.take_type(MSG_CHANNEL_EOF);
    cl.take_type(MSG_CHANNEL_CLOSE);
    // The client closes its side; the channel is gone.
    let mut w = Writer::new(MSG_CHANNEL_CLOSE);
    w.u32(0);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert_eq!(srv.pop_event(), Some(Event::Closed));
    assert!(!srv.can_write());
}

#[test]
fn the_handshake_works_without_strict_key_exchange_too() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (srv, cl) = with_channel(&cfg, &mut env, false);
    assert!(srv.is_authenticated());
    assert!(cl.session_id.is_some());
}

#[test]
fn typed_bytes_come_out_as_events_and_give_the_window_back() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    srv.pop_event();
    cl.data(0, b"ls\n");
    exchange(&mut cl, &mut srv, &mut env);
    assert_eq!(srv.pop_event(), Some(Event::Data(b"ls\n".to_vec())));
    // Past a quarter of the window consumed, the server tells the client.
    let chunk = vec![b'x'; LOCAL_MAX_PACKET as usize];
    let mut sent = 0u32;
    let mut adjusted = 0u64;
    for _ in 0..8 {
        cl.data(0, &chunk);
        exchange(&mut cl, &mut srv, &mut env);
        while let Some(ev) = srv.pop_event() {
            assert!(matches!(ev, Event::Data(_)));
        }
        exchange(&mut cl, &mut srv, &mut env);
        sent += chunk.len() as u32;
        while !cl.got.is_empty() {
            let p = cl.take_type(MSG_CHANNEL_WINDOW_ADJUST);
            let mut r = Reader::new(&p);
            r.u8();
            r.u32();
            adjusted += r.u32().unwrap() as u64;
        }
    }
    assert!(adjusted > 0, "no window adjust after {sent} bytes");
    assert!(sent as u64 <= LOCAL_WINDOW as u64 + adjusted, "the client was let send more than the window it was given");
}

#[test]
fn data_over_the_window_ends_the_connection() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    // The server never pops, so the window never comes back.
    for _ in 0..5 {
        cl.data(0, &vec![1u8; LOCAL_MAX_PACKET as usize]);
    }
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
    assert_eq!(cl.disconnected, Some(DISCONNECT_PROTOCOL_ERROR));
}

#[test]
fn a_packet_over_the_channel_s_maximum_ends_the_connection() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    cl.data(0, &vec![1u8; LOCAL_MAX_PACKET as usize + 1]);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
}

#[test]
fn writes_are_cut_to_the_peer_s_window_and_packet_size() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = logged_in(&cfg, &mut env, true);
    cl.open_session(9, 100, 40);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_CHANNEL_OPEN_CONFIRMATION);
    let big = vec![b'a'; 1000];
    assert_eq!(srv.write(&big), 40, "one packet, the peer's maximum");
    assert_eq!(srv.write(&big), 40);
    assert_eq!(srv.write(&big), 20, "the window ran down to 20");
    assert!(!srv.can_write());
    assert_eq!(srv.write(&big), 0);
    let mut w = Writer::new(MSG_CHANNEL_WINDOW_ADJUST);
    w.u32(0).u32(35);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.can_write());
    assert_eq!(srv.write(&big), 35);
    exchange(&mut cl, &mut srv, &mut env);
    // Everything arrived intact and in order.
    let mut total = 0;
    while !cl.got.is_empty() {
        let (t, c, d) = chan_msg(&cl.take());
        assert_eq!((t, c), (MSG_CHANNEL_DATA, 9));
        assert!(d.iter().all(|&b| b == b'a'));
        total += d.len();
    }
    assert_eq!(total, 135);
}

#[test]
fn the_window_never_grows_past_u32() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    for _ in 0..4 {
        let mut w = Writer::new(MSG_CHANNEL_WINDOW_ADJUST);
        w.u32(0).u32(u32::MAX);
        cl.send(&w.buf);
    }
    exchange(&mut cl, &mut srv, &mut env);
    assert!(!srv.is_closed());
    assert!(srv.can_write());
}

// ── Key exchange ────────────────────────────────────────────────────────────

#[test]
fn the_client_can_start_a_new_exchange_and_the_session_goes_on() {
    for strict in [true, false] {
        let cfg = config();
        let mut env = TestEnv::default();
        let (mut srv, mut cl) = with_channel(&cfg, &mut env, strict);
        srv.pop_event();
        let sid = cl.session_id.unwrap();
        // Output the server has queued while the exchange runs is held back and
        // arrives after it.
        cl.rekey();
        let held_before = srv.write(b"before");
        assert_eq!(held_before, 6);
        exchange(&mut cl, &mut srv, &mut env);
        assert!(cl.kex.is_none(), "the re-exchange finished");
        assert_eq!(cl.session_id, Some(sid), "the session id is the first exchange's for good");
        let d = cl.take_type(MSG_CHANNEL_DATA);
        assert_eq!(chan_msg(&d).2, b"before");
        // Both directions work under the new keys.
        assert_eq!(srv.write(b"after"), 5);
        cl.data(0, b"typed");
        exchange(&mut cl, &mut srv, &mut env);
        assert_eq!(chan_msg(&cl.take_type(MSG_CHANNEL_DATA)).2, b"after");
        assert_eq!(srv.pop_event(), Some(Event::Data(b"typed".to_vec())));
        // And a second one.
        cl.rekey();
        exchange(&mut cl, &mut srv, &mut env);
        assert!(cl.kex.is_none());
        assert_eq!(srv.write(b"again"), 5);
        exchange(&mut cl, &mut srv, &mut env);
        assert_eq!(chan_msg(&cl.take_type(MSG_CHANNEL_DATA)).2, b"again");
    }
}

#[test]
fn writes_wait_while_keys_change() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    cl.rekey();
    // Deliver the client's KEXINIT only.
    let b = std::mem::take(&mut cl.out);
    srv.feed(&mut env, &b);
    assert!(!srv.can_write(), "no channel data between KEXINIT and NEWKEYS");
    assert_eq!(srv.write(b"x"), 0);
}

#[test]
fn a_message_of_the_upper_layers_during_the_exchange_is_refused() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    cl.rekey();
    cl.data(0, b"sneaked");
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
}

#[test]
fn strict_key_exchange_refuses_an_ignore_before_kexinit() {
    // The Terrapin shape: a packet slipped in before the client's KEXINIT shifts
    // the sequence numbers. With strict key exchange offered, KEXINIT must be
    // packet 0.
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    let mut cl = Client::silent(true);
    cl.out.extend_from_slice(CLIENT_VERSION);
    cl.out.extend_from_slice(b"\r\n");
    let mut w = Writer::new(MSG_IGNORE);
    w.string(b"injected");
    cl.send(&w.buf);
    cl.send(&good_kexinit(true));
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
    assert_eq!(cl.disconnected, Some(DISCONNECT_PROTOCOL_ERROR));
}

#[test]
fn strict_key_exchange_refuses_any_other_message_during_the_first_exchange() {
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    let mut cl = Client::silent(true);
    cl.out.extend_from_slice(CLIENT_VERSION);
    cl.out.extend_from_slice(b"\r\n");
    cl.send(&good_kexinit(true));
    let mut w = Writer::new(MSG_DEBUG);
    w.boolean(false).string(b"x").string(b"");
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
}

#[test]
fn without_strict_an_ignore_before_kexinit_is_the_old_behavior() {
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    let mut cl = Client::silent(false);
    cl.out.extend_from_slice(CLIENT_VERSION);
    cl.out.extend_from_slice(b"\r\n");
    let mut w = Writer::new(MSG_IGNORE);
    w.string(b"x");
    cl.send(&w.buf);
    let ours = good_kexinit(false);
    cl.send(&ours);
    let eph = [0x41u8; 32];
    cl.kex = Some(crate::harness::Kex {
        ours,
        theirs: None,
        eph,
        q_c: azos_crypto::x25519::x25519(&eph, &azos_crypto::x25519::BASEPOINT),
        keys: None,
    });
    exchange(&mut cl, &mut srv, &mut env);
    assert!(!srv.is_closed(), "a client that does not offer strict mode is served as before");
    assert!(cl.session_id.is_some());
}

#[test]
fn a_key_exchange_with_no_common_algorithm_is_refused_and_recorded() {
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    let mut cl = Client::silent(false);
    cl.out.extend_from_slice(b"SSH-2.0-oldclient\r\n");
    cl.send(&client_kexinit(1, false, &["diffie-hellman-group14-sha1"], &["ssh-rsa"], &["aes128-ctr"], &["none"]));
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
    assert_eq!(cl.disconnected, Some(DISCONNECT_KEY_EXCHANGE_FAILED));
    let d = env.decisions.last().unwrap();
    assert_eq!((d.rule, d.verdict), (Rule::Kex, Verdict::Refuse));
    assert_eq!(d.subject, b"SSH-2.0-oldclient");
}

/// The host key is the keystore's. A host that cannot sign (the keystore refused,
/// or its key is gone) has no identity to offer: the exchange ends before the
/// reply, with no host key and no session.
///
/// **Canary.** Sign with a zero signature when the host says no: the client
/// sees a reply (and rejects it, but `host_key_seen` is set).
#[test]
fn a_host_that_cannot_sign_ends_the_key_exchange() {
    let cfg = config();
    let mut env = TestEnv { no_host_key: true, ..TestEnv::default() };
    let mut srv = Server::new(&cfg, &mut env);
    let mut cl = Client::new(true);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
    assert_eq!(cl.disconnected, Some(DISCONNECT_KEY_EXCHANGE_FAILED));
    assert!(cl.host_key_seen.is_none() && cl.session_id.is_none());
}

#[test]
fn a_small_order_public_key_is_refused() {
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    let mut cl = Client::silent(false);
    cl.out.extend_from_slice(CLIENT_VERSION);
    cl.out.extend_from_slice(b"\r\n");
    cl.send(&good_kexinit(false));
    let mut w = Writer::new(MSG_KEX_ECDH_INIT);
    w.string(&[0u8; 32]);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
    assert_eq!(cl.disconnected, Some(DISCONNECT_KEY_EXCHANGE_FAILED));
}

#[test]
fn a_public_key_of_the_wrong_length_is_refused() {
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    let mut cl = Client::silent(false);
    cl.out.extend_from_slice(CLIENT_VERSION);
    cl.out.extend_from_slice(b"\r\n");
    cl.send(&good_kexinit(false));
    let mut w = Writer::new(MSG_KEX_ECDH_INIT);
    w.string(&[9u8; 31]);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
}

#[test]
fn ecdh_init_before_kexinit_is_refused() {
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    let mut cl = Client::silent(false);
    cl.out.extend_from_slice(CLIENT_VERSION);
    cl.out.extend_from_slice(b"\r\n");
    let mut w = Writer::new(MSG_KEX_ECDH_INIT);
    w.string(&[9u8; 32]);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
}

#[test]
fn two_connections_have_different_ephemeral_keys_and_session_ids() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (_, a) = connected(&cfg, &mut env, true);
    let (_, b) = connected(&cfg, &mut env, true);
    assert_ne!(a.session_id, b.session_id);
}

// ── The version lines ───────────────────────────────────────────────────────

#[test]
fn the_server_speaks_first_with_its_version_and_kexinit() {
    let cfg = config();
    let mut env = TestEnv::default();
    let srv = Server::new(&cfg, &mut env);
    assert!(srv.pending().starts_with(b"SSH-2.0-AzOS_1\r\n"));
    assert!(srv.pending().len() > 100);
}

#[test]
fn a_peer_that_is_not_ssh_2_is_dropped() {
    for line in [&b"GET / HTTP/1.1\r\n"[..], b"SSH-1.5-ancient\r\n", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\n"] {
        let cfg = config();
        let mut env = TestEnv::default();
        let mut srv = Server::new(&cfg, &mut env);
        srv.feed(&mut env, line);
        assert!(srv.is_closed(), "{line:?}");
    }
}

#[test]
fn a_version_line_that_never_ends_is_dropped() {
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    srv.feed(&mut env, &vec![b'S'; 300]);
    assert!(srv.is_closed());
}

#[test]
fn the_version_line_may_arrive_in_pieces_and_end_in_a_bare_newline() {
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    for piece in [&b"SSH-2"[..], b".0-pieces", b"\n"] {
        srv.feed(&mut env, piece);
    }
    assert!(!srv.is_closed());
}

#[test]
fn ssh_1_99_is_taken_as_2_0() {
    let cfg = config();
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    srv.feed(&mut env, b"SSH-1.99-compat\r\n");
    assert!(!srv.is_closed());
}

#[test]
fn a_corrupt_packet_drops_the_connection_without_an_answer() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = connected(&cfg, &mut env, true);
    cl.service_request();
    let n = cl.out.len();
    cl.out[n - 3] ^= 1;
    let before = srv.pending().len();
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
    assert_eq!(before, 0);
    assert!(cl.disconnected.is_none(), "a packet that failed its tag gets no reply under keys it did not earn");
}

// ── The channel ─────────────────────────────────────────────────────────────

#[test]
fn only_one_session_and_only_session_channels() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    cl.open_session(6, 100, 100);
    exchange(&mut cl, &mut srv, &mut env);
    let f = cl.take_type(MSG_CHANNEL_OPEN_FAILURE);
    let mut r = Reader::new(&f);
    r.u8();
    assert_eq!(r.u32(), Some(6));
    assert_eq!(env.decisions.last().unwrap().why, "one session at a time");
    // Port forwarding.
    let mut w = Writer::new(MSG_CHANNEL_OPEN);
    w.string(b"direct-tcpip").u32(7).u32(100).u32(100).string(b"10.0.0.1").u32(80).string(b"127.0.0.1").u32(1234);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_CHANNEL_OPEN_FAILURE);
    let d = env.decisions.last().unwrap();
    assert_eq!((d.rule, d.verdict, d.subject.as_slice()), (Rule::Session, Verdict::Refuse, &b"direct-tcpip"[..]));
    assert!(!srv.is_closed());
}

#[test]
fn requests_that_are_not_offered_are_refused_and_recorded() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    for kind in [&b"subsystem"[..], b"x11-req", b"auth-agent-req@openssh.com", b"no-such-thing"] {
        cl.channel_request(0, kind, true, &[]);
        exchange(&mut cl, &mut srv, &mut env);
        cl.take_type(MSG_CHANNEL_FAILURE);
        let d = env.decisions.last().unwrap();
        assert_eq!((d.rule, d.verdict), (Rule::Session, Verdict::Refuse));
        assert_eq!(d.subject, kind);
    }
    // env is not honored, and is no reason to record anything.
    let n = env.decisions.len();
    let mut r = Writer::default();
    r.string(b"LANG").string(b"C");
    cl.channel_request(0, b"env", true, &r.buf);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_CHANNEL_FAILURE);
    assert_eq!(env.decisions.len(), n);
    // A request that wants no reply gets none.
    cl.channel_request(0, b"signal", false, &[]);
    cl.channel_request(0, b"subsystem", false, &[]);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(cl.got.is_empty());
}

#[test]
fn global_requests_are_answered_with_failure() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = logged_in(&cfg, &mut env, true);
    let mut w = Writer::new(MSG_GLOBAL_REQUEST);
    w.string(b"tcpip-forward").boolean(true).string(b"0.0.0.0").u32(8080);
    cl.send(&w.buf);
    let mut w = Writer::new(MSG_GLOBAL_REQUEST);
    w.string(b"keepalive@openssh.com").boolean(false);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_REQUEST_FAILURE);
    assert!(cl.got.is_empty());
}

#[test]
fn window_change_and_shell_become_events() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    srv.pop_event();
    cl.shell(0);
    let mut r = Writer::default();
    r.u32(132).u32(43).u32(0).u32(0);
    cl.channel_request(0, b"window-change", false, &r.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert_eq!(srv.pop_event(), Some(Event::Shell));
    assert_eq!(srv.pop_event(), Some(Event::Resize { cols: 132, rows: 43 }));
    cl.take_type(MSG_CHANNEL_SUCCESS);
    assert!(cl.got.is_empty(), "window-change wants no reply");
}

#[test]
fn eof_and_close_from_the_client_end_the_channel_cleanly() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    srv.pop_event();
    let mut w = Writer::new(MSG_CHANNEL_EOF);
    w.u32(0);
    cl.send(&w.buf);
    let mut w = Writer::new(MSG_CHANNEL_CLOSE);
    w.u32(0);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert_eq!(srv.pop_event(), Some(Event::Eof));
    assert_eq!(srv.pop_event(), Some(Event::Closed));
    cl.take_type(MSG_CHANNEL_CLOSE);
    // A new session can be opened on the same connection.
    cl.open_session(8, 1000, 1000);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_CHANNEL_OPEN_CONFIRMATION);
}

#[test]
fn a_message_for_a_channel_that_is_not_open_ends_the_connection() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    let mut w = Writer::new(MSG_CHANNEL_DATA);
    w.u32(3).string(b"x");
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
}

#[test]
fn an_unknown_message_number_is_answered_with_unimplemented() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = logged_in(&cfg, &mut env, true);
    let seq = cl.seq_out;
    cl.send(&[0xee, 1, 2, 3]);
    exchange(&mut cl, &mut srv, &mut env);
    let p = cl.take_type(MSG_UNIMPLEMENTED);
    assert_eq!(u32::from_be_bytes([p[1], p[2], p[3], p[4]]), seq);
}

#[test]
fn the_peer_s_disconnect_ends_the_connection_and_the_channel() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    srv.pop_event();
    let mut w = Writer::new(MSG_DISCONNECT);
    w.u32(11).string(b"bye").string(b"");
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
    assert_eq!(srv.pop_event(), Some(Event::Closed));
    // Nothing more is read after it.
    srv.feed(&mut env, b"garbage");
}

#[test]
fn the_server_can_disconnect_by_itself() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = connected(&cfg, &mut env, true);
    srv.disconnect(DISCONNECT_BY_APPLICATION, "grace time");
    exchange(&mut cl, &mut srv, &mut env);
    assert_eq!(cl.disconnected, Some(DISCONNECT_BY_APPLICATION));
    assert!(srv.is_closed());
}

#[test]
fn a_data_packet_is_one_segment_at_most() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = with_channel(&cfg, &mut env, true);
    let big = vec![b'z'; 10_000];
    let n = srv.write(&big);
    assert_eq!(n, MAX_DATA);
    exchange(&mut cl, &mut srv, &mut env);
    assert_eq!(chan_msg(&cl.take_type(MSG_CHANNEL_DATA)).2.len(), MAX_DATA);
}

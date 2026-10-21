// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Authentication: the logins of the topology view, the signature, and what the
//! server does with a login it will not take.

use crate::auth::*;
use crate::harness::*;
use crate::server::{Rule, Verdict};
use crate::wire::*;

fn login_line(user: &str, seed: &[u8; 32]) -> String {
    let hex: String = pubkey(seed).iter().map(|b| format!("{b:02x}")).collect();
    format!("{user} {hex}\n")
}

/// `/proc/ssh` is what the kernel writes from the signed topology: one line
/// per key, `<user name> <64 hex digits>`.
#[test]
fn the_logins_are_read_from_the_topology_view() {
    let file = format!(
        "{}{}{}",
        login_line("alice", &user_seed()),
        login_line("alice", &[9u8; 32]),
        login_line("bob", &other_seed()),
    );
    let p = parse_logins(file.as_bytes());
    assert_eq!(p.skipped, 0);
    let got: Vec<(&[u8], [u8; 32])> = p.keys.iter().map(|k| (&k.user[..], k.key)).collect();
    assert_eq!(
        got,
        vec![(&b"alice"[..], pubkey(&user_seed())), (&b"alice"[..], pubkey(&[9u8; 32])), (&b"bob"[..], pubkey(&other_seed()))]
    );
    // Nothing declared: nobody can log in.
    assert_eq!(parse_logins(b""), Parsed::default());
}

/// **Canary.** Accept a line the view cannot have written and a key the
/// topology never listed would be read in.
#[test]
fn a_line_that_is_not_a_login_is_skipped() {
    let good = login_line("alice", &user_seed());
    let hex: String = pubkey(&user_seed()).iter().map(|b| format!("{b:02x}")).collect();
    let file = format!(
        "{good}alice {}\nalice {}0\nalice {}\nalice\n alice {hex}\nalice {} x\n{hex}\nalice {}\n",
        &hex[..62],
        hex,
        hex.to_uppercase(),
        hex,
        "zz".repeat(32),
    );
    let p = parse_logins(file.as_bytes());
    assert_eq!(p.keys.len(), 1, "{:?}", p.keys);
    assert_eq!(p.keys[0].user, b"alice");
    assert_eq!(p.skipped, 8);
}

/// A key logs in as the user it is listed under and as no other: with the
/// right key and another name the server answers as for an unknown key.
#[test]
fn a_key_logs_in_only_as_its_own_user() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    cl.auth_publickey(b"admin", &user_seed(), false);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    cl.auth_publickey(b"admin", &user_seed(), true);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    assert!(!srv.is_authenticated());
    let r = refused(&env);
    assert_eq!(r.len(), 2);
    assert_eq!((r[0].why, &r[0].subject[..]), ("key is not authorized", &b"admin"[..]));
    // The same key under its own name is let in.
    cl.auth_publickey(b"root", &user_seed(), true);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_SUCCESS);
    assert!(srv.is_authenticated());
}

#[test]
fn key_blob_must_be_exactly_a_key() {
    let pk = pubkey(&user_seed());
    let mut ok = Writer::default();
    ok.string(b"ssh-ed25519").string(&pk);
    assert_eq!(key_of_blob(&ok.buf), Some(pk));
    let mut trailing = ok.buf.clone();
    trailing.push(0);
    assert_eq!(key_of_blob(&trailing), None);
    let mut short = Writer::default();
    short.string(b"ssh-ed25519").string(&pk[..31]);
    assert_eq!(key_of_blob(&short.buf), None);
    let mut other = Writer::default();
    other.string(b"ssh-rsa").string(&pk);
    assert_eq!(key_of_blob(&other.buf), None);
}

// ── On a connection ─────────────────────────────────────────────────────────

fn refused(env: &TestEnv) -> Vec<&crate::server::Decision> {
    env.decisions.iter().filter(|d| d.rule == Rule::Login && d.verdict == Verdict::Refuse).collect()
}

fn at_service<'c>(cfg: &'c crate::server::Config, env: &mut TestEnv) -> (crate::server::Server<'c>, Client) {
    let (mut srv, mut cl) = connected(cfg, env, true);
    cl.service_request();
    exchange(&mut cl, &mut srv, env);
    cl.take_type(MSG_SERVICE_ACCEPT);
    (srv, cl)
}

fn failure_methods(p: &[u8]) -> (Vec<u8>, bool) {
    let mut r = Reader::new(p);
    r.u8();
    let l = r.string().unwrap().to_vec();
    (l, r.boolean().unwrap())
}

#[test]
fn the_none_probe_says_public_keys_and_leaves_no_record() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    cl.auth_none(b"root");
    exchange(&mut cl, &mut srv, &mut env);
    let p = cl.take_type(MSG_USERAUTH_FAILURE);
    assert_eq!(failure_methods(&p), (b"publickey".to_vec(), false));
    assert!(env.decisions.is_empty());
}

#[test]
fn a_listed_key_is_offered_then_signed_for() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    cl.auth_publickey(b"root", &user_seed(), false);
    exchange(&mut cl, &mut srv, &mut env);
    let p = cl.take_type(MSG_USERAUTH_PK_OK);
    let mut r = Reader::new(&p);
    r.u8();
    assert_eq!(r.string(), Some(&b"ssh-ed25519"[..]));
    assert!(!srv.is_authenticated(), "a query is no login");
    cl.auth_publickey(b"root", &user_seed(), true);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_SUCCESS);
    assert!(srv.is_authenticated());
    let d = env.decisions.last().unwrap();
    assert_eq!((d.rule, d.verdict), (Rule::Login, Verdict::Admit));
    assert_eq!(d.subject, b"root");
    assert_eq!(d.key, Some(pubkey(&user_seed())));
}

#[test]
fn an_unknown_key_is_refused_and_recorded_with_its_fingerprint() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    cl.auth_publickey(b"mallory", &other_seed(), false);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    cl.auth_publickey(b"mallory", &other_seed(), true);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    assert!(!srv.is_authenticated());
    let r = refused(&env);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].why, "key is not authorized");
    assert_eq!(r[0].subject, b"mallory");
    assert_eq!(r[0].key, Some(pubkey(&other_seed())));
    let line = String::from_utf8(r[0].line()).unwrap();
    assert!(line.contains("login refuse user=mallory key=SHA256:"), "{line}");
    assert!(line.contains("rejected=log in:"), "a record names the alternative it rejected: {line}");
}

#[test]
fn a_listed_key_with_someone_elses_signature_is_refused() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    // The request names the authorized key but is signed by another secret:
    // build it by hand.
    let pk = pubkey(&user_seed());
    let mut blob = Writer::default();
    blob.string(b"ssh-ed25519").string(&pk);
    let sid = cl.session_id.unwrap();
    let mut m = Writer::default();
    m.string(&sid).u8(MSG_USERAUTH_REQUEST).string(b"root").string(b"ssh-connection").string(b"publickey").boolean(true);
    m.string(b"ssh-ed25519").string(&blob.buf);
    let sig = azos_crypto::ed25519::sign_message(&other_seed(), &m.buf);
    let mut sb = Writer::default();
    sb.string(b"ssh-ed25519").string(&sig);
    let mut w = Writer::new(MSG_USERAUTH_REQUEST);
    w.string(b"root").string(b"ssh-connection").string(b"publickey").boolean(true).string(b"ssh-ed25519").string(&blob.buf).string(&sb.buf);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    assert!(!srv.is_authenticated());
    assert_eq!(refused(&env)[0].why, "signature does not verify");
}

#[test]
fn the_signature_covers_the_session_the_user_and_the_service() {
    let cfg = config();
    let mut env = TestEnv::default();
    // Signed over another session id: a signature lifted from another
    // connection does not log in here.
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    cl.auth_publickey_for(b"root", b"ssh-connection", &user_seed(), true, &[0u8; 32]);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    assert!(!srv.is_authenticated());
    // Signed for another user name than the request says.
    let sid = cl.session_id.unwrap();
    let pk = pubkey(&user_seed());
    let mut blob = Writer::default();
    blob.string(b"ssh-ed25519").string(&pk);
    let mut m = Writer::default();
    m.string(&sid).u8(MSG_USERAUTH_REQUEST).string(b"alice").string(b"ssh-connection").string(b"publickey").boolean(true);
    m.string(b"ssh-ed25519").string(&blob.buf);
    let sig = azos_crypto::ed25519::sign_message(&user_seed(), &m.buf);
    let mut sb = Writer::default();
    sb.string(b"ssh-ed25519").string(&sig);
    let mut w = Writer::new(MSG_USERAUTH_REQUEST);
    w.string(b"root").string(b"ssh-connection").string(b"publickey").boolean(true).string(b"ssh-ed25519").string(&blob.buf).string(&sb.buf);
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    assert!(!srv.is_authenticated());
    // And with the right everything, it logs in.
    cl.auth_publickey(b"root", &user_seed(), true);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_SUCCESS);
}

#[test]
fn passwords_are_not_a_method_and_the_attempt_is_recorded() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    cl.auth_password(b"root");
    exchange(&mut cl, &mut srv, &mut env);
    let p = cl.take_type(MSG_USERAUTH_FAILURE);
    assert_eq!(failure_methods(&p).0, b"publickey");
    assert!(!srv.is_authenticated());
    assert_eq!(refused(&env)[0].why, "method not offered (public keys only)");
}

#[test]
fn another_service_than_ssh_connection_is_refused() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    cl.auth_publickey_for(b"root", b"ssh-telnet", &user_seed(), true, &cl.session_id.unwrap());
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    assert!(!srv.is_authenticated());
}

#[test]
fn an_rsa_key_is_not_accepted() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    let mut w = Writer::new(MSG_USERAUTH_REQUEST);
    w.string(b"root").string(b"ssh-connection").string(b"publickey").boolean(false).string(b"rsa-sha2-512").string(b"\0\0\0\x07ssh-rsa");
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    assert_eq!(refused(&env)[0].why, "key type not accepted (ssh-ed25519 only)");
}

#[test]
fn six_failed_signatures_end_the_connection() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    for i in 0..crate::server::MAX_FAILURES {
        assert!(!srv.is_closed(), "closed after {i} failures");
        cl.auth_publickey(b"root", &other_seed(), true);
        exchange(&mut cl, &mut srv, &mut env);
    }
    assert!(srv.is_closed());
    assert_eq!(cl.disconnected, Some(DISCONNECT_NO_MORE_AUTH_METHODS));
    assert!(!srv.is_authenticated());
}

#[test]
fn unsigned_queries_for_keys_that_are_not_listed_are_bounded_too() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    for _ in 0..200 {
        if srv.is_closed() {
            break;
        }
        cl.auth_publickey(b"root", &other_seed(), false);
        exchange(&mut cl, &mut srv, &mut env);
    }
    assert!(srv.is_closed(), "a client cannot ask for ever");
    assert!(env.decisions.len() as u32 <= crate::server::MAX_REQUESTS + 1);
}

#[test]
fn connection_messages_before_login_end_the_connection() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    cl.open_session(1, 1000, 1000);
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
    assert_eq!(cl.disconnected, Some(DISCONNECT_PROTOCOL_ERROR));
}

#[test]
fn auth_before_the_service_request_ends_the_connection() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = connected(&cfg, &mut env, true);
    cl.auth_none(b"root");
    exchange(&mut cl, &mut srv, &mut env);
    assert!(srv.is_closed());
}

#[test]
fn another_service_than_userauth_is_not_available() {
    let cfg = config();
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = connected(&cfg, &mut env, true);
    let mut w = Writer::new(MSG_SERVICE_REQUEST);
    w.string(b"ssh-connection");
    cl.send(&w.buf);
    exchange(&mut cl, &mut srv, &mut env);
    assert_eq!(cl.disconnected, Some(DISCONNECT_SERVICE_NOT_AVAILABLE));
}

#[test]
fn a_server_with_no_authorized_key_lets_nobody_in() {
    let cfg = crate::server::Config::new(pubkey(&host_seed()), vec![]);
    let mut env = TestEnv::default();
    let (mut srv, mut cl) = at_service(&cfg, &mut env);
    cl.auth_publickey(b"root", &user_seed(), true);
    exchange(&mut cl, &mut srv, &mut env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    assert!(!srv.is_authenticated());
    assert_eq!(refused(&env)[0].why, "key is not authorized");
}

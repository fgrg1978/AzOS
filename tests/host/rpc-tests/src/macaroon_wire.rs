// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The wire form of a caveated warrant: an HMAC-SHA256 chain keyed by the
//! session's Noise-derived key (`wire::Token`), and what the receiving node
//! makes of it (`Session::remint`). Every session here is the real handshake,
//! so the key under test is the one the channel derives, not a stand-in.

use azos_rpc::chan::{self, Channel};
use azos_rpc::session::{Refusal, Remint, Session, State};
use azos_rpc::wire::{cav, get_token, put_token, Caveat, Token, TokenError, CAVEATS_MAX, TOKEN_MAX};
use azos_rpc::NodeId;

const A: NodeId = 1;
const B: NodeId = 2;
const IFACE: u32 = 0x7001;
const SESSION: u32 = 41;
const NOW: u64 = 5_000_000_000;
const TTL: u64 = 60_000_000_000;

fn sk(n: NodeId, salt: u8) -> [u8; 32] {
    [0x40 + n as u8 + salt; 32]
}

/// A real Noise IK handshake from `A` (dialer) to `B`; the two channels.
fn handshake(salt: u8, nonce: u64) -> (Channel, Channel) {
    let (ska, skb) = (sk(A, salt), sk(B, salt));
    let (pka, pkb) = (chan::static_public_key(&ska), chan::static_public_key(&skb));
    let pro = chan::prologue(A, B, 1, nonce);
    let mut eph_a = [0xA0u8; 32];
    eph_a[..8].copy_from_slice(&nonce.to_le_bytes());
    let mut eph_b = [0xB0u8; 32];
    eph_b[..8].copy_from_slice(&nonce.to_le_bytes());
    let mut hello = [0u8; 160];
    let (hs, n) = chan::dial(&ska, &pkb, &pro, &eph_a, &[0u8], &mut hello).unwrap();
    let mut ack = [0u8; 160];
    let mut payload = [0u8; 64];
    let (chan_b, ack_len, _) = chan::answer(&skb, &pka, &pro, &hello[..n], &eph_b, &[0u8], &mut ack, &mut payload).unwrap();
    let (chan_a, _) = chan::finish_dial(hs, &pkb, &ack[..ack_len], &mut payload).unwrap();
    (chan_a, chan_b)
}

fn up(chan: Channel, peer: NodeId, id: u32) -> Box<Session> {
    let mut s = Box::new(Session::free());
    s.state = State::Up;
    s.peer = peer;
    s.id = id;
    s.chan = chan;
    // The peer serves IFACE to us, and we serve it to the peer: a session
    // where both directions are exported keeps one fixture for both ends.
    s.offered[0] = IFACE;
    s.n_offered = 1;
    s.granted[0] = IFACE;
    s.n_granted = 1;
    s
}

/// A's and B's view of one session.
fn pair() -> (Box<Session>, Box<Session>) {
    let (ca, cb) = handshake(0, 7);
    (up(ca, B, SESSION), up(cb, A, SESSION))
}

/// A token A issues for B's interface, with `caveats` appended.
fn token(a: &Session, caveats: &[Caveat]) -> Token {
    let mut t = a.issue(A, IFACE).expect("a session that is up, whose peer serves the interface");
    for c in caveats {
        t.attenuate(*c).unwrap();
    }
    t
}

fn wire(t: &Token) -> Vec<u8> {
    let mut buf = vec![0u8; TOKEN_MAX];
    let mut at = 0;
    put_token(t, &mut buf, &mut at).unwrap();
    buf.truncate(at);
    buf
}

fn unwire(b: &[u8]) -> Option<Token> {
    let mut at = 0;
    get_token(b, &mut at)
}

/// Over the wire and through B.
/// The uses of each budget of `r`, in order.
fn uses(r: &Remint) -> Vec<u64> {
    r.budget_list().iter().map(|b| b.uses).collect()
}

fn at_b(b: &Session, bytes: &[u8]) -> Result<Remint, Refusal> {
    b.remint(&unwire(bytes).ok_or(Refusal::BadChain)?, B, NOW, TTL)
}

const EXPIRY_3S: Caveat = Caveat::new(cav::EXPIRY, 3_000_000_000);
const QUOTA_4: Caveat = Caveat::new(cav::QUOTA, 4);
const OPS_0110: Caveat = Caveat::new(cav::OP_MASK, 0b0110);

/// The two ends of one handshake hold the same key; two handshakes do not; a
/// channel with no keys holds none. Without the first, no chain could verify;
/// without the second, one session's token would open another's.
#[test]
fn both_ends_derive_the_same_session_key_and_no_other_session_shares_it() {
    let (ca, cb) = handshake(0, 7);
    assert_eq!(ca.mac_key(), cb.mac_key());
    assert!(ca.mac_key().is_some());
    let (cc, _) = handshake(0, 8);
    assert_ne!(ca.mac_key(), cc.mac_key(), "another nonce, another session");
    let (cd, _) = handshake(1, 7);
    assert_ne!(ca.mac_key(), cd.mac_key(), "other static keys");
    assert_eq!(Channel::idle().mac_key(), None);
}

/// A chain A built under the session key, carried over the wire, verifies at B,
/// and B's warrant is exactly as narrow as the caveats say.
#[test]
fn a_valid_chain_is_accepted_and_re_minted_as_narrow_as_it_says() {
    let (a, b) = pair();
    let t = token(&a, &[EXPIRY_3S, QUOTA_4, OPS_0110]);
    let bytes = wire(&t);
    assert_eq!(unwire(&bytes), Some(t), "the wire form round-trips");
    let r = at_b(&b, &bytes).expect("a chain under the session key");
    assert_eq!(r.iface, IFACE);
    assert_eq!(r.expiry_ns, NOW + 3_000_000_000, "the token's 3 s, not the 60 s TTL");
    assert_eq!(uses(&r), [4]);
    assert_eq!(r.caveat_list(), &[Caveat::new(cav::OP_MASK, 0b0110)]);
    // A token with no caveat is the plain per-peer warrant: the TTL and nothing else.
    let r = at_b(&b, &wire(&token(&a, &[]))).unwrap();
    assert_eq!((r.expiry_ns, uses(&r), r.caveat_list().len()), (NOW + TTL, vec![], 0));
}

/// Change any one bit of a token on the wire: it is refused, whichever field
/// the bit is in (the count, a kind, an argument, the signature, the issuer,
/// the interface). Canary: the unchanged bytes are accepted just above, so a
/// refusal here is the bit and not the fixture.
#[test]
fn a_tampered_caveat_is_refused_whatever_bit_changes() {
    let (a, b) = pair();
    let good = wire(&token(&a, &[EXPIRY_3S, QUOTA_4, OPS_0110]));
    assert!(at_b(&b, &good).is_ok());
    for i in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[i] ^= 1 << bit;
            assert!(at_b(&b, &bad).is_err(), "byte {i} bit {bit} changed and the token was accepted");
        }
    }
}

/// The attack that matters: widen the warrant by editing a caveat to say more
/// (a longer expiry, more uses, every op) and keep the signature.
#[test]
fn a_widened_caveat_is_refused() {
    let (a, b) = pair();
    for (narrow, wide) in [
        (EXPIRY_3S, Caveat::new(cav::EXPIRY, 3_000_000_000_000)),
        (QUOTA_4, Caveat::new(cav::QUOTA, 4_000)),
        (OPS_0110, Caveat::new(cav::OP_MASK, u64::MAX)),
    ] {
        let mut t = token(&a, &[narrow]);
        let mut forged = wire(&t);
        // The argument of the one caveat sits at 11..19.
        forged[11..19].copy_from_slice(&wide.arg.to_le_bytes());
        assert_eq!(at_b(&b, &forged), Err(Refusal::BadChain));
        // The honest token it was cut from still passes.
        t.attenuate(Caveat::new(cav::QUOTA, 1)).unwrap();
        assert!(at_b(&b, &wire(&t)).is_ok());
    }
}

/// Dropping a caveat and keeping the signature: refused, whichever caveat goes
/// (the last, the first, the middle, all of them), and so is reordering.
#[test]
fn a_stripped_caveat_is_refused() {
    let (a, b) = pair();
    let t = token(&a, &[EXPIRY_3S, QUOTA_4, OPS_0110]);
    let good = wire(&t);
    assert!(at_b(&b, &good).is_ok());
    let sig = &good[good.len() - 32..];
    let header = &good[..8];
    let cavs: Vec<&[u8]> = good[10..good.len() - 32].chunks(9).collect();
    assert_eq!(cavs.len(), 3);
    let rebuild = |keep: &[usize]| -> Vec<u8> {
        let mut v = header.to_vec();
        v.push(keep.len() as u8);
        v.push(0);
        for &k in keep {
            v.extend_from_slice(cavs[k]);
        }
        v.extend_from_slice(sig);
        v
    };
    assert_eq!(at_b(&b, &rebuild(&[0, 1, 2])), Ok(at_b(&b, &good).unwrap()), "the rebuild helper alone changes nothing");
    for keep in [&[0usize, 1][..], &[1, 2], &[0, 2], &[2], &[0], &[]] {
        assert_eq!(at_b(&b, &rebuild(keep)), Err(Refusal::BadChain), "kept {keep:?}");
    }
    assert_eq!(at_b(&b, &rebuild(&[2, 1, 0])), Err(Refusal::BadChain), "reordered");
    // Stripping all of them and re-signing needs the session key, which only
    // the two nodes hold: a third party holding the key-less token cannot.
    let bare = token(&a, &[]);
    assert_ne!(wire(&bare)[wire(&bare).len() - 32..], *sig);
}

/// A holder with no key can add a caveat, and the result verifies and is
/// narrower than what it started from.
#[test]
fn an_appended_caveat_is_accepted_and_only_narrows() {
    let (a, b) = pair();
    let t = token(&a, &[EXPIRY_3S, OPS_0110]);
    let before = at_b(&b, &wire(&t)).unwrap();
    // A relay that holds the token and not the key (it goes through the wire).
    let mut relayed = unwire(&wire(&t)).unwrap();
    relayed.attenuate(Caveat::new(cav::EXPIRY, 1_000_000_000)).unwrap();
    relayed.attenuate(Caveat::new(cav::OP_MASK, 0b0011)).unwrap();
    let after = at_b(&b, &wire(&relayed)).expect("the appended chain verifies");
    assert_eq!(after.expiry_ns, NOW + 1_000_000_000);
    assert!(after.expiry_ns < before.expiry_ns);
    assert_eq!(after.caveat_list(), &[Caveat::new(cav::OP_MASK, 0b0010)], "0110 & 0011");
    // The original is untouched by the copy that grew.
    assert_eq!(at_b(&b, &wire(&t)), Ok(before));
    // Every QUOTA is a budget of its own, in order, whatever its size: a
    // larger one appended after a smaller one does not widen it (the first
    // still counts), and each counts in the lineage of the chain up to it.
    let mut q = token(&a, &[QUOTA_4]);
    let first = at_b(&b, &wire(&q)).unwrap().budget_list()[0].lineage;
    q.attenuate(Caveat::new(cav::QUOTA, 9)).unwrap();
    let r = at_b(&b, &wire(&q)).unwrap();
    assert_eq!(uses(&r), [4, 9]);
    assert_eq!(r.budget_list()[0].lineage, first, "attenuation keeps the lineage of the caveat it follows");
    assert_ne!(r.budget_list()[1].lineage, first);
    q.attenuate(Caveat::new(cav::QUOTA, 2)).unwrap();
    assert_eq!(uses(&at_b(&b, &wire(&q)).unwrap()), [4, 9, 2]);
}

/// A chain under another session's key is refused, and so is the right key
/// under another session id, another issuer or another interface (the root
/// binds all three).
#[test]
fn a_chain_under_the_wrong_session_key_is_refused() {
    let (a, b) = pair();
    let (a2, b2) = {
        let (ca, cb) = handshake(0, 99);
        (up(ca, B, SESSION), up(cb, A, SESSION))
    };
    let foreign = wire(&token(&a2, &[EXPIRY_3S]));
    assert_eq!(at_b(&b, &foreign), Err(Refusal::BadChain), "same session number, another handshake");
    // Not a fixture accident: the same token passes at the end of its own session.
    assert!(at_b(&b2, &foreign).is_ok());

    let ours = wire(&token(&a, &[EXPIRY_3S]));
    // The same keys, a session that is not the one the token was made in.
    let (_, b_other_id) = {
        let (ca, cb) = handshake(0, 7);
        (up(ca, B, SESSION + 1), up(cb, A, SESSION + 1))
    };
    assert_eq!(at_b(&b_other_id, &ours), Err(Refusal::BadChain), "another session id");
    // A token B itself issued, reflected at B: not the peer's.
    let reflected = b.issue(B, IFACE).unwrap();
    assert_eq!(b.remint(&reflected, B, NOW, TTL), Err(Refusal::WrongIssuer));
    // A token B issued is good at A, which is the end that did not issue it.
    assert!(a.remint(&reflected, A, NOW, TTL).is_ok());
    // Another interface than the one it was started for: the id is in the root.
    let mut other = unwire(&ours).unwrap();
    other.iface = IFACE + 1;
    let mut b3 = pair().1;
    b3.granted[1] = IFACE + 1;
    b3.n_granted = 2;
    assert_eq!(b3.remint(&other, B, NOW, TTL), Err(Refusal::BadChain));
}

/// What the receiver holds the verified chain to.
#[test]
fn the_re_minted_warrant_is_held_to_this_node() {
    let (a, b) = pair();
    let tok = |c: &[Caveat]| wire(&token(&a, c));
    // The TTL bounds a token that asks for longer, and a token with no expiry.
    assert_eq!(at_b(&b, &tok(&[Caveat::new(cav::EXPIRY, TTL * 10)])).unwrap().expiry_ns, NOW + TTL);
    // No TTL configured and no expiry in the token: never.
    let t = unwire(&tok(&[])).unwrap();
    assert_eq!(b.remint(&t, B, NOW, 0).unwrap().expiry_ns, 0);
    // No TTL configured, an expiry in the token: the token's.
    let t = unwire(&tok(&[EXPIRY_3S])).unwrap();
    assert_eq!(b.remint(&t, B, NOW, 0).unwrap().expiry_ns, NOW + 3_000_000_000);
    // A node caveat for this node is checked and dropped; for another it refuses.
    let r = at_b(&b, &tok(&[Caveat::new(cav::NODE, B as u64)])).unwrap();
    assert_eq!(r.caveat_list().len(), 0, "the kernel would refuse every use of a NODE caveat");
    assert_eq!(at_b(&b, &tok(&[Caveat::new(cav::NODE, 9)])), Err(Refusal::WrongNode));
    // A lapsed, spent or empty token.
    assert_eq!(at_b(&b, &tok(&[Caveat::new(cav::EXPIRY, 0)])), Err(Refusal::Lapsed));
    assert_eq!(at_b(&b, &tok(&[Caveat::new(cav::QUOTA, 0)])), Err(Refusal::Spent));
    assert_eq!(at_b(&b, &tok(&[Caveat::new(cav::OP_MASK, 0b01), Caveat::new(cav::OP_MASK, 0b10)])), Err(Refusal::NoOps));
    // A quota is a count of this node's: any size is kept as it is.
    assert_eq!(uses(&at_b(&b, &tok(&[Caveat::new(cav::QUOTA, u64::MAX)])).unwrap()), [u64::MAX]);
    // The reserved kind goes on to the kernel, in order, after the mask; a full
    // token still fits the list.
    let recv = Caveat::new(cav::RECEIPT, 77);
    let r = at_b(&b, &tok(&[recv, OPS_0110, EXPIRY_3S])).unwrap();
    assert_eq!(r.caveat_list(), &[Caveat::new(cav::OP_MASK, 0b0110), recv]);
    let r = at_b(&b, &tok(&[recv, recv, recv, recv])).unwrap();
    assert_eq!(r.caveat_list(), &[recv, recv, recv, recv], "four reserved kinds, no mask to make room for");
    // A declassification is a local human's warrant: no peer's token carries
    // one onto this node, wherever it sits in the chain.
    let decl = Caveat::new(cav::DECLASSIFY, 5);
    assert_eq!(at_b(&b, &tok(&[decl])), Err(Refusal::Declassify));
    assert_eq!(at_b(&b, &tok(&[recv, OPS_0110, decl])), Err(Refusal::Declassify));
}

/// Where the session stands decides before any chain is looked at.
#[test]
fn a_session_that_is_not_up_or_does_not_serve_the_interface_refuses() {
    let (a, mut b) = pair();
    let t = token(&a, &[]);
    b.granted[0] = IFACE + 5;
    assert_eq!(b.remint(&t, B, NOW, TTL), Err(Refusal::NotGranted), "B does not serve it to A");
    b.granted[0] = IFACE;
    b.state = State::Dialing;
    assert_eq!(b.remint(&t, B, NOW, TTL), Err(Refusal::NotUp));
    b.state = State::Up;
    assert!(b.remint(&t, B, NOW, TTL).is_ok());
    b.clear();
    b.state = State::Up;
    assert_eq!(b.remint(&t, B, NOW, TTL), Err(Refusal::NoKey), "a cleared channel keeps no key");
    // The sending side: no token for an interface the peer does not serve, or
    // from a session that is not up.
    let mut a = a;
    assert_eq!(a.issue(A, IFACE + 5), None);
    a.state = State::Dialing;
    assert_eq!(a.issue(A, IFACE), None);
}

/// The list holds as many as the kernel's does, and no more; a kind the
/// kernel does not know is refused when added and when read.
#[test]
fn the_list_is_bounded_and_an_unknown_kind_is_refused() {
    let (a, b) = pair();
    let mut t = token(&a, &[]);
    for _ in 0..CAVEATS_MAX {
        t.attenuate(Caveat::new(cav::QUOTA, 8)).unwrap();
    }
    assert_eq!(t.attenuate(Caveat::new(cav::QUOTA, 8)), Err(TokenError::Full));
    assert_eq!(t.caveats().len(), CAVEATS_MAX, "a refused caveat is not half added");
    assert!(at_b(&b, &wire(&t)).is_ok(), "and the chain is still the four");
    let mut t = token(&a, &[]);
    assert_eq!(t.attenuate(Caveat::new(0, 1)), Err(TokenError::UnknownKind));
    assert_eq!(t.attenuate(Caveat::new(7, 1)), Err(TokenError::UnknownKind));
    // On the wire: a count past the limit, a kind of 0 or 7, a reserved byte.
    let mut one = wire(&token(&a, &[QUOTA_4]));
    for (at, v) in [(8, 5u8), (10, 0), (10, 7), (9, 1)] {
        let old = one[at];
        one[at] = v;
        assert_eq!(unwire(&one), None, "byte {at} = {v}");
        one[at] = old;
    }
    assert!(unwire(&one).is_some());
    // Short input and trailing bytes: the first is refused, the second is the
    // next field's, and the reader says where it stopped.
    assert_eq!(unwire(&one[..one.len() - 1]), None);
    let mut at = 0;
    let mut long = one.clone();
    long.extend_from_slice(&[0xEE; 5]);
    assert!(get_token(&long, &mut at).is_some());
    assert_eq!(at, one.len());
}

/// The numbers the wire uses are the kernel's. The kernel's source is the
/// reference: a number changed there, or a kind added, fails here.
#[test]
fn the_kinds_and_the_limit_are_the_kernels() {
    let src = include_str!("../../../../crates/core/ipc/src/cap.rs");
    let num = |name: &str, ty: &str| -> u64 {
        let key = format!("pub const {name}: {ty} = ");
        let rest = &src[src.find(&key).unwrap_or_else(|| panic!("{key} not in cap.rs")) + key.len()..];
        rest[..rest.find(';').unwrap()].parse().unwrap()
    };
    assert_eq!(num("EXPIRY", "u8"), cav::EXPIRY as u64);
    assert_eq!(num("QUOTA", "u8"), cav::QUOTA as u64);
    assert_eq!(num("NODE", "u8"), cav::NODE as u64);
    assert_eq!(num("OP_MASK", "u8"), cav::OP_MASK as u64);
    assert_eq!(num("RECEIPT", "u8"), cav::RECEIPT as u64);
    assert_eq!(num("DECLASSIFY", "u8"), cav::DECLASSIFY as u64);
    assert_eq!(num("CAVEATS_MAX", "usize"), CAVEATS_MAX as u64);
    let known = (0..=255u8).filter(|&k| cav::known(k)).count();
    assert_eq!(known, 6, "the kernel's `known` lists six kinds");
    assert!(src.contains("matches!(kind, EXPIRY | QUOTA | NODE | OP_MASK | RECEIPT | DECLASSIFY)"));
}

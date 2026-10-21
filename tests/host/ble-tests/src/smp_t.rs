// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SMP LE Secure Connections between two hosts over the scripted radio.

use crate::rig::*;
use azos_ble::hci;
use azos_ble::l2cap::CID_SMP;
use azos_ble::smp::{io_cap, reason, Keys, Role};
use azos_ble::{PeerAddr, Config};
use std::cell::RefCell;
use std::rc::Rc;

const NIO: u8 = io_cap::NO_INPUT_NO_OUTPUT;
const DYN: u8 = io_cap::DISPLAY_YES_NO;

fn rig(a: Config, b: Config) -> Rig {
    let mut r = Rig::new(a, b);
    r.init();
    r.connect();
    assert!(r.ua.find(|e| matches!(e, Ev::Connected { role: Role::Initiator, .. }).then_some(())).is_some());
    assert!(r.ub.find(|e| matches!(e, Ev::Connected { role: Role::Responder, .. }).then_some(())).is_some());
    r.ua.take();
    r.ub.take();
    r
}

fn paired(r: &Rig) -> (Option<Keys>, Option<Keys>) {
    let f = |u: &Rec| u.find(|e| if let Ev::Paired(_, k) = e { Some(*k) } else { None });
    (f(&r.ua), f(&r.ub))
}

fn failed(u: &Rec) -> Vec<u8> {
    u.events.iter().filter_map(|e| if let Ev::PairingFailed(_, r) = e { Some(*r) } else { None }).collect()
}

fn numeric(u: &Rec) -> Option<u32> {
    u.find(|e| if let Ev::Numeric(_, v) = e { Some(*v) } else { None })
}

fn smp_codes(r: &Rig) -> Vec<(usize, u8)> {
    r.air.iter().filter(|(_, cid, _)| *cid == CID_SMP).map(|(f, _, p)| (*f, p[0])).collect()
}

fn started_encryption(c: &Side) -> Vec<[u8; 16]> {
    c.cmds
        .iter()
        .filter(|c| c.op == hci::OP_LE_START_ENCRYPTION)
        .map(|c| c.params[12..28].try_into().unwrap())
        .collect()
}

#[test]
fn just_works_ends_with_the_same_key_on_both_sides_and_an_encrypted_link() {
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
    r.settle();
    let (ka, kb) = paired(&r);
    let (ka, kb) = (ka.expect("central paired"), kb.expect("peripheral paired"));
    assert_eq!(ka.ltk, kb.ltk);
    assert_ne!(ka.ltk, [0; 16]);
    assert!(!ka.authenticated && !kb.authenticated, "just works is not an authenticated key");
    assert_eq!(ka.peer, PeerAddr { kind: 0, addr: ADDR_B });
    assert_eq!(kb.peer, PeerAddr { kind: 0, addr: ADDR_A });
    assert!(r.a.encrypted(r.ha) && r.b.encrypted(r.hb));
    assert!(r.ua.events.contains(&Ev::Encrypted(r.ha)) && r.ub.events.contains(&Ev::Encrypted(r.hb)));
    assert_eq!(started_encryption(&r.ca), vec![ka.ltk]);
    // Request, response, the two public keys, confirm, the two randoms, the two checks.
    use std::iter::once;
    let want: Vec<(usize, u8)> =
        once((0, 1)).chain(once((1, 2))).chain(once((0, 0x0C))).chain(once((1, 0x0C))).chain(once((1, 3))).chain(once((0, 4))).chain(once((1, 4))).chain(once((0, 0x0D))).chain(once((1, 0x0D))).collect();
    assert_eq!(smp_codes(&r), want);
    assert!(numeric(&r.ua).is_none() && numeric(&r.ub).is_none());
    // The long term key never crosses the air.
    for (_, cid, p) in &r.air {
        assert!(!p.windows(16).any(|w| w == ka.ltk), "the LTK on the air in cid {cid}");
    }
}

#[test]
fn two_pairings_make_two_keys() {
    let mut keys = vec![];
    for seed in 0..2u64 {
        let mut r = Rig::new(cfg(NIO, false), cfg(NIO, false));
        r.a = azos_ble::Host::new(Rng(100 + seed), cfg(NIO, false));
        r.init();
        r.connect();
        r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
        r.settle();
        keys.push(paired(&r).0.unwrap().ltk);
    }
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn numeric_comparison_shows_the_same_digits_and_waits_for_both_users() {
    let mut r = rig(cfg(DYN, true), cfg(DYN, true));
    r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
    r.settle();
    let (va, vb) = (numeric(&r.ua).unwrap(), numeric(&r.ub).unwrap());
    assert_eq!(va, vb);
    assert!(va < 1_000_000);
    assert_eq!(paired(&r), (None, None), "nothing is trusted before the users agree");
    assert!(started_encryption(&r.ca).is_empty());
    r.a.confirm_numeric(r.ha, true, &mut r.ua).unwrap();
    r.settle();
    assert_eq!(paired(&r), (None, None), "the peripheral's user has not answered");
    r.b.confirm_numeric(r.hb, true, &mut r.ub).unwrap();
    r.settle();
    let (ka, kb) = paired(&r);
    assert_eq!(ka.unwrap().ltk, kb.unwrap().ltk);
    assert!(ka.unwrap().authenticated && kb.unwrap().authenticated);
}

#[test]
fn numeric_comparison_in_the_other_order_of_answers() {
    let mut r = rig(cfg(DYN, true), cfg(DYN, true));
    r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
    r.settle();
    r.b.confirm_numeric(r.hb, true, &mut r.ub).unwrap();
    r.settle();
    assert_eq!(paired(&r), (None, None));
    r.a.confirm_numeric(r.ha, true, &mut r.ua).unwrap();
    r.settle();
    assert!(paired(&r).0.is_some() && paired(&r).1.is_some());
}

#[test]
fn a_user_who_says_the_digits_differ_ends_it_on_both_sides() {
    for rejecter in 0..2 {
        let mut r = rig(cfg(DYN, true), cfg(DYN, true));
        r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
        r.settle();
        if rejecter == 0 {
            r.a.confirm_numeric(r.ha, false, &mut r.ua).unwrap();
        } else {
            r.b.confirm_numeric(r.hb, false, &mut r.ub).unwrap();
        }
        r.settle();
        assert_eq!(failed(&r.ua), vec![reason::NUMERIC_COMPARISON_FAILED]);
        assert_eq!(failed(&r.ub), vec![reason::NUMERIC_COMPARISON_FAILED]);
        assert_eq!(paired(&r), (None, None));
        assert!(started_encryption(&r.ca).is_empty());
    }
}

/// Run a pairing with a man in the middle that changes one frame.
fn mitm(a: Config, b: Config, edit: impl FnMut(usize, u16, &mut Vec<u8>) + 'static) -> Rig {
    let mut r = rig(a, b);
    r.tamper = Some(Box::new(edit));
    r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
    r.settle();
    r
}

fn flip(p: &mut Vec<u8>, at: usize) {
    p[at] ^= 0x01;
}

#[test]
fn a_changed_confirm_value_is_caught_by_the_central() {
    let r = mitm(cfg(NIO, false), cfg(NIO, false), |from, cid, p| {
        if from == 1 && cid == CID_SMP && p[0] == 3 {
            flip(p, 5)
        }
    });
    assert_eq!(failed(&r.ua), vec![reason::CONFIRM_VALUE_FAILED]);
    assert_eq!(failed(&r.ub), vec![reason::CONFIRM_VALUE_FAILED], "the peer is told why");
    assert_eq!(paired(&r), (None, None));
    assert!(started_encryption(&r.ca).is_empty());
}

#[test]
fn a_changed_responder_nonce_does_not_open_the_commitment() {
    let r = mitm(cfg(NIO, false), cfg(NIO, false), |from, cid, p| {
        if from == 1 && cid == CID_SMP && p[0] == 4 {
            flip(p, 9)
        }
    });
    assert_eq!(failed(&r.ua), vec![reason::CONFIRM_VALUE_FAILED]);
    assert_eq!(paired(&r), (None, None));
}

#[test]
fn a_changed_initiator_nonce_makes_the_dhkey_check_fail_at_the_peripheral() {
    let r = mitm(cfg(NIO, false), cfg(NIO, false), |from, cid, p| {
        if from == 0 && cid == CID_SMP && p[0] == 4 {
            flip(p, 3)
        }
    });
    assert_eq!(failed(&r.ub), vec![reason::DHKEY_CHECK_FAILED]);
    assert_eq!(failed(&r.ua), vec![reason::DHKEY_CHECK_FAILED]);
    assert_eq!(paired(&r), (None, None));
}

#[test]
fn a_changed_dhkey_check_fails_on_the_side_that_verifies_it() {
    for from in 0..2usize {
        let r = mitm(cfg(NIO, false), cfg(NIO, false), move |f, cid, p| {
            if f == from && cid == CID_SMP && p[0] == 0x0D {
                flip(p, 16)
            }
        });
        let verifier = if from == 0 { &r.ub } else { &r.ua };
        assert_eq!(failed(verifier), vec![reason::DHKEY_CHECK_FAILED], "check from side {from}");
        assert_eq!(paired(&r), (None, None));
        if from == 0 {
            assert!(started_encryption(&r.ca).is_empty(), "the central never encrypts on a bad check");
        }
    }
}

#[test]
fn a_public_key_off_the_curve_is_refused() {
    for from in 0..2usize {
        let r = mitm(cfg(NIO, false), cfg(NIO, false), move |f, cid, p| {
            if f == from && cid == CID_SMP && p[0] == 0x0C {
                flip(p, 40)
            }
        });
        let receiver = if from == 0 { &r.ub } else { &r.ua };
        assert_eq!(failed(receiver), vec![reason::INVALID_PARAMETERS], "key from side {from}");
        assert_eq!(paired(&r), (None, None));
    }
}

#[test]
fn a_peers_public_key_equal_to_ours_is_refused() {
    let seen: Rc<RefCell<Option<Vec<u8>>>> = Rc::new(RefCell::new(None));
    let s = seen.clone();
    let r = mitm(cfg(NIO, false), cfg(NIO, false), move |from, cid, p| {
        if cid == CID_SMP && p[0] == 0x0C {
            if from == 0 {
                *s.borrow_mut() = Some(p.clone());
            } else {
                *p = s.borrow().clone().unwrap();
            }
        }
    });
    assert_eq!(failed(&r.ua), vec![reason::INVALID_PARAMETERS], "the reflected key");
    assert_eq!(paired(&r), (None, None));
}

#[test]
fn the_local_policy_can_refuse_just_works() {
    // The central demands MITM protection; the peripheral cannot offer it.
    let r = mitm(cfg(NIO, true), cfg(NIO, false), |_, _, _| {});
    assert_eq!(failed(&r.ua), vec![reason::AUTHENTICATION_REQUIREMENTS]);
    assert_eq!(failed(&r.ub), vec![reason::AUTHENTICATION_REQUIREMENTS]);
    // The peripheral demands it.
    let r = mitm(cfg(NIO, false), cfg(NIO, true), |_, _, _| {});
    assert_eq!(failed(&r.ua), vec![reason::AUTHENTICATION_REQUIREMENTS]);
    assert_eq!(paired(&r), (None, None));
}

#[test]
fn a_peripheral_that_is_not_pairable_says_so() {
    let mut b = cfg(NIO, false);
    b.smp.pairable = false;
    let r = mitm(cfg(NIO, false), b, |_, _, _| {});
    assert_eq!(failed(&r.ua), vec![reason::PAIRING_NOT_SUPPORTED]);
}

fn inject(r: &mut Rig, payload: &[u8]) {
    r.cb.frame_to_host(r.hb, CID_SMP, payload, 27);
    r.settle();
}

fn answers(r: &Rig) -> Vec<Vec<u8>> {
    r.air.iter().filter(|(f, cid, _)| *f == 1 && *cid == CID_SMP).map(|(_, _, p)| p.clone()).collect()
}

#[test]
fn requests_the_host_cannot_serve_are_refused_with_the_right_reason() {
    // Legacy pairing (no SC bit).
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    inject(&mut r, &[1, NIO, 0, 0x01, 16, 0, 0]);
    assert_eq!(answers(&r), vec![vec![5, reason::AUTHENTICATION_REQUIREMENTS]]);
    assert_eq!(failed(&r.ub), vec![reason::AUTHENTICATION_REQUIREMENTS]);
    // Out-of-band data.
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    inject(&mut r, &[1, NIO, 1, 0x09, 16, 0, 0]);
    assert_eq!(answers(&r), vec![vec![5, reason::OOB_NOT_AVAILABLE]]);
    // A short key.
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    inject(&mut r, &[1, NIO, 0, 0x09, 7, 0, 0]);
    assert_eq!(answers(&r), vec![vec![5, reason::ENCRYPTION_KEY_SIZE]]);
    // Passkey entry: the peer has a keyboard, we a yes/no display.
    let mut r = rig(cfg(DYN, true), cfg(DYN, true));
    inject(&mut r, &[1, io_cap::KEYBOARD_ONLY, 0, 0x0D, 16, 0, 0]);
    assert_eq!(answers(&r), vec![vec![5, reason::PAIRING_NOT_SUPPORTED]]);
    // An I/O capability that does not exist.
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    inject(&mut r, &[1, 9, 0, 0x09, 16, 0, 0]);
    assert_eq!(answers(&r), vec![vec![5, reason::INVALID_PARAMETERS]]);
}

#[test]
fn a_request_accepted_gets_a_response_with_no_key_distribution() {
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    inject(&mut r, &[1, NIO, 0, 0x09, 16, 7, 7]);
    assert_eq!(answers(&r), vec![vec![2, NIO, 0, 0x09, 16, 0, 0]], "SC and bonding, 16-byte key, nothing to distribute");
}

#[test]
fn malformed_unknown_and_out_of_turn_pdus() {
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    inject(&mut r, &[0x0F]); // not an SMP command
    inject(&mut r, &[3, 1, 2]); // a short confirm
    inject(&mut r, &[3; 17]); // a confirm nobody asked for
    assert_eq!(
        answers(&r),
        vec![
            vec![5, reason::COMMAND_NOT_SUPPORTED],
            vec![5, reason::INVALID_PARAMETERS],
            vec![5, reason::UNSPECIFIED],
        ]
    );
    // Key distribution PDUs are not part of this procedure and are not answered.
    let n = answers(&r).len();
    inject(&mut r, &[0x06; 17]);
    inject(&mut r, &[0x0A; 17]);
    assert_eq!(answers(&r).len(), n);
    // A second request inside a running pairing.
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    r.cb.frame_to_host(r.hb, CID_SMP, &[1, NIO, 0, 0x09, 16, 0, 0], 27);
    r.cb.frame_to_host(r.hb, CID_SMP, &[1, NIO, 0, 0x09, 16, 0, 0], 27);
    r.settle();
    assert_eq!(answers(&r)[1], vec![5, reason::UNSPECIFIED]);
    // And a Pairing Failed in idle is nobody's business.
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    inject(&mut r, &[5, 1]);
    assert!(answers(&r).is_empty() && r.ub.events.is_empty());
}

#[test]
fn only_the_central_pairs_and_only_the_peripheral_asks() {
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    assert_eq!(r.b.pair(r.hb, r.now, &mut r.ub), Err(azos_ble::host::SendError::NotAllowed));
    assert_eq!(r.a.security_request(r.ha), Err(azos_ble::host::SendError::NotAllowed));
    r.b.security_request(r.hb).unwrap();
    r.settle();
    assert_eq!(r.ua.events, vec![Ev::SecurityRequest(r.ha)]);
    // The upper layer answers by pairing.
    r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
    r.settle();
    assert!(paired(&r).0.is_some());
    // The peripheral does not act on a security request it receives.
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    r.a.security_request(r.ha).ok();
    inject(&mut r, &[0x0B, 0x09]);
    assert!(r.ub.events.is_empty() && answers(&r).is_empty());
}

#[test]
fn a_pairing_that_never_finishes_ends_after_thirty_seconds_with_the_link() {
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
    // Only the central's host runs: the request leaves, the peripheral never answers.
    step_host(&mut r.a, &mut r.ca, &mut r.ua, r.now);
    r.ca.process();
    r.ca.acl.clear();
    r.now += azos_ble::smp::TIMEOUT_MS - 1;
    step_host(&mut r.a, &mut r.ca, &mut r.ua, r.now);
    assert!(failed(&r.ua).is_empty());
    r.now += 1;
    step_host(&mut r.a, &mut r.ca, &mut r.ua, r.now);
    r.ca.process();
    assert_eq!(failed(&r.ua), vec![reason::TIMEOUT]);
    assert_eq!(r.ca.cmds.last().unwrap().op, hci::OP_DISCONNECT);
}

// ── Reconnection with a stored key ─────────────────────────────────────────

fn pair_and_store(r: &mut Rig) -> Keys {
    r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
    r.settle();
    let (ka, kb) = paired(r);
    let (ka, kb) = (ka.unwrap(), kb.unwrap());
    r.ua.store.push((ka.peer, ka.ltk));
    r.ub.store.push((kb.peer, kb.ltk));
    r.a.disconnect(r.ha, hci::status::REMOTE_USER_TERMINATED).unwrap();
    r.settle();
    assert!(r.ua.events.iter().any(|e| matches!(e, Ev::Disconnected(..))));
    assert!(!r.a.encrypted(r.ha), "a new link starts in the clear");
    r.ua.take();
    r.ub.take();
    r.connect();
    r.ua.take();
    r.ub.take();
    ka
}

#[test]
fn a_stored_key_encrypts_the_reconnection_without_pairing() {
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    let k = pair_and_store(&mut r);
    r.a.encrypt(r.ha, k.ltk).unwrap();
    r.settle();
    assert_eq!(r.ua.events, vec![Ev::Encrypted(r.ha)]);
    assert_eq!(r.ub.events, vec![Ev::Encrypted(r.hb)]);
    assert!(r.a.encrypted(r.ha) && r.b.encrypted(r.hb));
}

#[test]
fn a_wrong_or_missing_key_leaves_the_link_in_the_clear() {
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    let k = pair_and_store(&mut r);
    let mut wrong = k.ltk;
    wrong[0] ^= 1;
    r.a.encrypt(r.ha, wrong).unwrap();
    r.settle();
    assert_eq!(r.ua.events, vec![Ev::EncryptionFailed(r.ha, 0x06)]);
    assert!(!r.a.encrypted(r.ha) && !r.b.encrypted(r.hb));
    // The peripheral has no key for this peer.
    r.ub.store.clear();
    r.ub.take();
    r.cb.cmds.clear();
    r.a.encrypt(r.ha, k.ltk).unwrap();
    r.settle();
    assert!(r.cb.cmds.iter().any(|c| c.op == hci::OP_LE_LTK_NEGATIVE_REPLY));
    assert!(r.ub.events.iter().any(|e| matches!(e, Ev::EncryptionFailed(..))));
    // Only the central encrypts.
    assert_eq!(r.b.encrypt(r.hb, k.ltk), Err(azos_ble::host::SendError::NotAllowed));
}

#[test]
fn an_old_style_key_request_is_never_served() {
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    r.ub.store.push((PeerAddr { kind: 0, addr: ADDR_A }, [5; 16]));
    let mut p = r.hb.to_le_bytes().to_vec();
    p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    p.extend_from_slice(&[9, 0]);
    r.cb.le_event(hci::LE_LTK_REQUEST, &p);
    r.settle();
    assert!(r.cb.cmds.iter().any(|c| c.op == hci::OP_LE_LTK_NEGATIVE_REPLY));
    assert!(!r.cb.cmds.iter().any(|c| c.op == hci::OP_LE_LTK_REPLY), "legacy EDIV/Rand: no key from the store");
}

#[test]
fn the_pairing_state_dies_with_the_link() {
    let mut r = rig(cfg(NIO, false), cfg(NIO, false));
    r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
    step_host(&mut r.a, &mut r.ca, &mut r.ua, r.now);
    r.ca.process();
    r.ca.acl.clear();
    r.a.disconnect(r.ha, 0x13).unwrap();
    r.settle();
    r.ua.take();
    r.ub.take();
    r.connect();
    // The new link pairs from scratch.
    r.a.pair(r.ha, r.now, &mut r.ua).unwrap();
    r.settle();
    assert!(paired(&r).0.is_some() && paired(&r).1.is_some());
}

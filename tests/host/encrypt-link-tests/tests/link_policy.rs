// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! K-C5 — the encrypted-link policy and the AEAD session registry.
//!
//! These live in their own integration-test target, not in `src/lib.rs`,
//! because they assert on a **process-global** counter
//! (`azos_encrypt_link::aead_session_count`). Cargo gives every test
//! target its own process, so the handshake tests in `src/lib.rs` — which
//! create and drop `EncryptLink`s freely — cannot perturb the counts here.
//! Within this target the tests still run on parallel threads, so every one
//! of them takes `REGISTRY_LOCK` first.
//!
//! Run both ways; the suite asserts different things in each:
//!
//! ```text
//! cd tests/host/encrypt-link-tests
//! cargo test --release
//! cargo test --release --features enforced
//! ```

use std::sync::{Mutex, MutexGuard};

use azos_encrypt_link::{
    EncryptLink, HandshakeError, HandshakeState,
    aead_session_count, aead_session_established, envelope_frame_permitted,
    link_encrypt_enforced,
    CONFIRM_BYTES, HELLO_INIT_BYTES, HELLO_REPLY_BYTES,
    MODE_ENCRYPTED, LABEL_HELLO,
    RecordError, ENC_OVERHEAD,
};

/// Serialises every test in this file — see the module note.
static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

/// Take the lock, ignoring poisoning.
///
/// A test that fails while holding the lock poisons it, and `unwrap()` would
/// turn one real failure into N spurious ones and bury the cause.
fn serial() -> MutexGuard<'static, ()> {
    REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const PSK: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const ALICE_PRIV: [u8; 32] = [0xAA; 32];
const BOB_PRIV: [u8; 32] = [0xBB; 32];

/// Full handshake. `alice` is the crypto initiator (the brain), `bob` the
/// responder (the kernel) — see the role note in `encrypt-link/src/lib.rs`.
fn established_pair() -> (EncryptLink, EncryptLink) {
    let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
    let mut bob = EncryptLink::new(PSK, BOB_PRIV);

    let mut hello = [0u8; HELLO_INIT_BYTES];
    alice.start_initiator(&mut hello).unwrap();
    let mut reply = [0u8; HELLO_REPLY_BYTES];
    bob.handle_initiator_hello(&hello, &mut reply).unwrap();
    let mut confirm = [0u8; CONFIRM_BYTES];
    alice.handle_peer_hello(&reply, &mut confirm).unwrap();
    bob.handle_initiator_confirm(&confirm).unwrap();

    assert!(alice.is_established());
    assert!(bob.is_established());
    (alice, bob)
}

// ── The anti-trap test ─────────────────────────────────────────────────

/// The gate's *enabling condition* must be observable, in both states.
///
/// This tree has been burned exactly once by the opposite: the secure-boot
/// CI scenario passed without executing Ed25519 at all, because the public
/// key was `.gitignore`d, `build.rs` fell back to `[0u8; 32]`, and
/// verification short-circuited on the zero key — so it passed for
/// *different reasons on different machines*. A policy that can be silently
/// absent while the suite stays green is worse than no policy.
///
/// `link_encrypt_enforced()` is `cfg!`, so it cannot depend on disk state;
/// this test only has to prove the cargo feature is actually plumbed. If
/// someone renames the feature, forgets the forwarding entry in
/// `encrypt-link-tests/Cargo.toml`, or wires the kernel to the wrong name,
/// one of the two arms below fails loudly.
#[test]
fn policy_const_matches_the_feature_that_was_actually_enabled() {
    if cfg!(feature = "enforced") {
        assert!(
            link_encrypt_enforced(),
            "built with --features enforced but link_encrypt_enforced() is \
             false: the feature is not reaching azos_encrypt_link, so \
             every 'enforced' assertion below is vacuous"
        );
    } else {
        assert!(
            !link_encrypt_enforced(),
            "built WITHOUT --features enforced but link_encrypt_enforced() \
             is true: something is enabling the policy unconditionally"
        );
    }
}

// ── Registry lifecycle ─────────────────────────────────────────────────

#[test]
fn a_fresh_link_does_not_register() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);
    let link = EncryptLink::new(PSK, BOB_PRIV);
    assert_eq!(link.state(), HandshakeState::Init);
    assert_eq!(aead_session_count(), 0, "Init must not count as a session");
    drop(link);
    assert_eq!(aead_session_count(), 0);
}

#[test]
fn established_pair_registers_two_and_drops_back_to_zero() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);
    let (alice, bob) = established_pair();
    assert_eq!(aead_session_count(), 2);
    assert!(aead_session_established());
    drop(alice);
    assert_eq!(aead_session_count(), 1);
    drop(bob);
    assert_eq!(aead_session_count(), 0);
    assert!(!aead_session_established());
}

/// The kernel does `link = None` on every TCP disconnect. If the registry
/// did not come back down, an enforced build would keep emitting bare HMAC
/// envelopes after the brain went away — fail-open, the exact mode the
/// policy exists to forbid.
#[test]
fn reconnect_cycles_leave_the_registry_balanced() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);
    for _ in 0..16 {
        let (alice, bob) = established_pair();
        assert_eq!(aead_session_count(), 2);
        drop(alice);
        drop(bob);
        assert_eq!(aead_session_count(), 0);
    }
}

/// A half-open handshake (responder replied, initiator never confirmed) is
/// the state a kernel sits in when the brain vanishes mid-handshake. It must
/// not count: `AwaitConfirm` holds derived keys but no proof that the peer
/// knows the PSK.
#[test]
fn await_confirm_does_not_register() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);
    let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
    let mut bob = EncryptLink::new(PSK, BOB_PRIV);
    let mut hello = [0u8; HELLO_INIT_BYTES];
    alice.start_initiator(&mut hello).unwrap();
    let mut reply = [0u8; HELLO_REPLY_BYTES];
    bob.handle_initiator_hello(&hello, &mut reply).unwrap();
    assert_eq!(bob.state(), HandshakeState::AwaitConfirm);
    assert_eq!(aead_session_count(), 0);
    drop(alice);
    drop(bob);
    assert_eq!(aead_session_count(), 0);
}

// ── Hostile inputs must never register, and must never panic ───────────

#[test]
fn wrong_psk_never_registers() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);
    let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
    let mut bob = EncryptLink::new([0x77u8; 32], BOB_PRIV);
    let mut hello = [0u8; HELLO_INIT_BYTES];
    alice.start_initiator(&mut hello).unwrap();
    let mut reply = [0u8; HELLO_REPLY_BYTES];
    bob.handle_initiator_hello(&hello, &mut reply).unwrap();
    let mut confirm = [0u8; CONFIRM_BYTES];
    assert_eq!(
        alice.handle_peer_hello(&reply, &mut confirm),
        Err(HandshakeError::ProofMismatch)
    );
    assert!(alice.is_rejected());
    assert_eq!(aead_session_count(), 0);
    drop(alice);
    drop(bob);
    assert_eq!(aead_session_count(), 0);
}

#[test]
fn small_order_peer_key_never_registers() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);
    let mut bob = EncryptLink::new(PSK, BOB_PRIV);
    let mut hello = [0u8; HELLO_INIT_BYTES];
    hello[0] = MODE_ENCRYPTED;
    hello[1] = LABEL_HELLO;
    // hello[2..] stays all-zero: the canonical small-order point.
    let mut reply = [0u8; HELLO_REPLY_BYTES];
    assert_eq!(
        bob.handle_initiator_hello(&hello, &mut reply),
        Err(HandshakeError::BadPeerKey)
    );
    assert!(bob.is_rejected());
    assert_eq!(aead_session_count(), 0);
    drop(bob);
    assert_eq!(aead_session_count(), 0);
}

/// Every malformed shape an attacker can put on the socket, fed at every
/// step of the state machine. Nothing may register, and nothing may panic —
/// `panic = "abort"` in this tree means a reachable panic resets the board,
/// which on a robot is a physical-safety event triggered by a hostile packet.
#[test]
fn malformed_frames_never_register_and_never_panic() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);

    let shapes: [&[u8]; 10] = [
        &[],
        &[0x02],
        &[0x02, 0x48],
        &[0xFF; HELLO_INIT_BYTES],       // right length, wrong mode byte
        &[0x02; HELLO_INIT_BYTES],       // right mode, wrong label
        &[0x00; HELLO_REPLY_BYTES],
        &[0xAB; HELLO_REPLY_BYTES],
        &[0x02; CONFIRM_BYTES],
        &[0x02; HELLO_INIT_BYTES - 1],   // one byte short
        &[0x02; HELLO_REPLY_BYTES + 1],  // one byte long
    ];

    for shape in shapes {
        // Responder path, from Init.
        let mut bob = EncryptLink::new(PSK, BOB_PRIV);
        let mut reply = [0u8; HELLO_REPLY_BYTES];
        let _ = bob.handle_initiator_hello(shape, &mut reply);
        assert!(!bob.is_established(), "shape {:?} established a session", shape.len());

        // Responder path, from AwaitConfirm.
        let mut carol = EncryptLink::new(PSK, BOB_PRIV);
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut hello = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello).unwrap();
        let mut r2 = [0u8; HELLO_REPLY_BYTES];
        carol.handle_initiator_hello(&hello, &mut r2).unwrap();
        let _ = carol.handle_initiator_confirm(shape);
        assert!(!carol.is_established(), "shape {:?} confirmed", shape.len());

        // Initiator path, from AwaitPeerHello.
        let mut dave = EncryptLink::new(PSK, ALICE_PRIV);
        let mut h2 = [0u8; HELLO_INIT_BYTES];
        dave.start_initiator(&mut h2).unwrap();
        let mut c2 = [0u8; CONFIRM_BYTES];
        let _ = dave.handle_peer_hello(shape, &mut c2);
        assert!(!dave.is_established(), "shape {:?} accepted as reply", shape.len());

        assert_eq!(aead_session_count(), 0, "shape {:?} leaked a session", shape.len());
    }
    assert_eq!(aead_session_count(), 0);
}

/// Replaying the peer's CONFIRM at an already-established link must not
/// double-count. If it did, one decrement on drop would leave the registry
/// permanently non-zero and the gate permanently open.
#[test]
fn replayed_confirm_does_not_double_register() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);
    let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
    let mut bob = EncryptLink::new(PSK, BOB_PRIV);
    let mut hello = [0u8; HELLO_INIT_BYTES];
    alice.start_initiator(&mut hello).unwrap();
    let mut reply = [0u8; HELLO_REPLY_BYTES];
    bob.handle_initiator_hello(&hello, &mut reply).unwrap();
    let mut confirm = [0u8; CONFIRM_BYTES];
    alice.handle_peer_hello(&reply, &mut confirm).unwrap();
    bob.handle_initiator_confirm(&confirm).unwrap();
    assert_eq!(aead_session_count(), 2);

    for _ in 0..8 {
        assert_eq!(
            bob.handle_initiator_confirm(&confirm),
            Err(HandshakeError::BadState)
        );
    }
    assert_eq!(aead_session_count(), 2, "replayed CONFIRM inflated the registry");
    drop(alice);
    drop(bob);
    assert_eq!(aead_session_count(), 0);
}

// ── The gate itself ────────────────────────────────────────────────────

/// Both halves, in whichever policy state the suite was built for.
///
/// Policy OFF: the gate is a no-op and must never refuse a frame — that is
/// the compatibility guarantee for the default build.
///
/// Policy ON: with no AEAD session the gate refuses; with one, it permits;
/// after the session drops, it refuses again. That last transition is the
/// one that matters operationally — it is what happens when the brain
/// disconnects, and getting it wrong means the kernel resumes talking
/// HMAC-only to whoever reconnects.
#[test]
fn gate_tracks_policy_and_session() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);

    if link_encrypt_enforced() {
        assert!(
            !envelope_frame_permitted(),
            "enforced build permits an envelope frame with no AEAD session"
        );
        let (alice, bob) = established_pair();
        assert!(envelope_frame_permitted());
        drop(alice);
        assert!(envelope_frame_permitted(), "one live session still counts");
        drop(bob);
        assert!(
            !envelope_frame_permitted(),
            "gate stayed open after the last session was dropped — fail-open"
        );
    } else {
        assert!(envelope_frame_permitted(), "default build must not gate");
        let (alice, bob) = established_pair();
        assert!(envelope_frame_permitted());
        drop(alice);
        drop(bob);
        assert!(
            envelope_frame_permitted(),
            "default build started gating: this is a compatibility break"
        );
    }
    assert_eq!(aead_session_count(), 0);
}

/// Leaving `Established` through the record layer — a receive violation, a
/// REJECT sent, a REJECT received — must deregister at that moment, not at
/// drop. Otherwise an enforced build keeps the gate open for a session that
/// is already over, for as long as the caller holds the dead link.
#[test]
fn terminal_record_events_deregister_immediately() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);
    let (mut alice, mut bob) = established_pair();
    assert_eq!(aead_session_count(), 2);

    let mut wire = [0u8; 64];
    let n = alice.encrypt(b"CONFIG", &[1u8; 8], &mut wire);
    assert!(n > 0);
    wire[n - 1] ^= 0x01;
    let mut out = [0u8; 16];
    assert_eq!(bob.open_record(&wire[..n], &mut out), Err(RecordError::BadMac));
    assert_eq!(aead_session_count(), 1, "receive violation did not deregister");

    let mut rec = [0u8; ENC_OVERHEAD];
    assert_eq!(bob.seal_reject(&[2u8; 8], &mut rec), ENC_OVERHEAD);
    assert_eq!(aead_session_count(), 1, "sealing the REJECT deregistered twice");

    assert_eq!(alice.open_record(&rec, &mut out), Err(RecordError::PeerRejected));
    assert_eq!(aead_session_count(), 0, "received REJECT did not deregister");
    if link_encrypt_enforced() {
        assert!(!envelope_frame_permitted(), "gate open after both ends went terminal");
    }
    drop(alice);
    drop(bob);
    assert_eq!(aead_session_count(), 0);
}

#[test]
fn sealing_a_reject_from_established_deregisters() {
    let _g = serial();
    assert_eq!(aead_session_count(), 0);
    let (mut alice, bob) = established_pair();
    let mut rec = [0u8; ENC_OVERHEAD];
    assert_eq!(alice.seal_reject(&[3u8; 8], &mut rec), ENC_OVERHEAD);
    assert!(alice.is_rejected());
    assert_eq!(aead_session_count(), 1);
    drop(alice);
    assert_eq!(aead_session_count(), 1, "dropping a rejected link deregistered again");
    drop(bob);
    assert_eq!(aead_session_count(), 0);
}

/// Encrypt/decrypt still work after establishment, in both policy states.
/// The gate must not have made the happy path unreachable — "it refuses
/// everything" would pass a negative-only test suite just as happily as a
/// correct gate.
#[test]
fn established_session_still_round_trips() {
    let _g = serial();
    let (mut alice, bob) = established_pair();
    let msg = b"BR\x88\x00\x00\x00 emergency stop";
    let mut wire = [0u8; 256];
    let n = alice.encrypt(msg, &[7u8; 8], &mut wire);
    assert!(n > 0, "encrypt refused on an established link");
    let mut out = [0u8; 256];
    let (len, eaten) = bob.decrypt_consuming(&wire[..n], &mut out);
    assert_eq!(&out[..len], msg);
    assert_eq!(eaten, n);
    drop(alice);
    drop(bob);
    assert_eq!(aead_session_count(), 0);
}

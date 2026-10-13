// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cross-side handshake-state-machine pin tests (RFC-0019, task #40).
//!
//! Drives `azos_encrypt_link::EncryptLink` with deterministic
//! ephemeral private keys + a fixed PSK, verifies that the wire bytes
//! match a Python-computed reference vector byte-for-byte at every
//! step (HELLO_INIT, HELLO_REPLY, CONFIRM, the two proofs, the derived
//! ENC/MAC keys, and a sample encrypt frame).
//!
//! If any constant below drifts from the brain Python implementation,
//! these tests fail and the cross-side break is caught at CI time
//! instead of at first deployment.  The reference vector was generated
//! by `AzOSRobotBrain/secure_channel.py` with `_testing_eph_priv` and
//! `_testing_nonce_rand` injection points (those are TEST-ONLY hooks
//! on the brain side; production uses fresh os entropy).
//!
//! Run with:
//!   cd tests/host/encrypt-link-tests && cargo +stable test --release
//!
//! # The AEAD vectors come in a matched PAIR, one per direction
//!
//! Each side derives a separate (enc, mac) pair per direction —
//! `SHA-256(shared || "ENC"|"MAC" || "C2S"|"S2C")[0..16]` — with the
//! initiator (the brain) transmitting on `*_c2s` and the responder (the
//! kernel) on `*_s2c`. One sample frame therefore no longer serves both
//! tests, as it did under the old single-pair KDF:
//!
//! ```text
//!   SAMPLE_FRAME_C2S_HEX  Python initiator -> responder, MAC'd mac_c2s.
//!                         Pinned against what `alice` (initiator) EMITS.
//!   SAMPLE_FRAME_S2C_HEX  Python responder -> initiator, MAC'd mac_s2c.
//!                         Pinned against what `alice` (initiator) ACCEPTS.
//! ```
//!
//! That split is the direction property showing up in the wire bytes: the
//! two frames carry the same nonce and the same plaintext length, and
//! differ in every ciphertext and MAC byte. Feeding the C2S frame to the
//! decrypt test would fail at the MAC — which is the pin working, not a
//! vector to "fix" by swapping a role.
//!
//! # ⚠ NEVER derive these expectations from the Rust side
//!
//! These are *cross-implementation* pins. Their whole value is that the
//! bytes came from the other implementation; recomputing them with
//! `azos_encrypt_link` would make each assertion a tautology that
//! passes however far the two sides drift. A failing pin is a finding to
//! investigate, never a constant to adjust until the test goes green.
//!
//! **To regenerate** (only for a deliberate wire-format change made on
//! BOTH sides): drive `AzOSRobotBrain/secure_channel.py::SecureChannel`
//! through a full handshake with `_testing_eph_priv = 0xAA*32` (initiator)
//! and `0xBB*32` (responder), `PSK = bytes(range(32))`, then call
//! `encrypt(..., _testing_nonce_rand = 0x01..08)` on the initiator for the
//! C2S frame and on the responder for the S2C frame, and paste the hex.

#[cfg(test)]
mod tests {
    use azos_encrypt_link::{
        EncryptLink, HandshakeError, HandshakeState,
        MODE_ENCRYPTED, LABEL_HELLO, LABEL_CONFIRM,
        HELLO_INIT_BYTES, HELLO_REPLY_BYTES, CONFIRM_BYTES,
        ENC_OVERHEAD,
        EPH_PUB_BYTES, PROOF_BYTES,
        proof_responder, proof_initiator,
        x25519_pubkey,
    };

    // ── Reference vector (Python brain, deterministic) ─────────────────

    const PSK: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ];
    const ALICE_PRIV: [u8; 32] = [0xAA; 32];
    const BOB_PRIV:   [u8; 32] = [0xBB; 32];

    const ALICE_PUB_HEX: &str =
        "14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070";
    const BOB_PUB_HEX:   &str =
        "6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b";

    const HELLO_INIT_HEX:  &str =
        "024814ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070";
    const HELLO_REPLY_HEX: &str = concat!(
        "0248",
        "6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b",
        "babc57b9733e745434f1f9e41453755251175dad5d1e86c29f652cbc47130868",
    );
    const CONFIRM_HEX:     &str = concat!(
        "0243",
        "6100b3c5551d98d2ee6cabbc629805f0e753529e108a2086c0c6dccd57842ca7",
    );

    const PROOF_R_HEX: &str =
        "babc57b9733e745434f1f9e41453755251175dad5d1e86c29f652cbc47130868";
    const PROOF_I_HEX: &str =
        "6100b3c5551d98d2ee6cabbc629805f0e753529e108a2086c0c6dccd57842ca7";

    // Bulk encrypt vectors, both with nonce_rand = 0x01..08 and counter = 0.
    // Two frames, because there are now two key pairs — see the module
    // header. Both plaintexts are 33 bytes so the only difference on the
    // wire past the header is the one the keys make.

    /// alice (initiator, = the brain) → bob. Encrypted under `enc_c2s`.
    const SAMPLE_PLAINTEXT: &[u8] = b"alice->bob via RFC-0019 handshake";
    const SAMPLE_FRAME_C2S_HEX: &str = concat!(
        "0102030405060708",        // 8B nonce_rand
        "00000000",                // 4B AES-CTR counter LE (= 0)
        "2100",                    // 2B payload length LE (= 33)
        "e31802121d0ecc460b03a7e52132a7f448360d13d7228a34b4e0332e9a80fb3148",
        "600715bb19c051ccbd3ca8e14aee4c318b36099af62f8f8abbc38a4f7042396c",
    );

    /// bob (responder, = the kernel) → alice. Encrypted under `enc_s2c`.
    const SAMPLE_PLAINTEXT_S2C: &[u8] = b"bob->alice via RFC-0019 handshake";
    const SAMPLE_FRAME_S2C_HEX: &str = concat!(
        "0102030405060708",        // 8B nonce_rand
        "00000000",                // 4B AES-CTR counter LE (= 0)
        "2100",                    // 2B payload length LE (= 33)
        "0372be9437d421ed072a5529e39e988641169fe870f3327135bfc7621cbbd0c24f",
        "643d4e87f8a6d6ce5d752b1e665759e9fc09f4884ac86ad6e19739a956264f16",
    );

    // ── Helpers ────────────────────────────────────────────────────────

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
            .collect()
    }

    fn hex_arr32(s: &str) -> [u8; 32] {
        let v = hex(s);
        assert_eq!(v.len(), 32);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    // ── Sanity: X25519 pubkeys match Python ────────────────────────────

    #[test]
    fn x25519_pubkeys_match_python() {
        let alice_pub = x25519_pubkey(&ALICE_PRIV);
        let bob_pub   = x25519_pubkey(&BOB_PRIV);
        assert_eq!(alice_pub, hex_arr32(ALICE_PUB_HEX));
        assert_eq!(bob_pub,   hex_arr32(BOB_PUB_HEX));
    }

    // ── Pure proof functions match Python byte-for-byte ────────────────

    #[test]
    fn proof_responder_matches_python_vector() {
        let alice_pub = hex_arr32(ALICE_PUB_HEX);
        let bob_pub   = hex_arr32(BOB_PUB_HEX);
        let got = proof_responder(&PSK, &alice_pub, &bob_pub);
        let exp = hex(PROOF_R_HEX);
        assert_eq!(&got[..], &exp[..],
            "proof_responder drift: kernel != Python");
    }

    #[test]
    fn proof_initiator_matches_python_vector() {
        let alice_pub = hex_arr32(ALICE_PUB_HEX);
        let bob_pub   = hex_arr32(BOB_PUB_HEX);
        let got = proof_initiator(&PSK, &bob_pub, &alice_pub);
        let exp = hex(PROOF_I_HEX);
        assert_eq!(&got[..], &exp[..],
            "proof_initiator drift: kernel != Python");
    }

    // ── Wire byte pins (state machine output equals Python brain) ──────

    #[test]
    fn initiator_hello_bytes_match_python() {
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut out = [0u8; HELLO_INIT_BYTES];
        let n = alice.start_initiator(&mut out).unwrap();
        assert_eq!(n, HELLO_INIT_BYTES);
        assert_eq!(&out[..], &hex(HELLO_INIT_HEX)[..],
            "initiator HELLO bytes drift from Python");
        assert_eq!(alice.state(), HandshakeState::AwaitPeerHello);
        assert_eq!(out[0], MODE_ENCRYPTED);
        assert_eq!(out[1], LABEL_HELLO);
    }

    #[test]
    fn responder_reply_bytes_match_python() {
        let mut bob = EncryptLink::new(PSK, BOB_PRIV);
        let init_hello = hex(HELLO_INIT_HEX);
        let mut out = [0u8; HELLO_REPLY_BYTES];
        let n = bob.handle_initiator_hello(&init_hello, &mut out).unwrap();
        assert_eq!(n, HELLO_REPLY_BYTES);
        assert_eq!(&out[..], &hex(HELLO_REPLY_HEX)[..],
            "responder HELLO+proof bytes drift from Python");
        assert_eq!(bob.state(), HandshakeState::AwaitConfirm);
    }

    #[test]
    fn initiator_confirm_bytes_match_python() {
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut hello_out = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello_out).unwrap();

        let reply = hex(HELLO_REPLY_HEX);
        let mut confirm = [0u8; CONFIRM_BYTES];
        let n = alice.handle_peer_hello(&reply, &mut confirm).unwrap();
        assert_eq!(n, CONFIRM_BYTES);
        assert_eq!(&confirm[..], &hex(CONFIRM_HEX)[..],
            "initiator CONFIRM bytes drift from Python");
        assert!(alice.is_established());
        assert_eq!(confirm[0], MODE_ENCRYPTED);
        assert_eq!(confirm[1], LABEL_CONFIRM);
    }

    // ── Full kernel ↔ kernel handshake (sanity: both halves drive ──────
    // ── correctly when isolated from the brain side) ───────────────────

    #[test]
    fn full_handshake_both_kernel_halves_reach_established() {
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut bob   = EncryptLink::new(PSK, BOB_PRIV);

        let mut hello_init  = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello_init).unwrap();

        let mut hello_reply = [0u8; HELLO_REPLY_BYTES];
        bob.handle_initiator_hello(&hello_init, &mut hello_reply).unwrap();

        let mut confirm = [0u8; CONFIRM_BYTES];
        alice.handle_peer_hello(&hello_reply, &mut confirm).unwrap();
        bob.handle_initiator_confirm(&confirm).unwrap();

        assert!(alice.is_established());
        assert!(bob.is_established());
    }

    // ── Failure paths (rejections must be terminal) ────────────────────

    #[test]
    fn responder_rejects_bad_initiator_proof() {
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut bob   = EncryptLink::new(PSK, BOB_PRIV);

        let mut hello_init  = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello_init).unwrap();
        let mut hello_reply = [0u8; HELLO_REPLY_BYTES];
        bob.handle_initiator_hello(&hello_init, &mut hello_reply).unwrap();

        let mut confirm = [0u8; CONFIRM_BYTES];
        alice.handle_peer_hello(&hello_reply, &mut confirm).unwrap();
        // Flip a single bit in alice's proof — bob must reject.
        confirm[5] ^= 0x01;
        let res = bob.handle_initiator_confirm(&confirm);
        assert!(res.is_err());
        assert!(bob.is_rejected());
    }

    #[test]
    fn initiator_rejects_bad_responder_proof() {
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut bob   = EncryptLink::new(PSK, BOB_PRIV);

        let mut hello_init  = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello_init).unwrap();
        let mut hello_reply = [0u8; HELLO_REPLY_BYTES];
        bob.handle_initiator_hello(&hello_init, &mut hello_reply).unwrap();
        // Flip a bit in the responder's proof field.
        hello_reply[2 + EPH_PUB_BYTES + 5] ^= 0x80;

        let mut confirm = [0u8; CONFIRM_BYTES];
        let res = alice.handle_peer_hello(&hello_reply, &mut confirm);
        assert!(res.is_err());
        assert!(alice.is_rejected());
    }

    #[test]
    fn bad_psk_on_either_side_rejects() {
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let bad_psk = {
            let mut p = PSK;
            for b in p.iter_mut() { *b ^= 0xFF; }
            p
        };
        let mut bob = EncryptLink::new(bad_psk, BOB_PRIV);

        let mut hello_init  = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello_init).unwrap();
        let mut hello_reply = [0u8; HELLO_REPLY_BYTES];
        bob.handle_initiator_hello(&hello_init, &mut hello_reply).unwrap();
        // Bob's proof_r is computed with the WRONG psk → alice rejects.
        let mut confirm = [0u8; CONFIRM_BYTES];
        let res = alice.handle_peer_hello(&hello_reply, &mut confirm);
        assert!(res.is_err());
        assert!(alice.is_rejected());
    }

    // ── AEAD frame produced by Python → kernel decrypts to plaintext ───

    #[test]
    fn alice_kernel_decrypts_python_encrypted_frame() {
        // Drive alice (kernel-as-initiator) to Established with the
        // Python reference handshake.
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut hello_init  = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello_init).unwrap();
        let mut confirm = [0u8; CONFIRM_BYTES];
        let reply = hex(HELLO_REPLY_HEX);
        alice.handle_peer_hello(&reply, &mut confirm).unwrap();
        assert!(alice.is_established());

        // alice is the INITIATOR, so it receives on S2C: the only frame it
        // may accept is one the Python RESPONDER produced. Verifying this
        // one proves alice bound rx to the S2C pair; the reflection check
        // below proves it will not also accept its own C2S frames.
        let frame = hex(SAMPLE_FRAME_S2C_HEX);
        let mut out = vec![0u8; SAMPLE_PLAINTEXT_S2C.len()];
        let n = alice.decrypt(&frame, &mut out);
        assert_eq!(n, SAMPLE_PLAINTEXT_S2C.len(),
            "kernel rejected Python-produced S2C AEAD frame");
        assert_eq!(&out, SAMPLE_PLAINTEXT_S2C,
            "decrypted plaintext drift");
    }

    #[test]
    fn alice_kernel_rejects_the_python_frame_from_its_own_direction() {
        // The other half of the pin above, and the one that makes it a
        // DIRECTION pin rather than a key pin: the C2S frame is a valid
        // frame under a key alice holds — its tx pair — and must still be
        // refused inbound. Under the old shared-key KDF this decrypted.
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut hello_init  = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello_init).unwrap();
        let mut confirm = [0u8; CONFIRM_BYTES];
        let reply = hex(HELLO_REPLY_HEX);
        alice.handle_peer_hello(&reply, &mut confirm).unwrap();
        assert!(alice.is_established());

        let frame = hex(SAMPLE_FRAME_C2S_HEX);
        let mut out = vec![0u8; SAMPLE_PLAINTEXT.len()];
        assert_eq!(alice.decrypt(&frame, &mut out), 0,
            "initiator accepted a C2S frame inbound — direction binding is \
             not in effect on the wire, only in the local key names");
    }

    // ── Kernel encrypt with same nonce_rand → byte-equal to Python ─────

    #[test]
    fn alice_kernel_encrypt_matches_python_frame() {
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut hello_init  = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello_init).unwrap();
        let mut confirm = [0u8; CONFIRM_BYTES];
        let reply = hex(HELLO_REPLY_HEX);
        alice.handle_peer_hello(&reply, &mut confirm).unwrap();
        assert!(alice.is_established());

        let nonce_rand = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut out = vec![0u8; SAMPLE_PLAINTEXT.len() + 12 + 2 + 32];
        let n = alice.encrypt(SAMPLE_PLAINTEXT, &nonce_rand, &mut out);
        out.truncate(n);

        // alice is the initiator, so it TRANSMITS on C2S.
        let expected = hex(SAMPLE_FRAME_C2S_HEX);
        assert_eq!(out, expected,
            "kernel encrypt output drift from Python at same (key, nonce)");

        // And the two directions must not have produced the same bytes: if
        // they had, the direction label would not be reaching the KDF.
        assert_ne!(expected, hex(SAMPLE_FRAME_S2C_HEX),
            "C2S and S2C frames are identical — directions collapsed");
    }

    // ── Direction binding / coalescing / small-order (self-contained) ──
    //
    // These do not depend on any Python-generated vector: they exercise the
    // same properties purely against this side, so a failure here localises
    // the drift to the kernel rather than to the cross-side contract.

    /// Drive a full alice(initiator) ↔ bob(responder) handshake to
    /// Established. Mirrors deployment: brain = initiator, kernel = bob.
    fn established_pair() -> (EncryptLink, EncryptLink) {
        let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
        let mut bob = EncryptLink::new(PSK, BOB_PRIV);
        let mut hello_init = [0u8; HELLO_INIT_BYTES];
        alice.start_initiator(&mut hello_init).unwrap();
        let mut hello_reply = [0u8; HELLO_REPLY_BYTES];
        bob.handle_initiator_hello(&hello_init, &mut hello_reply).unwrap();
        let mut confirm = [0u8; CONFIRM_BYTES];
        alice.handle_peer_hello(&hello_reply, &mut confirm).unwrap();
        bob.handle_initiator_confirm(&confirm).unwrap();
        assert!(alice.is_established() && bob.is_established());
        (alice, bob)
    }

    #[test]
    fn each_direction_decrypts_only_the_other_sides_frames() {
        let (mut alice, mut bob) = established_pair();

        // brain → kernel
        let up: &[u8] = b"ESTOP now";
        let mut f = vec![0u8; up.len() + ENC_OVERHEAD];
        let n = alice.encrypt(up, &[0x01u8; 8], &mut f);
        assert!(n > 0);
        f.truncate(n);
        let mut out = vec![0u8; 64];
        assert_eq!(bob.decrypt(&f, &mut out), up.len());
        assert_eq!(&out[..up.len()], up);

        // ...and the SENDER must not be able to read its own frame back.
        // Pre-fix this succeeded: one key pair served both directions, so
        // an echoed TCP segment authenticated as genuine peer traffic.
        assert_eq!(alice.decrypt(&f, &mut out), 0,
                   "initiator accepted a reflection of its own frame");

        // kernel → brain, same property in the other direction.
        let down: &[u8] = b"sensor frame";
        let mut g = vec![0u8; down.len() + ENC_OVERHEAD];
        let m = bob.encrypt(down, &[0x02u8; 8], &mut g);
        assert!(m > 0);
        g.truncate(m);
        assert_eq!(alice.decrypt(&g, &mut out), down.len());
        assert_eq!(bob.decrypt(&g, &mut out), 0,
                   "responder accepted a reflection of its own frame");
    }

    #[test]
    fn coalesced_estop_is_not_dropped() {
        // The safety-critical case: the brain writes CONFIG then ESTOP with
        // two send() calls; TCP delivers both in one recv(). The old
        // decrypt() returned CONFIG and discarded ESTOP with no error and
        // no log, and the brain never retransmits ESTOP.
        let (mut alice, bob) = established_pair();
        let msgs: [&[u8]; 2] = [b"CONFIG maxspeed", b"ESTOP"];
        let mut stream: Vec<u8> = Vec::new();
        for m in msgs.iter() {
            let mut f = vec![0u8; m.len() + ENC_OVERHEAD];
            let n = alice.encrypt(m, &[0x05u8; 8], &mut f);
            assert!(n > 0);
            stream.extend_from_slice(&f[..n]);
        }

        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut off = 0usize;
        while off < stream.len() {
            let mut out = vec![0u8; 64];
            let (n, used) = bob.decrypt_consuming(&stream[off..], &mut out);
            if used == 0 { break; }
            out.truncate(n);
            seen.push(out);
            off += used;
        }
        assert_eq!(seen.len(), 2, "coalesced ESTOP was lost");
        assert_eq!(seen[1].as_slice(), msgs[1]);
    }

    #[test]
    fn responder_rejects_small_order_hello_before_proof_exchange() {
        // handle_initiator_hello derives the shared secret from a peer key
        // that has NOT been authenticated yet. A small-order point pins the
        // shared secret to 32 zero bytes for both sides. The rejection must
        // be terminal — a channel left in AwaitConfirm here would be one
        // holding all-zero session keys.
        let mut bob = EncryptLink::new(PSK, BOB_PRIV);
        let mut hello = [0u8; HELLO_INIT_BYTES];
        hello[0] = MODE_ENCRYPTED;
        hello[1] = LABEL_HELLO;
        // hello[2..] stays all zeros = the canonical small-order point.
        let mut reply = [0u8; HELLO_REPLY_BYTES];
        let res = bob.handle_initiator_hello(&hello, &mut reply);
        assert_eq!(res, Err(HandshakeError::BadPeerKey));
        assert!(bob.is_rejected(),
                "small-order HELLO left the channel non-terminal");
        assert!(!bob.is_established());
    }

    // ── Wire-format constants pin ──────────────────────────────────────

    #[test]
    fn wire_constants_match_brain_python() {
        assert_eq!(MODE_ENCRYPTED, 0x02);
        assert_eq!(LABEL_HELLO,    0x48);
        assert_eq!(LABEL_CONFIRM,  0x43);
        assert_eq!(EPH_PUB_BYTES,  32);
        assert_eq!(PROOF_BYTES,    32);
        assert_eq!(HELLO_INIT_BYTES,  2 + 32);
        assert_eq!(HELLO_REPLY_BYTES, 2 + 32 + 32);
        assert_eq!(CONFIRM_BYTES,     2 + 32);
    }

    /// `rekey_interval_secs` (wave 10, ENT2): a configured interval can only
    /// shorten the RFC-0019 hour, never lengthen it, and never goes under
    /// the 5 s floor.
    #[test]
    fn a_configured_rekey_interval_only_shortens() {
        use azos_encrypt_link::{
            rekey_interval_secs, REKEY_INTERVAL_MIN_SECS, REKEY_INTERVAL_SECS,
        };
        assert_eq!(REKEY_INTERVAL_SECS, 3600);
        assert_eq!(rekey_interval_secs(None), REKEY_INTERVAL_SECS);
        assert_eq!(rekey_interval_secs(Some(10)), 10);
        assert_eq!(rekey_interval_secs(Some(3599)), 3599);
        assert_eq!(rekey_interval_secs(Some(3600)), 3600);
        for longer in [3601, 7200, 65_535, u64::MAX] {
            assert_eq!(rekey_interval_secs(Some(longer)), REKEY_INTERVAL_SECS,
                       "{longer} s must not lengthen the interval");
        }
        for shorter in [0, 1, 4, 5] {
            assert_eq!(rekey_interval_secs(Some(shorter)), REKEY_INTERVAL_MIN_SECS,
                       "{shorter} s must clamp to the floor");
        }
    }
}

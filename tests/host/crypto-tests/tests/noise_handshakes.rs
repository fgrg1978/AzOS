// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Noise_IK / Noise_XX _25519_ChaChaPoly_SHA256.
//!
//! No Noise test-vector file is vendored (no downloads), so the vectors
//! below come from an independent implementation of the Noise spec written
//! in Python on pyca/cryptography primitives (HMAC-SHA256, ChaCha20-Poly1305,
//! X25519 from OpenSSL) with fixed static and ephemeral keys. They pin every
//! wire byte of every handshake message, the final handshake hash and the
//! two transport keys. Round-trip, transcript-hash consistency, tamper and
//! state-machine tests then cover what vectors cannot.

mod common;
use azos_crypto::noise::*;
use azos_crypto::x25519::x25519_pubkey;
use common::{hex, unhex, Rng};

const SI: [u8; 32] = [0x11; 32];
const SR: [u8; 32] = [0x22; 32];
const EI: [u8; 32] = [0x33; 32];
const ER: [u8; 32] = [0x44; 32];
const PROLOGUE: &[u8] = b"azos-test-prologue";

const IK_H: &str = "816e4ebe557cb1671f451ccb4d8903acd1f53afa1f02198c8f8d9a8fab5f4c69";
const IK_MSGS: &[&str] = &[
    "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14180209d22e6c95bf3b198efd0e3af2c121a6a3464ded18bd60a996a63e55b86906c3e40bcac34dd41e4f5e92018861ce6490928f5f88674847f4b900e882117299e33adb8d010cc0d90544ee84de31927eccb0",
    "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b2ec8a31b41fc3d83f2d0383f4c517933aeb41d25",
];
/// (i2r n=0, i2r n=1, r2i n=0) sealed with ad "ad": ciphertext || tag.
const IK_TRANSPORT: [&str; 3] = ["dfc329e2577c8bc8acfda71c78cfd6e61d28def8bd", "67ec578c899eaa49d02a12c1367df14c4df908ee92", "ad6d09e16803b9d6e1de8bcff9c0182ff5dbdc7fbf"];
/// REKEY(c1) from the reference: ENCRYPT(c1, 2^64-1, "", 32 zeros)[..32].
const IK_C1_REKEYED: &str = "7b4693c298ac347c5c1fd90a943506f1fa0317af62c8c11f56fbd89c7d398b00";
const XX_H: &str = "d2802ece6dcb69c89ccb64fa31349796315c572c9234ba158517c0998dd4807c";
const XX_MSGS: &[&str] = &[
    "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b1468656c6c6f",
    "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6bfcadb15080d9fd0434a18565751d3b6022bec571f33b6212486a1bffa54d1a1e285cbb44e7c744f18200da4a5b870145a9acabd8be8a7ce7077b38f16ebd9369f940466f7814",
    "a7ea7dd47dddbcfcd736b91b174c6107b2ad26c161965a119a7b644e0c6b3d06f089b04f2601563c6f1bed63ab4375be05d22753a3fa39f4c98232e63c592b9a6c01f2a3c2",
];
/// (i2r n=0, i2r n=1, r2i n=0) sealed with ad "ad": ciphertext || tag.
const XX_TRANSPORT: [&str; 3] = ["bb02a0d6a5131f6d8557c6a3d8d2254c63533cd371", "554f58619934bb2325970656fee22e8086ee24ad1a", "66d2913d84e19521a52ae87c0815f980bbba43e2c5"];

fn pair(p: Pattern) -> (HandshakeState, HandshakeState) {
    let rs = x25519_pubkey(&SR);
    let a = match p {
        Pattern::Ik => HandshakeState::initiator(p, &SI, Some(&rs), PROLOGUE),
        Pattern::Xx => HandshakeState::initiator(p, &SI, None, PROLOGUE),
    }
    .unwrap();
    (a, HandshakeState::responder(p, &SR, PROLOGUE).unwrap())
}

/// Run a whole handshake with the fixed ephemerals; returns the wire
/// messages and both transports. Asserts the transcript hashes agree after
/// every message.
fn run(p: Pattern, payloads: &[&[u8]]) -> (Vec<Vec<u8>>, Transport, Transport) {
    let (mut a, mut b) = pair(p);
    let mut wire = Vec::new();
    for (i, pl) in payloads.iter().enumerate() {
        let (w, r, eph) = if i % 2 == 0 { (&mut a, &mut b, &EI) } else { (&mut b, &mut a, &ER) };
        let mut buf = [0u8; 512];
        let n = w.write_message(eph, pl, &mut buf).unwrap();
        let mut got = [0u8; 512];
        let m = r.read_message(&buf[..n], &mut got).unwrap();
        assert_eq!(&got[..m], *pl, "payload {i}");
        assert_eq!(a.handshake_hash(), b.handshake_hash(), "transcript hash after message {i}");
        wire.push(buf[..n].to_vec());
    }
    assert!(a.is_finished() && b.is_finished());
    (wire, a.finish().unwrap(), b.finish().unwrap())
}

#[test]
fn transport_round_trip_many_messages_both_directions() {
    for p in [Pattern::Ik, Pattern::Xx] {
        let payloads: &[&[u8]] = if p == Pattern::Ik { &[b"a", b"b"] } else { &[b"a", b"b", b"c"] };
        let (_, mut a, mut b) = run(p, payloads);
        let mut rng = Rng(0x1234_5678_9abc_def1);
        for i in 0..300u32 {
            let len = (rng.next() % 1500) as usize;
            let msg: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let (s, r) = if i % 3 == 0 { (&mut b, &mut a) } else { (&mut a, &mut b) };
            let mut buf = msg.clone();
            let ad = i.to_le_bytes();
            let tag = s.send.encrypt(&ad, &mut buf).unwrap();
            if len > 0 {
                assert_ne!(buf, msg);
            }
            r.recv.decrypt(&ad, &mut buf, &tag).unwrap();
            assert_eq!(buf, msg);
        }
        assert_eq!(a.send.nonce() + b.send.nonce(), 300);
    }
}

#[test]
fn forged_transport_packet_does_not_advance_the_counter() {
    let (_, mut a, mut b) = run(Pattern::Xx, &[b"a", b"b", b"c"]);
    let mut m = *b"payload!";
    let tag = a.send.encrypt(b"", &mut m).unwrap();
    let mut bad = m;
    bad[0] ^= 1;
    assert_eq!(b.recv.decrypt(b"", &mut bad, &tag), Err(Error::Decrypt));
    assert_eq!(b.recv.nonce(), 0);
    b.recv.decrypt(b"", &mut m, &tag).unwrap();
    assert_eq!(b.recv.nonce(), 1);
    // Replay of the same packet fails: nonce moved on.
    let mut again = *b"payload!";
    let _ = a.send.encrypt(b"", &mut again).unwrap();
    assert!(b.recv.decrypt(b"", &mut m, &tag).is_err());
}

#[test]
fn transport_message_size_limit() {
    let (_, mut a, _) = run(Pattern::Ik, &[b"a", b"b"]);
    let mut big = vec![0u8; 65535 - 16 + 1];
    assert_eq!(a.send.encrypt(b"", &mut big), Err(Error::MessageTooLong));
    let mut max = vec![0u8; 65535 - 16];
    assert!(a.send.encrypt(b"", &mut max).is_ok());
}

#[test]
fn wrong_responder_static_fails_ik() {
    let wrong = x25519_pubkey(&[0x99; 32]);
    let mut a = HandshakeState::initiator(Pattern::Ik, &SI, Some(&wrong), PROLOGUE).unwrap();
    let mut b = HandshakeState::responder(Pattern::Ik, &SR, PROLOGUE).unwrap();
    let mut buf = [0u8; 512];
    let n = a.write_message(&EI, b"x", &mut buf).unwrap();
    let mut out = [0u8; 64];
    assert_eq!(b.read_message(&buf[..n], &mut out), Err(Error::Decrypt));
}

#[test]
fn prologue_mismatch_fails() {
    for p in [Pattern::Ik, Pattern::Xx] {
        let rs = x25519_pubkey(&SR);
        let mut a = HandshakeState::initiator(p, &SI, if p == Pattern::Ik { Some(&rs) } else { None }, b"one").unwrap();
        let mut b = HandshakeState::responder(p, &SR, b"two").unwrap();
        let mut buf = [0u8; 512];
        let n = a.write_message(&EI, b"x", &mut buf).unwrap();
        let mut out = [0u8; 64];
        let r1 = b.read_message(&buf[..n], &mut out);
        if p == Pattern::Ik {
            assert_eq!(r1, Err(Error::Decrypt));
        } else {
            // XX message 1 is unauthenticated; the divergence shows at once
            // in the hash and kills message 2's AEAD.
            assert!(r1.is_ok());
            let n = b.write_message(&ER, b"y", &mut buf).unwrap();
            assert_eq!(a.read_message(&buf[..n], &mut out), Err(Error::Decrypt));
        }
    }
}

#[test]
fn low_order_peer_ephemeral_is_rejected() {
    // An all-zero ephemeral as message 1 of XX: the ee DH is all-zero.
    let mut b = HandshakeState::responder(Pattern::Xx, &SR, PROLOGUE).unwrap();
    let mut out = [0u8; 64];
    let mut msg = [0u8; 32];
    assert_eq!(b.read_message(&msg, &mut out), Ok(0));
    let mut buf = [0u8; 512];
    assert_eq!(b.write_message(&ER, b"", &mut buf), Err(Error::BadDh));
    // Poisoned afterwards.
    assert_eq!(b.write_message(&ER, b"", &mut buf), Err(Error::WrongState));
    // Order-8 point (u=1) is the same story for IK's es.
    let rs = x25519_pubkey(&SR);
    let mut a = HandshakeState::initiator(Pattern::Ik, &SI, Some(&rs), PROLOGUE).unwrap();
    let _ = a.write_message(&EI, b"", &mut buf).unwrap();
    msg[0] = 1;
    let mut reply = vec![0u8; 0];
    reply.extend_from_slice(&msg);
    reply.extend_from_slice(&[0u8; 16]);
    assert_eq!(a.read_message(&reply, &mut out), Err(Error::BadDh));
}

#[test]
fn state_machine_rejects_out_of_turn_and_early_finish() {
    let (mut a, mut b) = pair(Pattern::Xx);
    let mut buf = [0u8; 512];
    let mut out = [0u8; 64];
    // Responder cannot write first; initiator cannot read first.
    assert_eq!(b.write_message(&ER, b"", &mut buf), Err(Error::WrongState));
    assert_eq!(a.read_message(&[0u8; 48], &mut out), Err(Error::WrongState));
    assert!(a.is_my_turn() && !b.is_my_turn());
    let n = a.write_message(&EI, b"", &mut buf).unwrap();
    assert!(!a.is_my_turn());
    assert_eq!(a.write_message(&EI, b"", &mut buf), Err(Error::WrongState));
    // finish() before the pattern completes is refused.
    assert!(matches!(a.finish(), Err(Error::WrongState)));
    b.read_message(&buf[..n], &mut out).unwrap();
    assert!(matches!(b.finish(), Err(Error::WrongState)));
}

#[test]
fn setup_rules_for_remote_static() {
    let rs = x25519_pubkey(&SR);
    assert!(HandshakeState::initiator(Pattern::Ik, &SI, None, b"").is_err());
    assert!(HandshakeState::initiator(Pattern::Xx, &SI, Some(&rs), b"").is_err());
}

#[test]
fn identity_hiding_ik_and_learned_statics() {
    let (mut a, mut b) = pair(Pattern::Xx);
    assert!(a.remote_static().is_none() && b.remote_static().is_none());
    let mut buf = [0u8; 512];
    let mut out = [0u8; 64];
    let n = a.write_message(&EI, b"", &mut buf).unwrap();
    b.read_message(&buf[..n], &mut out).unwrap();
    let n = b.write_message(&ER, b"", &mut buf).unwrap();
    a.read_message(&buf[..n], &mut out).unwrap();
    assert_eq!(a.remote_static(), Some(&x25519_pubkey(&SR)));
    assert!(b.remote_static().is_none());
    let n = a.write_message(&EI, b"", &mut buf).unwrap();
    b.read_message(&buf[..n], &mut out).unwrap();
    assert_eq!(b.remote_static(), Some(&x25519_pubkey(&SI)));
    // The static key never appears in clear on the wire.
    let (wire, _, _) = run(Pattern::Xx, &[b"", b"", b""]);
    let spub = x25519_pubkey(&SI);
    assert!(wire.iter().all(|m| !m.windows(32).any(|w| w == spub)));
    let (wire, _, _) = run(Pattern::Ik, &[b"", b""]);
    assert!(wire.iter().all(|m| !m.windows(32).any(|w| w == spub)));
}

fn open_vec(rx: &mut CipherState, ad: &[u8], hexv: &str) -> Vec<u8> {
    let mut v = unhex(hexv);
    let (c, tag) = v.split_at_mut(hexv.len() / 2 - 16);
    rx.decrypt(ad, c, (&*tag).try_into().unwrap()).unwrap();
    c.to_vec()
}

fn seal_vec(tx: &mut CipherState, ad: &[u8], pt: &[u8]) -> String {
    let mut m = pt.to_vec();
    let tag = tx.encrypt(ad, &mut m).unwrap();
    m.extend_from_slice(&tag);
    hex(&m)
}

/// Wire bytes, transcript hash and both transport keys against the
/// reference. The keys are pinned through transport ciphertext: the
/// reference sealed known plaintexts under c1 (initiator to responder) and
/// c2 (responder to initiator), and we must produce the same bytes.
fn check_vectors(p: Pattern, payloads: &[&[u8]], h: &str, msgs: &[&str], transport: &[&str; 3]) {
    let (wire, mut ti, mut tr) = run(p, payloads);
    assert_eq!(wire.len(), msgs.len());
    for (i, (w, m)) in wire.iter().zip(msgs).enumerate() {
        assert_eq!(hex(w), *m, "wire message {i}");
    }
    assert_eq!(hex(&ti.hash), h);
    assert_eq!(ti.hash, tr.hash);
    assert_eq!(ti.remote_static, x25519_pubkey(&SR));
    assert_eq!(tr.remote_static, x25519_pubkey(&SI));
    assert_eq!(seal_vec(&mut ti.send, b"ad", b"i2r-0"), transport[0]);
    assert_eq!(seal_vec(&mut ti.send, b"ad", b"i2r-1"), transport[1]);
    assert_eq!(open_vec(&mut tr.recv, b"ad", transport[0]), b"i2r-0");
    assert_eq!(open_vec(&mut tr.recv, b"ad", transport[1]), b"i2r-1");
    assert_eq!(seal_vec(&mut tr.send, b"ad", b"r2i-0"), transport[2]);
    assert_eq!(open_vec(&mut ti.recv, b"ad", transport[2]), b"r2i-0");
}

#[test]
fn ik_matches_reference_vectors() {
    check_vectors(Pattern::Ik, &[b"ping from initiator", b"pong"], IK_H, IK_MSGS, &IK_TRANSPORT);
}

#[test]
fn xx_matches_reference_vectors() {
    check_vectors(Pattern::Xx, &[b"hello", b"world!", b"third"], XX_H, XX_MSGS, &XX_TRANSPORT);
}

#[test]
fn rekey_matches_reference_and_both_ends_must_rekey() {
    let (_, mut ti, mut tr) = run(Pattern::Ik, &[b"ping from initiator", b"pong"]);
    ti.send.rekey();
    // Same nonce 0, same plaintext: must equal sealing under the reference key.
    let mut want = b"after".to_vec();
    let tag = azos_crypto::chachapoly::seal(&unhex(IK_C1_REKEYED).try_into().unwrap(), &[0u8; 12], b"", &mut want)
        .unwrap();
    want.extend_from_slice(&tag);
    assert_eq!(seal_vec(&mut ti.send, b"", b"after"), hex(&want));
    // The receiver has not rekeyed: it cannot read that; once it does, it can.
    let mut c = want[..5].to_vec();
    let t: [u8; 16] = want[5..].try_into().unwrap();
    assert_eq!(tr.recv.decrypt(b"", &mut c, &t), Err(Error::Decrypt));
    tr.recv.rekey();
    tr.recv.decrypt(b"", &mut c, &t).unwrap();
    assert_eq!(&c, b"after");
}

#[test]
fn every_handshake_byte_flip_is_caught() {
    for (p, payloads) in [
        (Pattern::Ik, vec![&b"one"[..], &b"two"[..]]),
        (Pattern::Xx, vec![&b"one"[..], &b"two"[..], &b"three"[..]]),
    ] {
        let (wire, _, _) = run(p, &payloads);
        for (mi, msg) in wire.iter().enumerate() {
            for byte in 0..msg.len() {
                // Honest prefix, then message `mi` with one byte corrupted.
                let (mut a, mut b) = pair(p);
                let mut buf = [0u8; 512];
                let mut got = [0u8; 512];
                for (i, pl) in payloads.iter().enumerate().take(mi + 1) {
                    let (w, r, eph) = if i % 2 == 0 { (&mut a, &mut b, &EI) } else { (&mut b, &mut a, &ER) };
                    let n = w.write_message(eph, pl, &mut buf).unwrap();
                    if i < mi {
                        r.read_message(&buf[..n], &mut got).unwrap();
                        continue;
                    }
                    buf[byte] ^= 0x10;
                    let res = r.read_message(&buf[..n], &mut got);
                    if p == Pattern::Xx && mi == 0 {
                        // XX message 1 is `e` plus a CLEARTEXT payload: nothing
                        // to authenticate against yet. It is accepted, but the
                        // transcripts have diverged and message 2 cannot open.
                        assert!(res.is_ok());
                        assert_ne!(a.handshake_hash(), b.handshake_hash());
                        let n = b.write_message(&ER, b"", &mut buf).unwrap();
                        assert!(a.read_message(&buf[..n], &mut got).is_err(), "diverged transcript opened");
                    } else {
                        assert!(res.is_err(), "{p:?} msg {mi} byte {byte}: corruption accepted");
                    }
                }
            }
        }
    }
}

#[test]
fn buffers_and_truncation() {
    let mut buf = [0u8; 512];
    let mut out = [0u8; 64];
    // Writer: output buffer too small for e + es-encrypted s + tags.
    let (mut a, _) = pair(Pattern::Ik);
    assert_eq!(a.write_message(&EI, b"", &mut [0u8; 40]), Err(Error::BufferTooSmall));
    // Reader: payload buffer too small.
    let (mut a, mut b) = pair(Pattern::Ik);
    let n = a.write_message(&EI, b"payload", &mut buf).unwrap();
    assert_eq!(b.read_message(&buf[..n], &mut [0u8; 3]), Err(Error::BufferTooSmall));
    // Reader: message cut short anywhere inside the fixed part.
    for cut in [0usize, 20, 31, 32, 60, 95] {
        let (mut a, mut b) = pair(Pattern::Ik);
        let n = a.write_message(&EI, b"payload", &mut buf).unwrap();
        assert!(cut < n);
        assert!(b.read_message(&buf[..cut], &mut out).is_err(), "cut {cut}");
    }
    // Oversize input.
    let (_, mut b) = pair(Pattern::Xx);
    assert_eq!(b.read_message(&vec![0u8; 65536], &mut out), Err(Error::MessageTooLong));
}

/// The exporter secret: the same on both ends of a session, not the handshake
/// hash (which anyone on the wire can compute), not zero, different for every
/// session and pattern, and handed over once (the copy kept is wiped). That it
/// differs from the two transport keys is checked through the pinned
/// ciphertexts: the key `k` of a `CipherState` is private, so the exporter is
/// used as a ChaCha20-Poly1305 key to seal what `c1` sealed and the bytes must
/// not be the reference's.
#[test]
fn exporter_is_shared_secret_and_independent_of_the_other_outputs() {
    use azos_crypto::chachapoly;
    let mut seen = Vec::new();
    for (p, payloads, vec0) in [
        (Pattern::Ik, &[&b"ping from initiator"[..], &b"pong"[..]][..], IK_TRANSPORT[0]),
        (Pattern::Xx, &[&b"hello"[..], &b"hello"[..], &b"hello"[..]][..], XX_TRANSPORT[0]),
    ] {
        let (_, mut ti, mut tr) = run(p, payloads);
        let (ei, er) = (ti.take_exporter(), tr.take_exporter());
        assert_eq!(ei, er, "both ends derive the same exporter");
        assert_ne!(ei, ti.hash, "not the wire-derivable handshake hash");
        assert_ne!(ei, [0u8; 32]);
        assert_eq!(ti.take_exporter(), [0u8; 32], "handed over once");
        let mut buf = *b"i2r-0";
        let tag = chachapoly::seal(&ei, &[0u8; 12], b"ad", &mut buf).unwrap();
        let mut sealed = buf.to_vec();
        sealed.extend_from_slice(&tag);
        assert_ne!(hex(&sealed), vec0, "not the first transport key");
        seen.push(ei);
    }
    assert_ne!(seen[0], seen[1], "another session, another exporter");
    // The same pattern and statics with other ephemerals is another session.
    let (mut a, mut b) = pair(Pattern::Ik);
    let (mut buf, mut got) = ([0u8; 512], [0u8; 512]);
    let n = a.write_message(&[0x55; 32], b"x", &mut buf).unwrap();
    b.read_message(&buf[..n], &mut got).unwrap();
    let n = b.write_message(&ER, b"y", &mut buf).unwrap();
    a.read_message(&buf[..n], &mut got).unwrap();
    assert_ne!(a.finish().unwrap().take_exporter(), seen[0], "other ephemerals, other exporter");
}

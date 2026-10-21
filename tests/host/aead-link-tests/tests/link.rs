// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The brain link's Noise secure channel, from the robot's side, against a
//! brain model built straight on `azos_crypto::noise` (so the brain's role is
//! not exercised through the code under test).
//!
//! The `*_vector` tests pin wire bytes for fixed keys. `AzOSRobotBrain`'s
//! `tests/test_secure_channel.py` asserts the same hex, produced here first
//! (`cargo test --release -- --nocapture print_vectors`) and then reproduced by
//! the Python implementation, which uses no code from this tree. A failing
//! pin is a finding on one side or the other, never a constant to adjust.

mod common;
use azos_crypto::noise::{HandshakeState, Pattern};
use azos_crypto::secure_channel::*;
use azos_crypto::x25519::x25519_pubkey;
use common::*;

// ── Handshakes ─────────────────────────────────────────────────────────

#[test]
fn ik_handshake_completes_and_traffic_flows_both_ways() {
    let mut s = ik();
    assert_eq!(s.msg1[0], PATTERN_IK);
    assert!(s.msg3.is_none());
    // msg1: pattern byte + prefix + (e 32, enc s 48, payload tag 16).
    assert_eq!(s.msg1.len(), 1 + 2 + 96);
    assert_eq!(s.msg2.len(), 2 + 48);
    assert_eq!(s.robot.remote_static(), &x25519_pubkey(&BRAIN_IK_SK));
    for i in 0..50u8 {
        let msg = vec![i; 1 + i as usize * 7];
        let f = seal(&mut s.robot, &msg);
        assert_eq!(brain_open(&mut s.brain_recv, &f).unwrap(), msg);
        let back = brain_seal(&mut s.brain_send, &msg);
        let (k, d) = robot_open(&mut s.robot, &back).unwrap();
        assert_eq!(k, RecordKind::Data { len: msg.len() });
        assert_eq!(d, msg);
    }
}

#[test]
fn xx_handshake_completes_and_the_brain_shows_the_derived_static() {
    let mut s = xx();
    assert_eq!(s.msg1[0], PATTERN_XX);
    assert_eq!(s.msg1.len(), 1 + 2 + 32);
    assert_eq!(s.msg2.len(), 2 + 96);
    assert_eq!(s.msg3.as_ref().unwrap().len(), 2 + 64);
    assert_eq!(s.robot.remote_static(), &x25519_pubkey(&brain_static_key(&PSK)));
    let f = seal(&mut s.robot, b"hello brain");
    assert_eq!(brain_open(&mut s.brain_recv, &f).unwrap(), b"hello brain");
    let back = brain_seal(&mut s.brain_send, b"hello robot");
    assert_eq!(robot_open(&mut s.robot, &back).unwrap().1, b"hello robot");
}

#[test]
fn both_ends_agree_on_the_session_id() {
    let s = ik();
    let sid = s.robot.session_id();
    assert_ne!(sid, [0u8; SESSION_ID_BYTES]);
    assert_ne!(sid, xx().robot.session_id());
}

#[test]
fn a_brain_with_another_link_key_is_refused_before_the_robot_shows_its_static() {
    let mut other = PSK;
    other[0] ^= 1;
    // XX: the brain's derived static differs, so message 2 is refused by the
    // robot and message 3 (the robot's static) never goes out.
    let e = handshake(&PSK, None, &other, &[0; 32]);
    assert!(matches!(e, Err(ref m) if m.contains("PeerKeyMismatch")), "{e:?}");
    // The Initiator itself says so and is poisoned afterwards.
    let mut ini = Initiator::new(&PSK, None).unwrap();
    let mut out = [0u8; HANDSHAKE_OUT_MAX];
    ini.step(None, &E_ROBOT, &mut out).unwrap();
    let mut bhs = HandshakeState::responder(Pattern::Xx, &brain_static_key(&other), &prologue(PATTERN_XX)).unwrap();
    let mut np = [];
    bhs.read_message(&out[3..1 + 2 + 32], &mut np).unwrap();
    let mut buf = [0u8; 256];
    let m = bhs.write_message(&E_BRAIN, &[], &mut buf).unwrap();
    assert_eq!(ini.step(Some(&frame(&buf[..m])), &E_ROBOT, &mut out), Err(HandshakeError::PeerKeyMismatch));
    assert!(!ini.is_done());
    assert_eq!(ini.step(None, &E_ROBOT, &mut out), Err(HandshakeError::BadState));
    assert!(ini.finish().is_err());
}

#[test]
fn ik_with_a_brain_that_does_not_hold_the_pinned_key_fails() {
    let pinned = x25519_pubkey(&BRAIN_IK_SK);
    // The brain answers with another key: its message 1 decryption fails.
    let e = handshake(&PSK, Some(pinned), &PSK, &[0x78; 32]);
    assert!(matches!(e, Err(ref m) if m.contains("brain read 1")), "{e:?}");
}

#[test]
fn ik_brain_rejects_a_robot_with_another_link_key() {
    let mut other = PSK;
    other[31] ^= 0x80;
    let pinned = x25519_pubkey(&BRAIN_IK_SK);
    // The robot's derived static is not the one the brain's link key derives.
    let e = handshake(&other, Some(pinned), &PSK, &BRAIN_IK_SK);
    assert!(matches!(e, Err(ref m) if m.contains("not the derived one")), "{e:?}");
}

#[test]
fn a_pattern_byte_the_brain_did_not_expect_changes_the_prologue_and_fails() {
    // Flip the announced pattern in front of an IK message 1: the responder
    // built for what the byte says would be XX; and with the byte kept and
    // the prologue of another pattern the first AEAD fails.
    let mut ini = Initiator::new(&PSK, Some(&x25519_pubkey(&BRAIN_IK_SK))).unwrap();
    let mut out = [0u8; HANDSHAKE_OUT_MAX];
    let n = ini.step(None, &E_ROBOT, &mut out).unwrap();
    let mut bhs = HandshakeState::responder(Pattern::Ik, &BRAIN_IK_SK, &prologue(PATTERN_XX)).unwrap();
    let mut np = [];
    assert!(bhs.read_message(&out[3..n], &mut np).is_err());
}

#[test]
fn handshake_inputs_are_checked() {
    let mut ini = Initiator::new(&PSK, None).unwrap();
    let mut out = [0u8; HANDSHAKE_OUT_MAX];
    let mut small = [0u8; 8];
    assert_eq!(ini.step(None, &E_ROBOT, &mut small), Err(HandshakeError::BufferTooSmall));
    // A failed step ends the handshake.
    assert_eq!(ini.step(None, &E_ROBOT, &mut out), Err(HandshakeError::BadState));

    let mut ini = Initiator::new(&PSK, None).unwrap();
    ini.step(None, &E_ROBOT, &mut out).unwrap();
    // A frame whose length prefix lies.
    assert_eq!(ini.step(Some(&[0, 5, 1, 2]), &E_ROBOT, &mut out), Err(HandshakeError::BadFrame));
    let mut ini = Initiator::new(&PSK, None).unwrap();
    ini.step(None, &E_ROBOT, &mut out).unwrap();
    assert_eq!(ini.step(Some(&[]), &E_ROBOT, &mut out), Err(HandshakeError::BadFrame));
    // finish() before the pattern completed.
    let ini = Initiator::new(&PSK, None).unwrap();
    assert!(ini.finish().is_err());
}

#[test]
fn low_order_brain_ephemeral_is_refused() {
    let mut ini = Initiator::new(&PSK, None).unwrap();
    let mut out = [0u8; HANDSHAKE_OUT_MAX];
    ini.step(None, &E_ROBOT, &mut out).unwrap();
    // e = all zero, then the payload tag and the encrypted static: the ee DH
    // is all-zero and the robot refuses before anything else.
    let msg = [0u8; 96];
    assert!(matches!(ini.step(Some(&frame(&msg)), &E_ROBOT, &mut out), Err(HandshakeError::Noise(_))));
}

#[test]
fn derived_statics_are_distinct() {
    assert_ne!(kernel_static_key(&PSK), brain_static_key(&PSK));
    assert_ne!(kernel_static_key(&PSK), PSK);
    let mut other = PSK;
    other[5] ^= 1;
    assert_ne!(kernel_static_key(&PSK), kernel_static_key(&other));
}

// ── Framing ────────────────────────────────────────────────────────────

#[test]
fn frame_len_rules() {
    let max = max_body_for(MAX_MESSAGE_BYTES);
    assert_eq!(frame_len(&[], max), Err(RecordError::Incomplete));
    assert_eq!(frame_len(&[0], max), Err(RecordError::Incomplete));
    assert_eq!(frame_len(&[0, 16], max), Ok(18));
    assert_eq!(frame_len(&[0, 15], max), Err(RecordError::BadHeader));
    assert_eq!(frame_len(&[0, 0], max), Err(RecordError::BadHeader));
    assert_eq!(frame_len(&[0x40, 0x10], max), Ok(2 + max));
    assert_eq!(frame_len(&[0x40, 0x11], max), Err(RecordError::BadHeader));
    assert_eq!(frame_len(&[0xff, 0xff], max), Err(RecordError::BadHeader));
    assert!(RecordError::BadMac.is_terminal() && !RecordError::Incomplete.is_terminal());
}

#[test]
fn coalesced_and_torn_frames_open_in_order_from_any_split() {
    let mut s = ik();
    let msgs: Vec<Vec<u8>> = (1..=6u8).map(|i| vec![i; 40 * i as usize]).collect();
    let mut wire = Vec::new();
    for m in &msgs {
        wire.extend(brain_seal(&mut s.brain_send, m));
    }
    for split in [1usize, 2, 3, 17, 18, 19, 200, wire.len()] {
        let mut s = ik();
        let mut wire = Vec::new();
        for m in &msgs {
            wire.extend(brain_seal(&mut s.brain_send, m));
        }
        let mut carry: Vec<u8> = Vec::new();
        let mut got: Vec<Vec<u8>> = Vec::new();
        for chunk in wire.chunks(split) {
            carry.extend_from_slice(chunk);
            let mut off = 0;
            loop {
                match s.robot.open_frame(&mut carry[off..], max_body_for(MAX_MESSAGE_BYTES)) {
                    Ok(o) => {
                        if let RecordKind::Data { len } = o.kind {
                            got.push(carry[off + FRAME_HEAD..off + FRAME_HEAD + len].to_vec());
                        }
                        off += o.consumed;
                    }
                    Err(RecordError::Incomplete) => break,
                    Err(e) => panic!("split {split}: {e:?}"),
                }
            }
            carry.drain(..off);
        }
        assert_eq!(got, msgs, "split {split}");
    }
}

#[test]
fn an_incomplete_frame_changes_nothing() {
    let mut s = ik();
    let f = brain_seal(&mut s.brain_send, b"abcdefgh");
    for cut in 0..f.len() {
        let mut part = f[..cut].to_vec();
        assert_eq!(s.robot.open_frame(&mut part, max_body_for(MAX_MESSAGE_BYTES)), Err(RecordError::Incomplete), "cut {cut}");
        assert!(s.robot.is_established());
    }
    assert!(robot_open(&mut s.robot, &f).is_ok());
}

// ── Violations end the session ─────────────────────────────────────────

fn assert_dead(l: &mut Link) {
    assert!(!l.is_established());
    let mut out = [0u8; 64];
    assert_eq!(l.seal_message(b"x", &mut out), Err(SealError::NotEstablished));
    let mut f = [0u8; 40];
    assert_eq!(l.open_frame(&mut f, 100), Err(RecordError::NotEstablished));
}

#[test]
fn a_forged_frame_is_terminal() {
    let mut s = ik();
    let mut f = brain_seal(&mut s.brain_send, b"stop everything");
    f[5] ^= 1;
    assert_eq!(robot_open(&mut s.robot, &f), Err(RecordError::BadMac));
    assert_dead(&mut s.robot);
}

#[test]
fn a_tampered_length_prefix_is_terminal_because_it_is_the_associated_data() {
    let mut s = ik();
    let mut f = brain_seal(&mut s.brain_send, b"stop everything");
    let n = f.len();
    // Claim two more bytes and supply them: the AEAD binds the old length.
    f[1] += 2;
    f.extend_from_slice(&[0, 0]);
    assert_eq!(f.len(), n + 2);
    assert_eq!(robot_open(&mut s.robot, &f), Err(RecordError::BadMac));
    assert_dead(&mut s.robot);
}

#[test]
// REQ-012
fn a_replayed_a_reordered_and_a_dropped_frame_are_terminal() {
    // Replay.
    let mut s = ik();
    let f1 = brain_seal(&mut s.brain_send, b"first");
    robot_open(&mut s.robot, &f1).unwrap();
    assert_eq!(robot_open(&mut s.robot, &f1), Err(RecordError::BadMac));
    assert_dead(&mut s.robot);
    // Reorder.
    let mut s = ik();
    let f1 = brain_seal(&mut s.brain_send, b"first");
    let f2 = brain_seal(&mut s.brain_send, b"second");
    assert_eq!(robot_open(&mut s.robot, &f2), Err(RecordError::BadMac));
    assert_dead(&mut s.robot);
    let _ = f1;
    // Drop: f1 never arrives.
    let mut s = ik();
    let _lost = brain_seal(&mut s.brain_send, b"first");
    let f2 = brain_seal(&mut s.brain_send, b"second");
    assert_eq!(robot_open(&mut s.robot, &f2), Err(RecordError::BadMac));
}

#[test]
fn a_frame_the_robot_itself_sent_does_not_open_as_inbound() {
    // Reflection: the two directions use different keys.
    let mut s = ik();
    let mine = seal(&mut s.robot, b"my own frame");
    assert_eq!(robot_open(&mut s.robot, &mine), Err(RecordError::BadMac));
}

#[test]
// REQ-012
fn a_frame_from_another_session_does_not_open() {
    let mut a = ik();
    let mut b = xx();
    let f = brain_seal(&mut a.brain_send, b"recorded in session a");
    assert_eq!(robot_open(&mut b.robot, &f), Err(RecordError::BadMac));
    // Same pattern, same keys, other ephemerals: also another session.
    let pinned = x25519_pubkey(&BRAIN_IK_SK);
    let mut ini = Initiator::new(&PSK, Some(&pinned)).unwrap();
    let mut out = [0u8; HANDSHAKE_OUT_MAX];
    ini.step(None, &[0x35; 32], &mut out).unwrap();
    assert_ne!(&out[..3 + 32], &a.msg1[..3 + 32]);
}

#[test]
fn oversize_and_undersize_bodies_are_terminal_before_any_body_is_read() {
    let mut s = ik();
    let mut head = [0xff, 0xff];
    assert_eq!(s.robot.open_frame(&mut head, max_body_for(MAX_MESSAGE_BYTES)), Err(RecordError::BadHeader));
    assert_dead(&mut s.robot);
    let mut s = ik();
    let mut head = [0, 3];
    assert_eq!(s.robot.open_frame(&mut head, max_body_for(MAX_MESSAGE_BYTES)), Err(RecordError::BadHeader));
    // A reader with a smaller cap refuses a legal frame of the larger size.
    let mut s = ik();
    let big = brain_seal(&mut s.brain_send, &vec![1u8; 300]);
    let mut b = big.clone();
    assert_eq!(s.robot.open_frame(&mut b, max_body_for(256)), Err(RecordError::BadHeader));
}

#[test]
fn seal_refusals_change_nothing() {
    let mut s = ik();
    let mut out = vec![0u8; sealed_len_max(MAX_MESSAGE_BYTES)];
    assert_eq!(s.robot.seal_message(&[], &mut out), Err(SealError::EmptyMessage));
    assert_eq!(s.robot.seal_message(&vec![0u8; MAX_MESSAGE_BYTES + 1], &mut out), Err(SealError::MessageTooLarge));
    assert_eq!(s.robot.seal_message(b"0123456789", &mut out[..27]), Err(SealError::BufferTooSmall));
    // The largest message works and nothing above spent a nonce.
    let n = s.robot.seal_message(&vec![7u8; MAX_MESSAGE_BYTES], &mut out).unwrap();
    assert_eq!(n, FRAME_OVERHEAD + MAX_MESSAGE_BYTES);
    let msg = brain_open(&mut s.brain_recv, &out[..n]).unwrap();
    assert_eq!(msg.len(), MAX_MESSAGE_BYTES);
}

// ── Rekey ──────────────────────────────────────────────────────────────

#[test]
fn a_requested_rekey_precedes_the_message_and_both_ends_follow() {
    let mut s = ik();
    let f = seal(&mut s.robot, b"gen 0");
    assert_eq!(f.len(), FRAME_OVERHEAD + 5);
    assert_eq!(brain_open(&mut s.brain_recv, &f).unwrap(), b"gen 0");
    assert_eq!(s.robot.tx_generation(), 0);
    s.robot.request_rekey();
    let f = seal(&mut s.robot, b"gen 1");
    assert_eq!(f.len(), 2 * FRAME_OVERHEAD + 5);
    assert_eq!(s.robot.tx_generation(), 1);
    // The brain reads the empty frame (and rekeys), then the data under the new key.
    let (rk, data) = f.split_at(FRAME_OVERHEAD);
    assert_eq!(brain_open(&mut s.brain_recv, rk).unwrap(), b"");
    assert_eq!(brain_open(&mut s.brain_recv, data).unwrap(), b"gen 1");
    // A second message does not rekey again.
    let f = seal(&mut s.robot, b"still gen 1");
    assert_eq!(f.len(), FRAME_OVERHEAD + 11);
    assert_eq!(brain_open(&mut s.brain_recv, &f).unwrap(), b"still gen 1");
}

#[test]
fn the_robot_follows_a_brain_rekey() {
    let mut s = ik();
    let rk = brain_seal(&mut s.brain_send, b"");
    s.brain_send.rekey();
    let (k, _) = robot_open(&mut s.robot, &rk).unwrap();
    assert_eq!(k, RecordKind::Rekey);
    assert_eq!(s.robot.rx_generation(), 1);
    let f = brain_seal(&mut s.brain_send, b"after the rekey");
    assert_eq!(robot_open(&mut s.robot, &f).unwrap().1, b"after the rekey");
}

#[test]
fn a_frame_from_before_the_rekey_does_not_open_after_it() {
    let mut s = ik();
    let old = brain_seal(&mut s.brain_send, b"old");
    let rk = brain_seal(&mut s.brain_send, b"");
    s.brain_send.rekey();
    robot_open(&mut s.robot, &rk).unwrap_err(); // out of order: old is first
    assert_dead(&mut s.robot);
    let _ = old;
    // In order, the old key is gone: a copy of `old` replays as garbage.
    let mut s = ik();
    let old = brain_seal(&mut s.brain_send, b"old");
    robot_open(&mut s.robot, &old).unwrap();
    let rk = brain_seal(&mut s.brain_send, b"");
    s.brain_send.rekey();
    robot_open(&mut s.robot, &rk).unwrap();
    assert_eq!(robot_open(&mut s.robot, &old), Err(RecordError::BadMac));
}

#[test]
fn message_and_byte_limits_trigger_a_rekey_on_both_ends() {
    let mut s = ik();
    s.robot.set_rekey_limits(4, u64::MAX);
    let mut gens = vec![];
    for i in 0..10u8 {
        let f = seal(&mut s.robot, &[i; 9]);
        gens.push(s.robot.tx_generation());
        // Feed the brain whatever the robot produced, frame by frame.
        let mut off = 0;
        while off < f.len() {
            let t = frame_len(&f[off..], max_body_for(MAX_MESSAGE_BYTES)).unwrap();
            let p = brain_open(&mut s.brain_recv, &f[off..off + t]).unwrap();
            if !p.is_empty() {
                assert_eq!(p, vec![i; 9]);
            }
            off += t;
        }
    }
    // 3 data messages and a rekey per generation: generations step every 3.
    assert_eq!(gens, vec![0, 0, 0, 1, 1, 1, 2, 2, 2, 3]);

    // The byte limit: two 9 KiB messages do not fit one 16 KiB generation.
    let mut s = ik();
    s.robot.set_rekey_limits(1 << 20, 16 * 1024);
    seal(&mut s.robot, &vec![1u8; 9000]);
    assert_eq!(s.robot.tx_generation(), 0);
    seal(&mut s.robot, &vec![1u8; 9000]);
    assert_eq!(s.robot.tx_generation(), 1);
}

#[test]
fn a_peer_that_skips_the_rekey_is_refused() {
    let mut s = ik();
    s.robot.set_rekey_limits(4, u64::MAX);
    for i in 0..3u8 {
        let f = brain_seal(&mut s.brain_send, &[i; 5]);
        robot_open(&mut s.robot, &f).unwrap();
    }
    let f = brain_seal(&mut s.brain_send, &[9; 5]);
    assert_eq!(robot_open(&mut s.robot, &f), Err(RecordError::RekeyOverdue));
    assert_dead(&mut s.robot);
    // The byte limit.
    let mut s = ik();
    s.robot.set_rekey_limits(1 << 20, 16 * 1024);
    let f = brain_seal(&mut s.brain_send, &vec![1u8; 9000]);
    robot_open(&mut s.robot, &f).unwrap();
    let f = brain_seal(&mut s.brain_send, &vec![1u8; 9000]);
    assert_eq!(robot_open(&mut s.robot, &f), Err(RecordError::RekeyOverdue));
}

#[test]
fn rekey_limits_are_clamped() {
    let mut s = ik();
    s.robot.set_rekey_limits(0, 0);
    // Clamped to the floors: the smallest limit still lets a message through.
    let f = seal(&mut s.robot, b"x");
    assert_eq!(brain_open(&mut s.brain_recv, &f[..FRAME_OVERHEAD + 1]).unwrap(), b"x");
    s.robot.set_rekey_limits(u32::MAX, u64::MAX);
    for _ in 0..3 {
        seal(&mut s.robot, b"y");
    }
}

#[test]
fn rekey_interval_is_only_ever_shortened() {
    assert_eq!(rekey_interval_secs(None), REKEY_INTERVAL_SECS);
    assert_eq!(rekey_interval_secs(Some(86_400)), REKEY_INTERVAL_SECS);
    assert_eq!(rekey_interval_secs(Some(60)), 60);
    assert_eq!(rekey_interval_secs(Some(1)), REKEY_INTERVAL_MIN_SECS);
    assert_eq!(rekey_interval_secs(Some(0)), REKEY_INTERVAL_MIN_SECS);
}

#[test]
fn session_id_cache_refuses_a_repeat_and_evicts_the_oldest() {
    let mut c = SessionIdCache::<2>::new();
    let a = [1u8; SESSION_ID_BYTES];
    let b = [2u8; SESSION_ID_BYTES];
    let d = [3u8; SESSION_ID_BYTES];
    assert!(c.insert_if_new(&a));
    assert!(!c.insert_if_new(&a));
    assert!(c.insert_if_new(&b));
    assert!(c.insert_if_new(&d)); // evicts a
    assert!(c.insert_if_new(&a));
    assert!(!c.insert_if_new(&d));
}

// ── Vectors: reproduced by AzOSRobotBrain/tests/test_secure_channel.py ─
//
// PSK = bytes(range(32)); robot ephemeral 0x33*32, brain ephemeral 0x44*32;
// IK toward the key of 0x77*32. Regenerate (only for a deliberate wire change,
// on BOTH sides) by printing from `print_vectors`.

const KERNEL_SK: &str = "9f1fcde4e89ea1e2a099cfef639daab5e6cbce97d016e6cc1a0a1898c423f774";
const KERNEL_PK: &str = "ed8af765db3e506ce9993ceb2cb824c2d1640b5531d8bb3dd19700a5243b271d";
const BRAIN_SK: &str = "ac9b2eb32bf8bb4e742800c7d14826bedcddabdc85a489981a12e501dfa94d7d";
const BRAIN_PK: &str = "b36a27f7b9be42fc6c11307347556eb1a34e81095684b6df11af3781382b1434";
const IK_BRAIN_PK: &str = "1cf579aba45a10ba1d1ef06d91fca2aa9ed0a1150515653155405d0b18cb9a67";
const IK_MSG1: &str = "4900607b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b140f31ce1e7b91df672735b75efa7d1eb743576872dc47b54ab044e26204667554f5208f24537e08182160bf762ed828cffd85fb0ec9fbe0da4b4d0fb42acd6f26";
const IK_MSG2: &str = "0030ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b1346dc7690404d34f646d6a09752a7fd";
const IK_SID: &str = "4dc0b2a9167f8b13bec0936fd40a3179";
const IK_ROBOT_F1: &str = "001b57e276ed408c8d0521e7132db429421eb654291aa56c19b3ce72d6";
const IK_ROBOT_F2: &str = "001e2070952fc43a92b28242947a8af5023c287e63277a329ca8a2faf6d47500";
const IK_BRAIN_F1: &str = "001b25b2d87f1d737f45a590b176ed6a807f8307713130335a82865f7b";
const IK_ROBOT_F3_REKEY: &str = "0010955a5c3aac132c8b360ed7c56203cb61001b2a45bd172f6ff7b1188fb23992a8bca8125d00ae3041ca1bfa6af6";
const XX_MSG1: &str = "5800207b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14";
const XX_MSG2: &str = "0060ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b406dfee9ebefd84127fadf3bdc15ad1f16be32cfa431ebeff801e358e531010a4f77fce2a2489b29f805adb69afd37198e8d917e40a8c3e1e3513f6682243dfd";
const XX_MSG3: &str = "0040bf490b653f124ebe7b2c2f514e4c107e92839895c8e19bd66328b57810d84cb76e8c50871e943be1cb3246bde1040012af44047aa7c60f52998553d4ffa162e1";
const XX_SID: &str = "70742d52f1efae547de5ed473d7dd0c2";
const XX_ROBOT_F1: &str = "001b0f817fca54e339881ea8c89296fd3791fbab2eb2d101c1469eb738";
const XX_BRAIN_F1: &str = "001bfdb82326098580d5bfabe8205bf997936778601eb86cb104ca7b3f";

#[test]
fn derived_static_keys_vector() {
    assert_eq!(hex(&kernel_static_key(&PSK)), KERNEL_SK);
    assert_eq!(hex(&x25519_pubkey(&kernel_static_key(&PSK))), KERNEL_PK);
    assert_eq!(hex(&brain_static_key(&PSK)), BRAIN_SK);
    assert_eq!(hex(&x25519_pubkey(&brain_static_key(&PSK))), BRAIN_PK);
    assert_eq!(hex(&x25519_pubkey(&BRAIN_IK_SK)), IK_BRAIN_PK);
}

#[test]
fn ik_vector() {
    let mut s = ik();
    assert_eq!(hex(&s.msg1), IK_MSG1);
    assert_eq!(hex(&s.msg2), IK_MSG2);
    assert_eq!(hex(&s.robot.session_id()), IK_SID);
    assert_eq!(hex(&seal(&mut s.robot, b"hello brain")), IK_ROBOT_F1);
    assert_eq!(hex(&seal(&mut s.robot, b"second message")), IK_ROBOT_F2);
    assert_eq!(hex(&brain_seal(&mut s.brain_send, b"hello robot")), IK_BRAIN_F1);
    s.robot.request_rekey();
    assert_eq!(hex(&seal(&mut s.robot, b"after rekey")), IK_ROBOT_F3_REKEY);
}

#[test]
fn xx_vector() {
    let mut s = xx();
    assert_eq!(hex(&s.msg1), XX_MSG1);
    assert_eq!(hex(&s.msg2), XX_MSG2);
    assert_eq!(hex(s.msg3.as_ref().unwrap()), XX_MSG3);
    assert_eq!(hex(&s.robot.session_id()), XX_SID);
    assert_eq!(hex(&seal(&mut s.robot, b"hello brain")), XX_ROBOT_F1);
    assert_eq!(hex(&brain_seal(&mut s.brain_send, b"hello robot")), XX_BRAIN_F1);
}

/// Prints the vectors above; `cargo test --release -- --nocapture print_vectors`.
#[test]
fn print_vectors() {
    let mut s = ik();
    println!("ik_msg1        {}", hex(&s.msg1));
    println!("ik_msg2        {}", hex(&s.msg2));
    println!("ik_sid         {}", hex(&s.robot.session_id()));
    println!("ik_robot_f1    {}", hex(&seal(&mut s.robot, b"hello brain")));
    println!("ik_robot_f2    {}", hex(&seal(&mut s.robot, b"second message")));
    println!("ik_brain_f1    {}", hex(&brain_seal(&mut s.brain_send, b"hello robot")));
    s.robot.request_rekey();
    println!("ik_robot_f3    {}", hex(&seal(&mut s.robot, b"after rekey")));
    let mut x = xx();
    println!("xx_msg1        {}", hex(&x.msg1));
    println!("xx_msg2        {}", hex(&x.msg2));
    println!("xx_msg3        {}", hex(x.msg3.as_ref().unwrap()));
    println!("xx_sid         {}", hex(&x.robot.session_id()));
    println!("xx_robot_f1    {}", hex(&seal(&mut x.robot, b"hello brain")));
    println!("xx_brain_f1    {}", hex(&brain_seal(&mut x.brain_send, b"hello robot")));
}

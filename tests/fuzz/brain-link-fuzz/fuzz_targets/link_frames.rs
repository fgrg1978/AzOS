// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: everything the brain link decodes off the wire.
//!
//! `data[0] % 4` picks the surface, the rest is the peer's bytes:
//!  0. an IK initiator reading a fuzzed reply frame (message 2);
//!  1. an XX initiator reading a fuzzed reply frame (message 2);
//!  2. an established link reading a raw frame stream (`frame_len` and
//!     `open_frame` until it stops);
//!  3. tamper: real sealed messages from the brain's side, bytes XOR-ed at
//!     input-chosen offsets, read by the link. Property: the link never
//!     completes a message that differs from what was sealed (a forgery past
//!     the AEAD), and an untampered stream round-trips.
#![no_main]

use azos_crypto::noise::{CipherState, HandshakeState, Pattern};
use azos_crypto::secure_channel::*;
use azos_crypto::x25519::x25519_pubkey;
use libfuzzer_sys::fuzz_target;

const PSK: [u8; 32] = [7; 32];
const BRAIN_SK: [u8; 32] = [0x77; 32];
const E_ROBOT: [u8; 32] = [0xAA; 32];
const E_BRAIN: [u8; 32] = [0xBB; 32];
const MAX_BODY: usize = max_body_for(MAX_MESSAGE_BYTES);

fn prologue(pb: u8) -> Vec<u8> {
    let mut p = PROLOGUE_LABEL.to_vec();
    p.push(pb);
    p
}

/// A completed IK handshake: the robot's link and the brain's send cipher.
fn pair() -> (Link, CipherState) {
    let pinned = x25519_pubkey(&BRAIN_SK);
    let mut ini = Initiator::new(&PSK, Some(&pinned)).unwrap();
    let mut out = [0u8; HANDSHAKE_OUT_MAX];
    let n = ini.step(None, &E_ROBOT, &mut out).unwrap();
    let mut bhs = HandshakeState::responder(Pattern::Ik, &BRAIN_SK, &prologue(PATTERN_IK)).unwrap();
    bhs.read_message(&out[1 + FRAME_HEAD..n], &mut []).unwrap();
    let mut buf = [0u8; 256];
    let m = bhs.write_message(&E_BRAIN, &[], &mut buf).unwrap();
    let mut frame = (m as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&buf[..m]);
    ini.step(Some(&frame), &E_ROBOT, &mut out).unwrap();
    let link = ini.finish().unwrap();
    let mut t = bhs.finish().unwrap();
    (link, core::mem::replace(&mut t.send, CipherState::empty()))
}

/// Read frames from `stream` until one fails or the stream is used up.
/// Returns the plaintext of every message the reader completed.
fn read_all(rx: &mut Link, stream: &[u8]) -> Vec<Vec<u8>> {
    let mut done = Vec::new();
    let mut buf = stream.to_vec();
    let mut off = 0;
    while off < buf.len() {
        match rx.open_frame(&mut buf[off..], MAX_BODY) {
            Ok(o) => {
                assert!(o.consumed > 0 && o.consumed <= buf.len() - off);
                if let RecordKind::Data { len } = o.kind {
                    assert!(len <= MAX_MESSAGE_BYTES);
                    done.push(buf[off + FRAME_HEAD..off + FRAME_HEAD + len].to_vec());
                }
                off += o.consumed;
            }
            Err(_) => break,
        }
    }
    done
}

fn brain_seal(cs: &mut CipherState, plain: &[u8]) -> Vec<u8> {
    let head = ((plain.len() + 16) as u16).to_be_bytes();
    let mut body = plain.to_vec();
    let tag = cs.encrypt(&head, &mut body).unwrap();
    let mut f = head.to_vec();
    f.extend_from_slice(&body);
    f.extend_from_slice(&tag);
    f
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let _ = frame_len(rest, MAX_BODY);
    match sel % 4 {
        0 | 1 => {
            let pinned = x25519_pubkey(&BRAIN_SK);
            let mut ini = Initiator::new(&PSK, if sel % 4 == 0 { Some(&pinned) } else { None }).unwrap();
            let mut out = [0u8; HANDSHAKE_OUT_MAX];
            ini.step(None, &E_ROBOT, &mut out).unwrap();
            let _ = ini.step(Some(rest), &E_ROBOT, &mut out);
            let _ = ini.finish();
        }
        2 => {
            let (mut a, _) = pair();
            let _ = read_all(&mut a, rest);
        }
        _ => {
            // rest = [msg_len_lo, msg_len_hi, n_flips, (off_lo, off_hi, xor)*]
            if rest.len() < 3 { return; }
            let msg_len = 1 + (u16::from_le_bytes([rest[0], rest[1]]) as usize) % 5000;
            let msgs: Vec<Vec<u8>> = (0..3u8)
                .map(|k| (0..msg_len).map(|i| i as u8 ^ 0x5A ^ k).collect())
                .collect();
            let (mut a, mut b_send) = pair();
            let mut sealed = Vec::new();
            for m in &msgs {
                sealed.extend(brain_seal(&mut b_send, m));
            }
            let original = sealed.clone();
            for f in rest[3..].chunks_exact(3).take(rest[2] as usize) {
                let off = u16::from_le_bytes([f[0], f[1]]) as usize;
                if off < sealed.len() {
                    sealed[off] ^= f[2];
                }
            }
            let tampered = sealed != original;
            let got = read_all(&mut a, &sealed);
            if tampered {
                assert!(got.len() < msgs.len(), "a tampered stream opened completely");
                assert!(got.iter().zip(&msgs).all(|(g, m)| g == m), "tampered stream opened to different bytes");
            } else {
                assert_eq!(got, msgs, "untampered stream did not round-trip");
            }
        }
    }
});

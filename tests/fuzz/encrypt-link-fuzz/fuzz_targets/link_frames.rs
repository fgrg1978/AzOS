// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: everything the RFC-0019 link decodes off the wire.
//!
//! `data[0] % 4` picks the surface, the rest is the peer's bytes:
//!  0. a responder's first frame (`handle_initiator_hello`), then the
//!     confirm (`handle_initiator_confirm`) on the remainder;
//!  1. an initiator's reply frame (`handle_peer_hello`);
//!  2. an established responder reading a raw record stream
//!     (`open_record` until it stops) and `decrypt_consuming`;
//!  3. tamper: a real sealed message from an established initiator, bytes
//!     XOR-ed at input-chosen offsets, read by the responder. Property: the
//!     responder never completes a message whose bytes differ from what was
//!     sealed (a forgery past the HMAC).
//!
//! After every iteration all links are dropped and the process-wide
//! established-session count must be back at zero (a leak there would keep
//! `envelope_frame_permitted` answering for a dead session).
#![no_main]

use libfuzzer_sys::fuzz_target;
use azos_encrypt_link::{
    aead_session_count, parse_record_header, sealed_len_max, EncryptLink, RecordKind,
    CONFIRM_BYTES, HELLO_INIT_BYTES, HELLO_REPLY_BYTES, MAX_MESSAGE_BYTES,
};

const PSK: [u8; 32] = [7; 32];
const A_PRIV: [u8; 32] = [0xAA; 32];
const B_PRIV: [u8; 32] = [0xBB; 32];

/// A completed handshake: (initiator, responder).
fn pair() -> (EncryptLink, EncryptLink) {
    let mut a = EncryptLink::new(PSK, A_PRIV);
    let mut b = EncryptLink::new(PSK, B_PRIV);
    let mut hi = [0u8; HELLO_INIT_BYTES];
    let mut hr = [0u8; HELLO_REPLY_BYTES];
    let mut cf = [0u8; CONFIRM_BYTES];
    a.start_initiator(&mut hi).unwrap();
    b.handle_initiator_hello(&hi, &mut hr).unwrap();
    a.handle_peer_hello(&hr, &mut cf).unwrap();
    b.handle_initiator_confirm(&cf).unwrap();
    assert!(a.is_established() && b.is_established());
    (a, b)
}

/// Read records from `stream` until one fails or the stream is used up.
/// Returns the plaintext of every message the reader completed.
fn read_all(rx: &mut EncryptLink, mut stream: &[u8]) -> Vec<Vec<u8>> {
    let mut done = Vec::new();
    let mut cur = Vec::new();
    let mut out = vec![0u8; 4096];
    while !stream.is_empty() {
        match rx.open_record(stream, &mut out) {
            Ok(o) => {
                assert!(o.consumed > 0 && o.consumed <= stream.len());
                if let RecordKind::Data { len, more } = o.kind {
                    cur.extend_from_slice(&out[..len]);
                    assert!(cur.len() <= MAX_MESSAGE_BYTES);
                    if !more {
                        done.push(core::mem::take(&mut cur));
                    }
                }
                stream = &stream[o.consumed..];
            }
            Err(_) => break,
        }
    }
    done
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let _ = parse_record_header(rest);
    match sel % 4 {
        0 => {
            let mut b = EncryptLink::new(PSK, B_PRIV);
            let mut hr = [0u8; HELLO_REPLY_BYTES];
            let n = rest.len().min(HELLO_INIT_BYTES);
            if b.handle_initiator_hello(&rest[..n], &mut hr).is_ok() {
                let _ = b.handle_initiator_confirm(&rest[n..]);
            }
        }
        1 => {
            let mut a = EncryptLink::new(PSK, A_PRIV);
            let mut hi = [0u8; HELLO_INIT_BYTES];
            let mut cf = [0u8; CONFIRM_BYTES];
            a.start_initiator(&mut hi).unwrap();
            let _ = a.handle_peer_hello(rest, &mut cf);
        }
        2 => {
            let (_a, mut b) = pair();
            let mut out = vec![0u8; 4096];
            let _ = b.decrypt_consuming(rest, &mut out);
            let _ = read_all(&mut b, rest);
        }
        _ => {
            // rest = [msg_len_lo, msg_len_hi, n_flips, (off_lo, off_hi, xor)*]
            if rest.len() < 3 { return; }
            let msg_len = (u16::from_le_bytes([rest[0], rest[1]]) as usize) % 5000;
            let msg: Vec<u8> = (0..msg_len).map(|i| i as u8 ^ 0x5A).collect();
            let (mut a, mut b) = pair();
            let mut sealed = vec![0u8; sealed_len_max(msg_len)];
            let mut ctr = 0u8;
            let n = a
                .seal_message(&msg, || { ctr = ctr.wrapping_add(1); [ctr; 8] }, &mut sealed)
                .expect("seal");
            sealed.truncate(n);
            let mut tampered = false;
            for f in rest[3..].chunks_exact(3).take(rest[2] as usize) {
                let off = u16::from_le_bytes([f[0], f[1]]) as usize;
                if off < sealed.len() && f[2] != 0 {
                    sealed[off] ^= f[2];
                    tampered = true;
                }
            }
            let got = read_all(&mut b, &sealed);
            if tampered {
                assert!(got.iter().all(|m| *m == msg), "tampered stream opened to different bytes");
            } else {
                assert_eq!(got, vec![msg], "untampered message did not round-trip");
            }
        }
    }
    assert_eq!(aead_session_count(), 0, "a dropped link is still counted as established");
});

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The binary packet protocol (RFC 4253 section 6) and
//! `chacha20-poly1305@openssh.com`.

use crate::packet::*;

fn key_material(seed: u8) -> [u8; 64] {
    let mut k = [0u8; 64];
    for (i, b) in k.iter_mut().enumerate() {
        *b = seed.wrapping_mul(31).wrapping_add(i as u8);
    }
    k
}

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)).collect()
}

/// The packet as OpenSSH lays it out before encryption: length, padding
/// length, payload, zero padding (so that all after the length is a multiple
/// of 8 and the padding is at least 4).
fn plain_packet(p: &[u8]) -> Vec<u8> {
    let mut pad = 8 - (1 + p.len()) % 8;
    if pad < 4 {
        pad += 8;
    }
    let mut v = Vec::new();
    v.extend_from_slice(&((1 + p.len() + pad) as u32).to_be_bytes());
    v.push(pad as u8);
    v.extend_from_slice(p);
    v.resize(v.len() + pad, 0);
    v
}

#[test]
fn seal_is_what_rings_openssh_construction_makes() {
    for (seed, seq, n) in [(1u8, 0u32, 1usize), (2, 1, 5), (3, 7, 16), (4, 0xffff_fffe, 43), (5, 123_456, 1000), (6, 3, 4096)] {
        let km = key_material(seed);
        let want = {
            let sk = ring::aead::chacha20_poly1305_openssh::SealingKey::new(&km);
            let mut buf = plain_packet(&payload(n, seed));
            let mut tag = [0u8; 16];
            sk.seal_in_place(seq, &mut buf, &mut tag);
            buf.extend_from_slice(&tag);
            buf
        };
        let mut got = Vec::new();
        seal(&Key::new(&km), seq, &payload(n, seed), &mut got).unwrap();
        assert_eq!(got, want, "seed {seed} seq {seq} payload {n}");
    }
}

#[test]
fn rx_opens_what_ring_seals_and_ring_opens_what_tx_seals() {
    let km = key_material(9);
    // ring -> us, a run of packets with the sequence number advancing.
    let sk = ring::aead::chacha20_poly1305_openssh::SealingKey::new(&km);
    let mut rx = Rx::new();
    rx.set_key(Key::new(&km));
    for seq in 0..5u32 {
        let p = payload(10 + 37 * seq as usize, 3);
        let mut buf = plain_packet(&p);
        let mut tag = [0u8; 16];
        sk.seal_in_place(seq, &mut buf, &mut tag);
        buf.extend_from_slice(&tag);
        rx.push(&buf);
        assert_eq!(rx.next().unwrap().unwrap(), p);
    }
    // us -> ring.
    let ok = ring::aead::chacha20_poly1305_openssh::OpeningKey::new(&km);
    let mut tx = Tx::new();
    tx.set_key(Key::new(&km));
    for seq in 0..5u32 {
        let p = payload(3 + 11 * seq as usize, 8);
        let mut wire = Vec::new();
        tx.send(&p, &mut wire).unwrap();
        let n = wire.len() - 16;
        let (head, tag) = wire.split_at_mut(n);
        let len = ok.decrypt_packet_length(seq, [head[0], head[1], head[2], head[3]]);
        assert_eq!(u32::from_be_bytes(len) as usize, head.len() - 4);
        let tag: [u8; 16] = (&*tag).try_into().unwrap();
        let plain = ok.open_in_place(seq, head, &tag).unwrap();
        let pad = plain[0] as usize;
        assert_eq!(&plain[1..plain.len() - pad], &p[..]);
    }
}

#[test]
fn clear_packets_frame_to_the_rfc() {
    let mut tx = Tx::new();
    let mut wire = Vec::new();
    tx.send(&[0x15], &mut wire).unwrap();
    // 4 + 1 + 1 + padding is a multiple of 8, padding at least 4: 8 bytes of
    // padding is wrong, 6 is right (4 + 1 + 1 + 6 = 12 is not; 4 + 1 + 1 + 10
    // = 16 is): the smallest padding >= 4 that aligns.
    assert_eq!(wire.len() % 8, 0);
    let len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
    assert_eq!(len + 4, wire.len());
    let pad = wire[4] as usize;
    assert!(pad >= 4);
    assert_eq!(wire[5], 0x15);
    // And back.
    let mut rx = Rx::new();
    rx.push(&wire);
    assert_eq!(rx.next().unwrap().unwrap(), [0x15]);
    assert_eq!(rx.next().unwrap(), None);
}

#[test]
fn packets_are_aligned_for_every_payload_length() {
    for n in 1..80usize {
        let mut clear = Vec::new();
        Tx::new().send(&payload(n, 1), &mut clear).unwrap();
        assert_eq!(clear.len() % 8, 0, "clear, payload {n}");
        let mut enc = Vec::new();
        let mut tx = Tx::new();
        tx.set_key(Key::new(&key_material(1)));
        tx.send(&payload(n, 1), &mut enc).unwrap();
        // The length field is outside the alignment: what follows it, up to
        // the tag, is a multiple of 8.
        assert_eq!((enc.len() - 4 - 16) % 8, 0, "chacha, payload {n}");
    }
}

#[test]
fn delivery_one_byte_at_a_time() {
    let mut tx = Tx::new();
    let mut wire = Vec::new();
    let ps: Vec<Vec<u8>> = (1..6).map(|i| payload(i * 13, i as u8)).collect();
    for p in &ps[..2] {
        tx.send(p, &mut wire).unwrap();
    }
    tx.set_key(Key::new(&key_material(2)));
    for p in &ps[2..] {
        tx.send(p, &mut wire).unwrap();
    }
    // The receiver switches to the key after its second packet, as NEWKEYS does.
    let mut rx = Rx::new();
    let mut got = Vec::new();
    for b in &wire {
        rx.push(&[*b]);
        while let Some(p) = rx.next().unwrap() {
            got.push(p);
            if got.len() == 2 {
                rx.set_key(Key::new(&key_material(2)));
            }
        }
    }
    assert_eq!(got, ps);
    assert_eq!(rx.seq(), 5);
}

#[test]
fn a_changed_bit_anywhere_is_refused() {
    let mut tx = Tx::new();
    tx.set_key(Key::new(&key_material(3)));
    let mut wire = Vec::new();
    tx.send(&payload(40, 4), &mut wire).unwrap();
    for i in 0..wire.len() {
        let mut bad = wire.clone();
        bad[i] ^= 0x01;
        let mut rx = Rx::new();
        rx.set_key(Key::new(&key_material(3)));
        rx.push(&bad);
        match rx.next() {
            Ok(Some(_)) => panic!("byte {i} changed and the packet was accepted"),
            Ok(None) | Err(_) => {}
        }
    }
}

#[test]
fn the_wrong_key_or_sequence_is_refused() {
    let mut tx = Tx::new();
    tx.set_key(Key::new(&key_material(3)));
    let mut wire = Vec::new();
    tx.send(&payload(40, 4), &mut wire).unwrap();
    let mut rx = Rx::new();
    rx.set_key(Key::new(&key_material(4)));
    rx.push(&wire);
    assert!(rx.next().is_err());
    // The same packet where the receiver expects number 1.
    let mut tx = Tx::new();
    tx.set_key(Key::new(&key_material(3)));
    let mut w1 = Vec::new();
    tx.send(&payload(1, 1), &mut w1).unwrap();
    let mut w2 = Vec::new();
    tx.send(&payload(40, 4), &mut w2).unwrap();
    let mut rx = Rx::new();
    rx.set_key(Key::new(&key_material(3)));
    rx.push(&w2);
    assert!(rx.next().is_err(), "packet 1 where 0 is expected is a replay or a reorder");
}

#[test]
fn lengths_out_of_range_are_refused_before_any_byte_is_waited_for() {
    // Clear: too long, too short, misaligned, zero.
    for len in [MAX_PACKET as u32 + 1, 0u32, 5, 17, u32::MAX] {
        let mut rx = Rx::new();
        rx.push(&len.to_be_bytes());
        assert!(rx.next().is_err(), "clear length {len}");
    }
    // Encrypted: an all-zero first block decrypts to some length; whatever it
    // is, the receiver does not wait for gigabytes on it.
    let mut rx = Rx::new();
    rx.set_key(Key::new(&key_material(1)));
    rx.push(&[0u8; 4]);
    let r = rx.next();
    assert!(matches!(r, Err(PacketError::Malformed)) || matches!(r, Ok(None)));
    // A valid-looking length in a clear packet waits for its bytes.
    let mut rx = Rx::new();
    rx.push(&12u32.to_be_bytes());
    assert_eq!(rx.next().unwrap(), None);
}

#[test]
fn padding_and_payload_bounds() {
    // padding_length 3 (under the minimum of 4).
    let mut rx = Rx::new();
    let mut v = 12u32.to_be_bytes().to_vec();
    v.extend_from_slice(&[3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    rx.push(&v);
    assert!(rx.next().is_err());
    // padding_length leaves no payload.
    let mut rx = Rx::new();
    let mut v = 12u32.to_be_bytes().to_vec();
    v.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    rx.push(&v);
    assert!(rx.next().is_err());
    // padding_length beyond the packet.
    let mut rx = Rx::new();
    let mut v = 12u32.to_be_bytes().to_vec();
    v.extend_from_slice(&[200, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    rx.push(&v);
    assert!(rx.next().is_err());
}

#[test]
fn oversize_payloads_are_not_sent() {
    let mut out = Vec::new();
    assert!(Tx::new().send(&vec![1u8; MAX_PAYLOAD + 1], &mut out).is_none());
    assert!(out.is_empty());
    assert!(Tx::new().send(&vec![1u8; MAX_PAYLOAD], &mut out).is_some());
}

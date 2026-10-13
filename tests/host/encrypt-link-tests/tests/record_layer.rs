// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RFC-0019 record layer: REJECT, session id, rekey, multi-record messages.
//!
//! The `*_matches_python` tests pin bytes produced by
//! `AzOSRobotBrain/secure_channel.py` with the deterministic hooks: ephemerals
//! `0xAA*32` (initiator) and `0xBB*32` (responder), `PSK = bytes(range(32))`,
//! and one fixed 8-byte nonce prefix per record. The same constants are
//! asserted on the Python side in `AzOSRobotBrain/tests/test_aead_link.py`, so
//! both implementations are held to identical wire bytes.
//!
//! ⚠ Never derive these expectations from the Rust side — see the note in
//! `src/lib.rs`. **To regenerate** (deliberate wire change on BOTH sides):
//! drive `SecureChannel` exactly as the tests below do — the chunked message,
//! then `request_rekey()` + `seal_message(b"after rekey")` on the initiator,
//! then `seal_reject()` on the responder — and paste the hex.

use azos_crypto::sha256::sha256;
use azos_encrypt_link::{
    parse_record_header, session_id, x25519_pubkey, EncryptLink, HandshakeError, Opened,
    RecordError, RecordKind, SealError, SessionIdCache, CONFIRM_BYTES, ENC_MAX_PAYLOAD,
    ENC_OVERHEAD, HELLO_INIT_BYTES, HELLO_REPLY_BYTES, KEY_MATERIAL_BYTES, LABEL_HELLO,
    MAX_MESSAGE_BYTES, MODE_ENCRYPTED, RECORD_FLAG_MORE, RECORD_FLAG_REJECT, RECORD_FLAG_REKEY,
    RECORD_FLAG_RESERVED, RECORD_HEADER_BYTES, REJECT_FRAME, REKEY_MIN_BYTES, REKEY_MIN_RECORDS,
};

const PSK: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const ALICE_PRIV: [u8; 32] = [0xAA; 32];
const BOB_PRIV: [u8; 32] = [0xBB; 32];

// ── Python reference vectors ───────────────────────────────────────────

/// `session_id(alice_pub, bob_pub)`, identical on both ends of the session.
const SESSION_ID_HEX: &str = "a47c3d67bf85ce3a083efe15b20e352c";

/// `seal_message(bytes((i*7+3)&0xFF for i in range(2100)))` with nonce
/// prefixes 01..08 and 11..18: a MORE record (2048 B) + a DATA record (52 B).
const CHUNKED_LEN: usize = 2192;
const CHUNKED_SHA256_HEX: &str =
    "39805581f43d257e457bb56766d1a61c20e45235aeee388d46c5be2c6d149b8a";
/// Record 0 header: nonce, counter 0, field 0x1800 = MORE | 2048.
const CHUNKED_HEAD0_HEX: &str = "0102030405060708000000000018";
/// Record 1 header: nonce, counter 1, field 0x0034 = DATA | 52.
const CHUNKED_HEAD1_HEX: &str = "1112131415161718010000003400";

/// After the chunked message: `request_rekey()` then
/// `seal_message(b"after rekey")`, nonce prefixes 21..28 and 31..38. A REKEY
/// record (counter 2, gen 0 keys) + a DATA record (counter 3, gen 1 keys).
const REKEY_THEN_DATA_HEX: &str = concat!(
    "2122232425262728", "02000000", "0020",
    "455db8e142bc44d0f7b233d47cfe5791ea1ee773b07076e00953c1120165805c",
    "3132333435363738", "03000000", "0b00",
    "5e769c20645d4064b9754cae2d0aac0fa5ec90b03501577c8421ab",
    "f2ec3427ce04403117a328d19120f3a7",
);

/// Responder `seal_reject()` with nonce prefix 41..48 as its first S2C record.
const REJECT_S2C_HEX: &str = concat!(
    "4142434445464748", "00000000", "0040",
    "381f7dc1ef052a5ea1cb8598001f220f7eb62979ea0329c6780f50e153acdd14",
);

// ── Helpers ────────────────────────────────────────────────────────────

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn prefix(start: u8) -> [u8; 8] {
    core::array::from_fn(|i| start + i as u8)
}

/// Nonce source yielding the given prefixes in order.
fn nonces(list: &[[u8; 8]]) -> impl FnMut() -> [u8; 8] + '_ {
    let mut it = list.iter();
    move || *it.next().expect("more records than nonce prefixes")
}

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
    (alice, bob)
}

fn chunked_message() -> Vec<u8> {
    (0..2100usize).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect()
}

fn seal(link: &mut EncryptLink, msg: &[u8], list: &[[u8; 8]]) -> Vec<u8> {
    let mut out = vec![0u8; azos_encrypt_link::sealed_len_max(msg.len())];
    let n = link.seal_message(msg, nonces(list), &mut out).unwrap();
    out.truncate(n);
    out
}

/// Read a byte stream the way the kernel does: records may arrive split at
/// any byte, the unconsumed tail is carried to the next read. Returns every
/// completed message.
fn read_stream(link: &mut EncryptLink, wire: &[u8], split: usize) -> Result<Vec<Vec<u8>>, RecordError> {
    let mut carry: Vec<u8> = Vec::new();
    let mut message: Vec<u8> = Vec::new();
    let mut done = Vec::new();
    let mut payload = vec![0u8; ENC_MAX_PAYLOAD];
    for chunk in wire.chunks(split) {
        carry.extend_from_slice(chunk);
        let mut off = 0;
        loop {
            match link.open_record(&carry[off..], &mut payload) {
                Ok(Opened { kind: RecordKind::Data { len, more }, consumed }) => {
                    message.extend_from_slice(&payload[..len]);
                    if !more {
                        done.push(core::mem::take(&mut message));
                    }
                    off += consumed;
                }
                Ok(Opened { kind: RecordKind::Rekey, consumed }) => off += consumed,
                Err(RecordError::Incomplete) => break,
                Err(e) => return Err(e),
            }
        }
        carry.drain(..off);
    }
    assert!(carry.is_empty(), "stream ended inside a record");
    Ok(done)
}

/// Does `needle` occur anywhere in `hay`?
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ── Session id ─────────────────────────────────────────────────────────

#[test]
fn session_id_matches_python() {
    let (alice, bob) = established_pair();
    let expected = hex(SESSION_ID_HEX);
    assert_eq!(alice.session_id().unwrap().to_vec(), expected);
    assert_eq!(bob.session_id().unwrap().to_vec(), expected);
    let a_pub = x25519_pubkey(&ALICE_PRIV);
    let b_pub = x25519_pubkey(&BOB_PRIV);
    assert_eq!(session_id(&a_pub, &b_pub).to_vec(), expected);
    // Order matters: initiator first.
    assert_ne!(session_id(&b_pub, &a_pub).to_vec(), expected);
}

#[test]
fn session_id_cache_refuses_a_repeat_and_evicts_the_oldest() {
    let mut cache: SessionIdCache<2> = SessionIdCache::new();
    let (a, b, c) = ([1u8; 16], [2u8; 16], [3u8; 16]);
    assert!(cache.insert_if_new(&a));
    assert!(!cache.insert_if_new(&a), "repeated session id accepted");
    assert!(cache.insert_if_new(&b));
    assert!(cache.insert_if_new(&c)); // evicts `a`
    assert!(!cache.insert_if_new(&b));
    assert!(!cache.insert_if_new(&c));
    assert!(cache.insert_if_new(&a), "capacity bound not honoured");
}

// ── Handshake REJECT ───────────────────────────────────────────────────

#[test]
fn reject_frame_is_the_rfc_bytes() {
    assert_eq!(REJECT_FRAME, [0x02, 0x52]);
}

#[test]
fn initiator_takes_a_reject_in_place_of_the_hello_reply() {
    let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
    let mut hello = [0u8; HELLO_INIT_BYTES];
    alice.start_initiator(&mut hello).unwrap();
    let mut confirm = [0u8; CONFIRM_BYTES];
    assert_eq!(alice.handle_peer_hello(&REJECT_FRAME, &mut confirm), Err(HandshakeError::PeerRejected));
    assert!(alice.is_rejected());
    assert_eq!(alice.session_id(), None);
}

#[test]
fn responder_takes_a_reject_in_place_of_the_confirm() {
    let mut alice = EncryptLink::new(PSK, ALICE_PRIV);
    let mut bob = EncryptLink::new(PSK, BOB_PRIV);
    let mut hello = [0u8; HELLO_INIT_BYTES];
    alice.start_initiator(&mut hello).unwrap();
    let mut reply = [0u8; HELLO_REPLY_BYTES];
    bob.handle_initiator_hello(&hello, &mut reply).unwrap();
    assert_eq!(bob.handle_initiator_confirm(&REJECT_FRAME), Err(HandshakeError::PeerRejected));
    assert!(bob.is_rejected());
}

#[test]
fn every_peer_driven_handshake_failure_is_terminal() {
    // A caller sends REJECT_FRAME for all of these; that only happens if the
    // link actually went terminal rather than staying retryable.
    let mut bob = EncryptLink::new(PSK, BOB_PRIV);
    let mut reply = [0u8; HELLO_REPLY_BYTES];
    assert_eq!(bob.handle_initiator_hello(&[0x02, 0x48, 0x00], &mut reply), Err(HandshakeError::BadFrameLength));
    assert!(bob.is_rejected());

    let mut bob = EncryptLink::new(PSK, BOB_PRIV);
    let mut bad = [0u8; HELLO_INIT_BYTES];
    bad[0] = 0x01; // AUTH_HMAC mode byte
    bad[1] = LABEL_HELLO;
    assert_eq!(bob.handle_initiator_hello(&bad, &mut reply), Err(HandshakeError::BadHeader));
    assert!(bob.is_rejected());

    // Our own ephemeral reflected back as the peer's.
    let mut bob = EncryptLink::new(PSK, BOB_PRIV);
    let mut mirror = [0u8; HELLO_INIT_BYTES];
    mirror[0] = MODE_ENCRYPTED;
    mirror[1] = LABEL_HELLO;
    mirror[2..].copy_from_slice(&x25519_pubkey(&BOB_PRIV));
    assert_eq!(bob.handle_initiator_hello(&mirror, &mut reply), Err(HandshakeError::BadPeerKey));
    assert!(bob.is_rejected());
}

// ── Multi-record messages ──────────────────────────────────────────────

#[test]
fn chunked_message_matches_python() {
    let (mut alice, mut bob) = established_pair();
    let msg = chunked_message();
    let wire = seal(&mut alice, &msg, &[prefix(0x01), prefix(0x11)]);
    assert_eq!(wire.len(), CHUNKED_LEN, "chunked message length drift");
    assert_eq!(to_hex(&wire[..RECORD_HEADER_BYTES]), CHUNKED_HEAD0_HEX);
    let second = ENC_OVERHEAD + ENC_MAX_PAYLOAD;
    assert_eq!(to_hex(&wire[second..second + RECORD_HEADER_BYTES]), CHUNKED_HEAD1_HEX);
    assert_eq!(to_hex(&sha256(&wire)), CHUNKED_SHA256_HEX, "chunked message bytes drift from Python");

    let mut out = vec![0u8; ENC_MAX_PAYLOAD];
    let r0 = bob.open_record(&wire, &mut out).unwrap();
    assert_eq!(r0, Opened { kind: RecordKind::Data { len: 2048, more: true }, consumed: second });
    assert_eq!(&out[..2048], &msg[..2048]);
    let r1 = bob.open_record(&wire[second..], &mut out).unwrap();
    assert_eq!(r1, Opened { kind: RecordKind::Data { len: 52, more: false }, consumed: wire.len() - second });
    assert_eq!(&out[..52], &msg[2048..]);
}

#[test]
fn a_message_survives_any_split_of_the_stream() {
    // The kernel reads a byte stream in arbitrary pieces. Every split size
    // from 1 byte up must recover exactly the messages that were sealed,
    // across a MORE chain and a REKEY.
    for split in [1usize, 7, 13, 46, 97, 2048, 5000] {
        let (mut alice, mut bob) = established_pair();
        let big: Vec<u8> = (0..MAX_MESSAGE_BYTES).map(|i| (i % 251) as u8).collect();
        let mut wire = seal(&mut alice, b"first", &[[1; 8]]);
        wire.extend(seal(&mut alice, &big, &[[2; 8]; 8]));
        alice.request_rekey();
        wire.extend(seal(&mut alice, b"ESTOP", &[[3; 8]; 2]));
        let got = read_stream(&mut bob, &wire, split).unwrap();
        assert_eq!(got.len(), 3, "split {split}");
        assert_eq!(got[0], b"first");
        assert_eq!(got[1], big);
        assert_eq!(got[2], b"ESTOP");
        assert_eq!(bob.rx_generation(), 1);
    }
}

#[test]
fn a_torn_record_is_incomplete_and_changes_nothing() {
    let (mut alice, mut bob) = established_pair();
    let wire = seal(&mut alice, b"ACTUATOR", &[[9; 8]]);
    let mut out = [0u8; 64];
    for cut in [0, 5, RECORD_HEADER_BYTES, wire.len() - 1] {
        assert_eq!(bob.open_record(&wire[..cut], &mut out), Err(RecordError::Incomplete));
        assert!(bob.is_established());
    }
    let r = bob.open_record(&wire, &mut out).unwrap();
    assert_eq!(r.kind, RecordKind::Data { len: 8, more: false });
}

/// **Nonce-prefix reuse (a broken/predictable caller-supplied RNG) does not
/// reuse the actual AEAD keystream, and both records still decrypt.**
///
/// `nonce_fn` is caller-supplied (see the crate's "Entropy" module docs: this
/// crate is pure and does not collect entropy itself). A caller with a weak
/// or stuck RNG could hand back the SAME 8-byte prefix for consecutive
/// records — this test is what stops that from being catastrophic: the
/// per-record monotonic counter is folded into the real AEAD nonce
/// independently of the prefix (U06's audit finding, "counter inside the
/// nonce so keystream uniqueness does not depend on nonce_rand"), so two
/// records sharing a wire nonce_rand still get distinct ciphertexts and both
/// decrypt correctly on the receiving end.
///
/// RED if the counter stopped being part of the nonce: the two ciphertexts
/// below would be byte-identical (same key, same "nonce", same message
/// content pattern reused via XOR) and `open_record` on the second one
/// would either fail its counter-monotonicity check for the wrong reason or
/// (worse, if that check were also gone) silently accept a replay.
#[test]
fn a_reused_nonce_prefix_still_gets_distinct_records_that_both_decrypt() {
    let (mut alice, mut bob) = established_pair();
    let stuck_prefix = [0x55u8; 8]; // simulates a caller RNG stuck on one value

    let wire0 = seal(&mut alice, b"first message", &[stuck_prefix]);
    let wire1 = seal(&mut alice, b"second message", &[stuck_prefix]);

    // Same wire `nonce_rand` field on both records (the RNG really is stuck).
    assert_eq!(&wire0[..8], &stuck_prefix[..]);
    assert_eq!(&wire1[..8], &stuck_prefix[..]);
    // The counter field (bytes 8..12 of the header) must differ — that is
    // what keeps the real AEAD nonce unique.
    assert_ne!(&wire0[8..12], &wire1[8..12],
        "the per-record counter must advance even when nonce_rand does not");
    // And the ciphertexts themselves must differ throughout, not just in
    // the header — same key, same nonce_rand: only a distinct effective
    // nonce (via the counter) can produce this.
    assert_ne!(wire0, wire1);

    let mut out = [0u8; 64];
    let r0 = bob.open_record(&wire0, &mut out).unwrap();
    let RecordKind::Data { len: len0, .. } = r0.kind else { panic!("expected Data") };
    assert_eq!(&out[..len0], b"first message");
    let r1 = bob.open_record(&wire1, &mut out).unwrap();
    let RecordKind::Data { len: len1, .. } = r1.kind else { panic!("expected Data") };
    assert_eq!(&out[..len1], b"second message");
}

#[test]
fn a_flags_zero_record_is_the_single_record_frame() {
    // `seal_message` of a short message and `encrypt` must put the same
    // bytes on the wire, which is what keeps the generation-0 pins in
    // src/lib.rs meaningful for the new path.
    let (mut a1, _b1) = established_pair();
    let (mut a2, _b2) = established_pair();
    let via_message = seal(&mut a1, b"sensor frame", &[prefix(0x01)]);
    let mut via_encrypt = vec![0u8; 12 + ENC_OVERHEAD];
    let n = a2.encrypt(b"sensor frame", &prefix(0x01), &mut via_encrypt);
    assert_eq!(via_message, via_encrypt[..n]);
}

#[test]
fn seal_refuses_an_oversize_message_or_a_short_buffer_without_side_effects() {
    let (mut alice, mut bob) = established_pair();
    let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
    let mut out = vec![0u8; azos_encrypt_link::sealed_len_max(big.len())];
    assert_eq!(alice.seal_message(&big, || [0; 8], &mut out), Err(SealError::MessageTooLarge));
    let mut short = vec![0u8; ENC_OVERHEAD + 2];
    assert_eq!(alice.seal_message(b"abc", || [0; 8], &mut short), Err(SealError::BufferTooSmall));
    // Counter untouched: the next record is counter 0 and opens.
    let wire = seal(&mut alice, b"abc", &[[4; 8]]);
    let mut buf = [0u8; 8];
    assert!(bob.open_record(&wire, &mut buf).is_ok());
}

#[test]
fn record_header_rules() {
    let head = |field: u16| {
        let mut h = [0u8; RECORD_HEADER_BYTES];
        h[12..].copy_from_slice(&field.to_le_bytes());
        h
    };
    assert_eq!(parse_record_header(&head(5)), Ok((0, 5)));
    assert_eq!(parse_record_header(&head(RECORD_FLAG_MORE | 2048)), Ok((RECORD_FLAG_MORE, 2048)));
    assert_eq!(parse_record_header(&head(RECORD_FLAG_REKEY)), Ok((RECORD_FLAG_REKEY, 0)));
    assert_eq!(parse_record_header(&head(RECORD_FLAG_REJECT)), Ok((RECORD_FLAG_REJECT, 0)));
    for bad in [
        2049,
        RECORD_FLAG_RESERVED | 5,
        RECORD_FLAG_MORE | 100,
        RECORD_FLAG_REKEY | 1,
        RECORD_FLAG_REJECT | 1,
        RECORD_FLAG_REKEY | RECORD_FLAG_REJECT,
        RECORD_FLAG_MORE | RECORD_FLAG_REKEY,
    ] {
        assert_eq!(parse_record_header(&head(bad)), Err(RecordError::BadHeader), "field {bad:#06x}");
    }
    assert_eq!(parse_record_header(&[0u8; 13]), Err(RecordError::Incomplete));
}

// ── Rekey ──────────────────────────────────────────────────────────────

#[test]
fn rekey_record_and_next_generation_match_python() {
    let (mut alice, mut bob) = established_pair();
    let first = seal(&mut alice, &chunked_message(), &[prefix(0x01), prefix(0x11)]);
    assert_eq!(read_stream(&mut bob, &first, first.len()).unwrap().len(), 1);

    alice.request_rekey();
    let wire = seal(&mut alice, b"after rekey", &[prefix(0x21), prefix(0x31)]);
    assert_eq!(to_hex(&wire), REKEY_THEN_DATA_HEX, "REKEY / generation-1 bytes drift from Python");
    assert_eq!(alice.tx_generation(), 1);

    let mut out = [0u8; 32];
    let r = bob.open_record(&wire, &mut out).unwrap();
    assert_eq!(r.kind, RecordKind::Rekey);
    let d = bob.open_record(&wire[r.consumed..], &mut out).unwrap();
    assert_eq!(d.kind, RecordKind::Data { len: 11, more: false });
    assert_eq!(&out[..11], b"after rekey");
    assert_eq!(bob.rx_generation(), 1);
}

#[test]
fn record_replayed_across_the_rekey_boundary_is_refused() {
    let (mut alice, mut bob) = established_pair();
    let before = seal(&mut alice, b"FORWARD 100", &[[1; 8]]);
    alice.request_rekey();
    let after = seal(&mut alice, b"STOP", &[[2; 8], [3; 8]]);
    let got = read_stream(&mut bob, &[before.clone(), after].concat(), 4096).unwrap();
    assert_eq!(got, vec![b"FORWARD 100".to_vec(), b"STOP".to_vec()]);

    // The generation-0 record, captured and injected after the rekey: its
    // MAC is under a key bob no longer holds.
    let mut out = [0u8; 64];
    assert_eq!(bob.open_record(&before, &mut out), Err(RecordError::BadMac));
    assert!(bob.is_rejected(), "a replay across the rekey left the session open");
}

#[test]
fn record_replayed_inside_a_generation_is_refused() {
    let (mut alice, mut bob) = established_pair();
    let wire = seal(&mut alice, b"FORWARD 100", &[[1; 8]]);
    let mut out = [0u8; 64];
    assert!(bob.open_record(&wire, &mut out).is_ok());
    assert_eq!(bob.open_record(&wire, &mut out), Err(RecordError::BadCounter));
    assert!(bob.is_rejected());
}

#[test]
fn record_and_byte_limits_trigger_a_rekey_on_both_ends() {
    let (mut alice, mut bob) = established_pair();
    alice.set_rekey_limits(REKEY_MIN_RECORDS, REKEY_MIN_BYTES);
    bob.set_rekey_limits(REKEY_MIN_RECORDS, REKEY_MIN_BYTES);

    // Record trigger: one-record messages; the generation closes once its
    // records plus the REKEY would pass the limit.
    let mut wire = Vec::new();
    for i in 0..40u8 {
        wire.extend(seal(&mut alice, &[i; 10], &[[i; 8], [i; 8]]));
    }
    let got = read_stream(&mut bob, &wire, 333).unwrap();
    assert_eq!(got.len(), 40);
    let per_gen = (REKEY_MIN_RECORDS - 1) as u64; // data records per generation
    assert_eq!(alice.tx_generation(), 40 / per_gen - if 40 % per_gen == 0 { 1 } else { 0 });
    assert_eq!(bob.rx_generation(), alice.tx_generation());

    // Byte trigger: each full-size message fills a generation by itself.
    let big = vec![0x5Au8; MAX_MESSAGE_BYTES];
    let g0 = alice.tx_generation();
    let mut wire = Vec::new();
    for _ in 0..3 {
        wire.extend(seal(&mut alice, &big, &[[7; 8]; 9]));
    }
    assert_eq!(read_stream(&mut bob, &wire, 1500).unwrap().len(), 3);
    assert_eq!(alice.tx_generation(), g0 + 3);
    assert_eq!(bob.rx_generation(), alice.tx_generation());
}

#[test]
fn a_peer_that_skips_the_rekey_is_refused() {
    let (mut alice, mut bob) = established_pair();
    bob.set_rekey_limits(REKEY_MIN_RECORDS, REKEY_MIN_BYTES); // alice keeps the maxima
    let mut out = [0u8; 16];
    for i in 0..REKEY_MIN_RECORDS {
        let wire = seal(&mut alice, &[1, 2, 3], &[[i as u8; 8]]);
        assert!(bob.open_record(&wire, &mut out).is_ok(), "record {i}");
    }
    let wire = seal(&mut alice, &[1, 2, 3], &[[0xEE; 8]]);
    assert_eq!(bob.open_record(&wire, &mut out), Err(RecordError::RekeyOverdue));
    assert!(bob.is_rejected());
}

#[test]
fn a_rekey_erases_the_previous_generation() {
    let (mut alice, mut bob) = established_pair();
    let km = alice.key_material();
    assert_eq!(km.len(), KEY_MATERIAL_BYTES);
    assert_eq!(&km[..32], &[0u8; 32], "ephemeral private key kept after the handshake");
    let old_tx = km[32..96].to_vec(); // chain | enc | mac

    alice.request_rekey();
    let wire = seal(&mut alice, b"x", &[[1; 8], [2; 8]]);
    let after = alice.key_material();
    for (name, window) in [("chain", &old_tx[..32]), ("enc", &old_tx[32..48]), ("mac", &old_tx[48..64])] {
        assert!(!contains(&after, window), "generation-0 tx {name} still held after the rekey");
    }

    let rx_before = bob.key_material()[96..160].to_vec();
    assert_eq!(read_stream(&mut bob, &wire, wire.len()).unwrap().len(), 1);
    let rx_after = bob.key_material();
    for (name, window) in [("chain", &rx_before[..32]), ("enc", &rx_before[32..48]), ("mac", &rx_before[48..64])] {
        assert!(!contains(&rx_after, window), "generation-0 rx {name} still held after the rekey");
    }
}

// ── In-session REJECT ──────────────────────────────────────────────────

#[test]
fn reject_record_matches_python_and_ends_both_ends() {
    let (mut alice, mut bob) = established_pair();
    let mut rec = [0u8; ENC_OVERHEAD];
    assert_eq!(bob.seal_reject(&prefix(0x41), &mut rec), ENC_OVERHEAD);
    assert_eq!(to_hex(&rec), REJECT_S2C_HEX, "REJECT record bytes drift from Python");
    assert!(bob.is_rejected());
    assert_eq!(bob.seal_reject(&prefix(0x41), &mut rec), 0, "a second REJECT was sealed");

    let mut out = [0u8; 8];
    assert_eq!(alice.open_record(&rec, &mut out), Err(RecordError::PeerRejected));
    assert!(alice.is_rejected());
    let mut buf = [0u8; 128];
    assert_eq!(alice.seal_message(b"more", || [0; 8], &mut buf), Err(SealError::NotEstablished));
    assert_eq!(alice.seal_reject(&[0; 8], &mut buf), 0, "answered a REJECT with a REJECT");
}

#[test]
fn a_violation_leaves_exactly_one_reject_to_send() {
    let (mut alice, mut bob) = established_pair();
    let mut wire = seal(&mut alice, b"CONFIG", &[[1; 8]]);
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    let mut out = [0u8; 16];
    assert_eq!(bob.open_record(&wire, &mut out), Err(RecordError::BadMac));
    assert!(bob.is_rejected());
    assert_eq!(bob.open_record(&wire, &mut out), Err(RecordError::NotEstablished));

    let mut rec = [0u8; ENC_OVERHEAD];
    assert_eq!(bob.seal_reject(&[5; 8], &mut rec), ENC_OVERHEAD);
    assert_eq!(alice.open_record(&rec, &mut out), Err(RecordError::PeerRejected));
    assert_eq!(bob.seal_reject(&[5; 8], &mut rec), 0);
}

#[test]
fn a_flag_bit_flipped_on_the_wire_is_refused() {
    let (mut alice, mut bob) = established_pair();
    let mut wire = seal(&mut alice, &[0u8; 2048], &[[1; 8]]);
    // DATA|2048 -> MORE|2048: a valid header, so only the MAC can catch it.
    wire[13] |= (RECORD_FLAG_MORE >> 8) as u8;
    let mut out = [0u8; 2048];
    assert_eq!(bob.open_record(&wire, &mut out), Err(RecordError::BadMac));
}

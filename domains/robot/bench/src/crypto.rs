// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cryptography subsystem microbenchmarks.
//!
//! SHA-256, X25519 scalarmult, AES-128-CTR.  All pure compute, no I/O —
//! good signal under TCG since rdcycle inflation is amortised over the
//! hot loop.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_crypto::{sha256, x25519, aes};
use azos_crypto::secure_channel::SecureChannel;

/// SHA-256 over a 64-byte payload (one full block).
pub fn bench_sha256_64B(iters: u64) -> BenchResult {
    let data = [0xA5u8; 64];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = sha256::sha256(&data);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// SHA-256 over a 1024-byte payload (16 blocks).
pub fn bench_sha256_1K(iters: u64) -> BenchResult {
    let data = [0x5Au8; 1024];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = sha256::sha256(&data);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// X25519 scalarmult — the expensive primitive in the secure_channel
/// handshake.  Single iter per call (no inner loop) so total reflects
/// per-op cost directly.
pub fn bench_x25519_scalarmult(iters: u64) -> BenchResult {
    let scalar: [u8; 32] = [0x01; 32];
    let point:  [u8; 32] = [0x02; 32];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = x25519::x25519(&scalar, &point);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// AES-128 single-block encryption.  Core building block of AES-CTR.
pub fn bench_aes128_encrypt_block(iters: u64) -> BenchResult {
    let key: [u8; 16] = [0x55; 16];
    let cipher = aes::Aes128::new(&key);
    let mut block: [u8; 16] = [0xAA; 16];

    let start = read_cycles();
    for _ in 0..iters {
        cipher.encrypt_block(&mut block);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// AES-128-CTR over 64-byte payload (full RFC-0019 packet shape).
pub fn bench_aes128_ctr_64B(iters: u64) -> BenchResult {
    let key:   [u8; 16] = [0x77; 16];
    let nonce: [u8; 12] = [0x11; 12];
    let cipher = aes::Aes128::new(&key);
    let mut data: [u8; 64] = [0x42; 64];

    let start = read_cycles();
    for _ in 0..iters {
        cipher.ctr_encrypt(&nonce, &mut data);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// AES-128 key schedule — `Aes128::new`.  Run once per encrypt/decrypt in
/// the current secure_channel design (no key caching), so its cost is paid
/// per packet; worth isolating from the block-cipher cost above.
pub fn bench_aes128_key_schedule(iters: u64) -> BenchResult {
    let key: [u8; 16] = [0x33; 16];

    let start = read_cycles();
    for _ in 0..iters {
        let cipher = aes::Aes128::new(&key);
        let _ = core::hint::black_box(&cipher);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// Two fixed 32-byte private keys for a deterministic handshake pair.
/// Not secrets — bench scaffolding only.
const SC_PRIV_A: [u8; 32] = [0x11; 32];
const SC_PRIV_B: [u8; 32] = [0x22; 32];

/// `SecureChannel::handshake` (RFC-0019) — X25519 scalarmult + 2× SHA-256
/// HMAC-style KDF.  This is the once-per-session cost; dominated by the
/// X25519 op but measured end-to-end including key derivation.
pub fn bench_sc_handshake(iters: u64) -> BenchResult {
    let peer = SecureChannel::new(SC_PRIV_B);
    let peer_pub = peer.public_key;

    let start = read_cycles();
    for _ in 0..iters {
        let mut ch = SecureChannel::new(SC_PRIV_A);
        ch.handshake(&peer_pub);
        let _ = core::hint::black_box(&ch);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// Build an established channel pair (A↔B) for the per-packet benches.
fn established_pair() -> (SecureChannel, SecureChannel) {
    let mut a = SecureChannel::new(SC_PRIV_A);
    let mut b = SecureChannel::new(SC_PRIV_B);
    let a_pub = a.public_key;
    let b_pub = b.public_key;
    a.handshake(&b_pub);
    b.handshake(&a_pub);
    (a, b)
}

/// `SecureChannel::encrypt` over a 64-byte payload — AES-128-CTR + key
/// schedule + HMAC-SHA-256 over the ciphertext.  The per-packet TX cost.
pub fn bench_sc_encrypt_64B(iters: u64) -> BenchResult {
    let (mut a, _b) = established_pair();
    if a.state != azos_crypto::secure_channel::ChannelState::Established {
        return BenchResult::from_total(0, 0, 0);
    }
    let plaintext = [0x42u8; 64];
    let nonce_rand = [0x01u8; 8];
    let mut out = [0u8; 64 + azos_crypto::secure_channel::PACKET_OVERHEAD];

    let start = read_cycles();
    for _ in 0..iters {
        // tx_counter increments each iter (no wrap over 1000); fresh nonce.
        let _ = a.encrypt(&plaintext, &nonce_rand, &mut out);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `SecureChannel::decrypt` over a 64-byte packet — HMAC verify (constant-
/// time) + AES-128-CTR.  The per-packet RX cost.  Pre-build one valid
/// packet outside the loop and decrypt it repeatedly.
pub fn bench_sc_decrypt_64B(iters: u64) -> BenchResult {
    let (mut a, b) = established_pair();
    if b.state != azos_crypto::secure_channel::ChannelState::Established {
        return BenchResult::from_total(0, 0, 0);
    }
    let plaintext = [0x42u8; 64];
    let nonce_rand = [0x01u8; 8];
    let mut packet = [0u8; 64 + azos_crypto::secure_channel::PACKET_OVERHEAD];
    let n = a.encrypt(&plaintext, &nonce_rand, &mut packet);
    if n == 0 {
        return BenchResult::from_total(0, 0, 0);
    }
    let mut out = [0u8; 64];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = b.decrypt(&packet[..n], &mut out);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("crypto.sha256_64B",          &best_of(|| bench_sha256_64B(iters)));          n += 1;
    report("crypto.sha256_1K",           &best_of(|| bench_sha256_1K(iters)));           n += 1;
    report("crypto.x25519_scalarmult",   &best_of(|| bench_x25519_scalarmult(iters)));   n += 1;
    report("crypto.aes128_encrypt_block", &best_of(|| bench_aes128_encrypt_block(iters))); n += 1;
    report("crypto.aes128_ctr_64B",      &best_of(|| bench_aes128_ctr_64B(iters)));      n += 1;
    report("crypto.aes128_key_schedule", &best_of(|| bench_aes128_key_schedule(iters))); n += 1;
    report("crypto.sc_handshake",        &best_of(|| bench_sc_handshake(iters)));        n += 1;
    report("crypto.sc_encrypt_64B",      &best_of(|| bench_sc_encrypt_64B(iters)));      n += 1;
    report("crypto.sc_decrypt_64B",      &best_of(|| bench_sc_decrypt_64B(iters)));      n += 1;
    n
}

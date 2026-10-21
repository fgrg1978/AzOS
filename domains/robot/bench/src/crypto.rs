// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cryptography subsystem microbenchmarks.
//!
//! SHA-256, X25519 scalarmult, AES-128-CTR, the brain link's Noise handshake
//! and transport.  All pure compute, no I/O —
//! good signal under TCG since rdcycle inflation is amortised over the
//! hot loop.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_crypto::{sha256, x25519, aes};
use azos_crypto::noise::{CipherState, HandshakeState, Pattern};
use azos_crypto::secure_channel::{
    max_body_for, Initiator, Link, FRAME_HEAD, FRAME_OVERHEAD, HANDSHAKE_OUT_MAX, PATTERN_IK,
    PROLOGUE_LABEL,
};

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

/// AES-128-CTR over 64-byte payload (full encrypted-link packet shape).
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

/// The link key and the brain's static key of the benched handshake pair.
/// Not secrets -- bench scaffolding only.
const SC_PSK: [u8; 32] = [0x11; 32];
const SC_BRAIN_SK: [u8; 32] = [0x22; 32];
/// Fixed ephemerals of the two sides.
const SC_E_ROBOT: [u8; 32] = [0x33; 32];
const SC_E_BRAIN: [u8; 32] = [0x44; 32];

/// The brain's half of an IK handshake against the robot's first message,
/// computed once: the reply frame and the brain's transport send cipher.
struct BrainSide {
    reply: [u8; 2 + 48],
    send: Option<CipherState>,
}

fn brain_side(first: &[u8]) -> Option<BrainSide> {
    let mut hs = HandshakeState::responder(Pattern::Ik, &SC_BRAIN_SK, &prologue_ik()).ok()?;
    hs.read_message(&first[1 + FRAME_HEAD..], &mut []).ok()?;
    let mut msg = [0u8; 48];
    let n = hs.write_message(&SC_E_BRAIN, &[], &mut msg).ok()?;
    let mut reply = [0u8; 2 + 48];
    reply[..2].copy_from_slice(&(n as u16).to_be_bytes());
    reply[2..2 + n].copy_from_slice(&msg[..n]);
    let mut t = hs.finish().ok()?;
    let send = core::mem::replace(&mut t.send, CipherState::empty());
    Some(BrainSide { reply, send: Some(send) })
}

fn prologue_ik() -> [u8; PROLOGUE_LABEL.len() + 1] {
    let mut p = [0u8; PROLOGUE_LABEL.len() + 1];
    p[..PROLOGUE_LABEL.len()].copy_from_slice(PROLOGUE_LABEL);
    p[PROLOGUE_LABEL.len()] = PATTERN_IK;
    p
}

/// The robot's half of an IK handshake: its first message and, once the
/// brain's reply is fed, the established link.
fn robot_handshake(reply: Option<&[u8]>, first_out: &mut [u8; HANDSHAKE_OUT_MAX]) -> Option<Link> {
    let pinned = x25519::x25519_pubkey(&SC_BRAIN_SK);
    let mut ini = Initiator::new(&SC_PSK, Some(&pinned)).ok()?;
    ini.step(None, &SC_E_ROBOT, first_out).ok()?;
    let mut scratch = [0u8; HANDSHAKE_OUT_MAX];
    ini.step(reply, &SC_E_ROBOT, &mut scratch).ok()?;
    ini.finish().ok()
}

/// A robot link and the brain's send cipher for the per-packet benches.
fn established_pair() -> Option<(Link, CipherState)> {
    let mut first = [0u8; HANDSHAKE_OUT_MAX];
    // Pass 1 learns the first message, pass 2 feeds the brain's reply to a
    // fresh initiator that sends the very same bytes (fixed ephemeral).
    let pinned = x25519::x25519_pubkey(&SC_BRAIN_SK);
    let mut ini = Initiator::new(&SC_PSK, Some(&pinned)).ok()?;
    let n = ini.step(None, &SC_E_ROBOT, &mut first).ok()?;
    let mut brain = brain_side(&first[..n])?;
    let mut scratch = [0u8; HANDSHAKE_OUT_MAX];
    ini.step(Some(&brain.reply), &SC_E_ROBOT, &mut scratch).ok()?;
    Some((ini.finish().ok()?, brain.send.take()?))
}

/// The robot's side of one IK handshake: initiator setup (static key
/// derivation), message 1, message 2, split. Two X25519 scalar mults for the
/// ephemeral and static DHs on each of the two messages plus the key
/// derivation's base-point mult: the once-per-session cost, dominated by
/// X25519 but measured end-to-end.
pub fn bench_sc_handshake(iters: u64) -> BenchResult {
    let mut first = [0u8; HANDSHAKE_OUT_MAX];
    let pinned = x25519::x25519_pubkey(&SC_BRAIN_SK);
    let Some(mut probe) = Initiator::new(&SC_PSK, Some(&pinned)).ok() else {
        return BenchResult::from_total(0, 0, 0);
    };
    let Some(n) = probe.step(None, &SC_E_ROBOT, &mut first).ok() else {
        return BenchResult::from_total(0, 0, 0);
    };
    let Some(brain) = brain_side(&first[..n]) else {
        return BenchResult::from_total(0, 0, 0);
    };

    let start = read_cycles();
    for _ in 0..iters {
        let l = robot_handshake(Some(&brain.reply), &mut first);
        let _ = core::hint::black_box(&l);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `Link::seal_message` over a 64-byte payload: ChaCha20-Poly1305 plus the
/// framing. The per-packet TX cost.
pub fn bench_sc_encrypt_64B(iters: u64) -> BenchResult {
    let Some((mut a, _b)) = established_pair() else {
        return BenchResult::from_total(0, 0, 0);
    };
    let plaintext = [0x42u8; 64];
    let mut out = [0u8; 64 + 2 * FRAME_OVERHEAD];

    let start = read_cycles();
    for _ in 0..iters {
        // The nonce is the message counter; rekeys land every 2^20 messages.
        let _ = a.seal_message(&plaintext, &mut out);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// Frames per round of the receive bench: the transport refuses a repeated
/// frame, so every open needs a frame of its own.
const SC_RX_ROUND: usize = 32;

/// `Link::open_frame` over a 64-byte message: AEAD tag check and decrypt in
/// place. The per-packet RX cost. Rounds of `SC_RX_ROUND` pre-sealed frames;
/// a fresh pair per round, outside the timed span.
pub fn bench_sc_decrypt_64B(iters: u64) -> BenchResult {
    const FRAME: usize = 64 + FRAME_OVERHEAD;
    let plaintext = [0x42u8; 64];
    let mut total = 0u64;
    let mut done = 0u64;
    while done < iters {
        let Some((mut a, mut brain)) = established_pair() else {
            return BenchResult::from_total(0, 0, 0);
        };
        let mut frames = [[0u8; FRAME]; SC_RX_ROUND];
        for f in frames.iter_mut() {
            let head = ((64 + 16) as u16).to_be_bytes();
            f[..2].copy_from_slice(&head);
            f[2..66].copy_from_slice(&plaintext);
            match brain.encrypt(&head, &mut f[2..66]) {
                Ok(tag) => f[66..].copy_from_slice(&tag),
                Err(_) => return BenchResult::from_total(0, 0, 0),
            }
        }
        let round = ((iters - done) as usize).min(SC_RX_ROUND);
        let t0 = read_cycles();
        for f in frames.iter_mut().take(round) {
            let _ = a.open_frame(f, max_body_for(64));
        }
        total += read_cycles().wrapping_sub(t0);
        done += round as u64;
    }
    BenchResult::from_total(0, total, iters)
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

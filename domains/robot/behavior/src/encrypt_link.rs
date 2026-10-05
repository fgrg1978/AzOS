// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel-side adapter for the RFC-0019 encrypt-link.
//!
//! The handshake state machine + AEAD wrapper live in the standalone
//! `azos_encrypt_link` crate (host-buildable, byte-pinned against the
//! brain by `tests/host/encrypt-link-tests/`).  This module re-exports that
//! API and adds the kernel-only entropy helpers — the standalone crate is
//! deliberately pure so its bytes can be diffed against Python.

#![allow(unused_imports)]

// `encrypt_link_policy` is declared in `lib.rs` (a sibling file, not a
// submodule of THIS file) — see that one-line addition in the same diff.
pub use crate::encrypt_link_policy::refuse_unseeded;

pub use azos_encrypt_link::{
    EncryptLink, HandshakeState, HandshakeError, link_encrypt_enforced,
    MODE_ENCRYPTED, LABEL_HELLO, LABEL_CONFIRM, LABEL_REJECT,
    EPH_PUB_BYTES, PROOF_BYTES, PSK_BYTES,
    HELLO_INIT_BYTES, HELLO_REPLY_BYTES, CONFIRM_BYTES,
    ENC_NONCE_SIZE, ENC_HMAC_SIZE, ENC_OVERHEAD, ENC_MAX_PAYLOAD,
    REJECT_BYTES, REJECT_FRAME, SESSION_ID_BYTES,
    RECORD_HEADER_BYTES, RECORD_LEN_MASK,
    RECORD_FLAG_MORE, RECORD_FLAG_REKEY, RECORD_FLAG_REJECT,
    MAX_MESSAGE_BYTES, REKEY_MAX_RECORDS, REKEY_MAX_BYTES, REKEY_INTERVAL_SECS,
    Opened, RecordKind, RecordError, SealError, SessionIdCache,
    is_reject_frame, parse_record_header, records_for, sealed_len_max, session_id,
    proof_responder, proof_initiator,
    x25519_pubkey,
};

use azos_crypto::sha256::Sha256;

// The kernel's boot-side entropy-pool helpers (`pool_mix`, the persisted
// seed, `record_ring3_unseeded_refusal`, and the `pool_fill` the network stack
// draws from) moved to `kernel/src/boot/entropy_pool.rs` (wave 11): the pool
// serves every image, not only the brain link. This module keeps its own
// `pool_fill` for the link's key derivation below.

/// Fill `out` from the kernel entropy pool, inside a critical section.
///
/// The pool's lock is a plain spin (`azos_crypto::entropy`, "Locking"):
/// holding preemption off across it keeps a same-hart preemption of the
/// holder from stranding a higher-priority caller. Returns `false`, with
/// `out` untouched, while the pool is unseeded.
pub fn pool_fill(out: &mut [u8]) -> bool {
    let _cs = azos_sync::critical_section();
    azos_crypto::entropy::fill(out)
}

/// Derive an ephemeral X25519 private key.
///
/// # Owner decision, 2026-09-26 (V1.2) — refuse rather than degrade, on an
/// enforced build
///
/// Returns `None`, refusing the handshake outright, when the entropy pool is
/// unseeded AND this is a `link-encrypt-enforced` build (`vf2`/`k1` today).
/// Before this decision the function always returned a key — silently
/// degraded on the boards, which have no TRNG (see [`refuse_unseeded`] and
/// `domains/robot/behavior/src/encrypt_link_policy.rs`, the host-testable pure
/// decision this wraps). A caller that gets `None` MUST refuse the
/// handshake and MUST NOT fall back to any other key-derivation path — see
/// callers in `kernel/src/tasks/brain_link.rs` (`brain_responder_handshake` and the
/// initiator-side dial loop). On a REFUSAL this function itself logs the
/// console line and writes the durable safety record
/// (`SAFETY_ENTROPY_UNSEEDED_REFUSED`) — the caller only needs to send
/// REJECT/decline to dial and not proceed.
///
/// On a non-enforced build (dev/QEMU today, no prod key rolled out) an
/// unseeded pool still returns `Some`, degraded — see the forward-secrecy
/// section below, unchanged from before this decision.
///
/// # Forward secrecy holds only on a boot whose entropy pool is seeded
///
/// **Seeded** (virtio-rng on QEMU: `[ENTROPY] pool seeded` in the boot log),
/// 32 pool bytes enter the hash, and the key does not collapse when the PSK
/// leaks: a recorded session is not recoverable from the PSK plus timing.
///
/// **Unseeded** (the boards today, which have no entropy device), read the
/// remaining inputs: the PSK, `timebase::now`, `wcet::read_cycles`, and a
/// `salt` that is itself another `get_time` sample XOR a small counter.
/// Forward secrecy only means anything under the compromised-PSK model —
/// an attacker who recorded traffic and later obtained the pre-shared key.
/// Give that attacker the PSK and every remaining input collapses to
/// *timing on two monotonic counters*, both of which start near zero at
/// boot and advance predictably. The reachable entropy is on the order of
/// 2^15–2^40 depending on how tightly the handshake's boot-relative timing
/// can be bounded — not 128 bits. Recorded sessions of such a boot are
/// recoverable by brute-forcing the ephemeral key. On an enforced build this
/// paragraph is now moot for the refused case — there is no session to
/// record — and still applies verbatim to a non-enforced build's `Some`.
///
/// The pool never stretches counters into key material: unseeded, it gives
/// nothing and this function keeps the inputs above. Closing the gap on the
/// boards for good requires a hardware entropy source feeding the pool
/// (RISC-V `Zkr`/`seed` CSR where the SoC implements it, or an on-board TRNG
/// peripheral) OR the persisted seed
/// (`azos_crypto::entropy::{seed_file_encode,seed_file_decode}`,
/// `kernel/src/msc_gadget.rs::RESERVED_SECTOR_ENTROPY_SEED`), which
/// `install_entropy_seed` in `kernel/src/boot/entropy.rs` mixes in at boot and
/// replaces before anything draws from the pool. The seed has to be
/// provisioned once on a board with no entropy device (`tools/seed_provision.py`);
/// a board that has never been provisioned still refuses every handshake, by
/// design, rather than running one with the weak key this section describes.
///
/// Either way the AEAD layer gives confidentiality and integrity against an
/// attacker who never learns the PSK. Do not describe the link as
/// forward-secret for an unseeded build in any doc, RFC status line, or
/// commit message.
///
/// (RFC-0019 calls this "forward secret". That holds for a seeded boot only.)
pub fn derive_ephemeral_priv(psk: &[u8; PSK_BYTES], salt: u64) -> Option<[u8; 32]> {
    let seeded = azos_crypto::entropy::seeded();
    if refuse_unseeded(seeded, link_encrypt_enforced()) {
        azos_drv_sys::kerr!(
            "[ENTROPY] REFUSED: brain link handshake — pool unseeded on a \
             link-encrypt-enforced build; no forward-secret key available. \
             Provision a TRNG-backed seed or the persisted seed file.");
        let _ = crate::logger::log_safety_violation_durable(
            crate::logger::SAFETY_ENTROPY_UNSEEDED_REFUSED, 0, 0);
        return None;
    }

    let mut h = Sha256::new();
    h.update(b"AZOS-EPH-V1");
    h.update(psk);
    let now = azos_drv_sys::timebase::now().to_le_bytes();
    h.update(&now);
    let cyc = azos_drv_sys::wcet::read_cycles().to_le_bytes();
    h.update(&cyc);
    h.update(&salt.to_le_bytes());
    let mut pool = [0u8; 32];
    if pool_fill(&mut pool) {
        h.update(b"POOL");
        h.update(&pool);
        azos_crypto::ct::secure_zero(&mut pool);
    }
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    Some(out)
}

/// Kernel-side 8-byte nonce randomness: 8 pool bytes when the pool is seeded,
/// plus the current clock and cycle counter and a caller-supplied salt counter.
pub fn fresh_nonce_rand(salt: u64) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"AZOS-NONCE-V1");
    h.update(&salt.to_le_bytes());
    let t = azos_drv_sys::timebase::now().to_le_bytes();
    h.update(&t);
    let c = azos_drv_sys::wcet::read_cycles().to_le_bytes();
    h.update(&c);
    let mut pool = [0u8; 8];
    if pool_fill(&mut pool) {
        h.update(b"POOL");
        h.update(&pool);
    }
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel-side adapter for the brain link's secure channel.
//!
//! The handshake and the transport live in `azos_crypto::secure_channel`
//! (pure, host-tested, byte-pinned against the brain by
//! `tests/host/aead-link-tests/`). This module re-exports that API and adds
//! what only the kernel has: the link key the boot installed, the entropy
//! helpers, and the brain's pinned key from the signed topology.

#![allow(unused_imports)]

// `encrypt_link_policy` is declared in `lib.rs` (a sibling file, not a
// submodule of THIS file).
pub use crate::encrypt_link_policy::refuse_unseeded;

pub use azos_crypto::secure_channel::{
    link_provisioning_enforced, HandshakeError, Initiator, Link, Opened, RecordError, RecordKind,
    SealError, SessionIdCache, frame_len, max_body_for, sealed_len_max, FRAME_HEAD,
    FRAME_OVERHEAD, HANDSHAKE_MSG_MAX, HANDSHAKE_OUT_MAX, MAX_MESSAGE_BYTES, PSK_BYTES,
    REKEY_INTERVAL_SECS, REKEY_MAX_BYTES, REKEY_MAX_RECORDS, SESSION_ID_BYTES,
};

// ── The link key ────────────────────────────────────────────────────────

/// The pre-shared link key the boot read from the reserved sector. All zeros
/// until [`install_link_key`] ran.
static mut LINK_KEY: [u8; PSK_BYTES] = [0u8; PSK_BYTES];

/// True once [`install_link_key`] stored a key.
static mut KEY_LOADED: bool = false;

/// Install the link key. Returns `false` (and installs nothing) unless
/// `key.len() == PSK_BYTES`.
///
/// SAFETY: called once during boot, single-threaded, before any task that
/// reads the key ([`link_key_copy`]) is spawned.
pub unsafe fn install_link_key(key: &[u8]) -> bool {
    if key.len() != PSK_BYTES {
        return false;
    }
    let dst = &mut *core::ptr::addr_of_mut!(LINK_KEY);
    dst.copy_from_slice(key);
    KEY_LOADED = true;
    true
}

/// Did the boot install a link key? Without one the brain link does not run.
pub fn link_key_installed() -> bool {
    // SAFETY: see `link_key_copy`.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(KEY_LOADED)) }
}

/// Copy of the installed link key, or `None` if the boot installed none.
///
/// The same 32-byte secret is the root of the brain link's Noise static keys
/// (one provisioned key: `azos_crypto::secure_channel`), so the link path
/// reads it from here rather than re-opening the key sector. A copy, not a
/// reference, so callers cannot alias the static; it lives only long enough
/// to start a handshake.
pub fn link_key_copy() -> Option<[u8; PSK_BYTES]> {
    // SAFETY: `KEY_LOADED` and `LINK_KEY` are written once by
    // `install_link_key` at boot before any task that could call this is
    // spawned; read-only thereafter.
    if !link_key_installed() {
        return None;
    }
    Some(unsafe { *core::ptr::addr_of!(LINK_KEY) })
}

/// The brain's pinned static Noise key: the `noise_pk` of the signed
/// topology's `[peer.brain]` row (`azos_topology::Topology::brain_noise_pk`).
/// `None` pins nothing: `Noise_XX`, authenticated by the link key. There is
/// no other source: a key from a file or a build option would be a second
/// authority over who the brain is.
pub fn brain_pinned_key() -> Option<[u8; 32]> {
    azos_topology::get()?.brain_noise_pk()
}

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
/// unseeded AND this is a `link-provisioning-enforced` build (every non-DEV robot build).
/// Before this decision the function always returned a key — silently
/// degraded on the boards, which have no TRNG (see [`refuse_unseeded`] and
/// `domains/robot/behavior/src/encrypt_link_policy.rs`, the host-testable pure
/// decision this wraps). A caller that gets `None` MUST refuse the
/// handshake and MUST NOT fall back to any other key-derivation path — see
/// callers in `kernel/src/tasks/brain_link.rs` (`brain_handshake`, run by the
/// control dial and the camera dial). On a REFUSAL this function itself logs the
/// console line and writes the durable safety record
/// (`SAFETY_ENTROPY_UNSEEDED_REFUSED`) — the caller only needs to close the
/// socket and not proceed.
///
/// On a non-enforced build (BUILD_TYPE_DEV, or a hand-set n) an
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
/// `kernel/src/reserved_tail.rs::ENTROPY_SEED`), which
/// `install_entropy_seed` in `kernel/src/boot/entropy.rs` mixes in at boot and
/// replaces before anything draws from the pool. The seed has to be
/// provisioned once on a board with no entropy device (`tools/seed_provision.py`);
/// a board that has never been provisioned still refuses every handshake, by
/// design, rather than running one with the weak key this section describes.
///
/// Either way the transport gives confidentiality and integrity against an
/// attacker who never learns the PSK. Do not describe the link as
/// forward-secret for an unseeded build in any doc, status line, or
/// commit message.
///
/// (The link design calls this "forward secret". That holds for a seeded boot only.)
pub fn derive_ephemeral_priv(psk: &[u8; PSK_BYTES], salt: u64) -> Option<[u8; 32]> {
    let seeded = azos_crypto::entropy::seeded();
    if refuse_unseeded(seeded, link_provisioning_enforced()) {
        azos_drv_sys::kerr!(
            "[ENTROPY] REFUSED: brain link handshake — pool unseeded on a \
             link-provisioning-enforced build; no forward-secret key available. \
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

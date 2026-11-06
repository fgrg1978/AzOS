// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel entropy pool's boot-side helpers: critical-section wrappers
//! around `azos_crypto::entropy`, the persisted-seed record, and the
//! durable record of a refused ring-3 read.
//!
//! Moved here from `crates/domains/robot/behavior/src/encrypt_link.rs` (wave 11,
//! DOMAIN): the pool seeds the network stack and the `entropy` endpoint in
//! every image, with or without the Robot domain's brain link.

/// Credited bytes that seed the kernel entropy pool, for the kernel's seed
/// read.
pub const POOL_SEED_BYTES: usize = azos_crypto::entropy::SEED_BYTES;

/// Fill `out` from the kernel entropy pool, inside a critical section.
///
/// The pool's lock is a plain spin (`azos_crypto::entropy`, "Locking"):
/// holding preemption off across it keeps a same-hart preemption of the
/// holder from stranding a higher-priority caller. Returns `false`, with
/// `out` untouched, while the pool is unseeded. This is the function the
/// kernel installs as the network stack's random source.
pub fn pool_fill(out: &mut [u8]) -> bool {
    let _cs = azos_sync::critical_section();
    azos_crypto::entropy::fill(out)
}

/// Mix `input` into the kernel entropy pool, inside a critical section,
/// counting `credit` of its bytes toward a seed (the entropy the source
/// vouches for; 0 for anything else). See [`pool_fill`].
pub fn pool_mix(input: &[u8], credit: usize) {
    let _cs = azos_sync::critical_section();
    azos_crypto::entropy::mix(input, credit)
}

/// How a ring-3 entropy driver's feed counts (Kconfig `ENTROPY_RING3_FEED`).
const RING3_FEED: azos_crypto::entropy::FeedCredit = if azos_limits::ENTROPY_RING3_FEED_CREDIT {
    azos_crypto::entropy::FeedCredit::Credit
} else {
    azos_crypto::entropy::FeedCredit::MixOnly
};

/// Mix what a ring-3 entropy device driver (task `tid`) read from its device,
/// credited as Kconfig `ENTROPY_RING3_FEED` says (by default not at all). The
/// first feed of a boot says so, and how the pool stands after it.
pub fn pool_mix_ring3(input: &[u8], tid: u32) {
    use core::sync::atomic::{AtomicBool, Ordering};
    static SAID: AtomicBool = AtomicBool::new(false);
    let was = azos_crypto::entropy::seeded();
    let credit = RING3_FEED.credit(input.len());
    pool_mix(input, credit);
    if !SAID.swap(true, Ordering::AcqRel) {
        let how = if credit == 0 { "mixed, not credited" } else { "credited" };
        let now = if was {
            "the pool was seeded already"
        } else if azos_crypto::entropy::seeded() {
            "pool seeded"
        } else {
            "pool unseeded"
        };
        crate::kprintln!("[ENTROPY] {} bytes fed from ring 3 (tid {}), {}: {}", input.len(), tid, how, now);
    }
}

pub use azos_crypto::entropy::{
    SeedApply, SeedLoad, SeedTail, SEED_FILE_BYTES, SEED_FILE_SEED_BYTES,
};

/// Load the persisted seed in `sector` into the kernel pool and derive the
/// record that replaces it, in one lock hold, inside a critical section. See
/// [`azos_crypto::entropy::Pool::apply_persisted_seed`] for the crediting
/// rule. The kernel's boot step (`install_entropy_seed`) writes
/// [`SeedApply::fresh`] back before anything else can draw from the pool.
pub fn pool_apply_persisted_seed(sector: &[u8]) -> SeedApply {
    let _cs = azos_sync::critical_section();
    azos_crypto::entropy::apply_persisted_seed(sector)
}

/// A fresh persisted-seed record drawn from the pool (the orderly-shutdown
/// refresh); `None` while the pool is unseeded.
pub fn pool_next_seed_record() -> Option<[u8; SEED_FILE_BYTES]> {
    let _cs = azos_sync::critical_section();
    azos_crypto::entropy::next_seed_record()
}


/// The first ring-3 entropy draw refused on an unseeded pool this
/// boot (`crates/core/syscall/src/entropy.rs` calls this once per boot; later
/// refusals are only counted there).
///
/// The same record the handshake refusal above writes,
/// `SAFETY_ENTROPY_UNSEEDED_REFUSED`, durably, told apart by its action
/// code: `0` is the kernel's own link handshake, `1` a ring-3 read, whose
/// `detail` is the caller's TID. Runs on the refused caller's syscall, like
/// the ring-3 e-stop's durable record (`safety-core`'s `actuation.rs`).
pub fn record_ring3_unseeded_refusal(tid: u32) {
    azos_drv_sys::kwarn!(
        "[ENTROPY] REFUSED: ring-3 read tid={} — pool unseeded; no entropy \
         source fed it this boot", tid);
    let _ = azos_actuation::logger::log_safety_violation_durable(
        azos_actuation::logger::SAFETY_ENTROPY_UNSEEDED_REFUSED, 1, tid);
}


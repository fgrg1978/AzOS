// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel entropy pool: HMAC_DRBG over SHA-256 (NIST SP 800-90A §10.1.2).
//!
//! # What goes in, what comes out
//!
//! * [`mix`] feeds bytes into the state. `credited = true` is for bytes from
//!   a real entropy source (virtio-rng today); `credited = false` is for
//!   anything else worth stirring in (MACs, boot timing) and never makes the
//!   pool seeded on its own.
//! * [`fill`] writes output **only when the pool is seeded** and returns
//!   `false` otherwise, leaving the buffer untouched. The unseeded fallback is
//!   the caller's: every consumer keeps the path it had before the pool
//!   existed. This crate depends on no `azos_*` crate (the TCB property
//!   `crates/core/sched/Cargo.toml` relies on), so it cannot reach a clock or a
//!   cycle counter to fabricate a fallback itself — and it should not.
//!
//! # Seed and reseed rule
//!
//! * **Seeded** once [`SEED_BYTES`] (48) credited bytes have been mixed:
//!   256 bits of entropy input plus the 128-bit nonce SP 800-90A §8.6.7 asks
//!   of an instantiation at the 256-bit security strength.
//! * **Reseeded** each further time [`RESEED_BYTES`] (32) credited bytes have
//!   accumulated: the generate counter restarts at 1. Credited bytes count
//!   across calls, so several short reads add up.
//! * **Unseeded again** after [`RESEED_INTERVAL`] generate requests without a
//!   reseed — the SP 800-90A Table 2 maximum for HMAC_DRBG (2^48). `fill`
//!   then returns `false` until credited bytes arrive.
//!
//! Every generate is followed by the §10.1.2.5 state update, so reading the
//! state later does not reveal earlier output (backtracking resistance). There
//! is no prediction resistance: output after a state compromise stays
//! predictable until the next reseed.
//!
//! # Locking
//!
//! The global pool sits behind a spin on an `AtomicBool`, because this crate
//! cannot use `azos_sync`. That spin does not disable preemption, and
//! `azos_sync::SpinLock::lock` does so for a reason: a holder preempted on
//! its own hart would leave a higher-priority caller there spinning against a
//! lock whose owner cannot run. So kernel code calls [`fill`] and [`mix`]
//! from inside `azos_sync::critical_section()` — through
//! `azos_behavior::encrypt_link::pool_fill` / `pool_mix` — except at boot,
//! before the first task exists, when there is nobody to contend with.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ct::secure_zero;
use crate::sha256::Sha256;

/// Credited bytes needed before the pool first reports seeded.
pub const SEED_BYTES: usize = 48;

/// Credited bytes that reseed an already-seeded pool.
pub const RESEED_BYTES: usize = 32;

/// Generate requests allowed between reseeds (SP 800-90A Table 2, HMAC_DRBG).
pub const RESEED_INTERVAL: u64 = 1 << 48;

/// Longest single generate request; `fill` splits anything larger. Far below
/// the 2^19-bit per-request maximum of SP 800-90A Table 2.
pub const MAX_REQUEST_BYTES: usize = 4096;

const OUT_BYTES: usize = 32;
const BLOCK_BYTES: usize = 64;

/// HMAC-SHA-256 with a 32-byte key over the concatenation of `parts`.
///
/// A 32-byte key is shorter than the block, so it is zero-padded as-is
/// (RFC 2104 §2); a shorter key padded with zeros to 32 bytes gives the same
/// MAC, which is how the RFC 4231 vectors apply.
pub fn hmac_sha256(key: &[u8; OUT_BYTES], parts: &[&[u8]]) -> [u8; OUT_BYTES] {
    let mut ipad = [0x36u8; BLOCK_BYTES];
    let mut opad = [0x5cu8; BLOCK_BYTES];
    for i in 0..OUT_BYTES {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut h = Sha256::new();
    h.update(&ipad);
    for p in parts {
        h.update(p);
    }
    let mut inner = h.finalize();
    let mut h = Sha256::new();
    h.update(&opad);
    h.update(&inner);
    let out = h.finalize();
    secure_zero(&mut ipad);
    secure_zero(&mut opad);
    secure_zero(&mut inner);
    out
}

/// One HMAC_DRBG instance plus the seed accounting described in the module doc.
pub struct Pool {
    k: [u8; OUT_BYTES],
    v: [u8; OUT_BYTES],
    /// Credited bytes mixed since the last (re)seed.
    credited: usize,
    /// Set by the first full seed; never cleared.
    ever_seeded: bool,
    /// Generate requests since the last (re)seed, starting at 1 (§10.1.2.3).
    reseed_counter: u64,
}

impl Pool {
    /// The §10.1.2.3 starting state: `K = 0x00…`, `V = 0x01…`, unseeded.
    pub const fn new() -> Self {
        Pool {
            k: [0x00; OUT_BYTES],
            v: [0x01; OUT_BYTES],
            credited: 0,
            ever_seeded: false,
            reseed_counter: 1,
        }
    }

    /// HMAC_DRBG_Update (§10.1.2.2) with `provided` as the provided data.
    fn update(&mut self, provided: &[u8]) {
        self.k = hmac_sha256(&self.k, &[&self.v, &[0x00], provided]);
        self.v = hmac_sha256(&self.k, &[&self.v]);
        if provided.is_empty() {
            return;
        }
        self.k = hmac_sha256(&self.k, &[&self.v, &[0x01], provided]);
        self.v = hmac_sha256(&self.k, &[&self.v]);
    }

    /// Stir `input` into the state; count it toward (re)seeding if `credited`.
    ///
    /// Mixing an empty slice is a no-op on the seed accounting but still runs
    /// the update, as §10.1.2.2 specifies for empty provided data.
    pub fn mix(&mut self, input: &[u8], credited: bool) {
        self.update(input);
        if !credited {
            return;
        }
        self.credited = self.credited.saturating_add(input.len());
        let need = if self.ever_seeded { RESEED_BYTES } else { SEED_BYTES };
        if self.credited >= need {
            self.ever_seeded = true;
            self.reseed_counter = 1;
            self.credited = 0;
        }
    }

    /// True once seeded and not past [`RESEED_INTERVAL`] since the last reseed.
    pub fn seeded(&self) -> bool {
        self.ever_seeded && self.reseed_counter <= RESEED_INTERVAL
    }

    /// Fill `out` from the generator. Returns `false`, and writes nothing,
    /// when the pool is not seeded.
    pub fn fill(&mut self, out: &mut [u8]) -> bool {
        if !self.seeded() {
            return false;
        }
        for chunk in out.chunks_mut(MAX_REQUEST_BYTES) {
            if !self.seeded() {
                // Only reachable if one call spans the interval boundary.
                // The bytes already written are good output; the caller is
                // told the fill did not complete.
                return false;
            }
            // HMAC_DRBG_Generate (§10.1.2.5), no additional input.
            let mut done = 0;
            while done < chunk.len() {
                self.v = hmac_sha256(&self.k, &[&self.v]);
                let n = (chunk.len() - done).min(OUT_BYTES);
                chunk[done..done + n].copy_from_slice(&self.v[..n]);
                done += n;
            }
            self.update(&[]);
            self.reseed_counter = self.reseed_counter.saturating_add(1);
        }
        true
    }
}

struct Shared {
    locked: AtomicBool,
    pool: UnsafeCell<Pool>,
}

// SAFETY: `pool` is only reached through `with_pool`, which holds `locked`.
unsafe impl Sync for Shared {}

static POOL: Shared = Shared {
    locked: AtomicBool::new(false),
    pool: UnsafeCell::new(Pool::new()),
};

fn with_pool<R>(f: impl FnOnce(&mut Pool) -> R) -> R {
    while POOL
        .locked
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `locked` is held, so this is the only live reference.
    let r = f(unsafe { &mut *POOL.pool.get() });
    POOL.locked.store(false, Ordering::Release);
    r
}

/// Mix `input` into the kernel pool. See [`Pool::mix`] and the locking note.
pub fn mix(input: &[u8], credited: bool) {
    with_pool(|p| p.mix(input, credited))
}

/// Whether the kernel pool is seeded. See [`Pool::seeded`].
pub fn seeded() -> bool {
    with_pool(|p| p.seeded())
}

/// Fill `out` from the kernel pool; `false` (nothing written) when unseeded.
/// See [`Pool::fill`] and the locking note.
pub fn fill(out: &mut [u8]) -> bool {
    with_pool(|p| p.fill(out))
}

// ── Persisted seed record (U09-8, owner decision 2026-09-26 V1.2) ─────────
//
// "Refuse to derive session keys on an unseeded pool" (the fix for U09-8 /
// security finding #26, applied at the caller —
// `domains/robot/behavior/src/encrypt_link.rs::derive_ephemeral_priv`, not in this
// crate) is only survivable on hardware with no TRNG if a seed can persist
// ACROSS boots. This is the pure side of that seed: the record format, the
// load-and-rotate rule, and the check that the storage is not filesystem
// data. The kernel-side storage location (deliberately NOT the MSC-exported
// FAT volume — the same USB-readable-PSK reasoning as U06-9/#30) is
// `kernel/src/msc_gadget.rs`'s reserved tail sectors,
// `RESERVED_SECTOR_ENTROPY_SEED`; the boot call site is
// `install_entropy_seed` in `kernel/src/boot/entropy.rs`.
//
// Format, one 512-byte sector, `SEED_FILE_BYTES` (73) meaningful:
//   offset  size  field
//   0       4     magic "SEED"
//   4       1     version (1)
//   5       64    seed bytes
//   69      4     integrity tag: first 4 bytes of SHA-256(magic‖version‖seed)
//
// The seed is 64 bytes, not 32: a pool is seeded by [`SEED_BYTES`] (48)
// credited bytes, so a 32-byte seed could never make an unseeded pool
// seeded on its own — which is the one case where crediting it matters.
//
// The tag is integrity (torn-write / wrong-sector detection), NOT
// authentication — anyone who can write the reserved region can write a
// self-consistent seed file. That is fine: entropy input does not need to
// be secret from an attacker who already has raw write access to the
// medium, only unpredictable to one who does not, and a corrupted or
// absent file falls back to "mix nothing" (`seed_file_decode` returning
// `None`), never to zero bytes credited as if they were real entropy.
pub const SEED_FILE_MAGIC: [u8; 4] = *b"SEED";
pub const SEED_FILE_VERSION: u8 = 1;
pub const SEED_FILE_SEED_BYTES: usize = 64;
pub const SEED_FILE_BYTES: usize = 4 + 1 + SEED_FILE_SEED_BYTES + 4;

/// Encode a seed file record into `out` (must be at least
/// [`SEED_FILE_BYTES`] long). Returns the number of bytes written.
pub fn seed_file_encode(seed: &[u8; SEED_FILE_SEED_BYTES], out: &mut [u8]) -> usize {
    if out.len() < SEED_FILE_BYTES {
        return 0;
    }
    out[0..4].copy_from_slice(&SEED_FILE_MAGIC);
    out[4] = SEED_FILE_VERSION;
    out[5..5 + SEED_FILE_SEED_BYTES].copy_from_slice(seed);
    let tag = seed_file_tag(seed);
    out[5 + SEED_FILE_SEED_BYTES..SEED_FILE_BYTES].copy_from_slice(&tag);
    SEED_FILE_BYTES
}

/// Decode a seed file record from `data`. Returns `None` on a short buffer,
/// bad magic/version, or a tag mismatch — every one of those means "there is
/// no usable persisted seed here", not "here is a seed of zero bytes".
#[must_use]
pub fn seed_file_decode(data: &[u8]) -> Option<[u8; SEED_FILE_SEED_BYTES]> {
    if data.len() < SEED_FILE_BYTES {
        return None;
    }
    if data[0..4] != SEED_FILE_MAGIC || data[4] != SEED_FILE_VERSION {
        return None;
    }
    let mut seed = [0u8; SEED_FILE_SEED_BYTES];
    seed.copy_from_slice(&data[5..5 + SEED_FILE_SEED_BYTES]);
    let tag = seed_file_tag(&seed);
    if data[5 + SEED_FILE_SEED_BYTES..SEED_FILE_BYTES] != tag {
        secure_zero(&mut seed);
        return None;
    }
    Some(seed)
}

fn seed_file_tag(seed: &[u8; SEED_FILE_SEED_BYTES]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(&SEED_FILE_MAGIC);
    h.update(&[SEED_FILE_VERSION]);
    h.update(seed);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// What loading the persisted seed did to the pool.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SeedLoad {
    /// No valid record (absent, short, bad magic/version, tag mismatch):
    /// nothing was mixed.
    Absent,
    /// Mixed AND credited: the pool had no other source, so this seed is the
    /// entropy that seeds it (when it is a valid record of
    /// [`SEED_FILE_SEED_BYTES`] ≥ [`SEED_BYTES`] bytes, the pool is now
    /// seeded).
    Credited,
    /// Mixed, not credited: the pool was already seeded by a real source, so
    /// the seed only stirs the state.
    Stirred,
}

/// The result of [`Pool::apply_persisted_seed`]: what was loaded, and the
/// record that must replace the one just read.
pub struct SeedApply {
    pub load: SeedLoad,
    /// The next on-disk record, drawn from the pool AFTER the load. `None`
    /// when the pool is still unseeded: there is nothing honest to write, and
    /// the caller leaves the sector alone. The caller must `secure_zero` it.
    pub fresh: Option<[u8; SEED_FILE_BYTES]>,
}

impl Pool {
    /// Load the persisted seed in `sector` and derive its replacement, in one
    /// step so nothing can draw from the pool in between.
    ///
    /// Crediting rule (the Linux `random-seed` rule, adapted): the seed is
    /// credited ONLY when the pool is not already seeded. Linux credits a
    /// seed file only when the operator vouches for it (`random.trust_*`);
    /// here a seed that is the sole source on a board with no TRNG is the
    /// only way the pool ever seeds, and refusing to credit it would leave
    /// `derive_ephemeral_priv` refusing every handshake forever. When another
    /// source has seeded the pool, an attacker-supplied file is not allowed to
    /// count toward that: it only stirs.
    ///
    /// The replacement is drawn after the mix, from the same lock hold, so it
    /// is never a function of the old seed alone and the old seed is never
    /// the record a later boot reads.
    pub fn apply_persisted_seed(&mut self, sector: &[u8]) -> SeedApply {
        let load = match seed_file_decode(sector) {
            None => SeedLoad::Absent,
            Some(mut seed) => {
                let credit = !self.seeded();
                self.mix(&seed, credit);
                secure_zero(&mut seed);
                if credit { SeedLoad::Credited } else { SeedLoad::Stirred }
            }
        };
        SeedApply { load, fresh: self.next_seed_record() }
    }

    /// A new seed record drawn from the pool; `None` while it is unseeded.
    pub fn next_seed_record(&mut self) -> Option<[u8; SEED_FILE_BYTES]> {
        let mut seed = [0u8; SEED_FILE_SEED_BYTES];
        if !self.fill(&mut seed) {
            secure_zero(&mut seed);
            return None;
        }
        let mut rec = [0u8; SEED_FILE_BYTES];
        seed_file_encode(&seed, &mut rec);
        secure_zero(&mut seed);
        Some(rec)
    }
}

/// [`Pool::apply_persisted_seed`] on the kernel pool. Call inside
/// `azos_sync::critical_section()` (`encrypt_link::pool_apply_persisted_seed`).
pub fn apply_persisted_seed(sector: &[u8]) -> SeedApply {
    with_pool(|p| p.apply_persisted_seed(sector))
}

/// [`Pool::next_seed_record`] on the kernel pool: the orderly-shutdown
/// refresh. Same locking note as [`apply_persisted_seed`].
pub fn next_seed_record() -> Option<[u8; SEED_FILE_BYTES]> {
    with_pool(|p| p.next_seed_record())
}

/// Whether the persisted-seed sector can be trusted to be ours.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SeedTail {
    /// No filesystem the kernel can see reaches the reserved tail.
    Clear,
    /// A partition, or the bare FAT32 volume, extends into the tail: a write
    /// there would overwrite filesystem data. (An image built without the
    /// headroom `MSC_RESERVED_TAIL_SECTORS` asks for, or an SD card whose FAT
    /// partition runs to the last sector.)
    FilesystemReaches,
    /// No partition table and sector 0 is not a FAT32 boot sector, so there
    /// is no extent to compare the tail against. Treated as unusable.
    UnknownLayout,
    /// The medium is no larger than the tail.
    TooSmall,
}

/// Decide whether the last `tail_sectors` sectors of a medium of
/// `capacity_sectors` may be written. `partitions` are the published
/// `(start, sectors)` pairs; `sector0` is the medium's first sector.
///
/// `reserved_region_write` alone only checks that the device is larger than
/// the tail — it cannot know where the filesystem ends — and the key it
/// guarded was only ever read. A seed is rewritten on every boot, so this is
/// the guard against a rewrite landing in FAT data.
#[must_use]
pub fn seed_tail_check(
    capacity_sectors: u64,
    tail_sectors: u64,
    partitions: &[(u64, u64)],
    sector0: &[u8],
) -> SeedTail {
    if capacity_sectors <= tail_sectors {
        return SeedTail::TooSmall;
    }
    let tail_start = capacity_sectors - tail_sectors;
    if !partitions.is_empty() {
        for &(start, len) in partitions {
            if start.saturating_add(len) > tail_start {
                return SeedTail::FilesystemReaches;
            }
        }
        return SeedTail::Clear;
    }
    // Bare medium: sector 0 must be a FAT32 boot sector, whose own total
    // bounds the volume (the same fields `fat32.rs::validate_bpb` insists on).
    if sector0.len() < 512 || sector0[510] != 0x55 || sector0[511] != 0xAA {
        return SeedTail::UnknownLayout;
    }
    let bytes_per_sec = u16::from_le_bytes([sector0[11], sector0[12]]);
    let tot16 = u16::from_le_bytes([sector0[19], sector0[20]]);
    let tot32 = u32::from_le_bytes([sector0[32], sector0[33], sector0[34], sector0[35]]);
    if bytes_per_sec != 512 || tot16 != 0 || tot32 == 0 {
        return SeedTail::UnknownLayout;
    }
    if u64::from(tot32) > tail_start {
        return SeedTail::FilesystemReaches;
    }
    SeedTail::Clear
}

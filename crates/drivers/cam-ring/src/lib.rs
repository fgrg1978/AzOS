// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Lock-free SPSC camera frame ring (S1/S6 — high-throughput multi-stream),
//! and [`FanoutRing`], the one-producer / many-consumer ring the kernel's
//! camera pipeline uses (module [`fanout`]).
//!
//! # Design
//!
//! `FrameRing<N, SZ>` holds `N` fixed-size slots of `SZ` bytes each.
//! It is **single-producer / single-consumer (SPSC)**:
//! - The **producer** calls [`FrameRing::claim_write`] to get a writable slot,
//!   fills it, then calls [`FrameRing::commit_write`] with the number of valid
//!   bytes.
//! - The **consumer** calls [`FrameRing::peek_read`] to look at the next
//!   committed frame, processes it, then calls [`FrameRing::release_read`].
//!
//! # Atomics and memory ordering
//!
//! Two indices advance monotonically and are masked with `N - 1` for slot
//! selection (so `N` must be a power of two):
//!
//! - `producer_idx`: owned by the producer.  Written with `Release` after the
//!   payload copy so the consumer observes a fully-written slot.
//! - `consumer_idx`: owned by the consumer.  Written with `Release` after
//!   consumption so the producer observes freed space.
//!
//! Loads on the *other* side use `Acquire` to pair with those `Release` stores.
//! This gives the acquire-release handoff required for correct visibility on
//! RISC-V and aarch64.
//!
//! # Safety
//!
//! Each slot is wrapped in `UnsafeCell`.  The SPSC invariant guarantees:
//! - The producer only holds a writable reference to `slots[producer_idx % N]`
//!   and only between `claim_write` and `commit_write`.
//! - The consumer only holds a readable reference to `slots[consumer_idx % N]`
//!   and only between `peek_read` and `release_read`.
//! - No index is aliased. This is a **back-pressure** design, not an
//!   overwrite-oldest one: [`FrameRing::claim_write`] computes
//!   `producer_idx.wrapping_sub(consumer_idx)` and returns `None` instead of
//!   advancing when that is `>= N`, so the producer physically cannot store
//!   into a slot the consumer has not yet released — verified at the actual
//!   `usize` wraparound boundary by `wrap_boundary_full_then_drain` and
//!   `wrap_boundary_negative_no_overwrite` in `tests/host/cam-ring-tests`.
//!
//!   Both indices are plain `usize` incremented only via `wrapping_add(1)`,
//!   never decremented, so the *true* (unwrapped) value of
//!   `producer_idx - consumer_idx` is an invariant held in `[0, N]` by
//!   induction (0 at construction; `commit_write` only increments
//!   `producer_idx` when the check above already showed the true difference
//!   is `< N`; `release_read` only decreases it). Two's-complement
//!   `wrapping_sub` recovers that true difference exactly by construction —
//!   `a.wrapping_sub(b) == (a - b) mod 2^BITS`, which equals the true
//!   difference whenever that difference is representable, i.e. `< 2^(BITS-1)`
//!   — a condition met here for any sane `N` (`N <= CAM_RING_MAX_SLOTS == 64`)
//!   regardless of where `producer_idx`/`consumer_idx` sit in the modulus,
//!   *including exactly at the `usize::MAX -> 0` rollover*: e.g.
//!   `0usize.wrapping_sub(usize::MAX) == 1`. Slot selection (`idx & (N - 1)`)
//!   stays continuous across that rollover too, because `N` is a power of two
//!   dividing `2^BITS` evenly, so `usize::MAX & (N - 1) == N - 1` and the very
//!   next index (`0`) masks to `0` — the round-robin sequence does not skip or
//!   repeat a slot at the boundary. This holds for any unsigned width, so it
//!   is independent of whether the target's `usize` is 32 or 64 bits.

#![no_std]

pub mod fanout;
pub use fanout::{FanoutRing, FrameRef, Policy};

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

// ── Ring capacity invariant ───────────────────────────────────────────────────

/// Maximum frame ring capacity (hard upper bound, not the default size).
/// Must be a power of two; exists to limit stack/static memory footprints.
pub const CAM_RING_MAX_SLOTS: usize = 64;

/// Maximum bytes per frame slot.  Sized for a 1080p YUV420 frame (≈ 3 MB)
/// rounded up to the nearest power of two; must fit in a u16 length field.
pub const CAM_RING_MAX_SLOT_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Header bytes stored alongside each committed frame: 2 bytes little-endian
/// "valid byte count" (separate from the slot raw size `SZ`).
/// Exposed as [`FRAME_HEADER_BYTES`] for external callers.
const FRAME_LEN_FIELD_BYTES: usize = 2;

/// Public alias for the per-frame length-field overhead (= 2).
pub const FRAME_HEADER_BYTES: usize = FRAME_LEN_FIELD_BYTES;

// ── Slot ─────────────────────────────────────────────────────────────────────

/// Internal storage for one frame slot.
///
/// `UnsafeCell` allows the producer to get a `&mut` through a shared
/// `&FrameRing` reference without triggering UB (see module safety note).
struct Slot<const SZ: usize> {
    /// Raw frame bytes (at most `SZ` valid, actual count in `len`).
    data: UnsafeCell<[u8; SZ]>,
    /// Number of valid bytes written by the producer.  Written by producer
    /// with `Release` *after* `data`; read by consumer with `Acquire`.
    len: AtomicUsize,
}

impl<const SZ: usize> Slot<SZ> {
    #[allow(dead_code)]
    const fn new() -> Self {
        Slot {
            data: UnsafeCell::new([0u8; SZ]),
            len: AtomicUsize::new(0),
        }
    }
}

// SAFETY: SPSC invariant — producer and consumer never access the same slot
// concurrently.  See module-level safety note.
unsafe impl<const SZ: usize> Sync for Slot<SZ> {}

// ── FrameRing ─────────────────────────────────────────────────────────────────

/// Lock-free SPSC ring of `N` camera-frame slots, each up to `SZ` bytes.
///
/// # Generic parameters
/// - `N` — number of frame slots; **must be a power of two** and ≤
///   [`CAM_RING_MAX_SLOTS`].
/// - `SZ` — byte capacity of each slot; must be > 0.
///
/// # Usage
/// ```no_run
/// # use azos_cam_ring::FrameRing;
/// static RING: FrameRing<4, 1024> = FrameRing::new();
///
/// // Producer side:
/// if let Some(slot) = RING.claim_write() {
///     slot[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
///     RING.commit_write(4);
/// }
///
/// // Consumer side:
/// if let Some((len, bytes)) = RING.peek_read() {
///     let _ = &bytes[..len];
///     RING.release_read();
/// }
/// ```
pub struct FrameRing<const N: usize, const SZ: usize> {
    slots: [Slot<SZ>; N],
    /// Next slot the producer will write into (monotonically increasing).
    producer_idx: AtomicUsize,
    /// Next slot the consumer will read from (monotonically increasing).
    consumer_idx: AtomicUsize,
}

// SAFETY: same SPSC guarantee as Slot above.
unsafe impl<const N: usize, const SZ: usize> Sync for FrameRing<N, SZ> {}

impl<const N: usize, const SZ: usize> FrameRing<N, SZ> {
    // Ensure power-of-two at const eval time.  This assertion fires during
    // monomorphisation so the user gets a clear compile-time error.
    const _N_IS_POW2: () = assert!(N.is_power_of_two(), "FrameRing: N must be a power of two");
    const _N_NONZERO: () = assert!(N > 0, "FrameRing: N must be > 0");
    const _SZ_NONZERO: () = assert!(SZ > 0, "FrameRing: SZ must be > 0");
    const _N_MAX: () = assert!(N <= CAM_RING_MAX_SLOTS, "FrameRing: N exceeds CAM_RING_MAX_SLOTS");

    /// Index mask — avoids modulo on hot paths.
    const IDX_MASK: usize = N - 1;

    /// Create a new, empty ring.  Suitable for `static` initialisation.
    // `[Slot::new(); N]` requires Copy; use a const fn workaround.
    pub const fn new() -> Self {
        // We need to initialise each slot without Copy/Default.
        // The macro-free way in const fn: a fixed-size init using
        // `MaybeUninit` transmutation is UB in const context before
        // Rust 1.84 stabilises `const_precise_live_drops`.
        // Instead we use the `const_init_array` idiom (safe since Rust 1.79):
        // we rely on N being known at compile-time and generate a fixed
        // array literal via a const-trait bound work-around.
        //
        // Approach: union-based zero-init trick is not needed here because
        // `AtomicUsize::new(0)` and `[0u8; SZ]` are zero-byte initialised.
        // We use `core::mem::zeroed()` in the const context which is valid for
        // types that are "safely zeroable" (plain integers + UnsafeCell of them).
        //
        // SAFETY: `[u8; SZ]`, `AtomicUsize`, and `UnsafeCell<[u8; SZ]>` are
        // all zeroable — zero is a valid bit pattern for each field.
        // `AtomicUsize::new(0)` == zeroed AtomicUsize, so this is sound.
        //
        // We use `unsafe { core::mem::zeroed() }` because `const fn new()`
        // cannot use iterator/loop to build `[Slot::new(); N]` without Copy.
        // Evaluate const assertions for this specific monomorphisation so
        // that FrameRing::<3, 8>::new() fails at compile time, not just
        // FrameRing::<4, 8> (which the module-level constants cover).
        let _: () = Self::_N_IS_POW2;
        let _: () = Self::_N_NONZERO;
        let _: () = Self::_SZ_NONZERO;
        let _: () = Self::_N_MAX;

        #[allow(clippy::zero_initialized_atomic)]
        // SAFETY: all fields are zero-initializable.
        let slots: [Slot<SZ>; N] = unsafe { core::mem::zeroed() };
        FrameRing {
            slots,
            producer_idx: AtomicUsize::new(0),
            consumer_idx: AtomicUsize::new(0),
        }
    }

    /// Test-only constructor: build an empty ring whose `producer_idx` and
    /// `consumer_idx` both start at `start` instead of `0`.
    ///
    /// Exists so host tests can drive the ring across the internal `usize`
    /// wraparound boundary (e.g. `start = usize::MAX - 1`) without looping
    /// billions of times. Only compiled with the `test-util` feature, which
    /// only `tests/host/cam-ring-tests` enables — never part of the on-target
    /// build.
    #[cfg(feature = "test-util")]
    pub fn with_start_index(start: usize) -> Self {
        let mut ring = Self::new();
        *ring.producer_idx.get_mut() = start;
        *ring.consumer_idx.get_mut() = start;
        ring
    }

    // ── Producer API ─────────────────────────────────────────────────────────

    /// Claim the next writable slot.
    ///
    /// Returns `Some(&mut [u8; SZ])` if a slot is available, `None` if the
    /// ring is full (back-pressure: caller must wait for the consumer to
    /// release a slot).
    ///
    /// The returned mutable reference is valid until the matching
    /// [`commit_write`] call.  After claiming, the caller **must** call
    /// `commit_write` before calling `claim_write` again; otherwise the slot
    /// will be overwritten.
    ///
    /// [`commit_write`]: FrameRing::commit_write
    pub fn claim_write(&self) -> Option<&mut [u8; SZ]> {
        let prod = self.producer_idx.load(Ordering::Relaxed);
        let cons = self.consumer_idx.load(Ordering::Acquire);
        // Ring is full when (prod - cons) == N (using wrapping arithmetic).
        if prod.wrapping_sub(cons) >= N {
            return None;
        }
        let slot_idx = prod & Self::IDX_MASK;
        // SAFETY: SPSC — only the producer accesses this slot while
        // (cons..prod] is the "in-flight" range.  The check above guarantees
        // `slot_idx` is not currently owned by the consumer.
        let ptr = self.slots[slot_idx].data.get();
        Some(unsafe { &mut *ptr })
    }

    /// Commit the previously claimed write slot, marking it as readable.
    ///
    /// `len` is the number of valid bytes written.  Values of `len > SZ` are
    /// clamped to `SZ` to avoid out-of-bounds reads on the consumer side.
    ///
    /// Must be called exactly once after a successful [`claim_write`].
    ///
    /// [`claim_write`]: FrameRing::claim_write
    pub fn commit_write(&self, len: usize) {
        let prod = self.producer_idx.load(Ordering::Relaxed);
        let slot_idx = prod & Self::IDX_MASK;
        // Clamp length — never allow consumer to read past slot boundary.
        let valid = if len > SZ { SZ } else { len };
        // Store valid byte count *before* advancing producer_idx so the
        // consumer always sees a consistent (len, data) pair.
        self.slots[slot_idx].len.store(valid, Ordering::Release);
        // Advance producer index with Release so payload write is visible.
        self.producer_idx.store(prod.wrapping_add(1), Ordering::Release);
    }

    // ── Consumer API ─────────────────────────────────────────────────────────

    /// Peek at the next readable frame without consuming it.
    ///
    /// Returns `Some((len, &[u8]))` where `len` is the number of valid bytes
    /// in the slot and the slice has length `SZ` (the slot boundary).  The
    /// caller must not access bytes beyond `len`.
    ///
    /// Returns `None` when the ring is empty.
    ///
    /// The reference remains valid until [`release_read`] is called.
    ///
    /// [`release_read`]: FrameRing::release_read
    pub fn peek_read(&self) -> Option<(usize, &[u8])> {
        let prod = self.producer_idx.load(Ordering::Acquire);
        let cons = self.consumer_idx.load(Ordering::Relaxed);
        if cons == prod {
            return None; // ring empty
        }
        let slot_idx = cons & Self::IDX_MASK;
        // Load valid byte count with Acquire so we see the full data write.
        let len = self.slots[slot_idx].len.load(Ordering::Acquire);
        // SAFETY: SPSC — only the consumer accesses this slot here.  Producer
        // has advanced past it (`prod > cons`).
        let ptr = self.slots[slot_idx].data.get();
        // SAFETY: SPSC — consumer has exclusive read access here.
        // We re-borrow through a reference to avoid the dangerous_implicit_autorefs
        // lint: `(&*ptr)[..]` would autoref through a raw pointer.
        let slice: &[u8] = unsafe { core::slice::from_raw_parts(ptr as *const u8, SZ) };
        Some((len, slice))
    }

    /// Release the front slot after the consumer has finished with it.
    ///
    /// Advances the consumer index so the producer can reclaim the slot.
    /// Must be called once after a successful [`peek_read`].
    ///
    /// [`peek_read`]: FrameRing::peek_read
    pub fn release_read(&self) {
        let cons = self.consumer_idx.load(Ordering::Relaxed);
        // Release so the producer's next Acquire of consumer_idx sees this.
        self.consumer_idx.store(cons.wrapping_add(1), Ordering::Release);
    }

    // ── Utility ──────────────────────────────────────────────────────────────

    /// Number of frames currently queued (approximate — indices are not
    /// loaded atomically as a pair).
    pub fn len(&self) -> usize {
        let prod = self.producer_idx.load(Ordering::Acquire);
        let cons = self.consumer_idx.load(Ordering::Acquire);
        prod.wrapping_sub(cons)
    }

    /// Returns `true` when no frames are queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` when all `N` slots are occupied.
    pub fn is_full(&self) -> bool {
        self.len() >= N
    }

    /// Slot capacity of the ring (generic parameter `N`).
    pub const fn capacity() -> usize {
        N
    }

    /// Maximum bytes per slot (generic parameter `SZ`).
    pub const fn slot_size() -> usize {
        SZ
    }
}

// Suppress the unused-const lint for the assertions (they exist only to
// trigger compile-time failures on invalid parameters).
const _: () = FrameRing::<4, 8>::_N_IS_POW2;
const _: () = FrameRing::<4, 8>::_N_NONZERO;
const _: () = FrameRing::<4, 8>::_SZ_NONZERO;
const _: () = FrameRing::<4, 8>::_N_MAX;


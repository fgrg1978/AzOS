// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fan-out frame ring: one producer, up to `C` consumers, each with its own
//! cursor (wave 15, B2).
//!
//! The camera is captured and encoded once per frame; every consumer (the
//! brain link's sender, the shared-memory stream) reads the same committed
//! frame. A frame is identified by its sequence number (1, 2, ...); a
//! consumer's cursor is the sequence number of the last frame it took.
//!
//! # Policies
//!
//! - [`Policy::OverwriteOldest`]: the producer never waits. It refuses a
//!   frame only after `4 * N` claim attempts all lost a race to a consumer
//!   pinning the chosen slot (bounded retries, counted in
//!   [`FanoutRing::refused`]; not seen in the host stress test). It writes into the oldest slot that holds neither the newest frame nor a
//!   frame a consumer is reading; a consumer that lagged loses the frames
//!   overwritten meanwhile (counted in [`FanoutRing::overwritten`]) and its
//!   next read skips to what is left ([`FrameRef::skipped`]).
//! - [`Policy::Backpressure`]: the producer refuses ([`FanoutRing::claim`]
//!   returns `None`, counted in [`FanoutRing::refused`]) rather than overwrite
//!   a frame an attached consumer has not taken yet. A slow consumer then
//!   holds back capture for every consumer.
//!
//! # Reads never tear, the producer never waits
//!
//! A consumer *pins* the slot it reads ([`FrameRef`] unpins on drop). The
//! producer skips pinned slots and the slot holding the newest frame, so it
//! needs `C + 2` slots to always find one (a compile-time check): at most
//! one pin per consumer, plus the newest, plus the one being written. Pin
//! and claim meet in a Dekker handshake on two `SeqCst` locations: the
//! consumer increments `pins` then re-reads `seq`; the producer stores
//! `WRITING` into `seq` then reads `pins`. In the single total order of
//! `SeqCst` operations one of the two sees the other and backs off, so a
//! slot is never written while a pinned reader holds a reference into it.
//! The frame is read in place: no copy-out, no retry around a copy.
//!
//! A frame's acquisition stamp travels with it: the producer stores it at
//! commit and every consumer reads the stamp of the frame it took, however
//! late.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// What the producer does when every free slot still holds a frame some
/// attached consumer has not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Overwrite the oldest such frame; the latest frame wins.
    OverwriteOldest,
    /// Refuse the new frame until the slowest consumer catches up.
    Backpressure,
}

/// `seq` of a slot that has never held a frame (or whose write was aborted).
const EMPTY: u64 = 0;
/// `seq` of the slot the producer is writing.
const WRITING: u64 = u64::MAX;
/// "No slot" in `latest` and `writing`.
const NO_SLOT: usize = usize::MAX;

struct FSlot<const SZ: usize> {
    /// Sequence number of the frame in the slot, [`EMPTY`] or [`WRITING`].
    seq: AtomicU64,
    /// Consumers holding a [`FrameRef`] into this slot.
    pins: AtomicUsize,
    /// Valid bytes of the frame.
    len: AtomicUsize,
    /// The frame's acquisition stamp (the producer's clock).
    stamp: AtomicU64,
    data: UnsafeCell<[u8; SZ]>,
}

/// One producer, `C` consumers, `N` slots of `SZ` bytes. See the module doc.
pub struct FanoutRing<const N: usize, const SZ: usize, const C: usize> {
    slots: [FSlot<SZ>; N],
    /// Last sequence number committed (0: none yet). Written by the producer.
    seq: AtomicU64,
    /// Slot of the newest committed frame. Producer-owned.
    latest: AtomicUsize,
    /// Slot claimed and not yet committed. Producer-owned.
    writing: AtomicUsize,
    /// Per consumer: the sequence number of the last frame it took.
    cursors: [AtomicU64; C],
    /// Bit `c` set: consumer `c` is attached.
    attached: AtomicUsize,
    policy: Policy,
    produced: AtomicU64,
    refused: AtomicU64,
    overwritten: AtomicU64,
}

// SAFETY: a slot's data is written only by the single producer between
// `claim` and `commit`/`abort`, while no consumer has it pinned (the Dekker
// handshake in the module doc), and read only by consumers that pinned it
// after it was committed.
unsafe impl<const N: usize, const SZ: usize, const C: usize> Sync for FanoutRing<N, SZ, C> {}

/// A committed frame a consumer has pinned. Unpins on drop.
pub struct FrameRef<'a, const N: usize, const SZ: usize, const C: usize> {
    ring: &'a FanoutRing<N, SZ, C>,
    idx: usize,
    seq: u64,
    skipped: u64,
}

impl<const N: usize, const SZ: usize, const C: usize> FrameRef<'_, N, SZ, C> {
    /// The frame's bytes.
    pub fn bytes(&self) -> &[u8] {
        let s = &self.ring.slots[self.idx];
        let len = s.len.load(Ordering::Acquire).min(SZ);
        // SAFETY: the slot is pinned and holds committed frame `self.seq`;
        // the producer never writes a pinned slot (module doc).
        unsafe { core::slice::from_raw_parts(s.data.get() as *const u8, len) }
    }
    /// The frame's acquisition stamp, as the producer committed it.
    pub fn stamp(&self) -> u64 {
        self.ring.slots[self.idx].stamp.load(Ordering::Acquire)
    }
    /// The frame's sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// Frames committed between this consumer's previous frame and this one
    /// that it never took (overwritten, or passed over by a latest read).
    pub fn skipped(&self) -> u64 {
        self.skipped
    }
}

impl<const N: usize, const SZ: usize, const C: usize> Drop for FrameRef<'_, N, SZ, C> {
    fn drop(&mut self) {
        self.ring.slots[self.idx].pins.fetch_sub(1, Ordering::Release);
    }
}

impl<const N: usize, const SZ: usize, const C: usize> FanoutRing<N, SZ, C> {
    const _SLOTS: () = assert!(N >= C + 2, "FanoutRing: N must be >= C + 2 (one pin per consumer, the newest, the one being written)");
    const _CONSUMERS: () = assert!(C >= 1 && C <= usize::BITS as usize, "FanoutRing: 1..=usize::BITS consumers");
    const _SZ: () = assert!(SZ > 0, "FanoutRing: SZ must be > 0");

    /// An empty ring with no consumer attached. Suitable for a `static`.
    pub const fn new(policy: Policy) -> Self {
        let _: () = Self::_SLOTS;
        let _: () = Self::_CONSUMERS;
        let _: () = Self::_SZ;
        // SAFETY: every field of `FSlot` (atomics and a byte array in an
        // `UnsafeCell`) and every `AtomicU64` is valid all-zero: `seq` EMPTY,
        // no pins, length 0, stamp 0, cursor 0.
        let slots: [FSlot<SZ>; N] = unsafe { core::mem::zeroed() };
        let cursors: [AtomicU64; C] = unsafe { core::mem::zeroed() };
        FanoutRing {
            slots,
            seq: AtomicU64::new(0),
            latest: AtomicUsize::new(NO_SLOT),
            writing: AtomicUsize::new(NO_SLOT),
            cursors,
            attached: AtomicUsize::new(0),
            policy,
            produced: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            overwritten: AtomicU64::new(0),
        }
    }

    /// The ring's policy.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    // ── Consumers ────────────────────────────────────────────────────────

    /// Attach consumer `c`. Its cursor starts at the newest frame committed
    /// before this call, so it takes only frames committed afterwards. A
    /// no-op when already attached.
    pub fn attach(&self, c: usize) {
        assert!(c < C);
        let bit = 1usize << c;
        if self.attached.load(Ordering::Acquire) & bit == 0 {
            self.cursors[c].store(self.seq.load(Ordering::Acquire), Ordering::Release);
            self.attached.fetch_or(bit, Ordering::AcqRel);
        }
    }

    /// Detach consumer `c`: the producer stops holding frames for it.
    pub fn detach(&self, c: usize) {
        assert!(c < C);
        self.attached.fetch_and(!(1usize << c), Ordering::AcqRel);
    }

    /// Whether consumer `c` is attached.
    pub fn is_attached(&self, c: usize) -> bool {
        c < C && self.attached.load(Ordering::Acquire) & (1usize << c) != 0
    }

    /// Whether any consumer is attached (the producer has someone to
    /// capture for).
    pub fn any_attached(&self) -> bool {
        self.attached.load(Ordering::Acquire) != 0
    }

    /// The newest frame consumer `c` has not taken; frames older than it
    /// count as skipped. `None`: nothing new.
    pub fn acquire_latest(&self, c: usize) -> Option<FrameRef<'_, N, SZ, C>> {
        self.acquire(c, true)
    }

    /// The oldest frame still in the ring that consumer `c` has not taken;
    /// frames it lost to overwrites count as skipped. `None`: nothing new.
    pub fn acquire_next(&self, c: usize) -> Option<FrameRef<'_, N, SZ, C>> {
        self.acquire(c, false)
    }

    fn acquire(&self, c: usize, newest: bool) -> Option<FrameRef<'_, N, SZ, C>> {
        assert!(c < C);
        let cursor = self.cursors[c].load(Ordering::Acquire);
        // Each failed attempt means the producer took the chosen slot for a
        // newer frame meanwhile; the bound only stops a producer far faster
        // than this reader from keeping it here.
        for _ in 0..2 * N {
            let mut best: Option<(usize, u64)> = None;
            for (i, s) in self.slots.iter().enumerate() {
                let q = s.seq.load(Ordering::Acquire);
                if q == EMPTY || q == WRITING || q <= cursor {
                    continue;
                }
                let better = match best {
                    None => true,
                    Some((_, b)) => if newest { q > b } else { q < b },
                };
                if better {
                    best = Some((i, q));
                }
            }
            let (idx, q) = best?;
            let s = &self.slots[idx];
            s.pins.fetch_add(1, Ordering::SeqCst);
            if s.seq.load(Ordering::SeqCst) == q {
                self.cursors[c].store(q, Ordering::Release);
                return Some(FrameRef { ring: self, idx, seq: q, skipped: q - cursor - 1 });
            }
            s.pins.fetch_sub(1, Ordering::Release);
        }
        None
    }

    // ── Producer (exactly one) ───────────────────────────────────────────

    /// The smallest cursor among attached consumers, or `None` with none.
    fn min_cursor(&self) -> Option<u64> {
        let mask = self.attached.load(Ordering::Acquire);
        (0..C).filter(|c| mask & (1usize << c) != 0)
            .map(|c| self.cursors[c].load(Ordering::Acquire))
            .min()
    }

    /// Claim a slot for the next frame. `None`: [`Policy::Backpressure`]
    /// refused (every free slot holds a frame an attached consumer has not
    /// taken), or every one of the bounded attempts lost a pin race. The
    /// slot is the producer's until [`commit`](Self::commit) or
    /// [`abort`](Self::abort); call one of them before claiming again.
    #[allow(clippy::mut_from_ref)]
    pub fn claim(&self) -> Option<&mut [u8; SZ]> {
        debug_assert_eq!(self.writing.load(Ordering::Relaxed), NO_SLOT, "claim before commit/abort");
        let latest = self.latest.load(Ordering::Relaxed);
        // A retry means a consumer pinned the chosen slot between the scan
        // and the claim, or moved its one pin across slots while the scan
        // ran (so every slot looked pinned). A consumer pins only a frame
        // newer than its cursor and the producer commits nothing meanwhile,
        // so the races run out; the bound keeps the producer from ever
        // waiting on them.
        for _ in 0..4 * N {
            // The oldest free slot not yet tried: EMPTY sorts first.
            let mut pick: Option<(usize, u64)> = None;
            for (i, s) in self.slots.iter().enumerate() {
                if i == latest || s.pins.load(Ordering::SeqCst) != 0 {
                    continue;
                }
                let q = s.seq.load(Ordering::Relaxed);
                if pick.is_none_or(|(_, b)| q < b) {
                    pick = Some((i, q));
                }
            }
            // N >= C + 2 leaves a free slot at any instant: at most one pin
            // per consumer.
            let Some((idx, old)) = pick else { continue };
            let pending = old != EMPTY && self.min_cursor().is_some_and(|m| old > m);
            if pending && self.policy == Policy::Backpressure {
                self.refused.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let s = &self.slots[idx];
            s.seq.store(WRITING, Ordering::SeqCst);
            if s.pins.load(Ordering::SeqCst) != 0 {
                // A consumer pinned it between the scan and the store.
                s.seq.store(old, Ordering::SeqCst);
                continue;
            }
            if pending {
                self.overwritten.fetch_add(1, Ordering::Relaxed);
            }
            self.writing.store(idx, Ordering::Relaxed);
            // SAFETY: `seq` is WRITING and no consumer holds a pin (the
            // handshake above): no `FrameRef` points into this slot and none
            // can be made until `commit` publishes it.
            return Some(unsafe { &mut *s.data.get() });
        }
        self.refused.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Publish the claimed slot as the next frame: `len` bytes (clamped to
    /// `SZ`), acquired at `stamp`. Returns the frame's sequence number.
    pub fn commit(&self, len: usize, stamp: u64) -> u64 {
        let idx = self.writing.swap(NO_SLOT, Ordering::Relaxed);
        assert!(idx != NO_SLOT, "commit without claim");
        let s = &self.slots[idx];
        s.len.store(len.min(SZ), Ordering::Relaxed);
        s.stamp.store(stamp, Ordering::Relaxed);
        let q = self.seq.load(Ordering::Relaxed) + 1;
        // Release: a consumer that reads this seq sees the data, len, stamp.
        s.seq.store(q, Ordering::SeqCst);
        self.latest.store(idx, Ordering::Relaxed);
        self.seq.store(q, Ordering::Release);
        self.produced.fetch_add(1, Ordering::Relaxed);
        q
    }

    /// Give the claimed slot back without publishing (nothing was captured).
    /// Its previous frame is gone: the slot reads as empty.
    pub fn abort(&self) {
        let idx = self.writing.swap(NO_SLOT, Ordering::Relaxed);
        if idx != NO_SLOT {
            self.slots[idx].seq.store(EMPTY, Ordering::SeqCst);
        }
    }

    // ── Counters ─────────────────────────────────────────────────────────

    /// Frames committed.
    pub fn produced(&self) -> u64 {
        self.produced.load(Ordering::Relaxed)
    }
    /// Claims refused (backpressure, or no free slot).
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
    /// Frames overwritten before an attached consumer took them. With a
    /// consumer that reads only the newest frame this counts the frames it
    /// passes over by design, not a loss.
    pub fn overwritten(&self) -> u64 {
        self.overwritten.load(Ordering::Relaxed)
    }
    /// Sequence number of the newest committed frame (0: none).
    pub fn last_seq(&self) -> u64 {
        self.seq.load(Ordering::Acquire)
    }
    /// Slot count.
    pub const fn capacity() -> usize {
        N
    }
    /// Bytes per slot.
    pub const fn slot_size() -> usize {
        SZ
    }
}

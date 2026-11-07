// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The frame pool: one producer, up to `C` readers, `N` buffers of `SZ` bytes.
//!
//! The camera is captured and encoded once per frame. The producer publishes
//! the frame's id into an [`azos_rings::Log`] (one writer, a private cursor
//! per reader) and the frame stays in its buffer; a reader takes a *reference*
//! on the buffer instead of pinning a ring slot, reads, and gives it back
//! ([`FrameRef`] drops it). A frame is identified by its sequence number (1,
//! 2, ...), which is also its number in the log; a reader's cursor is the
//! number of the last frame it took, and it takes the newest it has not taken
//! ([`FramePool::acquire_latest`]).
//!
//! The buffers are not the pool's: the owner lends one address per buffer
//! ([`FramePool::install`]), the kernel's memory objects. Until then the pool
//! is not [`ready`](FramePool::ready) and nothing is claimed.
//!
//! # Policies
//!
//! - [`Policy::OverwriteOldest`]: the producer never waits. It writes into the
//!   oldest buffer that holds neither the newest frame nor a frame a reader
//!   references; a reader that lagged loses the frames overwritten meanwhile
//!   (counted in [`FramePool::overwritten`]) and its next read skips to what
//!   is left ([`FrameRef::skipped`]). It refuses a frame only after `4 * N`
//!   claim attempts all lost a race to a reader (counted in
//!   [`FramePool::refused`]).
//! - [`Policy::Backpressure`]: the producer refuses ([`FramePool::claim`]
//!   returns `None`, counted in [`FramePool::refused`]) rather than overwrite
//!   a frame an attached reader has not taken yet. A slow reader then holds
//!   back capture for every reader.
//!
//! # A reader never sees a frame change under it, and cannot change it
//!
//! A reader holds a reference on the buffer it reads. The producer skips
//! referenced buffers and the one holding the newest frame, so it needs
//! `C + 2` buffers to always find one (a compile-time check): at most one
//! reference per reader, plus the newest, plus the one being written. Taking a
//! reference and claiming meet in a Dekker handshake on two `SeqCst`
//! locations: the reader increments `refs` then re-reads `seq`; the producer
//! stores `FILLING` into `seq` then reads `refs`. In the single total order of
//! `SeqCst` operations one of the two sees the other and backs off, so a
//! buffer is never written while a reader holds a reference into it. The
//! frame is read in place and through a shared slice: [`FrameRef`] has no
//! way to write.
//!
//! # Producers
//!
//! There is one producer at a time, not one producer for good: a claim is
//! taken with a compare-and-swap on `writing` and released by `commit` or
//! `abort`, so two sources that feed the same pool (the CSI capture task and
//! a USB camera's class driver) cannot be in the claim-to-commit window
//! together; the one that finds the window taken gets `None` and does
//! nothing. Which source the pool should carry is the owner's decision, not
//! the pool's.
//!
//! A frame's acquisition stamp travels with it: the producer stores it at
//! commit and every reader reads the stamp of the frame it took, however late.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use azos_rings::Log;

use crate::sink::{FrameInfo, FrameSink};

/// What the producer does when every free buffer still holds a frame some
/// attached reader has not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Overwrite the oldest such frame; the latest frame wins.
    OverwriteOldest,
    /// Refuse the new frame until the slowest reader catches up.
    Backpressure,
}

/// The owner lent fewer buffers than the pool needs (`C + 2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoRoom;

/// A committed frame, as the log carries it: which buffer holds it and its
/// sequence number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameId {
    pub slot: u32,
    pub seq: u64,
}

/// `seq` of a buffer that has never held a frame (or whose write was aborted).
const EMPTY: u64 = 0;
/// `seq` of the buffer the producer is writing.
const FILLING: u64 = u64::MAX;
/// "No buffer" in `writing`.
const NO_SLOT: usize = usize::MAX;
/// `writing` while a claim is choosing its buffer.
const PICKING: usize = usize::MAX - 1;

struct FSlot {
    /// Sequence number of the frame in the buffer, [`EMPTY`] or [`FILLING`].
    seq: AtomicU64,
    /// Readers holding a [`FrameRef`] into this buffer.
    refs: AtomicUsize,
    /// Valid bytes of the frame.
    len: AtomicUsize,
    /// The frame's acquisition stamp (the producer's clock).
    stamp: AtomicU64,
    /// What the bytes are ([`FrameInfo::pack`]); zero is a JPEG of unknown size.
    info: AtomicU64,
    /// The lent buffer: `SZ` bytes at this address.
    base: AtomicUsize,
}

/// One producer, `C` readers, `N` buffers of `SZ` bytes. See the module doc.
pub struct FramePool<const N: usize, const SZ: usize, const C: usize> {
    slots: [FSlot; N],
    /// The ids of the frames committed, newest last.
    ids: Log<FrameId, N>,
    /// Buffers lent; 0 until [`install`](Self::install).
    active: AtomicUsize,
    /// The buffer claimed and not yet committed; `PICKING` while a claim
    /// chooses one, `NO_SLOT` while no producer holds the pool.
    writing: AtomicUsize,
    /// Per reader: the sequence number of the last frame it took.
    cursors: [AtomicU64; C],
    /// Bit `c` set: reader `c` is attached.
    attached: AtomicUsize,
    policy: Policy,
    produced: AtomicU64,
    refused: AtomicU64,
    overwritten: AtomicU64,
}

// SAFETY: a buffer is written only by the single producer between `claim` and
// `commit`/`abort`, while no reader references it (the Dekker handshake in the
// module doc), and read only by readers that referenced it after it was
// committed.
unsafe impl<const N: usize, const SZ: usize, const C: usize> Sync for FramePool<N, SZ, C> {}

/// A committed frame a reader holds a reference on. The reference ends on
/// drop. It reads and nothing else: the frame is a shared slice.
pub struct FrameRef<'a, const N: usize, const SZ: usize, const C: usize> {
    pool: &'a FramePool<N, SZ, C>,
    idx: usize,
    seq: u64,
    skipped: u64,
}

impl<const N: usize, const SZ: usize, const C: usize> FrameRef<'_, N, SZ, C> {
    /// The frame's bytes.
    pub fn bytes(&self) -> &[u8] {
        let s = &self.pool.slots[self.idx];
        let len = s.len.load(Ordering::Acquire).min(SZ);
        let base = s.base.load(Ordering::Relaxed) as *mut u8;
        #[cfg(feature = "canary-reader-writes")]
        if len > 0 {
            // SAFETY: the canary is the reader writing a frame it holds.
            unsafe { base.write(0xEE) };
        }
        // SAFETY: the buffer is referenced and holds committed frame
        // `self.seq`; the producer never writes a referenced buffer (module
        // doc), and `base` is `SZ` lent bytes.
        unsafe { core::slice::from_raw_parts(base as *const u8, len) }
    }
    /// The frame's acquisition stamp, as the producer committed it.
    pub fn stamp(&self) -> u64 {
        self.pool.slots[self.idx].stamp.load(Ordering::Acquire)
    }
    /// What the frame's bytes are, as the producer committed it.
    pub fn info(&self) -> FrameInfo {
        FrameInfo::unpack(self.pool.slots[self.idx].info.load(Ordering::Acquire))
    }
    /// The frame's sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// Frames committed between this reader's previous frame and this one
    /// that it never took (overwritten, or passed over).
    pub fn skipped(&self) -> u64 {
        self.skipped
    }
}

impl<const N: usize, const SZ: usize, const C: usize> Drop for FrameRef<'_, N, SZ, C> {
    fn drop(&mut self) {
        #[cfg(not(feature = "canary-reference-leaks"))]
        self.pool.slots[self.idx].refs.fetch_sub(1, Ordering::Release);
    }
}

impl<const N: usize, const SZ: usize, const C: usize> FramePool<N, SZ, C> {
    const _SLOTS: () = assert!(N >= C + 2, "FramePool: N must be >= C + 2 (one reference per reader, the newest, the one being written)");
    const _READERS: () = assert!(C >= 1 && C <= usize::BITS as usize, "FramePool: 1..=usize::BITS readers");
    const _SZ: () = assert!(SZ > 0, "FramePool: SZ must be > 0");

    /// An empty pool with no buffer and no reader. Suitable for a `static`.
    pub const fn new(policy: Policy) -> Self {
        let _: () = Self::_SLOTS;
        let _: () = Self::_READERS;
        let _: () = Self::_SZ;
        // SAFETY: every field of `FSlot` and every `AtomicU64` is valid
        // all-zero: `seq` EMPTY, no references, length 0, stamp 0, info 0 (a
        // JPEG), no buffer, cursor 0.
        let slots: [FSlot; N] = unsafe { core::mem::zeroed() };
        let cursors: [AtomicU64; C] = unsafe { core::mem::zeroed() };
        FramePool {
            slots,
            ids: Log::new(FrameId { slot: 0, seq: 0 }),
            active: AtomicUsize::new(0),
            writing: AtomicUsize::new(NO_SLOT),
            cursors,
            attached: AtomicUsize::new(0),
            policy,
            produced: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            overwritten: AtomicU64::new(0),
        }
    }

    /// Lend the pool its buffers: `SZ` writable bytes at each address, valid
    /// for good, used by nobody else. The first `N` are taken. Answers how
    /// many the pool uses, or [`NoRoom`] (and uses none) with fewer than
    /// `C + 2`. Once.
    pub fn install(&self, buffers: &[usize]) -> Result<usize, NoRoom> {
        if buffers.len() < C + 2 || self.active.load(Ordering::Acquire) != 0 {
            return Err(NoRoom);
        }
        let n = buffers.len().min(N);
        for (s, b) in self.slots.iter().zip(&buffers[..n]) {
            s.base.store(*b, Ordering::Relaxed);
        }
        self.active.store(n, Ordering::Release);
        Ok(n)
    }

    /// Has the pool its buffers?
    pub fn ready(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
    }

    /// The pool's policy.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    // ── Readers ──────────────────────────────────────────────────────────

    /// Attach reader `c`. Its cursor starts at the newest frame committed
    /// before this call, so it takes only frames committed afterwards. A
    /// no-op when already attached. `false`: the pool has no buffers.
    pub fn attach(&self, c: usize) -> bool {
        assert!(c < C);
        if !self.ready() {
            return false;
        }
        let bit = 1usize << c;
        if self.attached.load(Ordering::Acquire) & bit == 0 {
            self.cursors[c].store(self.ids.head(), Ordering::Release);
            self.attached.fetch_or(bit, Ordering::AcqRel);
        }
        true
    }

    /// Detach reader `c`: the producer stops holding frames for it.
    pub fn detach(&self, c: usize) {
        assert!(c < C);
        #[cfg(not(feature = "canary-detach-keeps"))]
        self.attached.fetch_and(!(1usize << c), Ordering::AcqRel);
    }

    /// Whether reader `c` is attached.
    pub fn is_attached(&self, c: usize) -> bool {
        c < C && self.attached.load(Ordering::Acquire) & (1usize << c) != 0
    }

    /// Whether any reader is attached (the producer has someone to capture
    /// for).
    pub fn any_attached(&self) -> bool {
        self.attached.load(Ordering::Acquire) != 0
    }

    /// The newest frame reader `c` has not taken, with a reference on it;
    /// frames older than it count as skipped. `None`: nothing new.
    pub fn acquire_latest(&self, c: usize) -> Option<FrameRef<'_, N, SZ, C>> {
        assert!(c < C);
        let cursor = self.cursors[c].load(Ordering::Acquire);
        // Each failed attempt means the producer took the chosen buffer for a
        // newer frame meanwhile; the bound only stops a producer far faster
        // than this reader from keeping it here.
        for _ in 0..2 * N {
            let (head, id) = self.ids.latest();
            if head <= cursor {
                return None;
            }
            let s = &self.slots[id.slot as usize];
            s.refs.fetch_add(1, Ordering::SeqCst);
            if s.seq.load(Ordering::SeqCst) == id.seq {
                self.cursors[c].store(id.seq, Ordering::Release);
                return Some(FrameRef { pool: self, idx: id.slot as usize, seq: id.seq, skipped: id.seq - cursor - 1 });
            }
            s.refs.fetch_sub(1, Ordering::Release);
        }
        None
    }

    // ── Producer (exactly one) ───────────────────────────────────────────

    /// The smallest cursor among attached readers, or `None` with none.
    fn min_cursor(&self) -> Option<u64> {
        let mask = self.attached.load(Ordering::Acquire);
        (0..C).filter(|c| mask & (1usize << c) != 0)
            .map(|c| self.cursors[c].load(Ordering::Acquire))
            .min()
    }

    /// Claim a buffer for the next frame. `None`: the pool has no buffers,
    /// [`Policy::Backpressure`] refused (every free buffer holds a frame an
    /// attached reader has not taken), every one of the bounded attempts lost
    /// a reference race, or another producer holds a claim. The buffer is
    /// the producer's until [`commit`](Self::commit) or [`abort`](Self::abort);
    /// call one of them before claiming again.
    #[allow(clippy::mut_from_ref)]
    pub fn claim(&self) -> Option<&mut [u8]> {
        let active = self.active.load(Ordering::Acquire);
        if active == 0 {
            return None;
        }
        // The claim window, taken for good only once a buffer is chosen.
        if self.writing.compare_exchange(NO_SLOT, PICKING, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return None;
        }
        let (head, newest) = self.ids.latest();
        let latest = if head == 0 { NO_SLOT } else { newest.slot as usize };
        // A retry means a reader referenced the chosen buffer between the scan
        // and the claim, or moved its one reference across buffers while the
        // scan ran (so every buffer looked referenced). A reader references
        // only a frame newer than its cursor and the producer commits nothing
        // meanwhile, so the races run out; the bound keeps the producer from
        // ever waiting on them.
        for _ in 0..4 * active {
            // The oldest free buffer: EMPTY sorts first.
            let mut pick: Option<(usize, u64)> = None;
            for (i, s) in self.slots[..active].iter().enumerate() {
                if i == latest || s.refs.load(Ordering::SeqCst) != 0 {
                    continue;
                }
                let q = s.seq.load(Ordering::Relaxed);
                if pick.is_none_or(|(_, b)| q < b) {
                    pick = Some((i, q));
                }
            }
            // N >= C + 2 leaves a free buffer at any instant: at most one
            // reference per reader.
            let Some((idx, old)) = pick else { continue };
            let pending = old != EMPTY && self.min_cursor().is_some_and(|m| old > m);
            #[cfg(not(feature = "canary-backpressure-drops"))]
            if pending && self.policy == Policy::Backpressure {
                self.refused.fetch_add(1, Ordering::Relaxed);
                self.writing.store(NO_SLOT, Ordering::Release);
                return None;
            }
            #[cfg(feature = "canary-overwrite-refuses")]
            if pending && self.policy == Policy::OverwriteOldest {
                self.refused.fetch_add(1, Ordering::Relaxed);
                self.writing.store(NO_SLOT, Ordering::Release);
                return None;
            }
            let s = &self.slots[idx];
            s.seq.store(FILLING, Ordering::SeqCst);
            if s.refs.load(Ordering::SeqCst) != 0 {
                // A reader referenced it between the scan and the store.
                s.seq.store(old, Ordering::SeqCst);
                continue;
            }
            #[cfg(not(feature = "canary-backpressure-drops"))]
            if pending {
                self.overwritten.fetch_add(1, Ordering::Relaxed);
            }
            self.writing.store(idx, Ordering::Relaxed);
            // SAFETY: `seq` is FILLING and no reader holds a reference (the
            // handshake above): no `FrameRef` points into this buffer and
            // none can be made until `commit` publishes it. `writing` names
            // the buffer and no other producer can claim until it is released.
            // `base` is `SZ` lent bytes.
            return Some(unsafe { core::slice::from_raw_parts_mut(s.base.load(Ordering::Relaxed) as *mut u8, SZ) });
        }
        self.refused.fetch_add(1, Ordering::Relaxed);
        self.writing.store(NO_SLOT, Ordering::Release);
        None
    }

    /// Publish the claimed buffer as the next frame: `len` bytes (clamped to
    /// `SZ`) of JPEG, acquired at `stamp`. Returns the frame's sequence
    /// number.
    pub fn commit(&self, len: usize, stamp: u64) -> u64 {
        self.commit_info(len, stamp, FrameInfo::JPEG)
    }

    /// [`commit`](Self::commit) for a frame that is not a JPEG of unknown
    /// size: `info` says what the bytes are (and, for raw pixels, how many).
    pub fn commit_info(&self, len: usize, stamp: u64, info: FrameInfo) -> u64 {
        let idx = self.writing.load(Ordering::Relaxed);
        assert!(idx < N, "commit without claim");
        let s = &self.slots[idx];
        s.len.store(len.min(SZ), Ordering::Relaxed);
        s.stamp.store(stamp, Ordering::Relaxed);
        s.info.store(info.pack(), Ordering::Relaxed);
        // The claim window makes this the only writer.
        let mut w = self.ids.writer().expect("one producer at a time");
        let q = w.head() + 1;
        s.seq.store(q, Ordering::SeqCst);
        w.publish(FrameId { slot: idx as u32, seq: q });
        drop(w);
        self.produced.fetch_add(1, Ordering::Relaxed);
        // The window closes last, with Release: the next producer's claim
        // sees the log as this commit left it.
        self.writing.store(NO_SLOT, Ordering::Release);
        q
    }

    /// Give the claimed buffer back without publishing (nothing was
    /// captured). Its previous frame is gone: the buffer reads as empty.
    pub fn abort(&self) {
        let idx = self.writing.load(Ordering::Relaxed);
        if idx < N {
            self.slots[idx].seq.store(EMPTY, Ordering::SeqCst);
            self.writing.store(NO_SLOT, Ordering::Release);
        }
    }

    // ── Counters ─────────────────────────────────────────────────────────

    /// Frames committed.
    pub fn produced(&self) -> u64 {
        self.produced.load(Ordering::Relaxed)
    }
    /// Claims refused (backpressure, or no free buffer).
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
    /// Frames overwritten before an attached reader took them. With a reader
    /// that reads only the newest frame this counts the frames it passes over
    /// by design, not a loss.
    pub fn overwritten(&self) -> u64 {
        self.overwritten.load(Ordering::Relaxed)
    }
    /// Sequence number of the newest committed frame (0: none).
    pub fn last_seq(&self) -> u64 {
        self.ids.head()
    }
    /// References readers hold now, over all buffers.
    pub fn references(&self) -> usize {
        self.slots.iter().map(|s| s.refs.load(Ordering::Acquire)).sum()
    }
    /// Buffer count.
    pub const fn capacity() -> usize {
        N
    }
    /// Bytes per buffer.
    pub const fn slot_size() -> usize {
        SZ
    }
}

impl<const N: usize, const SZ: usize, const C: usize> FrameSink for FramePool<N, SZ, C> {
    fn wanted(&self) -> bool {
        self.any_attached()
    }
    fn claim(&self) -> Option<&mut [u8]> {
        FramePool::claim(self)
    }
    fn commit(&self, len: usize, stamp: u64, info: FrameInfo) {
        self.commit_info(len, stamp, info);
    }
    fn abort(&self) {
        FramePool::abort(self);
    }
}

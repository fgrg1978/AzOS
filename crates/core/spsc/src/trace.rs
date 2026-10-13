// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-CPU trace record rings (wave 15, TRACE): the layout the kernel tracer
//! (`azos_trace`) produces into and a ring-3 reader (`tracectl`) consumes
//! from, one shared-memory region holding one ring per CPU.
//!
//! # Layout
//!
//! ```text
//! region  [0..64)     header: magic, version, geometry, timebase, policy,
//!                     the compiled classes and the runtime mask (HDR_*)
//!         [56..64)    the timestamp of the last mask change (HDR_MASK_TS)
//!         [64..)      ring i at HDR_BYTES + i * stride, stride = RING_HDR_BYTES + entries * 32
//! ring    [0..4)      tail (u32, consumer written), its own 64-byte line
//!         [64..68)    drops (u32, producer written), its own line
//!         [128..)     entries x 32-byte records
//! record  [0..8)      ts (u64, the timebase the header names)
//!         [8..12)     seq (u32): the index the record was written at
//!         [12..14)    event id (u16, `azos_abi::trace::TRACE_EV_*`)
//!         [14]        cpu (u8)   [15] flags (u8, 0)
//!         [16..32)    four u32 arguments
//! ```
//!
//! # The record path touches one line
//!
//! Unlike [`crate::SpscBytes`], there is no shared head word and no doorbell.
//! A record is published by its own `seq` (a Release store of the index it
//! was written at), so the producer's steady state writes the record's
//! line and nothing else: its head and a cached copy of the consumer's tail
//! live in producer memory, and the shared tail is re-read only when the
//! cached copy says the ring is full. The reader polls; a tracer whose
//! producer paid a wake decision per event would cost more than the events.
//!
//! A slot's `seq` starts at `index - entries` (the previous lap), so a
//! reader at tail `t` finds `seq == t` exactly when record `t` is published.
//! No division anywhere: `entries` is a power of two and a slot is
//! `index & (entries - 1)`.
//!
//! # Policies
//!
//! * [`POLICY_DROP`] (default): a full ring refuses the NEWEST record and
//!   counts it in the ring's `drops` word (the stream rings' policy, for the
//!   same reason: dropping the oldest would race the reader on its slot).
//!   The producer never writes a slot the reader has not released, so a
//!   record read is never torn.
//! * [`POLICY_OVERWRITE`] (a flight recorder): the producer never refuses; a
//!   slot is first marked in progress (`seq = index ^ 1`, which no reader
//!   ever expects at that slot), then written, then published. The reader
//!   re-checks `seq` after its copy and counts a record overwritten under it
//!   as lost, then skips to the oldest surviving record. `drops` counts the
//!   unread records the producer overwrote. Cost: one more store and a
//!   store-store fence per record.
//!
//! # Trust boundary (the producer is the kernel)
//!
//! The reader maps the region read-write to store its tails, so the producer
//! trusts nothing in it: the tail is read as a number only (a garbage tail
//! reads as "full" and costs drops), every slot address is derived from the
//! producer's own `slots` base and mask, and nothing read from the region is
//! used as an address or a length. A hostile reader can lose its own events
//! and nothing else.

use core::sync::atomic::{fence, AtomicU32, Ordering};

/// `"KTR1"`, little-endian.
pub const TRACE_MAGIC: u32 = u32::from_le_bytes(*b"KTR1");
/// Layout version.
pub const TRACE_VERSION: u32 = 1;
/// Bytes of one record.
pub const TRACE_REC_BYTES: usize = 32;
const REC_SHIFT: u32 = TRACE_REC_BYTES.trailing_zeros();
const _: () = assert!(TRACE_REC_BYTES == 1 << REC_SHIFT);
/// Rings a region may hold: the ABI ceiling a reader validates against. The
/// kernel makes at most one ring per CPU of its Kconfig `NR_CPUS`, whose range
/// stops at this value (asserted in `crates/core/trace`); it was 8, the old
/// hard-coded hart bound.
pub const TRACE_MAX_CPUS: u32 = 64;

/// Header word offsets.
pub const HDR_MAGIC: usize = 0;
/// u32: [`TRACE_VERSION`].
pub const HDR_VERSION: usize = 4;
/// u32: [`TRACE_REC_BYTES`].
pub const HDR_REC_BYTES: usize = 8;
/// u32: rings in the region (one per CPU).
pub const HDR_NCPU: usize = 12;
/// u32: records per ring, a power of two.
pub const HDR_ENTRIES: usize = 16;
/// u32: [`POLICY_DROP`] or [`POLICY_OVERWRITE`].
pub const HDR_POLICY: usize = 20;
/// u32: offset of ring 0 from the region base.
pub const HDR_RING_OFF: usize = 24;
/// u32: bytes from one ring to the next.
pub const HDR_RING_STRIDE: usize = 28;
/// u64: ticks per second of the record timestamps (0: unknown, raw counts).
pub const HDR_TS_HZ: usize = 32;
/// u32: [`TS_TIMEBASE`] or [`TS_CYCLES`].
pub const HDR_TS_SOURCE: usize = 40;
/// u32: classes compiled into the kernel (`1 << TRACE_CLASS_*`).
pub const HDR_CLASSES: usize = 44;
/// u32: the runtime class mask (a mirror the kernel updates on every change).
pub const HDR_MASK: usize = 48;
/// u64 (two u32 words, low first): the timestamp, in the records' timebase,
/// of the last mask change, written before [`HDR_MASK`] (wave 15, static
/// keys): a reader dates a change by the kernel's clock, not by when it
/// noticed it.
pub const HDR_MASK_TS: usize = 56;
/// Bytes of the region header.
pub const HDR_BYTES: usize = 64;

/// Ring word offsets: the consumer's tail.
pub const RING_TAIL_OFF: usize = 0;
/// The producer's drop (or overwrite) count, on its own line.
pub const RING_DROPS_OFF: usize = 64;
/// Bytes of a ring header; the records follow.
pub const RING_HDR_BYTES: usize = 128;

/// A full ring refuses the newest record.
pub const POLICY_DROP: u32 = 0;
/// A full ring overwrites the oldest record.
pub const POLICY_OVERWRITE: u32 = 1;
/// Timestamps are the monotonic timebase the clock vDSO reads.
pub const TS_TIMEBASE: u32 = 0;
/// Timestamps are the CPU cycle counter (per CPU, not comparable across
/// CPUs, unknown rate: `HDR_TS_HZ` is 0).
pub const TS_CYCLES: u32 = 1;

/// Bytes of a region of `ncpu` rings of `entries` records.
pub const fn region_bytes(ncpu: u32, entries: u32) -> usize {
    HDR_BYTES + ncpu as usize * ring_stride(entries)
}

/// Bytes from one ring to the next.
pub const fn ring_stride(entries: u32) -> usize {
    RING_HDR_BYTES + entries as usize * TRACE_REC_BYTES
}

/// One decoded record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TraceRecord {
    /// Timestamp, in the header's timebase.
    pub ts: u64,
    /// The index the record was written at (consecutive unless dropped).
    pub seq: u32,
    /// `azos_abi::trace::TRACE_EV_*`.
    pub event: u16,
    /// The CPU that wrote it.
    pub cpu: u8,
    /// Reserved, 0.
    pub flags: u8,
    /// Event-specific arguments.
    pub args: [u32; 4],
}

#[inline(always)]
fn word(addr: usize) -> &'static AtomicU32 {
    // SAFETY: every caller passes an address inside a region laid out as the
    // module doc says, 4-byte aligned (every offset above is).
    unsafe { &*(addr as *const AtomicU32) }
}

/// Write the region header and reset every ring of a region at `base`
/// (`region_bytes(ncpu, entries)` long, 64-byte aligned): tails and drops 0,
/// every slot's `seq` set to its previous lap. Called once, by the kernel,
/// before any producer runs and before the region can be mapped.
pub fn region_init(base: usize, ncpu: u32, entries: u32, policy: u32, ts_hz: u64, ts_source: u32, classes: u32) {
    debug_assert!(entries.is_power_of_two() && base % 64 == 0);
    let w = |off: usize, v: u32| word(base + off).store(v, Ordering::Relaxed);
    w(HDR_VERSION, TRACE_VERSION);
    w(HDR_REC_BYTES, TRACE_REC_BYTES as u32);
    w(HDR_NCPU, ncpu);
    w(HDR_ENTRIES, entries);
    w(HDR_POLICY, policy);
    w(HDR_RING_OFF, HDR_BYTES as u32);
    w(HDR_RING_STRIDE, ring_stride(entries) as u32);
    w(HDR_TS_HZ, ts_hz as u32);
    w(HDR_TS_HZ + 4, (ts_hz >> 32) as u32);
    w(HDR_TS_SOURCE, ts_source);
    w(HDR_CLASSES, classes);
    w(HDR_MASK, 0);
    w(HDR_MASK_TS, 0);
    w(HDR_MASK_TS + 4, 0);
    for cpu in 0..ncpu {
        let ring = base + HDR_BYTES + cpu as usize * ring_stride(entries);
        word(ring + RING_TAIL_OFF).store(0, Ordering::Relaxed);
        word(ring + RING_DROPS_OFF).store(0, Ordering::Relaxed);
        for i in 0..entries {
            let s = ring + RING_HDR_BYTES + i as usize * TRACE_REC_BYTES;
            word(s + 8).store(i.wrapping_sub(entries), Ordering::Relaxed);
        }
    }
    // The magic last: a reader that sees it sees a whole header.
    word(base + HDR_MAGIC).store(TRACE_MAGIC, Ordering::Release);
}

/// The producing side of one ring, held in producer (kernel) memory: its
/// head, a cached copy of the reader's tail and its drop count never live in
/// the region (module doc, "Trust boundary").
#[derive(Debug)]
pub struct TraceProducer {
    /// Address of record 0.
    slots: usize,
    /// Address of the ring header.
    ring: usize,
    /// `entries - 1`.
    mask: u32,
    /// `(entries - 1) * TRACE_REC_BYTES`: the slot offset mask.
    mask_bytes: usize,
    /// Next index to write.
    head: u32,
    /// The reader's tail as last read.
    ctail: u32,
    /// Records refused (drop) or unread records overwritten (overwrite).
    drops: u32,
    /// This ring's CPU, already in its place in the record's event word
    /// (`cpu << 16`), stamped into every record.
    cpu_meta: u32,
}

impl TraceProducer {
    /// An unattached producer: [`TraceProducer::is_live`] is false.
    pub const fn empty() -> Self {
        TraceProducer { slots: 0, ring: 0, mask: 0, mask_bytes: 0, head: 0, ctail: 0, drops: 0, cpu_meta: 0 }
    }

    /// Attach to ring `cpu` of the region at `base`, which
    /// [`region_init`] has initialised.
    pub fn attach(base: usize, cpu: u32, entries: u32) -> Self {
        let ring = base + HDR_BYTES + cpu as usize * ring_stride(entries);
        TraceProducer {
            slots: ring + RING_HDR_BYTES,
            ring,
            mask: entries - 1,
            mask_bytes: (entries as usize - 1) << REC_SHIFT,
            head: 0,
            ctail: 0,
            drops: 0,
            cpu_meta: (cpu & 0xff) << 16,
        }
    }

    /// Is this producer attached to a ring?
    #[inline(always)]
    pub fn is_live(&self) -> bool {
        self.slots != 0
    }

    /// Next index to write: records published so far (a dropped record does
    /// not advance it).
    pub fn head(&self) -> u32 {
        self.head
    }

    /// Records dropped (or overwritten unread) so far.
    pub fn drops(&self) -> u32 {
        self.drops
    }

    /// Write one record. `OVERWRITE` is the policy, a constant at every call
    /// site so the other policy's code is not compiled. Returns whether it
    /// was written (always, under overwrite).
    ///
    /// Address arithmetic wraps rather than checks: every address is a
    /// producer-owned base plus a masked offset, inside the region by
    /// construction, and a checked add would cost a compare and a branch per
    /// store on a path that runs on every event.
    #[inline(always)]
    pub fn push<const OVERWRITE: bool>(&mut self, ts: u64, event: u16, args: [u32; 4]) -> bool {
        let h = self.head;
        if h.wrapping_sub(self.ctail) > self.mask {
            // The cached tail says full: read the reader's real one. Untrusted:
            // garbage reads as full (h - garbage is large), never as room.
            self.ctail = word(self.ring.wrapping_add(RING_TAIL_OFF)).load(Ordering::Acquire);
            if h.wrapping_sub(self.ctail) > self.mask {
                self.drops = self.drops.wrapping_add(1);
                word(self.ring.wrapping_add(RING_DROPS_OFF)).store(self.drops, Ordering::Relaxed);
                if !OVERWRITE {
                    return false;
                }
            }
        }
        // `(h << 5) & (mask << 5)`: the slot's byte offset in two
        // instructions (the zero extension of `h` is masked away).
        let s = self.slots.wrapping_add(((h as usize) << REC_SHIFT) & self.mask_bytes);
        let seq = word(s.wrapping_add(8));
        if OVERWRITE {
            // In progress: `h ^ 1` differs from `h` modulo every power of
            // two >= 2, so no reader expects it at this slot.
            seq.store(h ^ 1, Ordering::Relaxed);
            fence(Ordering::Release);
        }
        let p = s as *mut u32;
        // SAFETY: the slot is inside the ring by construction (masked index,
        // producer-owned base) and is not the reader's until `seq` says so.
        // Word stores: the arguments arrive as four registers, and packing
        // them into two doublewords costs more than the two extra stores.
        unsafe {
            core::ptr::write_volatile(s as *mut u64, ts);
            core::ptr::write_volatile(p.add(3), event as u32 | self.cpu_meta);
            core::ptr::write_volatile(p.add(4), args[0]);
            core::ptr::write_volatile(p.add(5), args[1]);
            core::ptr::write_volatile(p.add(6), args[2]);
            core::ptr::write_volatile(p.add(7), args[3]);
        }
        seq.store(h, Ordering::Release);
        // The canary breaks the producer index: every record lands on one slot.
        self.head = if cfg!(feature = "trace-producer-canary") { h } else { h.wrapping_add(1) };
        true
    }

    /// The record at index `i` as this producer wrote it, if it is still in
    /// the ring (`head - entries <= i < head`) and not being overwritten. For
    /// the kernel's own post-mortem dump, which reads its own view, never the
    /// reader's tail.
    pub fn peek(&self, i: u32) -> Option<TraceRecord> {
        let back = self.head.wrapping_sub(i);
        if back == 0 || back > self.mask + 1 {
            return None;
        }
        let s = self.slots + ((i & self.mask) as usize) * TRACE_REC_BYTES;
        let r = read_record(s);
        (r.seq == i).then_some(r)
    }
}

fn read_record(s: usize) -> TraceRecord {
    // SAFETY: `s` is a slot address inside a mapped ring.
    unsafe {
        let meta = core::ptr::read_volatile((s + 12) as *const u32);
        let a01 = core::ptr::read_volatile((s + 16) as *const u64);
        let a23 = core::ptr::read_volatile((s + 24) as *const u64);
        TraceRecord {
            ts: core::ptr::read_volatile(s as *const u64),
            seq: core::ptr::read_volatile((s + 8) as *const u32),
            event: meta as u16,
            cpu: (meta >> 16) as u8,
            flags: (meta >> 24) as u8,
            args: [a01 as u32, (a01 >> 32) as u32, a23 as u32, (a23 >> 32) as u32],
        }
    }
}

/// What one [`TraceConsumer::pop`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pop {
    /// The next record.
    Rec(TraceRecord),
    /// Nothing published yet.
    Empty,
    /// `n` records were overwritten before they could be read (overwrite
    /// policy only); the tail moved past them.
    Lost(u32),
}

/// The reading side of one ring (ring 3).
#[derive(Clone, Copy, Debug)]
pub struct TraceConsumer {
    slots: usize,
    ring: usize,
    mask: u32,
    tail: u32,
    overwrite: bool,
}

/// The geometry a region's header describes, if it is a sane one that fits
/// in `mapped` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceGeometry {
    /// Rings.
    pub ncpu: u32,
    /// Records per ring.
    pub entries: u32,
    /// [`POLICY_DROP`] or [`POLICY_OVERWRITE`].
    pub policy: u32,
    /// Timestamp ticks per second (0: unknown).
    pub ts_hz: u64,
    /// [`TS_TIMEBASE`] or [`TS_CYCLES`].
    pub ts_source: u32,
    /// Classes compiled in.
    pub classes: u32,
}

impl TraceGeometry {
    /// Read and check the header at `base`.
    pub fn from_header(base: usize, mapped: usize) -> Option<TraceGeometry> {
        if mapped < HDR_BYTES || word(base + HDR_MAGIC).load(Ordering::Acquire) != TRACE_MAGIC {
            return None;
        }
        let r = |off: usize| word(base + off).load(Ordering::Relaxed);
        let g = TraceGeometry {
            ncpu: r(HDR_NCPU),
            entries: r(HDR_ENTRIES),
            policy: r(HDR_POLICY),
            ts_hz: r(HDR_TS_HZ) as u64 | (r(HDR_TS_HZ + 4) as u64) << 32,
            ts_source: r(HDR_TS_SOURCE),
            classes: r(HDR_CLASSES),
        };
        let ok = r(HDR_VERSION) == TRACE_VERSION
            && r(HDR_REC_BYTES) == TRACE_REC_BYTES as u32
            && g.entries.is_power_of_two()
            && g.ncpu >= 1
            && g.ncpu <= TRACE_MAX_CPUS
            && r(HDR_RING_OFF) == HDR_BYTES as u32
            && r(HDR_RING_STRIDE) as usize == ring_stride(g.entries)
            && (g.ncpu as u64) * (ring_stride(g.entries) as u64) + HDR_BYTES as u64 <= mapped as u64;
        ok.then_some(g)
    }

    /// The runtime mask mirror in the header at `base`.
    pub fn mask(base: usize) -> u32 {
        word(base + HDR_MASK).load(Ordering::Acquire)
    }

    /// When the last mask change happened ([`HDR_MASK_TS`]; 0 never).
    pub fn mask_ts(base: usize) -> u64 {
        word(base + HDR_MASK_TS).load(Ordering::Relaxed) as u64
            | (word(base + HDR_MASK_TS + 4).load(Ordering::Relaxed) as u64) << 32
    }

    /// Record a mask change at `ts` (the kernel, under its mask lock).
    pub fn set_mask(base: usize, mask: u32, ts: u64) {
        word(base + HDR_MASK_TS).store(ts as u32, Ordering::Relaxed);
        word(base + HDR_MASK_TS + 4).store((ts >> 32) as u32, Ordering::Relaxed);
        word(base + HDR_MASK).store(mask, Ordering::Release);
    }
}

impl TraceConsumer {
    /// The reader of ring `cpu` in the region at `base` described by `g`.
    /// Starts at the tail stored in the ring (where the last reader stopped).
    pub fn new(base: usize, g: &TraceGeometry, cpu: u32) -> Self {
        let ring = base + HDR_BYTES + cpu as usize * ring_stride(g.entries);
        TraceConsumer {
            slots: ring + RING_HDR_BYTES,
            ring,
            mask: g.entries - 1,
            tail: word(ring + RING_TAIL_OFF).load(Ordering::Relaxed),
            overwrite: g.policy == POLICY_OVERWRITE,
        }
    }

    /// The producer's drop (or overwrite) count.
    pub fn drops(&self) -> u32 {
        word(self.ring + RING_DROPS_OFF).load(Ordering::Relaxed)
    }

    /// Next index to read.
    pub fn tail(&self) -> u32 {
        self.tail
    }

    /// Take the next record, if one is published. Does not release its slot:
    /// call [`TraceConsumer::release`] after a batch.
    pub fn pop(&mut self) -> Pop {
        let t = self.tail;
        let s = self.slots + ((t & self.mask) as usize) * TRACE_REC_BYTES;
        let mut q = word(s + 8).load(Ordering::Acquire);
        if q != t {
            if (q ^ t) & self.mask != 0 {
                // An in-progress marker (`index ^ 1`): that index is being written.
                q ^= 1;
            }
            let ahead = q.wrapping_sub(t) as i32;
            if ahead <= 0 {
                return Pop::Empty;
            }
            // Lapped: index `q` replaced `t`. The oldest record that can still
            // be there is `q - entries + 1`.
            let next = q.wrapping_sub(self.mask);
            let lost = next.wrapping_sub(t);
            self.tail = next;
            return Pop::Lost(lost);
        }
        let r = read_record(s);
        if self.overwrite {
            // Seqlock re-check: the copy above happened before this load.
            fence(Ordering::Acquire);
            if word(s + 8).load(Ordering::Relaxed) != t {
                self.tail = t.wrapping_add(1);
                return Pop::Lost(1);
            }
        }
        self.tail = t.wrapping_add(1);
        Pop::Rec(TraceRecord { seq: t, ..r })
    }

    /// Hand every slot read so far back to the producer (one store per batch).
    pub fn release(&self) {
        word(self.ring + RING_TAIL_OFF).store(self.tail, Ordering::Release);
    }
}

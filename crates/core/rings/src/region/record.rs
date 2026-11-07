// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The record substrate: one region holding one overwrite ring per record
//! source, every record behind the same [`Envelope`], and one reader,
//! [`Merge`], that takes them all in time order.
//!
//! The kernel log, the decision records and the actuation telemetry each
//! have a ring here (`azos_records` places them); the kernel writes, a
//! ring-3 sink (`logd`) maps the region read-only and reads. Both sides
//! compile this file, so the layout is the contract.
//!
//! # Layout (little endian)
//!
//! ```text
//! region  [0..4)      magic "REC1"           [4..8)    version
//!         [8..12)     rings (u32, at most MAX_RINGS)
//!         [16..24)    ts_hz: ticks per second of the timebase clock
//!         [64..192)   ring table, MAX_RINGS x 16 bytes:
//!                     offset u32, slot bytes u32, entries u32, source u8
//! ring    [0..8)      head (u64): records claimed so far, alone on its line
//!         [8..16)     base (u64): the first record the ring ever held (a
//!                     ring that took over from another starts past 0)
//!         [16..24)    lapped (u64): records whose producer the ring lapped mid-store
//!         [64..)      entries x slot-bytes slots
//! slot    [0..8)      stamp: 2s+1 while record s is being stored, 2s+2 once whole
//!         [8..16)     seq    (u64)  s, the record's index in its ring since boot
//!         [16..24)    ts     (u64)  in the clock `clock` names
//!         [24]        clock  (u8)   CLOCK_*
//!         [25]        source (u8)   the ring's source
//!         [26..28)    kind   (u16)  the source's own record kind
//!         [28..30)    len    (u16)  payload bytes
//!         [30]        cpu    (u8)
//!         [31]        flags  (u8)   the source's own
//!         [32..)      payload
//! ```
//!
//! # Protocol
//!
//! [`Log`](crate::Log)'s, over bytes, with the claim of a ring many CPUs
//! write: a producer takes index `s` with one `fetch_add` on the ring's head
//! (an interrupt handler that logs over a producer it interrupted gets the
//! next index, so nothing is masked or locked), stores the record between the
//! two stamps, and never waits: a full ring overwrites its oldest record.
//! A reader writes nothing to the region (the grant is `READ|MAP`; a hostile
//! reader cannot touch the kernel's words) and keeps a cursor per ring: it
//! takes slot `c` when its stamp is `2c+2`, re-reading the stamp after its
//! copy. A stamp that moved, or a cursor behind the oldest record, is a lap:
//! the reader jumps to the oldest record still there and is told how many it
//! lost ([`Read::Lost`]). A stamp below `2c+2` with the head past `c` is a
//! producer that claimed the slot and has not finished ([`Read::Pending`]).
//! A whole slot whose envelope names another sequence than the stamp's is not
//! the record `c` was: it is dropped and counted ([`Read::Stale`]), never
//! handed on as `c`.
//!
//! **A lapped producer.** A producer stalled mid-store (a descheduled vCPU, a
//! long interrupt) while the ring laps it shares its slot with the lapper.
//! Its final stamp is a compare-and-swap from its own odd stamp, so it never
//! lands over the lapper's: the slot's stamp never goes backward, and the
//! producer counts its record lost in the ring's `lapped` word
//! ([`Ring::lapped`]). What this does not close: if the lapper has already
//! finished, the stalled producer's late payload stores land under the
//! lapper's even stamp, and a reader copying in that window hands on mixed
//! bytes. Every such record is one the `lapped` word counts, so a sink can
//! say how many records may be torn; preventing it needs a claim that can
//! refuse (per-slot descriptor states, as Linux's printk ring has).
//!
//! The payload copies race the producer's stores (a seqlock's copy): the
//! stamp re-check discards a copy that raced, and on riscv64, aarch64 and
//! x86_64 a racing byte copy only ever yields bytes some store wrote.
//!
//! # One reader
//!
//! [`Merge`] holds one cursor per ring and the next record of each, and hands
//! out the oldest by timestamp (ties by ring), so a sink sees the kernel log,
//! the decisions and the telemetry as one sequence of events, in order. A
//! ring with a producer mid-store holds the merge back ([`Step::Pending`]): a
//! newer record of another ring is not handed out ahead of it.

use core::sync::atomic::{fence, AtomicU64, Ordering};

/// `"REC1"`.
pub const MAGIC: u32 = u32::from_le_bytes(*b"REC1");
/// Layout version.
pub const VERSION: u32 = 1;
/// Rings a region can describe.
pub const MAX_RINGS: usize = 8;
/// Bytes of the region header, the ring table included.
pub const HDR_BYTES: usize = 192;
/// Bytes before a ring's first slot: its head, on a line of its own.
pub const RING_HDR_BYTES: usize = 64;
/// Bytes of a slot's stamp and envelope; the payload follows.
pub const ENV_BYTES: usize = 32;

const OFF_VERSION: usize = 4;
const OFF_RINGS: usize = 8;
const OFF_TS_HZ: usize = 16;
const OFF_TABLE: usize = 64;
const DESC_BYTES: usize = 16;

const S_STAMP: usize = 0;
const S_SEQ: usize = 8;
const S_TS: usize = 16;
/// The word of clock, source, kind, len, cpu and flags (little endian, so
/// their byte offsets are the layout's 24..32).
const S_META: usize = 24;

const _: () = assert!(OFF_TABLE + MAX_RINGS * DESC_BYTES <= HDR_BYTES && HDR_BYTES % 64 == 0);

/// The monotonic timebase every producer stamps with (`ts_hz` ticks a second).
pub const CLOCK_TIMEBASE: u8 = 0;

/// `flags` bit of a record stamped before the timebase was calibrated (x86_64
/// until `timer_probe`): its `ts` runs fast, only its order is good.
pub const FLAG_CLOCK_UNCALIBRATED: u8 = 0x80;

/// The kernel log: every `kerr!` .. `kprintln!` line.
pub const SOURCE_KLOG: u8 = 1;
/// The explainable decision records (`azos_decision`).
pub const SOURCE_DECISION: u8 = 2;
/// The actuation telemetry (`azos_actuation::logger`'s ordinary events).
pub const SOURCE_TELEMETRY: u8 = 3;

/// What every record carries, whatever its source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Envelope {
    /// The record's index in its ring since boot.
    pub seq: u64,
    pub ts: u64,
    pub clock: u8,
    pub source: u8,
    pub kind: u16,
    /// Payload bytes.
    pub len: u16,
    pub cpu: u8,
    pub flags: u8,
}

/// One ring of a region, as the producer lays it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingSpec {
    pub source: u8,
    /// Bytes of a slot: [`ENV_BYTES`] plus the payload, a multiple of 8.
    pub slot_bytes: u32,
    /// Slots, a power of two.
    pub entries: u32,
}

impl RingSpec {
    /// Payload bytes a slot holds.
    pub const fn payload(&self) -> usize {
        self.slot_bytes as usize - ENV_BYTES
    }
    const fn bytes(&self) -> usize {
        RING_HDR_BYTES + self.entries as usize * self.slot_bytes as usize
    }
    const fn valid(&self) -> bool {
        self.slot_bytes as usize > ENV_BYTES && self.slot_bytes % 8 == 0 && self.entries.is_power_of_two()
    }
}

/// Bytes of a region holding `rings`, in order.
pub const fn region_bytes(rings: &[RingSpec]) -> usize {
    let mut n = HDR_BYTES;
    let mut i = 0;
    while i < rings.len() {
        n += rings[i].bytes();
        i += 1;
    }
    n
}

/// The byte offset of ring `i` of a region holding `rings`.
pub const fn ring_offset(rings: &[RingSpec], i: usize) -> usize {
    let mut n = HDR_BYTES;
    let mut k = 0;
    while k < i {
        n += rings[k].bytes();
        k += 1;
    }
    n
}

/// The header of a region holding `rings`, as bytes: the const form a
/// region in `.bss` is built from. Rings past [`MAX_RINGS`] or not
/// [`RingSpec::valid`] make the build fail.
pub const fn header(rings: &[RingSpec], ts_hz: u64) -> [u8; HDR_BYTES] {
    assert!(rings.len() <= MAX_RINGS);
    let mut h = [0u8; HDR_BYTES];
    put(&mut h, 0, &MAGIC.to_le_bytes());
    put(&mut h, OFF_VERSION, &VERSION.to_le_bytes());
    put(&mut h, OFF_RINGS, &(rings.len() as u32).to_le_bytes());
    put(&mut h, OFF_TS_HZ, &ts_hz.to_le_bytes());
    let mut off = HDR_BYTES;
    let mut i = 0;
    while i < rings.len() {
        let r = rings[i];
        assert!(r.valid());
        let d = OFF_TABLE + i * DESC_BYTES;
        put(&mut h, d, &(off as u32).to_le_bytes());
        put(&mut h, d + 4, &r.slot_bytes.to_le_bytes());
        put(&mut h, d + 8, &r.entries.to_le_bytes());
        h[d + 12] = r.source;
        off += r.bytes();
        i += 1;
    }
    h
}

const fn put(h: &mut [u8; HDR_BYTES], at: usize, b: &[u8]) {
    let mut i = 0;
    while i < b.len() {
        h[at + i] = b[i];
        i += 1;
    }
}

/// Format `base` as a region of `rings`, every ring empty.
///
/// # Safety
/// `base` is 64-aligned, writable, zeroed, [`region_bytes`]`(rings)` long,
/// and no producer or reader uses it yet.
pub unsafe fn format(base: *mut u8, rings: &[RingSpec], ts_hz: u64) {
    let h = header(rings, ts_hz);
    // SAFETY: the caller owns the region.
    unsafe { core::ptr::copy_nonoverlapping(h.as_ptr(), base, HDR_BYTES) };
    fence(Ordering::Release);
}

#[inline]
unsafe fn word(base: *const u8, off: usize) -> &'static AtomicU64 {
    // SAFETY: the caller keeps `base + off` inside a live, 8-aligned region.
    unsafe { AtomicU64::from_ptr(base.add(off) as *mut u64) }
}

#[inline]
unsafe fn read_u32(base: *const u8, off: usize) -> u32 {
    // SAFETY: as `word`.
    unsafe { core::ptr::read_volatile(base.add(off) as *const u32) }
}

/// One ring's geometry: where its head and slots are.
#[derive(Clone, Copy)]
struct Geom {
    ring: *mut u8,
    slot_bytes: usize,
    entries: u64,
    source: u8,
}

impl Geom {
    #[inline]
    fn head(&self) -> &'static AtomicU64 {
        // SAFETY: the ring's first word, inside the region.
        unsafe { word(self.ring, 0) }
    }
    #[inline]
    fn base(&self) -> &'static AtomicU64 {
        // SAFETY: the ring's second word, inside the region.
        unsafe { word(self.ring, 8) }
    }
    #[inline]
    fn lapped(&self) -> &'static AtomicU64 {
        // SAFETY: the ring's third word, inside the region.
        unsafe { word(self.ring, 16) }
    }
    #[inline]
    fn oldest(&self, head: u64) -> u64 {
        head.saturating_sub(self.entries).max(self.base().load(Ordering::Relaxed))
    }
    #[inline]
    fn slot(&self, i: u64) -> *mut u8 {
        // SAFETY: the index is masked to the ring.
        unsafe { self.ring.add(RING_HDR_BYTES + (i & (self.entries - 1)) as usize * self.slot_bytes) }
    }
}

/// A region, its header validated once: the rings it holds.
#[derive(Clone, Copy)]
pub struct Region {
    base: *mut u8,
    rings: usize,
    ts_hz: u64,
}

// SAFETY: every access to the region is through atomics or under the stamp
// protocol; the pointer is to memory that lives as long as the view is used.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    /// Open the region at `base`, `len` bytes: `None` unless it is one of
    /// this layout version whose every ring fits.
    ///
    /// # Safety
    /// `base` is 64-aligned and readable for `len` bytes for as long as the
    /// view (and any ring of it) is used.
    pub unsafe fn open(base: *const u8, len: usize) -> Option<Region> {
        if len < HDR_BYTES {
            return None;
        }
        // SAFETY: inside the header.
        let (magic, version, rings) = unsafe { (read_u32(base, 0), read_u32(base, OFF_VERSION), read_u32(base, OFF_RINGS)) };
        if magic != MAGIC || version != VERSION || rings as usize > MAX_RINGS {
            return None;
        }
        let r = Region { base: base as *mut u8, rings: rings as usize, ts_hz: 0 };
        for i in 0..r.rings {
            let g = r.desc(i);
            let (off, slot, entries) = (g.0 as usize, g.1 as usize, g.2);
            let spec = RingSpec { source: 0, slot_bytes: slot as u32, entries };
            if !spec.valid() || off % 64 != 0 || off < HDR_BYTES || off.checked_add(spec.bytes()).map_or(true, |end| end > len) {
                return None;
            }
        }
        // SAFETY: inside the header.
        let ts_hz = unsafe { word(base, OFF_TS_HZ).load(Ordering::Relaxed) };
        Some(Region { ts_hz, ..r })
    }

    fn desc(&self, i: usize) -> (u32, u32, u32, u8) {
        let d = OFF_TABLE + i * DESC_BYTES;
        // SAFETY: inside the header (`i < rings <= MAX_RINGS`).
        unsafe { (read_u32(self.base, d), read_u32(self.base, d + 4), read_u32(self.base, d + 8), *self.base.add(d + 12)) }
    }

    fn geom(&self, i: usize) -> Option<Geom> {
        if i >= self.rings {
            return None;
        }
        let (off, slot, entries, source) = self.desc(i);
        // SAFETY: `open` checked the ring lies inside the region.
        Some(Geom { ring: unsafe { self.base.add(off as usize) }, slot_bytes: slot as usize, entries: entries as u64, source })
    }

    /// Rings in the region.
    pub fn rings(&self) -> usize {
        self.rings
    }
    /// Ticks per second of [`CLOCK_TIMEBASE`].
    pub fn ts_hz(&self) -> u64 {
        self.ts_hz
    }
    /// Ring `i`, to read.
    pub fn ring(&self, i: usize) -> Option<Ring> {
        self.geom(i).map(|g| Ring { g })
    }
    /// The ring of `source`, to read.
    pub fn ring_of(&self, source: u8) -> Option<Ring> {
        (0..self.rings).find_map(|i| self.ring(i).filter(|r| r.source() == source))
    }

    /// Ring `i`, to write.
    ///
    /// # Safety
    /// The caller owns the region (it formatted it, or built it from
    /// [`header`]), so the geometry it reads back is its own.
    pub unsafe fn writer(&self, i: usize) -> Option<Writer> {
        self.geom(i).map(|g| Writer { g })
    }
}

/// What one [`Ring::read`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Read {
    /// The record at the cursor, copied out; the cursor moved past it.
    Record,
    /// Nothing newer than the cursor.
    Empty,
    /// A producer has claimed the record at the cursor and not finished
    /// storing it. Retry; a reader that sees it for good may [`Ring::skip`].
    Pending,
    /// The producer lapped the reader: this many records are gone, and the
    /// cursor now stands at the oldest one left.
    Lost(u64),
    /// The slot was whole but held a record of another sequence: dropped, and
    /// the cursor moved past it.
    Stale,
}

/// A ring, to read. Holds no cursor: the reader keeps its own.
#[derive(Clone, Copy)]
pub struct Ring {
    g: Geom,
}

impl Ring {
    /// The ring at `ring` laid out as `spec` (a producer reading its own
    /// region, whose geometry it knows at build time).
    ///
    /// # Safety
    /// `ring` is the start of a ring of `spec` inside a live region.
    pub const unsafe fn at(ring: *const u8, spec: RingSpec) -> Ring {
        Ring { g: Geom { ring: ring as *mut u8, slot_bytes: spec.slot_bytes as usize, entries: spec.entries as u64, source: spec.source } }
    }

    pub fn source(&self) -> u8 {
        self.g.source
    }
    /// Slots in the ring.
    pub fn entries(&self) -> u64 {
        self.g.entries
    }
    /// Payload bytes a slot holds.
    pub fn payload(&self) -> usize {
        self.g.slot_bytes - ENV_BYTES
    }
    /// Records claimed so far.
    pub fn head(&self) -> u64 {
        self.g.head().load(Ordering::Acquire)
    }
    /// The oldest record still in the ring.
    pub fn oldest(&self) -> u64 {
        self.g.oldest(self.head())
    }
    /// Records whose producer the ring lapped mid-store (lost, and possibly
    /// read torn: see the module's protocol notes).
    pub fn lapped(&self) -> u64 {
        self.g.lapped().load(Ordering::Relaxed)
    }

    /// The record at `*cursor`: its envelope into `env`, its payload into
    /// `payload` (cut at the slot's payload or at `payload.len()`).
    pub fn read(&self, cursor: &mut u64, env: &mut Envelope, payload: &mut [u8]) -> Read {
        let head = self.head();
        let c = *cursor;
        let oldest = self.g.oldest(head);
        if c < oldest {
            *cursor = oldest;
            return self.lost(oldest - c);
        }
        if c >= head {
            return Read::Empty;
        }
        let slot = self.g.slot(c);
        // SAFETY: the slot is inside the region `open` validated.
        let stamp = unsafe { word(slot, S_STAMP) };
        let want = c.wrapping_mul(2).wrapping_add(2);
        let s = stamp.load(Ordering::Acquire);
        if s < want {
            return Read::Pending;
        }
        if s > want {
            return self.overrun(cursor);
        }
        let n = payload.len().min(self.payload());
        // SAFETY: loads inside the slot; a torn copy is caught by the stamp.
        unsafe {
            env.seq = word(slot, S_SEQ).load(Ordering::Relaxed);
            env.ts = word(slot, S_TS).load(Ordering::Relaxed);
            let m = word(slot, S_META).load(Ordering::Relaxed);
            (env.clock, env.source, env.kind, env.len) = (m as u8, (m >> 8) as u8, (m >> 16) as u16, (m >> 32) as u16);
            (env.cpu, env.flags) = ((m >> 48) as u8, (m >> 56) as u8);
            core::ptr::copy_nonoverlapping(slot.add(ENV_BYTES), payload.as_mut_ptr(), n);
        }
        #[cfg(feature = "test-hook")]
        test_hook::between_copy_and_recheck();
        #[cfg(not(feature = "canary-no-fence"))]
        fence(Ordering::Acquire);
        #[cfg(not(feature = "canary-no-recheck"))]
        if stamp.load(Ordering::Relaxed) != want {
            return self.overrun(cursor);
        }
        #[cfg(not(feature = "canary-record-stale"))]
        if env.seq != c || env.source != self.g.source {
            *cursor = c + 1;
            return Read::Stale;
        }
        *cursor = c + 1;
        Read::Record
    }

    fn overrun(&self, cursor: &mut u64) -> Read {
        let oldest = self.oldest().max(*cursor + 1);
        let lost = oldest - *cursor;
        *cursor = oldest;
        self.lost(lost)
    }

    #[cfg_attr(feature = "canary-no-overrun", allow(unused_variables))]
    fn lost(&self, n: u64) -> Read {
        // Canary: the jump goes unreported.
        #[cfg(feature = "canary-no-overrun")]
        return Read::Empty;
        #[cfg(not(feature = "canary-no-overrun"))]
        Read::Lost(n)
    }

    /// Give up on the record at `*cursor` (a producer that never finished it).
    pub fn skip(&self, cursor: &mut u64) {
        *cursor += 1;
    }
}

/// A ring, to write: any number of producers at once.
#[derive(Clone, Copy)]
pub struct Writer {
    g: Geom,
}

// SAFETY: as `Region`.
unsafe impl Send for Writer {}
unsafe impl Sync for Writer {}

/// The payload of a record being stored: stores clamped to the slot.
pub struct Payload {
    at: *mut u8,
    cap: usize,
}

impl Payload {
    /// Store `b` at payload offset `off` (cut at the slot).
    #[inline]
    pub fn bytes(&mut self, off: usize, b: &[u8]) {
        if off >= self.cap {
            return;
        }
        let n = b.len().min(self.cap - off);
        // SAFETY: inside the claimed slot.
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), self.at.add(off), n) };
    }
    /// Store `v` at payload offset `off`, 8-aligned (dropped past the slot).
    #[inline]
    pub fn word(&mut self, off: usize, v: u64) {
        if off % 8 == 0 && off + 8 <= self.cap {
            // SAFETY: inside the claimed slot, aligned (slots are 8-aligned).
            unsafe { word(self.at, off).store(v, Ordering::Relaxed) };
        }
    }
    /// Store `v` at payload offset `off`.
    #[inline]
    pub fn byte(&mut self, off: usize, v: u8) {
        if off < self.cap {
            // SAFETY: inside the claimed slot.
            unsafe { core::ptr::write_volatile(self.at.add(off), v) };
        }
    }
    /// Payload bytes the slot holds.
    pub fn cap(&self) -> usize {
        self.cap
    }
}

/// The envelope fields a producer chooses; the sequence and the source are
/// the ring's.
#[derive(Clone, Copy, Debug, Default)]
pub struct Head {
    pub ts: u64,
    pub clock: u8,
    pub kind: u16,
    pub len: u16,
    pub cpu: u8,
    pub flags: u8,
}

impl Writer {
    /// The ring at `ring` laid out as `spec`, to write.
    ///
    /// # Safety
    /// `ring` is the start of a ring of `spec` inside a live region the
    /// caller owns.
    pub const unsafe fn at(ring: *mut u8, spec: RingSpec) -> Writer {
        Writer { g: Geom { ring, slot_bytes: spec.slot_bytes as usize, entries: spec.entries as u64, source: spec.source } }
    }

    pub fn source(&self) -> u8 {
        self.g.source
    }
    /// Payload bytes a slot holds.
    pub fn payload(&self) -> usize {
        self.g.slot_bytes - ENV_BYTES
    }
    /// Records claimed so far.
    pub fn head(&self) -> u64 {
        self.g.head().load(Ordering::Relaxed)
    }

    /// Store one record: `fill` writes the payload. Never waits. Returns the
    /// record's sequence number.
    #[inline]
    pub fn publish(&self, h: &Head, fill: impl FnOnce(&mut Payload)) -> u64 {
        let s = self.g.head().fetch_add(1, Ordering::Relaxed);
        self.store(s, s, h, fill);
        s
    }

    /// The store under a claimed index `s`, its envelope naming `seq`.
    #[inline]
    fn store(&self, s: u64, seq: u64, h: &Head, fill: impl FnOnce(&mut Payload)) {
        let slot = self.g.slot(s);
        // SAFETY: every store is inside the claimed slot.
        let stamp = unsafe { word(slot, S_STAMP) };
        let odd = s.wrapping_mul(2).wrapping_add(1);
        stamp.store(odd, Ordering::Relaxed);
        #[cfg(not(feature = "canary-no-fence"))]
        fence(Ordering::Release);
        // The clock, source, kind, length, CPU and flags are one word: one store.
        let meta = h.clock as u64
            | (self.g.source as u64) << 8
            | (h.kind as u64) << 16
            | (h.len as u64) << 32
            | (h.cpu as u64) << 48
            | (h.flags as u64) << 56;
        unsafe {
            word(slot, S_SEQ).store(seq, Ordering::Relaxed);
            word(slot, S_TS).store(h.ts, Ordering::Relaxed);
            word(slot, S_META).store(meta, Ordering::Relaxed);
        }
        // SAFETY: the payload area of the claimed slot.
        fill(&mut Payload { at: unsafe { slot.add(ENV_BYTES) }, cap: self.payload() });
        // A lapper owns the slot now: its stamp stays, this record is lost.
        if stamp.compare_exchange(odd, odd.wrapping_add(1), Ordering::Release, Ordering::Relaxed).is_err() {
            self.g.lapped().fetch_add(1, Ordering::Relaxed);
        }
    }

    /// [`publish`](Self::publish), its envelope naming the sequence before
    /// the one it takes: a record no reader may hand on as its slot's. For
    /// the gate's stale-sequence canary only.
    pub fn publish_stale(&self, h: &Head, fill: impl FnOnce(&mut Payload)) -> u64 {
        let s = self.g.head().fetch_add(1, Ordering::Relaxed);
        self.store(s, s.wrapping_sub(1), h, fill);
        s
    }

    /// Copy every record `from` still holds into this ring under its own
    /// sequence number, so an id handed out before the copy names the same
    /// record after it; a record of a stale sequence is copied as it is. The
    /// records `from` no longer holds are skipped (this ring's head starts
    /// past them). A record still being stored would be a gap, which the
    /// caller rules out (nothing writes `from` meanwhile). Returns how many it
    /// skipped.
    ///
    /// # Safety
    /// This ring is empty and nobody else writes it, and nobody writes `from`,
    /// until this returns.
    pub unsafe fn replay(&self, from: &Ring) -> u64 {
        #[cfg(not(feature = "canary-record-renumber"))]
        let first = from.oldest();
        // Canary: the copy starts its numbers at 0, as a plain re-push would.
        #[cfg(feature = "canary-record-renumber")]
        let (first, from_first) = (0, from.oldest());
        self.g.base().store(first, Ordering::Relaxed);
        self.g.head().store(first, Ordering::Relaxed);
        let mut buf = [0u8; REPLAY_PAYLOAD_MAX];
        let mut env = Envelope::default();
        #[cfg(not(feature = "canary-record-renumber"))]
        let mut c = first;
        #[cfg(feature = "canary-record-renumber")]
        let mut c = from_first;
        while c < from.head() {
            #[cfg(not(feature = "canary-record-renumber"))]
            let at = c;
            #[cfg(feature = "canary-record-renumber")]
            let at = c - from_first;
            let got = from.read(&mut c, &mut env, &mut buf);
            debug_assert!(got != Read::Pending, "nothing writes the ring being copied");
            if got == Read::Record || got == Read::Stale {
                // A stale record stays stale: copied under the sequence it
                // named, so the readers of this ring drop and count it too.
                let h = Head { ts: env.ts, clock: env.clock, kind: env.kind, len: env.len, cpu: env.cpu, flags: env.flags };
                let n = (env.len as usize).min(buf.len());
                let seq = if got == Read::Record { at } else { env.seq };
                self.g.head().store(at + 1, Ordering::Relaxed);
                self.store(at, seq, &h, |p| p.bytes(0, &buf[..n]));
            } else {
                c = c.max(at + 1);
                self.g.head().store(at + 1, Ordering::Relaxed);
            }
        }
        fence(Ordering::Release);
        first
    }
}

/// Payload bytes [`Writer::replay`] carries over: a ring whose slots hold more
/// cannot be handed over (its producer asserts it at build time).
pub const REPLAY_PAYLOAD_MAX: usize = 512;

/// A test's hook between a reader's copy and its stamp re-check, where a
/// racing producer would land (`tests/host/rings-tests` only).
#[cfg(feature = "test-hook")]
pub mod test_hook {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static HOOK: AtomicUsize = AtomicUsize::new(0);
    /// Call `f` (once) at the next read's window.
    pub fn set(f: fn()) {
        HOOK.store(f as usize, Ordering::SeqCst);
    }
    pub(super) fn between_copy_and_recheck() {
        let f = HOOK.swap(0, Ordering::SeqCst);
        if f != 0 {
            // SAFETY: only `set` stores here, a `fn()`.
            unsafe { core::mem::transmute::<usize, fn()>(f)() };
        }
    }
}

/// What one [`Merge::next`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// The oldest record of all the rings, from ring `ring`.
    Record { ring: usize },
    /// Every ring is drained.
    Empty,
    /// Ring `ring` has a producer mid-store at its cursor: nothing is handed
    /// out until it finishes (or the reader [`Merge::skip`]s it).
    Pending { ring: usize },
    /// Ring `ring` lapped the reader: `n` records lost.
    Lost { ring: usize, n: u64 },
    /// Ring `ring` held a record of a stale sequence: dropped.
    Stale { ring: usize },
}

/// The one reader of a region: a cursor per ring and the next record of
/// each, handed out oldest first. `P` is the payload bytes kept per ring (the
/// largest slot's payload the reader cares for; a longer payload is cut).
#[derive(Clone, Copy)]
pub struct Merge<const P: usize> {
    region: Region,
    cursor: [u64; MAX_RINGS],
    have: [bool; MAX_RINGS],
    env: [Envelope; MAX_RINGS],
    buf: [[u8; P]; MAX_RINGS],
    lost: [u64; MAX_RINGS],
    stale: [u64; MAX_RINGS],
}

impl<const P: usize> Merge<P> {
    /// A reader of `region` that starts at each ring's oldest record.
    pub fn oldest(region: Region) -> Self {
        let mut m = Merge {
            region,
            cursor: [0; MAX_RINGS],
            have: [false; MAX_RINGS],
            env: [Envelope::default(); MAX_RINGS],
            buf: [[0; P]; MAX_RINGS],
            lost: [0; MAX_RINGS],
            stale: [0; MAX_RINGS],
        };
        for i in 0..region.rings() {
            m.cursor[i] = region.ring(i).map_or(0, |r| r.oldest());
        }
        m
    }

    pub fn region(&self) -> &Region {
        &self.region
    }

    /// The next record ring `ring` will hand out (its cursor, the buffered
    /// record included).
    pub fn cursor(&self, ring: usize) -> u64 {
        if ring >= MAX_RINGS {
            return 0;
        }
        if self.have[ring] { self.env[ring].seq } else { self.cursor[ring] }
    }

    /// Move ring `ring`'s cursor to `seq` (a sink resuming where its files
    /// end), dropping a record it had buffered.
    pub fn seek(&mut self, ring: usize, seq: u64) {
        if ring < self.region.rings() {
            self.cursor[ring] = seq;
            self.have[ring] = false;
        }
    }

    /// Records ring `ring` lost to laps, since this reader began.
    pub fn lost(&self, ring: usize) -> u64 {
        self.lost.get(ring).copied().unwrap_or(0)
    }
    /// Records of ring `ring` dropped for a stale sequence, since this reader began.
    pub fn stale(&self, ring: usize) -> u64 {
        self.stale.get(ring).copied().unwrap_or(0)
    }

    /// Give up on the record ring `ring` is pending on.
    pub fn skip(&mut self, ring: usize) {
        if ring < self.region.rings() && !self.have[ring] {
            self.cursor[ring] += 1;
        }
    }

    /// The oldest record not yet handed out: its envelope into `env`, its
    /// payload into `payload` (cut at `P` and at `payload.len()`).
    pub fn next(&mut self, env: &mut Envelope, payload: &mut [u8]) -> Step {
        for i in 0..self.region.rings() {
            if self.have[i] {
                continue;
            }
            let Some(r) = self.region.ring(i) else { continue };
            match r.read(&mut self.cursor[i], &mut self.env[i], &mut self.buf[i]) {
                Read::Record => self.have[i] = true,
                Read::Empty => {}
                // Canary: a producer mid-store reads as an empty ring.
                #[cfg(feature = "canary-record-pending-empty")]
                Read::Pending => {}
                #[cfg(not(feature = "canary-record-pending-empty"))]
                Read::Pending => return Step::Pending { ring: i },
                Read::Lost(n) => {
                    self.lost[i] += n;
                    return Step::Lost { ring: i, n };
                }
                Read::Stale => {
                    self.stale[i] += 1;
                    return Step::Stale { ring: i };
                }
            }
        }
        let mut best: Option<usize> = None;
        for i in 0..self.region.rings() {
            if !self.have[i] {
                continue;
            }
            #[cfg(feature = "canary-record-unordered")]
            if best.is_none() {
                best = Some(i);
            }
            #[cfg(not(feature = "canary-record-unordered"))]
            match best {
                Some(b) if self.env[b].ts <= self.env[i].ts => {}
                _ => best = Some(i),
            }
        }
        let Some(b) = best else { return Step::Empty };
        self.have[b] = false;
        *env = self.env[b];
        let n = payload.len().min(P);
        payload[..n].copy_from_slice(&self.buf[b][..n]);
        Step::Record { ring: b }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The compressed-page pool (Kconfig `MM_RECLAIM_COMPRESS`): the middle of the
//! plan's reclaim order, between "drop what is clean" and "write to a block
//! device". The model is macOS/XNU's compressor (compressed pages packed into
//! segments, a compactor defragmenting them), reimplemented from the published
//! algorithms; no XNU code is used.
//!
//! # What a stored page is
//!
//! A page is named by `(obj, page)`: the container it belongs to and its page
//! number there. The container is a MemObj once anonymous regions have one;
//! until then the pager names it by the address space (the page-table root,
//! the identity `pager.rs` already keys its region table on) and the page by
//! its virtual page number. Three things can be stored for it:
//!
//! * **same-filled**: the page is one 64-bit word repeated (zero is the
//!   common case). One index entry, no bytes, no compression, no charge;
//! * **blob**: the page's WKdm stream (`azos_crypto::wkdm`), encrypted, packed
//!   into a segment;
//! * nothing: a page that does not compress below `max_pct` of its size is
//!   *skipped* ([`Packed::Skip`]) and stays resident for the reclaimer to drop
//!   or, in a later stage, swap. Compressing it would save little and the
//!   restore would still pay a decryption and a decompression. The reclaimer
//!   flags such a page (`aging::AgeTable::mark_incompressible`) and does not
//!   offer it again until it is touched, so the coder runs on it once, not on
//!   every storm.
//!
//! The order inside [`Codec::pack`] is the dedupe rule: the one-word test
//! (`same_filled`, a read of the page) comes before the coder, so a zero or
//! same-filled page never pays a compression, an encryption or a byte of
//! quota.
//!
//! # Segments and compaction
//!
//! Blobs are appended to *segments*: `SEG` bytes of contiguous frames from the
//! [`Backing`], taken as the pool grows (never past `SEGS`) and returned when
//! the last live blob of a segment is freed (one empty segment is kept, so a
//! store/restore cycle does not bounce frames off the page allocator). Each
//! blob is preceded in its segment by an 8-byte header (blob record, length),
//! so a segment can be walked front to back without a side table. Freeing a
//! blob leaves a hole; [`Pool::compact`] closes them: every segment is slid
//! down over its holes, then the sparsest segment is emptied into the tails of
//! the others and released, repeatedly. A store that finds no room tries to
//! grow, then compacts, then grows again, then refuses ([`Error::Full`]).
//! Compaction moves ciphertext as it is (the nonce belongs to the blob, not to
//! its place), so nothing is decrypted or re-keyed by it.
//!
//! # Encryption
//!
//! Every blob is AES-128-CTR under a key made once per boot (the caller
//! supplies it; the kernel draws it from the entropy pool on the first store
//! and keeps it in RAM only). The nonce is a 64-bit counter drawn once per
//! blob and never reused under a key, so the keystream of two blobs never
//! overlaps, which is the whole requirement of CTR. A segment therefore holds
//! only ciphertext and headers. CTR is not authenticated: a flipped bit in the
//! pool flips the same bit of the page. The pool lives in kernel RAM, which is
//! what an attacker would have to write to, so this is confidentiality for
//! frames that are reused or dumped, not integrity; the AEAD of the plan is
//! the swap stage's (the segment is the unit written out), where the medium is
//! outside the kernel's control.
//!
//! # Quota (H5)
//!
//! Compressed bytes are charged to the Domain that owned the page, not to a
//! global compressor. The pool keeps a ledger indexed by the Domain slot
//! (`azos_sched::domain::index`; `mm` cannot call `sched`, so the caller
//! passes the index): a store that would take the Domain past its quota is
//! refused ([`Error::Quota`]) and the page stays resident. An entry remembers
//! whom it was charged to and gives the bytes back when it goes, wherever and
//! by whomever it is removed. What is charged is the footprint (blob plus its
//! 8-byte header), so the ledger sums to the bytes the segments hold live.
//!
//! # Sharing
//!
//! A fork gives the child the parent's compressed pages without decompressing
//! them: [`Pool::dup_obj`] adds an index entry per page that points at the same
//! blob (a reference count; the blob is immutable) and charges the child's
//! entry to the same Domain as the parent's. The blob goes when its last entry
//! does.
//!
//! # Concurrency
//!
//! `Pool` is plain data: the kernel keeps it behind one lock, taken for index
//! operations and the copies in and out of a segment only. The expensive work
//! (compressing, encrypting, decrypting, decompressing) is [`Codec`]'s and runs
//! outside the lock on the caller's buffers: a restore copies the ciphertext
//! out under the lock, and [`Pool::fetch`] leaves the entry in place, so two
//! threads that fault the same page both restore it and the one that installs
//! first removes the entry ([`Pool::remove`]). The entry is never gone while a
//! thread that may still install it is working.
//!
//! # Reclaim storms
//!
//! What fills the pool. A Domain whose frame budget crosses its `high`
//! watermark (declared with the limit by `PageBudget::set_limit_marked`, from
//! Kconfig `MM_RECLAIM_HIGH_PCT` / `MM_RECLAIM_LOW_PCT`) gets one *storm*:
//! [`run_storm`] takes victims in the order the source offers them (the
//! oldest generation first, `aging.rs`, over the Domain's anonymous pages;
//! pages the coder already gave up on are not offered again until they are
//! touched), unmaps each from its address space, stores it
//! ([`Reclaimee::store`]), frees the frame and gives the charge back, until the charge is at `low` or the source has nothing
//! left. The storm is one `Rule::Compress` record however many pages it took
//! ([`budget::StormRecord`]), written by the caller. It never starts for a
//! Domain on a locked memory row or on a real-time hart
//! ([`budget::PageBudget::storm_begin`]), and it stops at the first refusal
//! that is not "this page does not compress" (the pool is full or the Domain
//! is at its quota: every later page would pay an unmap for the same answer).
//! The loop is generic over the victim source because the object table and
//! the page allocator are not this file's: `Reclaimee` is the seam a host row
//! runs the real loop through.
//!
//! # Swapped segments
//!
//! With Kconfig `MM_SWAP_BACKEND` a *full* segment can leave memory whole
//! (`swap.rs` drives it; this file only keeps the books). It is *parked*: its
//! frames are freed, and its record moves from `segs` to `parked`, where it
//! keeps the length it was written at and the number of live bytes; the slot
//! number of the swap area is the parked record's index. The blobs of a parked
//! segment keep their offsets, and their `seg` becomes `SEGS + slot`, so
//! nothing else about an entry changes. A restore finds such a page with
//! [`Pool::swapped`] (and [`Pool::fetch`] answers `None` for it), brings the
//! segment back ([`Pool::swap_in_begin`], [`Pool::swap_in_commit`]) and then
//! fetches as usual.
//!
//! A segment leaves in three steps, none of which does I/O under the pool's
//! lock: [`Pool::swap_pick`] chooses a full one, slides its holes out and marks
//! it *leaving* (appends, compaction and release skip it); [`Pool::swap_stage`]
//! copies its bytes out; [`Pool::swap_commit`] frees the frames once the copy
//! is on the medium. The Domain's bytes move from the pool ledger to the swap
//! ledger (`SWQ`, per Domain, like the pool's quota) at the commit. A segment
//! holding a page of a Domain the caller calls pinned is never picked.
//!
//! This file depends on `azos_crypto` and `azos_arch_api`'s constants, and on
//! the frame budget (`budget.rs`, which depends on `core` alone), so
//! `tests/host/mm-tests` compiles it unchanged.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use azos_arch_api::{Mmu, PageMarker};

use azos_crypto::aes::Aes128;
use azos_crypto::wkdm;

use crate::budget::{NoStorm, PageBudget, StormRecord};

/// Kconfig `MM_RECLAIM_COMPRESS`.
pub const ENABLED: bool = azos_limits::MM_RECLAIM_COMPRESS;

// The only coder there is. LZ4 joins the Kconfig choice with its coder.
const _: () = assert!(azos_limits::MM_COMPRESS_ALGO_WKDM);

const fn sized(n: usize) -> usize {
    if ENABLED { n } else { 0 }
}

/// Pages the pool holds at once (Kconfig `MM_ZPOOL_ENTRIES`; 0 when off).
pub const ENTRIES: usize = sized(azos_limits::MM_ZPOOL_ENTRIES);
/// Index slots: twice the entries, a power of two, so a lookup that misses
/// ends at the first empty slot (0 when off).
pub const SLOTS: usize = if ENABLED { (2 * ENTRIES).next_power_of_two() } else { 0 };
/// Segments the pool may hold (Kconfig `MM_ZPOOL_SEGMENTS`; 0 when off).
pub const SEGMENTS: usize = sized(azos_limits::MM_ZPOOL_SEGMENTS);
/// Bytes of one segment (Kconfig `MM_ZPOOL_SEGMENT_PAGES` frames).
pub const SEGMENT_BYTES: usize = azos_limits::MM_ZPOOL_SEGMENT_PAGES * azos_arch_api::PAGE_SIZE;
/// Domain slots the quota ledger covers (0 when off).
pub const OWNERS: usize = sized(azos_limits::MAX_TASKS);
/// Largest stored size, in percent of a page (Kconfig `MM_ZPOOL_MAX_RATIO_PCT`).
pub const MAX_RATIO_PCT: usize = azos_limits::MM_ZPOOL_MAX_RATIO_PCT;
/// The quota a Domain starts with, in bytes; 0 for none (Kconfig
/// `MM_ZPOOL_DOMAIN_KIB`).
pub const DEFAULT_QUOTA: u32 = (azos_limits::MM_ZPOOL_DOMAIN_KIB * 1024) as u32;

/// Kconfig `MM_SWAP_BACKEND`.
pub const SWAP: bool = ENABLED && azos_limits::MM_SWAP_BACKEND;
/// Segments that can be swapped out at once (Kconfig `MM_SWAP_SEGMENTS`; 0 when off).
pub const SWAP_SEGMENTS: usize = if SWAP { azos_limits::MM_SWAP_SEGMENTS } else { 0 };
/// Domain slots the swap ledger covers (0 when off).
pub const SWAP_OWNERS: usize = if SWAP { azos_limits::MAX_TASKS } else { 0 };
/// The swap quota a Domain starts with, in bytes; 0 for none (Kconfig `MM_SWAP_DOMAIN_KIB`).
pub const SWAP_DEFAULT_QUOTA: u32 = (azos_limits::MM_SWAP_DOMAIN_KIB * 1024) as u32;
/// A segment is written out once this share of it is live (Kconfig `MM_SWAP_FULL_PCT`).
pub const SWAP_FULL_PCT: usize = azos_limits::MM_SWAP_FULL_PCT;

// A Domain's watermarks are declared with its frame limit, from the topology
// row (`PageBudget::set_limit_marked`, called by `domain::set_limit` with
// `MM_RECLAIM_HIGH_PCT` / `MM_RECLAIM_LOW_PCT`); this is the one place the build
// refuses a gap that is not one.
const _: () = assert!(
    azos_limits::MM_RECLAIM_LOW_PCT < azos_limits::MM_RECLAIM_HIGH_PCT,
    "MM_RECLAIM_LOW_PCT must be below MM_RECLAIM_HIGH_PCT"
);

/// The header in front of every blob in a segment.
const HDR: usize = 8;

/// Why the pool or the codec said no. Every one leaves the page resident and
/// the pool as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `MM_RECLAIM_OFF`.
    Disabled,
    /// The page does not compress below the threshold: keep it resident.
    Incompressible,
    /// The owner's quota would be exceeded.
    Quota,
    /// No index entry or no room in the segments, also after compacting.
    Full,
    /// No key yet: the entropy pool is not seeded.
    NoKey,
    /// The owner is not a Domain slot.
    BadOwner,
    /// Not a 4 KiB, 16 KiB or 64 KiB page.
    BadPageSize,
    /// The stored stream does not decode (a corrupted pool).
    Corrupt,
    /// No swap area: `MM_SWAP_BACKEND` is off, or none was attached.
    NoSwap,
    /// No segment is full enough to be worth writing out.
    NoSegment,
    /// Every full segment holds a page of a pinned Domain.
    Pinned,
    /// The segment or slot is no longer what the caller saw (the pages left
    /// while it was out of the lock).
    Gone,
    /// Another swap step of the same kind is in flight (a segment is leaving,
    /// or one is coming back): nothing was touched, ask again when it ends.
    /// Distinct from `Full`, which means "make room", and from `NoSegment`,
    /// which means "nothing to do".
    Busy,
}

/// Where segments come from: contiguous memory the pool owns until it gives
/// it back. The kernel's is page-allocator frames; the host tests' is the
/// heap.
pub trait Backing {
    /// `bytes` (a multiple of the page size) of memory aligned to at least 8,
    /// exclusively the caller's until [`free`](Backing::free).
    fn alloc(&self, bytes: usize) -> Option<NonNull<u8>>;
    /// Give back what [`alloc`](Backing::alloc) returned for `bytes`.
    fn free(&self, p: NonNull<u8>, bytes: usize);
}

// ── Codec: compress+encrypt, decrypt+decompress ──────────────────────────────

/// Nonces: one per blob, from one counter for the whole system, so no two
/// blobs of any key share one (CTR forbids it).
static NONCE: AtomicU64 = AtomicU64::new(1);

/// What [`Codec::pack`] made of a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packed {
    /// One word repeated through the page; nothing else to keep.
    Fill(u64),
    /// `scratch[..len]` holds the encrypted stream; keep it with `nonce`.
    Blob { len: usize, nonce: u64 },
    /// Above the threshold: not worth storing.
    Skip,
}

/// The boot key (as its expanded AES schedule) and the threshold: everything
/// that compresses and encrypts. Neither `Copy` nor `Clone`: the key has one
/// home, and callers borrow it where it lives.
pub struct Codec {
    aes: Aes128,
    max_pct: usize,
}

impl Codec {
    pub fn new(key: &[u8; 16], max_pct: usize) -> Self {
        Self { aes: Aes128::new(key), max_pct }
    }

    /// Compress `page`, and encrypt the stream into `scratch` (at least as
    /// long as `page`; its contents on entry do not matter).
    pub fn pack(&self, page: &[u8], scratch: &mut [u8]) -> Result<Packed, Error> {
        if !wkdm::is_page_size(page.len()) || scratch.len() < page.len() {
            return Err(Error::BadPageSize);
        }
        if let Some(w) = same_filled(page) {
            return Ok(Packed::Fill(w));
        }
        let limit = page.len() * self.max_pct / 100;
        match wkdm::compress(page, &mut scratch[..limit]) {
            // `Ok(0)` is the all-zero page, which `same_filled` took already.
            Ok(0) => Ok(Packed::Fill(0)),
            Ok(len) => {
                let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
                self.aes.ctr_encrypt(&nonce12(nonce), &mut scratch[..len]);
                Ok(Packed::Blob { len, nonce })
            }
            Err(wkdm::Error::Incompressible) => Ok(Packed::Skip),
            Err(wkdm::Error::BadPageSize) => Err(Error::BadPageSize),
            Err(wkdm::Error::Malformed) => Err(Error::Corrupt),
        }
    }

    /// Decrypt `scratch[..len]` (a blob [`Pool::fetch`] copied out) in place
    /// and decompress it into `page`.
    pub fn unpack(&self, nonce: u64, len: usize, scratch: &mut [u8], page: &mut [u8]) -> Result<(), Error> {
        if len > scratch.len() {
            return Err(Error::Corrupt);
        }
        self.aes.ctr_decrypt(&nonce12(nonce), &mut scratch[..len]);
        wkdm::decompress(&scratch[..len], page).map_err(|e| match e {
            wkdm::Error::BadPageSize => Error::BadPageSize,
            _ => Error::Corrupt,
        })
    }
}

/// Write the page a same-filled entry stands for.
pub fn fill_page(word: u64, page: &mut [u8]) {
    let b = word.to_le_bytes();
    for c in page.chunks_exact_mut(8) {
        c.copy_from_slice(&b);
    }
}

/// The word `page` is made of, if it is one word repeated.
pub fn same_filled(page: &[u8]) -> Option<u64> {
    let mut it = page.chunks_exact(8);
    let first = it.next()?;
    let w = u64::from_le_bytes([first[0], first[1], first[2], first[3], first[4], first[5], first[6], first[7]]);
    for c in it {
        if u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]) != w {
            return None;
        }
    }
    Some(w)
}

fn nonce12(n: u64) -> [u8; 12] {
    let mut r = [0u8; 12];
    r[..8].copy_from_slice(&n.to_le_bytes());
    r
}

// ── The pool ──────────────────────────────────────────────────────────────────

const EMPTY: u16 = 0;
const FILL: u16 = 1;
const BLOB: u16 = 2;

/// One page of the index. `data` is the fill word, or the blob record.
#[derive(Clone, Copy)]
struct Entry {
    obj: u64,
    page: u64,
    data: u64,
    owner: u16,
    state: u16,
    /// The pool's insert counter when the entry was made: a holder of an
    /// older value (a fault that restored a previous incarnation) does not
    /// name this entry (see [`Pool::remove_if`]).
    gen: u32,
}

impl Entry {
    const EMPTY: Entry = Entry { obj: 0, page: 0, data: 0, owner: 0, state: EMPTY, gen: 0 };
}

/// A stored stream. `refs == 0` is a free record, and then `off` links the
/// free list (a record number plus one; 0 ends it).
#[derive(Clone, Copy)]
struct Blob {
    /// Offset of its header in the segment.
    off: u32,
    /// Length of the encrypted stream (without the header).
    len: u32,
    nonce: u64,
    refs: u32,
    /// The segment it lies in; `SEGS + slot` for a swapped one.
    seg: u16,
    /// The Domain it was charged to (every entry that shares it has the same).
    owner: u16,
}

impl Blob {
    const fn foot(&self) -> usize {
        self.len as usize + HDR
    }
}

#[derive(Clone, Copy)]
struct Segment {
    /// Null: the slot is free.
    base: *mut u8,
    /// Bytes used from the front: live blobs and holes.
    fill: u32,
    /// Bytes of live blobs (with headers).
    live: u32,
}

#[derive(Clone, Copy)]
struct Acct {
    used: u32,
    /// 0: the pool's default.
    limit: u32,
}

/// A swapped-out segment: `live == 0` is a free slot.
#[derive(Clone, Copy)]
struct Parked {
    /// Bytes written (the segment's `fill` when it left).
    fill: u32,
    /// Bytes of live blobs (with headers).
    live: u32,
    /// Names this incarnation: a holder of an older value does not name it.
    gen: u32,
}

/// The swap area's slots now ([`Pool::swap_slots`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapSlots {
    /// Slots the area has.
    pub cap: usize,
    /// Of them, the ones no segment is parked in.
    pub free: usize,
    /// The highest parked slot plus one (0: none), the least a shrink keeps.
    pub top: usize,
}

/// What [`Pool::swap_pick`] chose: a segment to write out, and the slot of the
/// swap area it goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapPick {
    pub seg: usize,
    pub slot: usize,
    /// Bytes of the segment written to (the rest of the staged image is zero).
    pub fill: usize,
    /// Bytes of live blobs in it (with headers).
    pub live: usize,
}

/// The page-in side of a swapped segment, as [`Pool::swapped`] finds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Swapped {
    pub slot: usize,
    /// Names this incarnation of the slot (for [`Pool::swap_in_commit`]).
    pub gen: u32,
    /// Bytes the segment was written with.
    pub fill: usize,
}

/// What [`Pool::fetch`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetched {
    Fill(u64),
    /// The ciphertext is in the caller's buffer, `len` bytes.
    Blob { len: usize, nonce: u64 },
}

/// What [`Pool::fetch_named`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// The page's entry is the marker's, and it is in memory: what it holds,
    /// its generation, and the Domain slot it is charged to (the one the
    /// storm that stored it gave the frame's charge back to).
    Page(Fetched, u32, u16),
    /// Nothing is stored under the key (the thread that restored it first
    /// removed it, or the range went).
    Gone,
    /// Its segment is on the swap area: bring it back first.
    Parked,
    /// Something is stored under the key but it is not the marker's page.
    Wrong,
}

/// One stored page, as [`Pool::parked_from`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored {
    pub obj: u64,
    pub page: u64,
    /// The entry's generation: the payload of its page marker.
    pub gen: u32,
}

/// Counters, for reports and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Pages held (same-filled and compressed).
    pub entries: usize,
    /// Distinct blobs (shared ones once).
    pub blobs: usize,
    /// Segments in memory.
    pub segments: usize,
    /// Segments written out to swap.
    pub swapped: usize,
    /// Bytes of live blobs with their headers.
    pub live_bytes: usize,
    /// Bytes the segments occupy in memory.
    pub resident_bytes: usize,
}

/// The pool. `E` entries, `SLOTS` index slots (a power of two, at least `2 * E`),
/// `SEGS` segments of `SEG` bytes (a multiple of the page size, below 4 GiB),
/// `OWNERS` Domain slots in the quota ledger, each with `QUOTA` bytes unless
/// told otherwise (0: no bound).
///
/// Everything is a const parameter, and the empty pool is all zero bytes, so a
/// `static` one lives in `.bss` and costs no image space.
///
/// Swap is three more, which default to none: `SW` swap slots (parked
/// segments), `SWOWNERS` Domain slots in the swap ledger and `SWQ` bytes of
/// swap quota each unless told otherwise. A pool without them has no swap
/// tables (the arrays are zero-sized; a few scalar fields remain), and its
/// entries, blobs and segments are the same size as before.
pub struct Pool<
    B: Backing,
    const E: usize,
    const SLOTS: usize,
    const SEGS: usize,
    const OWNERS: usize,
    const SEG: usize,
    const QUOTA: u32,
    const SW: usize = 0,
    const SWOWNERS: usize = 0,
    const SWQ: u32 = 0,
> {
    backing: B,
    entries: [Entry; SLOTS],
    n_entries: usize,
    blobs: [Blob; E],
    /// The free records: a record number plus one, 0 for none.
    blob_free: u32,
    /// Records handed out so far; the ones below it are in use or on the free list.
    blob_hwm: u32,
    n_blobs: usize,
    segs: [Segment; SEGS],
    n_segs: usize,
    /// The segment the next blob is tried in first.
    open: usize,
    acct: [Acct; OWNERS],
    /// Inserts so far (wrapping); each entry carries the value it was made at.
    gen: u32,
    /// The swapped-out segments, by swap slot.
    parked: [Parked; SW],
    /// Slots of the swap area that are usable (at most `SW`): what the
    /// attached area holds. 0: no swap.
    swap_cap: usize,
    n_parked: usize,
    /// Parkings so far (wrapping, never 0 in a record): names an incarnation.
    pgen: u32,
    /// The segment being staged out, plus one; 0 for none. Appends,
    /// compaction and release leave it alone.
    leaving: usize,
    /// A resident slot is held for a segment being brought back.
    inbound: bool,
    /// Where the next [`swap_pick`](Self::swap_pick) starts looking: the
    /// segment after the last one written out, so the choice goes round.
    hand: usize,
    /// The swap ledger, by Domain slot.
    swacct: [Acct; SWOWNERS],
}

// SAFETY: the segments are memory the pool owns exclusively (the `Backing`
// contract); nothing else holds their pointers.
unsafe impl<
        B: Backing + Send,
        const E: usize,
        const SLOTS: usize,
        const SEGS: usize,
        const OWNERS: usize,
        const SEG: usize,
        const QUOTA: u32,
        const SW: usize,
        const SWOWNERS: usize,
        const SWQ: u32,
    > Send for Pool<B, E, SLOTS, SEGS, OWNERS, SEG, QUOTA, SW, SWOWNERS, SWQ>
{
}

impl<
        B: Backing,
        const E: usize,
        const SLOTS: usize,
        const SEGS: usize,
        const OWNERS: usize,
        const SEG: usize,
        const QUOTA: u32,
        const SW: usize,
        const SWOWNERS: usize,
        const SWQ: u32,
    > Pool<B, E, SLOTS, SEGS, OWNERS, SEG, QUOTA, SW, SWOWNERS, SWQ>
{
    const GEOMETRY: () = assert!(
        ((SLOTS == 0 && E == 0) || (SLOTS.is_power_of_two() && SLOTS >= 2 * E && E < u32::MAX as usize))
            && SEG < u32::MAX as usize
            && OWNERS <= u16::MAX as usize + 1
            && SWOWNERS <= u16::MAX as usize + 1
            && SEGS + SW < u16::MAX as usize,
        "zpool: SLOTS must be a power of two of at least twice E, a segment below 4 GiB, and the segments and swap slots in a u16"
    );

    /// An empty pool.
    pub const fn new(backing: B) -> Self {
        let () = Self::GEOMETRY;
        Self {
            backing,
            entries: [Entry::EMPTY; SLOTS],
            n_entries: 0,
            blobs: [Blob { off: 0, len: 0, nonce: 0, refs: 0, seg: 0, owner: 0 }; E],
            blob_free: 0,
            blob_hwm: 0,
            n_blobs: 0,
            segs: [Segment { base: core::ptr::null_mut(), fill: 0, live: 0 }; SEGS],
            n_segs: 0,
            open: 0,
            acct: [Acct { used: 0, limit: 0 }; OWNERS],
            gen: 0,
            parked: [Parked { fill: 0, live: 0, gen: 0 }; SW],
            swap_cap: 0,
            n_parked: 0,
            pgen: 0,
            leaving: 0,
            inbound: false,
            hand: 0,
            swacct: [Acct { used: 0, limit: 0 }; SWOWNERS],
        }
    }

    // ── index ────────────────────────────────────────────────────────────────

    #[inline]
    fn home(obj: u64, page: u64) -> usize {
        let mut h = obj.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ page.wrapping_add(obj.rotate_left(32)).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
        h ^= h >> 29;
        h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        ((h ^ (h >> 32)) as usize) & SLOTS.wrapping_sub(1)
    }

    fn find(&self, obj: u64, page: u64) -> Option<usize> {
        if SLOTS == 0 {
            return None;
        }
        let mut i = Self::home(obj, page);
        loop {
            let e = &self.entries[i];
            if e.state == EMPTY {
                return None;
            }
            if e.obj == obj && e.page == page {
                return Some(i);
            }
            i = (i + 1) & (SLOTS - 1);
        }
    }

    /// The first empty slot on the probe path of a key that is not present.
    fn vacant(&self, obj: u64, page: u64) -> usize {
        let mut i = Self::home(obj, page);
        while self.entries[i].state != EMPTY {
            i = (i + 1) & (SLOTS - 1);
        }
        i
    }

    /// Empty slot `i`, closing the gap by moving back the entries of its
    /// cluster that may sit earlier (linear probing without tombstones).
    fn erase(&mut self, i: usize) {
        let mask = SLOTS - 1;
        let mut hole = i;
        let mut j = i;
        loop {
            j = (j + 1) & mask;
            let e = self.entries[j];
            if e.state == EMPTY {
                break;
            }
            let home = Self::home(e.obj, e.page);
            // `e` may move into the hole unless its home lies cyclically in
            // (hole, j]: then the hole is before the start of its probe path.
            if (j.wrapping_sub(home) & mask) >= (j.wrapping_sub(hole) & mask) {
                self.entries[hole] = e;
                hole = j;
            }
        }
        self.entries[hole] = Entry::EMPTY;
    }

    /// Remove the entry in slot `i`: give back its charge and its hold on the
    /// blob.
    fn remove_slot(&mut self, i: usize) {
        let e = self.entries[i];
        if e.state == BLOB {
            let idx = e.data as usize;
            self.discharge_blob(idx, e.owner as usize);
            self.release_blob(idx);
        }
        self.erase(i);
        self.n_entries -= 1;
    }

    // ── quota ────────────────────────────────────────────────────────────────

    fn charge(&mut self, owner: usize, bytes: u32) -> Result<(), Error> {
        let a = self.acct.get_mut(owner).ok_or(Error::BadOwner)?;
        let limit = if a.limit == 0 { QUOTA } else { a.limit };
        let next = a.used.saturating_add(bytes);
        if limit != 0 && next > limit {
            return Err(Error::Quota);
        }
        a.used = next;
        Ok(())
    }

    fn discharge(&mut self, owner: usize, bytes: u32) {
        if let Some(a) = self.acct.get_mut(owner) {
            a.used = a.used.saturating_sub(bytes);
        }
    }

    /// Charge one entry's footprint of blob `idx` to `owner`: to the swap
    /// ledger when the blob's segment is out, else the pool's.
    fn charge_blob(&mut self, idx: usize, owner: usize) -> Result<(), Error> {
        let foot = self.blobs[idx].foot() as u32;
        if self.is_parked(self.blobs[idx].seg) { self.sw_charge(owner, foot) } else { self.charge(owner, foot) }
    }

    fn discharge_blob(&mut self, idx: usize, owner: usize) {
        let foot = self.blobs[idx].foot() as u32;
        if self.is_parked(self.blobs[idx].seg) { self.sw_discharge(owner, foot) } else { self.discharge(owner, foot) }
    }

    #[inline]
    fn is_parked(&self, seg: u16) -> bool {
        seg as usize >= SEGS
    }

    fn sw_charge(&mut self, owner: usize, bytes: u32) -> Result<(), Error> {
        let a = self.swacct.get_mut(owner).ok_or(Error::BadOwner)?;
        let limit = if a.limit == 0 { SWQ } else { a.limit };
        let next = a.used.saturating_add(bytes);
        if limit != 0 && next > limit {
            return Err(Error::Quota);
        }
        a.used = next;
        Ok(())
    }

    fn sw_discharge(&mut self, owner: usize, bytes: u32) {
        if let Some(a) = self.swacct.get_mut(owner) {
            a.used = a.used.saturating_sub(bytes);
        }
    }

    /// Set the Domain's swap quota in bytes; 0 puts it back to the default.
    pub fn set_swap_quota(&mut self, owner: usize, bytes: u32) {
        if let Some(a) = self.swacct.get_mut(owner) {
            a.limit = bytes;
        }
    }

    /// Bytes of the Domain's pages that sit in swapped segments.
    pub fn swap_charged(&self, owner: usize) -> u32 {
        self.swacct.get(owner).map_or(0, |a| a.used)
    }

    /// Set the Domain's quota in bytes; 0 puts it back to the pool's default.
    /// A quota below what the Domain already holds refuses further stores; it
    /// does not evict.
    pub fn set_quota(&mut self, owner: usize, bytes: u32) {
        if let Some(a) = self.acct.get_mut(owner) {
            a.limit = bytes;
        }
    }

    /// Bytes charged to the Domain.
    pub fn charged(&self, owner: usize) -> u32 {
        self.acct.get(owner).map_or(0, |a| a.used)
    }

    // ── segments ─────────────────────────────────────────────────────────────

    /// A copy of the 8 bytes at `off` in segment `s`.
    fn header(&self, s: usize, off: usize) -> (u32, u32) {
        let mut h = [0u8; HDR];
        // SAFETY: `off + HDR` is within the bytes written to the segment
        // (`s.fill`), which lie inside its allocation.
        unsafe { core::ptr::copy_nonoverlapping(self.segs[s].base.add(off), h.as_mut_ptr(), HDR) };
        (u32::from_le_bytes([h[0], h[1], h[2], h[3]]), u32::from_le_bytes([h[4], h[5], h[6], h[7]]))
    }

    fn put_header(&mut self, s: usize, off: usize, idx: u32, len: u32) {
        let mut h = [0u8; HDR];
        h[..4].copy_from_slice(&idx.to_le_bytes());
        h[4..].copy_from_slice(&len.to_le_bytes());
        // SAFETY: the caller reserved `off..off + HDR` inside the segment.
        unsafe { core::ptr::copy_nonoverlapping(h.as_ptr(), self.segs[s].base.add(off), HDR) };
    }

    /// Is the blob record `idx` the live blob stored at `off` of segment `s`
    /// with `len` bytes (a walk meets dead blobs' headers too)?
    fn is_live_at(&self, idx: u32, s: usize, off: usize, len: u32) -> bool {
        (idx as usize) < E && {
            let b = &self.blobs[idx as usize];
            b.refs > 0 && b.seg as usize == s && b.off as usize == off && b.len == len
        }
    }

    /// Room for `foot` bytes in an allocated segment: where to append.
    fn fit(&mut self, foot: usize) -> Option<(usize, usize)> {
        for k in 0..SEGS {
            let s = (self.open + k) % SEGS;
            let g = &self.segs[s];
            if !g.base.is_null() && s + 1 != self.leaving && SEG - g.fill as usize >= foot {
                self.open = s;
                return Some((s, g.fill as usize));
            }
        }
        None
    }

    /// Take a segment from the backing. `false`: the ceiling, or no memory.
    fn grow(&mut self) -> bool {
        if self.n_segs + self.inbound as usize >= SEGS {
            return false;
        }
        let Some(s) = (0..SEGS).find(|&s| self.segs[s].base.is_null()) else { return false };
        let Some(p) = self.backing.alloc(SEG) else { return false };
        self.segs[s] = Segment { base: p.as_ptr(), fill: 0, live: 0 };
        self.n_segs += 1;
        true
    }

    fn release_segment(&mut self, s: usize) {
        if let Some(p) = NonNull::new(self.segs[s].base) {
            self.backing.free(p, SEG);
        }
        self.segs[s] = Segment { base: core::ptr::null_mut(), fill: 0, live: 0 };
        self.n_segs -= 1;
    }

    /// Where `foot` bytes go: an existing segment, a new one, a compacted one.
    fn reserve(&mut self, foot: usize) -> Option<(usize, usize)> {
        if let Some(r) = self.fit(foot) {
            return Some(r);
        }
        if self.grow() {
            return self.fit(foot);
        }
        self.compact();
        if let Some(r) = self.fit(foot) {
            return Some(r);
        }
        if self.grow() { self.fit(foot) } else { None }
    }

    /// Drop one hold on blob `idx`; the last one frees its bytes.
    fn release_blob(&mut self, idx: usize) {
        let b = &mut self.blobs[idx];
        b.refs -= 1;
        if b.refs > 0 {
            return;
        }
        let (s, foot) = (b.seg as usize, b.foot());
        b.off = self.blob_free;
        self.blob_free = idx as u32 + 1;
        self.n_blobs -= 1;
        if s >= SEGS {
            // In a swapped segment: its last blob frees the slot (nothing to
            // write; the medium's copy is just never read).
            let pk = &mut self.parked[s - SEGS];
            pk.live -= foot as u32;
            if pk.live == 0 {
                pk.fill = 0;
                self.n_parked -= 1;
            }
            return;
        }
        let g = &mut self.segs[s];
        g.live -= foot as u32;
        // A segment being staged out is settled by its commit or abort.
        if g.live == 0 && s + 1 != self.leaving {
            self.empty_segment(s);
        }
    }

    /// Segment `s` holds no live blob: give it back, or keep the last one.
    fn empty_segment(&mut self, s: usize) {
        if self.n_segs > 1 {
            self.release_segment(s);
        } else {
            self.segs[s].fill = 0;
        }
    }

    /// Slide the live blobs of segment `s` down over its holes.
    fn slide(&mut self, s: usize) {
        let (mut rd, mut wr) = (0usize, 0usize);
        let end = self.segs[s].fill as usize;
        while rd + HDR <= end {
            let (idx, len) = self.header(s, rd);
            let foot = len as usize + HDR;
            if rd + foot > end {
                break; // not a header of ours: stop rather than trust it
            }
            if self.is_live_at(idx, s, rd, len) {
                if wr != rd {
                    // SAFETY: both ranges lie below `fill`; `copy` handles the overlap.
                    unsafe { core::ptr::copy(self.segs[s].base.add(rd), self.segs[s].base.add(wr), foot) };
                    self.blobs[idx as usize].off = wr as u32;
                }
                wr += foot;
            }
            rd += foot;
        }
        self.segs[s].fill = wr as u32;
    }

    /// Move the live blobs of segment `v` into the tails of the others, and
    /// release it. `false`: they did not all fit; those that did have moved.
    fn evacuate(&mut self, v: usize) -> bool {
        let mut rd = 0usize;
        let end = self.segs[v].fill as usize;
        while rd + HDR <= end {
            let (idx, len) = self.header(v, rd);
            let foot = len as usize + HDR;
            if rd + foot > end {
                break;
            }
            if self.is_live_at(idx, v, rd, len) {
                let Some(w) = (0..SEGS).find(|&w| {
                    w != v && !self.segs[w].base.is_null() && w + 1 != self.leaving
                        && SEG - self.segs[w].fill as usize >= foot
                }) else {
                    return false;
                };
                let at = self.segs[w].fill as usize;
                // SAFETY: two different segments; the destination range lies
                // below `SEG` (checked above) and the source below `fill`.
                unsafe { core::ptr::copy_nonoverlapping(self.segs[v].base.add(rd), self.segs[w].base.add(at), foot) };
                self.segs[w].fill += foot as u32;
                self.segs[w].live += foot as u32;
                self.segs[v].live -= foot as u32;
                let b = &mut self.blobs[idx as usize];
                b.seg = w as u16;
                b.off = at as u32;
            }
            rd += foot;
        }
        if self.segs[v].live == 0 {
            self.release_segment(v);
            true
        } else {
            false
        }
    }

    /// Defragment: close the holes of every segment, then empty the sparsest
    /// segment into the others for as long as they have room for it. Frees
    /// segments (to the backing) and tail space; moves ciphertext only.
    pub fn compact(&mut self) {
        for s in 0..SEGS {
            if !self.segs[s].base.is_null() && s + 1 != self.leaving {
                self.slide(s);
            }
        }
        while self.n_segs > 1 {
            let Some(v) = (0..SEGS)
                .filter(|&s| !self.segs[s].base.is_null() && s + 1 != self.leaving)
                .min_by_key(|&s| self.segs[s].live)
            else {
                return;
            };
            let room: usize = (0..SEGS)
                .filter(|&w| w != v && !self.segs[w].base.is_null() && w + 1 != self.leaving)
                .map(|w| SEG - self.segs[w].fill as usize)
                .sum();
            if room < self.segs[v].live as usize || !self.evacuate(v) {
                return;
            }
        }
    }

    // ── store ────────────────────────────────────────────────────────────────

    /// Free slot for a new page, after dropping what was stored under the key.
    fn prepare(&mut self, owner: usize, obj: u64, page: u64) -> Result<(), Error> {
        if owner >= OWNERS {
            return Err(Error::BadOwner);
        }
        if let Some(i) = self.find(obj, page) {
            self.remove_slot(i);
        }
        if self.n_entries == E {
            return Err(Error::Full);
        }
        Ok(())
    }

    fn put(&mut self, owner: usize, obj: u64, page: u64, state: u16, data: u64) {
        let i = self.vacant(obj, page);
        self.gen = self.gen.wrapping_add(1);
        self.entries[i] = Entry { obj, page, data, owner: owner as u16, state, gen: self.gen };
        self.n_entries += 1;
    }

    /// Store a same-filled page. Replaces what was stored under the key.
    pub fn insert_fill(&mut self, owner: usize, obj: u64, page: u64, word: u64) -> Result<(), Error> {
        self.prepare(owner, obj, page)?;
        self.put(owner, obj, page, FILL, word);
        Ok(())
    }

    /// Store an encrypted stream (`Codec::pack`'s `Blob`). Replaces what was
    /// stored under the key. Charged `ct.len() + 8` bytes to `owner`.
    pub fn insert_blob(&mut self, owner: usize, obj: u64, page: u64, nonce: u64, ct: &[u8]) -> Result<(), Error> {
        self.prepare(owner, obj, page)?;
        let foot = ct.len() + HDR;
        if foot > SEG {
            return Err(Error::Full);
        }
        self.charge(owner, foot as u32)?;
        let Some((s, off)) = self.reserve(foot) else {
            self.discharge(owner, foot as u32);
            return Err(Error::Full);
        };
        // A record is free: those in use never exceed the entries, and
        // `prepare` found one entry free.
        let idx = match self.blob_free {
            0 => {
                self.blob_hwm += 1;
                self.blob_hwm - 1
            }
            f => {
                self.blob_free = self.blobs[f as usize - 1].off;
                f - 1
            }
        };
        self.n_blobs += 1;
        self.put_header(s, off, idx, ct.len() as u32);
        // SAFETY: `reserve` found `foot` bytes free at `off`.
        unsafe { core::ptr::copy_nonoverlapping(ct.as_ptr(), self.segs[s].base.add(off + HDR), ct.len()) };
        let g = &mut self.segs[s];
        g.fill = (off + foot) as u32;
        g.live += foot as u32;
        self.blobs[idx as usize] =
            Blob { off: off as u32, len: ct.len() as u32, nonce, refs: 1, seg: s as u16, owner: owner as u16 };
        self.put(owner, obj, page, BLOB, idx as u64);
        Ok(())
    }

    // ── fetch / remove ───────────────────────────────────────────────────────

    /// Read the page's entry without removing it, with the generation that
    /// names it (for [`remove_if`](Self::remove_if)). A blob's ciphertext is
    /// copied into `out[..len]`; `None` when nothing is stored, `out` is
    /// too small for the blob, **or the blob's segment is swapped out** (ask
    /// [`swapped`](Self::swapped) first: `gen_of` answers for such a page).
    pub fn fetch(&self, obj: u64, page: u64, out: &mut [u8]) -> Option<(Fetched, u32)> {
        let e = self.entries[self.find(obj, page)?];
        let what = match e.state {
            FILL => Fetched::Fill(e.data),
            _ => {
                let b = &self.blobs[e.data as usize];
                let len = b.len as usize;
                // A page in a swapped segment is not here: see `swapped`.
                if out.len() < len || self.is_parked(b.seg) {
                    return None;
                }
                // SAFETY: a live blob's bytes lie inside its segment, below `fill`.
                unsafe {
                    core::ptr::copy_nonoverlapping(self.segs[b.seg as usize].base.add(b.off as usize + HDR), out.as_mut_ptr(), len)
                };
                Fetched::Blob { len, nonce: b.nonce }
            }
        };
        Some((what, e.gen))
    }

    /// Remove the page's entry. `false`: there was none.
    pub fn remove(&mut self, obj: u64, page: u64) -> bool {
        match self.find(obj, page) {
            Some(i) => {
                self.remove_slot(i);
                true
            }
            None => false,
        }
    }

    /// Remove the page's entry if it is still the one `fetch` returned `gen`
    /// for. `false`: it was gone or has been replaced by a later store, which
    /// stays. This is what a fault that restored the page drops its copy with:
    /// the reclaimer may have stored the freshly installed frame again before
    /// the fault got here, and that newer copy is the only one of the page.
    pub fn remove_if(&mut self, obj: u64, page: u64, gen: u32) -> bool {
        match self.find(obj, page) {
            Some(i) if self.entries[i].gen == gen => {
                self.remove_slot(i);
                true
            }
            _ => false,
        }
    }

    /// Remove the entries of `obj` whose page is in `[lo, hi)`; how many.
    pub fn remove_range(&mut self, obj: u64, lo: u64, hi: u64) -> usize {
        let mut n = 0;
        let mut i = 0;
        // After a removal the slot is looked at again: the entry that closed
        // the gap came from further on in the table.
        while i < SLOTS {
            let e = &self.entries[i];
            if e.state != EMPTY && e.obj == obj && e.page >= lo && e.page < hi {
                self.remove_slot(i);
                n += 1;
            } else {
                i += 1;
            }
        }
        n
    }

    /// Remove every page of `obj`; how many.
    pub fn remove_obj(&mut self, obj: u64) -> usize {
        self.remove_range(obj, 0, u64::MAX)
    }

    /// Give `to` the pages of `from` (a fork's child gets the parent's), each
    /// charged to the Domain that holds the source. Blobs are shared, not
    /// copied, and each new entry has the generation of its source. Nothing is
    /// changed on `Err`.
    pub fn dup_obj(&mut self, from: u64, to: u64) -> Result<usize, Error> {
        if from == to {
            return Ok(0);
        }
        let mut n = 0;
        for i in 0..SLOTS {
            let e = self.entries[i];
            if e.state == EMPTY || e.obj != from {
                continue;
            }
            let r = if e.state == FILL {
                self.insert_fill(e.owner as usize, to, e.page, e.data)
            } else {
                self.share(e, to)
            };
            if let Err(err) = r {
                self.remove_obj(to);
                return Err(err);
            }
            // The child's entry has the generation of the parent's, so the
            // page marker in the parent's slot names the child's copy too: a
            // fork copies markers word for word.
            if let Some(j) = self.find(to, e.page) {
                self.entries[j].gen = e.gen;
            }
            n += 1;
        }
        Ok(n)
    }

    /// A second entry, `to`, for the blob that `e` points at.
    fn share(&mut self, e: Entry, to: u64) -> Result<(), Error> {
        let owner = e.owner as usize;
        self.prepare(owner, to, e.page)?;
        let idx = e.data as usize;
        self.charge_blob(idx, owner)?;
        self.blobs[idx].refs += 1;
        self.put(owner, to, e.page, BLOB, e.data);
        Ok(())
    }

    // ── swap ─────────────────────────────────────────────────────────────────
    //
    // The books of `swap.rs`. None of these does I/O or takes a lock; the
    // caller holds the pool's lock for each call, never across the device.
    // Two steps of a kind do not overlap (`leaving`, `inbound`): the second
    // asker is answered `Busy`.

    /// Declare the swap area: it holds `slots` segments (clamped to `SW`).
    /// Call before the first pick. `false`: no slot, or a segment is out.
    pub fn swap_attach(&mut self, slots: usize) -> bool {
        if self.n_parked != 0 || self.leaving != 0 {
            return false;
        }
        self.swap_cap = slots.min(SW);
        self.swap_cap != 0
    }

    /// How the area's slots stand: the count, the free ones, and the
    /// distance to the highest parked one (see [`SwapSlots`]).
    pub fn swap_slots(&self) -> SwapSlots {
        let cap = self.swap_cap.min(SW);
        let used = self.parked[..cap].iter().filter(|p| p.live != 0).count();
        let top = self.parked[..cap].iter().rposition(|p| p.live != 0).map_or(0, |i| i + 1);
        SwapSlots { cap, free: cap - used, top }
    }

    /// Change the area to `cap` slots (clamped to `SW`; never to none). A
    /// grow always happens. A shrink only when no segment is leaving and the
    /// slots it drops hold no parked segment (`swap_free_slot` fills from the
    /// bottom, so the tail is what empties): the answer is `false` otherwise
    /// and nothing changed. The caller has the medium follow the new size.
    pub fn swap_set_cap(&mut self, cap: usize) -> bool {
        let cap = cap.min(SW);
        if cap == 0 || self.swap_cap == 0 {
            return false;
        }
        if cap < self.swap_cap && (self.leaving != 0 || self.parked[cap..self.swap_cap].iter().any(|p| p.live != 0)) {
            return false;
        }
        self.swap_cap = cap;
        true
    }

    /// The first free slot of the area.
    fn swap_free_slot(&self) -> Option<usize> {
        (0..self.swap_cap.min(SW)).find(|&p| self.parked[p].live == 0)
    }

    /// Charge every live blob of segment `s` to its owner's swap ledger,
    /// undoing all of it on the first refusal. `Ok` leaves it charged.
    fn sw_charge_segment(&mut self, s: usize) -> Result<(), Error> {
        for i in 0..self.blob_hwm as usize {
            let b = self.blobs[i];
            if b.refs == 0 || b.seg as usize != s {
                continue;
            }
            let bytes = (b.foot() as u32).saturating_mul(b.refs);
            if let Err(e) = self.sw_charge(b.owner as usize, bytes) {
                for j in 0..i {
                    let c = self.blobs[j];
                    if c.refs != 0 && c.seg as usize == s {
                        self.sw_discharge(c.owner as usize, (c.foot() as u32).saturating_mul(c.refs));
                    }
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// Undo a [`sw_charge_segment`](Self::sw_charge_segment) that succeeded.
    fn sw_discharge_segment(&mut self, s: usize) {
        for i in 0..self.blob_hwm as usize {
            let b = self.blobs[i];
            if b.refs != 0 && b.seg as usize == s {
                self.sw_discharge(b.owner as usize, (b.foot() as u32).saturating_mul(b.refs));
            }
        }
    }

    /// Choose a segment to write out, slide the holes out of it and mark it
    /// leaving. It is *full*: its live blobs fill at least `MM_SWAP_FULL_PCT`
    /// percent of the segment. The first after the last pick, going round,
    /// wins. A segment holding a page of a Domain `pinned` calls pinned is
    /// never chosen, nor one whose Domains would pass their swap quota.
    /// `pinned` runs under the pool's lock: it takes none.
    ///
    /// `Err`: `NoSwap` (no area), `Busy` (another segment is leaving), `Full`
    /// (no free slot), `NoSegment` (none is full), `Pinned` or `Quota` (the
    /// full ones are refused for that reason).
    pub fn swap_pick(&mut self, pinned: &dyn Fn(usize) -> bool) -> Result<SwapPick, Error> {
        if self.swap_cap == 0 || SEGS == 0 {
            return Err(Error::NoSwap);
        }
        if self.leaving != 0 {
            return Err(Error::Busy);
        }
        let Some(slot) = self.swap_free_slot() else { return Err(Error::Full) };
        // One pass over the blobs: which segments hold a pinned Domain's page.
        let mut held = [false; SEGS];
        for i in 0..self.blob_hwm as usize {
            let b = &self.blobs[i];
            if b.refs != 0 && !self.is_parked(b.seg) && pinned(b.owner as usize) {
                held[b.seg as usize] = true;
            }
        }
        let (mut saw_pinned, mut saw_quota) = (false, false);
        for k in 1..=SEGS {
            let s = (self.hand + k) % SEGS;
            let g = self.segs[s];
            if g.base.is_null() || g.live == 0 || (g.live as usize) * 100 < SEG * SWAP_FULL_PCT {
                continue;
            }
            if held[s] {
                saw_pinned = true;
                continue;
            }
            if self.sw_charge_segment(s).is_err() {
                saw_quota = true;
                continue;
            }
            self.sw_discharge_segment(s);
            self.slide(s);
            self.leaving = s + 1;
            self.hand = s;
            return Ok(SwapPick { seg: s, slot, fill: self.segs[s].fill as usize, live: self.segs[s].live as usize });
        }
        Err(if saw_pinned {
            Error::Pinned
        } else if saw_quota {
            Error::Quota
        } else {
            Error::NoSegment
        })
    }

    /// Copy the picked segment's bytes into `dst` (`SEG` bytes; the tail past
    /// the written length is zeroed). The staged image is what goes to the
    /// medium, after the caller encrypts it.
    pub fn swap_stage(&self, pick: &SwapPick, dst: &mut [u8]) -> Result<(), Error> {
        let g = &self.segs[pick.seg];
        if self.leaving != pick.seg + 1 || g.base.is_null() || dst.len() != SEG {
            return Err(Error::Gone);
        }
        let n = g.fill as usize;
        // SAFETY: the segment's bytes below `fill` are written, within its allocation.
        unsafe { core::ptr::copy_nonoverlapping(g.base, dst.as_mut_ptr(), n) };
        dst[n..].fill(0);
        Ok(())
    }

    /// The staged image is on the medium: free the segment's frames, move its
    /// pages' bytes to the swap ledger and park it in the slot. `Err(Gone)`:
    /// every page left meanwhile (nothing is parked; the caller forgets the
    /// slot), `Err(Quota)`: a Domain passed its swap quota meanwhile. Either
    /// way the segment is no longer leaving.
    pub fn swap_commit(&mut self, pick: &SwapPick) -> Result<(), Error> {
        let s = pick.seg;
        if self.leaving != s + 1 {
            return Err(Error::Gone);
        }
        self.leaving = 0;
        if self.segs[s].live == 0 {
            self.empty_segment(s);
            return Err(Error::Gone);
        }
        if self.parked[pick.slot].live != 0 {
            return Err(Error::Gone);
        }
        self.sw_charge_segment(s)?;
        // The blobs move out; the pool's own charges go back.
        for i in 0..self.blob_hwm as usize {
            let b = self.blobs[i];
            if b.refs != 0 && b.seg as usize == s {
                self.discharge(b.owner as usize, (b.foot() as u32).saturating_mul(b.refs));
                self.blobs[i].seg = (SEGS + pick.slot) as u16;
            }
        }
        self.pgen = self.pgen.wrapping_add(1).max(1);
        self.parked[pick.slot] = Parked { fill: self.segs[s].fill, live: self.segs[s].live, gen: self.pgen };
        self.n_parked += 1;
        self.release_segment(s);
        Ok(())
    }

    /// The write failed (or the pick is given up): the segment stays.
    pub fn swap_abort(&mut self, pick: &SwapPick) {
        if self.leaving == pick.seg + 1 {
            self.leaving = 0;
            if self.segs[pick.seg].live == 0 {
                self.empty_segment(pick.seg);
            }
        }
    }

    /// Is the page's blob in a swapped segment? The slot, its incarnation and
    /// the length written.
    pub fn swapped(&self, obj: u64, page: u64) -> Option<Swapped> {
        let e = self.entries[self.find(obj, page)?];
        if e.state != BLOB {
            return None;
        }
        let b = &self.blobs[e.data as usize];
        if !self.is_parked(b.seg) {
            return None;
        }
        let slot = b.seg as usize - SEGS;
        let p = &self.parked[slot];
        Some(Swapped { slot, gen: p.gen, fill: p.fill as usize })
    }

    /// The generation of the page's entry (see [`remove_if`](Self::remove_if)):
    /// what a page marker carries, and what a restore checks the entry against.
    pub fn gen_of(&self, obj: u64, page: u64) -> Option<u32> {
        Some(self.entries[self.find(obj, page)?].gen)
    }

    /// [`fetch`](Self::fetch) of the page a page marker names: `gen` is the
    /// generation the marker carries. An entry of another generation is a
    /// different store of the page (the marker is stale, or the pool is
    /// wrong): [`Lookup::Wrong`], never restored, so the task that touches it
    /// fails and does not read the wrong bytes.
    pub fn fetch_named(&self, obj: u64, page: u64, gen: u32, out: &mut [u8]) -> Lookup {
        let Some(i) = self.find(obj, page) else { return Lookup::Gone };
        let e = &self.entries[i];
        if e.gen != gen {
            return Lookup::Wrong;
        }
        if e.state == BLOB && self.is_parked(self.blobs[e.data as usize].seg) {
            return Lookup::Parked;
        }
        let owner = e.owner;
        match self.fetch(obj, page, out) {
            Some((what, g)) => Lookup::Page(what, g, owner),
            None => Lookup::Wrong,
        }
    }

    /// The stored pages whose segment is on the swap area, from entry `from`
    /// of the index on, into `out`: how many, and where to go on (`None`: the
    /// index is done). For the caller that turns their markers into
    /// [`Swapped`](PageMarker::Swapped) ones a few at a time, without holding
    /// the pool's lock across a page-table write.
    pub fn parked_from(&self, from: usize, out: &mut [Stored]) -> (usize, Option<usize>) {
        let mut n = 0;
        let mut i = from;
        while i < SLOTS {
            if n == out.len() {
                return (n, Some(i));
            }
            let e = &self.entries[i];
            if e.state == BLOB && self.is_parked(self.blobs[e.data as usize].seg) {
                out[n] = Stored { obj: e.obj, page: e.page, gen: e.gen };
                n += 1;
            }
            i += 1;
        }
        (n, None)
    }

    /// Does a segment have somewhere to come back to (a free resident slot,
    /// below the ceiling)?
    pub fn swap_has_room(&self) -> bool {
        self.n_segs + (self.inbound as usize) < SEGS
    }

    /// Start bringing slot `sw.slot` back: hold a resident slot and take its
    /// `SEG` bytes from the backing. The caller fills them from the medium
    /// (outside the lock) and hands them to [`swap_in_commit`](Self::swap_in_commit)
    /// or [`swap_in_abort`](Self::swap_in_abort). `Err(Gone)`: the slot is no
    /// longer `sw`; `Err(Busy)`: another segment is coming back (ask again when
    /// that step ends); `Err(Full)`: no resident slot or no memory (make room
    /// by writing another segment out, and ask again).
    pub fn swap_in_begin(&mut self, sw: &Swapped) -> Result<NonNull<u8>, Error> {
        match self.parked.get(sw.slot) {
            Some(p) if p.live != 0 && p.gen == sw.gen => {}
            _ => return Err(Error::Gone),
        }
        if self.inbound {
            return Err(Error::Busy);
        }
        if !self.swap_has_room() {
            return Err(Error::Full);
        }
        let buf = self.backing.alloc(SEG).ok_or(Error::Full)?;
        self.inbound = true;
        Ok(buf)
    }

    /// Is slot `sw.slot` still the incarnation `sw` named: parked, with live
    /// pages, under the same generation? A reader whose block failed its tag
    /// asks this to tell a changed medium (yes: still `sw`, so nothing else
    /// could have written the slot) from a slot that was freed and sealed
    /// again while it read (no: not tamper, the segment it wanted is gone).
    #[must_use]
    pub fn swap_in_current(&self, sw: &Swapped) -> bool {
        self.parked.get(sw.slot).is_some_and(|p| p.live != 0 && p.gen == sw.gen)
    }

    /// The segment of `sw` is in `buf` (verified and decrypted): make it
    /// resident again and give its slot back. The bytes go back from the swap
    /// ledger to the pool's, unconditionally: a fault is never refused for
    /// quota. `Err(Gone)`: its pages all left meanwhile; `buf` is freed.
    pub fn swap_in_commit(&mut self, sw: &Swapped, buf: NonNull<u8>) -> Result<(), Error> {
        self.inbound = false;
        let p = self.parked.get(sw.slot).copied();
        let Some(p) = p.filter(|p| p.live != 0 && p.gen == sw.gen) else {
            self.backing.free(buf, SEG);
            return Err(Error::Gone);
        };
        let Some(s) = (0..SEGS).find(|&s| self.segs[s].base.is_null()) else {
            self.backing.free(buf, SEG);
            return Err(Error::Full);
        };
        self.segs[s] = Segment { base: buf.as_ptr(), fill: p.fill, live: p.live };
        self.n_segs += 1;
        let here = (SEGS + sw.slot) as u16;
        for i in 0..self.blob_hwm as usize {
            let b = self.blobs[i];
            if b.refs != 0 && b.seg == here {
                let bytes = (b.foot() as u32).saturating_mul(b.refs);
                self.sw_discharge(b.owner as usize, bytes);
                if let Some(a) = self.acct.get_mut(b.owner as usize) {
                    a.used = a.used.saturating_add(bytes);
                }
                self.blobs[i].seg = s as u16;
            }
        }
        self.parked[sw.slot] = Parked { fill: 0, live: 0, gen: p.gen };
        self.n_parked -= 1;
        Ok(())
    }

    /// The read or the verification failed: free the buffer and the held slot.
    pub fn swap_in_abort(&mut self, buf: NonNull<u8>) {
        self.inbound = false;
        self.backing.free(buf, SEG);
    }

    // ── reports ──────────────────────────────────────────────────────────────

    /// Pages held.
    pub fn len(&self) -> usize {
        self.n_entries
    }

    pub fn is_empty(&self) -> bool {
        self.n_entries == 0
    }

    pub fn stats(&self) -> Stats {
        Stats {
            entries: self.n_entries,
            blobs: self.n_blobs,
            segments: self.n_segs,
            swapped: self.n_parked,
            live_bytes: self.segs.iter().map(|g| g.live as usize).sum(),
            resident_bytes: self.n_segs * SEG,
        }
    }
}

// ── Reclaim storms ───────────────────────────────────────────────────────────

/// Where a storm's victims come from and what is done to each: the object
/// table, the page tables and the page allocator, behind one seam. A victim is
/// whatever names a page to the source (a copyable key). The calls for one
/// victim come in this order: `next`, `unmap`, then `store` and either `free`
/// or `keep`.
pub trait Reclaimee {
    type Victim: Copy;

    /// The next candidate: a swappable anonymous page of the Domain that is
    /// resident, not shared copy-on-write, and not locked. `None` when the
    /// source has no more to offer this storm. Oldest first (the coldest
    /// generation, `aging.rs`), and never a page already known not to compress
    /// that has not been touched since.
    fn next(&mut self) -> Option<Self::Victim>;

    /// Remove the page from every mapping, shot down on every hart, so nothing
    /// can write it. `false`: it is busy (a pinned or sealed mapping); the
    /// storm moves on and the page stays as it was.
    fn unmap(&mut self, v: Self::Victim) -> bool;

    /// Compress the unmapped page into the pool. `Ok(n)`: the pool holds it
    /// now, `n` bytes (0 for a same-filled page). `Err`: it stays resident.
    fn store(&mut self, v: Self::Victim) -> Result<u32, Error>;

    /// The stored page's frame goes back to the allocator, and the page is
    /// marked out for the fault that will restore it.
    fn free(&mut self, v: Self::Victim);

    /// The page was unmapped and not stored: it stays resident, and a fault
    /// maps it again.
    fn keep(&mut self, v: Self::Victim);
}

/// Run one reclaim storm of the Domain whose frame budget is `b`. `Err` when
/// the storm may not start (see [`NoStorm`]). Otherwise the storm ran until the
/// charge reached `low`, `max_steps` candidates were tried (the bound on how
/// long a storm holds its hart), the source had no more, or the pool refused
/// for want of room; the answer is its one record, whatever it did, and the
/// caller writes the `Rule::Compress` decision from it
/// ([`StormRecord::outcome`]). `locked` and `rt_hart` are the caller's facts about the
/// Domain's memory row and the hart it runs on; `page_bytes` the page size.
/// With reclaim off no Domain has a watermark, so no storm starts.
pub fn run_storm<R: Reclaimee>(
    b: &PageBudget,
    r: &mut R,
    locked: bool,
    rt_hart: bool,
    max_steps: u32,
    page_bytes: u32,
) -> Result<StormRecord, NoStorm> {
    b.storm_begin(locked, rt_hart)?;
    let mut steps = 0;
    let mut full = false;
    let mut refused = false;
    while steps < max_steps && b.reclaim_target() != 0 {
        steps += 1;
        let Some(v) = r.next() else { break };
        if !r.unmap(v) {
            continue;
        }
        match r.store(v) {
            Ok(out) => {
                r.free(v);
                b.storm_note_stored(out);
            }
            Err(e) => {
                r.keep(v);
                refused = true;
                if e != Error::Incompressible {
                    full = e == Error::Full;
                    break;
                }
            }
        }
    }
    let mut rec = b.storm_end(page_bytes).ok_or(NoStorm::Busy)?;
    rec.full = full;
    rec.refused = refused;
    Ok(rec)
}

// ── Page markers ─────────────────────────────────────────────────────────────
//
// What makes the pool restorable by a fault. A page the reclaimer takes out of
// an address space leaves a *marker* in its page-table slot
// (`azos_arch_api::PageMarker`), and the fault path decides from the word it
// reads, not from a look at the pool:
//
// * empty: a page nobody touched, or one `munmap` took: a zero page;
// * [`InTransit`](PageMarker::InTransit): the reclaimer has the page out of
//   the table and has not stored it yet. The fault waits and retries. Without
//   it the fault would read the pool (nothing yet), zero-fill, and the
//   reclaimer's copy would be orphaned: the window `pager::zpool_store`'s
//   doc used to list as open;
// * [`Compressed`](PageMarker::Compressed) / [`Swapped`](PageMarker::Swapped):
//   restore from the pool, and replace the marker with the page.
//
// A marker is only ever written over a plain user leaf the reclaimer owns, by
// compare-and-swap from the exact word it read, so a fork, a COW break or an
// `mprotect` that got there first wins and the reclaimer leaves the page
// alone. All the words are compare-and-swapped, never stored: the fault, the
// reclaimer and `munmap` race on them without a lock.
//
// This file does not know the page-table format; `PageWords` is the part of
// the architecture's `Mmu` it needs, so the host rows run these functions
// over each ISA's real encoding.

/// The page-table words a marker protocol reads and writes: the part of
/// [`azos_arch_api::Mmu`] it needs, which every `Mmu` is (the blanket impl).
pub trait PageWords {
    /// A plain 4 KiB user leaf the reclaimer may take: valid, a leaf at level
    /// 0, user-accessible, not shared copy-on-write, not one of a contiguous
    /// run (changing one member of a run on its own is not allowed).
    fn is_victim_leaf(&self, word: u64) -> bool;
    fn is_valid(&self, word: u64) -> bool;
    fn make_marker(&self, kind: PageMarker, payload: u32) -> u64;
    fn marker(&self, word: u64) -> Option<(PageMarker, u32)>;
}

impl<M: Mmu> PageWords for M {
    #[inline]
    fn is_victim_leaf(&self, word: u64) -> bool {
        self.pte_is_valid(word)
            && self.pte_is_leaf(word, 0)
            && self.pte_perms(word).user
            && !self.pte_is_cow(word)
            && !self.pte_is_contig(word)
    }

    #[inline]
    fn is_valid(&self, word: u64) -> bool {
        self.pte_is_valid(word)
    }

    #[inline]
    fn make_marker(&self, kind: PageMarker, payload: u32) -> u64 {
        self.pte_make_marker(kind, payload)
    }

    #[inline]
    fn marker(&self, word: u64) -> Option<(PageMarker, u32)> {
        self.pte_marker(word)
    }
}

/// Why [`take_out`] left the slot as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not a leaf the reclaimer takes: empty, a marker, shared, a block.
    NotVictim,
    /// The word changed between the read and the swap (a fork, a COW break,
    /// an `mprotect`, another fault): not this pass's page.
    Changed,
}

/// Start storing the page whose slot is `slot`: swap the leaf it holds for an
/// [`InTransit`](PageMarker::InTransit) marker carrying `ticket`, and give the
/// leaf back. The caller then shoots the translation down on every hart
/// before it reads the frame (until then another hart may still write
/// through a stale entry), and ends with exactly one of [`publish`] and
/// [`put_back`]. `ticket` names this store: the marker it finishes is its
/// own even if the page went and came back meanwhile.
pub fn take_out<W: PageWords>(w: &W, slot: &AtomicU64, ticket: u32) -> Result<u64, Refusal> {
    let cur = slot.load(Ordering::Acquire);
    if !w.is_victim_leaf(cur) {
        return Err(Refusal::NotVictim);
    }
    slot.compare_exchange(cur, w.make_marker(PageMarker::InTransit, ticket), Ordering::AcqRel, Ordering::Acquire)
        .map(|_| cur)
        .map_err(|_| Refusal::Changed)
}

/// The store ended well: the pool holds the page, `kind`/`payload` say where.
/// `false`: the slot is not the store's marker any more (the range was
/// unmapped meanwhile); the caller drops what it stored.
pub fn publish<W: PageWords>(w: &W, slot: &AtomicU64, ticket: u32, kind: PageMarker, payload: u32) -> bool {
    let from = w.make_marker(PageMarker::InTransit, ticket);
    slot.compare_exchange(from, w.make_marker(kind, payload), Ordering::AcqRel, Ordering::Acquire).is_ok()
}

/// The store did not happen: the page stays where it was, `original` is the
/// leaf [`take_out`] returned. `false`: the slot is not the store's marker any
/// more (unmapped meanwhile): the frame is the caller's to free.
pub fn put_back<W: PageWords>(w: &W, slot: &AtomicU64, ticket: u32, original: u64) -> bool {
    let from = w.make_marker(PageMarker::InTransit, ticket);
    slot.compare_exchange(from, original, Ordering::AcqRel, Ordering::Acquire).is_ok()
}

/// Empty the slot if it holds a marker (`munmap`, a range that stops
/// existing): its kind and payload; `None` when it holds anything else.
pub fn clear<W: PageWords>(w: &W, slot: &AtomicU64) -> Option<(PageMarker, u32)> {
    let mut cur = slot.load(Ordering::Acquire);
    loop {
        let m = w.marker(cur)?;
        match slot.compare_exchange(cur, 0, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(m),
            Err(now) => cur = now,
        }
    }
}

/// What a fault found in the slot of a page its region covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Nothing there: a zero page.
    Zero,
    /// A leaf: another thread resolved it, the access retries.
    Present,
    /// A store of the page is in flight: wait for it, then retry.
    Wait,
    /// The page is in the pool (or on swap): restore it.
    Restore(PageMarker, u32),
    /// A word the pager does not own (a demand reservation).
    Other,
}

/// Decide a fault from the word read from the slot. The only place that says
/// what an empty slot means: a zero page. The pool is not asked.
pub fn classify<W: PageWords>(w: &W, word: u64) -> Fault {
    if word == 0 {
        return Fault::Zero;
    }
    if w.is_valid(word) {
        return Fault::Present;
    }
    match w.marker(word) {
        Some((PageMarker::InTransit, _)) => Fault::Wait,
        Some((kind, payload)) => Fault::Restore(kind, payload),
        None => Fault::Other,
    }
}

// ── The reclaim pass ─────────────────────────────────────────────────────────

/// What one round of the compression stage did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Round {
    /// Pages the round stored.
    pub stored: u32,
    /// A storm ended for want of room in the pool.
    pub full: bool,
}

/// The stages of a reclaim pass, as the kernel runs them
/// (`kernel/src/tasks/reclaim.rs`). Each is the cheapest way to get frames
/// that the stages after it are not.
pub trait Stages {
    /// Stage 0: volatile memory objects give their frames up. Nothing is read,
    /// written or compressed: the owner rebuilds what it dropped, so this is
    /// the cheapest frame there is and goes before every other stage.
    fn purge(&mut self);
    /// Stage 1: the page cache gives back its clean frames and writes its
    /// dirty ones.
    fn page_cache(&mut self);
    /// Stage 2: every Domain over its high watermark has one storm into the
    /// pool.
    fn compress(&mut self) -> Round;
    /// Stage 3: write one full pool segment to swap. `false`: none went (no
    /// swap, nothing full enough, a pinned Domain's pages in each).
    fn swap(&mut self) -> bool;
    /// Is memory still below the stop mark?
    fn still_low(&mut self) -> bool;
}

/// Run a reclaim pass: volatile objects first, then the page cache, then
/// compression, and swap only when the pool says it is full, asking
/// compression again after each segment that went out. At most `max_rounds`
/// rounds of stage 2 (a pass holds its CPU for a bounded time). The rounds it
/// ran.
pub fn reclaim_pass<S: Stages>(s: &mut S, max_rounds: u32) -> u32 {
    s.purge();
    s.page_cache();
    let mut rounds = 0;
    while rounds < max_rounds {
        rounds += 1;
        let r = s.compress();
        if r.full {
            if !s.swap() {
                break;
            }
            continue;
        }
        if r.stored == 0 || !s.still_low() {
            break;
        }
    }
    rounds
}

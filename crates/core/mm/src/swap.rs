// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Swap after compression (Kconfig `MM_SWAP_BACKEND`): the last stage of the
//! reclaim order. A *full segment* of the compressed-page pool
//! (`zpool.rs`) is written whole to the swap partition and its frames freed;
//! a fault on one of its pages reads the segment back. Never a single page:
//! the unit on the medium is the unit in memory, so one request moves tens of
//! pages and the medium sees large sequential writes (the XNU compressor's
//! swap-file behaviour, reimplemented from the published design).
//!
//! The books (which segment, which slot, whose bytes) are the pool's
//! ([`Pool::swap_pick`] and its siblings); this file is the part that touches
//! the medium and the keys, and the loops around them. It depends on
//! `zpool.rs`, never the other way: the syscall-tests shim pulls `zpool.rs`
//! alone.
//!
//! # Encryption (always)
//!
//! A staged segment is AES-128-CTR under a key made once per boot from the
//! entropy pool and kept in RAM only (so swap does not survive a reboot, by
//! design), then tagged: `HMAC-SHA256(mac_key, slot || nonce || ciphertext)`
//! cut to 16 bytes. Each write takes a fresh nonce from one counter. **The tag
//! and the nonce stay in RAM**, in the slot's record, not on the medium: a
//! block that was changed, put in another slot (which holds another record),
//! or replaced by an earlier write of the same slot (another nonce) is refused
//! when it is read back, and nothing of it is decrypted or attached
//! ([`SwapError::Tamper`]). The blobs inside a segment
//! are ciphertext under the pool's key already; this layer hides the headers,
//! authenticates the whole and binds it to its slot. The tag is checked
//! before the decryption, in constant time.
//!
//! # The swap lock and the device (owner rule F1)
//!
//! No mutex is held across a device wait. The swap state (the keys, the
//! slots' records, the counters) is behind a lock the caller owns
//! ([`Locked`], a sleeping mutex in the kernel), taken for the CPU-only
//! steps: [`Swap::seal`] before a write and [`Swap::open`] after a read, the
//! record snapshot and the counters. A step is `submit` (under the locks) ->
//! release -> wait for the device (under none) -> re-take to commit:
//!
//! * out: `pick` (pool) -> stage (pool) -> seal (swap) -> **write** ->
//!   commit or abort (pool);
//! * in: `begin` (pool) -> record snapshot (swap) -> **read** -> open (swap)
//!   -> commit or abort (pool).
//!
//! Two steps of a kind do not overlap, and the pool says so instead of a
//! mutex: `pick` answers [`PoolError::Busy`] while a segment is leaving and
//! `in_begin` while one is coming back; the caller sees [`SwapError::Busy`]
//! and tries again when [`Locked::step_end`] rings (the kernel parks a fault on
//! a wait queue woken there; the storm entry just gives up). A slot is only
//! sealed again after the pool freed it, so a reader that started on a slot
//! can find it re-sealed under it: it verifies against the record it
//! snapshotted, and a block that fails its tag is **tamper only if the pool
//! still has the segment the reader started on** ([`Pool::swap_in_current`]);
//! otherwise the segment is gone, nothing of the bytes is used, and the
//! caller asks the pool again.
//!
//! The lock is not re-entrant, and no closure given to it calls it again. The
//! kernel's takers of the swap state are the boot attach and the steps above;
//! none holds it across anything but `seal`, `open` and a counter bump.
//!
//! The pool's own lock is never held across the device: it is taken for each
//! book-keeping step: `pick` (under the lock) → stage a copy → encrypt and
//! write (no pool lock) → `commit` (under the lock). A restore is `begin` →
//! read, verify, decrypt (no pool lock) → `commit`. The pool is reached
//! through [`Locked`], so the kernel gives it its spinlock and a host row a
//! `RefCell`.
//!
//! # Where it may run
//!
//! The device is the block layer's queue (`azos_drv_block::blkdev`; the kernel
//! implements [`SwapDev`] with it): a segment is one request, cut by the layer
//! into the device's largest commands and submitted plugged, up to the queue
//! depth in flight. On an NVMe controller a command starts on the slots of the
//! hart that starts it, on that hart's own hardware queue (Kconfig
//! `NVME_QUEUES`), and spills onto the other queues' free slots, so a
//! segment's chunks are spread over the controller's queues without this file
//! naming one. An eviction storm is refused on a
//! real-time hart before anything is touched ([`swap_out_storm`]): the block
//! layer's real-time check would otherwise stop the machine. The kernel's
//! storms come from one task pinned off the real-time CPUs (`kernel/src/tasks/reclaim.rs`)
//! and from the store path when the pool answers `Full`. A restore runs in
//! the faulting task, which is never a real-time one (real-time memory is
//! committed at map time and never faults). A segment holding a page of a
//! pinned Domain (`mem = "locked"`, real-time) is never written
//! ([`Pool::swap_pick`]).
//!
//! # An area that changes size (a swap file)
//!
//! A [`SwapDev`] that is [`resizable`](SwapDev::resizable) (the kernel's swap
//! file) starts small and follows the demand, by whole [`GROW_SLOTS`]-slot
//! steps. [`swap_out_storm`] grows it when a pick finds no free slot
//! ([`swap_grow`]: the device first, waited for with no lock held, then the
//! pool's slot count, so no pick names a slot the medium lacks; a step the
//! medium cannot give is halved) and once more at its end when it filled the
//! last slot, so the restore that meets the ceiling finds one: [`swap_in`] never
//! grows the area, because it may run in a task that holds the filesystem's
//! locks. [`swap_trim`], one call per idle reclaim pass, gives the free tail
//! back after [`SHRINK_POLLS`] passes in which no segment moved: slots first
//! (the pool refuses while a segment is leaving or one is parked in the tail),
//! then the device, and not while a discard is still on a tail slot. Only one
//! resize runs at a time. [`RunMap`] is the part of the kernel's device that
//! maps the file's sectors to the medium.
//!
//! # Records
//!
//! One `Rule::SwapOut` decision per storm, `[segments, live bytes, bytes
//! written]`, written through the policy's `record` hook at the end of
//! [`swap_out_storm`] (so no caller can forget it). A storm that wrote nothing
//! is a `Refuse`.

use core::ptr::NonNull;

use azos_crypto::aes::Aes128;
use azos_crypto::ct::{ct_eq, secure_zero};
use azos_crypto::hkdf::hmac_sha256;

use crate::zpool::{self, Backing, Error as PoolError, Pool, SwapPick, SwapSlots, Swapped};

/// Kconfig `MM_SWAP_BACKEND`.
pub const ENABLED: bool = zpool::SWAP;
/// Kconfig `MM_SWAP_ENCRYPT`: not a knob, on whenever swap is. The code
/// below encrypts unconditionally; the assertion is what makes the symbol
/// binding, so a Kconfig that turned it off under a swap area fails the build.
pub const ENCRYPT: bool = azos_limits::MM_SWAP_ENCRYPT;
const _: () = assert!(ENCRYPT || !ENABLED, "swap is always encrypted");

/// Bytes per sector of the swap area.
pub const SECTOR: usize = 512;
/// Bytes of a tag.
pub const TAG: usize = 16;

/// The swap area: whole sectors of the swap partition, addressed from its
/// first (the partition is the area's, nothing else lives in it). The
/// kernel's is the block layer's queue; a host row's a sector map.
pub trait SwapDev {
    /// Write `buf` (a multiple of [`SECTOR`]) from sector `sector` of the area.
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), ()>;
    /// Read `buf.len()` bytes (a multiple of [`SECTOR`]) from sector `sector`.
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), ()>;
    /// Tell the medium the `sectors` sectors from `sector` hold nothing worth
    /// keeping (a hint, waited for). A medium with no such command has nothing
    /// to do, which is the default.
    fn discard(&self, _sector: u64, _sectors: u32) -> Result<(), ()> {
        Ok(())
    }
    /// Does the area change size (a swap file)? A partition does not.
    fn resizable(&self) -> bool {
        false
    }
    /// Make the area `sectors` sectors long (a multiple of one segment): a
    /// grow adds sectors that hold nothing yet, a shrink gives the tail back.
    /// Waited for; `Err` leaves the area as it was or longer, never shorter
    /// than asked. Called with no lock held, one at a time ([`swap_grow`],
    /// [`swap_trim`]).
    fn resize(&self, _sectors: u64) -> Result<(), ()> {
        Err(())
    }
}

/// A run of consecutive sectors of the medium, absolute addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Run {
    pub lba: u64,
    pub sectors: u32,
}

/// Where the sectors of an area that is a file lie on the medium: `N` runs, in
/// file order. The swap file's [`SwapDev`] holds one (the filesystem gave the
/// runs, [`RunMap::set_iter`] keeps them) and cuts every request along them
/// ([`RunMap::piece`]), so a segment may cross a fragment of the file.
#[derive(Clone, Copy)]
pub struct RunMap<const N: usize> {
    runs: [Run; N],
    n: usize,
    total: u64,
}

impl<const N: usize> RunMap<N> {
    pub const fn new() -> Self {
        RunMap { runs: [Run { lba: 0, sectors: 0 }; N], n: 0, total: 0 }
    }

    /// Replace the map with `runs` (an iterator that can be walked twice: the
    /// first walk checks them, the second copies). `false`, and the map is as
    /// it was, when they are more than `N` or one is empty.
    pub fn set_iter<I: Iterator<Item = Run> + Clone>(&mut self, runs: I) -> bool {
        if runs.clone().count() > N || runs.clone().any(|r| r.sectors == 0) {
            return false;
        }
        self.n = 0;
        self.total = 0;
        for (slot, r) in self.runs.iter_mut().zip(runs) {
            *slot = r;
            self.n += 1;
            self.total += r.sectors as u64;
        }
        true
    }

    /// Sectors the map covers.
    pub fn sectors(&self) -> u64 {
        self.total
    }

    /// The piece of the area that starts at area sector `sector` and lies in
    /// one run: its medium address and its length, at most `want` sectors.
    /// `None`: `sector` is past the map.
    pub fn piece(&self, sector: u64, want: u32) -> Option<Run> {
        let mut at = 0u64;
        for r in &self.runs[..self.n] {
            if sector < at + r.sectors as u64 {
                let off = sector - at;
                return Some(Run { lba: r.lba + off, sectors: want.min((r.sectors as u64 - off) as u32) });
            }
            at += r.sectors as u64;
        }
        None
    }
}

/// Kconfig `BLK_DISCARD` is not off: a segment brought back has its slot
/// discarded.
const DISCARD: bool = !azos_limits::BLK_DISCARD_OFF;

/// Slots an elastic area (a swap file) grows by, and the least it keeps
/// (Kconfig `MM_SWAP_FILE_GROW_SEGMENTS`).
pub const GROW_SLOTS: usize = azos_limits::MM_SWAP_FILE_GROW_SEGMENTS;
/// Reclaim passes with the area untouched before its free tail is given back
/// (Kconfig `MM_SWAP_FILE_SHRINK_POLLS`).
pub const SHRINK_POLLS: u32 = azos_limits::MM_SWAP_FILE_SHRINK_POLLS as u32;

/// Why a swap step did not happen. Every one leaves the pool consistent: a
/// segment that was being written stays resident, one being read stays out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapError {
    /// The pool said no (see its error).
    Pool(PoolError),
    /// The device failed.
    Io,
    /// The block read back is not what was written (the tag does not match).
    Tamper,
    /// No memory for the staging segment.
    NoMemory,
    /// A real-time hart: swap never runs there.
    RtHart,
    /// Another step of the same kind is in flight (a segment is leaving, or
    /// one is coming back); nothing was touched. Try again when
    /// [`Locked::step_end`] has rung.
    Busy,
}

impl From<PoolError> for SwapError {
    fn from(e: PoolError) -> Self {
        SwapError::Pool(e)
    }
}

/// How a storm ended. The record carries it for the reader of the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// `done` said the pool has room again.
    Done,
    /// `max_segments` were written.
    Max,
    /// No segment is full enough.
    NoSegment,
    /// Every full segment holds a pinned Domain's page.
    Pinned,
    /// Every full segment would take a Domain past its swap quota.
    Quota,
    /// The swap area has no free slot.
    AreaFull,
    /// No swap area.
    NoSwap,
    /// The device failed.
    Io,
    /// No memory for the staging segment.
    NoMemory,
    /// Another storm or a restore's room-making has a segment out; the segments
    /// this storm wrote stand.
    Busy,
}

/// What one eviction storm did: the fields of its single `Rule::SwapOut`
/// record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapRecord {
    /// Segments written out.
    pub segments: u32,
    /// Bytes of live compressed pages in them.
    pub live_bytes: u64,
    /// Bytes of the segments' written length (the rest of each `SEG`-byte
    /// image, zeros, goes to the medium as well: it is one request per segment).
    pub written_bytes: u64,
    pub stop: Stop,
}

impl SwapRecord {
    /// A storm that wrote a segment was swap that paid (`Admit`).
    #[must_use]
    pub const fn paid(&self) -> bool {
        self.segments != 0
    }

    /// Wrote nothing because something said no. Not a refusal: no segment was
    /// full enough, or `done` said there was room before the first (`Refuse`
    /// is for a segment that could not go).
    #[must_use]
    pub const fn refused(&self) -> bool {
        !self.paid() && !matches!(self.stop, Stop::NoSegment | Stop::Done | Stop::Max)
    }

    /// The record's three numbers, in the rule's field order.
    #[must_use]
    pub const fn fields(&self) -> [u64; 3] {
        [self.segments as u64, self.live_bytes, self.written_bytes]
    }
}

/// What the kernel decides about swap, once, at attach.
#[derive(Clone, Copy)]
pub struct Policy {
    /// Is the Domain in this slot pinned (`mem = "locked"`, real-time)? Its
    /// pages are never swapped. Runs under the pool's lock: it takes none.
    pub pinned: fn(owner: usize) -> bool,
    /// Called once at the end of each storm, with the storm's record.
    pub record: fn(&SwapRecord),
    /// Called when a block read back fails its tag: the swap slot. The kernel
    /// logs it; the faulting task fails.
    pub tamper: fn(slot: usize),
}

/// A value (the pool, or the swap state) behind a lock the caller owns.
pub trait Locked<T> {
    /// Run `f` on the value with its lock held. `f` takes no lock and does
    /// no I/O.
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R;

    /// A swap step has ended (its segment is parked or back, or it was given
    /// up): whoever was answered [`SwapError::Busy`] may ask again. Called on
    /// the swap state's `Locked`, with no lock held; the pool's has nothing to
    /// ring.
    fn step_end(&self) {}
}

/// The pool operations a swap loop needs: [`Pool`]'s, by name.
pub trait Parkable {
    fn pick(&mut self, pinned: &dyn Fn(usize) -> bool) -> Result<SwapPick, PoolError>;
    fn stage(&self, pick: &SwapPick, dst: &mut [u8]) -> Result<(), PoolError>;
    fn commit(&mut self, pick: &SwapPick) -> Result<(), PoolError>;
    fn abort(&mut self, pick: &SwapPick);
    fn in_begin(&mut self, sw: &Swapped) -> Result<NonNull<u8>, PoolError>;
    fn in_commit(&mut self, sw: &Swapped, buf: NonNull<u8>) -> Result<(), PoolError>;
    fn in_current(&self, sw: &Swapped) -> bool;
    fn in_abort(&mut self, buf: NonNull<u8>);
    fn slots(&self) -> SwapSlots;
    fn set_cap(&mut self, cap: usize) -> bool;
    fn hold_room(&mut self, held: bool);
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
    > Parkable for Pool<B, E, SLOTS, SEGS, OWNERS, SEG, QUOTA, SW, SWOWNERS, SWQ>
{
    fn pick(&mut self, pinned: &dyn Fn(usize) -> bool) -> Result<SwapPick, PoolError> {
        self.swap_pick(pinned)
    }
    fn stage(&self, pick: &SwapPick, dst: &mut [u8]) -> Result<(), PoolError> {
        self.swap_stage(pick, dst)
    }
    fn commit(&mut self, pick: &SwapPick) -> Result<(), PoolError> {
        self.swap_commit(pick)
    }
    fn abort(&mut self, pick: &SwapPick) {
        self.swap_abort(pick)
    }
    fn in_begin(&mut self, sw: &Swapped) -> Result<NonNull<u8>, PoolError> {
        self.swap_in_begin(sw)
    }
    fn in_commit(&mut self, sw: &Swapped, buf: NonNull<u8>) -> Result<(), PoolError> {
        self.swap_in_commit(sw, buf)
    }
    fn in_current(&self, sw: &Swapped) -> bool {
        self.swap_in_current(sw)
    }
    fn in_abort(&mut self, buf: NonNull<u8>) {
        self.swap_in_abort(buf)
    }
    fn slots(&self) -> SwapSlots {
        self.swap_slots()
    }
    fn set_cap(&mut self, cap: usize) -> bool {
        self.swap_set_cap(cap)
    }
    fn hold_room(&mut self, held: bool) {
        self.swap_hold_room(held)
    }
}

/// A slot's record: the nonce and the tag of the last write of it. `nonce == 0`
/// is a slot never written.
#[derive(Clone, Copy)]
struct Rec {
    nonce: u64,
    tag: [u8; TAG],
}

/// Counters, for reports and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub written: u64,
    pub read: u64,
    pub tampered: u64,
    pub io_errors: u64,
    /// Times an elastic area grew, and shrank.
    pub grown: u64,
    pub shrunk: u64,
}

/// The swap area's keys and slot records. `SW` slots of `SEG` bytes.
///
/// Neither `Copy` nor `Clone`: the keys have one home.
pub struct Swap<'d, const SW: usize, const SEG: usize> {
    dev: &'d dyn SwapDev,
    policy: Policy,
    enc: Aes128,
    mac: [u8; 32],
    nonce: u64,
    recs: [Rec; SW],
    stats: Stats,
    /// The slot a segment just left that is being discarded, or about to be
    /// (see [`swap_in_step`]): a storm that picks it asks again later.
    trimming: Option<usize>,
    /// An elastic area is being resized ([`swap_grow`], [`swap_trim`]): one
    /// at a time, the medium's size is not a thing two steps may change.
    resizing: bool,
    /// Reclaim passes since a segment last moved ([`swap_trim`]).
    idle: u32,
}

impl<const SW: usize, const SEG: usize> Drop for Swap<'_, SW, SEG> {
    fn drop(&mut self) {
        secure_zero(&mut self.mac);
    }
}

/// The sector of the area where slot `slot` of `SEG`-byte segments starts.
const fn sector_of<const SEG: usize>(slot: usize) -> u64 {
    (slot * (SEG / SECTOR)) as u64
}

/// `SW` slots of `SEG` bytes in a partition of `area_sectors` sectors: how
/// many it holds.
pub const fn slots_for(area_sectors: u64, seg: usize, max: usize) -> usize {
    let n = area_sectors / (seg / SECTOR) as u64;
    if n < max as u64 { n as usize } else { max }
}

impl<'d, const SW: usize, const SEG: usize> Swap<'d, SW, SEG> {
    const GEOMETRY: () = assert!(SEG % SECTOR == 0 && SEG != 0, "swap: a segment is whole sectors");

    /// Keys from the boot secret `key` (the caller wipes its copy).
    pub fn new(dev: &'d dyn SwapDev, policy: Policy, key: &[u8; 32]) -> Self {
        let () = Self::GEOMETRY;
        let mut e = hmac_sha256(key, &[b"azos swap enc"]);
        let mac = hmac_sha256(key, &[b"azos swap mac"]);
        let mut k16 = [0u8; 16];
        k16.copy_from_slice(&e[..16]);
        let enc = Aes128::new(&k16);
        secure_zero(&mut k16);
        secure_zero(&mut e);
        Swap {
            dev,
            policy,
            enc,
            mac,
            nonce: 0,
            recs: [Rec { nonce: 0, tag: [0; TAG] }; SW],
            stats: Stats::default(),
            trimming: None,
            resizing: false,
            idle: 0,
        }
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    fn tag_of(&self, slot: usize, nonce: u64, ct: &[u8]) -> [u8; TAG] {
        let d = hmac_sha256(&self.mac, &[&(slot as u32).to_le_bytes(), &nonce.to_le_bytes(), ct]);
        let mut t = [0u8; TAG];
        t.copy_from_slice(&d[..TAG]);
        t
    }

    /// Encrypt the staged image `img` for `slot`, tag it and remember the
    /// nonce and tag. Returns nothing: the record is the slot's.
    fn seal(&mut self, slot: usize, img: &mut [u8]) {
        self.idle = 0;
        self.nonce += 1;
        let nonce = self.nonce;
        if !cfg!(feature = "swap-plain-canary") {
            self.enc.ctr_encrypt(&nonce12(nonce), img);
        }
        self.recs[slot] = Rec { nonce, tag: self.tag_of(slot, nonce, img) };
    }

    /// Verify then decrypt `img`, just read from `slot`, against `rec`: the
    /// slot's record as it was when the read began ([`Swap::rec_of`]). A
    /// mismatch is [`SwapError::Tamper`] here; whether it IS tamper (and not a
    /// slot sealed again under the reader) is the caller's to settle with the
    /// pool, and it counts it.
    fn open(&self, rec: Rec, slot: usize, img: &mut [u8]) -> Result<(), SwapError> {
        let ok = rec.nonce != 0 && ct_eq(&self.tag_of(slot, rec.nonce, img), &rec.tag);
        if !ok && !cfg!(feature = "swap-verify-canary") {
            return Err(SwapError::Tamper);
        }
        if !cfg!(feature = "swap-plain-canary") {
            self.enc.ctr_decrypt(&nonce12(rec.nonce), img);
        }
        Ok(())
    }

    /// The slot's record now: what a reader that is about to read the slot
    /// verifies against.
    fn rec_of(&mut self, slot: usize) -> Rec {
        self.idle = 0;
        self.recs[slot]
    }
}

fn nonce12(n: u64) -> [u8; 12] {
    let mut r = [0u8; 12];
    r[..8].copy_from_slice(&n.to_le_bytes());
    r
}

/// The bytes of a staging segment.
///
/// # Safety
/// `p` is `SEG` bytes of `Backing` memory nobody else touches until freed.
unsafe fn bytes<'a>(p: NonNull<u8>, n: usize) -> &'a mut [u8] {
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts_mut(p.as_ptr(), n) }
}

/// Write one full segment of the pool to the swap area. `Ok(Some((live,
/// written)))`: it is out. `Ok(None)`: its pages left while it was being
/// copied or written, so nothing was parked. `Err(Busy)`: another segment is
/// leaving. No lock is held while the device writes (see the module doc).
/// `grow`: an elastic area with no free slot is grown ([`swap_grow`]) and the
/// pick asked again; a restore making room does not (it runs in a task that
/// may hold the filesystem's locks).
fn swap_out_one<'d, P, L, SL, B, const SW: usize, const SEG: usize>(
    pool: &L,
    swap: &SL,
    bounce: &B,
    grow: bool,
) -> Result<Option<(u64, u64)>, SwapError>
where
    P: Parkable,
    L: Locked<P>,
    SL: Locked<Swap<'d, SW, SEG>>,
    B: Backing,
{
    let r = swap_out_step::<P, L, SL, B, SW, SEG>(pool, swap, bounce, grow);
    ring_unless_busy(swap, &r);
    r
}

fn swap_out_step<'d, P, L, SL, B, const SW: usize, const SEG: usize>(
    pool: &L,
    swap: &SL,
    bounce: &B,
    grow: bool,
) -> Result<Option<(u64, u64)>, SwapError>
where
    P: Parkable,
    L: Locked<P>,
    SL: Locked<Swap<'d, SW, SEG>>,
    B: Backing,
{
    let (pinned, dev) = swap.with(|s| (s.policy.pinned, s.dev));
    // Canary `swap-pinned-canary`: nothing is pinned, whatever the policy says.
    let pick = loop {
        match pool.with(|p| p.pick(&|o| pinned(o) && !cfg!(feature = "swap-pinned-canary"))) {
            Ok(pick) => break pick,
            Err(PoolError::Busy) => return Err(SwapError::Busy),
            // No free slot: an elastic area adds some (every pass raises the
            // slot count, which `SW` bounds, so the loop ends) and the pick
            // is asked again.
            Err(PoolError::Full) if grow && swap_grow::<P, L, SL, SW, SEG>(pool, swap).is_ok() => {}
            Err(e) => return Err(e.into()),
        }
    };
    // A slot being discarded is not written until the discard is over: the
    // medium does not order a discard against a write that follows it. The
    // storm gives the pick up and asks again when the step that holds the slot
    // ends (`step_end`).
    if swap.with(|s| s.trimming == Some(pick.slot)) {
        pool.with(|p| p.abort(&pick));
        // Its own pick made others wait for a moment: they ask again.
        swap.step_end();
        return Err(SwapError::Busy);
    }
    let Some(buf) = bounce.alloc(SEG) else {
        pool.with(|p| p.abort(&pick));
        return Err(SwapError::NoMemory);
    };
    // SAFETY: the staging segment is ours until freed below.
    let img = unsafe { bytes(buf, SEG) };
    let r = (|| {
        match pool.with(|p| p.stage(&pick, img)) {
            Ok(()) => {}
            // Every page left between the pick and the copy: nothing to park,
            // like a commit that finds it gone. The pick is given up here (the
            // segment must not stay `leaving`) and the caller tries the next.
            Err(PoolError::Gone) => {
                pool.with(|p| p.abort(&pick));
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
        swap.with(|s| s.seal(pick.slot, img));
        // The device wait: neither the swap lock nor the pool's is held.
        if dev.write(sector_of::<SEG>(pick.slot), img).is_err() {
            swap.with(|s| s.stats.io_errors += 1);
            return Err(SwapError::Io);
        }
        swap.with(|s| s.stats.written += 1);
        // The copy is on the medium: the segment's frames can go.
        match pool.with(|p| p.commit(&pick)) {
            Ok(()) => Ok(Some((pick.live as u64, pick.fill as u64))),
            Err(PoolError::Gone) => Ok(None),
            Err(e) => Err(e.into()),
        }
    })();
    if r.is_err() {
        pool.with(|p| p.abort(&pick));
    }
    // The staged image held the segment: it does not outlive the call.
    secure_zero(img);
    bounce.free(buf, SEG);
    r
}

/// One eviction storm: write full segments of the pool out until `done` says
/// there is room, `max_segments` are out, or something stops it. `rt_hart`:
/// the caller runs on a real-time hart; swap never does, and nothing is
/// touched. The storm's one `Rule::SwapOut` record is passed to the policy's
/// `record` hook and returned. `Err(Busy)` (nothing written, no record):
/// another segment was leaving when this storm asked for its first.
pub fn swap_out_storm<'d, P, L, SL, B, const SW: usize, const SEG: usize>(
    pool: &L,
    swap: &SL,
    bounce: &B,
    rt_hart: bool,
    max_segments: u32,
    done: &dyn Fn() -> bool,
) -> Result<SwapRecord, SwapError>
where
    P: Parkable,
    L: Locked<P>,
    SL: Locked<Swap<'d, SW, SEG>>,
    B: Backing,
{
    if rt_hart {
        return Err(SwapError::RtHart);
    }
    let mut rec = SwapRecord { segments: 0, live_bytes: 0, written_bytes: 0, stop: Stop::Max };
    while rec.segments < max_segments {
        if done() {
            rec.stop = Stop::Done;
            break;
        }
        match swap_out_one::<P, L, SL, B, SW, SEG>(pool, swap, bounce, true) {
            Ok(Some((live, written))) => {
                rec.segments += 1;
                rec.live_bytes += live;
                rec.written_bytes += written;
            }
            // The pages left while the segment was out of the lock: try the next.
            Ok(None) => {}
            Err(SwapError::Busy) if rec.segments == 0 => return Err(SwapError::Busy),
            Err(e) => {
                rec.stop = match e {
                    SwapError::Busy => Stop::Busy,
                    SwapError::Pool(PoolError::NoSegment) => Stop::NoSegment,
                    SwapError::Pool(PoolError::Pinned) => Stop::Pinned,
                    SwapError::Pool(PoolError::Quota) => Stop::Quota,
                    SwapError::Pool(PoolError::Full) => Stop::AreaFull,
                    SwapError::Pool(PoolError::NoSwap) => Stop::NoSwap,
                    SwapError::NoMemory => Stop::NoMemory,
                    _ => Stop::Io,
                };
                break;
            }
        }
    }
    // A restore that meets the ceiling writes a segment out to make room and
    // does not grow the area (see `swap_out_one`): leave it a free slot.
    if rec.segments != 0 && pool.with(|p| p.slots().free) == 0 {
        let _ = swap_grow::<P, L, SL, SW, SEG>(pool, swap);
    }
    let policy = swap.with(|s| s.policy);
    (policy.record)(&rec);
    Ok(rec)
}

/// Add slots to an elastic area: [`GROW_SLOTS`] of them, fewer when the
/// medium has not room for that many, never past `SW`. The device grows first
/// (every block allocated, waited for, no lock held) and the pool's slot count
/// follows, so no pick names a slot the medium does not have. `Err(AreaFull)`:
/// the area is not elastic, is at `SW`, or the medium has no room for one more
/// slot; `Err(Busy)`: another resize is under way.
pub fn swap_grow<'d, P, L, SL, const SW: usize, const SEG: usize>(pool: &L, swap: &SL) -> Result<usize, SwapError>
where
    P: Parkable,
    L: Locked<P>,
    SL: Locked<Swap<'d, SW, SEG>>,
{
    let dev = swap.with(|s| {
        if !s.dev.resizable() {
            Err(SwapError::Pool(PoolError::Full))
        } else if s.resizing {
            Err(SwapError::Busy)
        } else {
            s.resizing = true;
            Ok(s.dev)
        }
    })?;
    let cap = pool.with(|p| p.slots().cap);
    let mut r = Err(SwapError::Pool(PoolError::Full));
    let mut add = GROW_SLOTS.min(SW.saturating_sub(cap));
    while add != 0 {
        if dev.resize(sector_of::<SEG>(cap + add)).is_ok() && pool.with(|p| p.set_cap(cap + add)) {
            r = Ok(cap + add);
            break;
        }
        add /= 2;
    }
    swap.with(|s| {
        s.resizing = false;
        if r.is_ok() {
            s.stats.grown += 1;
        }
    });
    r
}

/// One reclaim pass over an elastic area that nothing has used for
/// [`SHRINK_POLLS`] passes: give back the free tail, rounded up to
/// [`GROW_SLOTS`] so a tail of less than one chunk stays. `Some(slots)`: the
/// area is now that long. `None`: nothing to give back, the area was used
/// recently, a segment is leaving or being resized, or the slot a discard is
/// still on lies in the tail. Call it with no lock held.
pub fn swap_trim<'d, P, L, SL, const SW: usize, const SEG: usize>(pool: &L, swap: &SL) -> Option<usize>
where
    P: Parkable,
    L: Locked<P>,
    SL: Locked<Swap<'d, SW, SEG>>,
{
    let dev = swap.with(|s| {
        if !s.dev.resizable() || s.resizing {
            return None;
        }
        s.idle = s.idle.saturating_add(1);
        if s.idle < SHRINK_POLLS {
            return None;
        }
        s.resizing = true;
        Some(s.dev)
    })?;
    let r = (|| {
        let books = pool.with(|p| p.slots());
        let keep = books.top.max(1).next_multiple_of(GROW_SLOTS).min(books.cap);
        if books.cap - keep < GROW_SLOTS.min(books.cap) || swap.with(|s| s.trimming.is_some_and(|t| t >= keep)) {
            return None;
        }
        // Slots first: no pick names the tail from here on. A discard that
        // started on a tail slot before the cut is looked for again after it
        // (a parked slot is live until its restore commits, so one that is on
        // a tail slot started before this and shows now).
        if !pool.with(|p| p.set_cap(keep)) {
            return None;
        }
        if swap.with(|s| s.trimming.is_some_and(|t| t >= keep)) {
            pool.with(|p| p.set_cap(books.cap));
            return None;
        }
        // The medium follows. A refusal leaves it longer than the slots, which
        // costs space and nothing else: the next grow sets its length again.
        let _ = dev.resize(sector_of::<SEG>(keep));
        Some(keep)
    })();
    swap.with(|s| {
        s.resizing = false;
        if r.is_some() {
            s.stats.shrunk += 1;
        }
    });
    r
}

/// A step ended: ring whoever was told `Busy`. A step that was itself told
/// `Busy` started nothing, and ringing for it would have the fault that waits
/// on the count see it move and ask again at once: a spin in the kernel that,
/// on the CPU of the task it is waiting for, that task never gets to end.
fn ring_unless_busy<'d, SL, T, const SW: usize, const SEG: usize>(swap: &SL, r: &Result<T, SwapError>)
where
    SL: Locked<Swap<'d, SW, SEG>>,
{
    if !matches!(r, Err(SwapError::Busy)) || cfg!(feature = "swap-busy-rings-canary") {
        swap.step_end();
    }
}

/// Bring the swapped segment `sw` back into the pool: read, verify, decrypt,
/// attach. `Ok` also when its pages left meanwhile (another fault brought it
/// back first, or the segment was freed and its slot used again while the
/// read ran): the caller asks the pool again. When the pool is at its
/// segment ceiling one other segment is written out first to make room.
/// `Err(Busy)`: another segment is coming back (or leaving, at the ceiling);
/// nothing was touched, the caller waits for [`Locked::step_end`] and asks again.
///
/// `Err(Tamper)` / `Err(Io)` leave the segment out and its pages in the
/// index: the task that touched one fails, and so does the next that does,
/// until its owner is gone (a page is never silently replaced by zeros).
pub fn swap_in<'d, P, L, SL, B, const SW: usize, const SEG: usize>(
    pool: &L,
    swap: &SL,
    bounce: &B,
    sw: &Swapped,
) -> Result<(), SwapError>
where
    P: Parkable,
    L: Locked<P>,
    SL: Locked<Swap<'d, SW, SEG>>,
    B: Backing,
{
    let r = swap_in_step::<P, L, SL, B, SW, SEG>(pool, swap, bounce, sw);
    ring_unless_busy(swap, &r);
    r
}

fn swap_in_step<'d, P, L, SL, B, const SW: usize, const SEG: usize>(
    pool: &L,
    swap: &SL,
    bounce: &B,
    sw: &Swapped,
) -> Result<(), SwapError>
where
    P: Parkable,
    L: Locked<P>,
    SL: Locked<Swap<'d, SW, SEG>>,
    B: Backing,
{
    let dev = swap.with(|s| s.dev);
    let mut made_room = false;
    let buf = loop {
        match pool.with(|p| p.in_begin(sw)) {
            Ok(b) => break b,
            Err(PoolError::Gone) => {
                pool.with(|p| p.hold_room(false));
                return Ok(());
            }
            Err(PoolError::Busy) => {
                pool.with(|p| p.hold_room(false));
                return Err(SwapError::Busy);
            }
            Err(PoolError::Full) if !made_room => {
                made_room = true;
                // Under pressure by definition: the segment written out is
                // what frees a frame run for this one.
                pool.with(|p| p.hold_room(true));
                if let Err(e) = swap_out_one::<P, L, SL, B, SW, SEG>(pool, swap, bounce, false) {
                    pool.with(|p| p.hold_room(false));
                    return Err(e);
                }
            }
            Err(e) => {
                pool.with(|p| p.hold_room(false));
                return Err(e.into());
            }
        }
    };
    pool.with(|p| p.hold_room(false));
    // SAFETY: the pool handed the buffer over until commit or abort.
    let img = unsafe { bytes(buf, SEG) };
    // The record the read verifies against, taken while the pool still holds
    // `sw` (a slot it freed and sealed again later is the Gone case below).
    let rec = swap.with(|s| s.rec_of(sw.slot));
    // The device wait: neither the swap lock nor the pool's is held.
    if dev.read(sector_of::<SEG>(sw.slot), img).is_err() {
        swap.with(|s| s.stats.io_errors += 1);
        secure_zero(img);
        pool.with(|p| p.in_abort(buf));
        return Err(SwapError::Io);
    }
    if let Err(e) = swap.with(|s| s.open(rec, sw.slot, img)) {
        secure_zero(img);
        // A block that fails its tag is tamper only if the segment it was read
        // for is still the pool's. If not, its pages left and the slot was
        // written again during the read: there is nothing to attach.
        let still_ours = pool.with(|p| p.in_current(sw));
        pool.with(|p| p.in_abort(buf));
        if !still_ours {
            return Ok(());
        }
        if e == SwapError::Tamper {
            let policy = swap.with(|s| {
                s.stats.tampered += 1;
                s.policy
            });
            (policy.tamper)(sw.slot);
        }
        return Err(e);
    }
    swap.with(|s| s.stats.read += 1);
    // The commit gives the slot back, and a storm may then write it. Its old
    // contents are wanted by nobody, so the medium is told (Kconfig
    // `BLK_DISCARD`), but the slot is reserved first and released after the
    // discard: a discard that landed after that write would erase the new
    // segment, and the medium orders neither. Only a commit that succeeded
    // freed this very slot (a `Gone` slot may already be another segment's),
    // and a failed discard is a hint lost.
    if DISCARD {
        swap.with(|s| s.trimming = Some(sw.slot));
    }
    let committed = pool.with(|p| p.in_commit(sw, buf));
    if DISCARD {
        if committed.is_ok() {
            let _ = dev.discard(sector_of::<SEG>(sw.slot), (SEG / SECTOR) as u32);
        }
        swap.with(|s| s.trimming = None);
    }
    match committed {
        Ok(()) | Err(PoolError::Gone) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

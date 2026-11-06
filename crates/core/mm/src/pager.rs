// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Demand paging for `mmap` through pagers (wave 14, DEMANDPAGE).
//!
//! The kernel owns the address space; a pager owns what is *in* a page. `mmap`
//! records a reserved range (a [`Mapping`] of an object) instead of committing
//! frames, and the first touch of each page faults here: the object's pager
//! supplies the page and the kernel installs it with the mapping's exact
//! permissions. The split is GNU Mach's external-pager idea (the kernel asks,
//! the pager answers), not a port of it.
//!
//! **Anonymous memory is an object.** A private anonymous `mmap` is a mapping
//! of an unnamed object of the space's own ([`crate::anon_obj`]), and a page's
//! state is its slot word ([`crate::slot`]): empty, resident in a frame, in
//! transit, compressed or swapped. **The slot decides**: a fault reads the
//! slot, never the page-table entry ([`slot::resolve`]), and the entry is a
//! cache of the slot, written when a page is installed and cleared when it
//! leaves. [`AnonPager`] supplies an empty slot's page zero-filled and a marked
//! one's from the compressed-page pool (Kconfig `MM_RECLAIM_COMPRESS`,
//! `crate::zpool`).
//!
//! * File pages come from the page cache: a file-backed page is a frame of a
//!   `MemKind::Paged` MemObj (storage L11, `azos_ipc::memobj`), the one page
//!   cache, and what it reads and writes back through is the
//!   [`PageBacking`] callback defined below. The file layer has the
//!   positional read and write it needs (`FileSystem::read_at`/`write_at`, an
//!   `InodeKey` naming the file), and `azos_fs::FsPageBacking` is the
//!   implementation. A file `mmap` is a [`Backing::File`] mapping whose `obj`
//!   and `off` name the cache object and the page in it; the object table is
//!   `crate::memobj`'s, which the fault path calls directly. Two kinds:
//!   **`MAP_SHARED`** maps the cache's own frame (the cache frame IS the mapped
//!   frame: every mapper sees every store, and the page is written back to the
//!   file); **`MAP_PRIVATE`** takes a copy of the cache page at the first touch
//!   into a frame of the task's own, charged and freed like anonymous memory,
//!   so its stores never reach the cache or the file. See [`resolve_file_fault`].
//! * An IPC pager (a ring-3 server answering page requests) is what
//!   [`Supply::Pending`] and [`PageRequest`] are shaped for: a pager that cannot
//!   answer at once returns `Pending`, the faulting task waits, and the
//!   server's reply installs the page through the same mapping re-check
//!   [`resolve_fault`] does. Not implemented; no pager returns `Pending` today,
//!   and a `Pending` answer is treated as unresolved.
//!
//! **The compressed pool** (see [`AnonReclaim`] and the section below). The
//! reclaimer takes a resident page out of an address space, compresses it into
//! the pool and leaves a *page marker* in its object's slot
//! ([`slot::PageMarker`] over [`slot::SlotWords`], the protocol is
//! `crate::zpool`'s; its leaf is cleared): `InTransit` while the store runs,
//! `Compressed` (`Swapped` once its segment is on the swap area) after it. A
//! fault decides from the word it reads, never from a look at the pool: an
//! empty slot is a zero page, `InTransit` is waited for (so a fault that
//! races a store neither zero-fills nor restores a copy that is not there yet),
//! and a marker is restored, the pool's entry being the one whose generation
//! the marker carries. Three rules keep that sound. The pool's entry stays
//! until the restored frame is *installed* (a thread that loses the install
//! race, or a mapping that changed under the fault, leaves it for the retry)
//! and is then dropped by generation, the copy the fault restored and no other;
//! whatever ends the address range (`munmap`, `mprotect(PROT_NONE)`, the
//! space's end) clears the markers and drops the entries; and a `fork` gives
//! the child a marker, and a pool entry sharing the parent's blob, for each
//! page the parent has out: it waits for the stores in flight first (a page
//! in transit would be in neither) and holds the parent until the child's
//! mappings are cloned ([`ForkHold`]: no store, no restore meanwhile). The pool's entries are keyed by the space
//! and the page's address, which a private object's single mapper makes
//! unique and the same name as the object and its page index. A key by object
//! would need an object handle that outlives reuse (a generation, as the
//! space's key has) and a per-object duplicate, discard and retag: the shape
//! objects with several mappers need, not these. The pool's lock is a leaf: taken with
//! neither a space's lock nor `RESVS` held, and over the page allocator, never the
//! other way round.
//!
//! **Accounting.** Reserve-time charging, from the page-budget model and owner
//! decision 102 (charge the whole request before taking a frame): `mmap` and
//! `brk` charge every reserved page to
//! the task's quota when it reserves, so a fault never refuses on quota — the
//! same reason a copy-on-write break is "observed, not charged". A page the
//! reclaimer stores gives its charge back (`PageBudget::storm_note_stored`),
//! so a page behind a marker is not charged; the fault that restores it
//! charges it again without refusing it ([`set_restore_hook`],
//! `PageBudget::charge_restore`), and `munmap` of a marked page gives nothing
//! back ([`release_range`]). Overcommit
//! policy: the per-task quota is never overcommitted; physical frames are,
//! within what memory admission allows, so a fault that finds the page
//! allocator empty kills the task, as a COW break does. The intermediate
//! page-table frames a first touch allocates are not in the reservation's
//! charge (a range's tables are built as its pages are touched), so the fault
//! takes each from the Domain whatever the limit says
//! ([`crate::vmm::TableCharge::Promised`]): the charge overshoots by at most
//! one frame per 2 MiB block the reservation touches, plus the upper levels
//! (the next reservation is then refused), and the touch is never refused for
//! a table. The kernel-memory ledger's own ceiling (`kmem_kib`) still applies
//! to a table. The one charge a fault may be refused is a chunk of slot words
//! an anonymous object takes past its inline slots (`crate::anon_obj`): kernel
//! memory the reservation did not count, charged within the limit.
//!
//! **Superpage reservations** (Kconfig `MM_THP_RESV`, `crate::resv`). The first
//! fault in a block-aligned part of an anonymous mapping that one record covers
//! whole, and where nothing is mapped yet, takes a contiguous run; this and
//! the following faults fill 4 KiB pages from it, and the fault that fills the
//! last one replaces the level-0 table with one level-1 leaf. A cut of the
//! mapping (`munmap`, `mprotect`), a fork, the task's exit, or an allocator that
//! ran dry breaks the reservation: the frames not yet handed out go back. The
//! reservation table has its own lock, never held across the page allocator
//! and never with a space's lock held (the promotion is the one place one is held
//! over a page-table swap, and takes no other lock). The task's quota is
//! unaffected: a reservation lies inside a mapping, which was charged whole.
//!
//! **State.** One [`MapSet`] per address space, in the space's object
//! ([`crate::aspace`]), under its IRQ-safe lock held only for lookups and the
//! install itself, never across the 4 KiB zero or a table walk. The space's
//! lock is also its anonymous objects' (each has that one mapper), so a fault
//! takes one lock twice, as before objects. Every install happens under it
//! after re-finding the mapping and its slot, and `munmap` removes the mapping
//! under it before sweeping the committed pages: a commit can never land after
//! the sweep. No path holds two spaces' locks at once.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use azos_arch::ARCH;
use azos_arch_api::{Mmu, PagePerms, PAGE_SIZE};
use azos_common::error::{KResult, KernelError};
use azos_sync::SpinLock;

use crate::addr::{self, PhysAddr};
use crate::aging;
use crate::anon_obj::{self, Spare};
use crate::aspace::{Space, SpaceRef};
pub use crate::mapping::{Backing, MapError, MapSet, Mapping};
use crate::slot::{self, PageMarker, Resolve, SlotWords};
// Core-only, so the object table, the file layer and the host suites link the
// one source (`#[path]`: it is a sibling of this file, not a crate module).
#[path = "page_backing.rs"]
mod page_backing;
pub use page_backing::{fill_page, valid_len, write_back_page, PageBacking, PageIoError, PageKey, PAGE_KEY_LEN};
use crate::resv::{self, Claim, Filled, ResvTable};
use crate::zpool::{self, Fetched, Lookup, Packed, Reclaimee};
use crate::swap;
use crate::memobj::{self, MemObjError, PagedError};
use crate::{pmm, vmm};

/// Kconfig `MM_DEMAND_PAGING`: anonymous `mmap` reserves instead of commits.
pub const DEMAND_PAGING: bool = azos_limits::MM_DEMAND_PAGING;
/// Kconfig `MM_PRECOMMIT_RT`: real-time-class tasks' mappings are committed
/// at map time.
pub const PRECOMMIT_RT: bool = azos_limits::MM_PRECOMMIT_RT;
/// The most bytes one anonymous mapping request (`mmap`) may reserve: 64 MiB,
/// 16,384 pages. A bound on what one call makes the kernel promise, its slot
/// chunks and page tables included, before any frame is taken.
pub const MAX_MAP_BYTES: usize = 64 * 1024 * 1024;
/// Mapping records per address space (Kconfig `MM_REGIONS_PER_SPACE`).
pub const MAPPINGS_PER_SPACE: usize = azos_limits::MM_REGIONS_PER_SPACE as usize;

/// What a pager is asked for: page `page` of object `obj`, which is the page
/// at `va` of the address space whose pool key is `space` (`SpaceRef::key`).
#[derive(Clone, Copy, Debug)]
pub struct PageRequest {
    pub obj: usize,
    pub page: usize,
    pub write: bool,
    pub space: usize,
    pub va: usize,
    /// The page marker the fault found in the slot, if any: the page is in the
    /// pool, and this is the kind and generation of its entry.
    pub stored: Option<(PageMarker, u32)>,
}

/// A pager's answer.
#[derive(Clone, Copy, Debug)]
pub enum Supply {
    /// A frame holding the page's contents, owned by the caller from now on.
    Frame(PhysAddr),
    /// As `Frame`, and the contents are the page's compressed copy in the pool
    /// (the generation names it), which the caller drops with
    /// [`zpool_release`] once the frame is installed (and not before: see the
    /// module doc). The third is the Domain slot the pool entry was charged to:
    /// the Domain the storm that stored the page gave its charge back to, and
    /// so the one the restore charges (see [`set_restore_hook`]).
    Restored(PhysAddr, u32, usize),
    /// The answer comes later (an IPC pager's server has to be asked). No
    /// in-kernel pager returns this.
    Pending,
    /// The page the marker named was restored by another thread of the space
    /// while this one fetched it: there is nothing to install, the fault
    /// looks at the slot again.
    Raced,
}

/// The pager interface. `supply` runs in the faulting task's trap context with
/// no lock held (see [`resolve_fault`]); an in-kernel pager answers at once,
/// a pager that has to wait answers `Pending` instead.
pub trait Pager {
    fn supply(&self, req: &PageRequest) -> KResult<Supply>;
}

fn file_err(e: PagedError) -> KernelError {
    match e {
        PagedError::Io(_) => KernelError::IoError,
        PagedError::Obj(MemObjError::NoMem | MemObjError::Busy) => KernelError::OutOfMemory,
        PagedError::Obj(_) => KernelError::NotMapped,
    }
}

/// Zero-filled anonymous memory.
pub struct AnonPager;

impl Pager for AnonPager {
    #[inline]
    fn supply(&self, req: &PageRequest) -> KResult<Supply> {
        if let Some((kind, gen)) = req.stored {
            // The marker names a copy: it is restored, or the fault says why
            // not. A copy another thread restored first is no zero page.
            return match zpool_restore(req.space, req.va, kind, gen)? {
                Some((f, gen, owner)) => Ok(Supply::Restored(f, gen, owner)),
                None => Ok(Supply::Raced),
            };
        }
        // `alloc_page` zero-fills, and that is the only zero: a task must
        // never see a previous owner's bytes.
        match pmm::alloc_page() {
            // The allocator ran dry: reservations hold frames no page uses
            // yet. Give one back and ask again.
            Err(KernelError::OutOfMemory) if resv::ENABLED && reclaim_reservation() => {
                Ok(Supply::Frame(pmm::alloc_page()?))
            }
            r => Ok(Supply::Frame(r?)),
        }
    }
}

// ── The compressed-page pool ─────────────────────────────────────────────────

/// Segments are page-allocator frames, taken and returned under the pool's
/// lock (so the allocator's lock is below it).
struct PmmBacking;

impl zpool::Backing for PmmBacking {
    fn alloc(&self, bytes: usize) -> Option<NonNull<u8>> {
        // SAFETY: the pool reads a segment only below the bytes it has written.
        let pa = unsafe { pmm::alloc_contiguous_aligned_uninit(bytes / PAGE_SIZE, PAGE_SIZE) }.ok()?;
        NonNull::new(addr::phys_to_virt(pa.as_usize()) as *mut u8)
    }

    fn free(&self, p: NonNull<u8>, bytes: usize) {
        let base = addr::virt_to_phys(p.as_ptr() as usize);
        for i in 0..bytes / PAGE_SIZE {
            let _ = pmm::free_page(PhysAddr::new(base + i * PAGE_SIZE));
        }
    }
}

type KernelPool = zpool::Pool<
    PmmBacking,
    { zpool::ENTRIES },
    { zpool::SLOTS },
    { zpool::SEGMENTS },
    { zpool::OWNERS },
    { zpool::SEGMENT_BYTES },
    { zpool::DEFAULT_QUOTA },
    { zpool::SWAP_SEGMENTS },
    { zpool::SWAP_OWNERS },
    { zpool::SWAP_DEFAULT_QUOTA },
>;

/// The pool. Task context only (faults, the reclaimer, `munmap`, `fork`, exit):
/// the plain lock, which keeps preemption off, is enough. A leaf lock; see the
/// module doc for its place among the others.
static ZPOOL: SpinLock<KernelPool> = SpinLock::new(KernelPool::new(PmmBacking));
/// The boot key and threshold, made on the first store.
static ZCODEC: SpinLock<Option<zpool::Codec>> = SpinLock::new(None);
/// Pages in the pool, for the paths that only have work when it holds some
/// (`munmap`, `fork`, the space's end) to read without the lock: while it is
/// zero, they cost one load.
static ZSTORED: AtomicUsize = AtomicUsize::new(0);
/// Stores in flight, in every space: pages out of their table and not in the
/// pool yet. `munmap` looks for markers to clear while this or the pool is not
/// empty.
static RECLAIMING: AtomicU32 = AtomicU32::new(0);
/// Counts the ends of stores. A fault that finds a page in transit reads it
/// before it reads the slot and sleeps only while it is unchanged, so an end
/// between the two cannot be missed (as `SWAP_STEPS`).
static MARKER_SEQ: AtomicU32 = AtomicU32::new(0);
/// The faults and forks waiting for a store to end.
static MARKER_WAIT: azos_sync::waitqueue::WaitQueue = azos_sync::waitqueue::WaitQueue::new();
/// Names a store: its `InTransit` marker carries it, and only that store's end
/// replaces the marker.
static TICKET: AtomicU32 = AtomicU32::new(1);
azos_common::ro_hook! {
    /// What a fault that restored a marked page does for the accounting, once it
    /// installed the page (see [`set_restore_hook`]).
    static RESTORE_HOOK: fn(usize);
}

/// Install the hook a fault calls after it installed a page it restored from
/// the pool: the kernel charges the page again (`PageBudget::charge_restore`;
/// the reclaimer discharged it when it took the page out) to the Domain slot
/// the hook is given, the one the pool entry was stored for, whichever task
/// (or none: a kernel-side fault) is running. `mm` cannot name the scheduler,
/// so it is a hook, as the page table charge is (`vmm::set_table_hook`). Unset
/// (host tests) it does nothing.
pub fn set_restore_hook(f: fn(usize)) {
    RESTORE_HOOK.set(f);
}

fn restore_hook(owner: usize) {
    if let Some(f) = RESTORE_HOOK.get() {
        f(owner);
    }
}

/// A store ended (or none started): wake the faults and forks that waited.
fn store_ended() {
    MARKER_SEQ.fetch_add(1, Ordering::AcqRel);
    MARKER_WAIT.wake_all();
}

/// Run `f` on the pool, and publish how many pages it holds afterwards.
fn with_pool<R>(f: impl FnOnce(&mut KernelPool) -> R) -> R {
    let mut p = ZPOOL.lock();
    let r = f(&mut p);
    ZSTORED.store(p.len(), Ordering::Relaxed);
    r
}

/// What the compressed pool holds now (all zero when the pool is compiled out
/// or empty). One lock, for the introspection tree's `metrics/memory/zpool`.
pub fn zpool_stats() -> zpool::Stats {
    let empty = zpool::Stats { entries: 0, blobs: 0, segments: 0, swapped: 0, live_bytes: 0, resident_bytes: 0 };
    if !zpool::ENABLED || ZSTORED.load(Ordering::Relaxed) == 0 {
        return empty;
    }
    with_pool(|p| p.stats())
}

// ── Swap (Kconfig `MM_SWAP_BACKEND`) ─────────────────────────────────────────
//
// Full segments of the pool go to the swap partition (`crate::swap`); a fault
// on a page of one brings the segment back first. The keys and slot records
// are behind a sleeping mutex that a step takes only for `seal`, `open` and a
// counter (owner rule F1: no mutex is held across the device wait), always
// before the pool's spinlock and never inside it. Two steps of a kind never
// overlap: the pool answers `Busy` to the second, and a fault waits on
// `SWAP_WAIT` for the first to end.

type KernelSwap = swap::Swap<'static, { zpool::SWAP_SEGMENTS }, { zpool::SEGMENT_BYTES }>;

struct SwapState(Option<KernelSwap>);

// SAFETY: the one member that is not `Send` is the `&'static dyn SwapDev`,
// the kernel's block-queue device: a zero-sized value over the block layer's
// free functions, which any hart may call (they take the queue's own lock).
unsafe impl Send for SwapState {}

static SWAP: azos_sync::kmutex::Mutex<SwapState> = azos_sync::kmutex::Mutex::new(SwapState(None));
/// Swap is attached (set once at boot, after `SWAP` holds the state): the
/// callers ask this and never take the mutex for a swap that is not there.
static SWAP_ON: AtomicBool = AtomicBool::new(false);

/// Is swap attached (its area is on the block medium)?
pub fn swap_on() -> bool {
    SWAP_ON.load(Ordering::Acquire)
}
/// Swap steps that have ended, and the faults that wait for one to.
static SWAP_STEPS: AtomicU32 = AtomicU32::new(0);
static SWAP_WAIT: azos_sync::waitqueue::WaitQueue = azos_sync::waitqueue::WaitQueue::new();

/// The pool behind its spinlock, as `swap.rs` reaches it.
struct PoolLock;

impl swap::Locked<KernelPool> for PoolLock {
    fn with<R>(&self, f: impl FnOnce(&mut KernelPool) -> R) -> R {
        with_pool(f)
    }
}

/// The swap state behind its sleeping mutex, as `swap.rs` reaches it: held for
/// the closure only. A step's end rings the faults that were told `Busy`.
struct SwapLock;

impl swap::Locked<KernelSwap> for SwapLock {
    fn with<R>(&self, f: impl FnOnce(&mut KernelSwap) -> R) -> R {
        let mut st = SWAP.lock();
        f(st.0.as_mut().expect("swap attached before the first step"))
    }

    fn step_end(&self) {
        SWAP_STEPS.fetch_add(1, Ordering::AcqRel);
        SWAP_WAIT.wake_all();
    }
}

/// Turn swap on: the area is `area_sectors` sectors of `dev`, the boot secret
/// `key` makes its keys, `policy` says which Domains are pinned and where a
/// storm's record goes. Call once at boot, before the first task, with the
/// entropy pool seeded. How many segments the area holds (0: swap stays off,
/// also with `MM_SWAP_BACKEND` off).
pub fn swap_attach(dev: &'static dyn swap::SwapDev, area_sectors: u64, key: &[u8; 32], policy: swap::Policy) -> usize {
    if !zpool::SWAP {
        return 0;
    }
    let slots = swap::slots_for(area_sectors, zpool::SEGMENT_BYTES, zpool::SWAP_SEGMENTS);
    let mut st = SWAP.lock();
    if slots == 0 || st.0.is_some() || !with_pool(|p| p.swap_attach(slots)) {
        return 0;
    }
    st.0 = Some(swap::Swap::new(dev, policy, key));
    SWAP_ON.store(true, Ordering::Release);
    slots
}

/// One eviction storm: write full segments of the pool out until `done` says
/// there is room again, `max_segments` are out, or nothing more can go. Its
/// one user is [`swap_segment`], the reclaim pass's third stage; one
/// `Rule::SwapOut` record is written for it (the policy's `record`).
///
/// **Never waits for another swap step**: `Err(Busy)` when a segment is already
/// leaving (another storm, or a restore making room for itself), with the pool
/// untouched. The step's own device wait holds no lock (see the section header),
/// so nothing here can deadlock on the swap mutex either.
fn swap_out(rt_hart: bool, max_segments: u32, done: &dyn Fn() -> bool) -> Result<swap::SwapRecord, swap::SwapError> {
    if rt_hart {
        return Err(swap::SwapError::RtHart);
    }
    if !SWAP_ON.load(Ordering::Acquire) {
        return Err(zpool::Error::NoSwap.into());
    }
    swap::swap_out_storm(&PoolLock, &SwapLock, &PmmBacking, rt_hart, max_segments, done)
}

/// Stage 3 of a reclaim pass: the pool is full, so write one segment to the
/// swap area, and say whether one went (the pass then runs the compression
/// stage again). The pages of the segment that went have their markers turned
/// from `Compressed` to `Swapped`, so their faults go straight to the swap
/// step. Always `false` with swap off or on a real-time hart.
pub fn swap_segment(rt_hart: bool) -> bool {
    if !zpool::SWAP || !swap_out(rt_hart, 1, &|| false).is_ok_and(|r| r.paid()) {
        return false;
    }
    mark_swapped();
    true
}

/// A reclaim pass found no pressure: give an elastic swap area (a swap file,
/// Kconfig `MM_SWAP_BACKEND_FILE`) its free tail back once nothing has moved
/// through it for `MM_SWAP_FILE_SHRINK_POLLS` passes. `true`: the area shrank.
/// Always `false` with swap off, on a partition, or when the area is in use.
/// The one caller is the reclaim task, which holds no lock here.
pub fn swap_trim() -> bool {
    zpool::SWAP && SWAP_ON.load(Ordering::Acquire) && swap::swap_trim(&PoolLock, &SwapLock).is_some()
}

/// Turn the `Compressed` marker of every page whose segment is on swap into a
/// `Swapped` one. Best effort, and only an optimisation of the fault: a
/// marker left `Compressed` still finds its entry parked (the lookup says so)
/// and brings the segment in. The pool is read a handful of entries at a time
/// (its lock is never held across a page-table write), and an entry that
/// moves while the scan is between two reads may be missed.
fn mark_swapped() {
    let mut buf = [zpool::Stored { obj: 0, page: 0, gen: 0 }; 32];
    let mut at = 0;
    loop {
        let (n, next) = with_pool(|p| p.parked_from(at, &mut buf));
        for st in &buf[..n] {
            retag(st.obj as usize, st.page as usize * PAGE_SIZE, PageMarker::Compressed, PageMarker::Swapped, st.gen);
        }
        match next {
            Some(i) => at = i,
            None => return,
        }
    }
}

/// Change the marker of the page at `va` of the space whose pool key is `key`
/// from `from` to `to` (same generation), if it is `from`. `false`: the space
/// or the marker is not there.
fn retag(key: usize, va: usize, from: PageMarker, to: PageMarker, gen: u32) -> bool {
    // SAFETY: a pool entry's container is a space's key (`zkey`).
    let Some((_, sp)) = (unsafe { SpaceRef::of_key(key) }) else { return false };
    anon_slot(&sp, va).is_some_and(|slot| {
        slot.compare_exchange(slot::marker(from, gen), slot::marker(to, gen), Ordering::AcqRel, Ordering::Acquire).is_ok()
    })
}

/// Bring back the segment holding the page `(obj, pg)`, if swap has it. Any
/// failure is the faulting task's: the page is not replaced by zeros. A step
/// of the same kind in flight (`Busy`) is waited for, with no lock held, on
/// the count of steps that have ended: it cannot be missed (the count is read
/// before the attempt, and the sleep tests it).
fn swap_bring_in(obj: u64, pg: u64) -> KResult<()> {
    if !zpool::SWAP {
        return Ok(());
    }
    let Some(sw) = with_pool(|p| p.swapped(obj, pg)) else { return Ok(()) };
    if !SWAP_ON.load(Ordering::Acquire) {
        return Err(KernelError::IoError);
    }
    loop {
        let seen = SWAP_STEPS.load(Ordering::Acquire);
        match swap::swap_in(&PoolLock, &SwapLock, &PmmBacking, &sw) {
            Err(swap::SwapError::Busy) => SWAP_WAIT.wait_if_for(azos_sync::waitstat::Site::PagerSwap, || SWAP_STEPS.load(Ordering::Acquire) == seen),
            r => return r.map_err(|_| KernelError::IoError),
        }
    }
}

/// A page's name in the pool: the container is the address space's key
/// ([`SpaceRef::key`]: a private object has that one mapper), the page its
/// virtual page number.
#[inline]
fn zkey(space: usize, va: usize) -> (u64, u64) {
    (space as u64, (va / PAGE_SIZE) as u64)
}

/// Make the boot key from the entropy pool on first use, and keep it in RAM
/// only. `NoKey` while the pool is unseeded: nothing is stored without it.
fn init_codec() -> Result<(), zpool::Error> {
    if ZCODEC.lock().is_some() {
        return Ok(());
    }
    let mut key = [0u8; 16];
    // The entropy pool's own lock does not keep preemption off (its crate
    // cannot use `azos_sync`), so the caller does.
    let seeded = {
        let _cs = azos_sync::critical_section();
        azos_crypto::entropy::fill(&mut key)
    };
    if seeded {
        let mut slot = ZCODEC.lock();
        // A thread that got here first keeps its key; this one's is dropped.
        if slot.is_none() {
            *slot = Some(zpool::Codec::new(&key, zpool::MAX_RATIO_PCT));
        }
    }
    azos_crypto::ct::secure_zero(&mut key);
    if seeded { Ok(()) } else { Err(zpool::Error::NoKey) }
}

/// Run `f` on the codec, where it lives: the key is never copied out of the
/// lock (a copy on a stack would outlive the call, unzeroed), so the
/// compression and the cipher run under it and the codec's users take turns.
/// A leaf lock: `f` takes none.
fn with_codec<R>(f: impl FnOnce(&zpool::Codec) -> R) -> Result<R, zpool::Error> {
    init_codec()?;
    ZCODEC.lock().as_ref().map(f).ok_or(zpool::Error::NoKey)
}

/// The bytes of a frame the caller owns (or, for the store, that no thread can
/// write: the reclaimer has unmapped it).
///
/// # Safety
/// `f` is a page-allocator frame no one else accesses for `'a`.
unsafe fn frame_bytes<'a>(f: PhysAddr) -> &'a mut [u8] {
    // SAFETY: the direct map covers every frame; exclusivity is the caller's.
    unsafe { core::slice::from_raw_parts_mut(addr::phys_to_virt(f.as_usize()) as *mut u8, PAGE_SIZE) }
}

/// Compress the resident page at `va` of the address space whose key is
/// `space` (`frame`) into the pool, charged to Domain slot `owner`. The caller is the
/// reclaimer ([`AnonReclaim`]). **It must keep the page out of every thread's
/// reach until this returns**: its slot holds an `InTransit` marker and the
/// translation is shot down on every hart, so no thread can write the frame
/// and no fault can install a zero page for the address meanwhile (it waits,
/// see [`resolve_fault`]). On `Ok` the caller publishes the page's marker,
/// frees the frame and takes the page off the space's committed count (it is
/// reserved, not committed, from now on: the restore counts it again); on
/// `Err` the page stays resident as it was. `Ok((n, gen))`: the bytes the pool
/// holds for it, 0 for a zero or same-filled page, and the generation of its
/// entry, which the marker carries. `Incompressible`, `Quota` and `Full` are
/// the ordinary reasons to leave a page where it is; `Full` ends the storm and
/// calls for the pass's swap stage ([`swap_segment`]), this store does not
/// write to swap itself.
///
/// The page's address range must be mapped (`reserve`d, not `release_range`d):
/// a stored page of an unreserved range could never be asked for, and would
/// stay until the space ends.
fn zpool_store(owner: usize, space: usize, va: usize, frame: PhysAddr) -> Result<(usize, u32), zpool::Error> {
    if !zpool::ENABLED {
        return Err(zpool::Error::Disabled);
    }
    init_codec()?;
    // SAFETY: the staging page is never read before `pack` writes what is read.
    let scratch = unsafe { pmm::alloc_page_uninit() }.map_err(|_| zpool::Error::Full)?;
    // SAFETY: the staging frame is ours; the source frame is out of the table
    // and shot down (above).
    let (page, buf) = unsafe { (&*frame_bytes(frame), frame_bytes(scratch)) };
    let (obj, pg) = zkey(space, va);
    let r = with_codec(|c| c.pack(page, buf)).and_then(|r| r).and_then(|packed| match packed {
        Packed::Skip => Err(zpool::Error::Incompressible),
        Packed::Fill(w) => with_pool(|p| p.insert_fill(owner, obj, pg, w).map(|()| (0, p.gen_of(obj, pg)))),
        Packed::Blob { len, nonce } => {
            with_pool(|p| p.insert_blob(owner, obj, pg, nonce, &buf[..len]).map(|()| (len + 8, p.gen_of(obj, pg))))
        }
    });
    // The staging page holds ciphertext, except after a skip: the coder wrote
    // part of the plaintext stream before giving up.
    if r == Err(zpool::Error::Incompressible) {
        pmm::zero_frame(scratch);
    }
    let _ = pmm::free_page(scratch);
    // The entry was just inserted under the lock, by the only thread that
    // stores this key: it is there.
    r.and_then(|(n, gen)| gen.map(|g| (n, g)).ok_or(zpool::Error::Corrupt))
}

/// The restore half of a fault: a fresh frame holding the page the pool has
/// for `va`, in the entry of generation `gen` that the page's marker (`kind`)
/// names, or `None` when the entry is gone (another thread of the space
/// restored the page first and removed it). The entry stays in the pool; the
/// caller removes it with [`zpool_release`], given the generation returned
/// with the frame, after it installed the frame. Frames are taken before the
/// pool lock, and the decryption and decompression run after it is dropped.
/// Two frames are taken (the page and a staging page for the stream): when the
/// allocator cannot give both, even after a reservation is broken, the fault
/// fails and the task dies, as for a zero page it cannot get. A page-in cannot
/// reserve its memory first.
fn zpool_restore(space: usize, va: usize, kind: PageMarker, gen: u32) -> KResult<Option<(PhysAddr, u32, usize)>> {
    // The segment that was brought back can be written out again by a storm
    // before this fault fetches its page: ask again (it is hot now, so a few
    // rounds are plenty), never take "gone" for "zero".
    let mut kind = kind;
    for _ in 0..4 {
        match zpool_restore_once(space, va, kind, gen)? {
            Restored::Again => kind = PageMarker::Swapped,
            Restored::Gone => return Ok(None),
            Restored::Page(f, gen, owner) => return Ok(Some((f, gen, owner))),
        }
    }
    Err(KernelError::IoError)
}

enum Restored {
    Gone,
    /// The frame, the entry's generation, and the Domain slot it is charged to.
    Page(PhysAddr, u32, usize),
    /// The page's segment is (or went) out to swap: bring it in and ask again.
    Again,
}

fn zpool_restore_once(space: usize, va: usize, kind: PageMarker, gen: u32) -> KResult<Restored> {
    if !zpool::ENABLED {
        // A marker with no pool behind it: nothing in this build writes one.
        return Err(KernelError::InvalidArg);
    }
    let (obj, pg) = zkey(space, va);
    // A `Swapped` marker says the entry's segment is out: no look at the pool
    // first, straight to the swap step.
    if kind == PageMarker::Swapped {
        swap_bring_in(obj, pg)?;
    }
    let alloc = || match unsafe { pmm::alloc_page_uninit() } {
        // The allocator ran dry: reservations hold frames no page uses yet.
        Err(KernelError::OutOfMemory) if resv::ENABLED && reclaim_reservation() => unsafe { pmm::alloc_page_uninit() },
        r => r,
    };
    // SAFETY (both): every byte of the frame is written below before anything
    // reads it, and on any failure the frame is freed unseen.
    let dst = alloc()?;
    let scratch = match alloc() {
        Ok(f) => f,
        Err(e) => {
            let _ = pmm::free_page(dst);
            return Err(e);
        }
    };
    // SAFETY: both frames are ours alone until freed or returned.
    let (page, buf) = unsafe { (frame_bytes(dst), frame_bytes(scratch)) };
    let restored = match with_pool(|p| p.fetch_named(obj, pg, gen, buf)) {
        Lookup::Page(Fetched::Fill(w), g, o) => {
            zpool::fill_page(w, page);
            Ok(Some((g, o)))
        }
        Lookup::Page(Fetched::Blob { len, nonce }, g, o) => {
            let r = with_codec(|c| c.unpack(nonce, len, buf, page)).and_then(|r| r);
            if cfg!(feature = "restore-flip-canary") {
                page[0] ^= 1;
            }
            // The decrypted stream is the page in another form.
            pmm::zero_frame(scratch);
            r.map(|()| Some((g, o)))
        }
        // Its segment is out in swap (a storm took it since the marker was
        // written, or since the segment was brought back), or the entry is
        // gone (the thread that installed it removed it): `None`, and the
        // pool says which below.
        Lookup::Parked | Lookup::Gone => Ok(None),
        Lookup::Wrong => Err(zpool::Error::Corrupt),
    };
    let _ = pmm::free_page(scratch);
    match restored {
        Ok(Some((g, o))) => Ok(Restored::Page(dst, g, o as usize)),
        Ok(None) => {
            let _ = pmm::free_page(dst);
            Ok(if zpool::SWAP && with_pool(|p| p.swapped(obj, pg)).is_some() { Restored::Again } else { Restored::Gone })
        }
        Err(_) => {
            // A pool entry that does not decode, or is not the one the marker
            // names: the page is lost, and the task that touched it dies as it
            // does for any unresolved fault.
            let _ = pmm::free_page(dst);
            Err(KernelError::InvalidArg)
        }
    }
}

/// The restored frame of the page at `va` is installed: drop the compressed
/// copy `gen` named. Keyed to that copy, not to the address: if the reclaimer
/// already stored the installed frame again, the new copy is the page's only
/// one and stays.
fn zpool_release(space: usize, va: usize, gen: u32) {
    let (obj, pg) = zkey(space, va);
    with_pool(|p| p.remove_if(obj, pg, gen));
}

/// The pages of `[s, e)` stop existing (`munmap`, `mprotect(PROT_NONE)`).
fn zpool_discard(space: usize, s: usize, e: usize) {
    if !zpool::ENABLED || ZSTORED.load(Ordering::Relaxed) == 0 {
        return;
    }
    let (obj, lo) = zkey(space, s);
    let (_, hi) = zkey(space, e.saturating_add(PAGE_SIZE - 1));
    with_pool(|p| p.remove_range(obj, lo, hi));
}

/// Every page of the address space whose key is `space` goes (it ends).
fn zpool_forget(space: usize) {
    if !zpool::ENABLED || ZSTORED.load(Ordering::Relaxed) == 0 {
        return;
    }
    with_pool(|p| p.remove_obj(space as u64));
}

/// The child of a fork gets the parent's compressed pages (shared, not copied),
/// each charged to the Domain that holds the parent's. `Err`: the pool had no
/// room or the quota refused, and the child has none of them.
fn zpool_dup(parent: usize, child: usize) -> Result<(), zpool::Error> {
    if !zpool::ENABLED || ZSTORED.load(Ordering::Relaxed) == 0 {
        return Ok(());
    }
    with_pool(|p| p.dup_obj(parent as u64, child as u64)).map(|_| ())
}

// ── The reclaimer's victims ──────────────────────────────────────────────────

/// Is `w` a leaf whose page the reclaimer may take: a valid 4 KiB user leaf,
/// not shared copy-on-write and not one of a contiguous run (one member of a
/// run cannot change on its own).
#[inline]
fn victim_leaf(w: u64) -> bool {
    ARCH.pte_is_valid(w) && ARCH.pte_is_leaf(w, 0) && ARCH.pte_perms(w).user && !ARCH.pte_is_cow(w) && !ARCH.pte_is_contig(w)
}

/// A page of an address space the reclaimer may take: where it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Victim {
    /// The space's page-table root.
    pub space: usize,
    pub va: usize,
}

/// The kernel's page-age table (Kconfig `MM_AGING_CHUNKS`): `age_space` feeds
/// it, [`AnonReclaim`] reads the order of its victims from it.
pub type Ages = aging::AgeTable<{ aging::CHUNKS }>;

/// A store in flight: the page is out of the table, its object's slot holds
/// the `InTransit` marker `ticket` names.
#[derive(Clone, Copy)]
struct Flight {
    space: SpaceRef,
    va: usize,
    frame: PhysAddr,
    /// The leaf word that mapped the page, for a store that does not happen.
    original: u64,
    ticket: u32,
    state: FlightState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlightState {
    /// Not stored yet (or refused): the slot holds the marker.
    Out,
    /// The pool holds it and the slot says so.
    Published,
    /// The range was unmapped meanwhile: the slot is not ours any more, the
    /// pool's copy is dropped, the frame is what is left.
    Gone,
}

/// The pages of one Domain's address spaces, as a reclaim storm's source
/// ([`Reclaimee`]): anonymous mapping pages that are resident, owned by their
/// space alone and plain 4 KiB leaves, oldest generation first
/// ([`aging::AgeTable::pick`]: the Accessed bit through `age_space`, four
/// generations, address order inside one), skipping the ones the compressor
/// gave up on until they are touched.
///
/// Per victim: `next` finds it, `unmap` turns its slot into an `InTransit`
/// marker, clears its leaf and shoots the translation down on every hart,
/// `store` compresses it into the pool and turns the marker into a
/// `Compressed` one, `free` frees the frame (or `keep` puts the slot and the
/// leaf back and, for a page whose range was unmapped meanwhile, frees the
/// frame). A fault on the page meanwhile waits ([`resolve_fault`]).
///
/// What it never offers or takes: a file mapping's page; a page shared with
/// another space (a fork's copy-on-write sharing, counted in the frame's
/// reference count); a page of a block promoted to one superpage or of a
/// contiguous run; any page of a space with a fork walking it. A Domain on a
/// `mem = "locked"` row, and a real-time hart, are the storm's gate
/// (`PageBudget::storm_begin`), not asked here; a real-time task's pages are
/// committed eagerly and have no mapping, so they are not offered either.
pub struct AnonReclaim<'a> {
    spaces: &'a [Option<SpaceRef>],
    owner: usize,
    ages: &'a mut Ages,
    cursor: aging::Cursor,
    flight: Option<Flight>,
}

impl<'a> AnonReclaim<'a> {
    /// A source over `spaces` (the Domain's threads' address spaces, each
    /// once; a `None` is skipped), whose pool entries are charged to Domain
    /// slot `owner`; `ages` is the table `age_space` fed.
    pub fn new(spaces: &'a [Option<SpaceRef>], owner: usize, ages: &'a mut Ages) -> Self {
        AnonReclaim { spaces, owner, ages, cursor: aging::Cursor::default(), flight: None }
    }

    /// The space of the source whose root is `root`.
    fn space_of(&self, root: usize) -> Option<SpaceRef> {
        self.spaces.iter().flatten().copied().find(|r| r.root() == root)
    }

    /// Is the page at `va` of `root` resident and one the reclaimer may take?
    /// The cheap test of the aging walk; `unmap` repeats it under the lock.
    fn candidate(root: usize, va: usize) -> bool {
        let (w, _) = peek(root, va);
        victim_leaf(w) && pmm::desc_of(ARCH.pte_phys(w)).is_some()
    }

    /// Copy out the mappings of `r` (empty when it has none).
    fn mappings_of(r: SpaceRef, out: &mut [Mapping; MAPPINGS_PER_SPACE]) -> usize {
        let Some(sp) = r.lock().filter(|sp| sp.recorded) else { return 0 };
        let rs = sp.set.as_slice();
        out[..rs.len()].copy_from_slice(rs);
        rs.len()
    }

    /// End the flight: the space counts one store fewer, the waiters are woken.
    fn finish(f: Flight) {
        if let Some(mut sp) = f.space.lock().filter(|sp| sp.recorded) {
            sp.reclaiming = sp.reclaiming.saturating_sub(1);
        }
        RECLAIMING.fetch_sub(1, Ordering::AcqRel);
        store_ended();
    }

    /// The slot of the flight's page, under the space's lock (`sp`, which the
    /// caller holds): `None` when no anonymous mapping holds the page any more
    /// (the range was unmapped meanwhile).
    fn slot_of<'t>(sp: &'t Space, f: &Flight) -> Option<&'t AtomicU64> {
        anon_slot(sp, f.va)
    }

    /// The flight's page's leaf entry, under the space's lock: `None` when the
    /// space has no records or no table there.
    fn leaf_of<'t>(sp: &'t Space, f: &Flight) -> Option<&'t AtomicU64> {
        if !sp.recorded {
            return None;
        }
        let p = vmm::walk(f.space.root(), f.va, false).ok()?;
        // SAFETY: an aligned entry of a live table page: the space has
        // records, and `forget` (which precedes the teardown of its tables)
        // takes the lock the caller holds.
        Some(unsafe { &*(p as *const AtomicU64) })
    }
}

/// The slot of the anonymous page at `va` of the space whose records are `sp`
/// (its lock held): `None` outside every anonymous mapping, or while the page
/// has no slot storage (an `Empty` slot).
fn anon_slot(sp: &Space, va: usize) -> Option<&AtomicU64> {
    if !sp.recorded {
        return None;
    }
    let (m, o) = sp.anon_at(va)?;
    o.slot(m.page_index(va))
}

impl Reclaimee for AnonReclaim<'_> {
    type Victim = Victim;

    fn next(&mut self) -> Option<Victim> {
        let spaces = self.spaces;
        let (space, page) = self.ages.pick(&mut self.cursor, |s| spaces.iter().flatten().any(|r| r.root() == s))?;
        Some(Victim { space, va: page * PAGE_SIZE })
    }

    fn unmap(&mut self, v: Victim) -> bool {
        debug_assert!(self.flight.is_none());
        let Some(space) = self.space_of(v.space) else { return false };
        // A reservation's frames are handed out in order and the block is
        // promoted when the last is in; a page that leaves and comes back in
        // another frame must not be the run's. Outside the space's lock (the
        // reservations' lock is never taken under it).
        break_range(v.space, v.va, v.va + PAGE_SIZE);
        let ticket = TICKET.fetch_add(1, Ordering::Relaxed);
        RECLAIMING.fetch_add(1, Ordering::AcqRel);
        let taken = space.lock().and_then(|mut sp| Self::take_out_locked(&mut sp, v, ticket));
        let Some((frame, original)) = taken else {
            RECLAIMING.fetch_sub(1, Ordering::AcqRel);
            return false;
        };
        // No hart may write the frame once this returns; until it does one
        // can still, through a translation it cached.
        crate::vmm::user_shootdown(v.space, v.va, PAGE_SIZE);
        self.flight = Some(Flight { space, va: v.va, frame, original, ticket, state: FlightState::Out });
        true
    }

    fn store(&mut self, _v: Victim) -> Result<u32, zpool::Error> {
        let Some(f) = self.flight.as_mut() else { return Err(zpool::Error::Incompressible) };
        let (bytes, gen) = match zpool_store(self.owner, f.space.key(), f.va, f.frame) {
            Ok(stored) => stored,
            Err(e) => {
                // The coder gave up on the bytes: not offered again until the
                // page is touched (a storm would unmap and shoot it down for
                // the same answer).
                if e == zpool::Error::Incompressible {
                    self.ages.mark_incompressible(f.space.root(), f.va / PAGE_SIZE);
                }
                return Err(e);
            }
        };
        let published = f.space.lock().is_some_and(|mut sp| match Self::slot_of(&sp, f) {
            // The range is still mapped: `release_range` takes the mapping out
            // before it drops the pool's pages of it, so a publish that finds
            // the mapping here is followed by that drop and the slot's clear,
            // and one that does not was preceded by them.
            Some(slot) if zpool::publish(&SlotWords, slot, f.ticket, PageMarker::Compressed, gen) => {
                sp.committed = sp.committed.saturating_sub(1);
                true
            }
            _ => false,
        });
        if published {
            f.state = FlightState::Published;
            return Ok(bytes as u32);
        }
        // The range was unmapped (or the space ended) while the page was
        // being stored: nobody can ask for this copy.
        let (obj, pg) = zkey(f.space.key(), f.va);
        with_pool(|p| p.remove_if(obj, pg, gen));
        f.state = FlightState::Gone;
        // Not stored, not a refusal of the pool: the storm goes on, and
        // `keep` frees the frame. (`Incompressible` is the one answer that
        // does not end a storm.)
        Err(zpool::Error::Incompressible)
    }

    fn free(&mut self, _v: Victim) {
        if let Some(f) = self.flight.take() {
            self.ages.evicted(f.space.root(), f.va / PAGE_SIZE);
            let _ = pmm::free_page(f.frame);
            Self::finish(f);
        }
    }

    fn keep(&mut self, _v: Victim) {
        let Some(f) = self.flight.take() else { return };
        // The slot first, then the leaf, both under the lock: a fault that
        // finds the slot `InTransit` waits, so nothing installed a leaf here,
        // and a slot that is not this store's any more gets no leaf at all.
        let back = f.state == FlightState::Out
            && f.space.lock().is_some_and(|mut sp| {
                let Some(slot) = Self::slot_of(&sp, &f) else { return false };
                let leaf = Self::leaf_of(&sp, &f);
                let put = slot::put_back_page(slot, f.ticket, f.frame.as_usize(), || {
                    leaf.is_some_and(|l| {
                        l.compare_exchange(ARCH.pte_empty(), f.original, Ordering::AcqRel, Ordering::Acquire).is_ok()
                    })
                });
                // An emptied slot is a reserved page that is not committed.
                if put == slot::PutBack::Emptied {
                    sp.committed = sp.committed.saturating_sub(1);
                }
                put == slot::PutBack::Back
            });
        if back {
            ARCH.flush_tlb_page(f.va);
        } else {
            // The page is gone (unmapped meanwhile): the frame was never
            // anyone else's.
            let _ = pmm::free_page(f.frame);
        }
        Self::finish(f);
    }
}

impl AnonReclaim<'_> {
    /// Under the space's lock (`sp`): check the page again, turn its slot into
    /// the `InTransit` marker and clear its leaf. The frame and the leaf word
    /// it held.
    fn take_out_locked(sp: &mut Space, v: Victim, ticket: u32) -> Option<(PhysAddr, u64)> {
        if !sp.recorded {
            return None;
        }
        // A fork walks the space: the pages it passes must stay.
        if sp.forking != 0 || vmm::write_would_enter_kernel_table(v.space, v.va) {
            return None;
        }
        // A leaf of 4 KiB: a promoted block's level-1 word is no page of ours
        // (promotion runs under this lock, so the answer holds).
        if vmm::leaf_level(v.space, v.va) != Some(0) {
            return None;
        }
        let slot = anon_slot(sp, v.va)?;
        let p = vmm::walk(v.space, v.va, false).ok()?;
        // SAFETY: an aligned entry of a live table page (the space has a slot).
        let leaf = unsafe { &*(p as *const AtomicU64) };
        let w = leaf.load(Ordering::Acquire);
        let frame = ARCH.pte_phys(w);
        // Shared with another space (a fork, a copy-on-write sibling), not a
        // frame the allocator tracks, or not the frame the slot names: not ours
        // to free.
        if !victim_leaf(w)
            || slot::frame_of(slot.load(Ordering::Acquire)) != Some(frame)
            || pmm::desc_of(frame).is_none()
            || crate::cow_table::page_is_shared(frame)
        {
            return None;
        }
        zpool::take_out(&SlotWords, slot, ticket).ok()?;
        // The leaf may have changed since the read (the hardware's Accessed or
        // Dirty bit): the page stays.
        if leaf.compare_exchange(w, ARCH.pte_empty(), Ordering::AcqRel, Ordering::Acquire).is_err() {
            slot.store(slot::frame(frame), Ordering::Release);
            return None;
        }
        sp.reclaiming += 1;
        Some((PhysAddr::new(frame), w))
    }
}

/// One aging pass over the anonymous mappings of the space `r`, for Domain
/// slot `owner`: feed `ages` (between `AgeTable::begin` and `end` of the
/// caller) the pages the reclaimer could take now and the ones used since the
/// last pass. Each 64-page window of a mapping is looked at with the space's
/// lock held for the harvest only: `Mmu::harvest_accessed` clears bits in the
/// page tables, and a table freed under it would be a stray write into a frame
/// the allocator has reissued; `forget` takes this lock before the space's
/// tables go, so a space that has records here has them. (The resident test
/// reads without the lock, as `candidate` always did: a stale read is a
/// stale hint, the victim is checked again under the lock by `unmap`.)
///
/// `false`: a chunk did not fit in the table (`MM_AGING_CHUNKS`).
pub fn age_space(r: SpaceRef, owner: usize, ages: &mut Ages) -> bool {
    if aging::CHUNKS == 0 {
        return true;
    }
    let root = r.root();
    let mut maps = [Mapping::anon(0, 0, false, 0, 0); MAPPINGS_PER_SPACE];
    let n = AnonReclaim::mappings_of(r, &mut maps);
    let span = aging::WINDOW * PAGE_SIZE;
    let mut fit = true;
    for reg in maps[..n].iter().filter(|m| m.anon_obj().is_some()) {
        let mut base = reg.start & !(span - 1);
        while base < reg.end {
            // The pages of this window inside the mapping.
            let first = reg.start.max(base).div_ceil(PAGE_SIZE) - base / PAGE_SIZE;
            let last = reg.end.min(base + span).div_ceil(PAGE_SIZE) - base / PAGE_SIZE;
            let scope = bits(first, last);
            let mut resident = 0u64;
            for i in first..last {
                if AnonReclaim::candidate(root, base + i * PAGE_SIZE) {
                    resident |= 1 << i;
                }
            }
            let accessed = if resident == 0 {
                0
            } else {
                // Only the span that holds them: the Accessed bit of a page
                // another mapping owns is not ours to clear.
                let (lo, hi) = (resident.trailing_zeros() as usize, 64 - resident.leading_zeros() as usize);
                let Some(_sp) = r.lock().filter(|sp| sp.recorded) else { return fit };
                ARCH.harvest_accessed(root, base + lo * PAGE_SIZE, hi - lo) << lo
            };
            let vpn = base / PAGE_SIZE;
            match u32::try_from(vpn >> aging::WINDOW_SHIFT) {
                Ok(chunk) => fit &= ages.observe(owner, root, chunk, scope, resident, accessed),
                Err(_) => fit = false,
            }
            base += span;
        }
    }
    fit
}

/// Bits `[first, last)` of a `u64`.
fn bits(first: usize, last: usize) -> u64 {
    let upto = if last >= 64 { u64::MAX } else { (1u64 << last) - 1 };
    upto & !((1u64 << first) - 1)
}

/// Reservation slots: one per task slot up to 64 (a reservation is a block of
/// an address space with a fault in flight in it; the pool runs out long
/// before the task table does, and a fault that finds it full takes a plain
/// page). None when reservations are off.
const RESV_SLOTS: usize = if !resv::ENABLED {
    0
} else if (azos_limits::MAX_TASKS as usize) < 8 {
    8
} else if (azos_limits::MAX_TASKS as usize) > 64 {
    64
} else {
    azos_limits::MAX_TASKS as usize
};

/// The reservations. Taken for lookups and bit flips only, IRQ-safe, never
/// held across the page allocator, a zero, or a space's lock.
static RESVS: SpinLock<ResvTable<RESV_SLOTS>> = SpinLock::new(ResvTable::new());

/// Free blocks the allocator must still have for a new reservation: a
/// reservation is a bet that its whole block gets used, not worth placing
/// while memory is tight.
const RESV_MIN_FREE_BLOCKS: usize = 4;

/// Give the frames of a broken reservation that no thread holds back to the
/// allocator.
fn release_unused(r: resv::Resv) {
    for pa in r.unused() {
        let _ = pmm::free_page(PhysAddr::new(pa));
    }
}

/// Break every reservation of `root` whose block overlaps `[s, e)`.
fn break_range(root: usize, s: usize, e: usize) {
    if !resv::ENABLED {
        return;
    }
    loop {
        let r = RESVS.lock_irqsave().take_overlapping(root, s, e);
        match r {
            Some(r) => release_unused(r),
            None => return,
        }
    }
}

/// Before a fork copies the space `r` (`cow::fork_cow_shared`, then
/// [`fork_clone`]): wait for the stores in flight in it to end and keep the
/// reclaimer from starting more, stop any block of it being promoted, break its
/// reservations, and split the blocks already promoted (the clone shares 4 KiB
/// leaves only). `false`: a block could not be split, the fork is to be
/// refused. Call [`fork_end`] after the clone either way. Free for a space
/// without mappings. Forks of one space may overlap (threads forking at once):
/// the space counts them, and promotion and reclaim resume when the last is over.
///
/// A page in transit is in no frame the clone can share and not yet in the pool
/// the child is given a share of; it is the one state a fork cannot copy, which
/// is why it is waited out and not skipped. The wait sleeps (a fork runs in a
/// syscall, outside every lock of this module).
pub fn fork_begin(r: SpaceRef) -> bool {
    if !reclaim_hold(r) {
        return true;
    }
    if !resv::ENABLED {
        return true;
    }
    // A promotion that passed its checks before the flag went up finished
    // under the space's lock, which the block above took after it.
    break_root(r.root());
    vmm::demote_all_user_megas(r.root())
}

/// The fork of `r` is over (its walk, and the clone of its mappings into the
/// child's, [`fork_clone`]): the parent's pages are copy-on-write, so nothing
/// of it can be promoted until it is filled afresh, and the reclaimer may take
/// pages of it again and its faults restore them.
pub fn fork_end(r: SpaceRef) {
    reclaim_release(r);
}

/// A fork's hold on its parent's space ([`fork_begin`] to [`fork_end`]), from
/// its walk until the child's mappings are cloned: while it lives the
/// reclaimer takes no page of the parent and no restore of the parent installs
/// (one decided before the hold is refused at its install and waits), so the
/// clone of the parent's objects ([`fork_clone`]) finds every page out of
/// memory still out, behind the marker the pool's share names. Dropping it is
/// the fork's end.
pub struct ForkHold(Option<SpaceRef>);

impl ForkHold {
    /// A hold on `r`, whose [`fork_begin`] succeeded (none: a root without
    /// records).
    pub(crate) fn new(r: Option<SpaceRef>) -> Self {
        // Canary `fork-hold-canary`: the hold ends with the walk, so a
        // sibling's restore or store runs while the markers are copied.
        if cfg!(feature = "fork-hold-canary") {
            if let Some(r) = r {
                fork_end(r);
            }
            return ForkHold(None);
        }
        ForkHold(r)
    }
}

impl Drop for ForkHold {
    fn drop(&mut self) {
        if let Some(r) = self.0.take() {
            fork_end(r);
        }
    }
}

/// Wait for the stores in flight in `r` to end and keep the reclaimer from
/// starting more until [`reclaim_release`]. Counted, so holds nest and overlap.
/// `false`: the space has no records (no mappings), so nothing is held.
/// Sleeps while a store is in flight: call it outside every lock of this module.
fn reclaim_hold(r: SpaceRef) -> bool {
    loop {
        let seen = MARKER_SEQ.load(Ordering::Acquire);
        {
            let Some(mut sp) = r.lock().filter(|sp| sp.recorded) else { return false };
            if sp.reclaiming == 0 {
                sp.forking += 1;
                return true;
            }
        }
        MARKER_WAIT.wait_if_for(azos_sync::waitstat::Site::PagerStore, || MARKER_SEQ.load(Ordering::Acquire) == seen);
    }
}

fn reclaim_release(r: SpaceRef) {
    if let Some(mut sp) = r.lock().filter(|sp| sp.recorded) {
        sp.forking = sp.forking.saturating_sub(1);
    }
    // The restores that waited for the hold to end.
    store_ended();
}

/// The reclaimer takes no page out of a space for as long as this lives, and
/// none is in flight when it is made ([`reclaim_pause`]).
pub struct ReclaimPause(SpaceRef);

impl Drop for ReclaimPause {
    fn drop(&mut self) {
        reclaim_release(self.0);
    }
}

/// Hold the reclaimer off `r` while its leaves are rewritten in place
/// (`mprotect`): a leaf the reclaimer swaps for its `InTransit` marker between
/// the rewrite's read and its store would be overwritten with a valid leaf on a
/// frame the store then frees, and a store that fails (`keep`) puts back the
/// leaf it took out, with the permission it had then.
pub fn reclaim_pause(r: SpaceRef) -> Option<ReclaimPause> {
    reclaim_hold(r).then_some(ReclaimPause(r))
}

/// Break every reservation of `root`.
fn break_root(root: usize) {
    if !resv::ENABLED {
        return;
    }
    loop {
        let r = RESVS.lock_irqsave().take_root(root);
        match r {
            Some(r) => release_unused(r),
            None => return,
        }
    }
}

/// Break the richest reservation of any space, for an allocator that ran dry.
/// `false` when there is none.
fn reclaim_reservation() -> bool {
    let r = RESVS.lock_irqsave().take_richest();
    match r {
        Some(r) => {
            release_unused(r);
            true
        }
        None => false,
    }
}

/// Where a faulting page's frame comes from.
#[derive(Clone, Copy)]
enum Source {
    /// A page of its own, already zeroed.
    Plain(PhysAddr),
    /// The frame the slot already names (its leaf is missing): nothing to give back.
    Held(PhysAddr),
    /// Frame `idx` of the block's reservation (`run` is the run's base), zeroed.
    Run { run: usize, idx: usize, frame: PhysAddr },
}

impl Source {
    /// A frame whose install did not happen: back to where it came from.
    fn give_back(self, root: usize, block: usize) {
        match self {
            Source::Plain(f) => {
                let _ = pmm::free_page(f);
            }
            Source::Held(_) => {}
            Source::Run { run, idx, frame } => {
                // The reservation takes it back; if it is gone, the frame is
                // this thread's to free.
                if !RESVS.lock_irqsave().unclaim(root, block, run, idx) {
                    let _ = pmm::free_page(frame);
                }
            }
        }
    }
}

/// Make a reservation for the block at `block` of `root`, if the block is
/// untouched and memory allows. `true` when the table holds one for the block
/// afterwards (also when another thread made it first).
fn make_reservation(root: usize, block: usize) -> bool {
    if pmm::free_pages() < RESV_MIN_FREE_BLOCKS * resv::BLOCK_PAGES || !vmm::user_block_untouched(root, block) {
        return false;
    }
    // SAFETY: no frame of the run reaches a reader before `claim` hands it out
    // and the fault path zeroes it (`resolve_fault`).
    let Ok(run) = (unsafe { pmm::alloc_contiguous_aligned_uninit(resv::BLOCK_PAGES, resv::BLOCK_SIZE) }) else {
        return false;
    };
    let kept = RESVS.lock_irqsave().insert(root, block, run.as_usize()).is_ok();
    if !kept {
        // Full, or another thread's was in first: ours goes back whole.
        for i in 0..resv::BLOCK_PAGES {
            let _ = pmm::free_page(PhysAddr::new(run.as_usize() + i * PAGE_SIZE));
        }
        return RESVS.lock_irqsave().find(root, block).is_some();
    }
    true
}

/// The frame for the fault at `page` from the block's reservation, making the
/// reservation first when the block qualifies. `None`: take a plain page.
fn run_frame(root: usize, page: usize, m: &Mapping) -> Option<Source> {
    let block = resv::block_of(page);
    if m.anon_obj().is_none() || !resv::covers(m.start, m.end, block) {
        return None;
    }
    let idx = resv::index_of(page);
    let mut made = false;
    loop {
        let c = RESVS.lock_irqsave().claim(root, block, idx);
        match c {
            Claim::Frame { run, pa } => {
                let frame = PhysAddr::new(pa);
                // The one zero of this page, outside every lock.
                pmm::zero_frame(frame);
                return Some(Source::Run { run, idx, frame });
            }
            // Another thread holds this page's frame and is about to install
            // it. Not waited for: that thread may be preempted between its
            // claim and its install, and a retry loop here would spin against
            // it on one hart. A plain page races it for the entry; the loser
            // gives its frame back (the reservation takes its own back, and
            // the block then never completes, so it is not promoted).
            Claim::Busy => return None,
            Claim::Installed => return None,
            Claim::None if !made => {
                made = true;
                if !make_reservation(root, block) {
                    return None;
                }
            }
            Claim::None => return None,
        }
    }
}

/// A page of a reservation is installed: when it was the last, swap the
/// block's table for one leaf.
fn after_install(r: SpaceRef, block: usize, run: usize, idx: usize, write: bool) {
    let root = r.root();
    let filled = RESVS.lock_irqsave().installed(root, block, run, idx);
    if !matches!(filled, Filled::Complete(_)) {
        return;
    }
    // Under the space's lock: the mapping is still the one whole record that
    // lets a leaf map the block, so no `munmap` or `mprotect` has cut it, and
    // none can start its sweep before the swap is done. The block's slots keep
    // naming its frames, one each.
    let old = r.lock().filter(|sp| sp.recorded).and_then(|sp| {
        let whole = sp.set.find(block).is_some_and(|m| {
            resv::covers(m.start, m.end, block) && m.write == write && m.anon_obj().is_some()
        }) && sp.forking == 0;
        if whole { vmm::promote_user_block(root, block, run, write) } else { None }
    });
    if let Some((l0, flushed)) = old {
        vmm::promote_finish(root, block, l0, flushed);
    }
}

/// Reserve `[start, end)` in the address space `r` as anonymous memory,
/// readable and writable iff `write`: a mapping of the object of the
/// anonymous mapping next to it with the same permission (below or above it,
/// whose record it then folds into), or of a new object of the space's.
/// Commits nothing. `Full` when the space's records are exhausted (or it is
/// no space any more, or no object can be made): the caller commits the range
/// eagerly instead.
///
/// `Overlap` when the range is not vacant: a mapping holds part of it, or
/// something is mapped or marked there in the page table (or reaching it
/// enters a kernel-shared table): the eager path refuses such a range
/// through `map`'s `AlreadyMapped`, and so must a reservation.
pub fn reserve(r: SpaceRef, start: usize, end: usize, write: bool) -> Result<(), MapError> {
    if start >= end {
        return Err(MapError::Invalid);
    }
    if !vmm::user_range_vacant(r.root(), start, end) {
        return Err(MapError::Overlap);
    }
    // The object's page numbers are addresses (`anon_obj` module doc).
    let (lo, hi) = (start / PAGE_SIZE, end / PAGE_SIZE);
    {
        let mut sp = r.lock().ok_or(MapError::Full)?;
        if sp.recorded {
            if sp.set.covered_pages(start, end) != 0 {
                return Err(MapError::Overlap);
            }
            let below = sp.set.ending_at(start).map(|m| m.start);
            let above = sp.set.find(end).filter(|m| m.start == end).map(|m| m.start);
            let beside = below.into_iter().chain(above).find_map(|at| {
                let (m, o) = sp.anon_at(at)?;
                (m.write == write && o.holds(lo, hi)).then_some(m.anon_obj()).flatten()
            });
            if let Some(h) = beside {
                return sp.set.insert(Mapping::anon(start, end, write, h, lo));
            }
        }
    }
    let h = anon_obj::create(lo, hi - lo).ok_or(MapError::Full)?;
    let res = match r.lock() {
        Some(mut sp) => {
            sp.open();
            let res = sp.set.insert(Mapping::anon(start, end, write, h, lo));
            if res.is_err() && sp.set.is_empty() {
                sp.close();
            }
            res
        }
        None => Err(MapError::Full),
    };
    if res.is_err() {
        // SAFETY: never mapped.
        unsafe { anon_obj::destroy(h, r.root()) };
    }
    res
}

/// Reserve `[start, end)` as one piece of a file mapping: pages `off..` of the
/// page-cache object `obj`, readable and writable iff `write`; `shared` is
/// `MAP_SHARED`. Commits nothing, and charges nothing (the caller charges a
/// private mapping as it does `mmap`'s anonymous ones; a shared one is the
/// cache's memory). The mapping counts as one user of `obj`
/// ([`memobj::memobj_paged_region_add_ref`]) until it ends.
///
/// `Overlap` when the page table is not vacant there or a mapping holds part
/// of the range; `Full` when the space's records are exhausted.
pub fn reserve_file(
    r: SpaceRef,
    start: usize,
    end: usize,
    write: bool,
    shared: bool,
    obj: u32,
    off: usize,
) -> Result<(), MapError> {
    if !vmm::user_range_vacant(r.root(), start, end) {
        return Err(MapError::Overlap);
    }
    {
        let mut sp = r.lock().ok_or(MapError::Full)?;
        sp.open();
        let res = sp.set.insert(Mapping::file(start, end, write, shared, obj, off));
        if res.is_err() {
            if sp.set.is_empty() {
                sp.close();
            }
            return res;
        }
    }
    memobj::memobj_paged_region_add_ref(obj);
    Ok(())
}

/// A file mapping as [`file_regions_in`] reports it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileRegion {
    pub start: usize,
    pub end: usize,
    pub obj: u32,
    /// The page of the object `start` is.
    pub off: usize,
    pub shared: bool,
}

impl FileRegion {
    /// What an array of them starts as.
    pub const NONE: FileRegion = FileRegion { start: 0, end: 0, obj: 0, off: 0, shared: false };
}

/// The file mappings `[s, e)` touches, into `out`; how many. `Invalid` when
/// the range would cut one (a file mapping goes whole or not at all), `Full`
/// when `out` is too short. Nothing changes.
pub fn file_regions_in(r: SpaceRef, s: usize, e: usize, out: &mut [FileRegion]) -> Result<usize, MapError> {
    let Some(sp) = r.lock().filter(|sp| sp.recorded) else { return Ok(0) };
    let set = &sp.set;
    if !set.file_cut_ok(s, e) {
        return Err(MapError::Invalid);
    }
    let mut n = 0;
    for m in set.as_slice() {
        if let Backing::File { obj, shared } = m.backing {
            if m.start < e && s < m.end {
                if n == out.len() {
                    return Err(MapError::Full);
                }
                out[n] = FileRegion { start: m.start, end: m.end, obj, off: m.off, shared };
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Does `[s, e)` touch a file mapping?
pub fn has_file(r: SpaceRef, s: usize, e: usize) -> bool {
    r.lock().is_some_and(|sp| sp.recorded && sp.set.has_file(s, e))
}

/// Resolve a fault in a file mapping (`r`, copied out of the set, of the
/// object `obj`; `page` the faulting page). The same two phases as
/// [`resolve_fault`]: the page is supplied with no lock held, then the mapping
/// is found again and the entry installed under the lock.
///
/// * **Shared**: the cache's frame ([`memobj::memobj_paged_frame_pinned_ref`]) is installed with the
///   mapping's permissions. The mapper's record in the object (made by the
///   syscall layer when it mapped) is what lets the cache drop the page from
///   this space, so after the install the cache is asked again: the same frame
///   means the install is covered, anything else means the page was dropped
///   between the lookup and the install, and the install is undone (the retry
///   faults again).
/// * **Private**: a frame of the task's own, the page's bytes copied in from the
///   cache and zeros after them. It is owned (munmap and the space's end free
///   it) and was charged when the mapping was reserved.
fn resolve_file_fault(space: SpaceRef, page: usize, r: &Mapping, obj: u32, shared: bool) -> KResult<()> {
    let root = space.root();
    let idx = r.page_index(page);
    // The cache's pin on a shared frame, held to the end of the install.
    struct Pin(Option<u32>);
    impl Drop for Pin {
        fn drop(&mut self) {
            if let Some(obj) = self.0 {
                memobj::memobj_paged_install_done_ref(obj);
            }
        }
    }
    let mut _pin = Pin(None);
    let frame = if shared {
        let f = memobj::memobj_paged_frame_pinned_ref(obj, idx, r.write).map(PhysAddr::new).map_err(file_err)?;
        _pin = Pin(Some(obj));
        f
    } else {
        // SAFETY: filled right below, before the entry that exposes it exists.
        let f = unsafe { pmm::alloc_page_uninit()? };
        // SAFETY: a frame this call owns, mapped by the direct map.
        let bytes = unsafe { core::slice::from_raw_parts_mut(addr::phys_to_virt(f.as_usize()) as *mut u8, PAGE_SIZE) };
        match memobj::memobj_paged_read_ref(obj, idx * PAGE_SIZE, bytes).map_err(file_err) {
            Ok(n) => bytes[n.min(PAGE_SIZE)..].fill(0),
            Err(e) => {
                let _ = pmm::free_page(f);
                return Err(e);
            }
        }
        f
    };
    let give_back = |f: PhysAddr| {
        if !shared {
            let _ = pmm::free_page(f);
        }
    };
    // A private mapping was charged whole when it was made; a shared one is the
    // cache's memory and promised nothing.
    let pte_ptr = match walk_installing(root, page, !shared) {
        Ok(Some(Leaf0(p))) => p,
        // A block leaf maps the page: the access retries on it.
        Ok(None) => {
            give_back(frame);
            return Ok(());
        }
        Err(e) => {
            give_back(frame);
            return Err(e);
        }
    };
    let perms = PagePerms { user: true, read: true, write: r.write, exec: false, accessed: true, dirty: r.write, ..PagePerms::USER_RW };
    let new = match ARCH.pte_make_leaf(frame.as_usize(), perms, 0) {
        Ok(w) => w,
        Err(_) => {
            give_back(frame);
            return Err(KernelError::InvalidArg);
        }
    };

    let same = space.lock().filter(|sp| {
        sp.recorded && sp.set.find(page).is_some_and(|now| now.write == r.write && now.backing == r.backing)
    });
    let Some(mut t) = same else {
        // Unmapped or re-protected since the lookup: retry on the new layout.
        give_back(frame);
        return Ok(());
    };
    // SAFETY: `pte_ptr` is an aligned entry of a live table page (the mapping
    // still exists, so `munmap` has not swept it).
    let old = unsafe { core::ptr::read_volatile(pte_ptr) };
    if old != ARCH.pte_empty() {
        drop(t);
        give_back(frame);
        return if ARCH.pte_is_valid(old) { Ok(()) } else { Err(KernelError::AlreadyMapped) };
    }
    // SAFETY: as above.
    let slot = unsafe { &*(pte_ptr as *const AtomicU64) };
    if slot.compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire).is_err() {
        drop(t);
        give_back(frame);
        return Ok(());
    }
    t.committed += 1;
    drop(t);
    ARCH.flush_tlb_page(page);
    if shared && memobj::memobj_page_phys_ref(obj, idx).ok().flatten().map(PhysAddr::new) != Some(frame) {
        // The cache dropped the page before the install could be covered.
        vmm::unmap(root, page);
        if let Some(mut sp) = space.lock().filter(|sp| sp.recorded) {
            sp.committed = sp.committed.saturating_sub(1);
        }
    }
    Ok(())
}

/// Resolve a fault at `va` of the space `r` from its mapping's pager.
///
/// `NotMapped` when no mapping holds `va` (the caller kills the task, as
/// before demand paging). `Ok` when the access should retry: the page is now
/// present (installed here or by another thread first), or the mapping changed
/// under the fault (`mprotect`, `munmap`) and the retry decides afresh.
///
/// Two phases, so interrupts are never off across the pager or the walk: the
/// mapping and the page's slot word are copied out under the lock, the page
/// supplied (4 KiB zeroed) and the tables walked without it, then the lock is
/// retaken, the mapping and the slot found again and the entry installed. The
/// install is the only step under the lock besides the lookups, which is what
/// keeps `release_range`'s promise: no commit lands after a removal, because
/// every install re-finds its mapping. The same shape is what an IPC pager
/// needs: its `Pending` answer is a supply that finishes later.
///
/// **The slot decides.** What an anonymous page is, a zero page, a resident
/// page whose leaf is missing, a page in transit, a page in the pool, is read
/// from its object's slot ([`slot::resolve`]), never from its leaf, before
/// anything is supplied, and the install replaces exactly that slot word and
/// the leaf word read with it: whatever changed either in between (the
/// reclaimer, a fork, another fault) makes the install fail and the fault
/// start again, bounded by [`FAULT_TRIES`]. A page in transit is waited for.
/// The same two steps are why the kernel's own access to a user page
/// ([`vmm::translate_user`]) can rely on this: it does not return before the
/// page is resident or the access is hopeless.
///
/// A wait for a fork's hold on the space is no try: the fault waits as long as
/// the fork runs, so a kernel copy (which does not fault again) does not give
/// up on a page a long fork keeps out.
///
/// `AlreadyMapped` when a leaf maps the page at the first look: the fault was
/// not the pager's (a store to a read-only page, or a sibling's install the
/// caller tells apart, `vmm::handle_user_fault`). A page found mapped after an
/// attempt of this call raced is resolved.
pub fn resolve_fault(r: SpaceRef, va: usize) -> KResult<()> {
    let page = va & !(PAGE_SIZE - 1);
    let mut tries = 0;
    let mut first = true;
    while tries < FAULT_TRIES {
        let step = fault_once(r, page)?;
        if matches!(step, Step::Mapped) && first {
            return Err(KernelError::AlreadyMapped);
        }
        first = false;
        match step {
            Step::Done | Step::Mapped => return Ok(()),
            // Canary `fork-wait-counted-canary`: the wait counts as a try.
            Step::Held if !cfg!(feature = "fork-wait-counted-canary") => {}
            Step::Held | Step::Again => tries += 1,
        }
    }
    // Still racing after every try: the access retries, and faults again.
    Ok(())
}

/// Attempts [`resolve_fault`] makes before it hands the retry back to the
/// access.
const FAULT_TRIES: usize = 8;

/// How one attempt ended.
enum Step {
    /// Resolved, or nothing left to resolve here: the access retries.
    Done,
    /// A leaf maps the page (its frame's, or a promoted block's).
    Mapped,
    /// The slot or the mapping changed under the attempt: look again.
    Again,
    /// A fork holds the space (its clone of the objects runs): waited, look again.
    Held,
}

/// The word that maps `page` under `root` and the level of its entry (0: the
/// page's own 4 KiB leaf slot); empty when its table is not there yet.
fn peek(root: usize, page: usize) -> (u64, usize) {
    match vmm::walk_level(root, page, false, false) {
        // SAFETY: `walk_level` answers an aligned entry of a live table page.
        Ok((p, level)) => (unsafe { core::ptr::read_volatile(p) }, level),
        Err(_) => (ARCH.pte_empty(), 0),
    }
}

/// A page's 4 KiB leaf entry: the only entry a fault installs into.
#[derive(Clone, Copy)]
struct Leaf0(*mut u64);

/// Canary `fault-block-leaf-canary`: a block leaf's word (a promoted block's)
/// is taken for the page's own 4 KiB leaf, by the fault's decision and by its
/// install.
const BLOCK_LEAF_CHECKED: bool = !cfg!(feature = "fault-block-leaf-canary");

/// The walk of a fault that is about to install a page, building the tables it
/// needs. `promised`: the page was charged with its reservation, so a table is
/// taken from the Domain whatever the limit says ([`vmm::TableCharge::Promised`]).
/// `None` when a block leaf maps the page (a promoted block): it is resident,
/// and its word is no 4 KiB leaf to replace.
fn walk_installing(root: usize, page: usize, promised: bool) -> KResult<Option<Leaf0>> {
    // Canary `table-refusable-canary`: the table is refusable like any other,
    // and a touch at the limit dies for it.
    let promised = promised && !cfg!(feature = "table-refusable-canary");
    let (p, level) = vmm::walk_level(root, page, true, promised)?;
    Ok((level == 0 || !BLOCK_LEAF_CHECKED).then_some(Leaf0(p)))
}

fn fault_once(space: SpaceRef, page: usize) -> KResult<Step> {
    let root = space.root();
    // The store counter first, then the slot: a store that ends between the
    // two moves the counter, and the wait below does not sleep.
    let seq = MARKER_SEQ.load(Ordering::Acquire);
    let (m, word, missing, forking) = {
        let sp = space.lock().filter(|sp| sp.recorded).ok_or(KernelError::NotMapped)?;
        match sp.anon_at(page) {
            Some((m, o)) => {
                let (word, missing) = o.look(m.page_index(page));
                (*m, word, missing, sp.forking != 0)
            }
            None => (*sp.set.find(page).ok_or(KernelError::NotMapped)?, slot::EMPTY, 0, false),
        }
    };
    // Mappings are made below the shm window and above the null guard, but the
    // walk below allocates tables: never into a table the kernel shares.
    if vmm::write_would_enter_kernel_table(root, page) {
        return Err(KernelError::InvalidArg);
    }
    let (seen, level) = peek(root, page);
    let h = match m.backing {
        Backing::File { .. } if ARCH.pte_is_valid(seen) => return Ok(Step::Mapped),
        Backing::File { obj, shared } => {
            resolve_file_fault(space, page, &m, obj, shared)?;
            return Ok(Step::Done);
        }
        Backing::Anon { obj } => obj,
    };
    let idx = m.page_index(page);
    // A block leaf maps the page (a promoted block): it is resident, and the
    // access retries on it.
    if level != 0 && ARCH.pte_is_valid(seen) && BLOCK_LEAF_CHECKED {
        return Ok(Step::Mapped);
    }
    // A word that is neither empty nor a leaf (a run break's parked entry)
    // is not the pager's to replace.
    if seen != ARCH.pte_empty() && !ARCH.pte_is_valid(seen) {
        return Err(KernelError::AlreadyMapped);
    }
    let leaf = ARCH.pte_is_valid(seen).then(|| ARCH.pte_phys(seen));
    let res = slot::resolve(word, leaf).ok_or(KernelError::InvalidArg)?;
    let stored = match res {
        Resolve::Present => return Ok(Step::Mapped),
        // A leaf the slot does not name is never replaced
        // (`slot::Resolve::Foreign`), and it is not the pager's: at the first
        // look the caller judges it by the access (a refusing leaf kills, as
        // for any mapped page), after a raced attempt the access retries.
        // Canary `fault-foreign-retry-canary`: it is looked at again, and
        // a refusing leaf faults for ever.
        Resolve::Foreign if cfg!(feature = "fault-foreign-retry-canary") => return Ok(Step::Again),
        Resolve::Foreign => return Ok(Step::Mapped),
        Resolve::Wait => {
            MARKER_WAIT.wait_if_for(azos_sync::waitstat::Site::PagerStore, || MARKER_SEQ.load(Ordering::Acquire) == seq);
            return Ok(Step::Again);
        }
        // A fork is copying the space's markers into its child: the page
        // stays out until it is done ([`ForkHold`]), and the fork's end wakes
        // the wait.
        Resolve::Restore(..) if forking => {
            MARKER_WAIT.wait_if_for(azos_sync::waitstat::Site::PagerStore, || MARKER_SEQ.load(Ordering::Acquire) == seq);
            return Ok(Step::Held);
        }
        Resolve::Restore(kind, gen) => Some((kind, gen)),
        Resolve::Supply | Resolve::Install(_) => None,
    };
    let block = resv::block_of(page);
    let mut restored = None;
    // A page the pool holds is not a reservation's to zero.
    let run = if resv::ENABLED && res == Resolve::Supply { run_frame(root, page, &m) } else { None };
    let src = match (res, run) {
        (Resolve::Install(f), _) => Source::Held(PhysAddr::new(f)),
        (_, Some(s)) => s,
        _ => {
            let req = PageRequest { obj: h, page: idx, write: m.write, space: space.key(), va: page, stored };
            match AnonPager.supply(&req)? {
                Supply::Frame(f) => Source::Plain(f),
                Supply::Restored(f, gen, owner) => {
                    restored = Some((gen, owner));
                    Source::Plain(f)
                }
                // Another thread restored the page first, and (the entry
                // being gone) the slot says what it is now.
                Supply::Raced => {
                    let same = space
                        .lock()
                        .is_some_and(|sp| anon_slot(&sp, page).is_some_and(|s| s.load(Ordering::Acquire) == word));
                    // The slot still names a page the pool no longer holds:
                    // it is lost, and the task that touched it dies.
                    return if same { Err(KernelError::InvalidArg) } else { Ok(Step::Again) };
                }
                Supply::Pending => return Err(KernelError::NotMapped),
            }
        }
    };
    let (Source::Plain(frame) | Source::Held(frame) | Source::Run { frame, .. }) = src;
    // The slot's storage, if it has none yet: taken now, never under the lock.
    let mut spare = match missing {
        0 => None,
        n => match Spare::take(root, n) {
            Ok(s) => Some(s),
            // `QuotaRefused`: the Domain is at its limit, which the trap tells
            // from a bad pointer (`vmm::UserFault::QuotaRefused`).
            Err(e) => {
                src.give_back(root, block);
                return Err(e);
            }
        },
    };
    let pte_ptr = match walk_installing(root, page, true) {
        Ok(Some(p)) => p,
        Ok(None) => {
            src.give_back(root, block);
            return Ok(Step::Done);
        }
        Err(e) => {
            src.give_back(root, block);
            return Err(e);
        }
    };
    let perms = PagePerms {
        user: true,
        read: true,
        write: m.write,
        exec: false,
        accessed: true,
        dirty: m.write,
        ..PagePerms::USER_RW
    };
    let new = match ARCH.pte_make_leaf(frame.as_usize(), perms, 0) {
        Ok(w) => w,
        Err(_) => {
            src.give_back(root, block);
            return Err(KernelError::InvalidArg);
        }
    };

    #[cfg(not(target_os = "none"))]
    {
        let h = INSTALL_HOOK.lock().take();
        if let Some(h) = h {
            h();
        }
    }
    let installed = space.lock().filter(|sp| sp.recorded).is_some_and(|mut t| {
        // A fork began holding the space while this restore supplied: its
        // clone must see the page out. The next attempt waits
        // for the fork's end. Canary `fork-install-recheck-canary`.
        if stored.is_some() && t.forking != 0 && !cfg!(feature = "fork-install-recheck-canary") {
            return false;
        }
        // Unmapped or re-protected since the lookup: look again and let the
        // new layout answer (a removed mapping then kills, as any hole does).
        // Canary `mm-install-after-release-canary`: the mapping of the lookup
        // is believed, so a page `munmap` released is installed after it.
        let found = match t.anon_at(page) {
            // SAFETY (canary only): the object of the lookup's mapping, which
            // the row keeps alive through the pages it still maps.
            None if cfg!(feature = "mm-install-after-release-canary") => Some((&m, unsafe { anon_obj::get(h) })),
            f => f,
        };
        let Some((n, o)) = found else { return false };
        if n.write != m.write || n.backing != m.backing || n.page_index(page) != idx {
            return false;
        }
        // A slot with no storage now (its chunk freed by a `munmap` since
        // the first look) is looked at again.
        let slot = match spare.as_mut() {
            None => o.slot(idx),
            Some(sp) => o.slot_fill(idx, sp),
        };
        let Some(slot) = slot else { return false };
        // The entry the walk found must still be the page's: a promotion
        // (under this lock) takes the level-0 table away, and a split after it
        // may put a new table at the same level, so the level alone does not
        // tell. Walked again, without allocating, under the lock that
        // serialises promotion. Canary `fault-entry-rewalk-canary`.
        if !cfg!(feature = "fault-entry-rewalk-canary")
            && !vmm::walk_level(root, page, false, false).is_ok_and(|(p, level)| p == pte_ptr.0 && level == 0)
        {
            return false;
        }
        // SAFETY: `pte_ptr` is the page's level-0 entry in its live table:
        // found again just now, under the lock every promotion holds.
        let leaf_word = unsafe { &*(pte_ptr.0 as *const AtomicU64) };
        // Both words the decision was made on, or nothing: installs are
        // serialised by the space's lock, but the leaf is shared with walkers
        // that do not take it (a fork, `munmap`'s sweep).
        if slot.load(Ordering::Relaxed) != word
            || leaf_word.compare_exchange(seen, new, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            return false;
        }
        slot.store(slot::frame(frame.as_usize()), Ordering::Relaxed);
        if !matches!(src, Source::Held(_)) {
            t.committed += 1;
        }
        true
    });
    drop(spare);
    if !installed {
        src.give_back(root, block);
        return Ok(Step::Again);
    }
    ARCH.flush_tlb_page(page);
    if let Some((gen, owner)) = restored {
        zpool_release(space.key(), page, gen);
        restore_hook(owner);
    }
    if let Source::Run { run, idx, .. } = src {
        after_install(space, block, run, idx, m.write);
    }
    Ok(Step::Done)
}

/// Is `va` reserved and not committed, and would its page be writable? For
/// the kernel's "may I copy into this user range" checks: a reserved page is
/// committed by the copy itself (`vmm::translate_user`).
pub fn reserved_writable(r: SpaceRef, va: usize) -> Option<bool> {
    let sp = r.lock().filter(|sp| sp.recorded)?;
    sp.set.find(va & !(PAGE_SIZE - 1)).map(|m| m.write)
}

/// Does a mapping hold `va`?
pub fn contains(r: SpaceRef, va: usize) -> bool {
    reserved_writable(r, va).is_some()
}

/// Most sub-ranges one removal can produce: one per record.
const MAX_PIECES: usize = MAPPINGS_PER_SPACE;
/// Most slot chunks one removal frees: those of the largest `munmap`
/// (`MAX_MAP_BYTES`) and one at each end; any past that stay with
/// their object until it ends.
const CHUNKS_FREED: usize = MAX_MAP_BYTES / (anon_obj::PER_CHUNK * PAGE_SIZE) + 2;

/// Take `[s, e)` out of every mapping of the space `r`, for `munmap` and
/// `mprotect(PROT_NONE)`. Returns the reserved pages in the range that were
/// never committed: the caller discharges those itself, and its sweep frees
/// (and discharges) the committed ones. Call it **before** the sweep: once
/// it returns, no fault can commit a page in the range.
///
/// The slots of the anonymous pieces are emptied (their frames are the
/// sweep's to free, their pool pages go here), and an object no mapping names
/// any more goes with them.
///
/// `Full` (nothing changed) when cutting a mapping in two needs a record the
/// space does not have.
pub fn release_range(r: SpaceRef, s: usize, e: usize) -> Result<usize, MapError> {
    let root = r.root();
    // `(start, end, pays, backing, first object page)` of each piece.
    let mut pieces = [(0usize, 0usize, false, Backing::Anon { obj: 0 }, 0usize); MAX_PIECES];
    let mut np = 0;
    // The objects no mapping names after the cut.
    let mut dead = [0usize; MAX_PIECES];
    let mut nd = 0;
    {
        let Some(mut sp) = r.lock().filter(|sp| sp.recorded) else { return Ok(0) };
        // A file mapping goes whole or not at all, or the page cache's count of
        // mappings would be wrong (`MapSet::file_cut_ok`).
        if !sp.set.file_cut_ok(s, e) {
            return Err(MapError::Invalid);
        }
        sp.set.for_each_overlap(s, e, |a, b, m| {
            pieces[np] = (a, b, m.charged(), m.backing, m.page_index(a));
            np += 1;
        });
        if np == 0 {
            return Ok(0);
        }
        sp.set.remove_range(s, e)?;
        for &(_, _, _, backing, _) in &pieces[..np] {
            if let Backing::Anon { obj } = backing {
                if sp.set.naming(obj) == 0 && !dead[..nd].contains(&obj) {
                    dead[nd] = obj;
                    nd += 1;
                }
            }
        }
    }
    // The cut breaks every reservation it touches (no new frame comes out of
    // one for the removed part: the fault path needs the block whole).
    break_range(root, s, e);
    // Outside the lock: nothing can commit in these pieces any more, and a
    // piece is up to 16,384 pages (64 MiB) — not with interrupts off.
    // `paid`: reserved pages of the pieces the task paid for; the committed
    // ones of them are the sweep's to discharge, the rest are returned.
    let mut paid = 0usize;
    let mut committed = 0usize;
    let mut paid_committed = 0usize;
    for &(a, b, pays, backing, off) in &pieces[..np] {
        let n = (b - a) / PAGE_SIZE;
        let (here, out) = match backing {
            Backing::Anon { obj } => {
                // The pages of the pool in the piece are gone with it.
                zpool_discard(r.key(), a, b);
                // SAFETY: the object is destroyed below, after this; no
                // mapping names these pages any more, so nothing else reaches
                // their slots (`anon_obj` module doc).
                let o = unsafe { anon_obj::get(obj) };
                let (mut here, mut out) = (0usize, 0usize);
                o.for_each(off, off + n, |_, slot| match slot::decode(slot.swap(slot::EMPTY, Ordering::AcqRel)) {
                    Some(slot::Slot::Frame(_)) => here += 1,
                    // In transit: it was resident and has not given its charge
                    // back, and its store, which fails now, never will; it is a
                    // committed page of the space that the sweep does not see.
                    Some(slot::Slot::Marker(PageMarker::InTransit, _)) => committed += 1,
                    // In the pool (or swap): it gave its charge back when the
                    // reclaimer took it out, so nothing to return for it.
                    Some(slot::Slot::Marker(..)) => out += 1,
                    _ => {}
                });
                (here, out)
            }
            Backing::File { .. } => {
                let mut here = 0usize;
                let mut va = a;
                while va < b {
                    here += matches!(vmm::user_page(root, va), vmm::UserPage::Leaf { .. }) as usize;
                    va += PAGE_SIZE;
                }
                (here, 0)
            }
        };
        committed += here;
        if pays {
            paid += n;
            paid_committed += here + out;
        }
    }
    // The slot chunks of the pieces no mapping of their object covers any
    // more, unhooked under the lock and freed after it.
    let mut chunks = [0usize; CHUNKS_FREED];
    let mut nc = 0;
    if let Some(mut sp) = r.lock().filter(|sp| sp.recorded) {
        sp.committed = sp.committed.saturating_sub(committed);
        if !cfg!(feature = "slot-chunk-kept-canary") {
            for &(a, b, _, backing, _) in &pieces[..np] {
                let Backing::Anon { obj } = backing else { continue };
                if dead[..nd].contains(&obj) {
                    continue;
                }
                let span = anon_obj::PER_CHUNK * PAGE_SIZE;
                let mut c = a / span;
                while c * span < b && nc < CHUNKS_FREED {
                    let (lo, hi) = (c * span, (c + 1) * span);
                    let covered = sp.set.as_slice().iter().any(|m| m.anon_obj() == Some(obj) && m.start < hi && lo < m.end);
                    if !covered {
                        // SAFETY: a mapping of the set named it before the cut
                        // and it is not dead: another mapping still names it.
                        if let Some(p) = unsafe { anon_obj::get(obj) }.take_chunk(c) {
                            chunks[nc] = p;
                            nc += 1;
                        }
                    }
                    c += 1;
                }
            }
        }
        if sp.set.is_empty() {
            sp.close();
        }
    }
    for &p in &chunks[..nc] {
        anon_obj::free_chunk(root, p);
    }
    for &obj in &dead[..nd] {
        // SAFETY: no mapping names it (above).
        unsafe { anon_obj::destroy(obj, root) };
    }
    // The file mappings are gone: their users in the page cache with them.
    for &(_, _, _, backing, _) in &pieces[..np] {
        if let Backing::File { obj, .. } = backing {
            memobj::memobj_paged_region_drop_ref(obj);
        }
    }
    Ok(paid - paid_committed)
}

/// Set the write permission of every mapped page in `[s, e)` (`mprotect` to
/// `PROT_READ` or read-write). Pages already committed are the caller's to
/// re-protect (`vmm::protect_user_range`). `Full`, nothing changed, when a
/// cut needs records the space does not have.
pub fn protect_range(r: SpaceRef, s: usize, e: usize, write: bool) -> Result<(), MapError> {
    let res = match r.lock().filter(|sp| sp.recorded) {
        // A file mapping keeps the permission it was mapped with: a shared
        // one's dirty record in the page cache is made from it.
        Some(sp) if sp.set.has_file(s, e) => Err(MapError::Invalid),
        Some(mut sp) => sp.set.protect_range(s, e, write),
        None => Ok(()),
    };
    // New permissions on part of a block, or the whole of one: the frames not
    // handed out yet go back, and what is installed is the sweep's.
    if res.is_ok() {
        break_range(r.root(), s, e);
    }
    res
}

/// A copy-on-write break of the page at `va` under `root` swaps its leaf
/// (`leaf`) from `old` to `new`, a leaf on another frame: the leaf and, for a
/// page of an anonymous mapping of the space whose root it is (the running
/// task's, or another task's a kernel write reaches), its slot move together,
/// under the space's lock. `false`: the leaf is not `old` any more, nothing
/// changed.
///
/// Canary `cow-slot-canary`: the slot stays on the old frame.
pub(crate) fn cow_swap(root: usize, va: usize, leaf: &AtomicU64, old: u64, new: u64) -> bool {
    let guard = crate::aspace::with_root(root).and_then(|r| r.lock());
    let slot = guard.as_ref().and_then(|sp| anon_slot(sp, va));
    if leaf.compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return false;
    }
    if let Some(s) = slot.filter(|_| !cfg!(feature = "cow-slot-canary")) {
        let _ = s.compare_exchange(
            slot::frame(ARCH.pte_phys(old)),
            slot::frame(ARCH.pte_phys(new)),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    true
}

/// The fork of the parent's (`parent`) mappings into its child (`child`): the
/// same records, each anonymous object of the parent cloned into one of the
/// child's ([`clone_slots`]: its slot words, every resident frame shared
/// copy-on-write and every compressed page a share of the pool's entry), and
/// the private file pages the fork's walk shared counted. Returns the reserved
/// pages the child holds uncommitted, for the caller to charge to the child.
///
/// The child's slots and leaves come from one read of each parent slot, so a
/// page a sibling thread commits during the fork is either the child's (read
/// after the commit, shared and counted) or a zero page of its own (read
/// before). The mapping set itself cannot change meanwhile (the caller holds
/// the group's `mm_lock`), and nothing runs on the child's table yet. The
/// child's leaf tables and slot chunks are built under a root that is not the
/// running task's, so the caller charges them (`take_current_pt_build`).
pub fn fork_clone(parent: SpaceRef, child: SpaceRef) -> Result<usize, MapError> {
    let r = fork_clone_twinned(parent, child);
    // The twins served this fork only.
    let mut buf = [Mapping::anon(0, 0, false, 0, 0); FORK_BATCH];
    let mut at = 0;
    loop {
        let n = mappings_from(parent, at, &mut buf);
        if n == 0 {
            break;
        }
        for h in buf[..n].iter().filter_map(Mapping::anon_obj) {
            // SAFETY: the parent's mappings cannot change (the caller holds
            // the group's `mm_lock`), so the object lives.
            unsafe { anon_obj::get(h) }.set_twin(0);
        }
        at += n;
    }
    r
}

fn fork_clone_twinned(parent: SpaceRef, child: SpaceRef) -> Result<usize, MapError> {
    // The records go a few at a time, each batch copied out under one space's
    // lock and in under the other's: no path holds two spaces' locks, and the
    // stack holds a batch, not a set. The parent's set cannot change
    // meanwhile (the caller holds the group's `mm_lock`), so its objects live.
    let mut buf = [Mapping::anon(0, 0, false, 0, 0); FORK_BATCH];
    let mut reserved = 0;
    let mut copied_any = false;
    let mut at = 0;
    loop {
        let n = {
            let Some(sp) = parent.lock().filter(|sp| sp.recorded) else { break };
            if at == 0 {
                reserved = sp.set.charged_pages();
            }
            let rs = &sp.set.as_slice()[at.min(sp.set.len())..];
            let n = rs.len().min(FORK_BATCH);
            buf[..n].copy_from_slice(&rs[..n]);
            n
        };
        if n == 0 {
            break;
        }
        // A shared file mapping is not inherited: its pages are the cache's
        // frames in the parent's shm window, which the fork walk leaves out of
        // the child, as it does every shared mapping.
        for m in buf[..n].iter().filter(|m| m.charged()) {
            let mut cm = *m;
            let mut made = None;
            if let Backing::Anon { obj } = m.backing {
                // SAFETY: a mapping of the parent names it (above).
                let o = unsafe { anon_obj::get(obj) };
                if o.twin() == 0 {
                    let Some(t) = anon_obj::create_twin(o) else {
                        drop_records(child);
                        return Err(MapError::Full);
                    };
                    o.set_twin(t);
                    made = Some(t);
                }
                cm.backing = Backing::Anon { obj: o.twin() };
            }
            let res = match child.lock() {
                Some(mut c) => {
                    if !copied_any {
                        c.open();
                        c.committed = 0;
                        copied_any = true;
                    }
                    // In order and never joining (the parent's set is folded):
                    // no record more than the parent's.
                    c.set.insert(cm)
                }
                None => Err(MapError::Full),
            };
            if let Err(e) = res {
                if let Some(t) = made {
                    // SAFETY: just made, named by no mapping (`fork_clone`
                    // clears the parent's twins).
                    unsafe { anon_obj::destroy(t, child.root()) };
                }
                // No page-cache count was taken for the child's records yet.
                drop_records(child);
                return Err(e);
            }
        }
        at += n;
    }
    if !copied_any {
        return Ok(0);
    }
    // The pages the parent has compressed are the child's too: a share of the
    // pool's entries, whose generations the copied markers name.
    if zpool_dup(parent.key(), child.key()).is_err() {
        forget(child);
        return Err(MapError::Full);
    }
    let mut c = Cloned { frames: 0, marked: 0, downgraded: false };
    let r = clone_objects(parent, child, &mut buf, &mut c);
    // The parent's write bits went: no hart may keep a writable translation of
    // a frame the child now shares. Also when the clone is refused, for the
    // leaves it had already downgraded.
    if c.downgraded {
        vmm::user_shootdown(parent.root(), 0, azos_arch_api::TLB_ALL);
    }
    if let Err(e) = r {
        forget(child);
        return Err(e);
    }
    if let Some(mut sp) = child.lock().filter(|sp| sp.recorded) {
        sp.committed = c.frames;
    }
    // A page behind a marker is not charged (the reclaimer gave the charge
    // back), in the child as in the parent.
    Ok(reserved.saturating_sub(c.frames).saturating_sub(c.marked))
}

/// What [`clone_objects`] gave the child.
struct Cloned {
    /// Pages the child holds in a frame (shared with the parent).
    frames: usize,
    /// Pages the child holds behind a pool marker.
    marked: usize,
    /// A writable leaf of the parent became read-only: it needs a shootdown.
    downgraded: bool,
}

/// Every charged mapping of `parent` into the child's twin objects (the
/// records are copied already, and each parent object names its twin). An
/// anonymous object is cloned slot by slot ([`clone_slots`]); a private file
/// mapping's pages are leaves the fork's walk shared, counted from the child's
/// table.
fn clone_objects(parent: SpaceRef, child: SpaceRef, buf: &mut [Mapping; FORK_BATCH], c: &mut Cloned) -> Result<(), MapError> {
    let mut at = 0;
    loop {
        let n = mappings_from(parent, at, buf);
        if n == 0 {
            return Ok(());
        }
        for m in buf[..n].iter().filter(|m| m.charged()) {
            match m.backing {
                Backing::Anon { obj } => {
                    // SAFETY: the parent's mappings cannot change (the caller
                    // holds the group's `mm_lock`), so the object lives; its
                    // twin is the child's, which has not run.
                    let (po, co) = unsafe { (anon_obj::get(obj), anon_obj::get(anon_obj::get(obj).twin())) };
                    clone_slots(parent.root(), child.root(), m, po, co, c)?;
                }
                Backing::File { obj, .. } => {
                    vmm::for_each_leaf_in(child.root(), m.start, m.end, |_, _| c.frames += 1);
                    // The private file mappings the child now holds, for the page cache's count.
                    memobj::memobj_paged_region_add_ref(obj);
                }
            }
        }
        at += n;
    }
}

/// Canary `cow-shared-write-canary`: a frame the clone shares keeps its write
/// permission in the parent and is mapped writable in the child, so a store by
/// either reaches the other.
const SHARE_READ_ONLY: bool = !cfg!(feature = "cow-shared-write-canary");

/// The fork of one anonymous mapping `m`: the child's object `co` gets the
/// parent's (`po`) slot words, and every page the parent holds in a frame is
/// shared with it copy-on-write: one more reference on the frame (taken before
/// either side's leaf names it as shared), the parent's leaf read-only and the
/// child's the same word. A compressed or swapped page is the marker word, its
/// pool entry the child's share ([`zpool_dup`]); nothing is restored.
///
/// The parent's slots are read without its lock: its sibling threads may
/// install, break and reuse pages meanwhile, each a single slot and leaf
/// change under that lock. The child gets the frame its slot word named at the
/// read, and the parent's leaf is made read-only only while it still names that
/// frame: a sibling's break since then gave the parent a private frame of its
/// own, and a reuse that raced the reference takes it back
/// (`cow::handle_cow_fault`). The fork's hold ([`ForkHold`]) keeps the
/// reclaimer and restores off the parent, so no marker changes, and none is in
/// transit. On a refusal the references taken so far are in the child's
/// leaves, which its teardown gives back.
fn clone_slots(
    proot: usize,
    croot: usize,
    m: &Mapping,
    po: &anon_obj::AnonObj,
    co: &anon_obj::AnonObj,
    c: &mut Cloned,
) -> Result<(), MapError> {
    let span = PAGE_SIZE * ARCH.entries_per_table();
    let mut va = m.start;
    while va < m.end {
        let end = (va | (span - 1)).saturating_add(1).min(m.end);
        // The two leaf tables of this span, looked up at its first frame.
        let mut tables: Option<(Option<*mut u64>, *mut u64)> = None;
        for k in 0..(end - va) / PAGE_SIZE {
            let page = va + k * PAGE_SIZE;
            let i = m.page_index(page);
            let word = po.slot(i).map_or(slot::EMPTY, |s| s.load(Ordering::Acquire));
            let f = match slot::decode(word) {
                Some(slot::Slot::Empty) => continue,
                Some(slot::Slot::Frame(f)) => f,
                // Canary `fork-marker-canary`: the child's slot stays empty.
                Some(slot::Slot::Marker(PageMarker::Compressed | PageMarker::Swapped, _)) if cfg!(feature = "fork-marker-canary") => continue,
                Some(slot::Slot::Marker(PageMarker::Compressed | PageMarker::Swapped, _)) => {
                    child_slot(croot, co, i)?.store(word, Ordering::Release);
                    c.marked += 1;
                    continue;
                }
                // In transit: the hold waited every store out, and starts none.
                _ => return Err(MapError::Invalid),
            };
            let (pl, cl) = match tables {
                Some(t) => t,
                None => *tables.insert(leaf_tables(proot, croot, va)?),
            };
            crate::cow::page_addref(f).map_err(|_| MapError::Invalid)?;
            let cs = match child_slot(croot, co, i) {
                Ok(s) => s,
                Err(e) => {
                    let _ = crate::cow::page_decref(f);
                    return Err(e);
                }
            };
            // SAFETY: entry `k` of the parent's leaf table for this span.
            let leaf = match share_leaf(pl.map(|p| unsafe { &*(p.add(k) as *const AtomicU64) }), f, m.write, c) {
                Ok(w) => w,
                Err(e) => {
                    let _ = crate::cow::page_decref(f);
                    return Err(e);
                }
            };
            cs.store(slot::frame(f), Ordering::Release);
            // SAFETY: entry `k` of the child's leaf table for this span, a
            // table of a root no CPU runs on yet.
            unsafe { core::ptr::write_volatile(cl.add(k), leaf) };
            c.frames += 1;
        }
        va = end;
    }
    Ok(())
}

/// Page `i`'s slot in the child's object, its storage taken now if it has none.
fn child_slot<'o>(croot: usize, co: &'o anon_obj::AnonObj, i: usize) -> Result<&'o AtomicU64, MapError> {
    if let Some(s) = co.slot(i) {
        return Ok(s);
    }
    let mut spare = Spare::take(croot, co.missing(i)).map_err(|_| MapError::Full)?;
    co.slot_fill(i, &mut spare).ok_or(MapError::Full)
}

/// The level-0 entries for `va` in the parent's table (none when it has no
/// leaf table there) and in the child's (built now). A block leaf in the
/// parent is refused: the fork split every block first and none is promoted
/// while it runs.
fn leaf_tables(proot: usize, croot: usize, va: usize) -> Result<(Option<*mut u64>, *mut u64), MapError> {
    let pl = match vmm::walk_level(proot, va, false, false) {
        Ok((p, 0)) => Some(p),
        Ok(_) => return Err(MapError::Invalid),
        Err(_) => None,
    };
    match vmm::walk_level(croot, va, true, false) {
        Ok((p, 0)) => Ok((pl, p)),
        _ => Err(MapError::Full),
    }
}

/// The parent's leaf `leaf` of a page whose frame `f` the child now shares,
/// made read-only (copy-on-write in a writable mapping); the word the child's
/// leaf gets. A leaf that names another frame or none is left as it is (a
/// sibling broke or reused the page since the slot was read), and the child's
/// word is made from the mapping's permission.
fn share_leaf(leaf: Option<&AtomicU64>, f: usize, write: bool, c: &mut Cloned) -> Result<u64, MapError> {
    if let Some(a) = leaf {
        let mut cur = a.load(Ordering::Acquire);
        while ARCH.pte_is_valid(cur) && ARCH.pte_is_leaf(cur, 0) && ARCH.pte_phys(cur) == f {
            if !SHARE_READ_ONLY {
                return Ok(cur);
            }
            if !ARCH.pte_perms(cur).write {
                return Ok(if write { ARCH.pte_share_cow(cur) } else { cur });
            }
            let shared = ARCH.pte_share_cow(cur);
            // The hardware's Accessed or Dirty bit, or a sibling, may change
            // the word meanwhile: taken again as it now is.
            match a.compare_exchange(cur, shared, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    c.downgraded = true;
                    return Ok(shared);
                }
                Err(now) => cur = now,
            }
        }
    }
    let perms = PagePerms { user: true, read: true, write, exec: false, accessed: true, dirty: write, ..PagePerms::USER_RW };
    let w = ARCH.pte_make_leaf(f, perms, 0).map_err(|_| MapError::Invalid)?;
    Ok(if write && SHARE_READ_ONLY { ARCH.pte_share_cow(w) } else { w })
}

/// Host suites only: run once just before a fault's install takes the
/// space's lock (`pte_truth.rs` starts a fork there).
#[cfg(not(target_os = "none"))]
static INSTALL_HOOK: SpinLock<Option<fn()>> = SpinLock::new(None);

/// Host suites only: install or remove [`INSTALL_HOOK`].
#[cfg(not(target_os = "none"))]
pub fn shim_set_install_hook(hook: Option<fn()>) {
    *INSTALL_HOOK.lock() = hook;
}

/// The ranges of the anonymous mappings of `r`, in address order, into `out`;
/// how many (none for a space without records). A fork's walk leaves their
/// pages to [`fork_clone`].
pub(crate) fn anon_ranges(r: SpaceRef, out: &mut [(usize, usize); MAPPINGS_PER_SPACE]) -> usize {
    let Some(sp) = r.lock().filter(|sp| sp.recorded) else { return 0 };
    let mut n = 0;
    for m in sp.set.as_slice().iter().filter(|m| m.anon_obj().is_some()) {
        out[n] = (m.start, m.end);
        n += 1;
    }
    n
}

/// Records [`fork_clone`] copies at a time.
const FORK_BATCH: usize = 8;

/// Copy the mappings of `r` from index `at` on into `out`; how many (0 when
/// there are no more, or no records).
fn mappings_from(r: SpaceRef, at: usize, out: &mut [Mapping]) -> usize {
    let Some(sp) = r.lock().filter(|sp| sp.recorded) else { return 0 };
    let rs = &sp.set.as_slice()[at.min(sp.set.len())..];
    let n = rs.len().min(out.len());
    out[..n].copy_from_slice(&rs[..n]);
    n
}

/// Forget every mapping of the space `r` and the anonymous objects they name
/// (its page table is being destroyed, or a fork that copied the mappings in
/// is refused).
pub fn forget(r: SpaceRef) {
    close_records(r, true);
}

/// [`forget`] of a fork's child whose file mappings took no page-cache count yet.
fn drop_records(r: SpaceRef) {
    close_records(r, false);
}

fn close_records(r: SpaceRef, files_counted: bool) {
    let mut files = [0u32; MAPPINGS_PER_SPACE];
    let mut nf = 0;
    let mut objs = [0usize; MAPPINGS_PER_SPACE];
    let mut no = 0;
    if let Some(mut sp) = r.lock() {
        if sp.recorded {
            for m in sp.set.as_slice() {
                match m.backing {
                    Backing::File { obj, .. } => {
                        files[nf] = obj;
                        nf += 1;
                    }
                    Backing::Anon { obj } if !objs[..no].contains(&obj) => {
                        objs[no] = obj;
                        no += 1;
                    }
                    Backing::Anon { .. } => {}
                }
            }
        }
        sp.close();
    }
    break_root(r.root());
    zpool_forget(r.key());
    for &obj in &objs[..no] {
        // SAFETY: the set that named it is closed.
        unsafe { anon_obj::destroy(obj, r.root()) };
    }
    // The mappings are gone: their users in the page cache with them.
    if files_counted {
        for &obj in &files[..nf] {
            memobj::memobj_paged_region_drop_ref(obj);
        }
    }
}

/// `(reserved, committed)` mapped pages of the space `r`, for tests and reports.
pub fn space_pages(r: SpaceRef) -> (usize, usize) {
    r.lock().filter(|sp| sp.recorded).map_or((0, 0), |sp| (sp.set.reserved_pages(), sp.committed))
}

/// Host suites: the mapping records of `r`.
#[cfg(not(target_os = "none"))]
pub fn shim_mappings(r: SpaceRef) -> usize {
    r.lock().filter(|sp| sp.recorded).map_or(0, |sp| sp.set.len())
}

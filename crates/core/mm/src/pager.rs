// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Demand paging for `mmap` through pagers (wave 14, DEMANDPAGE).
//!
//! The kernel owns the address space; a pager owns what is *in* a page. `mmap`
//! records a reserved range (a [`Region`]) instead of committing frames, and
//! the first touch of each page faults here: the region's pager supplies the
//! page and the kernel installs it with the region's exact permissions. The
//! split is GNU Mach's external-pager idea (the kernel asks, the pager
//! answers), not a port of it.
//!
//! **Pagers.** One exists: [`AnonPager`], anonymous memory: a page whose slot
//! holds a page marker (below) is decompressed into a fresh frame from the
//! compressed-page pool (Kconfig `MM_RECLAIM_COMPRESS`, `crate::zpool`), any
//! other is zero-filled.
//!
//! * File pages come from the page cache: a file-backed page is a frame of a
//!   `MemKind::Paged` MemObj (storage L11, `azos_ipc::memobj`), the one page
//!   cache, and what it reads and writes back through is the
//!   [`PageBacking`] callback defined below. The file layer has the
//!   positional read and write it needs (`FileSystem::read_at`/`write_at`, an
//!   `InodeKey` naming the file), and `azos_fs::FsPageBacking` is the
//!   implementation. A file `mmap` is a [`Region`] of [`PagerKind::File`] whose
//!   `obj`/`off` name the cache object and the page in it; the object table is
//!   not this crate's (it depends on this one), so the fault path reaches it
//!   through [`FileFrames`], which the syscall layer installs. Two kinds:
//!   **`MAP_SHARED`** maps the cache's own frame (the cache frame IS the mapped
//!   frame: every mapper sees every store, and the page is written back to the
//!   file); **`MAP_PRIVATE`** takes a copy of the cache page at the first touch
//!   into a frame of the task's own, charged and freed like anonymous memory,
//!   so its stores never reach the cache or the file. See [`resolve_file_fault`].
//! * An IPC pager (a ring-3 server answering page requests) is what
//!   [`Supply::Pending`] and the `obj`/`off` fields of [`Region`] are shaped
//!   for: a pager that cannot answer at once returns `Pending`, the faulting
//!   task waits, and the server's reply installs the page through the same
//!   region re-check [`resolve_fault`] does. Not implemented; no pager returns
//!   `Pending` today, and a `Pending` answer is treated as unresolved.
//!
//! **The compressed pool** (see [`AnonReclaim`] and the section below). The
//! reclaimer takes a resident page out of an address space, compresses it into
//! the pool and leaves a *page marker* in its slot (`azos_arch_api::PageMarker`,
//! the protocol is `crate::zpool`'s): `InTransit` while the store runs,
//! `Compressed` (`Swapped` once its segment is on the swap area) after it. A
//! fault decides from the word it reads, never from a look at the pool: an
//! empty slot is a zero page, `InTransit` is waited for (so a fault that
//! races a store neither zero-fills nor restores a copy that is not there yet),
//! and a marker is restored, the pool's entry being the one whose generation
//! the marker carries. Three rules keep that sound. The pool's entry stays
//! until the restored frame is *installed* (a thread that loses the install
//! race, or a region that changed under the fault, leaves it for the retry)
//! and is then dropped by generation, the copy the fault restored and no other;
//! whatever ends the address range (`munmap`, `mprotect(PROT_NONE)`, the
//! space's end) clears the markers and drops the entries; and a `fork` gives
//! the child a marker, and a pool entry sharing the parent's blob, for each
//! page the parent has out, and waits for the stores in flight first (a page
//! in transit would be in neither). The pool's lock is a leaf: taken with
//! neither `TABLE` nor `RESVS` held, and over the page allocator, never the
//! other way round.
//!
//! **Accounting.** Reserve-time charging, kept from the page-budget model (the model
//! `sys_alloc_demand` already follows) and owner decision 102 (charge the
//! whole request before taking a frame): `mmap` charges every reserved page to
//! the task's quota when it reserves, so a fault never refuses on quota — the
//! same reason a copy-on-write break is "observed, not charged". A page the
//! reclaimer stores gives its charge back (`PageBudget::storm_note_stored`),
//! so a page behind a marker is not charged; the fault that restores it
//! charges it again without refusing it ([`set_restore_hook`],
//! `PageBudget::charge_restore`), and `munmap` of a marked page gives nothing
//! back ([`release_range`]). Overcommit
//! policy: the per-task quota is never overcommitted; physical frames are,
//! within what memory admission allows, so a fault that finds the page
//! allocator empty kills the task, as a COW break does. One residual: the
//! intermediate page-table frames a first touch allocates are charged then,
//! through the table hook, so a task at its exact limit can still be refused
//! a table at fault time.
//!
//! **Superpage reservations** (Kconfig `MM_THP_RESV`, `crate::resv`). The first
//! fault in a block-aligned part of an anonymous region that one record covers
//! whole, and where nothing is mapped yet, takes a contiguous run; this and
//! the following faults fill 4 KiB pages from it, and the fault that fills the
//! last one replaces the level-0 table with one level-1 leaf. A cut of the
//! region (`munmap`, `mprotect`), a fork, the task's exit, or an allocator that
//! ran dry breaks the reservation: the frames not yet handed out go back. The
//! reservation table has its own lock, never held across the page allocator
//! and never with `TABLE` held (the promotion is the one place `TABLE` is held
//! over a page-table swap, and takes no other lock). The task's quota is
//! unaffected: a reservation lies inside a region, which was charged whole.
//!
//! **State.** One [`RegionSet`] per user page-table root, in a fixed table of
//! `MAX_TASKS` slots (an address space belongs to at least one task, so the
//! table cannot run out of slots before the task table does), under one
//! IRQ-safe lock held only for lookups and the install itself, never across
//! the 4 KiB zero or a table walk. Every install happens under that lock
//! after re-finding the region, and `munmap` removes the region under it
//! before sweeping the committed pages: a commit can never land after the
//! sweep.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use azos_arch::ARCH;
use azos_arch_api::{Mmu, PageMarker, PagePerms, PAGE_SIZE};
use azos_common::error::{KResult, KernelError};
use azos_sync::SpinLock;

use crate::addr::{self, PhysAddr};
use crate::aging;
pub use crate::region::{PagerKind, Region, RegionError, RegionSet};
// Core-only, so the object table, the file layer and the host suites link the
// one source (`#[path]`: it is a sibling of this file, not a crate module).
#[path = "page_backing.rs"]
mod page_backing;
pub use page_backing::{fill_page, valid_len, write_back_page, PageBacking, PageIoError, PageKey, PAGE_KEY_LEN};
use crate::resv::{self, Claim, Filled, ResvTable};
use crate::zpool::{self, Fault, Fetched, Lookup, PageWords, Packed, Reclaimee};
use crate::swap;
use crate::{pmm, vmm};

/// Kconfig `MM_DEMAND_PAGING`: anonymous `mmap` reserves instead of commits.
pub const DEMAND_PAGING: bool = azos_limits::MM_DEMAND_PAGING;
/// Kconfig `MM_PRECOMMIT_RT`: real-time-class tasks' mappings are committed
/// at map time.
pub const PRECOMMIT_RT: bool = azos_limits::MM_PRECOMMIT_RT;
/// Region records per address space (Kconfig `MM_REGIONS_PER_SPACE`).
pub const REGIONS_PER_SPACE: usize = azos_limits::MM_REGIONS_PER_SPACE as usize;
const SPACES: usize = azos_limits::MAX_TASKS as usize;

/// What a pager is asked for: page `page` of object `obj`, which is the page
/// at `va` of the address space under page-table root `space`.
#[derive(Clone, Copy, Debug)]
pub struct PageRequest {
    pub obj: u32,
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

/// What the file pager needs of the page cache, which lives in the object table
/// (`azos_ipc::memobj`, above this crate): installed once by the syscall layer
/// ([`set_file_frames`]), before the first file region exists.
///
/// `obj` is the packed reference a file region carries ([`Region::obj`]), `page`
/// the page within the object ([`Region::page_index`]). Every method may wait
/// for the file and is called with no lock of this module held.
pub trait FileFrames: Sync {
    /// The cache frame of the page, read from the file first if it is not
    /// there; `write` says the caller is about to store through it. The frame
    /// belongs to the cache.
    fn frame(&self, obj: u32, page: usize, write: bool) -> KResult<PhysAddr>;

    /// The frame the cache holds for the page now, without filling it.
    fn resident(&self, obj: u32, page: usize) -> Option<PhysAddr>;

    /// Copy the page into `dst` (one page), through the cache: how many bytes
    /// the file had there. The caller zeroes the rest.
    fn read(&self, obj: u32, page: usize, dst: &mut [u8]) -> KResult<usize>;

    /// A region over `obj` came to be (a `mmap`, or a fork's copy of one).
    fn addref(&self, obj: u32);

    /// A region over `obj` ended (`munmap`, the space's end).
    fn unref(&self, obj: u32);
}

static FILE_FRAMES: SpinLock<Option<&'static dyn FileFrames>> = SpinLock::new(None);

/// Install the page cache the file regions fault through. Idempotent.
pub fn set_file_frames(f: &'static dyn FileFrames) {
    *FILE_FRAMES.lock_irqsave() = Some(f);
}

fn file_frames() -> KResult<&'static dyn FileFrames> {
    // A region can only exist after the install (`reserve_file` refuses
    // without it), so a miss here is a kernel bug, answered as an unmapped page.
    (*FILE_FRAMES.lock_irqsave()).ok_or(KernelError::NotMapped)
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
        // never see a previous owner's bytes (see `demand.rs`).
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

/// Change the marker of the page at `va` of `space` from `from` to `to`
/// (same generation), if it is `from`. `false`: the space or the marker is
/// not there.
fn retag(space: usize, va: usize, from: PageMarker, to: PageMarker, gen: u32) -> bool {
    let t = TABLE.lock_irqsave();
    if t.slot(space).is_none() || vmm::write_would_enter_kernel_table(space, va) {
        return false;
    }
    let Ok(p) = vmm::walk(space, va, false) else { return false };
    // SAFETY: an aligned entry of a live table page; `TABLE` is held, so the
    // space's teardown (`forget`) has not started.
    let slot = unsafe { &*(p as *const core::sync::atomic::AtomicU64) };
    slot.compare_exchange(
        ARCH.pte_make_marker(from, gen),
        ARCH.pte_make_marker(to, gen),
        Ordering::AcqRel,
        Ordering::Acquire,
    )
    .is_ok()
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

/// A page's name in the pool: the container is the address space (until
/// anonymous regions are MemObjs), the page its virtual page number.
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

/// Compress the resident page at `va` of the address space under `space`
/// (`frame`) into the pool, charged to Domain slot `owner`. The caller is the
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
/// The page's address range must have a region (`reserve`d, not `release_range`d):
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

/// Every page of the address space `space` goes (its page table is destroyed).
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

/// A store in flight: the page is out of the table, its slot holds the
/// `InTransit` marker `ticket` names.
#[derive(Clone, Copy)]
struct Flight {
    space: usize,
    va: usize,
    frame: PhysAddr,
    /// The leaf word the marker replaced, for a store that does not happen.
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
/// ([`Reclaimee`]): anonymous region pages that are resident, owned by their
/// space alone and plain 4 KiB leaves, oldest generation first
/// ([`aging::AgeTable::pick`]: the Accessed bit through `age_space`, four
/// generations, address order inside one), skipping the ones the compressor
/// gave up on until they are touched.
///
/// Per victim: `next` finds it, `unmap` replaces its leaf with an `InTransit`
/// marker and shoots the translation down on every hart, `store` compresses it
/// into the pool and replaces the marker with a `Compressed` one, `free`
/// frees the frame (or `keep` puts the leaf back and, for a page whose range
/// was unmapped meanwhile, frees the frame). A fault on the page meanwhile
/// waits ([`resolve_fault`]).
///
/// What it never offers or takes: a file region's page; a page shared with
/// another space (a fork's copy-on-write sharing, counted in the frame's
/// reference count); a page of a block promoted to one superpage or of a
/// contiguous run; any page of a space with a fork walking it. A Domain on a
/// `mem = "locked"` row, and a real-time hart, are the storm's gate
/// (`PageBudget::storm_begin`), not asked here; a real-time task's pages are
/// committed eagerly and have no region, so they are not offered either.
pub struct AnonReclaim<'a> {
    roots: &'a [usize],
    owner: usize,
    ages: &'a mut Ages,
    cursor: aging::Cursor,
    flight: Option<Flight>,
}

impl<'a> AnonReclaim<'a> {
    /// A source over the spaces `roots` (page-table roots, the Domain's
    /// threads' address spaces, each once), whose pool entries are charged to
    /// Domain slot `owner`; `ages` is the table `age_space` fed.
    pub fn new(roots: &'a [usize], owner: usize, ages: &'a mut Ages) -> Self {
        AnonReclaim { roots, owner, ages, cursor: aging::Cursor::default(), flight: None }
    }

    /// Is the page at `va` of `root` resident and one the reclaimer may take?
    /// The cheap test of the aging walk; `unmap` repeats it under the lock.
    fn candidate(root: usize, va: usize) -> bool {
        let w = peek(root, va);
        ARCH.is_victim_leaf(w) && pmm::desc_of(ARCH.pte_phys(w)).is_some()
    }

    /// Copy out the regions of `root` (empty when it has none).
    fn regions_of(root: usize, out: &mut [Region; REGIONS_PER_SPACE]) -> usize {
        let t = TABLE.lock_irqsave();
        let Some(i) = t.slot(root) else { return 0 };
        let rs = t.s[i].set.as_slice();
        out[..rs.len()].copy_from_slice(rs);
        rs.len()
    }

    /// End the flight: the space counts one store fewer, the waiters are woken.
    fn finish(f: Flight) {
        {
            let mut t = TABLE.lock_irqsave();
            if let Some(i) = t.slot(f.space) {
                t.s[i].reclaiming = t.s[i].reclaiming.saturating_sub(1);
            }
        }
        RECLAIMING.fetch_sub(1, Ordering::AcqRel);
        store_ended();
    }

    /// The slot of the flight's page, under the table lock `t` the caller
    /// holds: `None` when its space or its table is gone.
    fn slot_of<'t>(t: &'t Table, f: &Flight) -> Option<(usize, &'t core::sync::atomic::AtomicU64)> {
        let i = t.slot(f.space)?;
        let p = vmm::walk(f.space, f.va, false).ok()?;
        // SAFETY: an aligned entry of a live table page: the space has a slot,
        // and `forget` (which precedes the teardown of its tables) takes the
        // lock the caller holds.
        Some((i, unsafe { &*(p as *const core::sync::atomic::AtomicU64) }))
    }
}

impl Reclaimee for AnonReclaim<'_> {
    type Victim = Victim;

    fn next(&mut self) -> Option<Victim> {
        let (space, page) = self.ages.pick(&mut self.cursor, self.roots)?;
        Some(Victim { space, va: page * PAGE_SIZE })
    }

    fn unmap(&mut self, v: Victim) -> bool {
        debug_assert!(self.flight.is_none());
        // A reservation's frames are handed out in order and the block is
        // promoted when the last is in; a page that leaves and comes back in
        // another frame must not be the run's. Outside `TABLE` (the
        // reservations' lock is never taken under it).
        break_range(v.space, v.va, v.va + PAGE_SIZE);
        let ticket = TICKET.fetch_add(1, Ordering::Relaxed);
        RECLAIMING.fetch_add(1, Ordering::AcqRel);
        let taken = {
            let mut t = TABLE.lock_irqsave();
            self.take_out_locked(&mut t, v, ticket)
        };
        let Some((frame, original)) = taken else {
            RECLAIMING.fetch_sub(1, Ordering::AcqRel);
            return false;
        };
        // No hart may write the frame once this returns; until it does one
        // can still, through a translation it cached.
        crate::vmm::user_shootdown(v.space, v.va, PAGE_SIZE);
        self.flight = Some(Flight { space: v.space, va: v.va, frame, original, ticket, state: FlightState::Out });
        true
    }

    fn store(&mut self, _v: Victim) -> Result<u32, zpool::Error> {
        let Some(f) = self.flight.as_mut() else { return Err(zpool::Error::Incompressible) };
        let (bytes, gen) = match zpool_store(self.owner, f.space, f.va, f.frame) {
            Ok(stored) => stored,
            Err(e) => {
                // The coder gave up on the bytes: not offered again until the
                // page is touched (a storm would unmap and shoot it down for
                // the same answer).
                if e == zpool::Error::Incompressible {
                    self.ages.mark_incompressible(f.space, f.va / PAGE_SIZE);
                }
                return Err(e);
            }
        };
        let published = {
            let mut t = TABLE.lock_irqsave();
            match Self::slot_of(&t, f) {
                // The range is still a region of the space: `release_range`
                // takes the region out before it drops the pool's pages of
                // it, so a publish that finds the region here is followed by
                // that drop and the marker's clear, and one that does not was
                // preceded by them.
                Some((i, slot))
                    if t.s[i].set.find(f.va).is_some_and(|r| r.pager == PagerKind::Anon)
                        && zpool::publish(&ARCH, slot, f.ticket, PageMarker::Compressed, gen) =>
                {
                    t.s[i].committed = t.s[i].committed.saturating_sub(1);
                    true
                }
                _ => false,
            }
        };
        if published {
            f.state = FlightState::Published;
            return Ok(bytes as u32);
        }
        // The range was unmapped (or the space ended) while the page was
        // being stored: nobody can ask for this copy.
        let (obj, pg) = zkey(f.space, f.va);
        with_pool(|p| p.remove_if(obj, pg, gen));
        f.state = FlightState::Gone;
        // Not stored, not a refusal of the pool: the storm goes on, and
        // `keep` frees the frame. (`Incompressible` is the one answer that
        // does not end a storm.)
        Err(zpool::Error::Incompressible)
    }

    fn free(&mut self, _v: Victim) {
        if let Some(f) = self.flight.take() {
            self.ages.evicted(f.space, f.va / PAGE_SIZE);
            let _ = pmm::free_page(f.frame);
            Self::finish(f);
        }
    }

    fn keep(&mut self, _v: Victim) {
        let Some(f) = self.flight.take() else { return };
        let back = f.state == FlightState::Out && {
            let t = TABLE.lock_irqsave();
            Self::slot_of(&t, &f).is_some_and(|(_, slot)| zpool::put_back(&ARCH, slot, f.ticket, f.original))
        };
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
    /// Under the table lock: check the page again and swap its leaf for the
    /// `InTransit` marker. The frame and the leaf word it held.
    fn take_out_locked(&self, t: &mut Table, v: Victim, ticket: u32) -> Option<(PhysAddr, u64)> {
        let i = t.slot(v.space)?;
        // A fork walks the space: the pages it passes must stay.
        if t.s[i].forking != 0 || vmm::write_would_enter_kernel_table(v.space, v.va) {
            return None;
        }
        let r = t.s[i].set.find(v.va)?;
        if r.pager != PagerKind::Anon {
            return None;
        }
        // A leaf of 4 KiB: a promoted block's level-1 word is no page of ours
        // (promotion runs under this lock, so the answer holds).
        if vmm::leaf_level(v.space, v.va) != Some(0) {
            return None;
        }
        let p = vmm::walk(v.space, v.va, false).ok()?;
        // SAFETY: an aligned entry of a live table page (the space has a slot).
        let slot = unsafe { &*(p as *const core::sync::atomic::AtomicU64) };
        let w = slot.load(Ordering::Acquire);
        let frame = ARCH.pte_phys(w);
        // Shared with another space (a fork, a copy-on-write sibling), or not
        // a frame the allocator tracks: not ours to free.
        if pmm::desc_of(frame).is_none() || crate::cow_table::page_is_shared(frame) {
            return None;
        }
        let original = zpool::take_out(&ARCH, slot, ticket).ok()?;
        t.s[i].reclaiming += 1;
        Some((PhysAddr::new(frame), original))
    }
}

/// One aging pass over the anonymous regions of the space under `root`, for
/// Domain slot `owner`: feed `ages` (between `AgeTable::begin` and `end` of the
/// caller) the pages the reclaimer could take now and the ones used since the
/// last pass. Each 64-page window of a region is looked at with the table
/// lock held for the harvest only: `Mmu::harvest_accessed` clears bits in the
/// page tables, and a table freed under it would be a stray write into a frame
/// the allocator has reissued; `forget` takes this lock before the space's
/// tables go, so a space that has a slot here has them. (The resident test
/// reads without the lock, as `candidate` always did: a stale read is a
/// stale hint, the victim is checked again under the lock by `unmap`.)
///
/// `false`: a chunk did not fit in the table (`MM_AGING_CHUNKS`).
pub fn age_space(root: usize, owner: usize, ages: &mut Ages) -> bool {
    if aging::CHUNKS == 0 {
        return true;
    }
    let mut regions = [Region::anon(0, 0, false); REGIONS_PER_SPACE];
    let n = AnonReclaim::regions_of(root, &mut regions);
    let span = aging::WINDOW * PAGE_SIZE;
    let mut fit = true;
    for reg in regions[..n].iter().filter(|r| r.pager == PagerKind::Anon) {
        let mut base = reg.start & !(span - 1);
        while base < reg.end {
            // The pages of this window inside the region.
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
                // another region owns is not ours to clear.
                let (lo, hi) = (resident.trailing_zeros() as usize, 64 - resident.leading_zeros() as usize);
                let t = TABLE.lock_irqsave();
                if t.slot(root).is_none() {
                    return fit;
                }
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
} else if SPACES < 8 {
    8
} else if SPACES > 64 {
    64
} else {
    SPACES
};

/// The reservations. Taken for lookups and bit flips only, IRQ-safe, never
/// held across the page allocator, a zero, or `TABLE`.
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

/// Before a fork walks the space `root` (`cow::fork_cow_shared`): wait for the
/// stores in flight in it to end and keep the reclaimer from starting more,
/// stop any block of it being promoted, break its reservations, and split the
/// blocks already promoted (the walk skips level-1 leaves, so the child would
/// get a hole). `false`: a block could not be split, the fork is to be refused.
/// Call [`fork_end`] after the walk either way. Free for a space without
/// regions. Walks of one space may overlap (threads forking at once): the space
/// counts them, and promotion and reclaim resume when the last is over.
///
/// A page in transit is in no table the walk can see and not yet in the pool
/// the child is given a share of ([`fork_clone`]); it is the one state a fork
/// cannot copy, which is why it is waited out and not skipped. The wait sleeps
/// (a fork runs in a syscall, outside every lock of this module).
pub fn fork_begin(root: usize) -> bool {
    loop {
        let seen = MARKER_SEQ.load(Ordering::Acquire);
        {
            let mut t = TABLE.lock_irqsave();
            match t.slot(root) {
                Some(i) if t.s[i].reclaiming == 0 => {
                    t.s[i].forking += 1;
                    break;
                }
                Some(_) => {}
                None => return true,
            }
        }
        MARKER_WAIT.wait_if_for(azos_sync::waitstat::Site::PagerStore, || MARKER_SEQ.load(Ordering::Acquire) == seen);
    }
    if !resv::ENABLED {
        return true;
    }
    // A promotion that passed its checks before the flag went up finished
    // under `TABLE`, which the block above took after it.
    break_root(root);
    vmm::demote_all_user_megas(root)
}

/// The fork walk of `root` is over: the parent's pages are copy-on-write, so
/// nothing of it can be promoted until it is filled afresh, and the reclaimer
/// may take pages of it again.
pub fn fork_end(root: usize) {
    let mut t = TABLE.lock_irqsave();
    if let Some(i) = t.slot(root) {
        t.s[i].forking = t.s[i].forking.saturating_sub(1);
    }
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
fn run_frame(root: usize, page: usize, r: &Region) -> Option<Source> {
    let block = resv::block_of(page);
    if r.pager != PagerKind::Anon || !resv::covers(r.start, r.end, block) {
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
fn after_install(root: usize, block: usize, run: usize, idx: usize, write: bool) {
    let filled = RESVS.lock_irqsave().installed(root, block, run, idx);
    if !matches!(filled, Filled::Complete(_)) {
        return;
    }
    // Under `TABLE`: the region is still the one whole record that lets a
    // leaf map the block, so no `munmap` or `mprotect` has cut it, and none
    // can start its sweep before the swap is done.
    let old = {
        let t = TABLE.lock_irqsave();
        let whole = t.slot(root).and_then(|i| t.s[i].set.find(block)).is_some_and(|reg| {
            resv::covers(reg.start, reg.end, block) && reg.write == write && reg.pager == PagerKind::Anon
        }) && !t.slot(root).is_some_and(|i| t.s[i].forking > 0);
        if whole { vmm::promote_user_block(root, block, run, write) } else { None }
    };
    if let Some((l0, flushed)) = old {
        vmm::promote_finish(root, block, l0, flushed);
    }
}

struct Space {
    root: usize,
    /// Region pages whose frame is installed (page table entries this module
    /// made valid and that `munmap` has not taken back).
    committed: usize,
    /// Fork walks running on this space (`fork_begin` .. `fork_end`; threads
    /// of one space may fork at once, so a count, not a flag): while it is
    /// not zero no block of the space may be promoted, or a walk would pass
    /// the leaf and the child get a hole, and the reclaimer takes no page out
    /// of it, or the child would miss a page that is in neither table.
    forking: u32,
    /// Stores of this space in flight (the reclaimer has a page out of the
    /// table and not yet in the pool). A fork waits for them to end, and the
    /// reclaimer starts none while a fork walks.
    reclaiming: u32,
    set: RegionSet<REGIONS_PER_SPACE>,
}

impl Space {
    const fn new() -> Self {
        Space { root: 0, committed: 0, forking: 0, reclaiming: 0, set: RegionSet::new() }
    }
}

struct Table {
    used: usize,
    s: [Space; SPACES],
}

impl Table {
    #[inline]
    fn slot(&self, root: usize) -> Option<usize> {
        (0..self.used).find(|&i| self.s[i].root == root)
    }

    fn slot_or_new(&mut self, root: usize) -> Option<usize> {
        if let Some(i) = self.slot(root) {
            return Some(i);
        }
        if self.used == SPACES {
            return None;
        }
        let i = self.used;
        self.s[i].root = root;
        self.s[i].committed = 0;
        self.s[i].forking = 0;
        self.s[i].reclaiming = 0;
        self.s[i].set.clear();
        self.used += 1;
        Some(i)
    }

    fn drop_slot(&mut self, i: usize) {
        let last = self.used - 1;
        if i != last {
            self.s[i].root = self.s[last].root;
            self.s[i].committed = self.s[last].committed;
            self.s[i].forking = self.s[last].forking;
            self.s[i].reclaiming = self.s[last].reclaiming;
            let (a, b) = self.s.split_at_mut(last);
            a[i].set.copy_from(&b[0].set);
        }
        self.s[last].root = 0;
        self.used = last;
    }
}

static TABLE: SpinLock<Table> = SpinLock::new(Table {
    used: 0,
    s: [const { Space::new() }; SPACES],
});

/// Reserve `[start, end)` in the address space under `root` as anonymous
/// memory, readable and writable iff `write`. Commits nothing. `Full` when
/// the space's records (or the table) are exhausted: the caller commits the
/// range eagerly instead.
///
/// `Overlap` when the range is not vacant in the page table (something is
/// mapped or marked there, or reaching it enters a kernel-shared table): the
/// eager path refuses such a range through `map`'s `AlreadyMapped`, and so
/// must a reservation.
pub fn reserve(root: usize, start: usize, end: usize, write: bool) -> Result<(), RegionError> {
    if !vmm::user_range_vacant(root, start, end) {
        return Err(RegionError::Overlap);
    }
    let mut t = TABLE.lock_irqsave();
    let i = t.slot_or_new(root).ok_or(RegionError::Full)?;
    let r = t.s[i].set.insert(Region::anon(start, end, write));
    if r.is_err() && t.s[i].set.is_empty() {
        t.drop_slot(i);
    }
    r
}

/// Reserve `[start, end)` as one piece of a file mapping: pages `off..` of the
/// page-cache object `obj`, readable and writable iff `write`; `shared` is
/// `MAP_SHARED`. Commits nothing, and charges nothing (the caller charges a
/// private region as it does `mmap`'s anonymous ones; a shared one is the
/// cache's memory). The region counts as one user of `obj`
/// ([`FileFrames::addref`]) until it ends.
///
/// `Overlap` as [`reserve`]; `Full` when the space's records are exhausted;
/// `Invalid` before any page cache is installed.
pub fn reserve_file(
    root: usize,
    start: usize,
    end: usize,
    write: bool,
    shared: bool,
    obj: u32,
    off: usize,
) -> Result<(), RegionError> {
    let ff = file_frames().map_err(|_| RegionError::Invalid)?;
    if !vmm::user_range_vacant(root, start, end) {
        return Err(RegionError::Overlap);
    }
    {
        let mut t = TABLE.lock_irqsave();
        let i = t.slot_or_new(root).ok_or(RegionError::Full)?;
        let r = t.s[i].set.insert(Region::file(start, end, write, shared, obj, off));
        if r.is_err() {
            if t.s[i].set.is_empty() {
                t.drop_slot(i);
            }
            return r;
        }
    }
    ff.addref(obj);
    Ok(())
}

/// A file region as [`file_regions_in`] reports it.
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

/// The file regions `[s, e)` touches, into `out`; how many. `Invalid` when the
/// range would cut one (a file region goes whole or not at all), `Full` when
/// `out` is too short. Nothing changes.
pub fn file_regions_in(root: usize, s: usize, e: usize, out: &mut [FileRegion]) -> Result<usize, RegionError> {
    let t = TABLE.lock_irqsave();
    let Some(i) = t.slot(root) else { return Ok(0) };
    let set = &t.s[i].set;
    if !set.file_cut_ok(s, e) {
        return Err(RegionError::Invalid);
    }
    let mut n = 0;
    for r in set.as_slice() {
        if r.pager == PagerKind::File && r.start < e && s < r.end {
            if n == out.len() {
                return Err(RegionError::Full);
            }
            out[n] = FileRegion { start: r.start, end: r.end, obj: r.obj, off: r.off, shared: r.shared };
            n += 1;
        }
    }
    Ok(n)
}

/// Does `[s, e)` touch a file region?
pub fn has_file(root: usize, s: usize, e: usize) -> bool {
    let t = TABLE.lock_irqsave();
    t.slot(root).is_some_and(|i| t.s[i].set.has_file(s, e))
}

/// Resolve a fault in a file region (`r`, copied out of the set; `page` the
/// faulting page). The same two phases as [`resolve_fault`]: the page is
/// supplied with no lock held, then the region is found again and the entry
/// installed under the lock.
///
/// * **Shared**: the cache's frame ([`FileFrames::frame`]) is installed with the
///   region's permissions. The mapper's record in the object (made by the
///   syscall layer when it mapped) is what lets the cache drop the page from
///   this space, so after the install the cache is asked again: the same frame
///   means the install is covered, anything else means the page was dropped
///   between the lookup and the install, and the install is undone (the retry
///   faults again).
/// * **Private**: a frame of the task's own, the page's bytes copied in from the
///   cache and zeros after them. It is owned (munmap and the space's end free
///   it) and was charged when the region was reserved.
fn resolve_file_fault(root: usize, page: usize, r: &Region) -> KResult<()> {
    let ff = file_frames()?;
    let idx = r.page_index(page);
    let frame = if r.shared {
        ff.frame(r.obj, idx, r.write)?
    } else {
        // SAFETY: filled right below, before the entry that exposes it exists.
        let f = unsafe { pmm::alloc_page_uninit()? };
        // SAFETY: a frame this call owns, mapped by the direct map.
        let bytes = unsafe { core::slice::from_raw_parts_mut(addr::phys_to_virt(f.as_usize()) as *mut u8, PAGE_SIZE) };
        match ff.read(r.obj, idx, bytes) {
            Ok(n) => bytes[n.min(PAGE_SIZE)..].fill(0),
            Err(e) => {
                let _ = pmm::free_page(f);
                return Err(e);
            }
        }
        f
    };
    let give_back = |f: PhysAddr| {
        if !r.shared {
            let _ = pmm::free_page(f);
        }
    };
    let pte_ptr = match vmm::walk(root, page, true) {
        Ok(p) => p,
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

    let mut t = TABLE.lock_irqsave();
    let same = t.slot(root).and_then(|i| {
        t.s[i].set.find(page).filter(|now| now.write == r.write && now.pager == r.pager && now.obj == r.obj && now.shared == r.shared).map(|_| i)
    });
    let Some(i) = same else {
        // Unmapped or re-protected since the lookup: retry on the new layout.
        drop(t);
        give_back(frame);
        return Ok(());
    };
    // SAFETY: `pte_ptr` is an aligned entry of a live table page (the region
    // still exists, so `munmap` has not swept it).
    let old = unsafe { core::ptr::read_volatile(pte_ptr) };
    if ARCH.pte_is_valid(old) || ARCH.pte_is_demand(old) {
        drop(t);
        give_back(frame);
        return if ARCH.pte_is_valid(old) { Ok(()) } else { Err(KernelError::AlreadyMapped) };
    }
    // SAFETY: as above.
    let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
    if slot.compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire).is_err() {
        drop(t);
        give_back(frame);
        return Ok(());
    }
    t.s[i].committed += 1;
    drop(t);
    ARCH.flush_tlb_page(page);
    if r.shared && ff.resident(r.obj, idx) != Some(frame) {
        // The cache dropped the page before the install could be covered.
        vmm::unmap(root, page);
        let mut t = TABLE.lock_irqsave();
        if let Some(i) = t.slot(root) {
            t.s[i].committed = t.s[i].committed.saturating_sub(1);
        }
    }
    Ok(())
}

/// Resolve a fault at `va` under `root` from its region's pager.
///
/// `NotMapped` when no region holds `va` (the caller kills the task, as
/// before demand paging). `Ok` when the access should retry: the page is now
/// present (installed here or by another thread first), or the region changed
/// under the fault (`mprotect`, `munmap`) and the retry decides afresh.
///
/// Two phases, so interrupts are never off across the pager or the walk: the
/// region is copied out under the lock, the page supplied (4 KiB zeroed) and
/// the tables walked without it, then the lock is retaken, the region found
/// again and the entry installed. The install is the only step under the lock
/// besides the lookups, which is what keeps `release_range`'s promise: no
/// commit lands after a removal, because every install re-finds its region.
/// The same shape is what an IPC pager needs: its `Pending` answer is a
/// supply that finishes later.
///
/// **The slot decides.** What the page is, a zero page, a page in transit, a
/// page in the pool, is read from the word in its slot ([`zpool::classify`]),
/// before anything is supplied, and the install replaces exactly that word:
/// whatever changed it in between (the reclaimer, a fork, another fault) makes
/// the install fail and the fault start again, bounded by [`FAULT_TRIES`]. A
/// page in transit is waited for. The same two steps are why the kernel's own
/// access to a user page ([`vmm::translate_user`]) can rely on this: it does
/// not return before the page is resident or the access is hopeless.
pub fn resolve_fault(root: usize, va: usize) -> KResult<()> {
    let page = va & !(PAGE_SIZE - 1);
    for _ in 0..FAULT_TRIES {
        if let Step::Done = fault_once(root, page)? {
            return Ok(());
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
    /// The slot or the region changed under the attempt: look again.
    Again,
}

/// The word in the slot of `page` under `root`; empty when its table is not
/// there yet.
fn peek(root: usize, page: usize) -> u64 {
    match vmm::walk(root, page, false) {
        // SAFETY: `walk` answers an aligned entry of a live table page.
        Ok(p) => unsafe { core::ptr::read_volatile(p) },
        Err(_) => ARCH.pte_empty(),
    }
}

fn fault_once(root: usize, page: usize) -> KResult<Step> {
    let r = {
        let t = TABLE.lock_irqsave();
        let i = t.slot(root).ok_or(KernelError::NotMapped)?;
        *t.s[i].set.find(page).ok_or(KernelError::NotMapped)?
    };
    // Regions are made below the shm window and above the null guard, but the
    // walk below allocates tables: never into a table the kernel shares.
    if vmm::write_would_enter_kernel_table(root, page) {
        return Err(KernelError::InvalidArg);
    }
    if r.pager == PagerKind::File {
        resolve_file_fault(root, page, &r)?;
        return Ok(Step::Done);
    }
    // The store counter first, then the slot: a store that ends between the
    // two moves the counter, and the wait below does not sleep.
    let seq = MARKER_SEQ.load(Ordering::Acquire);
    let seen = peek(root, page);
    let stored = match zpool::classify(&ARCH, seen) {
        Fault::Zero => None,
        Fault::Present => return Ok(Step::Done),
        Fault::Wait => {
            MARKER_WAIT.wait_if_for(azos_sync::waitstat::Site::PagerStore, || MARKER_SEQ.load(Ordering::Acquire) == seq);
            return Ok(Step::Again);
        }
        Fault::Restore(kind, gen) => Some((kind, gen)),
        // A demand reservation: the demand path owns it.
        Fault::Other => return Err(KernelError::AlreadyMapped),
    };
    let block = resv::block_of(page);
    let mut restored = None;
    // A page the pool holds is not a reservation's to zero.
    let src = match if resv::ENABLED && stored.is_none() { run_frame(root, page, &r) } else { None } {
        Some(s) => s,
        None => {
            let req = PageRequest { obj: r.obj, page: r.page_index(page), write: r.write, space: root, va: page, stored };
            // Anonymous memory: the file regions took their own path above.
            match AnonPager.supply(&req)? {
                Supply::Frame(f) => Source::Plain(f),
                Supply::Restored(f, gen, owner) => {
                    restored = Some((gen, owner));
                    Source::Plain(f)
                }
                // Another thread installed the page first, and (the entry
                // being gone) the slot says what it is now.
                Supply::Raced => {
                    return if peek(root, page) == seen {
                        // The slot still names a page the pool no longer
                        // holds: it is lost, and the task that touched it dies.
                        Err(KernelError::InvalidArg)
                    } else {
                        Ok(Step::Again)
                    };
                }
                Supply::Pending => return Err(KernelError::NotMapped),
            }
        }
    };
    let (Source::Plain(frame) | Source::Run { frame, .. }) = src;
    let pte_ptr = match vmm::walk(root, page, true) {
        Ok(p) => p,
        Err(e) => {
            src.give_back(root, block);
            return Err(e);
        }
    };
    let perms = PagePerms {
        user: true,
        read: true,
        write: r.write,
        exec: false,
        accessed: true,
        dirty: r.write,
        ..PagePerms::USER_RW
    };
    let new = match ARCH.pte_make_leaf(frame.as_usize(), perms, 0) {
        Ok(w) => w,
        Err(_) => {
            src.give_back(root, block);
            return Err(KernelError::InvalidArg);
        }
    };

    let mut t = TABLE.lock_irqsave();
    let same = t.slot(root).and_then(|i| {
        t.s[i].set.find(page).filter(|now| now.write == r.write && now.pager == r.pager && now.obj == r.obj).map(|_| i)
    });
    let Some(i) = same else {
        // Unmapped or re-protected since the lookup: look again and let the
        // new layout answer (a removed region then kills, as any hole does).
        drop(t);
        src.give_back(root, block);
        return Ok(Step::Again);
    };
    // SAFETY: `pte_ptr` is an aligned entry of a live table page (the region
    // still exists, so `munmap` has not swept it).
    let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
    // Compare-and-swap from the word the decision was made on, as `demand.rs`
    // does: installs are serialised by the table lock, but the entry is shared
    // with walkers that do not take it (a fork, the reclaimer, `munmap`). A
    // word that is not the one the fault read, a marker included, is not
    // replaced: that is the whole point of the marker.
    if slot.compare_exchange(seen, new, Ordering::AcqRel, Ordering::Acquire).is_err() {
        drop(t);
        src.give_back(root, block);
        return Ok(Step::Again);
    }
    t.s[i].committed += 1;
    drop(t);
    ARCH.flush_tlb_page(page);
    if let Some((gen, owner)) = restored {
        zpool_release(root, page, gen);
        restore_hook(owner);
    }
    if let Source::Run { run, idx, .. } = src {
        after_install(root, block, run, idx, r.write);
    }
    Ok(Step::Done)
}

/// Is `va` reserved and not committed, and would its page be writable? For
/// the kernel's "may I copy into this user range" checks: a reserved page is
/// committed by the copy itself (`vmm::translate_user`).
pub fn reserved_writable(root: usize, va: usize) -> Option<bool> {
    let t = TABLE.lock_irqsave();
    let i = t.slot(root)?;
    t.s[i].set.find(va & !(PAGE_SIZE - 1)).map(|r| r.write)
}

/// Does a region hold `va`?
pub fn contains(root: usize, va: usize) -> bool {
    reserved_writable(root, va).is_some()
}

/// Most sub-ranges one removal can produce: one per record.
const MAX_PIECES: usize = REGIONS_PER_SPACE;

/// Can any slot hold a page marker: the pool has pages, or a store is in
/// flight? When not, the paths that clear markers skip their walk.
fn marks_possible() -> bool {
    zpool::ENABLED && (ZSTORED.load(Ordering::Acquire) != 0 || RECLAIMING.load(Ordering::Acquire) != 0)
}

/// Empty the slot of the page at `va` of `root` if it holds a page marker, and
/// say which kind.
fn clear_marker(root: usize, va: usize) -> Option<PageMarker> {
    if vmm::write_would_enter_kernel_table(root, va) {
        return None;
    }
    let p = vmm::walk(root, va, false).ok()?;
    // SAFETY: `walk` answers an aligned entry of a live table page.
    zpool::clear(&ARCH, unsafe { &*(p as *const core::sync::atomic::AtomicU64) }).map(|(kind, _)| kind)
}

/// Take `[s, e)` out of every region under `root`, for `munmap` and
/// `mprotect(PROT_NONE)`. Returns the reserved pages in the range that were
/// never committed: the caller discharges those itself, and its sweep frees
/// (and discharges) the committed ones. Call it **before** the sweep: once
/// it returns, no fault can commit a page in the range.
///
/// `Full` (nothing changed) when cutting a region in two needs a record the
/// space does not have.
pub fn release_range(root: usize, s: usize, e: usize) -> Result<usize, RegionError> {
    // `(start, end, pays, file object)` of each piece.
    let mut pieces = [(0usize, 0usize, false, None::<u32>); MAX_PIECES];
    let mut np = 0;
    {
        let mut t = TABLE.lock_irqsave();
        let Some(i) = t.slot(root) else { return Ok(0) };
        // A file region goes whole or not at all, or the page cache's count of
        // regions would be wrong (`RegionSet::file_cut_ok`).
        if !t.s[i].set.file_cut_ok(s, e) {
            return Err(RegionError::Invalid);
        }
        t.s[i].set.for_each_overlap(s, e, |a, b, reg| {
            let file = (reg.pager == PagerKind::File).then_some(reg.obj);
            pieces[np] = (a, b, reg.charged(), file);
            np += 1;
        });
        if np == 0 {
            return Ok(0);
        }
        t.s[i].set.remove_range(s, e)?;
    }
    // The cut breaks every reservation it touches (no new frame comes out of
    // one for the removed part: the fault path needs the block whole).
    break_range(root, s, e);
    // Are there markers to look for? Asked before the pool's pages go, which
    // is what makes the answer zero: a marker outlives its entry only here.
    let marked = marks_possible();
    // The pages of the pool in the removed pieces are gone with them.
    for &(a, b, _, _) in &pieces[..np] {
        zpool_discard(root, a, b);
    }
    // Outside the lock: nothing can commit in these pieces any more, and the
    // walk is up to 16,384 entries (64 MiB) — not with interrupts off.
    // `paid`: reserved pages of the pieces the task paid for; the committed
    // ones of them are the sweep's to discharge, the rest are returned.
    let mut paid = 0usize;
    let mut committed = 0usize;
    let mut paid_committed = 0usize;
    for &(a, b, pays, _) in &pieces[..np] {
        let mut va = a;
        while va < b {
            let mut here = matches!(vmm::user_page(root, va), vmm::UserPage::Leaf { .. });
            // The marker goes (it would make the range look occupied to the
            // next `mmap`). A store that fails meanwhile puts the leaf back
            // under the clear: the page is then resident after all, and the
            // sweep's to free.
            let mut cleared = None;
            if !here && marked {
                cleared = clear_marker(root, va);
                if cleared.is_none() {
                    here = matches!(vmm::user_page(root, va), vmm::UserPage::Leaf { .. });
                }
            }
            // A page the pool holds (or swap) gave its charge back when the
            // reclaimer took it out: nothing to return for it. A page in
            // transit has not given it back, and its store, which fails now,
            // never will; but it was resident, so it is a committed page of
            // the space that the sweep does not see.
            let out = matches!(cleared, Some(PageMarker::Compressed | PageMarker::Swapped));
            committed += (here || cleared == Some(PageMarker::InTransit)) as usize;
            if pays {
                paid += 1;
                paid_committed += (here || out) as usize;
            }
            va += PAGE_SIZE;
        }
    }
    let mut t = TABLE.lock_irqsave();
    if let Some(i) = t.slot(root) {
        t.s[i].committed = t.s[i].committed.saturating_sub(committed);
        if t.s[i].set.is_empty() {
            t.drop_slot(i);
        }
    }
    drop(t);
    // The regions are gone: their users in the page cache with them.
    if let Ok(ff) = file_frames() {
        for &(_, _, _, file) in &pieces[..np] {
            if let Some(obj) = file {
                ff.unref(obj);
            }
        }
    }
    Ok(paid - paid_committed)
}

/// Set the write permission of every region page in `[s, e)` (`mprotect` to
/// `PROT_READ` or read-write). Pages already committed are the caller's to
/// re-protect (`vmm::protect_user_range`). `Full`, nothing changed, when a
/// cut needs records the space does not have.
pub fn protect_range(root: usize, s: usize, e: usize, write: bool) -> Result<(), RegionError> {
    let r = {
        let mut t = TABLE.lock_irqsave();
        match t.slot(root) {
            // A file region keeps the permission it was mapped with: a shared
            // one's dirty record in the page cache is made from it.
            Some(i) if t.s[i].set.has_file(s, e) => Err(RegionError::Invalid),
            Some(i) => t.s[i].set.protect_range(s, e, write),
            None => Ok(()),
        }
    };
    // New permissions on part of a block, or the whole of one: the frames not
    // handed out yet go back, and what is installed is the sweep's.
    if r.is_ok() {
        break_range(root, s, e);
    }
    r
}

/// Give a fork's child (`child`) the parent's (`parent`) reservation: the
/// same regions, not the pages (the parent's committed region pages reach
/// the child through the copy-on-write fork). Returns the reserved pages the
/// child holds uncommitted, for the caller to charge to the child.
///
/// **The child's committed count is the child's own** (wave 14, FORKSPAWN):
/// its region pages present in ITS table, counted after the copy-on-write
/// walk, not the parent's counter. A sibling thread of a multithreaded
/// parent can commit a region page after the walk passed it and before this
/// runs: the parent's counter then includes a page the child does not have,
/// and the child was charged one page short and could commit it unpaid. The
/// region set itself cannot change meanwhile (the caller holds the group's
/// `mm_lock`), and nothing runs on the child's table yet, so the count is
/// exact.
pub fn fork_clone(parent: usize, child: usize) -> Result<usize, RegionError> {
    let mut spans = [(0usize, 0usize); REGIONS_PER_SPACE];
    let mut ns = 0;
    // The private file regions the child now holds, for the page cache's count.
    let mut files = [0u32; REGIONS_PER_SPACE];
    let mut nf = 0;
    let reserved = {
        let mut t = TABLE.lock_irqsave();
        let Some(p) = t.slot(parent) else { return Ok(0) };
        if t.s[p].set.is_empty() {
            return Ok(0);
        }
        let c = t.slot_or_new(child).ok_or(RegionError::Full)?;
        // `slot_or_new` never moves an existing slot, so `p` is still the parent.
        if c != p {
            let (src, dst) = if p < c {
                let (a, b) = t.s.split_at_mut(c);
                (&a[p], &mut b[0])
            } else {
                let (a, b) = t.s.split_at_mut(p);
                (&b[0], &mut a[c])
            };
            dst.set.copy_from(&src.set);
            dst.committed = 0;
            // A shared file mapping is not inherited: its pages are the
            // cache's frames in the parent's shm window, which the fork walk
            // leaves out of the child, as it does every shared mapping.
            for r in src.set.as_slice() {
                if r.pager == PagerKind::File && r.shared {
                    // Whole regions: cannot need a record.
                    let _ = dst.set.remove_range(r.start, r.end);
                }
            }
            if dst.set.is_empty() {
                t.drop_slot(c);
                return Ok(0);
            }
        }
        for r in t.s[p].set.as_slice() {
            if !r.charged() {
                continue;
            }
            if ns < spans.len() {
                spans[ns] = (r.start, r.end);
                ns += 1;
            }
            if r.pager == PagerKind::File && nf < files.len() {
                files[nf] = r.obj;
                nf += 1;
            }
        }
        t.s[p].set.charged_pages()
    };
    // Outside the lock, as `release_range`'s sweep: a walk of the child's
    // own leaf tables over the regions.
    let committed: usize = if cfg!(feature = "fork-commit-race-canary") {
        let t = TABLE.lock_irqsave();
        t.slot(parent).map_or(0, |p| t.s[p].committed)
    } else {
        spans[..ns].iter().map(|&(a, b)| vmm::user_leaves_in(child, a, b)).sum()
    };
    if nf != 0 {
        if let Ok(ff) = file_frames() {
            for &obj in &files[..nf] {
                ff.addref(obj);
            }
        }
    }
    // The pages the parent has compressed are the child's too: a share of the
    // pool's entries, and a copy of the parent's marker for each.
    let marked = marks_possible();
    if zpool_dup(parent, child).is_err() {
        // The fork is refused: the child's copy of the regions goes too.
        forget(child);
        return Err(RegionError::Full);
    }
    let copied = if marked { copy_markers(parent, child, &spans[..ns]) } else { Ok(0) };
    let Ok(copied) = copied else {
        forget(child);
        return Err(RegionError::Full);
    };
    let mut t = TABLE.lock_irqsave();
    if let Some(c) = t.slot(child) {
        t.s[c].committed = committed;
    }
    // A page behind a marker is not charged (the reclaimer gave the charge
    // back), in the child as in the parent.
    Ok(reserved.saturating_sub(committed).saturating_sub(copied))
}

/// Give the child's slots the parent's page markers over `spans`, word for
/// word (the pool's shared entries have the parent's generations, so the same
/// word names the child's copy). How many. Table allocation can fail: the
/// fork is then refused. No store of the parent is in flight (`fork_begin`
/// waited for them and the pages the walk left valid are shared with the
/// child, so the reclaimer takes none), so no marker is `InTransit`.
fn copy_markers(parent: usize, child: usize, spans: &[(usize, usize)]) -> KResult<usize> {
    let mut n = 0;
    for &(a, b) in spans {
        let mut va = a;
        while va < b {
            if let Ok(p) = vmm::walk(parent, va, false) {
                // SAFETY: `walk` answers an aligned entry of a live table page.
                let word = unsafe { core::ptr::read_volatile(p) };
                if let Some((PageMarker::Compressed | PageMarker::Swapped, _)) = ARCH.pte_marker(word) {
                    let c = vmm::walk(child, va, true)?;
                    // SAFETY: the child's own entry, which only this fork writes.
                    let slot = unsafe { &*(c as *const core::sync::atomic::AtomicU64) };
                    // Over an empty slot only. The walk left the page out
                    // (it was a marker), so an empty slot is the usual case;
                    // a leaf here is a page the parent got back and lost again
                    // since the walk, which the child holds from the walk and
                    // must keep: its copy in the pool is dropped, not used.
                    if slot.compare_exchange(0, word, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                        n += 1;
                    } else {
                        zpool_discard(child, va, va + PAGE_SIZE);
                    }
                }
            }
            va += PAGE_SIZE;
        }
    }
    Ok(n)
}

/// Forget every region of `root` (its page table is being destroyed).
pub fn forget(root: usize) {
    let mut files = [0u32; REGIONS_PER_SPACE];
    let mut nf = 0;
    {
        let mut t = TABLE.lock_irqsave();
        if let Some(i) = t.slot(root) {
            for r in t.s[i].set.as_slice() {
                if r.pager == PagerKind::File && nf < files.len() {
                    files[nf] = r.obj;
                    nf += 1;
                }
            }
            t.drop_slot(i);
        }
    }
    break_root(root);
    zpool_forget(root);
    // The regions are gone: their users in the page cache with them.
    if nf != 0 {
        if let Ok(ff) = file_frames() {
            for &obj in &files[..nf] {
                ff.unref(obj);
            }
        }
    }
}

/// `(reserved, committed)` region pages under `root`, for tests and reports.
pub fn space_pages(root: usize) -> (usize, usize) {
    let t = TABLE.lock_irqsave();
    match t.slot(root) {
        Some(i) => (t.s[i].set.reserved_pages(), t.s[i].committed),
        None => (0, 0),
    }
}

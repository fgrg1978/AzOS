// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! MemObj: the one kernel object for memory that is named, charged,
//! transferred or shared (owner decision D4/L6).
//!
//! It absorbed `shm.rs` (the region table), the tracer's private regions, the
//! demand reservation of the old allocation call. A buffer travels to another
//! task as a MOVE or a SHARE through an endpoint.
//! A MemObj is named by a `Cap<Shm>` (the cap kind and its syscalls are frozen
//! by D0: `SYS_SHM_*_TYPED` keep their numbers and gain fields in their
//! arguments).
//!
//! # Kinds
//!
//! | kind       | frames                                  | charged | freed with it |
//! |------------|-----------------------------------------|---------|---------------|
//! | [`MemKind::Anon`]   | one frame per page, zeroed at create | yes     | yes           |
//! | [`MemKind::Contig`] | physically contiguous run, zeroed  | yes     | yes           |
//! | [`MemKind::Paged`]  | file pages, filled on demand, droppable  | no      | yes (clean or flushed) |
//!
//! A `Phys` kind (device or scanout memory with a memory type) is not built: it
//! waits for its first user, the framebuffer handed to a ring-3 display server.
//!
//! An Anon object that is only ever mapped by one task does not need a table
//! slot: [`anon_map_private`] is that case, on the marker-PTE fast path of
//! `azos_mm::demand` (no frame until the first touch, no lock on the fault).
//! A shared Anon object has its frames at create because every mapper needs
//! the same frames and the fault path would have to ask the object; that is
//! the pager (`Paged`), not built.
//!
//! # Paged objects: the page cache
//!
//! A [`MemKind::Paged`] object is a window of up to [`MAX_MEMOBJ_PAGES`] pages
//! of one file, and it IS that file's page cache: a cached page is one of its
//! frames (`phys_pages[i] != 0`), the frame a mapper maps, the frame the kernel
//! reads and writes. There is no second cache to keep coherent. The pages come
//! from the file through a [`PageBacking`] callback (`azos_mm::pager`, the file
//! layer implements it) and are filled on first use, outside every lock.
//!
//! * kernel-made only ([`memobj_create_paged`]; ring 3 cannot create one), kernel-owned and
//!   charged to no Domain, like the other kernel objects: the cache is system
//!   memory that gives itself back under pressure, as the next two lines say;
//! * a clean page is droppable at any time ([`memobj_paged_drop_clean`]): the
//!   object's mapping list unmaps it everywhere (the rmap), the frame goes back
//!   to the allocator, and the next use reads it again. A page is never
//!   compressed (the reclaimer's source, `azos_mm::pager::AnonReclaim`, offers
//!   anonymous region pages only); the file already holds a copy;
//! * a dirty page is written back ([`memobj_paged_writeback_ref`]) and then clean. It
//!   is dirty from a kernel write ([`memobj_paged_write_ref`]), a
//!   `write` request of [`memobj_paged_frame_ref`], and for as long as a
//!   writable mapping reaches it (no PTE dirty bit is read yet, so a writable
//!   mapping is taken to be writing). A dirty page is never dropped;
//! * an object never changes the file's length: the cache clamps reads and
//!   write-backs to the size it was attached at ([`memobj_paged_set_size_ref`]
//!   re-attaches it when the file layer lengthened or cut the file);
//! * [`memobj_paged_close_ref`] is the one way a dirty object ends: flush, then the
//!   kernel's reference goes, and the frames with it. The release of the last
//!   reference by any other path frees the frames as it does for any object and
//!   would lose a dirty page.
//!
//! A file `mmap` faults these pages into its regions (`azos_mm::pager`, the file
//! pager; `azos_syscall::file_map` makes the objects, one per 64-page window of
//! a file, and books the shared mappings), and the file layer's `read` and
//! `write` go through the same objects (`file_map::cache_*`, the kernel's
//! `PageCacheHooks`). The write-back on a timer and at the dirty watermark is
//! the file layer's (`fs-wb`, per file and per Domain); under pressure it is
//! [`memobj_paged_reclaim`]. Not here: a mapping list that names more than one
//! mapping per task.
//!
//! # Attributes
//!
//! [`ATTR_SWAPPABLE`] (opt-in for a reclaimer of MemObj frames, which does not
//! exist yet: only a guest's memory check reads it), [`ATTR_NO_KERNEL_MAP`] (the kernel
//! never reads the object through the direct map: `memobj_with_word_ref`
//! refuses it), [`ATTR_VOLATILE`] (purgeable: see the next section).
//!
//! # Volatile objects: memory that may be dropped under pressure
//!
//! An Anon object created with [`ATTR_VOLATILE`] may give its contents up
//! instead of being swapped: a scratch the owner can rebuild (decoded weights,
//! a rendered-surface cache; `infsrv`'s blob arena is the one in the tree). The owner
//! says when it does not need the contents ([`memobj_set_volatile_ref`]); from
//! then until it says it does, the memory reclaim pass ([`memobj_purge_volatile`],
//! stage 0 of `azos_mm::zpool::reclaim_pass`: the cheapest, nothing is written)
//! may take the object's frames. The object has three states:
//!
//! | state    | frames | set by                                              |
//! |----------|--------|-----------------------------------------------------|
//! | Held     | yes    | create, [`memobj_set_volatile_ref`]`(false)`        |
//! | Volatile | yes    | [`memobj_set_volatile_ref`]`(true)`                 |
//! | Purged   | no     | [`memobj_purge_volatile`] on a Volatile object      |
//!
//! A purge unmaps the object from every holder (the mapping list, as a page
//! drop does), gives the frames back to the allocator, gives the charge back to
//! the Domain, and writes one `Rule::Purge` record. **Nothing is written
//! anywhere**: the contents are gone. Purged is final for the object: the
//! next map answers [`MemObjError::Purged`] (`-EPURGED`), as does a clone, and
//! [`memobj_set_volatile_ref`] answers `true` ("it was purged") to either
//! toggle; the holder lets go of the object and creates a new one. A task
//! that touches a mapping while the object is Volatile may find the page
//! gone (a fault): the owner stops using the object before it says so.
//!
//! Never purged: a Held object; one with a pinned holder (a failed map may
//! have left PTEs the mapping list does not name); one the kernel holds a
//! reference to (a guest's RAM, a pipe the kernel reads: it keeps direct-map
//! addresses to the frames); one whose frames a clone shares; and one charged
//! to a Domain on a `mem = "locked"` row (real-time memory is committed at map
//! time and is never reclaimed).
//!
//! Stage 0 belongs to the reclaim task, which exists only with
//! `MM_RECLAIM_COMPRESS`: on a `MM_RECLAIM_OFF` image a Volatile object is
//! never purged.
//!
//! # Operations
//!
//! * create: [`memobj_create_spec`] (ring 3: Anon, or Contig for memory a device
//!   reads or writes), [`memobj_create_kernel`] (Contig, kernel-owned);
//! * map and unmap: the mapping a task made is recorded per holder
//!   ([`MemHolder::map_va`]); the access it was allowed is recorded with it, so
//!   a map never gives more than the capability had ([`memobj_resolve_map`]);
//! * protect: [`memobj_protect_ref`] changes the access of a recorded
//!   mapping within what the map was allowed (`SYS_MO_MAP`'s second argument);
//! * revoke: a share is taken back with the warrant it derived from
//!   (`SYS_CAP_REVOKE`): [`memobj_warrant_swept`] takes the Domain of every
//!   swept `Cap<Shm>` out of the object, unmapping its holders' mappings on every
//!   hart and giving back their references. It reads the object's mapping list
//!   (its holder table, bounded by [`MAX_MEMOBJ_HOLDERS`]); no page table is
//!   scanned;
//! * clone: [`memobj_clone`] (COW: frames shared through the frame refcount until
//!   a write mapping or [`memobj_cow_break`] gives the clone its own);
//! * MOVE: [`memobj_move`] hands a task's references, its charge (when it holds
//!   the owning reference) and its ownership to another task and drops the
//!   sender's mapping; the capability travels by the IPC transfer's MOVE entry;
//! * SHARE: the IPC transfer's DUP entry (needs `DUP` and `TRANSFER` on the
//!   sender's capability) derives an attenuated warrant
//!   (`cap_store::move_caps`); the receiver takes its own reference and its map
//!   is bounded by the rights it got.
//!
//! # Charge
//!
//! The frames of an Anon or Contig object are charged to the Domain of the
//! task that holds the owning reference ([`MemObj::charge_key`]) and given
//! back to that Domain when the last reference goes. A MOVE of the owning
//! reference charges the receiver's Domain first (all or nothing) and then
//! gives the sender's back.
//!
//! Allows two or more processes to map the same physical pages into their
//! address spaces for zero-copy data sharing (e.g., camera frames, LiDAR scans).

use crate::cap::ty;
use core::sync::atomic::{AtomicU32, Ordering};
use azos_sync::SpinLock;

use crate::cap::objref;
use crate::cap::{CapError, CapType};
use azos_mm::pager::{PageBacking, PageIoError, PageKey};

/// How a `Cap<Shm>` packs `(index, generation)`: 8 + 24 bits (`objref::SHM`).
const LAYOUT: objref::Layout = objref::SHM;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of MemObjs system-wide (Kconfig `MAX_MEMOBJS`).
pub const MAX_MEMOBJS: usize = azos_limits::MAX_MEMOBJS as usize;

/// Maximum pages per shared memory region (64 pages = 256 KiB).
pub const MAX_MEMOBJ_PAGES: usize = 64;

/// Maximum number of distinct tasks that may hold a reference to one region
/// at the same time. The holder table is also the object's reverse map: each
/// holder carries at most one recorded mapping (its address space and VA), so
/// this is the bound of the mapping list a revoke and a page drop
/// walk ([`memobj_warrant_swept`], [`memobj_paged_drop_clean`])
/// instead of scanning page tables. A mapper beyond it is refused at the
/// acquire. Kconfig symbol `MEMOBJ_MAX_HOLDERS` (default 8) once `config/`
/// carries it; until then this constant is the default.
///
/// WHY a bound exists at all: references are now tracked *per task*
/// (see [`MemHolder`]), which needs somewhere to put the per-task counter.
/// A fixed array keeps the whole table in BSS with no allocator on the IPC
/// path. Eight simultaneous sharers per region is well beyond anything the
/// robot's pipelines do (producer + a handful of consumers); exhausting it
/// fails the *acquire*, it never corrupts accounting.
pub const MAX_MEMOBJ_HOLDERS: usize = 8;

/// A `Cap<Shm>` stores a packed `(index, generation)` with `LAYOUT.idx_bits()`
/// of index, so every region index must fit them.
const _: () = assert!(MAX_MEMOBJS <= 1 << LAYOUT.idx_bits());

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Permission flags for a shared memory region.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemPerms {
    ReadOnly,
    ReadWrite,
}

/// What a MemObj is made of (module doc, "Kinds").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MemKind {
    /// Zero-filled frames, one per page.
    Anon = 0,
    /// Device or scanout memory at a fixed physical address; never freed.
    /// A physically contiguous, zeroed run of frames.
    Contig = 2,
    /// File-backed pages, the page cache: frames come from a [`PageBacking`]
    /// on first use and go back when clean (module doc, "Paged objects").
    /// Ring 3 cannot create one: [`memobj_create_spec`] refuses it.
    Paged = 3,
}

impl MemKind {
    /// The kind a syscall argument names, `None` for an unknown value.
    pub const fn from_raw(v: u8) -> Option<MemKind> {
        match v {
            0 => Some(MemKind::Anon),
            2 => Some(MemKind::Contig),
            3 => Some(MemKind::Paged),
            _ => None,
        }
    }
}

/// The frames may be taken by a reclaimer. None reads it yet: a MemObj frame
/// taken out of its mappings has no fault path to restore it (the shm window is
/// not a pager Region), so the compressed pool takes anonymous region pages
/// only (`azos_mm::pager::AnonReclaim`). Kept as the object's opt-in for the
/// front that adds one; a guest's memory (`syscall/vm.rs`) refuses an object
/// that carries it.
pub const ATTR_SWAPPABLE: u8 = 1 << 0;
/// The kernel never reads the object through the direct map.
pub const ATTR_NO_KERNEL_MAP: u8 = 1 << 1;
/// Purgeable: the owner may mark the object volatile
/// ([`memobj_set_volatile_ref`]), and while it is, memory reclaim may drop its
/// frames without writing them ([`memobj_purge_volatile`]). Anon objects only.
pub const ATTR_VOLATILE: u8 = 1 << 2;
const ATTRS_KNOWN: u8 = ATTR_SWAPPABLE | ATTR_NO_KERNEL_MAP | ATTR_VOLATILE;

/// What to create: the kind, the access mode and the attributes. Built with
/// [`MemSpec::anon`] and the `with_*` methods.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemSpec {
    pub kind: MemKind,
    pub perms: MemPerms,
    pub attrs: u8,
    /// Contig only: a device may be given this memory (a DMA or accelerator
    /// buffer). Recorded; the IOMMU seam reads it.
    pub device_visible: bool,
}

impl MemSpec {
    /// An Anon object of the given access mode, no attributes.
    pub const fn anon(perms: MemPerms) -> MemSpec {
        MemSpec { kind: MemKind::Anon, perms, attrs: 0, device_visible: false }
    }
    /// A Contig object of the given access mode.
    pub const fn contig(perms: MemPerms, device_visible: bool) -> MemSpec {
        MemSpec { kind: MemKind::Contig, perms, attrs: 0, device_visible }
    }
    pub const fn with_attrs(mut self, attrs: u8) -> MemSpec {
        self.attrs = attrs;
        self
    }
}

/// Per-task reference accounting for one region.
///
/// **WHY this exists (W3-F1):** a bare reference count is an integer that any
/// caller could decrement. `SYS_IPC_UNSHARE` took a raw userspace `shm_id`
/// and called `memobj_release` unconditionally, so a task could drop references
/// it never took — sixteen guesses were enough to drive any live region's
/// count to zero, which frees every `phys_pages[i]` back to the PMM while the
/// real holders' `USER_RW` PTEs stay valid. Recording *who* took each
/// reference makes a release only able to give back what the caller actually
/// holds.
#[derive(Clone, Copy)]
pub struct MemHolder {
    /// TID of the holding task. Meaningful only when `refs > 0`.
    pub tid: u32,
    /// References this task currently holds (create counts as one, each
    /// successful `memobj_acquire_ref` counts as one). `0` ⇒ free holder slot.
    ///
    /// A task names all of them through one `Cap<Shm>`, and the typed release
    /// revokes that capability, so it gives every one of them back at once
    /// ([`memobj_release_holder_ref`]); only a [`pinned`](Self::pinned) reference
    /// waits for the task's exit.
    pub refs: u32,
    /// User virtual base address this task mapped the region at via
    /// `shm_map_user`, or `0` if it has no live mapping.
    ///
    /// **WHY the VA is recorded:** the pages must never go back to the PMM
    /// while a user page table still points at them. Keeping the VA is what
    /// lets the release path tear the mapping down *before* the refcount can
    /// reach zero — see [`memobj_take_mapping`].
    pub map_va: usize,
    /// Number of pages mapped at `map_va` (0 when `map_va == 0`).
    pub map_pages: usize,
    /// This task may have PTEs into the region that `map_va` does not name:
    /// a `SYS_MO_MAP` failed after its reference was taken, and
    /// `shm_map_user` returns `None` from a partial mapping. Set by
    /// [`memobj_pin_ref`]. While set, the typed release keeps one reference, so no
    /// frame returns to the PMM under those PTEs; the task's exit
    /// (`memobj_release_all`) gives it back, when its address space is gone.
    pub pinned: bool,
    /// The page-table root `map_va` lives in (the process's, at map time). Valid
    /// while `map_va != 0`: exec and exit clear the record before the root is
    /// freed ([`memobj_exec`], [`memobj_release_all`]), so a MOVE or a protect
    /// that finds it under the table lock finds a live address space.
    pub map_root: usize,
    /// The mapping at `map_va` is writable now.
    pub map_write: bool,
    /// The most the mapping may be made writable again: the access the
    /// capability allowed when the map was made (`WRITE` on a writable
    /// object). [`memobj_protect_mapping`] never goes past it.
    pub map_max_write: bool,
    /// The ends of a POSIX pipe this task holds on the region
    /// ([`PIPE_END_READ`], [`PIPE_END_WRITE`]; see the pipe section below).
    /// Meaningful only when the region is a pipe; kept here, in the kernel,
    /// and not in the region, so no kill can separate a task's record of an
    /// end from the count it stands for.
    pub ends: u8,
}

impl MemHolder {
    pub const fn empty() -> Self {
        Self { tid: 0, refs: 0, map_va: 0, map_pages: 0, pinned: false, map_root: 0, map_write: false, map_max_write: false, ends: 0 }
    }

    /// Does this holder have a mapping recorded: a live reference and a VA?
    #[inline]
    fn is_mapped(&self) -> bool {
        self.refs > 0 && self.map_va != 0
    }

    /// Forget the recorded mapping; the references stay.
    #[inline]
    fn clear_mapping(&mut self) {
        self.map_va = 0;
        self.map_pages = 0;
        self.map_root = 0;
        self.map_write = false;
        self.map_max_write = false;
    }
}

/// A shared memory region.
pub struct MemObj {
    /// Physical addresses of allocated pages (0 = unused slot in page array).
    pub phys_pages: [usize; MAX_MEMOBJ_PAGES],
    /// Number of pages allocated.
    pub page_count: usize,
    /// Task that created this region. Read by [`memobj_owner`]; the untyped
    /// `SYS_IPC_MAP` gated on it until generation-stamped handles retired that call.
    pub owner_task: u32,
    /// Permissions.
    pub perms: MemPerms,
    /// Whether this slot is active.
    pub active: bool,
    /// Generation of the region in this slot: stamped by
    /// `memobj_create`, 0 while the slot is free.
    ///
    /// A `Cap<Shm>` stores `(slot, generation)` and resolves only while both
    /// match, so a capability to a freed region never reaches the next region
    /// created at its index, in any task's table. Cleared with the slot, which
    /// `MemObj::empty()` does at the last reference and at the OOM rollback
    /// — never at a holder's decrement, which leaves the region live for its
    /// other holders.
    pub generation: u32,
    /// Per-task reference accounting. See [`MemHolder`].
    pub holders: [MemHolder; MAX_MEMOBJ_HOLDERS],
    /// What the object is made of.
    pub kind: MemKind,
    /// `ATTR_*` bits.
    pub attrs: u8,
    /// Contig: a device may be given this memory.
    pub device_visible: bool,
    /// The Domain the frames are charged to (`azos_sched::domain` key), 0 for
    /// none: a kernel-owned object, covered by the kernel reserve.
    /// It is now the holder's Domain and no longer the creating task's
    /// budget: the last reference gives the charge back to this Domain from
    /// whichever task drops it, and a MOVE of the owning reference changes it.
    pub charge_key: u32,
    /// KMEM-CHARGE: the Domain the region's metadata ([`MEMOBJ_KMEM_BYTES`]) is
    /// charged to, `0` for none. The creator's, for the object's whole life: a
    /// MOVE changes `charge_key` and not this, so the charge is taken and
    /// given back outside the table lock (a refusal writes a decision record,
    /// which may flush to the medium).
    pub meta_key: u32,
    /// Pages whose frame another object shares (a COW clone): bit `i` is page
    /// `i`. Cleared per page by [`memobj_cow_break`]; a mapping for write
    /// breaks every set bit first.
    pub cow_shared: u64,
    /// This object's own packed `(index, generation)` reference: what the frame
    /// descriptors of its pages name as their holder (`FrameDesc::owner`, the
    /// reverse map). `0` while the slot is free.
    ident: u32,
    /// Paged only: the file and the cache's state of its pages.
    paged: Option<PagedState>,
    /// [`ATTR_VOLATILE`] objects only: whether reclaim may take the frames now
    /// (module doc, "Volatile objects").
    purge: PurgeState,
}

/// Where a volatile object stands (module doc, "Volatile objects"). Always
/// `Held` for an object without [`ATTR_VOLATILE`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PurgeState {
    /// In use: the frames stay.
    Held,
    /// The owner does not need the contents now: reclaim may drop the frames.
    Volatile,
    /// Reclaim dropped the frames. Final.
    Purged,
}

/// The state of a Paged object that an Anon one has no use for.
#[derive(Clone, Copy)]
struct PagedState {
    /// Where the pages come from and go back to.
    backing: &'static dyn PageBacking,
    /// The file, as its backend names it.
    key: PageKey,
    /// The file page (in units of the build's page) that page 0 of the object
    /// is: the window's place in the file.
    first: u64,
    /// The file's size in bytes: the cache's reads and write-backs stop here.
    size: u64,
    /// Pages written since they were last written back: bit `i` is page `i`.
    dirty: u64,
    /// Pages being written back now: bit `i` is page `i`. Such a page is not
    /// dropped and not written by the kernel until its write-back ends.
    flushing: u64,
}

impl MemObj {
    pub const fn empty() -> Self {
        const EMPTY_HOLDER: MemHolder = MemHolder::empty();
        Self {
            phys_pages: [0; MAX_MEMOBJ_PAGES],
            page_count: 0,
            owner_task: 0,
            perms: MemPerms::ReadOnly,
            active: false,
            generation: 0,
            holders: [EMPTY_HOLDER; MAX_MEMOBJ_HOLDERS],
            kind: MemKind::Anon,
            attrs: 0,
            device_visible: false,
            charge_key: 0,
            meta_key: 0,
            cow_shared: 0,
            ident: 0,
            paged: None,
            purge: PurgeState::Held,
        }
    }
}

/// Kernel memory one region's metadata costs the Domain that holds its
/// charge.
const MEMOBJ_KMEM_BYTES: u64 = core::mem::size_of::<MemObj>() as u64;

const _: () = assert!(MAX_MEMOBJ_PAGES <= 64, "MemObj::cow_shared is one bit per page");

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global shm region table.
///
/// Protected by a single `SpinLock` covering the whole table (same shape as
/// `port.rs`'s `PORTS`). Was previously a bare
/// `static mut` with every accessor (`memobj_create`/`shm_acquire`/
/// `shm_page_phys`/`memobj_release`/`memobj_info`) touching it under an `unsafe`
/// block with zero synchronization — reachable concurrently from any hart
/// via the syscall dispatch table, so e.g. two harts racing `memobj_create`
/// could both find the same "free" slot and both write into it. Uses
/// `lock_irqsave()` (not plain `lock()`) for the same reason `PORTS` does:
/// keeping every accessor on the same IRQ-safe discipline is what makes it
/// safe to add an IRQ-context caller later without silently reopening a
/// same-hart deadlock.
const EMPTY_MEMOBJ: MemObj = MemObj::empty();

/// The region table plus its per-slot generation sources,
/// under the same lock. `Deref`/
/// `DerefMut` to the region array so every existing `regions[i]` /
/// `regions.iter()` accessor below is unchanged; only `create_core` reads
/// `next_gen`.
struct MemObjTable {
    regions: [MemObj; MAX_MEMOBJS],
    /// Entry `i` is the generation index `i`'s *next* create will stamp.
    /// Starts at 1 (`0` doubles as the mid-sweep marker), never reset by an
    /// ordinary release — only by that slot's own targeted wrap sweep. See
    /// `objref`'s module doc ("Per-slot generations...").
    next_gen: [u32; MAX_MEMOBJS],
}

impl core::ops::Deref for MemObjTable {
    type Target = [MemObj; MAX_MEMOBJS];
    fn deref(&self) -> &Self::Target {
        &self.regions
    }
}

impl core::ops::DerefMut for MemObjTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.regions
    }
}

static MEMOBJS: SpinLock<MemObjTable> = SpinLock::new(MemObjTable {
    regions: [EMPTY_MEMOBJ; MAX_MEMOBJS],
    next_gen: [1u32; MAX_MEMOBJS],
});

// ---------------------------------------------------------------------------
// Page-table hooks (boot-registered)
// ---------------------------------------------------------------------------

/// Remove `pages` pages at `va` from the user page table rooted at `root` and
/// shoot the range down on every hart that may hold it. Frees no frame.
/// Called with the MemObj table lock held (a MOVE, a revoke, a shrink; never
/// from an interrupt), so it must not block and must take no lock that is held
/// while it is being taken. The kernel registers
/// `vmm::unmap_user_range_and_free(root, va, end, va, end)` (the skip range is
/// the whole range, so nothing is freed and `page_decref` is never reached).
pub type UnmapHook = fn(root: usize, va: usize, pages: usize);

azos_common::ro_hook! {
    static UNMAP_HOOK: UnmapHook;
}

/// Register the [`UnmapHook`]. Boot, once. Without it a revoke records the
/// window but removes no PTE (the host suite's default).
pub fn set_unmap_hook(f: UnmapHook) {
    UNMAP_HOOK.set(f);
}

/// Forget the registered page-table hooks: host-test hygiene, they are
/// process-wide.
#[cfg(not(target_os = "none"))]
pub fn __clear_hooks_for_tests() {
    UNMAP_HOOK.clear_for_tests();
    PROTECT_HOOK.clear_for_tests();
}

pub(crate) fn unmap_range(root: usize, va: usize, pages: usize) {
    if let Some(f) = UNMAP_HOOK.get() {
        f(root, va, pages);
    }
}

/// Set (`write == false`) or give back (`write == true`) the write permission
/// of the user leaves in `pages` pages at `va` of the page table rooted at
/// `root`, then shoot the range down on every hart that may hold it. Returns
/// how many leaves changed. Called under the same rules as [`UnmapHook`]. The kernel registers
/// `vmm::set_user_range_write` plus the shootdown.
pub type ProtectHook = fn(root: usize, va: usize, pages: usize, write: bool) -> usize;

azos_common::ro_hook! {
    static PROTECT_HOOK: ProtectHook;
}

/// Register the [`ProtectHook`]. Boot, once. Without it a protect records
/// the change but changes no PTE (the host suite's default).
pub fn set_protect_hook(f: ProtectHook) {
    PROTECT_HOOK.set(f);
}

pub(crate) fn protect_range(root: usize, va: usize, pages: usize, write: bool) -> usize {
    match PROTECT_HOOK.get() {
        Some(f) => f(root, va, pages, write),
        // No PTE to change: report the whole range, so the record (and a
        // host test of it) is exercised as the kernel's would be.
        None => pages,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Most MemObjs ONE task may own at once.
///
/// **The obligation the minting rule creates.** The capability design states it
/// plainly: a task may be handed a capability over an object it just created,
/// and *minting without a per-task quota is exhaustion*. `MAX_MEMOBJS` bounds
/// the pool for the WHOLE MACHINE, so before this a single ring-3 program
/// calling `memobj_create` in a loop took every slot and denied shared-memory regions to
/// everyone — the kernel's own users included.
///
/// Half the pool, mirroring `MAX_SOCKETS_PER_TASK` and `MAX_FDS_PER_TASK`:
/// enough for a program doing ordinary work, never enough for one task to lock
/// the machine out.
pub const MAX_MEMOBJS_PER_TASK: usize = MAX_MEMOBJS / 2;

/// An Anon object of `perms`, `page_count` pages; its index, or `None`.
pub fn memobj_create(owner_task: u32, page_count: usize, perms: MemPerms) -> Option<u32> {
    memobj_create_ref(owner_task, page_count, perms).map(|r| LAYOUT.idx(r))
}

/// [`memobj_create`], answering the packed `(index, generation)` reference of the
/// new region: the value a `Cap<Shm>` stores (see `objref`).
pub fn memobj_create_ref(owner_task: u32, page_count: usize, perms: MemPerms) -> Option<u32> {
    memobj_create_spec(owner_task, page_count, &MemSpec::anon(perms)).ok()
}

/// Create the object `spec` describes for `owner_task`, charging its frames to
/// the owner's Domain. Anon and Contig only. `BadArg` for a Paged spec (kernel-only, [`memobj_create_paged`]), an unknown attribute,
/// [`ATTR_VOLATILE`] on anything but an Anon object (a Contig run may be
/// handed to a device), or a page count of 0 or over [`MAX_MEMOBJ_PAGES`];
/// `NoMem` for a full table, a quota, a budget or an allocator that cannot
/// give the frames.
pub fn memobj_create_spec(owner_task: u32, page_count: usize, spec: &MemSpec) -> Result<u32, MemObjError> {
    if !matches!(spec.kind, MemKind::Anon | MemKind::Contig) {
        return Err(MemObjError::BadArg);
    }
    create_core(owner_task, page_count, spec)
}

/// The Domain `tid` charges: its task's, `0` for none (a kernel owner, a TID
/// that names no live task).
fn charge_key_of(tid: u32) -> u32 {
    if tid == MEMOBJ_KERNEL_OWNER {
        return 0;
    }
    azos_sched::idx_for_tid(tid).map_or(0, azos_sched::task_domain)
}

/// Charge a new region to the Domain `key` names: its `pages` frames (the frame
/// budget) and its metadata (the kernel-memory ledger). All or nothing. Before
/// the table's lock is taken, so a refusal's decision record is written with no
/// lock held. `key == 0` (a kernel owner) is charged nothing.
fn charge_region(key: u32, pages: usize) -> bool {
    if key == 0 {
        return true;
    }
    if !azos_sched::mm_charge_domain(key, pages as u32) {
        return false;
    }
    if !crate::cap_store::kmem_charge(key, crate::cap_store::KMEM_MEMOBJ_META, MEMOBJ_KMEM_BYTES) {
        azos_sched::mm_discharge_domain(key, pages as u32);
        return false;
    }
    true
}

/// Give back what [`charge_region`] took, for a region that was never published.
fn uncharge_region(key: u32, pages: usize) {
    if key != 0 {
        azos_sched::mm_discharge_domain(key, pages as u32);
        crate::cap_store::kmem_discharge(key, crate::cap_store::KMEM_MEMOBJ_META, MEMOBJ_KMEM_BYTES);
    }
}

/// The create body. Returns the new region's packed `(index, generation)`
/// reference.
///
/// **Per-slot generation, swept only at its own index.**
/// Each slot's generation is its own
/// (`MemObjTable::next_gen`); when slot `i`'s reaches `LAYOUT.gen_max()`, this
/// marks it mid-sweep (`next_gen[i] = 0`, which the free-slot scan already
/// treats as unavailable), releases the table lock, runs
/// `objref::sweep_index(ty::SHM, i)` — which revokes only the stale
/// `Cap<Shm>`s left over at index `i`, nothing live — resets `next_gen[i]` to
/// `1`, and retries. At most two passes: the second always finds `Gen(1)`.
/// Must not be called with a cap-table lock held.
///
/// **Pages are allocated before the table lock is taken, and zeroed once.**
/// `pmm::alloc_page` hands back a zeroed page; that is the only zero, and it
/// is what keeps a new region from showing a previous owner's bytes. This
/// used to allocate inside `MEMOBJS.lock_irqsave()` and then `write_bytes`
/// every page a second time: up to 64 pages x two 4 KiB zeroes (~1,560
/// instructions each, scalar) with interrupts off on this hart. Now the
/// interrupts-off window holds no zeroing at all. The price is ordering: a
/// cheap quota/free-slot check runs under the lock first, so an ordinary
/// refusal costs no allocation; the authoritative check is repeated when the
/// slot is claimed, and a refusal there gives every page back.
fn create_core(
    owner_task: u32,
    page_count: usize,
    spec: &MemSpec,
) -> Result<u32, MemObjError> {
    if page_count == 0 || page_count > MAX_MEMOBJ_PAGES {
        return Err(MemObjError::BadArg);
    }
    // Unknown attributes are refused whatever the kind; only Anon memory is
    // purgeable (a Contig run may be given to a device, which writes it
    // behind the purger's back).
    if spec.attrs & !ATTRS_KNOWN != 0 || (spec.attrs & ATTR_VOLATILE != 0 && spec.kind != MemKind::Anon) {
        return Err(MemObjError::BadArg);
    }
    if !has_room(&MEMOBJS.lock_irqsave(), owner_task) {
        return Err(MemObjError::NoMem);
    }

    let page = azos_arch::PAGE_SIZE;
    let mut pages = [0usize; MAX_MEMOBJ_PAGES];
    // The owner's Domain: the frames count against it,
    // charged before one is taken.
    let key = charge_key_of(owner_task);
    if !charge_region(key, page_count) {
        return Err(MemObjError::NoMem);
    }
    let uncharge = || uncharge_region(key, page_count);

    match spec.kind {
        MemKind::Contig => match azos_mm::pmm::alloc_contiguous(page_count) {
            Ok(base) => {
                for (i, p) in pages.iter_mut().enumerate().take(page_count) {
                    *p = base.as_usize() + i * page;
                }
            }
            Err(_) => {
                uncharge();
                return Err(MemObjError::NoMem);
            }
        },
        MemKind::Anon => {
            for i in 0..page_count {
                match azos_mm::pmm::alloc_page() {
                    Ok(frame) => pages[i] = frame.as_usize(),
                    Err(_) => {
                        // OOM: give back what this call already took.
                        free_frames(&pages[..i]);
                        uncharge();
                        return Err(MemObjError::NoMem);
                    }
                }
            }
        }
        // Not built from a spec: [`memobj_create_paged`] is its constructor.
        MemKind::Paged => {
            uncharge();
            return Err(MemObjError::BadArg);
        }
    }

    let r = claim_slot(owner_task, &pages[..page_count], spec, key);
    if r.is_none() {
        // Refused at claim time (quota or table filled since the pre-check):
        // the pages were never published, so they go straight back.
        free_frames(&pages[..page_count]);
        uncharge();
    }
    r.ok_or(MemObjError::NoMem)
}

/// The owner a kernel-created region is booked to: no task has this TID, so
/// no task's exit (`memobj_release_all`) and no task's quota ever touches it.
pub const MEMOBJ_KERNEL_OWNER: u32 = u32::MAX;

/// An object the KERNEL owns, for a kernel producer that writes it through the
/// direct map as one span (the tracer, the introspection regions). `spec` must be Contig: the frames are one physically contiguous
/// run. Answers the packed reference and the physical address of the first
/// byte.
///
/// Booked to [`MEMOBJ_KERNEL_OWNER`] with that owner's one reference, never
/// charged to a Domain (the kernel reserve covers it), never released: a
/// consumer's capability and mapping come and go, the kernel's reference
/// keeps the frames. Frames are zeroed (`alloc_contiguous`) and, should the
/// object ever be freed, go back one `free_page` each, which is how
/// `alloc_contiguous` frames are released.
pub fn memobj_create_kernel(page_count: usize, spec: &MemSpec) -> Option<(u32, usize)> {
    if spec.kind != MemKind::Contig {
        return None;
    }
    let r = create_core(MEMOBJ_KERNEL_OWNER, page_count, spec).ok()?;
    // The object is new and only the kernel's reference exists: its first
    // page is its base.
    let base = MEMOBJS.lock_irqsave()[LAYOUT.idx(r) as usize].phys_pages[0];
    Some((r, base))
}

/// Would `owner_task` get a slot right now: under its quota, and a free slot
/// that is not mid-sweep. Counted under the SAME lock that claims: checking the
/// quota and then taking the lock would let two of a task's own threads both
/// pass the check and both claim, which is the bug one level down. Same rule
/// and same reasoning as `socket_create`'s quota. `create_core` runs it twice:
/// as a pre-check before allocating, and again in `claim_slot`.
fn has_room(regions: &MemObjTable, owner_task: u32) -> bool {
    owns_fewer_than_quota(regions, owner_task)
        && (0..MAX_MEMOBJS).any(|i| !regions[i].active && regions.next_gen[i] != 0)
}

/// Is `owner_task` under [`MAX_MEMOBJS_PER_TASK`]? The kernel owner has no
/// quota.
fn owns_fewer_than_quota(regions: &MemObjTable, owner_task: u32) -> bool {
    owner_task == MEMOBJ_KERNEL_OWNER
        || regions.iter().filter(|r| r.active && r.owner_task == owner_task).count() < MAX_MEMOBJS_PER_TASK
}

/// Give back frames `create_core` allocated but never published.
fn free_frames(pages: &[usize]) {
    for &p in pages {
        let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(p));
    }
}

/// Claim a slot for the already-allocated, already-zeroed `pages` and publish
/// them. `None` leaves `pages` owned by the caller.
fn claim_slot(owner_task: u32, pages: &[usize], spec: &MemSpec, charge_key: u32) -> Option<u32> {
    claim_slot_cow(owner_task, pages, spec, charge_key, 0, None)
}

/// [`claim_slot`] for pages whose frames another object shares: bit `i` of
/// `cow_shared` is page `i`.
fn claim_slot_cow(
    owner_task: u32,
    pages: &[usize],
    spec: &MemSpec,
    charge_key: u32,
    cow_shared: u64,
    paged: Option<PagedState>,
) -> Option<u32> {
    // Two passes at most: the second runs only after this call's own
    // per-slot wrap sweep finishes.
    for _ in 0..2 {
        let mut regions = MEMOBJS.lock_irqsave();

        // Find and claim a free slot. Marking `active` before releasing the
        // lock (we hold it for the whole function) is what stops two harts
        // racing memobj_create() from finding and writing into the same slot.
        if !has_room(&regions, owner_task) {
            return None;
        }
        // `next_gen[i] != 0` excludes a slot this call has marked mid-sweep.
        let slot = (0..MAX_MEMOBJS).find(|&i| !regions[i].active && regions.next_gen[i] != 0)?;
        // The generation is taken once a free slot is known, so a full table
        // or a quota refusal consumes none.
        let gen = match objref::take_slot_gen(regions.next_gen[slot], LAYOUT) {
            objref::SlotGen::Gen(g) => g,
            objref::SlotGen::Wrap => {
                regions.next_gen[slot] = 0;
                drop(regions);
                objref::sweep_index(ty::SHM, slot as u32);
                regions = MEMOBJS.lock_irqsave();
                regions.next_gen[slot] = 1;
                continue;
            }
        };
        regions.next_gen[slot] = gen + 1;
        regions[slot].active = true;
        regions[slot].generation = gen;

        let region = &mut regions[slot];
        region.phys_pages[..pages.len()].copy_from_slice(pages);
        region.page_count = pages.len();
        region.owner_task = owner_task;
        region.perms = spec.perms;
        region.kind = spec.kind;
        region.attrs = spec.attrs;
        region.device_visible = spec.device_visible;
        region.charge_key = charge_key;
        region.meta_key = charge_key;
        region.cow_shared = cow_shared;
        region.paged = paged;
        region.ident = LAYOUT.pack(slot as u32, gen);
        // The reverse map: each frame this object allocated names it. A frame
        // another object shares (a COW clone) keeps naming its allocator. A
        // Paged object has no frame yet (`0`): each names it when it is filled.
        for (idx, &p) in pages.iter().enumerate() {
            if p != 0 && cow_shared & (1u64 << idx) == 0 {
                let _ = azos_mm::pmm::set_frame_owner(p, region.ident, idx as u32);
            }
        }
        // The creator's initial reference is booked against *it*, so its own
        // later `memobj_release` is the only thing that can give it back.
        region.holders[0] = MemHolder { tid: owner_task, refs: 1, ..MemHolder::empty() };

        return Some(LAYOUT.pack(slot as u32, gen));
    }
    None
}

/// TID of the task that created `shm_id`, or `None` if the slot is not active.
///
/// **WHY this is public (W3-F1):** `owner_task` was written by `memobj_create`
/// and then never read anywhere in the tree, so the field documented an
/// ownership model that nothing enforced. `SYS_IPC_MAP` (retired) read it to
/// reject a non-owner before mapping another task's camera / LiDAR /
/// inference buffers into its address space — the region index is a small
/// integer chosen by userspace, so without this the whole table was
/// enumerable in sixteen guesses.
pub fn memobj_owner(shm_id: u32) -> Option<u32> {
    if shm_id as usize >= MAX_MEMOBJS {
        return None;
    }
    let regions = MEMOBJS.lock_irqsave();
    let region = &regions[shm_id as usize];
    if region.active { Some(region.owner_task) } else { None }
}

/// The packed reference of live region `shm_id`, or `None` if its slot is not
/// active: the value a `Cap<Shm>` stores.
pub fn memobj_ref(shm_id: u32) -> Option<u32> {
    if shm_id as usize >= MAX_MEMOBJS {
        return None;
    }
    let regions = MEMOBJS.lock_irqsave();
    let region = &regions[shm_id as usize];
    if region.active { Some(LAYOUT.pack(shm_id, region.generation)) } else { None }
}

/// Resolve a packed reference to its slot, with the table lock held by the
/// caller.
///
/// `Stale` unless the slot is active and carries the reference's generation: a
/// freed slot (generation 0), a slot reused by another region, and a bare index
/// (generation 0) all answer `Stale`.
fn live_index(regions: &[MemObj; MAX_MEMOBJS], r: u32) -> Result<usize, MemObjError> {
    let i = LAYOUT.idx(r) as usize;
    let g = LAYOUT.gen(r);
    if g == 0 || i >= MAX_MEMOBJS || !regions[i].active || regions[i].generation != g {
        return Err(MemObjError::Cap(CapError::Stale));
    }
    Ok(i)
}

/// Find the holder slot for `tid`, or the first free slot. Returns
/// `(index, is_existing)`. Caller holds the table lock.
fn holder_slot(region: &MemObj, tid: u32) -> Option<(usize, bool)> {
    let mut free: Option<usize> = None;
    for i in 0..MAX_MEMOBJ_HOLDERS {
        let h = &region.holders[i];
        if h.refs > 0 && h.tid == tid {
            return Some((i, true));
        }
        if h.refs == 0 && free.is_none() {
            free = Some(i);
        }
    }
    free.map(|i| (i, false))
}

/// Acquire a reference to the region a packed reference names **on behalf of
/// `tid`**: increments the caller's per-task holder count and the region
/// refcount, and returns `(page_count, perms)`. `Stale` if the region at its
/// index is not the one it names, `Closed` if the holder table is full.
///
/// `tid` is threaded through (rather than read from the scheduler here) so
/// the kernel-internal callers — the typed `Cap<Shm>` path — stay explicit
/// about whose reference they are taking.
pub fn memobj_acquire_ref(tid: u32, r: u32) -> Result<(usize, MemPerms), MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    acquire_locked(&mut regions[i], tid).ok_or(MemObjError::Closed)
}

/// The acquire body, on an active region with the table lock held.
fn acquire_locked(region: &mut MemObj, tid: u32) -> Option<(usize, MemPerms)> {
    let (idx, existing) = holder_slot(region, tid)?;
    // `checked_add`: `refs` is driven by an unprivileged syscall loop, and
    // with `overflow-checks = true` a bare `+= 1` at u32::MAX would panic —
    // and a panic here is `panic = "abort"`, i.e. a board reset. Refuse the
    // acquire instead.
    let next = region.holders[idx].refs.checked_add(1)?;
    if existing {
        region.holders[idx].refs = next;
    } else {
        region.holders[idx] = MemHolder { tid, refs: 1, ..MemHolder::empty() };
    }
    Some((region.page_count, region.perms))
}

/// How many references the region has: the sum of its holders' `refs`, which
/// is the only record of them.
///
/// **WHY no counter beside the table.** A `u32` mirror of this sum was
/// incremented with an unguarded `fetch_add` and freed the frames when it read
/// `0`; two holders each past 2^31 acquires wrapped it to `0` while their
/// `USER_RW` PTEs were live (the OpenBSD `shm_nattch` use-after-free). A sum
/// taken in `u64` over at most [`MAX_MEMOBJ_HOLDERS`] `u32`s cannot wrap, and
/// there is nothing to drift from the holders it stands for.
#[inline]
fn total_refs(region: &MemObj) -> u64 {
    let sum: u64 = region.holders.iter().map(|h| u64::from(h.refs)).sum();
    // Canary `memobj-refcount-wrap-canary`: the sum is a `u32` that wraps, as
    // the old mirror counter did.
    if cfg!(feature = "memobj-refcount-wrap-canary") {
        u64::from(sum as u32)
    } else {
        sum
    }
}

/// Does `tid` already have a live mapping of `shm_id`?
///
/// `SYS_MO_MAP`, as the retired `SYS_IPC_MAP` did, records exactly one
/// VA per (task, region) so that the release path can always find the mapping it must tear down.
/// A second map by the same task is refused rather than silently creating an
/// untracked alias to pages the refcount thinks it can free.
pub fn memobj_has_mapping(tid: u32, shm_id: u32) -> bool {
    if shm_id as usize >= MAX_MEMOBJS {
        return false;
    }
    let regions = MEMOBJS.lock_irqsave();
    let region = &regions[shm_id as usize];
    if !region.active {
        return false;
    }
    has_mapping_locked(region, tid)
}

/// [`memobj_has_mapping`] through a packed reference.
pub fn memobj_has_mapping_ref(tid: u32, r: u32) -> Result<bool, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    Ok(has_mapping_locked(&regions[i], tid))
}

fn has_mapping_locked(region: &MemObj, tid: u32) -> bool {
    for i in 0..MAX_MEMOBJ_HOLDERS {
        let h = &region.holders[i];
        if h.refs > 0 && h.tid == tid && h.map_va != 0 {
            return true;
        }
    }
    false
}

/// `tid`'s recorded mapping of the region a packed reference names, as
/// `(va, pages)`, without clearing it (a fork asks whether the parent maps a
/// `Cap<Shm>` it hands the child, and where).
pub fn memobj_mapping_of_ref(tid: u32, r: u32) -> Result<Option<(usize, usize)>, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    Ok(regions[i].holders.iter()
        .find(|h| h.refs > 0 && h.tid == tid && h.map_va != 0)
        .map(|h| (h.map_va, h.map_pages)))
}

/// Record that `tid` mapped the region a packed reference names at `va` for
/// `pages` pages.
///
/// `Ok(false)` if the caller holds no reference, already has a mapping
/// recorded, or the arguments are degenerate — in every one of those cases
/// the caller must undo its mapping, because an unrecorded mapping is
/// precisely the state that lets `memobj_release` free pages out from under a
/// live user PTE.
pub fn memobj_note_mapping_ref(
    tid: u32,
    r: u32,
    root: usize,
    va: usize,
    pages: usize,
    access: MapAccess,
) -> Result<bool, MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    if va == 0 || pages == 0 {
        return Ok(false);
    }
    Ok(note_mapping_locked(&mut regions[i], tid, root, va, pages, access))
}

/// The access a recorded mapping has and the most it may be given back
/// ([`MemHolder::map_write`], [`MemHolder::map_max_write`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MapAccess {
    pub write: bool,
    pub max_write: bool,
}

impl MapAccess {
    /// Writable now, and may stay so.
    pub const RW: MapAccess = MapAccess { write: true, max_write: true };
    /// Read-only, and may not be made writable.
    pub const RO: MapAccess = MapAccess { write: false, max_write: false };
}

fn note_mapping_locked(region: &mut MemObj, tid: u32, root: usize, va: usize, pages: usize, access: MapAccess) -> bool {
    for i in 0..MAX_MEMOBJ_HOLDERS {
        let h = &mut region.holders[i];
        if h.refs > 0 && h.tid == tid {
            if h.map_va != 0 {
                return false; // already mapped — see memobj_has_mapping()
            }
            h.map_va = va;
            h.map_pages = pages;
            h.map_root = root;
            h.map_write = access.write;
            h.map_max_write = access.max_write;
            return true;
        }
    }
    false
}

/// Clear and return `tid`'s recorded mapping of `shm_id` as `(va, pages)`.
///
/// The syscall layer calls this **before** `memobj_release` and unmaps the
/// returned range from the caller's page table. That ordering is the whole
/// invariant: no reference may be dropped while the dropper still has PTEs
/// pointing into the region, so the refcount can never reach zero — and the
/// pages can never return to the PMM — with a live user mapping outstanding.
pub fn memobj_take_mapping(tid: u32, shm_id: u32) -> Option<(usize, usize)> {
    if shm_id as usize >= MAX_MEMOBJS {
        return None;
    }
    let mut regions = MEMOBJS.lock_irqsave();
    let region = &mut regions[shm_id as usize];
    if !region.active {
        return None;
    }
    take_mapping_locked(region, tid)
}

/// [`memobj_take_mapping`] through a packed reference.
pub fn memobj_take_mapping_ref(tid: u32, r: u32) -> Result<Option<(usize, usize)>, MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    Ok(take_mapping_locked(&mut regions[i], tid))
}

fn take_mapping_locked(region: &mut MemObj, tid: u32) -> Option<(usize, usize)> {
    take_mapping_root_locked(region, tid).map(|(_, va, pages)| (va, pages))
}

/// [`take_mapping_locked`] with the page-table root the mapping lives in.
fn take_mapping_root_locked(region: &mut MemObj, tid: u32) -> Option<(usize, usize, usize)> {
    for i in 0..MAX_MEMOBJ_HOLDERS {
        let h = &mut region.holders[i];
        if h.refs > 0 && h.tid == tid && h.map_va != 0 {
            let out = (h.map_root, h.map_va, h.map_pages);
            h.clear_mapping();
            return Some(out);
        }
    }
    None
}

/// The region `tid` has MAPPED at user address `va`: `(packed reference,
/// byte offset into the region, physical address of that byte)`, or `None`
/// when no mapping `tid` has recorded covers `va`.
///
/// For `crate::notify` (wave 6), whose key is (region, offset) and never an
/// address. A mapping is recorded only by `SYS_MO_MAP`, which demands
/// `READ` and `MAP` on a `Cap<Shm>`, so resolving through it asks the same authority
/// question — without needing the handle, which the creator loses when it
/// moves the capability to a peer (`cap_store::move_cap`). Answered under the
/// table lock on every call, so a released mapping stops resolving at once.
pub fn memobj_resolve_mapped(tid: u32, va: usize) -> Option<(u32, usize, usize)> {
    let page = azos_arch::PAGE_SIZE;
    let regions = MEMOBJS.lock_irqsave();
    for (i, region) in regions.iter().enumerate() {
        // The word is read and written by the kernel through the direct map.
        if !region.active || region.attrs & ATTR_NO_KERNEL_MAP != 0 { continue; }
        for h in region.holders.iter() {
            if h.refs == 0 || h.tid != tid || h.map_va == 0 { continue; }
            let span = h.map_pages.min(region.page_count) * page;
            if va >= h.map_va && va - h.map_va < span {
                let off = va - h.map_va;
                // `va` is the caller's (notify wait/wake a0): the page index
                // is masked after the check (Spectre v1, `azos_limits::nospec`).
                let pg = azos_limits::nospec::array_index_nospec(off / page, span / page);
                // A Paged page that is not in the cache names no word.
                if region.phys_pages[pg] == 0 {
                    continue;
                }
                let phys = region.phys_pages[pg] + off % page;
                return Some((LAYOUT.pack(i as u32, region.generation), off, phys));
            }
        }
    }
    None
}

/// The physical address of page `page_idx` of the region a packed reference
/// names: `Ok(None)` past the region's last page, and for a page of a Paged
/// object that is not in the cache (it has no frame: a map must not install
/// address 0; [`memobj_paged_frame_ref`] brings it in).
pub fn memobj_page_phys_ref(r: u32, page_idx: usize) -> Result<Option<usize>, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &regions[i];
    Ok(if page_idx < region.page_count { Some(region.phys_pages[page_idx]).filter(|&p| p != 0) } else { None })
}

/// [`memobj_page_phys_ref`] for the KERNEL's own access to the page through
/// the direct map (a robust-list sweep, a doorbell word): `Ok(None)` past the
/// object and for an object with [`ATTR_NO_KERNEL_MAP`], whose frames only a
/// user mapping may reach.
pub fn memobj_kernel_page_phys_ref(r: u32, page_idx: usize) -> Result<Option<usize>, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &regions[i];
    Ok(if page_idx < region.page_count && region.attrs & ATTR_NO_KERNEL_MAP == 0 && region.phys_pages[page_idx] != 0 {
        Some(region.phys_pages[page_idx])
    } else {
        None
    })
}

/// Run `f` on the 32-bit word at byte `offset` of the region a packed
/// reference names, **with the region table locked across `f`**: `Ok(None)` for
/// an offset past the region's last page. The caller checks 4-alignment.
///
/// For `OP_NOTIFY_WAIT`'s look at its word (OVSwrap review F5). It used to
/// read the page address under this lock ([`memobj_page_phys_ref`]) and load the
/// word after dropping it, so a last-holder release on another hart in between
/// put the frame back in the PMM and the load read whatever owned it next —
/// an equality oracle on a reallocated frame, since the wait completes when the
/// word equals the caller's `expected`. A region's frames are freed only in
/// `drop_refs_locked`, under this lock, so holding it pins the page for the
/// length of `f`. `f` must be short and must not take this lock (one atomic
/// load, in the kernel's use).
///
/// The offset is split with the build's translation granule
/// (`azos_arch::PAGE_SIZE`), as [`memobj_resolve_mapped`] splits it:
/// each entry of `phys_pages` is one granule. It used a fixed 4096, so on an
/// aarch64 16/64 KiB build a word past the first 4 KiB of a region was read
/// from a later frame (or refused past `page_count` 4 KiB "pages").
pub fn memobj_with_word_ref<R>(
    r: u32,
    offset: usize,
    f: impl FnOnce(&AtomicU32) -> R,
) -> Result<Option<R>, MemObjError> {
    let page_size = azos_arch::PAGE_SIZE;
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &regions[i];
    let page = offset / page_size;
    // `None` for an object the kernel does not map, as for an offset past it:
    // there is no word the kernel may read.
    // Canary `memobj-no-kernel-map-canary`: the attribute is not consulted.
    let hidden = region.attrs & ATTR_NO_KERNEL_MAP != 0 && !cfg!(feature = "memobj-no-kernel-map-canary");
    if page >= region.page_count || offset % 4 != 0 || hidden {
        return Ok(None);
    }
    // `offset` is the caller's (`OP_NOTIFY_WAIT`'s SQE): the page index is
    // masked after the check (Spectre v1, `azos_limits::nospec`), as in
    // `memobj_resolve_mapped`.
    let page = azos_limits::nospec::array_index_nospec(page, region.page_count);
    // A Paged page that is not in the cache has no word to read.
    if region.phys_pages[page] == 0 {
        return Ok(None);
    }
    let va = azos_mm::addr::phys_to_virt(region.phys_pages[page]) + offset % page_size;
    // SAFETY: a 4-aligned word inside a live page of the region, which cannot
    // be freed while this guard is held (see the doc).
    let word = unsafe { &*(va as *const AtomicU32) };
    let out = f(word);
    drop(regions);
    Ok(Some(out))
}

/// Run `f` on the kernel's address of the first `bytes` bytes of the region a
/// packed reference names, **with the region table locked across `f`**, for a
/// kernel that reads and WRITES a ring the region holds (the kernel end of a
/// queue a client made: `Uart` and `Adc` in `azos_syscall::devices`).
/// `Ok(None)` when the span cannot be touched through the direct map as one
/// piece: it is longer than the region, the object is `ATTR_NO_KERNEL_MAP`,
/// read-only, shares a frame with a clone (`cow_shared`: a write would show in
/// the clone), or its frames are not physically contiguous. `Err` when the
/// reference is stale.
///
/// No address outlives the call, which is the point: the kernel keeps the
/// packed reference (a generation-checked name) and asks again for each access,
/// so a region freed or copy-on-write-broken after the attach is a
/// `Stale` or `None` at the next access and never a write into a frame that
/// belongs to someone else. `f` must be short (one ring push or pop) and must
/// not take this lock.
pub fn memobj_with_span_ref<R>(r: u32, bytes: usize, f: impl FnOnce(usize) -> R) -> Result<Option<R>, MemObjError> {
    let page = azos_arch::PAGE_SIZE;
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &regions[i];
    let pages = bytes.div_ceil(page);
    let hidden = region.attrs & ATTR_NO_KERNEL_MAP != 0 && !cfg!(feature = "memobj-no-kernel-map-canary");
    let shared = pages.min(64) as u32;
    let shared_mask = if shared >= 64 { u64::MAX } else { (1u64 << shared) - 1 };
    if bytes == 0
        || pages > region.page_count
        || hidden
        || region.perms != MemPerms::ReadWrite
        || region.cow_shared & shared_mask != 0
    {
        return Ok(None);
    }
    let first = region.phys_pages[0];
    // First frame 0: a purged object has none.
    if first == 0 || (0..pages).any(|k| region.phys_pages[k] != first + k * page) {
        return Ok(None);
    }
    let out = f(azos_mm::addr::phys_to_virt(first));
    drop(regions);
    Ok(Some(out))
}

/// Is the region table's lock free right now? For the F5 test of
/// [`memobj_with_word_ref`] only: called from inside its closure, `false` proves
/// the table was locked across the load.
pub fn __memobj_table_unlocked_for_tests() -> bool {
    MEMOBJS.try_lock().is_some()
}

/// Pin `tid`'s references on the region a packed reference names
/// ([`MemHolder::pinned`]): for `SYS_MO_MAP` when a map fails after its
/// reference was taken, which may leave PTEs no record names. From then on the
/// typed release keeps one of `tid`'s references; the exit gives it back.
/// `Ok(false)` if `tid` holds no reference; `Stale` as the other forms.
pub fn memobj_pin_ref(tid: u32, r: u32) -> Result<bool, MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    match regions[i].holders.iter_mut().find(|h| h.refs > 0 && h.tid == tid) {
        Some(h) => {
            h.pinned = true;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Release one reference to a shared memory region **held by `tid`**.
///
/// Returns `true` iff a reference was actually dropped.
///
/// Two refusals, both load-bearing (W3-F1):
///
///  1. **No reference held.** A caller that never acquired gets `false` and
///     the count is untouched. The old signature took only `shm_id`, so
///     `SYS_IPC_UNSHARE(n)` in a loop drove any region to zero and freed its
///     pages back to the PMM — a write-after-free with no race at all, since
///     the real holder's `USER_RW` PTEs survive the free and the frames get
///     reissued to somebody else.
///  2. **Caller still has a live mapping.** Dropping a reference while the
///     dropper's own page table still points into the region is the same
///     hazard one step removed. Callers must `memobj_take_mapping` + unmap
///     first; see [`memobj_take_mapping`].
///
/// Freeing the pages only when the *last* reference goes away is unchanged.
pub fn memobj_release(tid: u32, shm_id: u32) -> bool {
    if shm_id as usize >= MAX_MEMOBJS {
        return false;
    }
    let mut regions = MEMOBJS.lock_irqsave();
    let region = &mut regions[shm_id as usize];
    if !region.active {
        return false;
    }
    release_locked(region, tid)
}

/// [`memobj_release`] through a packed reference: `Stale` if the region at its
/// index is not the one it names, `Closed` if no reference was dropped.
pub fn memobj_release_ref(tid: u32, r: u32) -> Result<(), MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    if release_locked(&mut regions[i], tid) {
        Ok(())
    } else {
        Err(MemObjError::Closed)
    }
}

/// The release body, on an active region with the table lock held.
fn release_locked(region: &mut MemObj, tid: u32) -> bool {
    let mut found: Option<usize> = None;
    for i in 0..MAX_MEMOBJ_HOLDERS {
        let h = &region.holders[i];
        if h.refs > 0 && h.tid == tid {
            // Refuse while this holder still has PTEs into the region.
            if h.map_va != 0 {
                return false;
            }
            found = Some(i);
            break;
        }
    }
    let idx = match found {
        Some(i) => i,
        None => return false,
    };
    drop_refs_locked(region, idx, 1);
    true
}

/// Give back every reference `tid` holds on the region a packed reference
/// names, except one a failed map pinned ([`MemHolder::pinned`]): the pool half
/// of the typed release ([`memobj_release_cap`]). `Stale` if the region at its
/// index is not the one it names; `Closed` if nothing was given back — `tid`
/// holds no reference, still has a mapping recorded (unmap first, see
/// [`memobj_take_mapping`]), or holds only its pinned one.
///
/// **WHY all of them.** A task books every reference it takes on a region (the
/// creation reference, each acquire, each map) on one holder slot and names
/// them all through one `Cap<Shm>`, which the typed release revokes. Giving back
/// one would leave the rest booked to the task with nothing left to name them,
/// holding a pool slot and its frames until the task exits; a create, map and
/// release loop then runs the task out of its share of the pool.
///
/// Other holders' references are untouched, so the region, its generation and
/// their capabilities stay live until the last of them goes.
pub fn memobj_release_holder_ref(tid: u32, r: u32) -> Result<(), MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    if release_holder_locked(&mut regions[i], tid) {
        Ok(())
    } else {
        Err(MemObjError::Closed)
    }
}

/// The [`memobj_release_holder_ref`] body, on an active region with the table
/// lock held.
fn release_holder_locked(region: &mut MemObj, tid: u32) -> bool {
    let Some(idx) = (0..MAX_MEMOBJ_HOLDERS).find(|&i| region.holders[i].refs > 0 && region.holders[i].tid == tid)
    else {
        return false;
    };
    let holder = region.holders[idx];
    // Refuse while this holder still has PTEs into the region, as
    // `release_locked` does.
    if holder.map_va != 0 {
        return false;
    }
    // `refs > 0` is established above, so neither form underflows.
    let n = if holder.pinned { holder.refs - 1 } else { holder.refs };
    if n == 0 {
        return false;
    }
    drop_refs_locked(region, idx, n);
    true
}

/// Take `n` references off holder `idx`, with the table lock held and `n` no
/// more than the holder's `refs`. When no holder has a reference left
/// ([`total_refs`]) the frames go back to the PMM and the slot is cleared.
fn drop_refs_locked(region: &mut MemObj, idx: usize, n: u32) {
    // `saturating_sub` rather than `-`: the callers bound `n` by the holder's
    // `refs`, but with `overflow-checks = true` an underflow here would abort
    // the board.
    region.holders[idx].refs = region.holders[idx].refs.saturating_sub(n);
    if region.holders[idx].refs == 0 {
        // The generation stays: the region is still live for its other
        // holders, and their capabilities must keep resolving.
        region.holders[idx] = MemHolder::empty();
    }

    if total_refs(region) == 0 {
        // Last reference — and, by the callers' refusal of a holder with a
        // recorded mapping, no holder can still have one, so freeing the
        // frames is safe. `empty()` clears the generation, so every capability
        // naming this region is stale from here on, whichever table holds it.
        // A frame a clone still shares (`cow_shared`) goes back only when the
        // last sharer lets go of it.
        for i in 0..region.page_count {
            release_frame(region, i);
        }
        // Given back to the Domain that holds the charge, from whichever task
        // drops the last reference (the budget is atomic).
        if region.charge_key != 0 {
            azos_sched::mm_discharge_domain(region.charge_key, region.page_count as u32);
        }
        if region.meta_key != 0 {
            crate::cap_store::kmem_discharge(region.meta_key, crate::cap_store::KMEM_MEMOBJ_META, MEMOBJ_KMEM_BYTES);
        }
        *region = MemObj::empty();
    }
}

/// Let go of page `i`'s frame: it stops naming this object, and goes back to the
/// allocator unless a clone still shares it (the last sharer frees it). The page
/// slot is cleared. Table lock held.
fn release_frame(region: &mut MemObj, i: usize) {
    let p = region.phys_pages[i];
    if p == 0 {
        return;
    }
    // Before the frame can be freed or reissued: a free frame names no object.
    let _ = azos_mm::pmm::clear_frame_owner_if(p, region.ident);
    let shared = region.cow_shared & (1u64 << i) != 0;
    if !shared || azos_mm::cow::page_decref(p) {
        let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(p));
    }
    region.phys_pages[i] = 0;
    region.cow_shared &= !(1u64 << i);
}

/// Drop every reference `tid` holds across all regions — called from the
/// task-exit hook.
///
/// **WHY the exit hook must do this (W3-F1):** per-task reference accounting
/// means a dead task's references are otherwise never given back, so one
/// crashed consumer pins a region (and its pages) for the life of the board.
/// Freeing them here is safe precisely because the exiting task's address
/// space stops being reachable: `task_exit` is the last thing that runs on
/// that task, nothing will ever dispatch into its page table again, and the
/// slot is only recycled by `do_schedule` after the context switch away.
///
/// The mapping record is cleared without unmapping for the same reason —
/// there is no live execution context left that could reach those PTEs.
pub fn memobj_release_all(tid: u32) {
    // A pipe's ends the task still holds go first: its peers must see end of
    // file or `EPIPE` the moment it is gone, and the record of them lives in
    // the holder this function is about to clear.
    pipe_drop_all(tid);
    {
        let mut moved = MOVED_WINDOWS.lock_irqsave();
        for row in moved.iter_mut().filter(|r| r.0 == tid) {
            *row = (0, 0, 0);
            MOVED_PENDING.fetch_sub(1, Ordering::Release);
        }
    }
    // One look under the lock for the regions that exist at all (wave 13): a
    // task with nothing to release used to take the lock twice per region,
    // ~2,800 instructions on every exit. A region created after the look is
    // not this exiting task's.
    let mut live = [false; MAX_MEMOBJS];
    {
        let regions = MEMOBJS.lock_irqsave();
        for (l, r) in live.iter_mut().zip(regions.iter()) {
            *l = r.active;
        }
    }
    for id in 0..MAX_MEMOBJS {
        if !live[id] {
            continue;
        }
        loop {
            // Clear the mapping record first so `memobj_release` will proceed;
            // see the note above on why not unmapping is sound here.
            let _ = memobj_take_mapping(tid, id as u32);
            if !memobj_release(tid, id as u32) {
                break;
            }
        }
    }
}

/// `tid` exec'd: its old address space is about to be freed by the exec
/// hand-off, so every mapping record it holds names a root that is going away.
/// They are forgotten (no unmap: the task is switching away from that root and
/// nothing else runs in it), and the references stay; a MOVE or a protect that
/// ran afterwards would otherwise edit a freed page table. Must run before the
/// old root is freed.
pub fn memobj_exec(tid: u32) {
    let mut regions = MEMOBJS.lock_irqsave();
    for region in regions.regions.iter_mut().filter(|r| r.active) {
        let _ = take_mapping_locked(region, tid);
    }
    drop(regions);
    let mut moved = MOVED_WINDOWS.lock_irqsave();
    for row in moved.iter_mut().filter(|r| r.0 == tid) {
        *row = (0, 0, 0);
        MOVED_PENDING.fetch_sub(1, Ordering::Release);
    }
}

/// Get info about a shared memory region: (page_count, references saturated at `u32::MAX`, perms).
pub fn memobj_info(shm_id: u32) -> Option<(usize, u32, MemPerms)> {
    if shm_id as usize >= MAX_MEMOBJS {
        return None;
    }
    let regions = MEMOBJS.lock_irqsave();
    let region = &regions[shm_id as usize];
    if !region.active {
        return None;
    }
    Some((
        region.page_count,
        u32::try_from(total_refs(region)).unwrap_or(u32::MAX),
        region.perms,
    ))
}

// ──────────────────────────────────────────────────────────────────────────
// Operations beyond create / reference / release
// ──────────────────────────────────────────────────────────────────────────

/// A copy of an object's description, for the layers that map it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemDesc {
    pub kind: MemKind,
    pub perms: MemPerms,
    pub attrs: u8,
    pub device_visible: bool,
    pub page_count: usize,
    pub owner_task: u32,
    /// The Domain the frames are charged to; 0 for none.
    pub charge_key: u32,
    /// Pages whose frame a clone shares ([`MemObj::cow_shared`]).
    pub cow_shared: u64,
    /// Where a volatile object stands ([`PurgeState`]).
    pub purge: PurgeState,
}

/// [`MemDesc`] of the object a packed reference names, or `Stale`.
pub fn memobj_describe_ref(r: u32) -> Result<MemDesc, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let o = &regions[i];
    Ok(MemDesc {
        kind: o.kind,
        perms: o.perms,
        attrs: o.attrs,
        device_visible: o.device_visible,
        page_count: o.page_count,
        owner_task: o.owner_task,
        charge_key: o.charge_key,
        cow_shared: o.cow_shared,
        purge: o.purge,
    })
}

/// What a map through a capability may be: the object it names and whether
/// the mapping may be writable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MapGrant {
    pub r: u32,
    pub desc: MemDesc,
    /// The mapping may be writable: the object is read-write AND the
    /// capability holds `WRITE`. A capability that was attenuated to `READ`
    /// (a SHARE with fewer rights) maps the same object read-only — map
    /// permissions are a subset of the warrant's rights.
    pub writable: bool,
}

/// Resolve `cap` in `table` for a map: `READ` and `MAP` are required (reading a
/// region through the kernel is not a window in ring 3: `MAP` is the right to
/// have one); `WRITE` decides the writable bit of a read-write object. A refusal other than the missing
/// `WRITE` (a stale or revoked capability, containment) is the map's.
pub fn memobj_resolve_map(
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
    op: u16,
) -> Result<MapGrant, MemObjError> {
    let r = table.get_op(cap, crate::cap::CapPerms::READ.union(crate::cap::CapPerms::MAP), op)?;
    let desc = memobj_describe_ref(r)?;
    // A purged object has no frame to map: say so, not "not reachable".
    if desc.purge == PurgeState::Purged {
        return Err(MemObjError::Purged);
    }
    let writable = if desc.perms == MemPerms::ReadWrite {
        match table.get_op(cap, crate::cap::CapPerms::WRITE, op) {
            Ok(_) => true,
            // Canary `memobj-share-no-narrow-canary`: an attenuated capability
            // maps as writable as the object is.
            Err(CapError::MissingPerms) => cfg!(feature = "memobj-share-no-narrow-canary"),
            Err(e) => return Err(MemObjError::Cap(e)),
        }
    } else {
        false
    };
    Ok(MapGrant { r, desc, writable })
}

/// Change the access of `tid`'s recorded mapping of the object `r` names to
/// `write`: the record and the page table change together (through the
/// boot-registered [`ProtectHook`]). Making it writable is refused
/// (`Cap(MissingPerms)`) past what the map was allowed ([`MapAccess::max_write`])
/// and (`Busy`) while the
/// object has frames a clone shares: a write mapping of shared frames would
/// write the other object's memory. `Closed` when `tid` has no mapping of it.
/// This is `SYS_MO_MAP` with its second argument set.
pub fn memobj_protect_ref(tid: u32, r: u32, write: bool) -> Result<(), MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &mut regions[i];
    reclaim_sole_frames(region);
    let shared = region.cow_shared != 0;
    let h = region
        .holders
        .iter_mut()
        .find(|h| h.refs > 0 && h.tid == tid && h.map_va != 0)
        .ok_or(MemObjError::Closed)?;
    // Canary `memobj-protect-max-canary`: any mapping may be made writable.
    if write && !h.map_max_write && !cfg!(feature = "memobj-protect-max-canary") {
        return Err(MemObjError::Cap(CapError::MissingPerms));
    }
    if write && shared {
        return Err(MemObjError::Busy);
    }
    // The leaves change under the table lock, as a MOVE's unmap does: the
    // record's root is a live address space (`map_root`).
    let (root, va, pages) = (h.map_root, h.map_va, h.map_pages);
    h.map_write = write;
    let _ = protect_range(root, va, pages, write);
    Ok(())
}

/// Pages marked shared whose other sharer has gone: the frame is this object's
/// alone again (count back to "one holder"), so the mark goes. The
/// compare-and-swap tells a sole owner from one a fresh clone just joined.
fn reclaim_sole_frames(region: &mut MemObj) {
    for page in 0..region.page_count {
        let bit = 1u64 << page;
        if region.cow_shared & bit != 0 {
            let p = region.phys_pages[page];
            if azos_mm::cow::page_is_sole(p) && azos_mm::cow::page_forget_if_sole(p) {
                region.cow_shared &= !bit;
            }
        }
    }
}

/// Break page `page` of the object `r` names out of a COW share: it gets a
/// frame of its own holding the same bytes, and the frame it shared loses one
/// holder. `Ok(())` for a page that is not shared. `Busy` while any holder has
/// the object mapped: the PTEs of a mapping name the old frame and a break
/// would leave them reading it. Alloc and copy happen outside the table lock.
pub fn memobj_cow_break(r: u32, page: usize) -> Result<(), MemObjError> {
    let (old, key) = {
        let regions = MEMOBJS.lock_irqsave();
        let i = live_index(&regions, r)?;
        let o = &regions[i];
        if page >= o.page_count {
            return Err(MemObjError::BadArg);
        }
        if o.cow_shared & (1u64 << page) == 0 {
            return Ok(());
        }
        if o.holders.iter().any(|h| h.refs > 0 && h.map_va != 0) {
            return Err(MemObjError::Busy);
        }
        (o.phys_pages[page], o.generation)
    };
    // The last sharer keeps the frame: the other object let go of it (freed, or
    // broke its own copy first), so nothing is left to protect from. The share
    // count is dropped back to "one holder" with the compare-and-swap that tells
    // a clone taken in the meantime (it would be above one) from a sole owner.
    if azos_mm::cow::page_is_sole(old) && azos_mm::cow::page_forget_if_sole(old) {
        let mut regions = MEMOBJS.lock_irqsave();
        if let Ok(i) = live_index(&regions, r) {
            if regions[i].generation == key && regions[i].phys_pages[page] == old {
                regions[i].cow_shared &= !(1u64 << page);
            }
        }
        return Ok(());
    }
    // The copy, with no lock held. A second thread breaking the same page
    // races here: whoever finds the bit still set after the allocation swaps,
    // the other frees its copy.
    let fresh = azos_mm::pmm::alloc_page().map_err(|_| MemObjError::NoMem)?;
    // SAFETY: `old` is a live frame of this object (the caller holds a
    // reference, or the break runs under the map that holds one), `fresh` is
    // ours; both are one granule.
    unsafe {
        core::ptr::copy_nonoverlapping(
            azos_mm::addr::phys_to_virt(old) as *const u8,
            azos_mm::addr::phys_to_virt(fresh.as_usize()) as *mut u8,
            azos_arch::PAGE_SIZE,
        );
    }
    let mut regions = MEMOBJS.lock_irqsave();
    let still = live_index(&regions, r).ok().filter(|&i| {
        let o = &regions[i];
        o.generation == key
            && o.phys_pages[page] == old
            && o.cow_shared & (1u64 << page) != 0
            && !o.holders.iter().any(|h| h.refs > 0 && h.map_va != 0)
    });
    let Some(i) = still else {
        drop(regions);
        let _ = azos_mm::pmm::free_page(fresh);
        return Err(MemObjError::Busy);
    };
    let o = &mut regions[i];
    // Canary `memobj-cow-no-break-canary`: the bit goes and the frame stays, so
    // the two objects write the same bytes.
    if !cfg!(feature = "memobj-cow-no-break-canary") {
        o.phys_pages[page] = fresh.as_usize();
        // The reverse map follows the page: the new frame names this object,
        // and the shared one stops naming it (it goes on naming its allocator
        // when that is another object).
        let _ = azos_mm::pmm::clear_frame_owner_if(old, o.ident);
        let _ = azos_mm::pmm::set_frame_owner(fresh.as_usize(), o.ident, page as u32);
    }
    o.cow_shared &= !(1u64 << page);
    drop(regions);
    // Our share of `old` is given up; the last sharer frees it.
    if azos_mm::cow::page_decref(old) {
        let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(old));
    }
    Ok(())
}

/// Give every page of the object its own frame ([`memobj_cow_break`] for each
/// shared page): what a write mapping of a clone does first.
pub fn memobj_cow_break_all(r: u32) -> Result<(), MemObjError> {
    let shared = memobj_describe_ref(r)?.cow_shared;
    for page in 0..MAX_MEMOBJ_PAGES {
        if shared & (1u64 << page) != 0 {
            memobj_cow_break(r, page)?;
        }
    }
    Ok(())
}

/// Clone the object `src` names into a new Anon object of `owner_task`, with
/// the access mode `perms`: a snapshot. Copy-on-write: while no holder maps the
/// source writable, the clone shares the source's frames (the frame refcount
/// counts both; neither object may be mapped writable until
/// [`memobj_cow_break_all`] has given it frames of its own). If the source is
/// mapped writable somewhere, its bytes can change under a lazy share, so the
/// clone copies them now. `tid` takes a reference on the source for the length
/// of the call, which keeps the frames alive while they are copied.
///
/// A Paged source is refused (`BadArg`): there are no frames to snapshot.
/// The clone's frames are charged to `owner_task`'s Domain whichever way they
/// are made.
pub fn memobj_clone(tid: u32, src: u32, owner_task: u32, perms: MemPerms) -> Result<u32, MemObjError> {
    let spec = MemSpec::anon(perms);
    let d = memobj_describe_ref(src)?;
    if !matches!(d.kind, MemKind::Anon | MemKind::Contig) {
        return Err(MemObjError::BadArg);
    }
    if d.purge == PurgeState::Purged {
        return Err(MemObjError::Purged);
    }
    if !has_room(&MEMOBJS.lock_irqsave(), owner_task) {
        return Err(MemObjError::NoMem);
    }
    let n = d.page_count;
    let key = charge_key_of(owner_task);
    if !charge_region(key, n) {
        return Err(MemObjError::NoMem);
    }
    let uncharge = || uncharge_region(key, n);

    let mut pages = [0usize; MAX_MEMOBJ_PAGES];
    // One hold: a reference for `tid`, the decision, and the share.
    let lazy = {
        let mut regions = MEMOBJS.lock_irqsave();
        let i = match live_index(&regions, src) {
            Ok(i) => i,
            Err(e) => {
                drop(regions);
                uncharge();
                return Err(e);
            }
        };
        // Purged since the look above: the frames the copy would read are gone.
        if regions[i].purge == PurgeState::Purged {
            drop(regions);
            uncharge();
            return Err(MemObjError::Purged);
        }
        if acquire_locked(&mut regions[i], tid).is_none() {
            drop(regions);
            uncharge();
            return Err(MemObjError::Closed);
        }
        let o = &mut regions[i];
        let writable_somewhere = o.holders.iter().any(|h| h.refs > 0 && h.map_va != 0 && h.map_write);
        pages[..n].copy_from_slice(&o.phys_pages[..n]);
        if !writable_somewhere && o.kind == MemKind::Anon {
            let mut shared = 0usize;
            for &p in &pages[..n] {
                if azos_mm::cow::page_addref(p).is_err() {
                    break;
                }
                shared += 1;
            }
            if shared == n {
                o.cow_shared |= if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
                true
            } else {
                for &p in &pages[..shared] {
                    let _ = azos_mm::cow::page_decref(p);
                }
                false
            }
        } else {
            false
        }
    };

    let result = if lazy {
        let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
        claim_slot_cow(owner_task, &pages[..n], &spec, key, mask, None).ok_or(MemObjError::NoMem).inspect_err(|_| {
            for &p in &pages[..n] {
                let _ = azos_mm::cow::page_decref(p);
            }
        })
    } else {
        copy_into_new(&pages[..n], owner_task, &spec, key)
    };
    // The temporary reference goes back whichever way it ended. `tid` may
    // have had none before (then its holder entry goes with it) or others.
    {
        let mut regions = MEMOBJS.lock_irqsave();
        if let Ok(i) = live_index(&regions, src) {
            if let Some(idx) = (0..MAX_MEMOBJ_HOLDERS).find(|&k| regions[i].holders[k].refs > 0 && regions[i].holders[k].tid == tid) {
                drop_refs_locked(&mut regions[i], idx, 1);
            }
        }
    }
    if result.is_err() {
        uncharge();
    }
    result
}

/// The eager half of [`memobj_clone`]: a fresh frame per page of `src_pages`
/// holding the same bytes, published as a new object.
fn copy_into_new(src_pages: &[usize], owner_task: u32, spec: &MemSpec, key: u32) -> Result<u32, MemObjError> {
    let mut fresh = [0usize; MAX_MEMOBJ_PAGES];
    for (k, &sp) in src_pages.iter().enumerate() {
        match azos_mm::pmm::alloc_page() {
            Ok(f) => {
                // SAFETY: `sp` is held live by the caller's reference, `f` is
                // ours; one granule each.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        azos_mm::addr::phys_to_virt(sp) as *const u8,
                        azos_mm::addr::phys_to_virt(f.as_usize()) as *mut u8,
                        azos_arch::PAGE_SIZE,
                    );
                }
                fresh[k] = f.as_usize();
            }
            Err(_) => {
                free_frames(&fresh[..k]);
                return Err(MemObjError::NoMem);
            }
        }
    }
    claim_slot(owner_task, &fresh[..src_pages.len()], spec, key).ok_or_else(|| {
        free_frames(&fresh[..src_pages.len()]);
        MemObjError::NoMem
    })
}

// ──────────────────────────────────────────────────────────────────────────
// The reverse map: from an object (or a frame) to the mappings of it
// ──────────────────────────────────────────────────────────────────────────
//
// The mapping list of an object is its holder table: every holder with a
// recorded mapping names the address space (`map_root`) and the VA it maps the
// object at, one mapping per holder (the process), at most
// `MAX_MEMOBJ_HOLDERS` of them. A frame names the object that holds it
// (`FrameDesc::owner`) and its page index in it. So "take this holder out of the
// object" and "unmap this page everywhere" walk at most eight records and issue
// one ranged unmap per space; none of them scans a page table to find who maps
// what.

/// Is any holder pinned ([`MemHolder::pinned`])? Its failed map may have left
/// PTEs the mapping list does not name, so a walk of the list is not a walk of
/// every PTE of the object.
fn any_pinned(region: &MemObj) -> bool {
    region.holders.iter().any(|h| h.refs > 0 && h.pinned)
}

/// The holder `tid` lost its name for the object `r` names: unmap its mapping
/// on every hart, and give back its references. The revoke half of "a share
/// is taken back": the capability that named the references is already gone
/// (swept with the warrant it derived from), so the holder has no handle to
/// call `SYS_MO_UNMAP` or the typed release with, which is the reason this
/// unmaps what those would have refused (`Closed` while a mapping is recorded).
///
/// The sequence is the exit path's, in order: the pipe ends it held first (its
/// peers must see end of file, not wait for a holder that cannot come back),
/// then the mapping record and its PTEs, then the references. The window the
/// mapping occupied is the holder's own address range to give back
/// ([`memobj_take_moved_windows`]), as after a MOVE. A pinned holder
/// ([`MemHolder::pinned`]) may have PTEs the record does not name (a failed
/// map): it keeps its pinned reference, so no frame goes back under them, and
/// that reference ends with the holder's exit.
///
/// `Closed` when `tid` holds no reference, so a second call, or a holder whose
/// typed release got there first, is a no-op. The other holders and the object
/// are untouched: the object lives for as long as one reference does.
fn memobj_revoke_holder_ref(tid: u32, r: u32) -> Result<(), MemObjError> {
    memobj_pipe_drop_all_ref(tid, r);
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &mut regions[i];
    let hi = holder_index(region, tid).ok_or(MemObjError::Closed)?;
    // The PTEs go now, shot down on every hart, with the table locked: the
    // record's root is a live address space, and no reference is given back
    // while they exist.
    if let Some((root, va, pages)) = take_mapping_root_locked(region, tid) {
        unmap_range(root, va, pages);
        note_moved_window(tid, va, pages);
    }
    let h = region.holders[hi];
    let n = if h.pinned { h.refs - 1 } else { h.refs };
    if n > 0 {
        drop_refs_locked(region, hi, n);
    }
    Ok(())
}

/// The object half of a swept warrant ([`crate::cap_store::SweptHook`]), the
/// production caller of the revoke: a `Cap<Shm>` slot of the Domain `owner`
/// was revoked with the warrant it derived from (`SYS_CAP_REVOKE` on the
/// capability it was shared from, the sweep of a capability that went), so no
/// task of that Domain keeps a reference to the object `resource` names or a
/// mapping of it. A holder is a process, the Domain's tables are per Domain: a
/// holder belongs to the Domain its task slot is in. The revoker's own
/// capability is granted again, not swept, and the holders of other Domains
/// are untouched.
///
/// Called after the table's lock is released, never under it; takes the
/// object table's lock once per holder (the revoke of one holder is
/// [`memobj_revoke_holder_ref`]).
pub fn memobj_warrant_swept(resource: u32, owner: u32) {
    // The holders are named under the lock and sorted into Domains outside it:
    // `idx_for_tid` and `task_domain` are the scheduler's, and a holder that
    // has no task any more (the kernel's own reference, an exited process) is
    // no Domain's.
    let mut tids = [0u32; MAX_MEMOBJ_HOLDERS];
    let mut n = 0;
    {
        let regions = MEMOBJS.lock_irqsave();
        let Ok(i) = live_index(&regions, resource) else { return };
        for h in regions[i].holders.iter().filter(|h| h.refs > 0) {
            tids[n] = h.tid;
            n += 1;
        }
    }
    for &tid in &tids[..n] {
        // Canary `memobj-sweep-every-domain-canary`: the owner is not consulted,
        // every Domain's holder loses the object.
        let in_domain = azos_sched::idx_for_tid(tid).map(azos_sched::task_domain) == Some(owner);
        if in_domain || cfg!(feature = "memobj-sweep-every-domain-canary") {
            let _ = memobj_revoke_holder_ref(tid, resource);
        }
    }
}

/// Remove page `idx` of `region`'s PTE from every recorded mapping that reaches
/// it; how many. Table lock held.
fn unmap_frame_in(region: &MemObj, idx: usize) -> usize {
    let page = azos_arch::PAGE_SIZE;
    let mut spaces = 0;
    for h in region.holders.iter().filter(|h| h.is_mapped() && idx < h.map_pages) {
        unmap_range(h.map_root, h.map_va + idx * page, 1);
        spaces += 1;
    }
    spaces
}

/// Windows of mappings a MOVE removed, until the sender gives the addresses
/// back: `(tid, va, pages)`, `tid == 0` a free row. Only the sender can release
/// its own window addresses (they are per task), and a MOVE can run on
/// another task's behalf, so the row waits here for the sender's next
/// shm call or syscall return. A full table drops the row: the window then
/// stays reserved until the task exits, which wastes addresses and nothing else.
static MOVED_WINDOWS: SpinLock<[(u32, usize, usize); MOVED_WINDOW_ROWS]> =
    SpinLock::new([(0, 0, 0); MOVED_WINDOW_ROWS]);

/// Rows of [`MOVED_WINDOWS`] (Kconfig `MEMOBJ_MOVED_WINDOWS`).
const MOVED_WINDOW_ROWS: usize = azos_limits::MEMOBJ_MOVED_WINDOWS as usize;

/// Rows of [`MOVED_WINDOWS`] in use: the transfer paths ask it before they
/// take the lock, so a transfer that moved no mapping pays one load.
static MOVED_PENDING: AtomicU32 = AtomicU32::new(0);

fn note_moved_window(tid: u32, va: usize, pages: usize) {
    let mut t = MOVED_WINDOWS.lock_irqsave();
    if let Some(row) = t.iter_mut().find(|r| r.0 == 0) {
        *row = (tid, va, pages);
        MOVED_PENDING.fetch_add(1, Ordering::Release);
    }
}

/// Is any MOVE-removed window waiting for its task to release it?
pub fn memobj_moved_windows_pending() -> bool {
    MOVED_PENDING.load(Ordering::Acquire) != 0
}

/// Take the windows of `tid`'s mappings a MOVE removed, into `out`; how many.
/// The caller (`tid` itself) gives each back with `release_user_window`.
pub fn memobj_take_moved_windows(tid: u32, out: &mut [(usize, usize)]) -> usize {
    let mut t = MOVED_WINDOWS.lock_irqsave();
    let mut n = 0;
    for row in t.iter_mut().filter(|r| r.0 == tid && tid != 0) {
        if n == out.len() {
            break;
        }
        out[n] = (row.1, row.2);
        n += 1;
        *row = (0, 0, 0);
        MOVED_PENDING.fetch_sub(1, Ordering::Release);
    }
    n
}

/// The object half of a capability MOVE: [`crate::cap_store::MoveHook`] for
/// `Cap<Shm>`, registered at boot. The tables key holders by PROCESS, so both
/// TIDs are resolved to theirs. A refusal ([`Moved::transferred`] false) leaves
/// the references where they were: nothing is lost, and the sender's mapping is
/// gone either way.
pub fn memobj_moved(kind: CapType, resource: u32, from_tid: u32, to_tid: u32) {
    if kind != ty::SHM {
        return;
    }
    let (from, to) = (azos_sched::group::proc_tid(from_tid), azos_sched::group::proc_tid(to_tid));
    if from != to {
        let _ = memobj_move(from, to, resource);
    }
}

/// What [`memobj_move`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Moved {
    /// The sender's recorded mapping `(va, pages)`: dropped from the record and
    /// removed from its page table. Its window addresses are the sender's to
    /// give back ([`memobj_take_moved_windows`]).
    pub mapping: Option<(usize, usize)>,
    /// The references (and, for the owning reference, the ownership and the
    /// charge) are now the receiver's. `false`: the receiver could not take
    /// them (no holder slot, over quota, over budget); the sender keeps them,
    /// and nothing was charged.
    pub transferred: bool,
}

/// MOVE the object `r` names from `from` to `to`: the sender's mapping is
/// dropped from the record (always: it no longer holds the capability), and its
/// references go to the receiver. When the sender holds the OWNING reference
/// the ownership and the charge go too: the receiver's Domain is charged first
/// (all or nothing) and the sender's is given back. The capability itself
/// moves by the IPC transfer's MOVE entry (`cap_store::move_caps`); this is the
/// object half of it.
///
/// `Closed` when `from` holds no reference. A pinned reference (a failed map's
/// stranded PTEs) stays with the sender: only the others move.
pub fn memobj_move(from: u32, to: u32, r: u32) -> Result<Moved, MemObjError> {
    if from == to || to == MEMOBJ_KERNEL_OWNER {
        return Err(MemObjError::BadArg);
    }
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    // The cache is the kernel's, charged to no Domain: there is no charge to move.
    if regions[i].kind == MemKind::Paged {
        return Err(MemObjError::BadArg);
    }
    let fi = (0..MAX_MEMOBJ_HOLDERS)
        .find(|&k| regions[i].holders[k].refs > 0 && regions[i].holders[k].tid == from)
        .ok_or(MemObjError::Closed)?;
    // The sender's mapping goes whether or not the references can follow.
    // Canary `memobj-move-keeps-map-canary`: the record stays, and with it the
    // sender's PTEs.
    let taken = if cfg!(feature = "memobj-move-keeps-map-canary") {
        None
    } else {
        take_mapping_root_locked(&mut regions[i], from)
    };
    // The PTEs go now, shot down on every hart, with the table locked: the
    // record's root is a live address space (`map_root`), so nothing can free
    // it under this call, and no reference moves while they exist.
    let mapping = taken.map(|(root, va, pages)| {
        unmap_range(root, va, pages);
        note_moved_window(from, va, pages);
        (va, pages)
    });
    let not_moved = Moved { mapping, transferred: false };

    let sender = regions[i].holders[fi];
    let movable = if sender.pinned { sender.refs - 1 } else { sender.refs };
    if movable == 0 {
        return Ok(not_moved);
    }
    let Some((ti, existing)) = holder_slot(&regions[i], to) else { return Ok(not_moved) };
    let base = if existing { regions[i].holders[ti].refs } else { 0 };
    let Some(total) = base.checked_add(movable) else { return Ok(not_moved) };

    let owning = regions[i].owner_task == from;
    if owning {
        if !owns_fewer_than_quota(&regions, to) {
            return Ok(not_moved);
        }
        if regions[i].charge_key != 0 {
            let to_key = charge_key_of(to);
            let pages = regions[i].page_count as u32;
            if to_key == 0 || !azos_sched::mm_charge_domain(to_key, pages) {
                return Ok(not_moved);
            }
            // The receiver is charged; the sender's Domain gets its charge back.
            if !cfg!(feature = "memobj-charge-stays-canary") {
                azos_sched::mm_discharge_domain(regions[i].charge_key, pages);
            }
            regions[i].charge_key = to_key;
        }
        regions[i].owner_task = to;
    }
    if existing {
        regions[i].holders[ti].refs = total;
    } else {
        regions[i].holders[ti] = MemHolder { tid: to, refs: total, ..MemHolder::empty() };
    }
    // A pipe's ends go with the references (counted once per holding task).
    ends_merge_locked(&mut regions[i], sender.ends, ti);
    regions[i].holders[fi].ends = 0;
    if sender.pinned {
        regions[i].holders[fi].refs = 1;
    } else {
        regions[i].holders[fi] = MemHolder::empty();
    }
    Ok(Moved { mapping, transferred: true })
}

// ──────────────────────────────────────────────────────────────────────────
// The ends of a POSIX pipe region
// ──────────────────────────────────────────────────────────────────────────
//
// A POSIX pipe is a byte ring in a shared region (`azos_bytepipe`); its two
// end counts say how many tasks hold the read end and the write end, and a
// reader sees end of file when the writers reach zero. The kernel keeps who
// holds which end in the holder record ([`MemHolder::ends`]) and is the only
// writer of the counts, so a task killed at any instruction cannot leave a
// count it had given up, nor half-give one up:
//
// * the creator holds both ends ([`memobj_create_cap`]);
// * a hand-over counts the receiver's ends in the step that gives it the
//   region: a spawn's move list ([`memobj_pipe_hold`], the end its fd position
//   names), a fork ([`memobj_pipe_inherit`], what the parent holds);
// * a task gives an end up with `MEMOBJ_END_DROP` ([`memobj_pipe_drop`]);
// * its exit gives up the rest and opens a lock word it died owning
//   ([`pipe_drop_all`], from [`memobj_release_all`]).
//
// All of it reads and writes the first page of the region through the direct
// map (a region the kernel may not map, [`ATTR_NO_KERNEL_MAP`], is never a
// pipe here). The wakes a count reaching zero (or a lock reopened) owes are
// collected under the table lock and rung after it.

/// [`MemHolder::ends`]: the read end.
pub const PIPE_END_READ: u8 = 1;
/// [`MemHolder::ends`]: the write end.
pub const PIPE_END_WRITE: u8 = 2;

fn end_of_bit(bit: u8) -> azos_bytepipe::End {
    if bit == PIPE_END_WRITE { azos_bytepipe::End::Write } else { azos_bytepipe::End::Read }
}

/// Wakes owed by a pipe operation: `(region reference, offset of the word)`.
/// A task holds at most a handful of pipe regions, 4 words each; a wake that does
/// not fit is not lost for good, the sleeper's own timeout finds the change.
struct PipeWakes {
    at: [(u32, u32); 32],
    n: usize,
}

impl PipeWakes {
    const fn new() -> Self {
        Self { at: [(0, 0); 32], n: 0 }
    }
    fn push(&mut self, r: u32, off: usize) {
        if self.n < self.at.len() {
            self.at[self.n] = (r, off as u32);
            self.n += 1;
        }
    }
    /// Wake the sleepers on every word collected. Called with no lock held.
    fn ring(self) {
        for &(obj, offset) in &self.at[..self.n] {
            let _ = azos_sched::futex::wake_key(azos_sched::futex::Key::Shared { obj, offset }, u32::MAX);
        }
    }
}

/// The pipe header on the first page of `region`, if it is one the kernel may
/// read and its magic word says it is a pipe.
fn pipe_header(region: &MemObj) -> Option<azos_bytepipe::Header> {
    // A Paged object is a file's pages: never a pipe (a file may hold the magic
    // word, and the header's recovery writes), and its first page may not be in
    // the cache at all (no frame to read).
    if region.page_count == 0
        || region.attrs & ATTR_NO_KERNEL_MAP != 0
        || region.kind == MemKind::Paged
        || region.phys_pages[0] == 0
    {
        return None;
    }
    let va = azos_mm::addr::phys_to_virt(region.phys_pages[0]);
    // SAFETY: the first frame of a live region the table lock pins, page
    // aligned, at least HEADER_BYTES long, mapped in the direct map.
    unsafe { azos_bytepipe::Header::at(va) }
}

fn holder_index(region: &MemObj, tid: u32) -> Option<usize> {
    (0..MAX_MEMOBJ_HOLDERS).find(|&k| region.holders[k].refs > 0 && region.holders[k].tid == tid)
}

/// Give up the `bits` of `holder` on `region` (`r` its reference), counted and
/// woken as a task's `MEMOBJ_END_DROP` or its death does. Table lock held.
fn drop_bits_locked(region: &mut MemObj, r: u32, hi: usize, bits: u8, wakes: &mut PipeWakes) {
    let held = region.holders[hi].ends & bits;
    region.holders[hi].ends &= !bits;
    if let Some(h) = pipe_header(region) {
        for bit in [PIPE_END_READ, PIPE_END_WRITE] {
            if held & bit != 0 {
                h.drop_end(end_of_bit(bit), |off| wakes.push(r, off));
            }
        }
    }
}

/// Count the `new` ends for holder `hi`, undoing the ones already counted if a
/// count has no room. `Full` then. Table lock held.
fn hold_bits_locked(region: &mut MemObj, hi: usize, bits: u8) -> Result<(), MemObjError> {
    let new = bits & !region.holders[hi].ends;
    if new == 0 {
        return Ok(());
    }
    if let Some(h) = pipe_header(region) {
        let mut counted = 0u8;
        for bit in [PIPE_END_READ, PIPE_END_WRITE] {
            if new & bit != 0 {
                if !h.add_end(end_of_bit(bit)) {
                    // Never zero here: this holder's earlier bits kept a count.
                    for undo in [PIPE_END_READ, PIPE_END_WRITE] {
                        if counted & undo != 0 {
                            h.drop_end(end_of_bit(undo), |_| {});
                        }
                    }
                    return Err(MemObjError::Full);
                }
                counted |= bit;
            }
        }
    }
    region.holders[hi].ends |= new;
    Ok(())
}

/// A moved reference carries its ends to the receiver `ti`; an end both held
/// was counted twice and is counted once now. Table lock held.
fn ends_merge_locked(region: &mut MemObj, from: u8, ti: usize) {
    let overlap = from & region.holders[ti].ends;
    if overlap != 0 {
        if let Some(h) = pipe_header(region) {
            for bit in [PIPE_END_READ, PIPE_END_WRITE] {
                if overlap & bit != 0 {
                    // The receiver still holds the end: not the last.
                    h.drop_end(end_of_bit(bit), |_| {});
                }
            }
        }
    }
    region.holders[ti].ends |= from;
}

/// The creator of the region `r` holds both ends of what may become a pipe.
/// Nothing is counted: `BytePipe::init` writes the creator's one reader and
/// one writer itself.
fn pipe_creator_ends(tid: u32, r: u32) {
    let mut regions = MEMOBJS.lock_irqsave();
    if let Ok(i) = live_index(&regions, r) {
        if let Some(hi) = holder_index(&regions[i], tid) {
            regions[i].holders[hi].ends = PIPE_END_READ | PIPE_END_WRITE;
        }
    }
}

/// Hand `tid` the `ends` of the pipe region `r` it already holds a reference
/// on (a spawn's move list: fd 0 reads, any other fd writes): the ends it did
/// not hold are counted. `Closed` if `tid` holds no reference, `Full` if a
/// count has no room. A region that is no pipe is left alone.
pub fn memobj_pipe_hold(tid: u32, r: u32, ends: u8) -> Result<(), MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let hi = holder_index(&regions[i], tid).ok_or(MemObjError::Closed)?;
    hold_bits_locked(&mut regions[i], hi, ends & (PIPE_END_READ | PIPE_END_WRITE))
}

/// [`memobj_pipe_hold`] for a fork: `child` holds the ends `parent` holds.
pub fn memobj_pipe_inherit(parent: u32, child: u32, r: u32) -> Result<(), MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let pi = holder_index(&regions[i], parent).ok_or(MemObjError::Closed)?;
    let ci = holder_index(&regions[i], child).ok_or(MemObjError::Closed)?;
    let ends = regions[i].holders[pi].ends;
    hold_bits_locked(&mut regions[i], ci, ends)
}

/// `MEMOBJ_END_DROP`: `tid` gives up the `ends` it holds on the pipe region
/// `r`. `BadArg` for no end, or an end `tid` does not hold; the last holder of
/// an end wakes its peers.
pub fn memobj_pipe_drop(tid: u32, r: u32, ends: u8) -> Result<(), MemObjError> {
    let mut wakes = PipeWakes::new();
    {
        let mut regions = MEMOBJS.lock_irqsave();
        let i = live_index(&regions, r)?;
        let hi = holder_index(&regions[i], tid).ok_or(MemObjError::Closed)?;
        let bits = ends & (PIPE_END_READ | PIPE_END_WRITE);
        if bits == 0 || bits != ends || bits & !regions[i].holders[hi].ends != 0 {
            return Err(MemObjError::BadArg);
        }
        drop_bits_locked(&mut regions[i], r, hi, bits, &mut wakes);
    }
    wakes.ring();
    Ok(())
}

/// `tid` lets go of the region `r` altogether (a typed release, a refused
/// hand-over undone): whatever ends it still holds are given up first.
pub fn memobj_pipe_drop_all_ref(tid: u32, r: u32) {
    let mut wakes = PipeWakes::new();
    {
        let mut regions = MEMOBJS.lock_irqsave();
        let Ok(i) = live_index(&regions, r) else { return };
        let Some(hi) = holder_index(&regions[i], tid) else { return };
        let held = regions[i].holders[hi].ends;
        if held != 0 {
            drop_bits_locked(&mut regions[i], r, hi, held, &mut wakes);
        }
    }
    wakes.ring();
}

/// The kernel's view of the region `r` for a byte-pipe call it makes itself
/// (the Linux personality's `read` and `write` on a pipe, `crate::kpipe`): the
/// direct-map address of each page's first byte, written to `out`, and the
/// page count. The kernel reads and writes the ring, so the region must be
/// **read-write** (a read-only region answers `BadArg`, as a ring-3 mapping of
/// it would be read-only); one the direct map does not cover
/// (`ATTR_NO_KERNEL_MAP`) or longer than `out` answers `BadArg` too. The
/// kernel takes a reference of its own, booked to no task, so the frames
/// outlive a holder that lets go of the region during the call;
/// [`memobj_frames_unpin`] gives it back.
pub fn memobj_frames_pin(r: u32, out: &mut [usize]) -> Result<usize, MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &mut regions[i];
    if region.attrs & ATTR_NO_KERNEL_MAP != 0
        || region.perms != MemPerms::ReadWrite
        || region.page_count == 0
        || region.page_count > out.len()
    {
        return Err(MemObjError::BadArg);
    }
    if region.purge == PurgeState::Purged {
        return Err(MemObjError::Purged);
    }
    acquire_locked(region, MEMOBJ_KERNEL_OWNER).ok_or(MemObjError::Closed)?;
    for (slot, &pa) in out.iter_mut().zip(&region.phys_pages[..region.page_count]) {
        *slot = azos_mm::addr::phys_to_virt(pa);
    }
    Ok(region.page_count)
}

/// Give back the reference [`memobj_frames_pin`] took on `r`.
pub fn memobj_frames_unpin(r: u32) {
    let mut regions = MEMOBJS.lock_irqsave();
    if let Ok(i) = live_index(&regions, r) {
        let _ = release_locked(&mut regions[i], MEMOBJ_KERNEL_OWNER);
    }
}

/// The task `tid` is gone: every end it holds on every region is given up and
/// every lock word it died owning is opened, so its peers see end of file,
/// `EPIPE` or a free lock instead of waiting for a holder that will not come.
/// The ring publishes an index only after the bytes are copied, so a lock
/// opened under a holder killed mid-copy exposes no half-written data.
fn pipe_drop_all(tid: u32) {
    // Regions in small batches: the wake table is bounded, the regions are not.
    let mut next = 0usize;
    while next < MAX_MEMOBJS {
        let mut wakes = PipeWakes::new();
        {
            let mut regions = MEMOBJS.lock_irqsave();
            while next < MAX_MEMOBJS && wakes.n + 4 <= wakes.at.len() {
                let i = next;
                next += 1;
                if !regions[i].active {
                    continue;
                }
                let Some(hi) = holder_index(&regions[i], tid) else { continue };
                let held = regions[i].holders[hi].ends;
                let r = LAYOUT.pack(i as u32, regions[i].generation);
                if held != 0 {
                    drop_bits_locked(&mut regions[i], r, hi, held, &mut wakes);
                }
                // A lock is opened whatever the task still held: it may have
                // given an end up while another thread of it was inside a
                // call on the ring.
                if let Some(h) = pipe_header(&regions[i]) {
                    h.recover_locks(tid, |off| wakes.push(r, off));
                }
            }
        }
        wakes.ring();
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Private Anon: the marker-PTE fast path
// ──────────────────────────────────────────────────────────────────────────
//
// An Anon object that one task maps does not need a table slot, a capability or
// a holder record: its frames are the PTEs' and `vmm` frees them on unmap. It is
// the demand-zero mapping an anonymous `SYS_MO_MAP` makes, and it keeps the
// mechanism `azos_mm::demand` built for it: one marker PTE per page, no frame
// until the first touch, the fault resolved by a compare-and-swap on that
// entry with no lock. A pager or an object-aware fault would cost every
// first touch a table lookup; this is what the fast path is for.

/// Reserve `pages` pages of private Anon memory at `base` in the address space
/// rooted at `root`, as the CALLING task: charged to its Domain now, the whole
/// reservation, so a first touch can never be refused for budget
/// (as Linux's strict overcommit). All or nothing: a refusal leaves no
/// marker and no charge. `NoMem` when the Domain cannot take it, `Busy` when
/// part of the range is already mapped or marked.
pub fn anon_reserve(root: usize, base: usize, pages: usize) -> Result<(), MemObjError> {
    // Canary `memobj-anon-uncharged-canary`: the reservation is not charged.
    if !cfg!(feature = "memobj-anon-uncharged-canary") && !azos_sched::mm_charge(pages as u32) {
        return Err(MemObjError::NoMem);
    }
    if azos_mm::demand::map_demand_range(root, base, pages).is_err() {
        // The range wrote no marker (all or nothing); the charge goes back.
        azos_sched::mm_discharge(pages as u32);
        return Err(MemObjError::Busy);
    }
    Ok(())
}

/// Clear the markers in `[start, end)` of the address space rooted at `root`
/// and answer how many there were: reserved pages that were never touched and
/// so hold no frame, which the caller discharges (`unmap_user_range_and_free`
/// counts only the pages that had one). An invalid PTE is never cached in a
/// TLB, so this needs no shootdown.
pub fn anon_release_range(root: usize, start: usize, end: usize) -> u32 {
    let page = azos_arch::PAGE_SIZE;
    let mut n = 0u32;
    let mut va = start;
    while va < end {
        if azos_mm::demand::clear_demand_marker(root, va) {
            n = n.saturating_add(1);
        }
        va += page;
    }
    n
}

// ──────────────────────────────────────────────────────────────────────────
// Paged objects: the page cache (storage L11, part A)
// ──────────────────────────────────────────────────────────────────────────
//
// Module doc, "Paged objects", says what the kind is. Rules this section keeps:
//
// * the backing is called with NO lock held: a fill or a write-back may wait
//   for the medium, and the file layer takes its own locks. Every operation
//   that needs it is three phases, as `memobj_cow_break` is: look under the
//   table lock, do the I/O, take the lock again and re-check the object (the
//   packed reference still live, the page still as it was) before installing;
// * a frame is installed only into an empty slot and names the object at once
//   (`set_frame_owner`), the reverse map every other kind has;
// * the page being written back is pinned by the `flushing` bit, which every
//   path that frees or rewrites a frame honours.

/// Tries a fill makes when the page it just brought in was dropped before it
/// could be used: a drop between two lock holds is possible, a loop of them is
/// a pressure storm the caller should see as `Busy`.
const PAGED_TRIES: usize = 4;

/// Why a Paged operation failed: the object's refusal or the file's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PagedError {
    Obj(MemObjError),
    Io(PageIoError),
}

impl From<MemObjError> for PagedError {
    fn from(e: MemObjError) -> Self {
        PagedError::Obj(e)
    }
}

/// What the cache holds of one Paged object ([`memobj_paged_info_ref`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PagedInfo {
    /// The file page (in the build's page units) that page 0 of the object is.
    pub first: u64,
    /// The file's size in bytes, as the cache clamps to it.
    pub size: u64,
    /// Bit `i`: page `i` has a frame (is in the cache).
    pub resident: u64,
    /// Bit `i`: page `i` has to be written back before it can be dropped
    /// (written, or under a writable mapping).
    pub dirty: u64,
    /// Bit `i`: page `i` is being written back now, by another caller. Its
    /// write is not complete until the bit is clear.
    pub flushing: u64,
}

/// The bytes of a cache frame, the whole page.
///
/// # Safety
/// `phys` is a frame this object table holds for as long as the slice lives:
/// a resident page read or written with the table lock held, a page pinned by
/// its `flushing` bit, or a frame the caller has just allocated and has not
/// published. The direct map covers it.
unsafe fn frame_bytes<'a>(phys: usize) -> &'a mut [u8] {
    // SAFETY: the caller's contract above.
    unsafe { core::slice::from_raw_parts_mut(azos_mm::addr::phys_to_virt(phys) as *mut u8, azos_arch::PAGE_SIZE) }
}

/// The slot of the live Paged object `r` names.
fn paged_slot(regions: &MemObjTable, r: u32) -> Result<usize, MemObjError> {
    let i = live_index(regions, r)?;
    if regions[i].kind == MemKind::Paged && regions[i].paged.is_some() {
        Ok(i)
    } else {
        Err(MemObjError::BadArg)
    }
}

/// Byte offset in the file of page `idx` of the object.
fn paged_file_off(st: &PagedState, idx: usize) -> u64 {
    // `memobj_create_paged` checked that the whole window's byte offsets fit.
    (st.first + idx as u64) * azos_arch::PAGE_SIZE as u64
}

/// Is a writable mapping of the object reaching page `idx`? Its writes leave no
/// record yet (no PTE dirty bit is read), so such a page is taken to be dirty.
fn writable_mapped(region: &MemObj, idx: usize) -> bool {
    region.holders.iter().any(|h| h.is_mapped() && h.map_write && idx < h.map_pages)
}

/// Must page `idx` be written back before its frame can go: written since the
/// last write-back, or under a writable mapping.
fn must_flush(region: &MemObj, idx: usize) -> bool {
    region.paged.is_some_and(|st| st.dirty & (1u64 << idx) != 0) || writable_mapped(region, idx)
}

/// Create the page cache of one window of a file: `pages` pages from file page
/// `first_page` (in units of the build's page), of a file `file_size` bytes
/// long, named `key` to `backing`. Kernel-owned, charged to no Domain, with no
/// frame yet: pages come in on first use. The answer is the packed reference;
/// the kernel's reference is the only one, and
/// [`memobj_paged_close_ref`] is how it ends. `BadArg` for a window of 0 or over
/// [`MAX_MEMOBJ_PAGES`] pages or one whose byte offsets overflow, `NoMem` for a
/// full table.
pub fn memobj_create_paged(
    backing: &'static dyn PageBacking,
    key: PageKey,
    first_page: u64,
    pages: usize,
    file_size: u64,
    perms: MemPerms,
) -> Result<u32, MemObjError> {
    if pages == 0 || pages > MAX_MEMOBJ_PAGES {
        return Err(MemObjError::BadArg);
    }
    let fits = first_page
        .checked_add(pages as u64)
        .and_then(|end| end.checked_mul(azos_arch::PAGE_SIZE as u64))
        .is_some();
    if !fits {
        return Err(MemObjError::BadArg);
    }
    let spec = MemSpec { kind: MemKind::Paged, perms, attrs: 0, device_visible: false };
    let st = PagedState { backing, key, first: first_page, size: file_size, dirty: 0, flushing: 0 };
    claim_slot_cow(MEMOBJ_KERNEL_OWNER, &[0usize; MAX_MEMOBJ_PAGES][..pages], &spec, 0, 0, Some(st))
        .ok_or(MemObjError::NoMem)
}

/// Bring page `idx` of the Paged object `r` names into the cache if it is not
/// there: read from the file outside every lock into a fresh frame, installed
/// if the slot is still empty (a racing fill that won keeps its frame, this
/// one's goes back).
fn paged_page_in(r: u32, idx: usize) -> Result<(), PagedError> {
    let (backing, key, off, size, ident) = {
        let regions = MEMOBJS.lock_irqsave();
        let i = paged_slot(&regions, r)?;
        let o = &regions[i];
        if idx >= o.page_count {
            return Err(MemObjError::BadArg.into());
        }
        if o.phys_pages[idx] != 0 {
            return Ok(());
        }
        let st = o.paged.as_ref().ok_or(MemObjError::BadArg)?;
        (st.backing, st.key, paged_file_off(st, idx), st.size, o.ident)
    };
    let frame = azos_mm::pmm::alloc_page().map_err(|_| MemObjError::NoMem)?;
    // SAFETY: allocated just above and published nowhere yet.
    let bytes = unsafe { frame_bytes(frame.as_usize()) };
    if let Err(e) = azos_mm::pager::fill_page(backing, &key, off, size, bytes) {
        let _ = azos_mm::pmm::free_page(frame);
        return Err(PagedError::Io(e));
    }
    let mut regions = MEMOBJS.lock_irqsave();
    match paged_slot(&regions, r) {
        Ok(i) if regions[i].phys_pages[idx] == 0 => {
            regions[i].phys_pages[idx] = frame.as_usize();
            let _ = azos_mm::pmm::set_frame_owner(frame.as_usize(), ident, idx as u32);
            Ok(())
        }
        other => {
            drop(regions);
            let _ = azos_mm::pmm::free_page(frame);
            other.map(|_| ()).map_err(PagedError::from)
        }
    }
}

/// The frame of page `idx` of the Paged object `r` names, read from the file
/// first if it is not in the cache: what a mapper installs, and so the frame the
/// mapping and the cache share. `write`: the caller is about to write through
/// it (an object that allows it), so the page is dirty from now.
///
/// The frame belongs to the cache and can be dropped when the page is clean
/// ([`memobj_paged_drop_clean`]). A mapper that installs it therefore records
/// the mapping first ([`memobj_note_mapping_ref`]: from then on a drop removes
/// the PTE through the object's mapping list), installs the PTE, and then asks
/// again: the same frame means the PTE is covered, a different or missing one
/// means a drop slipped in before the install and the install is undone. The
/// kernel's own access should not hold a frame at all: use
/// [`memobj_paged_read_ref`] / [`memobj_paged_write_ref`].
///
/// `Obj(Cap(MissingPerms))` for `write` on a read-only object, `Obj(BadArg)`
/// for a page past the window or an object that is not Paged, `Obj(Busy)` if
/// the page keeps being dropped under the call, `Io` if the file cannot be read,
/// `Obj(NoMem)` without a frame.
pub fn memobj_paged_frame_ref(r: u32, idx: usize, write: bool) -> Result<usize, PagedError> {
    for _ in 0..PAGED_TRIES {
        if write {
            let regions = MEMOBJS.lock_irqsave();
            let i = paged_slot(&regions, r)?;
            if regions[i].perms != MemPerms::ReadWrite {
                return Err(MemObjError::Cap(CapError::MissingPerms).into());
            }
        }
        paged_page_in(r, idx)?;
        let mut regions = MEMOBJS.lock_irqsave();
        let i = paged_slot(&regions, r)?;
        let o = &mut regions[i];
        let phys = o.phys_pages[idx];
        if phys == 0 {
            continue; // dropped between the fill and here: bring it in again
        }
        if write {
            if let Some(st) = o.paged.as_mut() {
                st.dirty |= 1u64 << idx;
            }
        }
        return Ok(phys);
    }
    Err(MemObjError::Busy.into())
}

/// The shared body of [`memobj_paged_read_ref`] and [`memobj_paged_write_ref`].
enum PagedIo<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

fn paged_io(r: u32, off: usize, mut io: PagedIo<'_>) -> Result<(usize, usize), PagedError> {
    let page = azos_arch::PAGE_SIZE;
    let len = match &io {
        PagedIo::Read(b) => b.len(),
        PagedIo::Write(b) => b.len(),
    };
    if let PagedIo::Write(_) = io {
        let regions = MEMOBJS.lock_irqsave();
        let i = paged_slot(&regions, r)?;
        if regions[i].perms != MemPerms::ReadWrite {
            return Err(MemObjError::Cap(CapError::MissingPerms).into());
        }
    }
    let mut done = 0usize;
    let mut newly = 0usize;
    let mut misses = 0usize;
    while done < len {
        let step: Result<Option<usize>, PagedError> = {
            let mut regions = MEMOBJS.lock_irqsave();
            let i = paged_slot(&regions, r)?;
            let o = &mut regions[i];
            let Some(st) = o.paged else { return Err(MemObjError::BadArg.into()) };
            let Some(pos) = off.checked_add(done) else { break };
            let idx = pos / page;
            // The end of the window, or of the file: a short count, not an error.
            let file_pos = st.first.saturating_mul(page as u64).saturating_add(pos as u64);
            if idx >= o.page_count || file_pos >= st.size {
                break;
            }
            let n = (len - done).min(page - pos % page).min((st.size - file_pos).min(usize::MAX as u64) as usize);
            let phys = o.phys_pages[idx];
            if phys == 0 {
                Ok(None)
            } else if matches!(io, PagedIo::Write(_)) && st.flushing & (1u64 << idx) != 0 {
                // The write-back is reading this frame without the lock.
                drop(regions);
                return if done > 0 { Ok((done, newly)) } else { Err(MemObjError::Busy.into()) };
            } else {
                // SAFETY: a resident page of the object, with the table locked.
                let frame = unsafe { frame_bytes(phys) };
                let at = pos % page;
                match &mut io {
                    PagedIo::Read(b) => b[done..done + n].copy_from_slice(&frame[at..at + n]),
                    PagedIo::Write(b) => {
                        frame[at..at + n].copy_from_slice(&b[done..done + n]);
                        if let Some(st) = o.paged.as_mut() {
                            newly += usize::from(st.dirty & (1u64 << idx) == 0);
                            st.dirty |= 1u64 << idx;
                        }
                    }
                }
                Ok(Some(n))
            }
        };
        match step {
            Ok(Some(n)) => {
                done += n;
                misses = 0;
            }
            Ok(None) => {
                misses += 1;
                if misses > PAGED_TRIES {
                    return if done > 0 { Ok((done, newly)) } else { Err(MemObjError::Busy.into()) };
                }
                if let Err(e) = paged_page_in(r, (off + done) / page) {
                    return if done > 0 { Ok((done, newly)) } else { Err(e) };
                }
            }
            Err(e) => return if done > 0 { Ok((done, newly)) } else { Err(e) },
        }
    }
    Ok((done, newly))
}

/// Read up to `dst.len()` bytes of the Paged object `r` names, from byte `off`
/// of the object's window, through the cache: a page that is not there is read
/// from the file first. Fewer bytes than asked means the window or the file
/// ended. The copy is made with the table locked, so no frame is held after the
/// call.
pub fn memobj_paged_read_ref(r: u32, off: usize, dst: &mut [u8]) -> Result<usize, PagedError> {
    paged_io(r, off, PagedIo::Read(dst)).map(|(n, _)| n)
}

/// Write `src` into the Paged object `r` names at byte `off` of its window,
/// through the cache; the pages are dirty until written back. A write stops at
/// the end of the file (the cache never lengthens it): the first count says how
/// much went in, the second how many of those pages were clean before (what the
/// file layer charges to the writer's Domain). `Obj(Cap(MissingPerms))` on a
/// read-only object, `Obj(Busy)` while the page is being written back.
pub fn memobj_paged_write_ref(r: u32, off: usize, src: &[u8]) -> Result<(usize, usize), PagedError> {
    paged_io(r, off, PagedIo::Write(src))
}

/// Write back every page of the Paged object `r` names that has to be: the
/// dirty ones, and those under a writable mapping (taken to be dirty). Answers
/// how many pages were written. The dirty bit is cleared BEFORE the write, so a
/// write that lands during it keeps the page dirty; a page whose write fails is
/// dirty again and the first error is the answer. The caller holds a reference
/// (the kernel's) for the whole call: a pinned page is not dropped, but the
/// object freed under the call would take the frame with it.
pub fn memobj_paged_writeback_ref(r: u32) -> Result<usize, PagedError> {
    let pages = {
        let regions = MEMOBJS.lock_irqsave();
        regions[paged_slot(&regions, r)?].page_count
    };
    let mut written = 0usize;
    for idx in 0..pages {
        let bit = 1u64 << idx;
        let (backing, key, off, size, phys) = {
            let mut regions = MEMOBJS.lock_irqsave();
            let i = paged_slot(&regions, r)?;
            let o = &mut regions[i];
            let phys = o.phys_pages[idx];
            let flush = phys != 0 && must_flush(o, idx);
            let Some(st) = o.paged.as_mut() else { return Err(MemObjError::BadArg.into()) };
            if !flush || st.flushing & bit != 0 {
                continue;
            }
            st.dirty &= !bit;
            st.flushing |= bit;
            (st.backing, st.key, paged_file_off(st, idx), st.size, phys)
        };
        // SAFETY: pinned by `flushing`, which the drop and the kernel's write honour.
        let src = unsafe { frame_bytes(phys) };
        let res = azos_mm::pager::write_back_page(backing, &key, off, size, src);
        {
            let mut regions = MEMOBJS.lock_irqsave();
            let i = paged_slot(&regions, r)?;
            if let Some(st) = regions[i].paged.as_mut() {
                st.flushing &= !bit;
                if res.is_err() {
                    st.dirty |= bit;
                }
            }
        }
        res.map_err(PagedError::Io)?;
        written += 1;
    }
    Ok(written)
}

/// Give back the frames of up to `max_pages` clean cached pages, across every
/// Paged object, and answer how many went. The memory-pressure entry of the
/// page cache. A page goes if it is in the cache, is not dirty or under a
/// writable mapping, is not being written back, and its object has no pinned
/// holder (the mapping list could miss a PTE): the
/// object's mapping list unmaps it from every address space first (the rmap),
/// then the frame goes back to the allocator. The next
/// use reads the page from the file again. Dirty pages stay: write them back
/// first ([`memobj_paged_writeback_ref`]).
pub fn memobj_paged_drop_clean(max_pages: usize) -> usize {
    let mut regions = MEMOBJS.lock_irqsave();
    let mut dropped = 0usize;
    for i in 0..MAX_MEMOBJS {
        if dropped >= max_pages {
            break;
        }
        let o = &mut regions[i];
        if !o.active || o.kind != MemKind::Paged || any_pinned(o) {
            continue;
        }
        for idx in 0..o.page_count {
            if dropped >= max_pages {
                break;
            }
            let flushing = o.paged.is_some_and(|st| st.flushing & (1u64 << idx) != 0);
            if o.phys_pages[idx] == 0 || flushing || must_flush(o, idx) {
                continue;
            }
            unmap_frame_in(o, idx);
            release_frame(o, idx);
            dropped += 1;
        }
    }
    drop(regions);
    record_purge(0, PURGE_PAGE_CACHE, dropped);
    dropped
}

/// What one page-cache reclaim pass did ([`memobj_paged_reclaim`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PagedReclaim {
    /// Pages written back to their files.
    pub written: usize,
    /// Clean pages whose frames went back to the allocator.
    pub dropped: usize,
    /// Objects whose write-back failed (the file said no): their dirty pages
    /// stay, and only clean pages elsewhere were dropped.
    pub failed: usize,
}

/// The slot index and reference of the first live Paged object at or after
/// slot `from`: the walk of [`memobj_paged_reclaim`]'s write-back, one object
/// per lock hold.
fn paged_object_from(from: usize) -> Option<(usize, u32)> {
    let regions = MEMOBJS.lock_irqsave();
    (from..MAX_MEMOBJS).find(|&i| regions[i].active && regions[i].kind == MemKind::Paged).map(|i| (i, regions[i].ident))
}

/// The page cache's reclaim pass, the first stage of memory reclaim (before
/// anything is compressed or swapped): write back every Paged object's dirty
/// pages ([`memobj_paged_writeback_ref`]), then give back the frames of up to
/// `max_pages` clean ones ([`memobj_paged_drop_clean`]). The order is the point:
/// a page that was dirty a moment ago is clean now and can go in the same pass.
/// Runs the file layer's I/O in the caller, with no lock held across it, so
/// the caller is a task that may sleep and is never a real-time one.
///
/// The kernel's reference to each object (it is kernel-owned, and
/// [`memobj_paged_close_ref`] is the one thing that ends it) holds it for the
/// write-back; an object closed between the walk and its write-back answers
/// stale and is skipped, and a close that finds a page being written back
/// retries (it does not free the frame under the write).
pub fn memobj_paged_reclaim(max_pages: usize) -> PagedReclaim {
    let mut out = PagedReclaim::default();
    let mut from = 0;
    while let Some((i, r)) = paged_object_from(from) {
        from = i + 1;
        match memobj_paged_writeback_ref(r) {
            Ok(n) => out.written += n,
            Err(PagedError::Io(_)) => out.failed += 1,
            // Closed since the walk: nothing to write, nothing to drop.
            Err(PagedError::Obj(_)) => {}
        }
    }
    out.dropped = memobj_paged_drop_clean(max_pages);
    out
}

/// What the cache holds of the Paged object `r` names.
pub fn memobj_paged_info_ref(r: u32) -> Result<PagedInfo, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    let i = paged_slot(&regions, r)?;
    let o = &regions[i];
    let Some(st) = o.paged else { return Err(MemObjError::BadArg) };
    let mut info = PagedInfo { first: st.first, size: st.size, resident: 0, dirty: 0, flushing: st.flushing };
    for idx in 0..o.page_count {
        if o.phys_pages[idx] != 0 {
            info.resident |= 1u64 << idx;
            if must_flush(o, idx) {
                info.dirty |= 1u64 << idx;
            }
        }
    }
    Ok(info)
}

/// Give back the frames of pages `from_idx..` of the Paged object `o`, dirty
/// ones too, after unmapping them from every address space that maps them.
/// Their dirty bits go with them. `Busy`, with nothing dropped, while a holder
/// is pinned (the mapping list could miss a PTE) or a page of the range is
/// being written back (the write reads its frame without the lock).
fn paged_forget_locked(o: &mut MemObj, from_idx: usize) -> Result<(), MemObjError> {
    if from_idx >= o.page_count {
        return Ok(());
    }
    let flushing = o.paged.map_or(0, |st| st.flushing);
    if any_pinned(o) || (from_idx..o.page_count).any(|idx| flushing & (1u64 << idx) != 0) {
        return Err(MemObjError::Busy);
    }
    for idx in from_idx..o.page_count {
        if o.phys_pages[idx] != 0 {
            unmap_frame_in(o, idx);
            release_frame(o, idx);
        }
        if let Some(st) = o.paged.as_mut() {
            st.dirty &= !(1u64 << idx);
        }
    }
    Ok(())
}

/// Index in the object of the page that holds file byte `byte`, or past the
/// window when the byte is after it (`page_count` at most).
fn paged_page_of(o: &MemObj, st: &PagedState, byte: u64) -> usize {
    let file_page = byte / azos_arch::PAGE_SIZE as u64;
    file_page.saturating_sub(st.first).min(o.page_count as u64) as usize
}

/// Forget the pages of the Paged object `r` names that hold a byte at or after
/// file byte `from`, DIRTY ONES TOO and without writing them: the file changed
/// under them or is gone (unlink, truncate, rename over it), and a dirty page
/// written back later would put its bytes into whatever now has the file's
/// name. Mappings of the pages are removed first. `from` before the window
/// forgets all of it. `Obj(Busy)` while a page of the range is being written
/// back or a holder is pinned: nothing was forgotten, the caller tries again.
pub fn memobj_paged_forget_ref(r: u32, from: u64) -> Result<(), PagedError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = paged_slot(&regions, r)?;
    let o = &mut regions[i];
    let Some(st) = o.paged else { return Err(MemObjError::BadArg.into()) };
    // A byte inside page `p` keeps the pages before `p` only.
    let idx = paged_page_of(o, &st, from);
    paged_forget_locked(o, idx).map_err(PagedError::from)
}

/// Attach the Paged object `r` names to a file of `new_size` bytes: the cache's
/// reads and write-backs clamp to it from now on. The contract the file layer
/// states for `PageCacheHooks::read`:
///
/// * the same size: nothing happens (one lock hold);
/// * a LONGER file keeps its pages except the one that held the old end, which
///   has zeros after the old end that are bytes now (the file was lengthened
///   behind the cache), and the pages after it. The file is not refilled whole
///   at every append;
/// * a SHORTER file is another object: every page goes;
/// * what is dirty is written back FIRST, at the old size, so no page leaves
///   with its bytes unwritten and none is written past the end it had.
///
/// `Obj(Busy)` when a page that has to go keeps being dirtied or written back
/// (a few passes), `Io` when the write-back fails (nothing changed).
pub fn memobj_paged_set_size_ref(r: u32, new_size: u64) -> Result<(), PagedError> {
    for _ in 0..PAGED_TRIES {
        let old = {
            let regions = MEMOBJS.lock_irqsave();
            let i = paged_slot(&regions, r)?;
            regions[i].paged.map_or(0, |st| st.size)
        };
        if old == new_size {
            return Ok(());
        }
        memobj_paged_writeback_ref(r)?;
        let mut regions = MEMOBJS.lock_irqsave();
        let i = paged_slot(&regions, r)?;
        let o = &mut regions[i];
        let Some(st) = o.paged else { return Err(MemObjError::BadArg.into()) };
        if st.size != old {
            continue; // attached at another size meanwhile: decide again
        }
        let from = if new_size > old { paged_page_of(o, &st, old) } else { 0 };
        // Dirtied since the write-back: the loop writes it at the old size.
        if (from..o.page_count).any(|idx| st.dirty & (1u64 << idx) != 0) {
            continue;
        }
        paged_forget_locked(o, from)?;
        if let Some(st) = o.paged.as_mut() {
            st.size = new_size;
        }
        return Ok(());
    }
    Err(MemObjError::Busy.into())
}

/// End the page cache of one window: write back what is dirty, then let go of
/// the kernel's reference, which frees the frames. The last reference only:
/// `Obj(Busy)` while another task holds one (it is still using the pages; the
/// dirty ones are not lost, the object stays) or after a few passes that each
/// found the pages dirty again. A write-back error is the answer and the object
/// stays.
pub fn memobj_paged_close_ref(r: u32) -> Result<(), PagedError> {
    for _ in 0..PAGED_TRIES {
        memobj_paged_writeback_ref(r)?;
        let mut regions = MEMOBJS.lock_irqsave();
        let i = paged_slot(&regions, r)?;
        let o = &mut regions[i];
        if total_refs(o) != 1 {
            return Err(MemObjError::Busy.into());
        }
        let busy = (0..o.page_count).any(|idx| {
            o.phys_pages[idx] != 0
                && (must_flush(o, idx) || o.paged.is_some_and(|st| st.flushing & (1u64 << idx) != 0))
        });
        if busy {
            continue; // written again since the pass: flush that too
        }
        return if release_locked(o, MEMOBJ_KERNEL_OWNER) { Ok(()) } else { Err(MemObjError::Busy.into()) };
    }
    Err(MemObjError::Busy.into())
}

// ──────────────────────────────────────────────────────────────────────────
// Volatile objects: memory that may be dropped under pressure
// ──────────────────────────────────────────────────────────────────────────
//
// Module doc, "Volatile objects", says what the state is. The purge is the
// third of the object table's reclaim entries, beside `memobj_paged_drop_clean`
// (a clean cache page: re-read from the file) and the compressed pool (an
// anonymous region page: restored on a fault): it is the one that needs no
// copy and no I/O, because the owner can rebuild what it dropped.

/// `Rule::Purge`'s `what`: the page cache.
const PURGE_PAGE_CACHE: u64 = 1;
/// `Rule::Purge`'s `what`: anonymous pages (a volatile object's).
const PURGE_ANON: u64 = 2;

/// The `Rule::Purge` record of `pages` pages dropped, subject Domain `key` (0:
/// the whole machine). Written with no table lock held: a record may be flushed
/// to the medium. Nothing for no pages.
fn record_purge(key: u32, what: u64, pages: usize) {
    if pages != 0 {
        let bytes = (pages * azos_arch::PAGE_SIZE) as u64;
        azos_decision::record(azos_decision::Rule::Purge, azos_decision::Verdict::Admit, key, [what, bytes, 0]);
    }
}

/// Mark the volatile object `r` names droppable (`volatile`: the owner does not
/// need its contents now) or in use again (`!volatile`). Answers whether the
/// object was purged: `true` means its contents are gone for good and the state
/// did not change (module doc). `BadArg` for an object created without
/// [`ATTR_VOLATILE`]; `Cap(MissingPerms)` unless `tid` is the object's owner
/// (the one who made it, or received its owning reference by a MOVE): a
/// holder that only shares the object must not make it droppable under the
/// others.
pub fn memobj_set_volatile_ref(tid: u32, r: u32, volatile: bool) -> Result<bool, MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let o = &mut regions[i];
    if o.attrs & ATTR_VOLATILE == 0 {
        return Err(MemObjError::BadArg);
    }
    if o.owner_task != tid {
        return Err(MemObjError::Cap(CapError::MissingPerms));
    }
    if o.purge == PurgeState::Purged {
        return Ok(true);
    }
    o.purge = if volatile { PurgeState::Volatile } else { PurgeState::Held };
    Ok(false)
}

/// Keep a volatile object from being purged while a mapping of it is built.
/// A mapper reads the frames' addresses, installs page-table leaves and only
/// then books the mapping ([`memobj_note_mapping_ref`]); a purge in between
/// finds no mapping to remove and frees the frames under the leaves. This takes
/// the kernel's own reference (which [`memobj_purge_volatile`] respects), and
/// the caller gives it back with [`memobj_frames_unpin`] once the mapping is
/// booked or undone. `Ok(false)` for an object that is not volatile (nothing
/// to give back), `Purged` for one already purged (nothing to map), `Closed`
/// when the holder table is full.
pub fn memobj_pin_for_map(r: u32) -> Result<bool, MemObjError> {
    let mut regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let o = &mut regions[i];
    if o.attrs & ATTR_VOLATILE == 0 {
        return Ok(false);
    }
    if o.purge == PurgeState::Purged {
        return Err(MemObjError::Purged);
    }
    acquire_locked(o, MEMOBJ_KERNEL_OWNER).ok_or(MemObjError::Closed)?;
    Ok(true)
}

/// May reclaim take this object's frames now? `mem_locked` answers whether a
/// Domain key is on a `mem = "locked"` row.
fn purgeable(o: &MemObj, mem_locked: fn(u32) -> bool) -> bool {
    // Canary `memobj-purge-held-canary`: an object in use is taken too.
    let volatile = o.purge == PurgeState::Volatile || (cfg!(feature = "memobj-purge-held-canary") && o.purge == PurgeState::Held);
    // Canary `memobj-purge-kernel-held-canary`: the kernel's own reference
    // (`memobj_frames_pin`: direct-map addresses of the frames; a guest's RAM)
    // does not stop the purge.
    let kernel_held = o.holders.iter().any(|h| h.refs > 0 && h.tid == MEMOBJ_KERNEL_OWNER)
        && !cfg!(feature = "memobj-purge-kernel-held-canary");
    // Canary `memobj-purge-locked-canary`: a `mem = "locked"` Domain's object
    // is taken like any other.
    let locked = o.charge_key != 0 && mem_locked(o.charge_key) && !cfg!(feature = "memobj-purge-locked-canary");
    o.active
        && o.attrs & ATTR_VOLATILE != 0
        && volatile
        && o.cow_shared == 0
        && !any_pinned(o)
        && !kernel_held
        && !locked
}

/// Take the frames of volatile object `o`: unmap it from every holder, free the
/// frames, give the charge back. Table lock held. The Domain that was charged
/// and the pages freed.
fn purge_locked(o: &mut MemObj) -> (u32, usize) {
    for hi in 0..MAX_MEMOBJ_HOLDERS {
        let h = &mut o.holders[hi];
        if h.is_mapped() {
            let (tid, root, va, pages) = (h.tid, h.map_root, h.map_va, h.map_pages);
            h.clear_mapping();
            // The PTEs go now, shot down on every hart, before a frame is
            // freed; the window addresses are the holder's to give back, as
            // after a MOVE.
            unmap_range(root, va, pages);
            note_moved_window(tid, va, pages);
        }
    }
    let pages = o.page_count;
    for idx in 0..pages {
        release_frame(o, idx);
    }
    // The frames are not the Domain's any more; zeroed so the last release does
    // not give them back a second time. The metadata's charge (`meta_key`)
    // stays until the object does.
    let key = o.charge_key;
    if key != 0 {
        azos_sched::mm_discharge_domain(key, pages as u32);
        o.charge_key = 0;
    }
    o.purge = PurgeState::Purged;
    (key, pages)
}

/// Drop the frames of volatile objects until `max_pages` pages are free again
/// or none is left to take; the pages freed. The memory-pressure entry of the
/// volatile objects: stage 0 of a reclaim pass, before the page cache is
/// written and before anything is compressed, because nothing is written or
/// copied. `mem_locked` answers whether a Domain is on a `mem = "locked"` row
/// (`azos_sched::domain::mem_locked`): its objects stay. One `Rule::Purge`
/// record per object, written with no lock held. An object is dropped whole,
/// so the answer may exceed `max_pages` by less than one object.
pub fn memobj_purge_volatile(max_pages: usize, mem_locked: fn(u32) -> bool) -> usize {
    let mut freed = 0usize;
    let mut from = 0usize;
    while freed < max_pages {
        let mut regions = MEMOBJS.lock_irqsave();
        let Some(i) = (from..MAX_MEMOBJS).find(|&i| purgeable(&regions[i], mem_locked)) else { break };
        from = i + 1;
        let (key, pages) = purge_locked(&mut regions[i]);
        drop(regions);
        record_purge(key, PURGE_ANON, pages);
        freed += pages;
    }
    freed
}

// ──────────────────────────────────────────────────────────────────────────
// Cap<Shm> typed wrappers
// ──────────────────────────────────────────────────────────────────────────
//
// Same shape as `port_*_cap`: each typed entry validates the cap against
// the caller's per-task `CapTable`, then delegates to the existing
// integer-handle logic. `memobj_create_cap` allocates a region *and* mints
// the cap atomically (it cannot leave a region orphaned on cap-table
// exhaustion — the region is freed if the grant fails).

/// Errors returned by the typed `shm_*_cap` functions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemObjError {
    /// Capability dereference failed (stale / wrong kind / missing perms).
    Cap(crate::cap::CapError),
    /// Out of memory or no free region slot.
    NoMem,
    /// Caller asked for 0 pages or > [`MAX_MEMOBJ_PAGES`].
    BadArg,
    /// Region doesn't exist or has been released.
    Closed,
    /// Cap-table slot table is full — the region was rolled back.
    Full,
    /// The operation needs the object unmapped (a COW break under a live
    /// mapping, a write mapping of a clone another task already maps).
    Busy,
    /// A volatile object whose frames reclaim took ([`PurgeState::Purged`]):
    /// there is nothing to map or copy. The holder creates a new object.
    Purged,
}

impl From<crate::cap::CapError> for MemObjError {
    fn from(e: crate::cap::CapError) -> Self {
        Self::Cap(e)
    }
}

/// Derive `CapPerms` for a freshly-minted Shm cap from the region's own access
/// mode, for the task that made the region: ReadOnly → READ; ReadWrite → RW;
/// both with `MAP` (its creator maps it), `DUP` (it may share it) and
/// `TRANSFER` (it may hand it over). Callers that want a more restricted grant
/// (e.g. duplicating read-only into a child) derive with fewer rights.
fn cap_perms_for(perms: MemPerms) -> crate::cap::CapPerms {
    use crate::cap::CapPerms;
    let access = match perms {
        MemPerms::ReadOnly => CapPerms::READ,
        MemPerms::ReadWrite => CapPerms::RW,
    };
    access.union(CapPerms::MAP).union(CapPerms::DELEGATE)
}

/// Typed `memobj_create`: allocates a region with `page_count` pages and
/// mints a `Cap<Shm>` into `tid`'s cap-table.
///
/// On cap-table exhaustion the region is released so the caller never
/// observes a partial state.
pub fn memobj_create_cap(
    tid: u32,
    page_count: usize,
    spec: &MemSpec,
) -> Result<crate::cap::Cap<crate::cap::targets::Shm>, MemObjError> {
    let r = memobj_create_spec(tid, page_count, spec)?;
    // A POSIX pipe starts with one reader and one writer, the creator's
    // (`azos_bytepipe::BytePipe::init`): its record holds both. Meaningless
    // for a region that is no pipe (nothing reads it then).
    pipe_creator_ends(tid, r);
    let perms = spec.perms;
    // The capability stores the packed `(index, generation)`. `MAP` and
    // `DELEGATE` (owner decision 2026-09-26, O3.4): the creator maps its own
    // region and may share or gift it.
    match objref::grant_packed::<crate::cap::targets::Shm>(tid, cap_perms_for(perms), r) {
        Some(cap) => Ok(cap),
        None => {
            // Roll back the region so we don't leak it on cap-table
            // exhaustion. `memobj_create` booked one reference against `tid`, so a
            // single release will free all pages and clear the slot. The
            // region has never been mapped at this point, so the "no live
            // mapping" refusal cannot fire.
            let _ = memobj_release_ref(tid, r);
            Err(MemObjError::Full)
        }
    }
}

/// Typed clone: a COW snapshot of the object `src` names in `tid`'s table
/// (requires `READ`), owned by `tid` and charged to its Domain, with its own
/// `Cap<Shm>` of access mode `perms`. `page_count` is 0 or the source's page
/// count (`BadArg` otherwise).
pub fn memobj_clone_cap(
    tid: u32,
    src: crate::cap::Cap<crate::cap::targets::Shm>,
    perms: MemPerms,
    page_count: usize,
) -> Result<crate::cap::Cap<crate::cap::targets::Shm>, MemObjError> {
    let r = crate::cap_store::get(tid, src, crate::cap::CapPerms::READ)?;
    if page_count != 0 && page_count != memobj_describe_ref(r)?.page_count {
        return Err(MemObjError::BadArg);
    }
    let nr = memobj_clone(tid, r, tid, perms)?;
    match objref::grant_packed::<crate::cap::targets::Shm>(tid, cap_perms_for(perms), nr) {
        Some(cap) => Ok(cap),
        None => {
            let _ = memobj_release_ref(tid, nr);
            Err(MemObjError::Full)
        }
    }
}

/// Typed acquire: validates the cap (requires `READ`) and bumps
/// `tid`'s reference on the region. Returns `(page_count, perms)`.
///
/// `tid` must be the task the cap table belongs to — the reference is
/// booked against it, and only it can give the reference back.
///
/// The capability's generation is compared with the region's inside the
/// table lock the acquire takes: a capability to a freed or
/// reused region answers `Stale`.
pub fn memobj_acquire_cap(
    tid: u32,
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
    op: u16,
) -> Result<(usize, MemPerms), MemObjError> {
    let r = table.get_op(cap, crate::cap::CapPerms::READ, op)?;
    memobj_acquire_ref(tid, r)
}

/// Typed release: validates the cap (requires `READ`, since release is
/// paired with acquire and any holder may give back its own references),
/// gives back **every** reference `tid` holds on the region except a pinned
/// one ([`memobj_release_holder_ref`]), **and deletes the cap's slot** (a share
/// made from it stays with its holder: delete is not revoke). Refused
/// (`Closed`) while `tid` still has a mapping recorded; the slot is deleted on
/// every answer.
///
/// The capability is `tid`'s only name for those references, so they go
/// with it: releasing one and revoking the name left the rest booked to `tid`
/// until its exit.
///
/// **WHY the cap is revoked here (W3-F5):** shm ids are handed out
/// first-free-slot, and `CapTable::get` only validates the cap-table slot's
/// own generation — which a region teardown does not touch. Leaving the cap
/// live after the reference is given up means that once the region is freed
/// and id `n` is reissued to a different task, the stale cap still
/// dereferences to `n` and drives somebody else's region: a textbook
/// confused deputy. The previous doc explicitly told callers to revoke
/// separately; nothing did.
///
/// The untyped `SYS_IPC_UNSHARE` it paired with was retired with the move to
/// generation-stamped handles;
/// `SYS_MO_UNMAP` removes the caller's mapping before it calls this.
pub fn memobj_release_cap(
    tid: u32,
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
) -> Result<(), MemObjError> {
    memobj_release_cap_op(tid, table, cap, azos_abi::invoke::op(azos_abi::cap::CapKind::MemObj, azos_abi::invoke::CLASS_CTL, 0))
}

/// [`memobj_release_cap`] for a release that is an op of the caller's:
/// `op` discharges an `OP_MASK` caveat of the capability (`SYS_MO_UNMAP`
/// passes the class-only op of `CTL`, the class that "ends an object").
pub fn memobj_release_cap_op(
    tid: u32,
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
    op: u16,
) -> Result<(), MemObjError> {
    let r = table.get_op(cap, crate::cap::CapPerms::READ, op)?;
    let released = memobj_release_holder_ref(tid, r);
    table.delete(cap);
    released
}

/// Wipe the region table without returning pages, and restart every slot's
/// generation source. Host-test hygiene only: the suite shares one static
/// table, and the page allocator shim is reset separately. Never built into
/// the kernel.
#[cfg(test)]
pub fn __memobj_reset_for_tests() {
    let mut regions = MEMOBJS.lock_irqsave();
    for i in 0..MAX_MEMOBJS {
        regions[i] = MemObj::empty();
        regions.next_gen[i] = 1;
    }
    drop(regions);
    // The windows a MOVE, a revoke or a shrink left for their tasks belong to
    // the table that was just emptied.
    let mut moved = MOVED_WINDOWS.lock_irqsave();
    moved.iter_mut().for_each(|row| *row = (0, 0, 0));
    MOVED_PENDING.store(0, Ordering::Release);
}

/// Fast-forward slot `i`'s own generation source, so a host test reaches its
/// wrap without `LAYOUT.gen_max()` create/release cycles at that index.
#[cfg(test)]
pub fn __memobj_set_next_gen_for_tests(i: usize, next_gen: u32) {
    MEMOBJS.lock_irqsave().next_gen[i] = next_gen;
}

/// Set the references `tid` holds on slot `shm_id` to `refs`, taking a free
/// holder slot if it holds none: a host test starts a holder near `u32::MAX`
/// without four billion acquires.
#[cfg(test)]
pub fn __memobj_set_refs_for_tests(shm_id: u32, tid: u32, refs: u32) {
    let mut regions = MEMOBJS.lock_irqsave();
    let region = &mut regions[shm_id as usize];
    let (idx, _) = holder_slot(region, tid).expect("a holder slot");
    region.holders[idx] = MemHolder { tid, refs, ..MemHolder::empty() };
}

/// The generation stamped in slot `shm_id` (host tests).
#[cfg(test)]
pub fn __memobj_generation_for_tests(shm_id: u32) -> u32 {
    MEMOBJS.lock_irqsave()[shm_id as usize].generation
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;
    use crate::cap::targets::{IoRing, Shm};
    use crate::cap::{Cap, CapPerms};
    use crate::cap_store;

    // `tests/host/ipc-tests`' scheduler shim maps a TID below `MAX_TASKS` to
    // the task-pool slot of the same number.
    const A: u32 = 21;
    const B: u32 = 22;
    const C: u32 = 23;
    const STALE: MemObjError = MemObjError::Cap(CapError::Stale);

    /// The crate-wide serial lock (the page shim is shared with the io_ring
    /// and port suites), an empty region table and three empty cap tables.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        __memobj_reset_for_tests();
        for tid in [A, B, C] {
            cap_store::reset(tid);
        }
        g
    }

    /// The op a map resolves with (`SYS_MO_MAP`: the class-only op of `CTL`).
    const MAP_OP: u16 = azos_abi::invoke::op(azos_abi::cap::CapKind::MemObj, azos_abi::invoke::CLASS_CTL, 0);

    /// A region created by `tid` through the typed path: its capability and the
    /// packed reference the capability stores.
    fn create(tid: u32) -> (Cap<Shm>, u32) {
        let cap = memobj_create_cap(tid, 1, &MemSpec::anon(MemPerms::ReadWrite)).expect("create");
        (cap, cap_store::get(tid, cap, CapPerms::READ).expect("a fresh capability resolves"))
    }

    /// Another holder's capability for `r`, minted the way every packed
    /// capability is.
    fn mint(tid: u32, r: u32) -> Cap<Shm> {
        objref::grant_packed::<Shm>(tid, CapPerms::RW, r).expect("mint")
    }

    /// `memobj_acquire_cap` through `tid`'s own table; answers the page count.
    fn acquire(tid: u32, cap: Cap<Shm>) -> Result<usize, MemObjError> {
        cap_store::with_table(tid, |t| memobj_acquire_cap(tid, t, cap, azos_abi::invoke::MEMOBJ_ACQUIRE))
            .expect("a live tid")
            .map(|(pages, _)| pages)
    }

    fn release(tid: u32, cap: Cap<Shm>) -> Result<(), MemObjError> {
        cap_store::with_table(tid, |t| memobj_release_cap(tid, t, cap)).expect("a live tid")
    }

    fn refs(shm_id: u32) -> Option<u32> {
        memobj_info(shm_id).map(|(_, refs, _)| refs)
    }

    /// **OVSwrap review F5: the notify word is read with its page pinned.**
    /// `memobj_with_word_ref` runs its closure with the region table locked, so a
    /// last-holder release (which frees frames only under that lock) cannot
    /// land between the lookup and the load. Asserted from inside the closure:
    /// the table's lock is held. The word read is the one written through the
    /// region's own page, and an offset past the region answers `None`.
    ///
    /// **Canary (by hand, 2026-10-02).** In `memobj_with_word_ref`, `drop(regions)`
    /// before calling `f` (the old shape: address under the lock, load after):
    /// red on "the region table was unlocked during the load".
    #[test]
    fn the_notify_word_is_loaded_with_the_region_table_locked() {
        let _g = setup();
        let (_cap, r) = create(A);
        let phys = memobj_page_phys_ref(r, 0).unwrap().unwrap();
        let w = azos_mm::addr::phys_to_virt(phys) + 8;
        unsafe { (*(w as *const AtomicU32)).store(0x5eed_f00d, Ordering::Release) };
        let (v, unlocked) = memobj_with_word_ref(r, 8, |word| {
            (word.load(Ordering::Acquire), __memobj_table_unlocked_for_tests())
        })
        .expect("a live reference")
        .expect("offset 8 is inside the region");
        assert_eq!(v, 0x5eed_f00d, "the word was not read through the region's page");
        assert!(!unlocked, "the region table was unlocked during the load");
        assert!(__memobj_table_unlocked_for_tests(), "the lock outlived the call");
        let page = azos_arch::PAGE_SIZE;
        assert_eq!(memobj_with_word_ref(r, page, |w| w.load(Ordering::Acquire)), Ok(None));
        assert_eq!(memobj_with_word_ref(r, 6, |w| w.load(Ordering::Acquire)), Ok(None));
    }

    /// **A span is the region's own memory, under the table lock, and only
    /// when the kernel may use it whole.** The closure's address is the
    /// region's first frame through the direct map and the table is locked
    /// across it; a span longer than the region, a read-only region, a frame
    /// shared with a clone and frames that are not contiguous are each `None`
    /// (a ring would otherwise be written in pieces, or into the clone's data);
    /// a released region is `Stale`, never an address.
    ///
    /// **Canary (by hand).** Drop the `cow_shared` test: the shared region
    /// hands out its address. Drop the contiguity loop: the broken region does.
    #[test]
    fn a_span_is_the_regions_own_memory_under_the_lock_and_only_when_whole() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let (cap, r) = create(A);
        let phys = memobj_page_phys_ref(r, 0).unwrap().unwrap();
        let (base, unlocked) = memobj_with_span_ref(r, 64, |b| {
            unsafe { *(b as *mut u8) = 0x5a };
            (b, __memobj_table_unlocked_for_tests())
        })
        .expect("live")
        .expect("one page, read-write, whole");
        assert_eq!(base, azos_mm::addr::phys_to_virt(phys), "not the region's first frame");
        assert!(!unlocked, "the region table was unlocked during the closure");
        assert_eq!(unsafe { *(base as *const u8) }, 0x5a);
        assert_eq!(memobj_with_span_ref(r, page + 1, |_| ()), Ok(None), "longer than the region");
        assert_eq!(memobj_with_span_ref(r, 0, |_| ()), Ok(None), "an empty span names nothing");

        let set = |f: &dyn Fn(&mut MemObj)| {
            let mut regions = MEMOBJS.lock_irqsave();
            let i = live_index(&regions, r).unwrap();
            f(&mut regions[i]);
        };
        set(&|o| o.cow_shared = 1);
        assert_eq!(memobj_with_span_ref(r, 8, |_| ()), Ok(None), "a frame a clone shares");
        set(&|o| o.cow_shared = 0);
        set(&|o| o.perms = MemPerms::ReadOnly);
        assert_eq!(memobj_with_span_ref(r, 8, |_| ()), Ok(None), "a read-only region");
        set(&|o| o.perms = MemPerms::ReadWrite);
        set(&|o| o.attrs = ATTR_NO_KERNEL_MAP);
        assert_eq!(memobj_with_span_ref(r, 8, |_| ()), Ok(None), "an object the kernel does not map");
        set(&|o| o.attrs = 0);
        assert_eq!(memobj_with_span_ref(r, 8, |_| ()).map(|o| o.is_some()), Ok(true), "back to whole");

        // Two pages, the second not the frame after the first.
        let two = memobj_create_cap(A, 2, &MemSpec::anon(MemPerms::ReadWrite)).expect("two pages");
        let r2 = cap_store::get(A, two, CapPerms::READ).expect("resolves");
        let fix = |delta: usize| {
            let mut regions = MEMOBJS.lock_irqsave();
            let i = live_index(&regions, r2).unwrap();
            regions[i].phys_pages[1] = regions[i].phys_pages[0] + page + delta;
        };
        fix(0);
        assert!(memobj_with_span_ref(r2, 2 * page, |_| ()).unwrap().is_some(), "contiguous frames");
        let kept = {
            let regions = MEMOBJS.lock_irqsave();
            regions[live_index(&regions, r2).unwrap()].phys_pages[1]
        };
        fix(page);
        assert_eq!(memobj_with_span_ref(r2, 2 * page, |_| ()), Ok(None), "frames that are not contiguous");
        assert!(memobj_with_span_ref(r2, page, |_| ()).unwrap().is_some(), "the first page alone still is");
        {
            // Put the real frame back so the release frees what was allocated.
            let mut regions = MEMOBJS.lock_irqsave();
            let i = live_index(&regions, r2).unwrap();
            regions[i].phys_pages[1] = kept;
        }

        cap_store::with_table(A, |t| memobj_release_cap(A, t, cap)).expect("a live tid").expect("released");
        assert_eq!(memobj_with_span_ref(r, 8, |_| ()), Err(STALE), "a released region is never an address");
    }

    /// **The notify word is the word the mapping shows (wave 11 fix).** For
    /// every 4-aligned offset of a multi-page region, at the start, middle and
    /// end of each page: a word written through the frame `memobj_resolve_mapped`
    /// names for the mapped address is the word `memobj_with_word_ref` reads at
    /// that region offset, and the first offset past the region is `None`.
    /// Both split the offset with the build's granule.
    ///
    /// At the default 4 KiB host page the old fixed 4096 agreed by accident;
    /// [`no_fixed_page_size_in_the_offset_split`] is the half that is red on
    /// the old code there. At 16 KiB (`tests/host/ipc-tests`, `cargo
    /// test --release --features page-16k --lib`) this one is red on the old
    /// code too ("offset 0x2004: the notify word is not the mapped word",
    /// run by hand 2026-10-03).
    #[test]
    fn the_notify_word_is_the_word_the_mapping_shows_on_every_page() {
        let _g = setup();
        const PAGES: usize = 3;
        const VA: usize = 0x4000_0000;
        let page = azos_arch::PAGE_SIZE;
        let cap = memobj_create_cap(A, PAGES, &MemSpec::anon(MemPerms::ReadWrite)).expect("create");
        let r = cap_store::get(A, cap, CapPerms::READ).expect("a fresh capability resolves");
        assert_eq!(memobj_note_mapping_ref(A, r, 0x1000, VA, PAGES, MapAccess::RW), Ok(true));
        let mut tag = 0x5100_0000u32;
        for p in 0..PAGES {
            for off in [p * page, p * page + page / 2 + 4, p * page + page - 4] {
                tag += 1;
                let (rr, roff, phys) = memobj_resolve_mapped(A, VA + off).expect("mapped");
                assert_eq!((rr, roff), (r, off));
                let w = azos_mm::addr::phys_to_virt(phys);
                unsafe { (*(w as *const AtomicU32)).store(tag, Ordering::Release) };
                let v = memobj_with_word_ref(r, off, |word| word.load(Ordering::Acquire));
                assert_eq!(v, Ok(Some(tag)), "offset {off:#x}: the notify word is not the mapped word");
            }
        }
        assert_eq!(memobj_with_word_ref(r, PAGES * page, |w| w.load(Ordering::Acquire)), Ok(None));
        assert_eq!(memobj_resolve_mapped(A, VA + PAGES * page), None);
    }

    /// The source half of the fix above: the two functions that split a
    /// region offset into (frame, offset in frame) both take the granule from
    /// `azos_arch::PAGE_SIZE`, and neither carries a page size of its
    /// own. Red on the old `memobj_with_word_ref` (`const PAGE: usize = 4096`).
    ///
    /// Both also index `phys_pages` with a page number derived from a ring-3
    /// value, so both mask it after the bounds check (Spectre v1, Kconfig
    /// `MITIGATION_SPECTRE_V1_INDEX`). A speculative load is invisible to any
    /// host test, so the mask's presence is asserted in the source.
    /// **Canary (wave 12).** Delete the `array_index_nospec` line from
    /// `memobj_with_word_ref`: red, naming it.
    #[test]
    fn no_fixed_page_size_in_the_offset_split() {
        const SRC: &str = include_str!("memobj.rs");
        let body = |name: &str| {
            let start = SRC.find(&format!("pub fn {name}")).unwrap_or_else(|| panic!("{name} not found"));
            let end = start + SRC[start..].find("\n}\n").expect("end of fn");
            &SRC[start..end]
        };
        for name in ["memobj_with_word_ref", "memobj_resolve_mapped"] {
            let b = body(name);
            assert!(b.contains("azos_arch::PAGE_SIZE"), "{name} does not take the build's granule");
            for fixed in ["4096", "0x1000", "16384", "65536"] {
                assert!(!b.contains(fixed), "{name} splits the offset with a fixed {fixed}");
            }
            let mask = b.find("nospec::array_index_nospec(")
                .unwrap_or_else(|| panic!("{name} indexes phys_pages without the Spectre v1 mask"));
            let load = b.find("phys_pages[").expect("phys_pages load");
            assert!(mask < load, "{name} masks after its phys_pages load");
        }
    }

    /// (1) A region freed and recreated at the same index is another object:
    /// the old capability is `Stale` in the creator's table and in a second
    /// task's table, and the new region gains no reference. The frees go
    /// through the untyped `memobj_release`, which revokes nothing, so only the
    /// generation can refuse.
    ///
    /// **Canary.** Drop `regions[i].generation != g` from `live_index`: both
    /// old capabilities acquire the new region.
    #[test]
    fn a_recreated_index_is_stale_in_every_table_that_named_the_old_region() {
        let _g = setup();
        let (cap_a, old) = create(A);
        let in_b = mint(B, old);
        assert_eq!(acquire(B, in_b), Ok(1), "precondition: B's capability resolves");
        let idx = LAYOUT.idx(old);
        assert!(memobj_release(B, idx), "B's reference");
        assert!(memobj_release(A, idx), "A's reference: the region is freed");

        let (cap_c, new) = create(C);
        assert_eq!(LAYOUT.idx(new), idx, "precondition: the index was reused");
        assert_ne!(LAYOUT.gen(new), LAYOUT.gen(old), "precondition: another generation");

        assert_eq!(acquire(A, cap_a), Err(STALE), "the creator's table");
        assert_eq!(acquire(B, in_b), Err(STALE), "a second table");
        assert_eq!(refs(idx), Some(1), "the new region gained no reference");
        assert_eq!(release(C, cap_c), Ok(()));
    }

    /// (2) A kernel-context release of the last reference, with no recreate,
    /// stales a ring-3 holder: the freed slot's generation is 0. (The pool
    /// reads no caller identity; the kernel context is the caller the
    /// syscall-layer residual named.)
    ///
    /// **Canaries.** Keep the generation across `*region = MemObj::empty()`
    /// in `release_locked`: the slot's generation reads non-zero. Resolve by
    /// index only (drop the `g == 0`, active and generation tests from
    /// `live_index`): B's acquire books a reference on the freed slot.
    #[test]
    fn a_kernel_release_of_the_last_reference_stales_a_holder() {
        let _g = setup();
        let (_cap_a, r) = create(A);
        let in_b = mint(B, r);
        azos_sched::shim_set_current(0, 0);
        assert!(memobj_release(A, LAYOUT.idx(r)), "the kernel drops A's only reference");
        assert_eq!(__memobj_generation_for_tests(LAYOUT.idx(r)), 0, "the freed slot is vacant");
        assert_eq!(acquire(B, in_b), Err(STALE));
        assert_eq!(refs(LAYOUT.idx(r)), None, "nothing was booked on the freed slot");
    }

    /// (3) The exit of the last holder (`memobj_release_all`) stales the
    /// capabilities in other tables.
    ///
    /// **Canary.** `break` in `memobj_release_all` right after `memobj_take_mapping`:
    /// the region stays live and B's acquire reads `Ok(1)`.
    #[test]
    fn the_exit_of_the_last_holder_stales_the_other_tables() {
        let _g = setup();
        let (_cap_a, r) = create(A);
        let in_b = mint(B, r);
        memobj_release_all(A);
        assert_eq!(refs(LAYOUT.idx(r)), None, "precondition: A's exit freed the region");
        assert_eq!(acquire(B, in_b), Err(STALE));
    }

    /// (4) One holder's release, typed or at exit, leaves the other holders'
    /// capabilities live: the generation is cleared with the last reference
    /// only.
    ///
    /// **Canary.** Clear `region.generation` where a holder's `refs` reaches 0
    /// in `release_locked`: A's acquires read `Stale`.
    #[test]
    fn one_holders_release_leaves_the_other_holders_capability_live() {
        let _g = setup();
        let (cap_a, r) = create(A);
        let in_b = mint(B, r);
        let in_c = mint(C, r);
        assert_eq!(acquire(B, in_b), Ok(1));
        assert_eq!(acquire(C, in_c), Ok(1));
        assert_eq!(release(B, in_b), Ok(()), "B's typed release");
        assert_eq!(acquire(A, cap_a), Ok(1), "after B's release");
        memobj_release_all(C);
        assert_eq!(acquire(A, cap_a), Ok(1), "after C's exit");
        assert_eq!(__memobj_generation_for_tests(LAYOUT.idx(r)), LAYOUT.gen(r));
        assert_eq!(refs(LAYOUT.idx(r)), Some(3), "A's create reference and two acquires");
    }

    /// The typed release gives back every reference its holder booked (the
    /// creation reference and two acquires here) and no other holder's: B's
    /// capability still resolves, and B's release frees the region.
    ///
    /// **Canaries.** Give back one reference in `memobj_release_cap`
    /// (`memobj_release_ref`): the count after A's release reads `Some(3)`. Give
    /// back the region's whole count in `release_holder_locked`: it reads `None`.
    #[test]
    fn the_typed_release_gives_back_every_reference_its_holder_booked() {
        let _g = setup();
        let (cap_a, r) = create(A);
        let idx = LAYOUT.idx(r);
        assert_eq!(acquire(A, cap_a), Ok(1));
        assert_eq!(acquire(A, cap_a), Ok(1));
        let in_b = mint(B, r);
        assert_eq!(acquire(B, in_b), Ok(1));
        assert_eq!(refs(idx), Some(4), "precondition");

        assert_eq!(release(A, cap_a), Ok(()), "A's creation reference and two acquires");
        assert_eq!(refs(idx), Some(1), "B's reference only");
        assert_eq!(__memobj_generation_for_tests(idx), LAYOUT.gen(r), "the region is live");
        assert_eq!(acquire(B, in_b), Ok(1), "B's capability still resolves");
        assert_eq!(release(B, in_b), Ok(()), "B's two references");
        assert_eq!(refs(idx), None, "the last holder's release freed the region");
        assert_eq!(__memobj_generation_for_tests(idx), 0);
    }

    /// A pinned reference (a map that failed part-way) survives the typed
    /// release and goes at the exit; a recorded mapping refuses the typed
    /// release and gives back nothing.
    ///
    /// **Canary.** Ignore `pinned` in `release_holder_locked`: the count after
    /// A's release reads `None`.
    #[test]
    fn a_pinned_reference_waits_for_the_exit_and_a_recorded_mapping_refuses() {
        let _g = setup();
        let (cap_a, r) = create(A);
        let idx = LAYOUT.idx(r);
        assert_eq!(memobj_acquire_ref(A, r).map(|(n, _)| n), Ok(1), "a map's reference");
        assert_eq!(memobj_pin_ref(A, r), Ok(true), "the map failed part-way");
        assert_eq!(memobj_pin_ref(B, r), Ok(false), "B holds nothing to pin");
        assert_eq!(release(A, cap_a), Ok(()), "the creation reference");
        assert_eq!(refs(idx), Some(1), "the pinned reference stays");
        assert_eq!(memobj_release_holder_ref(A, r), Err(MemObjError::Closed), "only the pinned one is left");
        memobj_release_all(A);
        assert_eq!(refs(idx), None, "the exit gave it back");

        let (cap_c, rc) = create(C);
        assert_eq!(memobj_note_mapping_ref(C, rc, 0x1000, 0x6000_0000, 1, MapAccess::RW), Ok(true));
        assert_eq!(release(C, cap_c), Err(MemObjError::Closed), "a recorded mapping");
        assert_eq!(refs(LAYOUT.idx(rc)), Some(1), "nothing was given back");
        memobj_release_all(C);
        assert_eq!(refs(LAYOUT.idx(rc)), None);
    }

    /// (6) U03-1 / U04-1's fix, owner decision 2026-09-26: a slot that reaches
    /// `LAYOUT.gen_max()` is swept **at its own index only**
    /// (`objref::sweep_index`) and reused from generation 1 — instead of the
    /// old design's pool-wide counter, whose exhaustion swept every `Cap<Shm>`
    /// in every table, live or not. A's churn on slot 1 crosses the same
    /// ceiling; B's capability and an unrelated `Cap<IoRing>`, both on/at
    /// index 0, read exactly as before it. C's stale capability on slot 1's
    /// previous incarnation — the targeted sweep's one job — is gone
    /// afterward, and slot 1 itself comes back, not lost.
    ///
    /// **Canary.** Drop the `regions.next_gen[i] != 0` guard from
    /// `create_core`'s free-slot scan: a concurrent create could select slot 1
    /// while it is mid-sweep.
    #[test]
    fn a_slots_own_wrap_sweeps_only_that_index_and_the_slot_still_comes_back() {
        let _g = setup();

        // B's region: the "other task's live capability" the old sweep
        // revoked. Created first so it lands on slot 0.
        let (cap_b, r_b) = create(B);
        assert_eq!(LAYOUT.idx(r_b), 0, "precondition: B's region is slot 0");
        let ring: Cap<IoRing> = cap_store::grant(B, CapPerms::RW, objref::IO_RING.pack(1, 5)).unwrap();

        // A churns slot 1 right up to and past its own generation ceiling.
        let (cap_a1, r1) = create(A);
        assert_eq!(LAYOUT.idx(r1), 1, "precondition: A's churn lands on slot 1");
        assert_eq!(release(A, cap_a1), Ok(()));
        __memobj_set_next_gen_for_tests(1, LAYOUT.gen_max() - 1);

        let (cap_a2, r1) = create(A);
        assert_eq!(LAYOUT.idx(r1), 1);
        assert_eq!(LAYOUT.gen(r1), LAYOUT.gen_max() - 1);
        assert_eq!(release(A, cap_a2), Ok(()));

        let (cap_a3, r1) = create(A);
        assert_eq!(LAYOUT.idx(r1), 1);
        assert_eq!(LAYOUT.gen(r1), LAYOUT.gen_max(), "the last generation slot 1 can carry");
        // C holds a capability on THIS incarnation, already unreachable
        // through the generation compare the moment it is released below.
        let in_c = mint(C, r1);
        assert_eq!(release(A, cap_a3), Ok(()));

        // The next create on slot 1 wraps: swept at index 1 only, then reused.
        let (_cap_a4, r_new) = create(A);
        assert_eq!(LAYOUT.idx(r_new), 1, "the slot comes back — no permanent loss");
        assert_eq!(LAYOUT.gen(r_new), 1, "reused from generation 1 after its own wrap");

        assert_eq!(cap_store::get(B, cap_b, CapPerms::READ), Ok(r_b), "B's capability");
        assert_eq!(cap_store::get(B, ring, CapPerms::READ), Ok(objref::IO_RING.pack(1, 5)), "another kind");
        assert_eq!(memobj_ref(0), Some(r_b), "B's region is still live");
        assert_eq!(cap_store::get(C, in_c, CapPerms::READ), Err(CapError::Stale), "C's stale capability, swept");
        assert_eq!(memobj_ref(1), Some(r_new), "slot 1 now answers for the new incarnation");
    }

    /// (7) A bare index (generation 0) resolves to nothing, whether its slot is
    /// live or free.
    ///
    /// **Canary.** Drop `g == 0` and the generation compare from `live_index`:
    /// the bare capability acquires A's live region.
    #[test]
    fn a_bare_index_capability_never_resolves() {
        let _g = setup();
        let (_cap_a, r) = create(A);
        let idx = LAYOUT.idx(r);
        let bare: Cap<Shm> = cap_store::grant(B, CapPerms::RW, idx).unwrap();
        let bare_free: Cap<Shm> = cap_store::grant(B, CapPerms::RW, idx + 1).unwrap();
        assert_eq!(acquire(B, bare), Err(STALE), "a live region");
        assert_eq!(acquire(B, bare_free), Err(STALE), "a free slot");
        assert_eq!(memobj_acquire_ref(B, idx).map(|(n, _)| n), Err(STALE));
        assert_eq!(refs(idx), Some(1), "no reference was booked");
    }

    /// The packed-reference forms answer like their index forms for a live
    /// reference, and `Stale` for an old one without touching the region now
    /// at that index.
    ///
    /// **Canary.** Resolve `memobj_note_mapping_ref` by `objref::idx` instead of
    /// `live_index`: the stale note reads `Ok(false)`.
    #[test]
    fn the_reference_forms_refuse_an_old_reference() {
        let _g = setup();
        let old = memobj_create_ref(A, 2, MemPerms::ReadWrite).expect("create");
        assert_eq!(memobj_has_mapping_ref(A, old), Ok(false));
        assert_eq!(memobj_page_phys_ref(old, 1).map(|p| p.is_some()), Ok(true));
        assert_eq!(memobj_page_phys_ref(old, 2), Ok(None), "past the region");
        assert_eq!(memobj_note_mapping_ref(A, old, 0x1000, 0x6000_0000, 2, MapAccess::RW), Ok(true));
        assert_eq!(memobj_has_mapping_ref(A, old), Ok(true));
        assert_eq!(memobj_release_ref(A, old), Err(MemObjError::Closed), "a live mapping refuses");
        assert_eq!(memobj_take_mapping_ref(A, old), Ok(Some((0x6000_0000, 2))));
        assert_eq!(memobj_release_ref(A, old), Ok(()), "the last reference");

        let new = memobj_create_ref(B, 1, MemPerms::ReadOnly).expect("create");
        assert_eq!(LAYOUT.idx(new), LAYOUT.idx(old), "precondition: the index was reused");
        let answers = [
            ("has_mapping", memobj_has_mapping_ref(A, old).map(|_| ())),
            ("page_phys", memobj_page_phys_ref(old, 0).map(|_| ())),
            ("note_mapping", memobj_note_mapping_ref(A, old, 0x1000, 0x6100_0000, 1, MapAccess::RW).map(|_| ())),
            ("take_mapping", memobj_take_mapping_ref(A, old).map(|_| ())),
            ("acquire", memobj_acquire_ref(A, old).map(|_| ())),
            ("release", memobj_release_ref(A, old)),
        ];
        for (what, got) in answers {
            assert_eq!(got, Err(STALE), "{what}");
        }
        assert!(!memobj_has_mapping(B, LAYOUT.idx(new)));
        assert_eq!(refs(LAYOUT.idx(new)), Some(1));
    }

    // ── One zero per page, none with interrupts off ───────────────────────
    //
    // `create_core` no longer zeroes; `pmm::alloc_page` does. What these
    // tests can prove on the host is that shm RELIES on the allocator's zero
    // and returns every page it took on each refusal path. That the kernel's
    // real allocator zeroes is `tests/host/mm-tests`
    // (`a_reallocated_page_is_zeroed_not_the_old_content`), on the real
    // `pmm.rs`; the page shim here zeroes in `alloc_page` to match it.

    /// A page recycled from a dead region into a new one carries none of the
    /// old owner's bytes.
    ///
    /// **Canary.** Delete the `write_bytes` in the mm shim's `alloc_page`
    /// (the stand-in for `pmm::alloc_page`'s zero): this fails, because
    /// `create_core` itself no longer zeroes.
    #[test]
    fn a_recycled_page_reaches_the_new_region_zeroed() {
        let _g = setup();
        let old = memobj_create_ref(A, 1, MemPerms::ReadWrite).expect("create");
        let p = memobj_page_phys_ref(old, 0).expect("live").expect("page 0");
        unsafe { core::ptr::write_bytes(p as *mut u8, 0xAA, azos_arch::PAGE_SIZE) };
        assert_eq!(memobj_release_ref(A, old), Ok(()), "the last reference");
        assert_eq!(azos_mm::shim_free_count(p), 1, "the region's page went back");

        let new = memobj_create_ref(B, 1, MemPerms::ReadWrite).expect("create");
        let q = memobj_page_phys_ref(new, 0).expect("live").expect("page 0");
        assert_eq!(q, p, "precondition: the new region got the poisoned page back");
        let bytes = unsafe { core::slice::from_raw_parts(q as *const u8, azos_arch::PAGE_SIZE) };
        assert!(bytes.iter().all(|&b| b == 0), "a new region shows the previous owner's bytes");
    }

    /// Out of memory halfway through: every page this call took goes back.
    ///
    /// **Canary.** Drop `free_frames(&pages[..i])` from the OOM arm: the
    /// shim's whole pool stays checked out.
    #[test]
    fn a_create_that_runs_out_of_pages_gives_back_every_page_it_took() {
        let _g = setup();
        let more_than_the_pool = azos_mm::SHIM_PAGES + 6;
        assert!(more_than_the_pool <= MAX_MEMOBJ_PAGES, "precondition: a legal size");
        assert_eq!(memobj_create_ref(A, more_than_the_pool, MemPerms::ReadWrite), None);
        assert_eq!(azos_mm::shim_pages_in_use(), 0, "pages leaked on the OOM path");
        assert!(memobj_create_ref(A, 1, MemPerms::ReadWrite).is_some(), "the table slot was not consumed");
    }

    /// A task at its quota is refused before anything is allocated, and a
    /// refusal at claim time gives the pages back.
    ///
    /// **Canaries.** (1) Delete the `has_room` pre-check at the top of
    /// `create_core`: the refused call now allocates and frees the four pages
    /// after the quota's eight, and the free-count assertion fails. (2) With
    /// (1) applied, also drop the `free_frames` after `claim_slot` returns
    /// `None`: the in-use assertion fails with 12.
    #[test]
    fn a_create_over_quota_allocates_nothing_and_leaks_nothing() {
        let _g = setup();
        let mut first = 0usize;
        for k in 0..MAX_MEMOBJS_PER_TASK {
            let r = memobj_create_ref(A, 1, MemPerms::ReadWrite).expect("under quota");
            if k == 0 {
                first = memobj_page_phys_ref(r, 0).expect("live").expect("page 0");
            }
        }
        let held = azos_mm::shim_pages_in_use();
        assert_eq!(held, MAX_MEMOBJS_PER_TASK);
        assert_eq!(memobj_create_ref(A, 4, MemPerms::ReadWrite), None, "over quota");
        assert_eq!(azos_mm::shim_pages_in_use(), held, "pages leaked on a quota refusal");
        let page = azos_arch::PAGE_SIZE;
        for k in held..held + 4 {
            assert_eq!(azos_mm::shim_free_count(first + k * page), 0,
                       "a refused create allocated page {k} before checking the quota");
        }
    }

    /// A region's frames count against its OWNER's Domain from
    /// create until they are freed, whoever drops the last reference; a
    /// create that does not fit the budget is refused before any frame is
    /// taken.
    ///
    /// **Canaries** (run by hand 2026-09-28): drop the `mm_discharge_tid` in
    /// `drop_refs_locked` — "freed by B, discharged to A" fails, 4 != 0; drop
    /// the pre-charge in `create_core` — "create charged the creator" fails,
    /// 0 != 4.
    #[test]
    fn frames_are_charged_to_the_creator_until_freed() {
        let _g = setup();
        azos_sched::shim_set_current(A, 0x1000);
        let (cap_a, r) = {
            let cap = memobj_create_cap(A, 4, &MemSpec::anon(MemPerms::ReadWrite)).expect("create");
            (cap, cap_store::get(A, cap, CapPerms::READ).expect("resolves"))
        };
        assert_eq!(azos_sched::shim_charged(A), 4, "create charged the creator");
        let in_b = mint(B, r);
        acquire(B, in_b).expect("B holds it");
        release(A, cap_a).expect("A lets go");
        assert_eq!(azos_sched::shim_charged(A), 4, "still allocated: B holds it");
        azos_sched::shim_set_current(B, 0x2000);
        release(B, in_b).expect("B lets go, the frames are freed");
        assert_eq!(azos_sched::shim_charged(A), 0, "freed by B, discharged to A");
        assert_eq!(azos_sched::shim_charged(B), 0, "B was never charged");

        // Over budget: refused, nothing taken, nothing charged.
        azos_sched::shim_set_current(A, 0x1000);
        azos_sched::shim_set_limit(A, 3);
        let before = azos_mm::shim_pages_in_use();
        assert!(memobj_create_cap(A, 4, &MemSpec::anon(MemPerms::ReadWrite)).is_err());
        assert_eq!(azos_mm::shim_pages_in_use(), before, "no frame taken");
        assert_eq!(azos_sched::shim_charged(A), 0);

        // The charge is the OWNER's Domain's, whoever makes the call: a kernel
        // caller creating for A charges A (and a kernel-owned object charges
        // nobody, below).
        azos_sched::shim_set_current(0, 0);
        azos_sched::shim_set_limit(A, 0);
        let cap = memobj_create_cap(A, 4, &MemSpec::anon(MemPerms::ReadWrite)).expect("create for A");
        assert_eq!(azos_sched::shim_charged(A), 4, "charged to the owner's Domain");
        release(A, cap).expect("A lets go");
        assert_eq!(azos_sched::shim_charged(A), 0);
        let (k, _) = memobj_create_kernel(2, &MemSpec::contig(MemPerms::ReadWrite, false)).expect("kernel object");
        assert_eq!(azos_sched::shim_charged_domain(azos_sched::task_domain(0)), 0, "a kernel-owned object charges nobody");
        let _ = k;
    }

    // ── The MemObj operations: lifecycle, COW clone, MOVE, SHARE, charge ──────
    //
    // Canary discipline: each test says which switch of the ipc crate puts its
    // hole back (`--features memobj-...-canary`); the gate row runs it alone and
    // requires it to fail.

    use std::sync::Mutex as StdMutex;

    /// `(root, va, pages)` of every unmap and `(root, va, pages, write)` of
    /// every protect the hooks saw.
    static UNMAPS: StdMutex<Vec<(usize, usize, usize)>> = StdMutex::new(Vec::new());
    static PROTECTS: StdMutex<Vec<(usize, usize, usize, bool)>> = StdMutex::new(Vec::new());

    fn rec_unmap(root: usize, va: usize, pages: usize) {
        UNMAPS.lock().unwrap().push((root, va, pages));
    }
    fn rec_protect(root: usize, va: usize, pages: usize, write: bool) -> usize {
        PROTECTS.lock().unwrap().push((root, va, pages, write));
        pages
    }

    /// The hooks installed and the record empty; `Hooks` removes them again.
    struct Hooks;
    impl Hooks {
        fn install() -> Hooks {
            UNMAPS.lock().unwrap().clear();
            PROTECTS.lock().unwrap().clear();
            set_unmap_hook(rec_unmap);
            set_protect_hook(rec_protect);
            cap_store::set_move_hook(memobj_moved);
            cap_store::set_swept_hook(memobj_warrant_swept);
            Hooks
        }
    }
    impl Drop for Hooks {
        fn drop(&mut self) {
            __clear_hooks_for_tests();
            cap_store::__clear_move_hook_for_tests();
            cap_store::__clear_swept_hook_for_tests();
        }
    }

    const ROOT_A: usize = 0xA000;
    const VA: usize = 0x6000_0000;

    /// Move (`dup == false`) or share (`dup == true`) `cap` of `from` to `to`
    /// through the capability transfer, as an IPC send does; the receiver's
    /// capability.
    fn transfer(from: u32, to: u32, cap: Cap<Shm>, dup: bool, rights: Option<CapPerms>) -> Result<Cap<Shm>, CapError> {
        let x = cap_store::CapXfer { rights, ..cap_store::CapXfer::new(cap.raw(), dup) };
        let mut out = [crate::cap::CapHandle(0); 1];
        cap_store::move_caps(from, to, &[x], false, &mut out)?;
        Ok(Cap::<Shm>::from_raw(out[0]))
    }

    /// **Lifecycle, every kind.** Anon: charged to the owner's Domain, described,
    /// mapped (the record names the root), protected, unmapped, released: the
    /// frames go back and the charge with them. Contig (kernel): one run, the
    /// frames in order. Paged and a volatile Contig run are refused.
    /// `ATTR_NO_KERNEL_MAP` hides the object from
    /// the kernel's own reads.
    #[test]
    fn a_memobj_lives_from_create_to_release_whatever_its_kind() {
        let _g = setup();
        let _h = Hooks::install();
        azos_sched::shim_set_current(A, 0x1000);
        let before = azos_mm::shim_pages_in_use();

        // Anon.
        let spec = MemSpec::anon(MemPerms::ReadWrite).with_attrs(ATTR_SWAPPABLE);
        let cap = memobj_create_cap(A, 3, &spec).expect("create");
        let r = cap_store::get(A, cap, CapPerms::READ).unwrap();
        let d = memobj_describe_ref(r).unwrap();
        assert_eq!((d.kind, d.page_count, d.attrs, d.owner_task), (MemKind::Anon, 3, ATTR_SWAPPABLE, A));
        assert_ne!(d.charge_key, 0, "an owned object is charged to a Domain");
        assert_eq!(azos_sched::shim_charged(A), 3);
        assert_eq!(memobj_note_mapping_ref(A, r, ROOT_A, VA, 3, MapAccess::RW), Ok(true));
        assert_eq!(memobj_protect_ref(A, r, false), Ok(()), "RW to RO");
        assert_eq!(PROTECTS.lock().unwrap().as_slice(), &[(ROOT_A, VA, 3, false)]);
        assert_eq!(memobj_protect_ref(A, r, true), Ok(()), "back, within what the map was allowed");
        assert_eq!(memobj_protect_ref(B, r, true), Err(MemObjError::Closed), "a task with no mapping of it");
        assert_eq!(memobj_take_mapping_ref(A, r), Ok(Some((VA, 3))));
        release(A, cap).expect("release");
        assert_eq!(azos_mm::shim_pages_in_use(), before, "every frame went back");
        assert_eq!(azos_sched::shim_charged(A), 0, "and the charge");

        // Contig, kernel-owned: not charged, one run.
        let (kr, base) = memobj_create_kernel(4, &MemSpec::contig(MemPerms::ReadWrite, true)).expect("contig");
        let kd = memobj_describe_ref(kr).unwrap();
        assert_eq!((kd.kind, kd.charge_key, kd.owner_task), (MemKind::Contig, 0, MEMOBJ_KERNEL_OWNER));
        assert!(kd.device_visible);
        let page = azos_arch::PAGE_SIZE;
        for i in 0..4 {
            assert_eq!(memobj_page_phys_ref(kr, i), Ok(Some(base + i * page)), "page {i} follows page {}", i.max(1) - 1);
        }
        assert_eq!(memobj_release_ref(MEMOBJ_KERNEL_OWNER, kr), Ok(()));
        assert_eq!(azos_mm::shim_pages_in_use(), before, "a contiguous run goes back page by page");

        // Reserved and unknown.
        let paged = MemSpec { kind: MemKind::Paged, ..MemSpec::anon(MemPerms::ReadOnly) };
        assert_eq!(memobj_create_spec(A, 1, &paged), Err(MemObjError::BadArg), "Paged is reserved");
        let vol_contig = MemSpec::contig(MemPerms::ReadOnly, false).with_attrs(ATTR_VOLATILE);
        assert_eq!(memobj_create_spec(A, 1, &vol_contig), Err(MemObjError::BadArg), "only Anon memory is purgeable");
        assert_eq!(memobj_create_spec(A, 1, &MemSpec::anon(MemPerms::ReadOnly).with_attrs(0x80)), Err(MemObjError::BadArg));
        assert_eq!(azos_mm::shim_pages_in_use(), before, "a refusal takes no frame");
    }

    /// **`ATTR_NO_KERNEL_MAP`: the kernel does not read the object.**
    /// `memobj_with_word_ref` and `memobj_kernel_page_phys_ref` answer nothing for
    /// it, `memobj_resolve_mapped` does not name it, while the user mapping
    /// (`memobj_page_phys_ref`) is unchanged.
    ///
    /// **Canary** `memobj-no-kernel-map-canary`: the attribute is not consulted;
    /// the word is read, and "the kernel read a NO_KERNEL_MAP object" fails.
    #[test]
    fn no_kernel_map_hides_the_object_from_the_kernels_own_reads() {
        let _g = setup();
        azos_sched::shim_set_current(A, 0x1000);
        let hidden = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite).with_attrs(ATTR_NO_KERNEL_MAP)).unwrap();
        let open = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let rh = cap_store::get(A, hidden, CapPerms::READ).unwrap();
        let ro = cap_store::get(A, open, CapPerms::READ).unwrap();
        assert!(matches!(memobj_with_word_ref(ro, 0, |w| w.load(Ordering::Acquire)), Ok(Some(_))), "the open object is readable");
        assert_eq!(memobj_kernel_page_phys_ref(ro, 0).map(|p| p.is_some()), Ok(true));
        assert_eq!(
            memobj_with_word_ref(rh, 0, |w| w.load(Ordering::Acquire)),
            Ok(None),
            "the kernel read a NO_KERNEL_MAP object"
        );
        assert_eq!(memobj_kernel_page_phys_ref(rh, 0), Ok(None));
        assert!(memobj_page_phys_ref(rh, 0).unwrap().is_some(), "a user mapping still reaches its frames");
        assert_eq!(memobj_note_mapping_ref(A, rh, ROOT_A, VA, 1, MapAccess::RW), Ok(true));
        assert_eq!(memobj_resolve_mapped(A, VA), None, "notify cannot key a word the kernel may not read");
        assert!(memobj_resolve_mapped(A, VA).is_none());
    }

    /// **COW clone.** A clone of an object nobody maps writable shares its
    /// source's frames (same physical pages, one more holder in the frame count)
    /// until it is written: `memobj_cow_break` then gives it a frame of its own
    /// with the same bytes, the source keeps its frame, and a write to the clone is
    /// invisible to the source. A clone of an object that IS mapped writable
    /// cannot share (its bytes would change under the clone): it copies at once.
    /// A write mapping of a clone breaks every shared page first.
    ///
    /// **Canary** `memobj-cow-no-break-canary`: the break clears its bit and keeps
    /// the frame; "the clone's write reached the source" fails.
    #[test]
    fn a_clone_shares_frames_until_it_is_written() {
        let _g = setup();
        azos_sched::shim_set_current(A, 0x1000);
        let src_cap = memobj_create_cap(A, 2, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let src = cap_store::get(A, src_cap, CapPerms::READ).unwrap();
        // Source content: page 0 is 0x11.., page 1 is 0x22..
        let page = azos_arch::PAGE_SIZE;
        let p0 = memobj_page_phys_ref(src, 0).unwrap().unwrap();
        let p1 = memobj_page_phys_ref(src, 1).unwrap().unwrap();
        unsafe {
            core::ptr::write_bytes(p0 as *mut u8, 0x11, page);
            core::ptr::write_bytes(p1 as *mut u8, 0x22, page);
        }

        let clone_cap = memobj_clone_cap(A, src_cap, MemPerms::ReadWrite, 0).expect("clone");
        let clone = cap_store::get(A, clone_cap, CapPerms::READ).unwrap();
        assert_ne!(clone, src);
        assert_eq!(memobj_page_phys_ref(clone, 0), Ok(Some(p0)), "the clone shares the source's frame");
        assert_eq!(azos_mm::cow::page_getref(p0), 2, "and the frame counts both");
        assert_eq!(memobj_describe_ref(clone).unwrap().cow_shared, 0b11);
        assert_eq!(memobj_describe_ref(src).unwrap().cow_shared, 0b11);
        assert_eq!(azos_sched::shim_charged(A), 4, "the clone is charged its own pages, shared or not");

        // A write mapping of a shared object is refused while another holder maps it.
        assert_eq!(memobj_note_mapping_ref(A, src, ROOT_A, VA, 2, MapAccess::RO), Ok(true));
        assert_eq!(memobj_cow_break(clone, 0), Ok(()), "the clone's mappers are none: it may break");
        assert_eq!(memobj_cow_break(src, 0), Err(MemObjError::Busy), "a mapping names the old frame: no break under it");
        assert_eq!(memobj_protect_ref(A, src, true), Err(MemObjError::Cap(CapError::MissingPerms)), "RO map, max RO");
        memobj_take_mapping_ref(A, src).unwrap();

        // The clone's page 0 is its own now; page 1 is still shared.
        let c0 = memobj_page_phys_ref(clone, 0).unwrap().unwrap();
        assert_ne!(c0, p0, "the break gave the clone a frame");
        assert_eq!(unsafe { *(c0 as *const u8) }, 0x11, "with the same bytes");
        assert!(azos_mm::cow::page_is_sole(p0), "the source is the frame's only holder again");
        unsafe { core::ptr::write_bytes(c0 as *mut u8, 0x99, page) };
        assert_eq!(unsafe { *(p0 as *const u8) }, 0x11, "the clone's write reached the source");
        assert_eq!(memobj_page_phys_ref(clone, 1), Ok(Some(p1)), "page 1 is still shared");

        // Breaking the rest, then freeing the source keeps the clone's frames.
        assert_eq!(memobj_cow_break_all(clone), Ok(()));
        assert_eq!(memobj_describe_ref(clone).unwrap().cow_shared, 0);
        release(A, src_cap).expect("source released");
        assert_eq!(unsafe { *(memobj_page_phys_ref(clone, 1).unwrap().unwrap() as *const u8) }, 0x22);
        release(A, clone_cap).expect("clone released");
        assert_eq!(azos_mm::shim_pages_in_use(), 0, "every frame went back exactly once");
        assert_eq!(azos_sched::shim_charged(A), 0);
    }

    /// The last sharer of a frame keeps it: once the source is gone, breaking the
    /// clone copies nothing.
    #[test]
    fn the_last_sharer_of_a_frame_breaks_without_a_copy() {
        let _g = setup();
        azos_sched::shim_set_current(A, 0x1000);
        let src_cap = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let clone_cap = memobj_clone_cap(A, src_cap, MemPerms::ReadWrite, 0).unwrap();
        let clone = cap_store::get(A, clone_cap, CapPerms::READ).unwrap();
        let p = memobj_page_phys_ref(clone, 0).unwrap().unwrap();
        release(A, src_cap).expect("the source goes");
        assert_eq!(azos_mm::cow::page_getref(p), 1, "the clone is the frame's only holder");
        let before = azos_mm::shim_pages_in_use();
        assert_eq!(memobj_cow_break_all(clone), Ok(()));
        assert_eq!(memobj_page_phys_ref(clone, 0), Ok(Some(p)), "no new frame");
        assert_eq!(azos_mm::shim_pages_in_use(), before, "and none taken");
        assert_eq!(azos_mm::cow::page_getref(p), 0, "back to a private page");
        assert_eq!(memobj_describe_ref(clone).unwrap().cow_shared, 0);
        release(A, clone_cap).expect("the clone goes");
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// A clone of an object mapped writable copies now; the charge is refused when the owner's Domain cannot take it.
    #[test]
    fn a_clone_of_a_writable_mapping_copies_and_a_budget_can_refuse_it() {
        let _g = setup();
        azos_sched::shim_set_current(A, 0x1000);
        let src_cap = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let src = cap_store::get(A, src_cap, CapPerms::READ).unwrap();
        let p = memobj_page_phys_ref(src, 0).unwrap().unwrap();
        unsafe { *(p as *mut u8) = 0x5a };
        assert_eq!(memobj_note_mapping_ref(A, src, ROOT_A, VA, 1, MapAccess::RW), Ok(true));
        let c = memobj_clone_cap(A, src_cap, MemPerms::ReadOnly, 1).expect("clone");
        let cr = cap_store::get(A, c, CapPerms::READ).unwrap();
        assert_ne!(memobj_page_phys_ref(cr, 0).unwrap().unwrap(), p, "a writable source is copied, not shared");
        assert_eq!(unsafe { *(memobj_page_phys_ref(cr, 0).unwrap().unwrap() as *const u8) }, 0x5a);
        assert_eq!(memobj_describe_ref(cr).unwrap().cow_shared, 0);
        assert_eq!(memobj_clone_cap(A, src_cap, MemPerms::ReadOnly, 7).err(), Some(MemObjError::BadArg), "a wrong size");
        // Over budget: refused, nothing taken.
        azos_sched::shim_set_limit(A, 2);
        let in_use = azos_mm::shim_pages_in_use();
        assert_eq!(memobj_clone_cap(A, src_cap, MemPerms::ReadOnly, 0).err(), Some(MemObjError::NoMem));
        assert_eq!(azos_mm::shim_pages_in_use(), in_use);
        azos_sched::shim_set_limit(A, 0);
    }

    /// **MOVE.** A capability moved to another task takes the object with it:
    /// the sender's mapping is removed from its page table (and its record), the
    /// references and the ownership are the receiver's, and the charge moves
    /// from the sender's Domain to the receiver's. The capability is the
    /// receiver's alone.
    ///
    /// **Canaries.** `memobj-move-keeps-map-canary`: the record and the PTEs
    /// stay, "MOVE dropped the sender's mapping" fails. `memobj-charge-stays-canary`:
    /// the sender is never discharged, "the charge follows the holder" fails.
    #[test]
    fn a_move_drops_the_senders_mapping_and_the_charge_follows_the_holder() {
        let _g = setup();
        let _h = Hooks::install();
        azos_sched::shim_set_current(A, 0x1000);
        let cap_a = memobj_create_cap(A, 4, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let r = cap_store::get(A, cap_a, CapPerms::READ).unwrap();
        assert_eq!(memobj_note_mapping_ref(A, r, ROOT_A, VA, 4, MapAccess::RW), Ok(true));
        assert_eq!((azos_sched::shim_charged(A), azos_sched::shim_charged(B)), (4, 0));

        let cap_b = transfer(A, B, cap_a, false, None).expect("the capability moves");
        assert!(cap_store::get(A, cap_a, CapPerms::READ).is_err(), "the sender holds no capability");
        assert_eq!(UNMAPS.lock().unwrap().as_slice(), &[(ROOT_A, VA, 4)], "MOVE dropped the sender's mapping");
        assert_eq!(memobj_has_mapping_ref(A, r), Ok(false), "and its record");
        assert_eq!(memobj_owner(LAYOUT.idx(r)), Some(B), "ownership went with it");
        assert_eq!(
            (azos_sched::shim_charged(A), azos_sched::shim_charged(B)),
            (0, 4),
            "the charge follows the holder"
        );
        assert!(memobj_take_moved_windows(A, &mut [(0, 0); 4]) == 1, "the window is the sender's to release");
        // The receiver is the holder: its release frees the object and
        // discharges ITS Domain.
        release(B, cap_b).expect("the receiver releases");
        assert_eq!(memobj_info(LAYOUT.idx(r)), None, "the sender's references moved: nothing keeps it");
        assert_eq!(azos_sched::shim_charged(B), 0);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// **KMEM-CHARGE.** A region's metadata is kernel memory kept for the
    /// Domain that CREATED it, for the object's whole life: charged at create,
    /// left with the creator by a MOVE (the frames' charge follows the holder,
    /// this one does not: it is taken and given back with no table lock held),
    /// and given back by the last release, whoever makes it.
    ///
    /// **Canaries.** Drop the `kmem_charge` in `charge_region`: "charged at
    /// create" fails. Drop the `kmem_discharge` in the free path: the last row
    /// fails. Let the MOVE rewrite `meta_key`: "stays with the creator" fails.
    #[test]
    fn a_regions_metadata_is_charged_to_its_creator_and_freed_with_the_object() {
        use crate::cap_store::{kmem_fake, KMEM_MEMOBJ_META};
        let _g = setup();
        let _h = Hooks::install();
        kmem_fake::install();
        let (ka, kb) = (cap_store::domain_key_of(A), cap_store::domain_key_of(B));
        kmem_fake::forget(ka);
        kmem_fake::forget(kb);
        azos_sched::shim_set_current(A, 0x1000);
        let (cap_a, r) = create(A);
        assert_eq!(kmem_fake::used(ka, KMEM_MEMOBJ_META), MEMOBJ_KMEM_BYTES, "charged at create");
        assert_eq!(kmem_fake::used(kb, KMEM_MEMOBJ_META), 0);

        let cap_b = transfer(A, B, cap_a, false, None).expect("the capability moves");
        assert_eq!(azos_sched::shim_charged(B), 1, "the frames' charge followed the holder");
        assert_eq!(kmem_fake::used(ka, KMEM_MEMOBJ_META), MEMOBJ_KMEM_BYTES, "the metadata stays with the creator");
        assert_eq!(kmem_fake::used(kb, KMEM_MEMOBJ_META), 0);

        release(B, cap_b).expect("the receiver releases");
        assert_eq!(memobj_info(LAYOUT.idx(r)), None);
        assert_eq!(kmem_fake::used(ka, KMEM_MEMOBJ_META), 0, "freed with the object, to the creator");
        kmem_fake::forget(ka);
        kmem_fake::forget(kb);
    }

    #[test]
    fn a_region_the_creator_cannot_hold_in_kernel_memory_is_refused_and_takes_nothing() {
        use crate::cap_store::kmem_fake;
        let _g = setup();
        let _h = Hooks::install();
        kmem_fake::install();
        let ka = cap_store::domain_key_of(A);
        kmem_fake::forget(ka);
        kmem_fake::set_limit(ka, MEMOBJ_KMEM_BYTES - 1);
        assert_eq!(
            memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).err(),
            Some(MemObjError::NoMem),
        );
        assert_eq!((azos_sched::shim_charged(A), azos_mm::shim_pages_in_use()), (0, 0), "no frame, no frame charge");
        assert_eq!(kmem_fake::total(ka), 0, "and no metadata charge");
        kmem_fake::set_limit(ka, 0);
        let _ = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).expect("it fits once the limit is lifted");
        kmem_fake::forget(ka);
    }

    /// A MOVE the receiver cannot pay for leaves the references, the ownership
    /// and the charge with the sender (nothing is lost or charged twice), and the
    /// sender's mapping is gone all the same: it no longer holds the capability.
    #[test]
    fn a_move_to_a_receiver_over_budget_charges_nobody() {
        let _g = setup();
        let _h = Hooks::install();
        azos_sched::shim_set_current(A, 0x1000);
        let cap_a = memobj_create_cap(A, 4, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let r = cap_store::get(A, cap_a, CapPerms::READ).unwrap();
        assert_eq!(memobj_note_mapping_ref(A, r, ROOT_A, VA, 4, MapAccess::RW), Ok(true));
        azos_sched::shim_set_limit(B, 3);
        let cap_b = transfer(A, B, cap_a, false, None).expect("the capability still moves");
        assert_eq!(UNMAPS.lock().unwrap().len(), 1, "the sender lost its mapping");
        assert_eq!(memobj_owner(LAYOUT.idx(r)), Some(A), "the owner is still the sender");
        assert_eq!((azos_sched::shim_charged(A), azos_sched::shim_charged(B)), (4, 0), "nobody was charged twice");
        // The receiver can still take its own reference for free (SHARE-like).
        assert!(acquire(B, cap_b).is_ok());
    }

    /// **SHARE attenuates.** A DUP entry derives a warrant under the sender's:
    /// the receiver cannot have more rights than the sender, and a READ-only
    /// copy of a writable object maps read-only. The sender keeps its own
    /// capability and the object is charged once.
    ///
    /// **Canary** `memobj-share-no-narrow-canary`: an attenuated copy resolves as
    /// writable; "a READ share maps writable" fails.
    #[test]
    fn a_share_is_attenuated_and_charges_nobody_twice() {
        let _g = setup();
        let _h = Hooks::install();
        azos_sched::shim_set_current(A, 0x1000);
        let cap_a = memobj_create_cap(A, 2, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        // The share keeps DELEGATE so the refusal below is the rights check,
        // not a missing TRANSFER.
        let view = CapPerms::READ.union(CapPerms::MAP).union(CapPerms::DELEGATE);
        let ro_b = transfer(A, B, cap_a, true, Some(view)).expect("share READ|MAP");
        let grant = cap_store::with_table(B, |t| memobj_resolve_map(t, ro_b, MAP_OP)).unwrap().expect("resolves");
        assert!(!grant.writable, "a READ share maps writable");
        assert_eq!(grant.desc.perms, MemPerms::ReadWrite, "the object is still writable for its owner");
        // The owner's own capability maps writable.
        let own = cap_store::with_table(A, |t| memobj_resolve_map(t, cap_a, MAP_OP)).unwrap().expect("resolves");
        assert!(own.writable);
        // The share cannot be raised: asking the sender's copy for more is refused,
        // and the receiver's copy cannot hand on what it lacks.
        assert!(transfer(A, C, cap_a, true, Some(CapPerms::RW)).is_ok(), "equal rights are fine");
        let again = transfer(B, C, ro_b, true, Some(CapPerms::WRITE));
        assert_eq!(again.err(), Some(CapError::MissingPerms), "a share cannot raise rights");
        assert_eq!(azos_sched::shim_charged(A), 2, "the object is charged once, to its holder");
        assert_eq!(azos_sched::shim_charged(B), 0);
        assert!(cap_store::get(A, cap_a, CapPerms::READ).is_ok(), "the sender keeps its capability");
        // Revoking the sender's capability takes the share with it (the warrant tree).
        cap_store::revoke(A, cap_a);
        assert!(cap_store::get(B, ro_b, CapPerms::READ).is_err(), "the share is a child of the sender's warrant");
    }

    /// **MAP is its own right.** A capability that reads a region (`READ`: acquire,
    /// release, clone) does not thereby get a window in ring 3: the map asks
    /// `READ` and `MAP`. The creator's capability has both, `WRITE` still decides
    /// the writable bit, and a SHARE that left `MAP` out maps nothing.
    ///
    /// **Canary.** Resolve the map with `READ` alone (`memobj_resolve_map`): the
    /// `MissingPerms` assertions read `Ok(_)`.
    #[test]
    fn a_map_needs_map_and_read_does_not_give_it() {
        let _g = setup();
        let _h = Hooks::install();
        azos_sched::shim_set_current(A, 0x1000);
        let cap_a = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let held = cap_store::with_table(A, |t| t.peek_raw(cap_a.raw())).unwrap().expect("held").1;
        assert!(held.contains(CapPerms::RW.union(CapPerms::MAP)), "the creator maps its own region");
        assert!(held.contains(CapPerms::DELEGATE), "and may share or gift it");
        let map = |who: u32, cap: Cap<Shm>| cap_store::with_table(who, |t| memobj_resolve_map(t, cap, MAP_OP)).unwrap();

        // READ and WRITE without MAP: the capability reads and writes the region
        // through the kernel, and maps nothing.
        let no_map = transfer(A, B, cap_a, true, Some(CapPerms::RW)).expect("share RW");
        assert_eq!(map(B, no_map), Err(MemObjError::Cap(CapError::MissingPerms)), "RW is no window");
        assert_eq!(cap_store::get(B, no_map, CapPerms::READ).map(|_| ()), Ok(()), "READ still resolves");
        // MAP without READ is no map either: the region is read through the window.
        let map_only = transfer(A, C, cap_a, true, Some(CapPerms::MAP)).expect("share MAP");
        assert_eq!(map(C, map_only), Err(MemObjError::Cap(CapError::MissingPerms)), "MAP alone reads nothing");
        // READ|MAP maps, read-only; adding WRITE maps it writable.
        let view = transfer(A, B, cap_a, true, Some(CapPerms::READ.union(CapPerms::MAP))).expect("share READ|MAP");
        let g = map(B, view).expect("READ|MAP maps");
        assert!(!g.writable, "without WRITE the window is read-only");
        let rw = transfer(A, C, cap_a, true, Some(CapPerms::RW.union(CapPerms::MAP))).expect("share RW|MAP");
        assert!(map(C, rw).expect("RW|MAP maps").writable);
    }

    /// A map may be made writable again only within what it was allowed: a
    /// mapping a READ-only share made cannot be raised by a protect.
    ///
    /// **Canary** `memobj-protect-max-canary`: "protect raised past the map's
    /// rights" fails.
    #[test]
    fn protect_never_goes_past_what_the_map_was_allowed() {
        let _g = setup();
        let _h = Hooks::install();
        azos_sched::shim_set_current(A, 0x1000);
        let cap = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let r = cap_store::get(A, cap, CapPerms::READ).unwrap();
        assert_eq!(memobj_acquire_ref(B, r).map(|_| ()), Ok(()));
        // B mapped read-only: the access its capability allowed.
        assert_eq!(memobj_note_mapping_ref(B, r, 0xB000, VA, 1, MapAccess::RO), Ok(true));
        let raised = memobj_protect_ref(B, r, true);
        assert_eq!(raised, Err(MemObjError::Cap(CapError::MissingPerms)), "protect raised past the map's rights");
        assert!(PROTECTS.lock().unwrap().is_empty(), "and no PTE changed");
        // A's own writable mapping can drop to read-only and come back.
        assert_eq!(memobj_note_mapping_ref(A, r, ROOT_A, VA + 0x10_0000, 1, MapAccess::RW), Ok(true));
        assert_eq!(memobj_protect_ref(A, r, false), Ok(()));
        assert_eq!(memobj_protect_ref(A, r, true), Ok(()));
        assert_eq!(PROTECTS.lock().unwrap().len(), 2);
    }

    /// **Private Anon on the marker-PTE path.** A reservation is charged whole to
    /// the caller's Domain, writes one marker per page and no frame; one that
    /// overlaps an existing reservation, or does not fit the budget, takes nothing
    /// (no marker, no charge); releasing the range answers how many markers there
    /// were, for the caller to discharge.
    ///
    /// **Canary** `memobj-anon-uncharged-canary`: the reservation is not charged,
    /// and "reserve charged the caller" fails.
    #[test]
    fn a_private_anon_reservation_is_charged_whole_and_all_or_nothing() {
        let _g = setup();
        azos_sched::shim_set_current(A, ROOT_A);
        let page = azos_arch::PAGE_SIZE;
        let frames = azos_mm::shim_pages_in_use();
        assert_eq!(anon_reserve(ROOT_A, VA, 4), Ok(()));
        assert_eq!(azos_sched::shim_charged(A), 4, "reserve charged the caller");
        assert_eq!(azos_mm::demand::shim_markers(), 4, "one marker per page");
        assert_eq!(azos_mm::shim_pages_in_use(), frames, "and no frame");
        // Overlapping: refused, nothing taken, the first reservation untouched.
        assert_eq!(anon_reserve(ROOT_A, VA + 2 * page, 4), Err(MemObjError::Busy));
        assert_eq!((azos_sched::shim_charged(A), azos_mm::demand::shim_markers()), (4, 4));
        // Over budget.
        azos_sched::shim_set_limit(A, 6);
        assert_eq!(anon_reserve(ROOT_A, VA + 0x10_0000, 4), Err(MemObjError::NoMem));
        assert_eq!((azos_sched::shim_charged(A), azos_mm::demand::shim_markers()), (4, 4));
        // The release counts what was never touched.
        assert_eq!(anon_release_range(ROOT_A, VA, VA + 6 * page), 4);
        azos_sched::mm_discharge(4);
        assert_eq!((azos_sched::shim_charged(A), azos_mm::demand::shim_markers()), (0, 0));
    }

    // ── The reverse map: object -> mappings ───────────────────────────────────

    const ROOT_B: usize = 0xB000;
    const ROOT_C: usize = 0xC000;
    const VA_B: usize = 0x6100_0000;
    const VA_C: usize = 0x6200_0000;

    fn unmaps() -> Vec<(usize, usize, usize)> {
        let mut v = UNMAPS.lock().unwrap().clone();
        v.sort();
        v
    }

    /// Give back every reference of `tids` on `r` the way their exits do.
    fn release_all_holders(tids: &[u32], r: u32) {
        for &tid in tids {
            let _ = memobj_take_mapping_ref(tid, r);
            while memobj_release_ref(tid, r).is_ok() {}
        }
    }

    /// `A` creates an object of `pages` pages and maps it at `(ROOT_A, VA)`;
    /// the capability and the packed reference.
    fn created_and_mapped_by_a(pages: usize) -> (Cap<Shm>, u32) {
        azos_sched::shim_set_current(A, 0x1000);
        let cap = memobj_create_cap(A, pages, &MemSpec::anon(MemPerms::ReadWrite)).expect("create");
        let r = cap_store::get(A, cap, CapPerms::READ).unwrap();
        assert_eq!(memobj_note_mapping_ref(A, r, ROOT_A, VA, pages, MapAccess::RW), Ok(true));
        (cap, r)
    }

    /// `from` shares `cap` with `to` (a DUP: the warrant tree gains a child),
    /// `to` takes its reference and maps `n` pages at `(root, va)`; the
    /// receiver's capability.
    fn shared_and_mapped(from: u32, to: u32, cap: Cap<Shm>, root: usize, va: usize, n: usize) -> Cap<Shm> {
        let shared = transfer(from, to, cap, true, None).expect("the share lands");
        acquire(to, shared).expect("the receiver takes a reference");
        let r = cap_store::get(to, shared, CapPerms::READ).unwrap();
        assert_eq!(memobj_note_mapping_ref(to, r, root, va, n, MapAccess::RW), Ok(true));
        shared
    }

    /// **A revoked share loses its mapping and its references.** A creates an
    /// object and shares it with B and C, who map it in their own spaces
    /// (different lengths). A revokes what it derived (`SYS_CAP_REVOKE`: the
    /// sweep revokes the two shares): each is unmapped in its own root at its own
    /// VA and length, its record is forgotten, its window is its own to give
    /// back, its references are gone, and its capability is stale. A keeps its
    /// mapping, its reference, and a capability that resolves. A second revoke
    /// finds nothing to take.
    ///
    /// **Canary** `memobj-sweep-no-hook-canary`: the sweep does not call the
    /// hook (boot had not registered it); the unmaps row fails and B and C still
    /// map the object.
    #[test]
    fn a_revoked_share_loses_its_mapping_and_its_references() {
        let _g = setup();
        let _h = Hooks::install();
        let (cap_a, r) = created_and_mapped_by_a(3);
        let cap_b = shared_and_mapped(A, B, cap_a, ROOT_B, VA_B, 2);
        let cap_c = shared_and_mapped(A, C, cap_a, ROOT_C, VA_C, 1);
        assert_eq!(refs(LAYOUT.idx(r)), Some(3), "A, B and C each hold one");

        let kept = cap_store::revoke_derived(A, cap_a.raw()).expect("A revokes what it derived");
        assert_eq!(unmaps(), vec![(ROOT_B, VA_B, 2), (ROOT_C, VA_C, 1)], "B's and C's spaces, nothing of A's");
        for tid in [B, C] {
            assert_eq!(memobj_has_mapping_ref(tid, r), Ok(false), "the record of {tid} is gone");
            assert_eq!(memobj_take_moved_windows(tid, &mut [(0, 0); 4]), 1, "{tid} gets its window to give back");
        }
        assert_eq!(refs(LAYOUT.idx(r)), Some(1), "only A's reference is left");
        assert!(cap_store::get(B, cap_b, CapPerms::READ).is_err() && cap_store::get(C, cap_c, CapPerms::READ).is_err());
        assert_eq!(memobj_has_mapping_ref(A, r), Ok(true), "the revoker keeps its mapping");
        assert_eq!(memobj_take_moved_windows(A, &mut [(0, 0); 4]), 0);
        assert!(cap_store::get(A, Cap::<Shm>::from_raw(kept), CapPerms::READ).is_ok(), "and a capability that resolves");

        memobj_warrant_swept(r, cap_store::domain_key_of(B));
        assert_eq!(UNMAPS.lock().unwrap().len(), 2, "a second sweep of the same Domain takes nothing");
        release_all_holders(&[A], r);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// **The sweep reaches a share of a share, and only the objects and Domains
    /// it names.** B passes A's share on to C; A revokes: both lose the
    /// object. B's mapping of a second object A also shared with it is left
    /// alone, so is a Domain that holds a reference by no swept capability.
    ///
    /// **Canary** `memobj-sweep-every-domain-canary`: `memobj_warrant_swept`
    /// ignores `owner` (takes every holder); D's mapping goes too and "D is not
    /// swept" fails.
    #[test]
    fn the_sweep_reaches_a_share_of_a_share_and_spares_other_objects_and_domains() {
        const D: u32 = 24;
        let _g = setup();
        cap_store::reset(D);
        let _h = Hooks::install();
        let (cap_a, r) = created_and_mapped_by_a(2);
        let other = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let other_r = cap_store::get(A, other, CapPerms::READ).unwrap();
        let other_b = transfer(A, B, other, true, None).expect("the second object is shared too");
        acquire(B, other_b).unwrap();
        assert_eq!(memobj_note_mapping_ref(B, other_r, ROOT_B, VA_B + 0x10_0000, 1, MapAccess::RW), Ok(true));

        let cap_b = shared_and_mapped(A, B, cap_a, ROOT_B, VA_B, 2);
        let cap_c = shared_and_mapped(B, C, cap_b, ROOT_C, VA_C, 2);
        // D holds a reference to `r` with no capability from this warrant tree.
        memobj_acquire_ref(D, r).expect("D takes a reference");
        assert_eq!(memobj_note_mapping_ref(D, r, 0xD000, VA_C + 0x10_0000, 2, MapAccess::RW), Ok(true));
        UNMAPS.lock().unwrap().clear();

        cap_store::revoke_derived(A, cap_a.raw()).expect("A revokes");
        assert_eq!(unmaps(), vec![(ROOT_B, VA_B, 2), (ROOT_C, VA_C, 2)], "B's and its pass-on C's");
        assert!(cap_store::get(C, cap_c, CapPerms::READ).is_err(), "the share of a share is revoked");
        assert_eq!(memobj_has_mapping_ref(B, other_r), Ok(true), "B's other object is left alone");
        assert_eq!(memobj_has_mapping_ref(D, r), Ok(true), "D is not swept");
        assert_eq!(memobj_has_mapping_ref(A, r), Ok(true));
        release_all_holders(&[A, D], r);
        release_all_holders(&[A, B], other_r);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// **A Domain that holds the object by another capability keeps it.** B has
    /// two `Cap<Shm>` slots for one object: a share of A's, and one minted from
    /// a warrant tree of its own (the creator's `DELEGATE` hand-over by another
    /// route). A revokes its share: the slot it derived is swept, the other is
    /// B's still, so B's mapping and reference stay and the surviving capability
    /// resolves.
    ///
    /// **Canary** `memobj-sweep-no-retain-canary`: the sweep skips
    /// `retain_unheld`; B's mapping goes and "B keeps its mapping" fails.
    #[test]
    fn a_domain_that_still_holds_the_object_by_another_capability_keeps_its_mapping() {
        let _g = setup();
        let _h = Hooks::install();
        let (cap_a, r) = created_and_mapped_by_a(2);
        let shared = shared_and_mapped(A, B, cap_a, ROOT_B, VA_B, 2);
        let own = mint(B, r);
        UNMAPS.lock().unwrap().clear();

        cap_store::revoke_derived(A, cap_a.raw()).expect("A revokes");
        assert!(cap_store::get(B, shared, CapPerms::READ).is_err(), "the share is swept");
        assert!(cap_store::get(B, own, CapPerms::READ).is_ok(), "B's other capability resolves");
        assert!(UNMAPS.lock().unwrap().is_empty(), "nothing of B's is unmapped");
        assert_eq!(memobj_has_mapping_ref(B, r), Ok(true), "B keeps its mapping");
        assert_eq!(refs(LAYOUT.idx(r)), Some(2), "and its reference");
        release_all_holders(&[A, B], r);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// A pinned holder may have PTEs the records do not name (a failed map): the
    /// revoke of its share unmaps the mapping it does name and gives back all
    /// its references but the pinned one, so no frame goes back under the
    /// stranded PTEs; that reference ends with the holder's exit.
    ///
    /// **Canary (by hand):** drop the `h.pinned` test from
    /// `memobj_revoke_holder_ref`; B's pinned reference goes and the "still
    /// pinned" row fails.
    #[test]
    fn a_pinned_holder_keeps_its_pinned_reference_when_its_share_is_revoked() {
        let _g = setup();
        let _h = Hooks::install();
        let (cap_a, r) = created_and_mapped_by_a(2);
        let cap_b = shared_and_mapped(A, B, cap_a, ROOT_B, VA_B, 2);
        assert_eq!(memobj_pin_ref(B, r), Ok(true));
        assert_eq!(refs(LAYOUT.idx(r)), Some(2), "A's one, and B's, which the pin marks");

        cap_store::revoke_derived(A, cap_a.raw()).expect("A revokes");
        assert_eq!(unmaps(), vec![(ROOT_B, VA_B, 2)], "the mapping the record names is unmapped");
        assert_eq!(memobj_has_mapping_ref(B, r), Ok(false));
        assert_eq!(refs(LAYOUT.idx(r)), Some(2), "A's, and B's pinned one: no frame goes back under B's stranded PTEs");
        assert!(cap_store::get(B, cap_b, CapPerms::READ).is_err());
        memobj_release_all(B);
        assert_eq!(refs(LAYOUT.idx(r)), Some(1), "the exit gives the pinned one back");
        release_all_holders(&[A], r);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// **Delete is not revoke: a sharer's exit leaves the share.** A creates an
    /// object and shares it with B, who maps it. A exits (the table wipe and the
    /// release of its references and mapping): B's capability resolves, its
    /// mapping and reference stay, nothing of B's is unmapped, and the object
    /// lives on its frames until B lets go.
    ///
    /// **Canary** `memobj-sweep-no-hook-canary` does not apply (the hook is not
    /// reached); by hand: make `clear_all` revoke what it forwards
    /// (`clear_all` owing a revocation): B's capability is swept, its
    /// mapping unmapped, and every row below fails.
    #[test]
    fn a_sharers_exit_leaves_the_share_and_its_mapping() {
        let _g = setup();
        let _h = Hooks::install();
        let (cap_a, r) = created_and_mapped_by_a(2);
        let cap_b = shared_and_mapped(A, B, cap_a, ROOT_B, VA_B, 2);
        UNMAPS.lock().unwrap().clear();

        cap_store::reset(A);
        memobj_release_all(A);
        assert!(unmaps().is_empty(), "no unmap was shot at B's mapping (A's own goes with its address space)");
        assert!(cap_store::get(B, cap_b, CapPerms::READ).is_ok(), "B's capability still resolves");
        assert_eq!(memobj_has_mapping_ref(B, r), Ok(true), "B keeps its mapping");
        assert_eq!(refs(LAYOUT.idx(r)), Some(1), "and its reference, alone now");
        let grant = cap_store::with_table(B, |t| memobj_resolve_map(t, cap_b, MAP_OP)).unwrap();
        assert!(grant.is_ok(), "B can still map it");
        assert!(azos_mm::shim_pages_in_use() > 0, "the object lives on");
        release_all_holders(&[B], r);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// **An explicit revoke after a close still reaches the share of a share.**
    /// A shares with B, B passes it on to C and then closes its own capability
    /// (its reference and mapping go with it). C's share stays: it hangs under
    /// A's capability now. A then revokes what it derived: C loses the object,
    /// its mapping and its reference. This is what tells a re-parent from a
    /// copy turned into a root (which no revoke of A's would reach).
    ///
    /// **Canary** (by hand): re-parent to 0 in `sweep_dead` (`Fate::Reparent(0)`
    /// always): the revoke finds nothing and "C loses the object" fails.
    #[test]
    fn a_revoke_reaches_the_share_of_a_share_whose_middle_link_was_closed() {
        let _g = setup();
        let _h = Hooks::install();
        let (cap_a, r) = created_and_mapped_by_a(2);
        let cap_b = shared_and_mapped(A, B, cap_a, ROOT_B, VA_B, 2);
        let cap_c = shared_and_mapped(B, C, cap_b, ROOT_C, VA_C, 1);
        // B lets go: its mapping, then its capability (a close).
        memobj_take_mapping_ref(B, r).expect("B unmaps");
        UNMAPS.lock().unwrap().clear();
        cap_store::with_table(B, |t| memobj_release_cap(B, t, cap_b)).unwrap().expect("B closes");
        assert!(cap_store::get(B, cap_b, CapPerms::READ).is_err(), "B's handle is gone");
        assert!(cap_store::get(C, cap_c, CapPerms::READ).is_ok(), "C's share stays");
        assert_eq!(memobj_has_mapping_ref(C, r), Ok(true), "C keeps its mapping");
        assert!(UNMAPS.lock().unwrap().is_empty(), "nothing of C's was unmapped");

        cap_store::revoke_derived(A, cap_a.raw()).expect("A revokes what it derived");
        assert!(cap_store::get(C, cap_c, CapPerms::READ).is_err(), "C loses the object");
        assert_eq!(unmaps(), vec![(ROOT_C, VA_C, 1)], "and its mapping");
        assert_eq!(memobj_has_mapping_ref(C, r), Ok(false));
        assert_eq!(refs(LAYOUT.idx(r)), Some(1), "only A's reference is left");
        release_all_holders(&[A], r);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// **The holder table is bounded.** An object has `MAX_MEMOBJ_HOLDERS`
    /// holders, each with at most one recorded mapping; the next task's acquire
    /// is refused (`Closed`) and the holders keep their references.
    #[test]
    fn the_holder_table_is_bounded_and_the_next_mapper_is_refused() {
        let _g = setup();
        let _h = Hooks::install();
        azos_sched::shim_set_current(A, 0x1000);
        let cap = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let r = cap_store::get(A, cap, CapPerms::READ).unwrap();
        let tids: Vec<u32> = (0..MAX_MEMOBJ_HOLDERS as u32).map(|k| if k == 0 { A } else { 100 + k }).collect();
        for (k, &tid) in tids.iter().enumerate() {
            if tid != A {
                memobj_acquire_ref(tid, r).expect("a holder slot is free");
            }
            let root = 0x1_0000 + k * 0x1000;
            assert_eq!(memobj_note_mapping_ref(tid, r, root, VA + k * 0x10_0000, 1, MapAccess::RW), Ok(true));
        }
        assert_eq!(memobj_acquire_ref(999, r), Err(MemObjError::Closed), "the list is full");
        release_all_holders(&tids, r);
    }

    /// **A COW clone shares frames and the reverse map follows the rule: the
    /// object that allocated a frame names it until it lets go.** The clone's
    /// shared pages are still the source's; a source that goes first leaves them
    /// nameless (the clone still holds them); the clone's break gives it frames
    /// of its own that name the clone, and its old shared frame stops naming
    /// the clone's source only when the source is the one releasing. The shim's
    /// `free_page` refuses a frame that still names an object, so every release
    /// below also checks the clearing.
    #[test]
    fn a_cow_clone_leaves_the_frames_naming_their_allocator_until_the_break() {
        let _g = setup();
        let _h = Hooks::install();
        azos_sched::shim_set_current(A, 0x1000);
        let cap = memobj_create_cap(A, 2, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let src = cap_store::get(A, cap, CapPerms::READ).unwrap();
        let shared: Vec<usize> = (0..2).map(|i| memobj_page_phys_ref(src, i).unwrap().unwrap()).collect();
        let clone = memobj_clone(A, src, B, MemPerms::ReadWrite).expect("clone");
        assert_eq!(memobj_page_phys_ref(clone, 0), Ok(Some(shared[0])), "the clone shares the frame");
        for (i, &p) in shared.iter().enumerate() {
            assert_eq!(azos_mm::pmm::frame_owner(p), Some((src, i as u32)), "still the allocator's");
        }
        // The clone breaks page 0: a frame of its own, naming the clone.
        assert_eq!(memobj_cow_break(clone, 0), Ok(()));
        let own = memobj_page_phys_ref(clone, 0).unwrap().unwrap();
        assert_ne!(own, shared[0]);
        assert_eq!(azos_mm::pmm::frame_owner(own), Some((clone, 0)));
        assert_eq!(azos_mm::pmm::frame_owner(shared[0]), Some((src, 0)), "the source's frame is the source's");
        // The source lets go while the clone still shares page 1: the frame
        // lives on, nameless.
        release_all_holders(&[A], src);
        assert_eq!(memobj_info(LAYOUT.idx(src)), None);
        assert_eq!(azos_mm::pmm::frame_owner(shared[1]), None);
        assert_eq!(azos_mm::shim_free_count(shared[1]), 0, "still held by the clone");
        assert_eq!(azos_mm::shim_free_count(shared[0]), 1, "page 0 had one sharer left: the source");
        // The clone's last release frees what it holds, clearing first.
        release_all_holders(&[B], clone);
        assert_eq!(azos_mm::pmm::frame_owner(own), None);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    // ── Paged objects: the page cache (storage L11, part A) ───────────────────
    //
    // A file stands in as a byte vector behind `PageBacking`; the real file
    // layer's side of it is `tests/host/fs-tests/src/page_cache.rs`.

    use core::sync::atomic::AtomicBool;
    use azos_mm::pager::PageIoError;

    struct FileBacking {
        data: StdMutex<Vec<u8>>,
        reads: AtomicUsize,
        /// `(byte offset, length)` of every write-back.
        writes: StdMutex<Vec<(u64, usize)>>,
        fail_reads: AtomicBool,
        fail_writes: AtomicBool,
        /// Run (with no lock of ours held) inside every write-back.
        in_write: StdMutex<Option<fn(u32)>>,
        cur: AtomicU32,
    }

    impl PageBacking for FileBacking {
        fn read_page(&self, _k: &PageKey, off: u64, dst: &mut [u8]) -> Result<usize, PageIoError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.fail_reads.load(Ordering::SeqCst) {
                return Err(PageIoError::Io);
            }
            let d = self.data.lock().unwrap();
            let off = off as usize;
            let n = dst.len().min(d.len().saturating_sub(off));
            dst[..n].copy_from_slice(&d[off..off + n]);
            Ok(n)
        }

        fn write_page(&self, _k: &PageKey, off: u64, src: &[u8]) -> Result<(), PageIoError> {
            let hook = *self.in_write.lock().unwrap();
            if let Some(f) = hook {
                f(self.cur.load(Ordering::SeqCst));
            }
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(PageIoError::Io);
            }
            self.writes.lock().unwrap().push((off, src.len()));
            let mut d = self.data.lock().unwrap();
            let off = off as usize;
            assert!(off + src.len() <= d.len(), "a write-back lengthened the file");
            d[off..off + src.len()].copy_from_slice(src);
            Ok(())
        }
    }

    /// A file of `len` bytes, byte `p` being `p % 251 + 1` (never 0, so a zero
    /// is the cache's, not the file's).
    fn file(len: usize) -> &'static FileBacking {
        Box::leak(Box::new(FileBacking {
            data: StdMutex::new((0..len).map(|p| (p % 251 + 1) as u8).collect()),
            reads: AtomicUsize::new(0),
            writes: StdMutex::new(Vec::new()),
            fail_reads: AtomicBool::new(false),
            fail_writes: AtomicBool::new(false),
            in_write: StdMutex::new(None),
            cur: AtomicU32::new(0),
        }))
    }

    const FKEY: PageKey = PageKey([7; 64]);

    /// The cache's frame of page `i`, which must be in the cache.
    fn cached(r: u32, i: usize) -> &'static mut [u8] {
        let p = memobj_page_phys_ref(r, i).unwrap().expect("page is in the cache");
        // SAFETY: a frame of a live object, in a single-threaded test.
        unsafe { frame_bytes(p) }
    }

    fn fbyte(p: usize) -> u8 {
        (p % 251 + 1) as u8
    }

    /// A 3-page window at file page 5 of a file that ends 100 bytes into the
    /// window's third page.
    fn window() -> (&'static FileBacking, u32, usize) {
        let page = azos_arch::PAGE_SIZE;
        let size = 7 * page + 100;
        let f = file(size);
        let r = memobj_create_paged(f, FKEY, 5, 3, size as u64, MemPerms::ReadWrite).expect("create");
        f.cur.store(r, Ordering::SeqCst);
        (f, r, 5 * page)
    }

    /// **Read through the cache.** The first read of a page fills it from the
    /// file (one backing call per page), a second read is a hit, the bytes are
    /// the file's from the window's place in it, the page that straddles the end
    /// is zero after the file's last byte, and a read stops at the end of the
    /// file. A failed fill takes no frame and leaves the page out.
    ///
    /// **Canary (by hand, 2026-10-16).** `paged_page_in` filling without the
    /// `phys_pages[idx] != 0` early return: "a hit read the file again" red.
    #[test]
    fn a_paged_object_reads_through_the_cache_and_fills_each_page_once() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let (f, r, base) = window();
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0, "no frame before the first use");
        assert_eq!(azos_mm::shim_pages_in_use(), 0);

        let len = 2 * page + 100;
        let mut buf = vec![0u8; len];
        assert_eq!(memobj_paged_read_ref(r, 0, &mut buf), Ok(len));
        assert!(buf.iter().enumerate().all(|(p, &b)| b == fbyte(base + p)), "the window's bytes are the file's");
        assert_eq!(f.reads.load(Ordering::SeqCst), 3, "one backing call per page");
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0b111);
        assert_eq!(azos_mm::shim_pages_in_use(), 3);
        assert!(cached(r, 2)[100..].iter().all(|&b| b == 0), "zeros after the file's end");
        assert_eq!(cached(r, 2)[99], fbyte(base + 2 * page + 99));

        assert_eq!(memobj_paged_read_ref(r, 10, &mut buf[..20]), Ok(20));
        memobj_paged_frame_ref(r, 1, false).expect("a hit");
        assert_eq!(f.reads.load(Ordering::SeqCst), 3, "a hit read the file again");
        assert_eq!(azos_mm::pmm::frame_owner(memobj_page_phys_ref(r, 1).unwrap().unwrap()), Some((r, 1)), "the frame names the object");

        let mut tail = [0u8; 50];
        assert_eq!(memobj_paged_read_ref(r, 2 * page + 90, &mut tail), Ok(10), "the file ends there");
        assert_eq!(memobj_paged_read_ref(r, 3 * page, &mut tail), Ok(0), "past the window");
        assert_eq!(memobj_page_phys_ref(r, 3), Ok(None));

        // A fill that fails: no frame, no page.
        assert_eq!(memobj_paged_drop_clean(8), 3);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
        f.fail_reads.store(true, Ordering::SeqCst);
        assert_eq!(memobj_paged_read_ref(r, 0, &mut tail), Err(PagedError::Io(PageIoError::Io)));
        assert_eq!(azos_mm::shim_pages_in_use(), 0, "a failed fill leaked its frame");
        assert_eq!(memobj_page_phys_ref(r, 0), Ok(None));
        f.fail_reads.store(false, Ordering::SeqCst);
        assert_eq!(memobj_paged_read_ref(r, 0, &mut tail), Ok(50));

        assert_eq!(memobj_paged_close_ref(r), Ok(()));
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
        assert_eq!(memobj_paged_info_ref(r), Err(STALE), "the object ended with its last reference");
    }

    /// **Dirty write-back.** A write through the cache dirties its page and
    /// stops at the end of the file; the write-back sends the valid part of the
    /// page only (the file never grows), clears the bit, and sends nothing the
    /// second time. A write that fails leaves the page dirty. A read-only object
    /// refuses writes.
    ///
    /// **Canary (by hand, 2026-10-16).** `write_back_page` writing all of
    /// `src`: the fake file's "lengthened the file" assert fires.
    #[test]
    fn a_dirty_page_is_written_back_once_and_only_its_valid_part() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let (f, r, base) = window();

        assert_eq!(memobj_paged_write_ref(r, 2 * page + 90, &[0xEE; 50]), Ok((10, 1)), "stops at the end of the file");
        assert_eq!(memobj_paged_info_ref(r).unwrap().dirty, 0b100);
        assert_eq!(f.data.lock().unwrap()[base + 2 * page + 90], fbyte(base + 2 * page + 90), "not in the file yet");
        assert_eq!(memobj_paged_writeback_ref(r), Ok(1));
        assert_eq!(f.writes.lock().unwrap().as_slice(), &[((base + 2 * page) as u64, 100)], "the valid part only");
        let d = f.data.lock().unwrap();
        assert_eq!(d.len(), base + 2 * page + 100, "the file did not grow");
        assert!(d[base + 2 * page + 90..].iter().all(|&b| b == 0xEE));
        drop(d);
        assert_eq!(memobj_paged_info_ref(r).unwrap().dirty, 0);
        assert_eq!(memobj_paged_writeback_ref(r), Ok(0), "nothing to write twice");

        // A failing medium: dirty again, the error is the answer.
        assert_eq!(memobj_paged_write_ref(r, 3, &[0xAB]), Ok((1, 1)));
        f.fail_writes.store(true, Ordering::SeqCst);
        assert_eq!(memobj_paged_writeback_ref(r), Err(PagedError::Io(PageIoError::Io)));
        assert_eq!(memobj_paged_info_ref(r).unwrap().dirty, 0b001, "still dirty");
        f.fail_writes.store(false, Ordering::SeqCst);
        assert_eq!(memobj_paged_writeback_ref(r), Ok(1));
        assert_eq!(f.data.lock().unwrap()[base + 3], 0xAB);

        // Dirty at close: flushed, then the frames go.
        assert_eq!(memobj_paged_write_ref(r, page + 1, &[0xCD]), Ok((1, 1)));
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
        assert_eq!(f.data.lock().unwrap()[base + page + 1], 0xCD, "close wrote the dirty page");
        assert_eq!(azos_mm::shim_pages_in_use(), 0);

        // Read-only.
        let ro = memobj_create_paged(f, FKEY, 5, 1, 6 * page as u64, MemPerms::ReadOnly).unwrap();
        let denied = PagedError::Obj(MemObjError::Cap(CapError::MissingPerms));
        assert_eq!(memobj_paged_write_ref(ro, 0, &[1]), Err(denied));
        assert_eq!(memobj_paged_frame_ref(ro, 0, true), Err(denied));
        assert_eq!(memobj_paged_close_ref(ro), Ok(()));
    }

    /// **A clean page is droppable, a dirty one is not.** The drop returns the
    /// frame to the allocator (and the frame stops naming the object); the next
    /// read goes to the file again; a dirty page stays until it is written
    /// back, and then goes.
    ///
    /// **Canary (by hand, 2026-10-16).** `memobj_paged_drop_clean` without the
    /// `must_flush` test: "dropped a dirty page" red.
    #[test]
    fn a_clean_page_is_dropped_under_pressure_and_a_dirty_one_is_not() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let (f, r, base) = window();
        let mut b = [0u8; 4];
        assert_eq!(memobj_paged_read_ref(r, 0, &mut b), Ok(4));
        assert_eq!(memobj_paged_read_ref(r, page, &mut b), Ok(4));
        assert_eq!(memobj_paged_write_ref(r, page + 8, &[0x55]), Ok((1, 1)));
        let p0 = memobj_page_phys_ref(r, 0).unwrap().unwrap();
        assert_eq!(azos_mm::shim_pages_in_use(), 2);

        assert_eq!(memobj_paged_drop_clean(8), 1, "dropped a dirty page");
        assert_eq!(azos_mm::shim_pages_in_use(), 1, "the clean frame went back to the allocator");
        assert_eq!(azos_mm::pmm::frame_owner(p0), None);
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0b010);
        assert_eq!(memobj_paged_drop_clean(8), 0, "the dirty page stays");

        // The dropped page is read again, and the budget bounds a pass.
        let reads = f.reads.load(Ordering::SeqCst);
        assert_eq!(memobj_paged_read_ref(r, 0, &mut b), Ok(4));
        assert_eq!(f.reads.load(Ordering::SeqCst), reads + 1);
        assert_eq!(b, [fbyte(base), fbyte(base + 1), fbyte(base + 2), fbyte(base + 3)]);
        assert_eq!(memobj_paged_writeback_ref(r), Ok(1));
        assert_eq!(memobj_paged_drop_clean(1), 1, "bounded by the budget");
        assert_eq!(memobj_paged_drop_clean(8), 1);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
    }

    /// **The reclaim pass writes back, then drops, in that order.** A dirty
    /// page and a clean one: one pass writes the dirty page and drops both
    /// (the dirty one only because it was written first); a failing file leaves
    /// its dirty page resident and counts the object, and the clean pages go.
    ///
    /// **Canary (by hand, 2026-10-16).** `memobj_paged_reclaim` dropping before
    /// it writes back: "the dirty page was not dropped in the same pass" red.
    #[test]
    fn the_reclaim_pass_writes_back_before_it_drops() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let (f, r, _base) = window();
        let mut b = [0u8; 4];
        assert_eq!(memobj_paged_read_ref(r, 0, &mut b), Ok(4));
        assert_eq!(memobj_paged_write_ref(r, page + 8, &[0x55]), Ok((1, 1)));
        assert_eq!(azos_mm::shim_pages_in_use(), 2);

        let got = memobj_paged_reclaim(8);
        assert_eq!(got, PagedReclaim { written: 1, dropped: 2, failed: 0 }, "the dirty page was not dropped in the same pass");
        assert_eq!(azos_mm::shim_pages_in_use(), 0);

        // A file that refuses the write: the dirty page stays, the pass says so.
        assert_eq!(memobj_paged_read_ref(r, 0, &mut b), Ok(4));
        assert_eq!(memobj_paged_write_ref(r, page + 8, &[0x66]), Ok((1, 1)));
        f.fail_writes.store(true, Ordering::SeqCst);
        let got = memobj_paged_reclaim(8);
        assert_eq!(got, PagedReclaim { written: 0, dropped: 1, failed: 1 });
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0b010, "only the dirty page is left");
        f.fail_writes.store(false, Ordering::SeqCst);
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// **A mapping shares the cache's frame, and the rmap unmaps it on a drop.**
    /// The frame a mapper is given is the frame the kernel reads and writes (a
    /// kernel write shows through it); a clean page that is dropped is unmapped
    /// from the holder's address space, and the mapping stops resolving to it. A
    /// WRITABLE mapping makes its pages count as dirty: they are written back
    /// (every pass) and never dropped until the mapping goes.
    ///
    /// **Canary (by hand, 2026-10-16).** `writable_mapped` returning false:
    /// "dropped a page under a writable mapping" red.
    #[test]
    fn a_mapping_shares_the_cache_frame_and_a_drop_unmaps_it() {
        let _g = setup();
        let _h = Hooks::install();
        let page = azos_arch::PAGE_SIZE;
        let (f, r, base) = window();
        memobj_acquire_ref(A, r).expect("acquire");
        assert_eq!(memobj_note_mapping_ref(A, r, ROOT_A, VA, 3, MapAccess::RO), Ok(true));

        let p1 = memobj_paged_frame_ref(r, 1, false).expect("fill");
        assert_eq!(memobj_page_phys_ref(r, 1), Ok(Some(p1)), "the object's page is the frame the mapper got");
        assert_eq!(memobj_resolve_mapped(A, VA + page + 16), Some((r, page + 16, p1 + 16)), "the mapping resolves to the same frame");
        assert!(cached(r, 1).iter().enumerate().all(|(p, &b)| b == fbyte(base + page + p)));
        assert_eq!(memobj_paged_write_ref(r, page, &[0x77]), Ok((1, 1)));
        assert_eq!(cached(r, 1)[0], 0x77, "a kernel write shows through the mapped frame");
        assert_eq!(memobj_paged_frame_ref(r, 1, false), Ok(p1), "a second ask is the same frame");

        assert_eq!(memobj_paged_drop_clean(8), 0, "dirty");
        assert_eq!(memobj_paged_writeback_ref(r), Ok(1));
        assert!(UNMAPS.lock().unwrap().is_empty());
        assert_eq!(memobj_paged_drop_clean(8), 1);
        assert_eq!(unmaps(), vec![(ROOT_A, VA + page, 1)], "the rmap unmapped the page from the holder's space");
        assert_eq!(memobj_page_phys_ref(r, 1), Ok(None));
        assert_eq!(memobj_resolve_mapped(A, VA + page), None, "the mapping names no word of a page that is out");
        assert_eq!(azos_mm::pmm::frame_owner(p1), None);
        assert_eq!(f.data.lock().unwrap()[base + page], 0x77, "and the file has the write");

        // Filled again, still mapped: the same page, from the file.
        let again = memobj_paged_frame_ref(r, 1, false).unwrap();
        assert_eq!(cached(r, 1)[0], 0x77);
        assert_eq!(memobj_page_phys_ref(r, 1), Ok(Some(again)));

        // A writable mapping: its pages are dirty while it lasts.
        assert_eq!(memobj_take_mapping_ref(A, r), Ok(Some((VA, 3))));
        assert_eq!(memobj_note_mapping_ref(A, r, ROOT_A, VA, 3, MapAccess::RW), Ok(true));
        memobj_paged_frame_ref(r, 2, true).unwrap();
        UNMAPS.lock().unwrap().clear();
        assert_eq!(memobj_paged_info_ref(r).unwrap().dirty, 0b110, "resident pages under a writable mapping");
        assert_eq!(memobj_paged_drop_clean(8), 0, "dropped a page under a writable mapping");
        assert_eq!(memobj_paged_writeback_ref(r), Ok(2));
        assert_eq!(memobj_paged_writeback_ref(r), Ok(2), "a writable mapping is written again on every pass");
        assert_eq!(memobj_paged_drop_clean(8), 0);
        assert!(UNMAPS.lock().unwrap().is_empty());
        assert_eq!(memobj_take_mapping_ref(A, r), Ok(Some((VA, 3))));
        assert_eq!(memobj_paged_drop_clean(8), 2, "clean once the mapping is gone");
        assert_eq!(azos_mm::shim_pages_in_use(), 0);

        // The holder's reference keeps the object: the kernel's close waits.
        assert_eq!(memobj_paged_close_ref(r), Err(PagedError::Obj(MemObjError::Busy)));
        assert_eq!(memobj_release_ref(A, r), Ok(()));
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
    }

    /// **The other generic operations refuse a Paged object.** Clone and MOVE
    /// refuse it; the ring-3 create refuses it; an Anon object is no cache.
    #[test]
    fn generic_operations_refuse_a_paged_object() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let (_f, r, _) = window();
        let mut b = [0u8; 1];
        for i in 0..3 {
            memobj_paged_read_ref(r, i * page, &mut b).unwrap();
        }
        let anon = memobj_create_ref(A, 2, MemPerms::ReadWrite).unwrap();

        memobj_acquire_ref(A, r).unwrap();
        assert_eq!(memobj_clone(A, r, B, MemPerms::ReadWrite), Err(MemObjError::BadArg));
        assert_eq!(memobj_move(A, B, r), Err(MemObjError::BadArg));
        assert_eq!(memobj_create_spec(A, 1, &MemSpec { kind: MemKind::Paged, ..MemSpec::anon(MemPerms::ReadWrite) }), Err(MemObjError::BadArg));
        assert_eq!(memobj_paged_info_ref(anon), Err(MemObjError::BadArg), "an Anon object is not a cache");
        assert_eq!(memobj_paged_read_ref(anon, 0, &mut b), Err(PagedError::Obj(MemObjError::BadArg)));
        assert_eq!(memobj_release_ref(A, r), Ok(()));
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
        assert!(memobj_release_ref(A, anon).is_ok());
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// **A page being written back is neither dropped nor written.** From inside
    /// the backing call (the table unlocked, the dirty bit already cleared) the
    /// drop leaves the page alone and a kernel write to it is refused; once the
    /// write-back ends both work.
    ///
    /// **Canary (by hand, 2026-10-16).** `memobj_paged_drop_clean` without its
    /// `flushing` test: "dropped a page that is being written back" red.
    #[test]
    fn a_page_being_written_back_is_neither_dropped_nor_written() {
        static DROPPED: AtomicUsize = AtomicUsize::new(usize::MAX);
        static WRITE: StdMutex<Option<Result<(usize, usize), PagedError>>> = StdMutex::new(None);
        static LOCK_FREE: AtomicBool = AtomicBool::new(false);
        fn inside(r: u32) {
            LOCK_FREE.store(__memobj_table_unlocked_for_tests(), Ordering::SeqCst);
            DROPPED.store(memobj_paged_drop_clean(8), Ordering::SeqCst);
            *WRITE.lock().unwrap() = Some(memobj_paged_write_ref(r, 0, &[1]));
        }
        let _g = setup();
        let (f, r, _) = window();
        assert_eq!(memobj_paged_write_ref(r, 0, &[0x42]), Ok((1, 1)));
        *f.in_write.lock().unwrap() = Some(inside);
        assert_eq!(memobj_paged_writeback_ref(r), Ok(1));
        *f.in_write.lock().unwrap() = None;
        assert!(LOCK_FREE.load(Ordering::SeqCst), "the backing was called with the table locked");
        assert_eq!(DROPPED.load(Ordering::SeqCst), 0, "dropped a page that is being written back");
        assert_eq!(WRITE.lock().unwrap().take(), Some(Err(PagedError::Obj(MemObjError::Busy))));
        assert_eq!(memobj_paged_write_ref(r, 0, &[1]), Ok((1, 1)), "writable again");
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
    }

    /// The file grows by `by` bytes behind the cache (an append through the
    /// backend), the pattern continuing.
    fn grow_file(f: &FileBacking, by: usize) {
        let mut d = f.data.lock().unwrap();
        let n = d.len();
        d.extend((n..n + by).map(fbyte));
    }

    /// **Growth keeps the pages, shrinking drops them, dirt goes first.** The
    /// contract of `PageCacheHooks::read`: a longer file keeps every page but
    /// the one that held the old end (it has zeros after it that are bytes
    /// now) and those after it, so an appended file is not refilled whole; a
    /// shorter one loses every page; the dirty pages are written back at the
    /// OLD size before any of it, and the same size does nothing.
    ///
    /// **Canaries (by hand, 2026-10-17).** `memobj_paged_set_size_ref` keeping
    /// the old-end page: the "zeros that are bytes now" read red. Dropping
    /// every page on growth: "a growth refilled the whole file" red. Skipping
    /// the write-back: "dirty bytes reached the file" red. Not clearing on
    /// shrink: the shrink row red.
    #[test]
    fn a_longer_file_keeps_its_pages_but_the_old_end_and_a_shorter_one_loses_them() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let (f, r, base) = window();
        let old = 7 * page + 100;
        let mut all = vec![0u8; 2 * page + 100];
        assert_eq!(memobj_paged_read_ref(r, 0, &mut all), Ok(2 * page + 100));
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0b111);
        assert_eq!(f.reads.load(Ordering::SeqCst), 3);

        // Dirty page 0, then the file is lengthened behind the cache.
        assert_eq!(memobj_paged_write_ref(r, 5, &[0xDD; 4]), Ok((4, 1)));
        grow_file(f, 200);
        assert_eq!(memobj_paged_set_size_ref(r, old as u64 + 200), Ok(()));
        assert_eq!(f.data.lock().unwrap()[base + 5], 0xDD, "dirty bytes reached the file");
        assert_eq!(f.writes.lock().unwrap().as_slice(), &[(base as u64, page)], "page 0 at the old size, whole page");
        let info = memobj_paged_info_ref(r).unwrap();
        assert_eq!((info.size, info.resident, info.dirty), (old as u64 + 200, 0b011, 0), "all but the old-end page");
        assert_eq!(f.reads.load(Ordering::SeqCst), 3, "a growth refilled the whole file");
        let mut tail = vec![0u8; 300];
        assert_eq!(memobj_paged_read_ref(r, 2 * page, &mut tail), Ok(300));
        assert!(tail.iter().enumerate().all(|(p, &b)| b == fbyte(base + 2 * page + p)), "the zeros are bytes now");
        assert_eq!(f.reads.load(Ordering::SeqCst), 4, "the old-end page alone was filled again");

        // The same size: nothing, not even a write-back.
        f.writes.lock().unwrap().clear();
        assert_eq!(memobj_paged_write_ref(r, page, &[1]), Ok((1, 1)));
        assert_eq!(memobj_paged_set_size_ref(r, old as u64 + 200), Ok(()));
        assert!(f.writes.lock().unwrap().is_empty(), "the same size wrote back");
        assert_eq!(memobj_paged_info_ref(r).unwrap().dirty, 0b010);

        // A shorter file is another object: dirt written at the old size, then nothing is left.
        assert_eq!(memobj_paged_set_size_ref(r, 3 * page as u64), Ok(()));
        assert_eq!(f.data.lock().unwrap()[base + page], 1, "dirty bytes reached the file before the cut");
        let info = memobj_paged_info_ref(r).unwrap();
        assert_eq!((info.size, info.resident, info.dirty), (3 * page as u64, 0, 0));
        assert_eq!(azos_mm::shim_pages_in_use(), 0, "the frames went back");
        let mut b = [0u8; 8];
        assert_eq!(memobj_paged_read_ref(r, 2 * page - 4, &mut b), Ok(0), "the cache serves nothing past the new end");
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
    }

    /// **A growth from a page-aligned end drops the empty page after it, and a
    /// write-back that fails changes nothing.** The old end at a page boundary:
    /// the page past it (resident as zeros after a mapper touched it) is the
    /// one dropped, the last real page stays. A medium that refuses the dirty
    /// page leaves the size, the pages and the dirt as they were.
    #[test]
    fn a_page_aligned_old_end_drops_the_page_after_it_and_a_failed_write_back_changes_nothing() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let size = 7 * page;
        let f = file(size);
        let r = memobj_create_paged(f, FKEY, 5, 3, size as u64, MemPerms::ReadWrite).unwrap();
        memobj_paged_frame_ref(r, 1, false).unwrap();
        memobj_paged_frame_ref(r, 2, false).unwrap();
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0b110, "page 2 is past the end: zeros");
        grow_file(f, 10);
        assert_eq!(memobj_paged_set_size_ref(r, size as u64 + 10), Ok(()));
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0b010, "only the page past the old end went");

        assert_eq!(memobj_paged_write_ref(r, page + 3, &[0xEE]), Ok((1, 1)));
        f.fail_writes.store(true, Ordering::SeqCst);
        grow_file(f, 10);
        assert_eq!(memobj_paged_set_size_ref(r, size as u64 + 20), Err(PagedError::Io(PageIoError::Io)));
        let info = memobj_paged_info_ref(r).unwrap();
        assert_eq!((info.size, info.resident, info.dirty), (size as u64 + 10, 0b010, 0b010), "nothing changed");
        f.fail_writes.store(false, Ordering::SeqCst);
        assert_eq!(memobj_paged_set_size_ref(r, size as u64 + 20), Ok(()));
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    /// **Forgetting drops dirty pages without writing them.** The file changed
    /// under the cache (unlink, truncate): from the page that holds the byte,
    /// frames go, dirty ones too, their bytes never reach the file, and a
    /// mapping is unmapped first. The pages before it stay. A pinned holder or
    /// a page being written back refuses it (`Busy`) and nothing is dropped.
    ///
    /// **Canary (by hand, 2026-10-17).** `memobj_paged_forget_ref` writing back
    /// first: "a forgotten page was written" red. Not clearing the dirty bit:
    /// the info row red.
    #[test]
    fn forgetting_drops_dirty_pages_unwritten_and_unmaps_them() {
        let _g = setup();
        let _h = Hooks::install();
        let page = azos_arch::PAGE_SIZE;
        let (f, r, base) = window();
        let mut all = vec![0u8; 2 * page + 100];
        assert_eq!(memobj_paged_read_ref(r, 0, &mut all), Ok(2 * page + 100));
        assert_eq!(memobj_paged_write_ref(r, 3, &[0x11]), Ok((1, 1)));
        assert_eq!(memobj_paged_write_ref(r, page + 3, &[0x22]), Ok((1, 1)));
        assert_eq!(memobj_paged_write_ref(r, 2 * page + 3, &[0x33]), Ok((1, 1)));
        assert_eq!(memobj_paged_info_ref(r).unwrap().dirty, 0b111);

        // A byte inside page 1: pages 1 and 2 go, page 0 (and its dirt) stays.
        assert_eq!(memobj_paged_forget_ref(r, (5 + 1) as u64 * page as u64 + 17), Ok(()));
        let info = memobj_paged_info_ref(r).unwrap();
        assert_eq!((info.resident, info.dirty), (0b001, 0b001));
        assert!(f.writes.lock().unwrap().is_empty(), "a forgotten page was written");
        assert_ne!(f.data.lock().unwrap()[base + page + 3], 0x22);
        // Before the window: all of it. Past it: none.
        assert_eq!(memobj_paged_forget_ref(r, 100 * page as u64), Ok(()));
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0b001);
        assert_eq!(memobj_paged_forget_ref(r, 0), Ok(()));
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
        assert!(f.writes.lock().unwrap().is_empty(), "the dirt was gone: close wrote nothing");

        // A mapping of the page is removed before the frame goes; a pinned holder refuses.
        let (_f2, r2, _) = window();
        memobj_acquire_ref(A, r2).expect("acquire");
        assert_eq!(memobj_note_mapping_ref(A, r2, ROOT_A, VA, 3, MapAccess::RO), Ok(true));
        memobj_paged_frame_ref(r2, 1, false).unwrap();
        UNMAPS.lock().unwrap().clear();
        assert_eq!(memobj_paged_forget_ref(r2, 6 * page as u64), Ok(()));
        assert_eq!(unmaps(), vec![(ROOT_A, VA + page, 1)], "the mapper lost the page before the frame went");
        assert_eq!(memobj_paged_info_ref(r2).unwrap().resident, 0);
        memobj_paged_frame_ref(r2, 1, false).unwrap();
        assert_eq!(memobj_pin_ref(A, r2), Ok(true));
        assert_eq!(memobj_paged_forget_ref(r2, 0), Err(PagedError::Obj(MemObjError::Busy)));
        assert_eq!(memobj_paged_info_ref(r2).unwrap().resident, 0b010, "a refused forget dropped nothing");
        memobj_release_all(A);
        UNMAPS.lock().unwrap().clear();
        assert_eq!(memobj_paged_close_ref(r2), Ok(()));
    }

    /// **A page being written back is not forgotten, nor is its size changed
    /// under it.** From inside the backing's write (the table unlocked, the page
    /// flagged) a forget of that page and a set-size that has to drop it both
    /// answer `Busy`, and the page is still there afterwards.
    #[test]
    fn a_page_being_written_back_refuses_a_forget_and_a_set_size() {
        use std::sync::Mutex as M;
        static SEEN: M<Vec<Result<(), PagedError>>> = M::new(Vec::new());
        fn inside(r: u32) {
            let mut seen = SEEN.lock().unwrap();
            seen.push(memobj_paged_forget_ref(r, 0));
            seen.push(memobj_paged_set_size_ref(r, 1));
        }
        let _g = setup();
        let (f, r, _) = window();
        assert_eq!(memobj_paged_write_ref(r, 0, &[0x42]), Ok((1, 1)));
        *f.in_write.lock().unwrap() = Some(inside);
        assert_eq!(memobj_paged_writeback_ref(r), Ok(1));
        *f.in_write.lock().unwrap() = None;
        let seen = SEEN.lock().unwrap();
        let busy = Err(PagedError::Obj(MemObjError::Busy));
        assert_eq!(seen[0], busy, "forgot the page that is being written");
        assert_eq!(seen[1], busy, "cut the file under the write");
        drop(seen);
        assert_eq!(memobj_paged_info_ref(r).unwrap().resident, 0b001);
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
    }

    /// **A write says how many clean pages it dirtied.** What the file layer
    /// charges to the writer's Domain: the first byte of a clean page is one,
    /// the rest of that page none, a write across a dirty page and a clean one
    /// counts the clean one; a flushed page is clean again.
    ///
    /// **Canary (by hand, 2026-10-17).** Counting every page a write touches:
    /// the second and third asserts red.
    #[test]
    fn a_write_counts_the_pages_it_made_dirty() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let (_f, r, _) = window();
        assert_eq!(memobj_paged_write_ref(r, 1, &[1; 8]), Ok((8, 1)));
        assert_eq!(memobj_paged_write_ref(r, 9, &[1; 8]), Ok((8, 0)), "the page was already dirty");
        assert_eq!(memobj_paged_write_ref(r, page - 4, &[1; 8]), Ok((8, 1)), "page 0 dirty, page 1 clean");
        assert_eq!(memobj_paged_writeback_ref(r), Ok(2));
        assert_eq!(memobj_paged_write_ref(r, 1, &[1; 8]), Ok((8, 1)), "clean again after the write-back");
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
    }
    // ── Volatile objects: dropped under pressure, never written ───────────────

    /// A volatile read-write object of `pages` pages made by `tid`.
    fn create_volatile(tid: u32, pages: usize) -> (Cap<Shm>, u32) {
        let spec = MemSpec::anon(MemPerms::ReadWrite).with_attrs(ATTR_VOLATILE);
        let cap = memobj_create_cap(tid, pages, &spec).expect("create volatile");
        (cap, cap_store::get(tid, cap, CapPerms::READ).expect("resolves"))
    }

    fn nobody_is_locked(_key: u32) -> bool {
        false
    }

    /// The Domain of task `A` is on a `mem = "locked"` row.
    fn a_is_locked(key: u32) -> bool {
        key == azos_sched::task_domain(A as usize)
    }

    /// `(subject, [what, bytes, reason])` of the `Rule::Purge` records written
    /// after record `base`.
    fn purge_records_since(base: u64) -> Vec<(u32, [u64; 3])> {
        let mut v = Vec::new();
        azos_decision::for_each(|r| {
            if r.seq > base && r.rule == azos_decision::Rule::Purge as u8 {
                v.push((r.subject, r.n));
            }
        });
        v
    }

    /// **`ATTR_VOLATILE` is accepted, and only the owner toggles it.** Anon
    /// memory takes the attribute; an object without it, and a task that only
    /// shares the object, cannot be made volatile. A fresh object is Held.
    ///
    /// **Canary (by hand, 2026-10-20).** Dropping the `owner_task` test in
    /// `memobj_set_volatile_ref`: the sharer's refusal goes red.
    #[test]
    fn a_volatile_object_is_toggled_by_its_owner_only() {
        let _g = setup();
        let (cap, r) = create_volatile(A, 1);
        assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Held, "a new object is in use");
        let (plain, rp) = create(A);
        assert_eq!(memobj_set_volatile_ref(A, rp, true), Err(MemObjError::BadArg), "created without the attribute");

        let theirs = mint(B, r);
        acquire(B, theirs).expect("B shares it");
        assert_eq!(memobj_set_volatile_ref(B, r, true), Err(MemObjError::Cap(CapError::MissingPerms)), "a sharer made it droppable");
        assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Held);

        assert_eq!(memobj_set_volatile_ref(A, r, true), Ok(false));
        assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Volatile);
        assert_eq!(memobj_set_volatile_ref(A, r, false), Ok(false));
        assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Held);
        let _ = (cap, plain);
    }

    /// **Reclaim drops a volatile object whole, with no write, and the next map
    /// says `Purged`.** Both holders' mappings are unmapped and their windows
    /// parked for the holder to give back; the frames go back to the allocator
    /// and the charge to the Domain (once: the release of the last reference
    /// does not give it back again); one `Rule::Purge` record names the Domain
    /// and the bytes. The state is final: the map, the clone and both toggles
    /// say so, and a second pass finds nothing.
    ///
    /// **Canary (by hand, 2026-10-20).** `purge_locked` not clearing
    /// `charge_key`: "the charge went back twice" red. Not unmapping: the
    /// unmap assertions red.
    #[test]
    fn reclaim_drops_a_volatile_object_and_the_next_map_says_purged() {
        let _g = setup();
        let _h = Hooks::install();
        let page = azos_arch::PAGE_SIZE;
        azos_sched::shim_set_limit(A, 0);
        // Another object of the Domain, so a charge given back twice shows
        // (the shim's ledger stops at zero).
        let (keep, _) = create(A);
        let (cap, r) = create_volatile(A, 4);
        let theirs = mint(B, r);
        acquire(B, theirs).expect("B shares it");
        assert_eq!(memobj_note_mapping_ref(A, r, ROOT_A, VA, 4, MapAccess::RW), Ok(true));
        assert_eq!(memobj_note_mapping_ref(B, r, ROOT_B, VA + 0x10_0000, 4, MapAccess::RO), Ok(true));
        assert_eq!(azos_sched::shim_charged(A), 5);
        let in_use = azos_mm::shim_pages_in_use();

        // In use: not taken.
        assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 0, "an object in use was purged");
        assert_eq!(memobj_set_volatile_ref(A, r, true), Ok(false));
        assert_eq!(memobj_purge_volatile(0, nobody_is_locked), 0, "asked for nothing");

        let base = azos_decision::total();
        assert_eq!(memobj_purge_volatile(2, nobody_is_locked), 4, "an object goes whole");
        assert_eq!(azos_mm::shim_pages_in_use(), in_use - 4, "the frames went back");
        assert_eq!(azos_sched::shim_charged(A), 1, "and the charge");
        assert_eq!(unmaps(), vec![(ROOT_A, VA, 4), (ROOT_B, VA + 0x10_0000, 4)], "every holder lost its mapping");
        assert_eq!(memobj_has_mapping_ref(A, r), Ok(false));
        assert_eq!(memobj_has_mapping_ref(B, r), Ok(false));
        let mut w = [(0usize, 0usize); 4];
        assert_eq!(memobj_take_moved_windows(A, &mut w), 1);
        assert_eq!(w[0], (VA, 4), "the holder gets its window addresses back");
        assert_eq!(memobj_page_phys_ref(r, 0), Ok(None));
        if azos_decision::ON {
            assert_eq!(
                purge_records_since(base),
                vec![(azos_sched::task_domain(A as usize), [2, (4 * page) as u64, 0])],
                "one record: anonymous pages, the bytes, purged"
            );
        }

        // Final.
        assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Purged);
        assert_eq!(cap_store::with_table(A, |t| memobj_resolve_map(t, cap, MAP_OP)).unwrap().map(|g| g.r), Err(MemObjError::Purged));
        assert_eq!(memobj_clone(A, r, A, MemPerms::ReadWrite), Err(MemObjError::Purged));
        assert_eq!(memobj_set_volatile_ref(A, r, false), Ok(true), "the owner is told");
        assert_eq!(memobj_set_volatile_ref(A, r, true), Ok(true));
        assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Purged, "it does not come back");
        assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 0, "nothing left to take");
        assert_eq!(memobj_with_span_ref(r, 1, |_| ()), Ok(None), "the kernel has no frame to touch");
        let mut out = [0usize; 4];
        assert_eq!(memobj_frames_pin(r, &mut out), Err(MemObjError::Purged));

        // Both holders let go: no frame and no charge goes back a second time.
        release(B, theirs).expect("B lets go");
        release(A, cap).expect("A lets go");
        assert_eq!(azos_mm::shim_pages_in_use(), in_use - 4);
        assert_eq!(azos_sched::shim_charged(A), 1, "the charge went back twice");
        assert_eq!(memobj_info(LAYOUT.idx(r)), None, "the object is gone");
        release(A, keep).expect("A lets go of the other one");
        assert_eq!(azos_sched::shim_charged(A), 0);
    }

    /// **What reclaim never takes.** An object in use; one a kernel reference
    /// pins (its frames' direct-map addresses are in use); one a clone shares
    /// frames with; one a failed map pinned; one whose Domain is on a
    /// `mem = "locked"` row (real-time memory). Each is taken the moment the
    /// reason goes, which shows the object was volatile all along.
    ///
    /// **Canaries** (`--features`, by hand 2026-10-20; each must fail this
    /// test): `memobj-purge-held-canary` (the in-use object is taken),
    /// `memobj-purge-kernel-held-canary` (the pinned one), and
    /// `memobj-purge-locked-canary` (the locked Domain's).
    #[test]
    fn reclaim_never_takes_an_object_in_use_pinned_shared_or_locked() {
        let _g = setup();
        let _h = Hooks::install();

        // In use.
        let (cap, r) = create_volatile(A, 1);
        assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 0, "an object in use was purged");

        // The kernel holds it.
        assert_eq!(memobj_set_volatile_ref(A, r, true), Ok(false));
        let mut out = [0usize; 2];
        assert_eq!(memobj_frames_pin(r, &mut out), Ok(1));
        assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 0, "an object the kernel pinned was purged");
        memobj_frames_unpin(r);

        // A clone shares its frames.
        let copy = memobj_clone_cap(A, cap, MemPerms::ReadWrite, 0).expect("clone");
        assert_ne!(memobj_describe_ref(r).unwrap().cow_shared, 0, "precondition: the frames are shared");
        assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 0, "an object a clone shares was purged");
        release(A, copy).expect("the clone goes");
        let _ = memobj_describe_ref(r);
        // (`cow_shared` clears when the sharer is gone and the object is next written or protected.)
        {
            let mut regions = MEMOBJS.lock_irqsave();
            let i = live_index(&regions, r).unwrap();
            reclaim_sole_frames(&mut regions[i]);
        }

        // A pinned holder.
        assert_eq!(memobj_pin_ref(A, r), Ok(true));
        assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 0, "an object with a pinned holder was purged");
        {
            let mut regions = MEMOBJS.lock_irqsave();
            let i = live_index(&regions, r).unwrap();
            for h in regions[i].holders.iter_mut() {
                h.pinned = false;
            }
        }

        // A real-time Domain's.
        assert_eq!(memobj_purge_volatile(8, a_is_locked), 0, "a mem=locked Domain's object was purged");
        assert_eq!(azos_sched::shim_charged(A), 1);

        // And now nothing stands in the way.
        assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 1);
        assert_eq!(azos_sched::shim_charged(A), 0);
    }

    /// **A mapping being built keeps a volatile object whole.** The mapper reads
    /// the frames' addresses and installs leaves before it books the mapping, so
    /// a purge in between would free the frames under them: the kernel's pin
    /// stops the purge, and a purged object cannot be pinned at all. An object
    /// that is not volatile needs no pin.
    ///
    /// **Canary (by hand, 2026-10-20).** `memobj_pin_for_map` answering `Ok(false)`
    /// for a volatile object: the purge assertion red.
    #[test]
    fn a_mapping_in_flight_keeps_a_volatile_object_from_being_purged() {
        let _g = setup();
        let (_plain, rp) = create(A);
        assert_eq!(memobj_pin_for_map(rp), Ok(false), "nothing to give back for an object that is not volatile");

        let (_cap, r) = create_volatile(A, 2);
        assert_eq!(memobj_set_volatile_ref(A, r, true), Ok(false));
        assert_eq!(memobj_pin_for_map(r), Ok(true));
        assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 0, "purged under a mapping being built");
        memobj_frames_unpin(r);
        assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 2);
        assert_eq!(memobj_pin_for_map(r), Err(MemObjError::Purged));
        assert_eq!(memobj_pin_for_map(0), Err(STALE), "a name that is no object");
    }

    /// **The page cache's clean drop writes the same record.** `what` 1, the
    /// whole machine as subject, the bytes dropped; nothing for a pass that
    /// dropped nothing.
    ///
    /// **Canary (by hand, 2026-10-20).** Removing `record_purge` from
    /// `memobj_paged_drop_clean`: red.
    #[test]
    fn dropping_clean_cache_pages_writes_a_purge_record() {
        let _g = setup();
        let page = azos_arch::PAGE_SIZE;
        let (_f, r, _) = window();
        let mut b = [0u8; 1];
        for i in 0..2 {
            memobj_paged_read_ref(r, i * page, &mut b).unwrap();
        }
        let base = azos_decision::total();
        assert_eq!(memobj_paged_drop_clean(8), 2);
        assert_eq!(memobj_paged_drop_clean(8), 0);
        if azos_decision::ON {
            assert_eq!(purge_records_since(base), vec![(0, [1, (2 * page) as u64, 0])]);
        }
        assert_eq!(memobj_paged_close_ref(r), Ok(()));
    }
}

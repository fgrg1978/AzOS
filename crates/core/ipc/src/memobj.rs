// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! MemObj: the one kernel object for memory that is named, charged,
//! transferred or shared (owner decision D4/L6).
//!
//! It absorbed `shm.rs` (the region table), `stream_ring`'s and the tracer's
//! private regions, and the demand reservation of the old allocation call; the lease table
//! keeps the lease protocol and holds memory only through the operations here.
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
//! | [`MemKind::Paged`]  | reserved (file-backed); refused at create | - | -             |
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
//! # Attributes
//!
//! [`ATTR_SWAPPABLE`] (the reclaimer may take the frames; stored, nothing
//! reads it until the reclaimer exists), [`ATTR_NO_KERNEL_MAP`] (the kernel
//! never reads the object through the direct map: `memobj_with_word_ref`
//! refuses it), [`ATTR_VOLATILE`] (purgeable; reserved, create refuses it).
//!
//! # Operations
//!
//! * create: [`memobj_create_spec`] (ring 3: Anon only), [`memobj_create_kernel`]
//!   (Contig);
//! * map and unmap: the mapping a task made is recorded per holder
//!   ([`MemHolder::map_va`]); the access it was allowed is recorded with it, so
//!   a map never gives more than the capability had ([`memobj_resolve_map`]);
//! * protect: [`memobj_protect_ref`] changes the access of a recorded
//!   mapping within what the map was allowed (`SYS_MO_MAP`'s second argument);
//! * clone: [`memobj_clone`] (COW: frames shared through the frame refcount until
//!   a write mapping or [`memobj_cow_break`] gives the clone its own);
//! * MOVE: [`memobj_move`] hands a task's references, its charge (when it holds
//!   the owning reference) and its ownership to another task and drops the
//!   sender's mapping; the capability travels by the IPC transfer's MOVE entry;
//! * SHARE: the IPC transfer's DUP entry derives an attenuated warrant
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
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use azos_sync::SpinLock;

use crate::cap::objref;
use crate::cap::{CapError, CapType};

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
/// at the same time.
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
    /// File-backed pages supplied by a pager. Reserved: create refuses it.
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

/// The frames may be taken by the reclaimer. Stored; nothing reads it yet.
pub const ATTR_SWAPPABLE: u8 = 1 << 0;
/// The kernel never reads the object through the direct map.
pub const ATTR_NO_KERNEL_MAP: u8 = 1 << 1;
/// Purgeable. Reserved: create refuses it until a purger exists.
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
/// **WHY this exists (W3-F1):** `ref_count` alone is a bare integer that any
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
    /// Sealed grants of a lease that hold this mapping read-only
    /// ([`seal_range`]); the write comes back with the last of them.
    pub map_seals: u8,
    /// The mapping at `map_va` is writable now.
    pub map_write: bool,
    /// The most the mapping may be made writable again: the access the
    /// capability allowed when the map was made (`WRITE` on a writable
    /// object). [`memobj_protect_mapping`] never goes past it.
    pub map_max_write: bool,
}

impl MemHolder {
    pub const fn empty() -> Self {
        Self { tid: 0, refs: 0, map_va: 0, map_pages: 0, pinned: false, map_root: 0, map_seals: 0, map_write: false, map_max_write: false }
    }
}

/// A shared memory region.
pub struct MemObj {
    /// Physical addresses of allocated pages (0 = unused slot in page array).
    pub phys_pages: [usize; MAX_MEMOBJ_PAGES],
    /// Number of pages allocated.
    pub page_count: usize,
    /// Reference count — how many processes have this mapped.
    ///
    /// Invariant: equals the sum of `holders[i].refs`. Kept as a separate
    /// field only because `memobj_info` exposes it; the holder table is the
    /// authority.
    pub ref_count: AtomicU32,
    /// Task that created this region. Read by [`memobj_owner`]; the untyped
    /// `SYS_IPC_MAP` gated on it until RFC-0040 gap 1 retired that call.
    pub owner_task: u32,
    /// Permissions.
    pub perms: MemPerms,
    /// Whether this slot is active.
    pub active: bool,
    /// Generation of the region in this slot (RFC-0040 gap 1): stamped by
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
    /// RFC-0049 M1, now the holder's Domain and no longer the creating task's
    /// budget: the last reference gives the charge back to this Domain from
    /// whichever task drops it, and a MOVE of the owning reference changes it.
    pub charge_key: u32,
    /// Pages whose frame another object shares (a COW clone): bit `i` is page
    /// `i`. Cleared per page by [`memobj_cow_break`]; a mapping for write
    /// breaks every set bit first.
    pub cow_shared: u64,
}

impl MemObj {
    pub const fn empty() -> Self {
        const EMPTY_HOLDER: MemHolder = MemHolder::empty();
        Self {
            phys_pages: [0; MAX_MEMOBJ_PAGES],
            page_count: 0,
            ref_count: AtomicU32::new(0),
            owner_task: 0,
            perms: MemPerms::ReadOnly,
            active: false,
            generation: 0,
            holders: [EMPTY_HOLDER; MAX_MEMOBJ_HOLDERS],
            kind: MemKind::Anon,
            attrs: 0,
            device_visible: false,
            charge_key: 0,
            cow_shared: 0,
        }
    }
}

const _: () = assert!(MAX_MEMOBJ_PAGES <= 64, "MemObj::cow_shared is one bit per page");

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global shm region table.
///
/// Protected by a single `SpinLock` covering the whole table (same shape as
/// `port.rs`'s `PORTS` / `lease.rs`'s `LEASES`). Was previously a bare
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

/// The region table plus its per-slot generation sources (RFC-0040 gap 1,
/// revised, owner decision 2026-09-26), under the same lock. `Deref`/
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
/// Called with a table lock held (`LEASES`, or the MemObj table by a MOVE; never
/// from an interrupt), so it must not block and must take no lock that is held
/// while either is being taken. The kernel registers
/// `vmm::unmap_user_range_and_free(root, va, end, va, end)` (the skip range is
/// the whole range, so nothing is freed and `page_decref` is never reached).
pub type UnmapHook = fn(root: usize, va: usize, pages: usize);

static UNMAP_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Register the [`UnmapHook`]. Boot, once. Without it a revoke records the
/// window but removes no PTE (the host suite's default).
pub fn set_unmap_hook(f: UnmapHook) {
    UNMAP_HOOK.store(f as usize, Ordering::Release);
}

/// Forget the registered page-table hooks: host-test hygiene, they are
/// process-wide.
pub fn __clear_hooks_for_tests() {
    UNMAP_HOOK.store(0, Ordering::Release);
    PROTECT_HOOK.store(0, Ordering::Release);
}

pub(crate) fn unmap_range(root: usize, va: usize, pages: usize) {
    let raw = UNMAP_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only `set_unmap_hook` stores here, and it stores an `UnmapHook`.
        let f: UnmapHook = unsafe { core::mem::transmute::<usize, UnmapHook>(raw) };
        f(root, va, pages);
    }
}

/// Set (`write == false`) or give back (`write == true`) the write permission
/// of the user leaves in `pages` pages at `va` of the page table rooted at
/// `root`, then shoot the range down on every hart that may hold it. Returns
/// how many leaves changed. Called under the same rules as [`UnmapHook`]. The kernel registers
/// `vmm::set_user_range_write` plus the shootdown.
pub type ProtectHook = fn(root: usize, va: usize, pages: usize, write: bool) -> usize;

static PROTECT_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Register the [`ProtectHook`]. Boot, once. Without it a sealed grant or a protect records
/// the change but changes no PTE (the host suite's default).
pub fn set_protect_hook(f: ProtectHook) {
    PROTECT_HOOK.store(f as usize, Ordering::Release);
}

pub(crate) fn protect_range(root: usize, va: usize, pages: usize, write: bool) -> usize {
    let raw = PROTECT_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        // No PTE to change: report the whole range, so the record (and a
        // host test of it) is exercised as the kernel's would be.
        return pages;
    }
    // SAFETY: only `set_protect_hook` stores here, and it stores a `ProtectHook`.
    let f: ProtectHook = unsafe { core::mem::transmute::<usize, ProtectHook>(raw) };
    f(root, va, pages, write)
}

/// Seal (`on`) or unseal a lessor's mapping for a lease (`lease.rs`): the
/// mapping at `(root, va, pages)` becomes read-only, and protect cannot make
/// it writable until the last seal on it is lifted, when it gets back the
/// access its task had set. Answers how many leaves changed (0 when nothing
/// was sealed or restored). Called with `LEASES` held, the page-table-lifetime
/// invariant of `lease.rs` covering the root.
pub(crate) fn seal_range(root: usize, va: usize, pages: usize, on: bool) -> usize {
    let mut regions = MEMOBJS.lock_irqsave();
    for region in regions.regions.iter_mut().filter(|r| r.active) {
        let Some(h) = region
            .holders
            .iter_mut()
            .find(|h| h.refs > 0 && h.map_va == va && h.map_root == root && h.map_pages == pages)
        else {
            continue;
        };
        if on {
            h.map_seals = h.map_seals.saturating_add(1);
            return protect_range(root, va, pages, false);
        }
        h.map_seals = h.map_seals.saturating_sub(1);
        return if h.map_seals == 0 { protect_range(root, va, pages, h.map_write) } else { 0 };
    }
    // No record names this mapping (a seal taken for a mapping the table does
    // not know): the page table is all there is to change.
    protect_range(root, va, pages, !on)
}


// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Most MemObjs ONE task may own at once.
///
/// **The obligation the minting rule creates.** RFC-0003's addendum states it
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
/// the owner's Domain. Anon and Contig only. `BadArg` for a Paged spec, an unknown attribute, the reserved
/// [`ATTR_VOLATILE`], or a page count of 0 or over [`MAX_MEMOBJ_PAGES`];
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

/// The create body. Returns the new region's packed `(index, generation)`
/// reference.
///
/// **Per-slot generation, swept only at its own index (RFC-0040 gap 1,
/// revised, owner decision 2026-09-26).** Each slot's generation is its own
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
    // Reserved and unknown attributes are refused whatever the kind.
    if spec.attrs & !ATTRS_KNOWN != 0 || spec.attrs & ATTR_VOLATILE != 0 {
        return Err(MemObjError::BadArg);
    }
    if !has_room(&MEMOBJS.lock_irqsave(), owner_task) {
        return Err(MemObjError::NoMem);
    }

    let page = azos_arch::PAGE_SIZE;
    let mut pages = [0usize; MAX_MEMOBJ_PAGES];
    // RFC-0049 M1, now the owner's Domain: the frames count against it,
    // charged before one is taken.
    let key = charge_key_of(owner_task);
    if key != 0 && !azos_sched::mm_charge_domain(key, page_count as u32) {
        return Err(MemObjError::NoMem);
    }
    let uncharge = || if key != 0 { azos_sched::mm_discharge_domain(key, page_count as u32) };

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
/// direct map as one span (wave 11, SHMRING: `crate::stream_ring`; the
/// tracer). `spec` must be Contig: the frames are one physically contiguous
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
    claim_slot_cow(owner_task, pages, spec, charge_key, 0)
}

/// [`claim_slot`] for pages whose frames another object shares: bit `i` of
/// `cow_shared` is page `i`.
fn claim_slot_cow(owner_task: u32, pages: &[usize], spec: &MemSpec, charge_key: u32, cow_shared: u64) -> Option<u32> {
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
        region.ref_count.store(1, Ordering::Release);
        region.owner_task = owner_task;
        region.perms = spec.perms;
        region.kind = spec.kind;
        region.attrs = spec.attrs;
        region.device_visible = spec.device_visible;
        region.charge_key = charge_key;
        region.cow_shared = cow_shared;
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
/// active: for a caller holding a validated index that needs the value a
/// `Cap<Shm>` stores.
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
    region.ref_count.fetch_add(1, Ordering::AcqRel);
    Some((region.page_count, region.perms))
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
/// `(va, pages)`, without clearing it (wave 11, LEASE3: the lessor's mapping a
/// sealed grant makes read-only).
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
            h.map_va = 0;
            h.map_pages = 0;
            h.map_root = 0;
            h.map_seals = 0;
            h.map_write = false;
            h.map_max_write = false;
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
/// `READ` on a `Cap<Shm>`, so resolving through it asks the same authority
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
                let phys = region.phys_pages[pg] + off % page;
                return Some((LAYOUT.pack(i as u32, region.generation), off, phys));
            }
        }
    }
    None
}

/// Does any holder of the region a packed reference names have it mapped
/// now? `false` for a stale reference. For a kernel producer deciding whether
/// a frame is worth making (`crate::stream_ring`).
pub fn memobj_is_mapped_by_any_ref(r: u32) -> bool {
    let regions = MEMOBJS.lock_irqsave();
    match live_index(&regions, r) {
        Ok(i) => regions[i].holders.iter().any(|h| h.refs != 0 && h.map_va != 0),
        Err(_) => false,
    }
}

/// The physical address of page `page_idx` of the region a packed reference
/// names: `Ok(None)` past the region's last page.
pub fn memobj_page_phys_ref(r: u32, page_idx: usize) -> Result<Option<usize>, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &regions[i];
    Ok(if page_idx < region.page_count { Some(region.phys_pages[page_idx]) } else { None })
}

/// [`memobj_page_phys_ref`] for the KERNEL's own access to the page through
/// the direct map (a robust-list sweep, a doorbell word): `Ok(None)` past the
/// object and for an object with [`ATTR_NO_KERNEL_MAP`], whose frames only a
/// user mapping may reach.
pub fn memobj_kernel_page_phys_ref(r: u32, page_idx: usize) -> Result<Option<usize>, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &regions[i];
    Ok(if page_idx < region.page_count && region.attrs & ATTR_NO_KERNEL_MAP == 0 {
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
    let va = azos_mm::addr::phys_to_virt(region.phys_pages[page]) + offset % page_size;
    // SAFETY: a 4-aligned word inside a live page of the region, which cannot
    // be freed while this guard is held (see the doc).
    let word = unsafe { &*(va as *const AtomicU32) };
    let out = f(word);
    drop(regions);
    Ok(Some(out))
}

/// Is the region table's lock free right now? For the F5 test of
/// [`memobj_with_word_ref`] only: called from inside its closure, `false` proves
/// the table was locked across the load.
pub fn __memobj_table_unlocked_for_tests() -> bool {
    MEMOBJS.try_lock().is_some()
}

/// The index of the region a packed reference names, or `Stale`: the inverse
/// of [`memobj_ref`]. For `MEMOBJ_LEASE_GRANT`, which resolves a
/// `Cap<Shm>` and hands the lease table the region index it records.
pub fn memobj_index_ref(r: u32) -> Result<u32, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    live_index(&regions, r).map(|i| i as u32)
}

/// The access mode of the region a packed reference names, or `Stale`. For
/// `SYS_MO_MAP`, which needs `WRITE` only for a writable region.
pub fn memobj_perms_ref(r: u32) -> Result<MemPerms, MemObjError> {
    let regions = MEMOBJS.lock_irqsave();
    let i = live_index(&regions, r)?;
    Ok(regions[i].perms)
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

/// Take `n` references off holder `idx` and off the region's count, with the
/// table lock held and `n` no more than the holder's `refs`. At the region's
/// last reference its frames go back to the PMM and the slot is cleared.
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

    let prev = region.ref_count.load(Ordering::Acquire);
    let now = prev.saturating_sub(n);
    region.ref_count.store(now, Ordering::Release);
    if now == 0 {
        // Last reference — and, by the callers' refusal of a holder with a
        // recorded mapping, no holder can still have one, so freeing the
        // frames is safe. `empty()` clears the generation, so every capability
        // naming this region is stale from here on, whichever table holds it.
        // A frame a clone still shares (`cow_shared`) goes back only when the
        // last sharer lets go of it.
        for i in 0..region.page_count {
            let p = region.phys_pages[i];
            if p == 0 {
                continue;
            }
            let shared = region.cow_shared & (1u64 << i) != 0;
            if !shared || azos_mm::cow::page_decref(p) {
                let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(p));
            }
        }
        // Given back to the Domain that holds the charge, from whichever task
        // drops the last reference (the budget is atomic).
        if region.charge_key != 0 {
            azos_sched::mm_discharge_domain(region.charge_key, region.page_count as u32);
        }
        *region = MemObj::empty();
    }
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
/// old root is freed, as `lease_exec` does.
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

/// Get info about a shared memory region: (page_count, ref_count, perms).
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
        region.ref_count.load(Ordering::Acquire),
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

/// Resolve `cap` in `table` for a map: `READ` is required; `WRITE` decides the
/// writable bit of a read-write object. A refusal other than the missing
/// `WRITE` (a stale or revoked capability, containment) is the map's.
pub fn memobj_resolve_map(
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
) -> Result<MapGrant, MemObjError> {
    let r = table.get(cap, crate::cap::CapPerms::READ)?;
    let desc = memobj_describe_ref(r)?;
    let writable = if desc.perms == MemPerms::ReadWrite {
        match table.get(cap, crate::cap::CapPerms::WRITE) {
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
/// and while a lease's seal holds the mapping read-only, and (`Busy`) while the
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
    // A lessor's sealed mapping stays read-only until the lease ends.
    if write && h.map_seals != 0 {
        return Err(MemObjError::Cap(CapError::MissingPerms));
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
    if !has_room(&MEMOBJS.lock_irqsave(), owner_task) {
        return Err(MemObjError::NoMem);
    }
    let n = d.page_count;
    let key = charge_key_of(owner_task);
    if key != 0 && !azos_sched::mm_charge_domain(key, n as u32) {
        return Err(MemObjError::NoMem);
    }
    let uncharge = || if key != 0 { azos_sched::mm_discharge_domain(key, n as u32) };

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
        claim_slot_cow(owner_task, &pages[..n], &spec, key, mask).ok_or(MemObjError::NoMem).inspect_err(|_| {
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
    if sender.pinned {
        regions[i].holders[fi].refs = 1;
    } else {
        regions[i].holders[fi] = MemHolder::empty();
    }
    Ok(Moved { mapping, transferred: true })
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
/// reservation, so a first touch can never be refused for budget (RFC-0049
/// M1, as Linux's strict overcommit). All or nothing: a refusal leaves no
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
// Cap<Shm> typed wrappers (RFC-0003 W5 batch 2)
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
}

impl From<crate::cap::CapError> for MemObjError {
    fn from(e: crate::cap::CapError) -> Self {
        Self::Cap(e)
    }
}

/// Derive `CapPerms` for a freshly-minted Shm cap from the region's
/// own access mode. ReadOnly → READ; ReadWrite → RW. Callers that
/// want a more restricted grant (e.g. duplicating read-only into a
/// child) can `revoke` + `grant` with a tighter mask afterwards.
fn cap_perms_for(perms: MemPerms) -> crate::cap::CapPerms {
    match perms {
        MemPerms::ReadOnly => crate::cap::CapPerms::READ,
        MemPerms::ReadWrite => crate::cap::CapPerms::RW,
    }
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
    let perms = spec.perms;
    // The capability stores the packed `(index, generation)`. `DUP` (owner
    // decision 2026-09-26, O3.4): the creator may gift its own region.
    match objref::grant_packed::<crate::cap::targets::Shm>(
        tid,
        cap_perms_for(perms).union(crate::cap::CapPerms::DUP),
        r,
    ) {
        Some(cap) => Ok(cap),
        None => {
            // Roll back the region so we don't leak it on cap-table
            // exhaustion. `memobj_create` booked ref_count=1 against `tid`, so a
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
    match objref::grant_packed::<crate::cap::targets::Shm>(
        tid,
        cap_perms_for(perms).union(crate::cap::CapPerms::DUP),
        nr,
    ) {
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
/// table lock the acquire takes (RFC-0040 gap 1): a capability to a freed or
/// reused region answers `Stale`.
pub fn memobj_acquire_cap(
    tid: u32,
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
) -> Result<(usize, MemPerms), MemObjError> {
    let r = table.get(cap, crate::cap::CapPerms::READ)?;
    memobj_acquire_ref(tid, r)
}

/// Typed release: validates the cap (requires `READ`, since release is
/// paired with acquire and any holder may give back its own references),
/// gives back **every** reference `tid` holds on the region except a pinned
/// one ([`memobj_release_holder_ref`]), **and revokes the cap**. Refused
/// (`Closed`) while `tid` still has a mapping recorded; the cap is revoked on
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
/// The untyped `SYS_IPC_UNSHARE` it paired with was retired in RFC-0040 gap 1;
/// `SYS_MO_UNMAP` removes the caller's mapping before it calls this.
pub fn memobj_release_cap(
    tid: u32,
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
) -> Result<(), MemObjError> {
    let r = table.get(cap, crate::cap::CapPerms::READ)?;
    let released = memobj_release_holder_ref(tid, r);
    table.revoke(cap);
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
}

/// Fast-forward slot `i`'s own generation source, so a host test reaches its
/// wrap without `LAYOUT.gen_max()` create/release cycles at that index.
#[cfg(test)]
pub fn __memobj_set_next_gen_for_tests(i: usize, next_gen: u32) {
    MEMOBJS.lock_irqsave().next_gen[i] = next_gen;
}

/// The generation stamped in slot `shm_id` (host tests).
#[cfg(test)]
pub fn __memobj_generation_for_tests(shm_id: u32) -> u32 {
    MEMOBJS.lock_irqsave()[shm_id as usize].generation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::targets::{IoRing, Shm};
    use crate::cap::{Cap, CapPerms};
    use crate::cap_store;

    // `tests/host/ipc-lease-tests`' scheduler shim maps a TID below `MAX_TASKS` to
    // the task-pool slot of the same number.
    const A: u32 = 21;
    const B: u32 = 22;
    const C: u32 = 23;
    const STALE: MemObjError = MemObjError::Cap(CapError::Stale);

    /// The crate-wide serial lock (the page shim is shared with the io_ring
    /// and lease suites), an empty region table and three empty cap tables.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        __memobj_reset_for_tests();
        for tid in [A, B, C] {
            cap_store::reset(tid);
        }
        g
    }

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
        cap_store::with_table(tid, |t| memobj_acquire_cap(tid, t, cap))
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

    /// **The notify word is the word the mapping shows (wave 11 fix).** For
    /// every 4-aligned offset of a multi-page region, at the start, middle and
    /// end of each page: a word written through the frame `memobj_resolve_mapped`
    /// names for the mapped address is the word `memobj_with_word_ref` reads at
    /// that region offset, and the first offset past the region is `None`.
    /// Both split the offset with the build's granule.
    ///
    /// At the default 4 KiB host page the old fixed 4096 agreed by accident;
    /// [`no_fixed_page_size_in_the_offset_split`] is the half that is red on
    /// the old code there. At 16 KiB (`tests/host/ipc-lease-tests`, `cargo
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

    // ── RFC-0049 M0: one zero per page, none with interrupts off ──────────
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

    /// RFC-0049 M1: a region's frames count against its OWNER's Domain from
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
            Hooks
        }
    }
    impl Drop for Hooks {
        fn drop(&mut self) {
            __clear_hooks_for_tests();
            cap_store::__clear_move_hook_for_tests();
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
    /// frames in order. Paged and the reserved
    /// volatile attribute are refused. `ATTR_NO_KERNEL_MAP` hides the object from
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
        let vol = MemSpec::anon(MemPerms::ReadOnly).with_attrs(ATTR_VOLATILE);
        assert_eq!(memobj_create_spec(A, 1, &vol), Err(MemObjError::BadArg), "volatile is reserved");
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
        let ro_b = transfer(A, B, cap_a, true, Some(CapPerms::READ)).expect("share READ");
        let grant = cap_store::with_table(B, |t| memobj_resolve_map(t, ro_b)).unwrap().expect("resolves");
        assert!(!grant.writable, "a READ share maps writable");
        assert_eq!(grant.desc.perms, MemPerms::ReadWrite, "the object is still writable for its owner");
        // The owner's own capability maps writable.
        let own = cap_store::with_table(A, |t| memobj_resolve_map(t, cap_a)).unwrap().expect("resolves");
        assert!(own.writable);
        // The share cannot be raised: asking the sender's copy for more is refused,
        // and the receiver's copy cannot hand on what it lacks.
        assert!(transfer(A, C, cap_a, true, Some(CapPerms::RW)).is_ok(), "equal rights are fine");
        let again = transfer(B, C, ro_b, true, Some(CapPerms::WRITE));
        assert!(again.is_err(), "a share cannot raise rights");
        assert_eq!(azos_sched::shim_charged(A), 2, "the object is charged once, to its holder");
        assert_eq!(azos_sched::shim_charged(B), 0);
        assert!(cap_store::get(A, cap_a, CapPerms::READ).is_ok(), "the sender keeps its capability");
        // Revoking the sender's capability takes the share with it (the warrant tree).
        cap_store::revoke(A, cap_a);
        assert!(cap_store::get(B, ro_b, CapPerms::READ).is_err(), "the share is a child of the sender's warrant");
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

    /// A lessor's sealed mapping cannot be made writable by a protect while a
    /// seal holds it, and gets back what its task had set when the last seal
    /// lifts; two overlapping seals lift one at a time.
    ///
    /// **Canary (by hand):** drop the `map_seals` refusal in `memobj_protect_ref`
    /// and the write-after-seal check fails.
    #[test]
    fn a_seal_holds_the_mapping_read_only_against_a_protect() {
        let _g = setup();
        let _h = Hooks::install();
        azos_sched::shim_set_current(A, 0x1000);
        let cap = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).unwrap();
        let r = cap_store::get(A, cap, CapPerms::READ).unwrap();
        assert_eq!(memobj_note_mapping_ref(A, r, ROOT_A, VA, 1, MapAccess::RW), Ok(true));
        assert_eq!(seal_range(ROOT_A, VA, 1, true), 1);
        assert_eq!(seal_range(ROOT_A, VA, 1, true), 1, "a second sealed lease on the same mapping");
        assert_eq!(
            memobj_protect_ref(A, r, true),
            Err(MemObjError::Cap(CapError::MissingPerms)),
            "a protect widened a sealed mapping"
        );
        assert_eq!(seal_range(ROOT_A, VA, 1, false), 0, "one seal still holds it");
        assert_eq!(memobj_protect_ref(A, r, true), Err(MemObjError::Cap(CapError::MissingPerms)));
        assert_eq!(seal_range(ROOT_A, VA, 1, false), 1, "the last seal gives the write back");
        assert_eq!(PROTECTS.lock().unwrap().last(), Some(&(ROOT_A, VA, 1, true)));
        assert_eq!(memobj_protect_ref(A, r, true), Ok(()));
        // What the task had set before the seal is what comes back.
        assert_eq!(memobj_protect_ref(A, r, false), Ok(()));
        assert_eq!(seal_range(ROOT_A, VA, 1, true), 1);
        assert_eq!(seal_range(ROOT_A, VA, 1, false), 1);
        assert_eq!(PROTECTS.lock().unwrap().last(), Some(&(ROOT_A, VA, 1, false)), "back to read-only, as the task left it");
    }
}

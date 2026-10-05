// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Shared Memory regions (F00.4).
//!
//! Allows two or more processes to map the same physical pages into their
//! address spaces for zero-copy data sharing (e.g., camera frames, LiDAR scans).

use core::sync::atomic::{AtomicU32, Ordering};
use azos_sync::SpinLock;

use crate::cap::objref;
use crate::cap::{CapError, CapKind};

/// How a `Cap<Shm>` packs `(index, generation)`: 8 + 24 bits (`objref::SHM`).
const LAYOUT: objref::Layout = objref::SHM;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of shared memory regions system-wide.
pub const MAX_SHM_REGIONS: usize = 16;

/// Maximum pages per shared memory region (64 pages = 256 KiB).
pub const MAX_SHM_PAGES: usize = 64;

/// Maximum number of distinct tasks that may hold a reference to one region
/// at the same time.
///
/// WHY a bound exists at all: references are now tracked *per task*
/// (see [`ShmHolder`]), which needs somewhere to put the per-task counter.
/// A fixed array keeps the whole table in BSS with no allocator on the IPC
/// path. Eight simultaneous sharers per region is well beyond anything the
/// robot's pipelines do (producer + a handful of consumers); exhausting it
/// fails the *acquire*, it never corrupts accounting.
pub const MAX_SHM_HOLDERS: usize = 8;

/// A `Cap<Shm>` stores a packed `(index, generation)` with `LAYOUT.idx_bits()`
/// of index, so every region index must fit them.
const _: () = assert!(MAX_SHM_REGIONS <= 1 << LAYOUT.idx_bits());

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Permission flags for a shared memory region.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ShmPerms {
    ReadOnly,
    ReadWrite,
}

/// Per-task reference accounting for one region.
///
/// **WHY this exists (W3-F1):** `ref_count` alone is a bare integer that any
/// caller could decrement. `SYS_IPC_UNSHARE` took a raw userspace `shm_id`
/// and called `shm_release` unconditionally, so a task could drop references
/// it never took — sixteen guesses were enough to drive any live region's
/// count to zero, which frees every `phys_pages[i]` back to the PMM while the
/// real holders' `USER_RW` PTEs stay valid. Recording *who* took each
/// reference makes a release only able to give back what the caller actually
/// holds.
#[derive(Clone, Copy)]
pub struct ShmHolder {
    /// TID of the holding task. Meaningful only when `refs > 0`.
    pub tid: u32,
    /// References this task currently holds (create counts as one, each
    /// successful `shm_acquire_ref` counts as one). `0` ⇒ free holder slot.
    ///
    /// A task names all of them through one `Cap<Shm>`, and the typed release
    /// revokes that capability, so it gives every one of them back at once
    /// ([`shm_release_holder_ref`]); only a [`pinned`](Self::pinned) reference
    /// waits for the task's exit.
    pub refs: u32,
    /// User virtual base address this task mapped the region at via
    /// `shm_map_user`, or `0` if it has no live mapping.
    ///
    /// **WHY the VA is recorded:** the pages must never go back to the PMM
    /// while a user page table still points at them. Keeping the VA is what
    /// lets the release path tear the mapping down *before* the refcount can
    /// reach zero — see [`shm_take_mapping`].
    pub map_va: usize,
    /// Number of pages mapped at `map_va` (0 when `map_va == 0`).
    pub map_pages: usize,
    /// This task may have PTEs into the region that `map_va` does not name:
    /// a `SYS_SHM_MAP_TYPED` failed after its reference was taken, and
    /// `shm_map_user` returns `None` from a partial mapping. Set by
    /// [`shm_pin_ref`]. While set, the typed release keeps one reference, so no
    /// frame returns to the PMM under those PTEs; the task's exit
    /// (`shm_release_all`) gives it back, when its address space is gone.
    pub pinned: bool,
}

impl ShmHolder {
    pub const fn empty() -> Self {
        Self { tid: 0, refs: 0, map_va: 0, map_pages: 0, pinned: false }
    }
}

/// A shared memory region.
pub struct ShmRegion {
    /// Physical addresses of allocated pages (0 = unused slot in page array).
    pub phys_pages: [usize; MAX_SHM_PAGES],
    /// Number of pages allocated.
    pub page_count: usize,
    /// Reference count — how many processes have this mapped.
    ///
    /// Invariant: equals the sum of `holders[i].refs`. Kept as a separate
    /// field only because `shm_info` exposes it; the holder table is the
    /// authority.
    pub ref_count: AtomicU32,
    /// Task that created this region. Read by [`shm_owner`]; the untyped
    /// `SYS_IPC_MAP` gated on it until RFC-0040 gap 1 retired that call.
    pub owner_task: u32,
    /// Permissions.
    pub perms: ShmPerms,
    /// Whether this slot is active.
    pub active: bool,
    /// Generation of the region in this slot (RFC-0040 gap 1): stamped by
    /// `shm_create`, 0 while the slot is free.
    ///
    /// A `Cap<Shm>` stores `(slot, generation)` and resolves only while both
    /// match, so a capability to a freed region never reaches the next region
    /// created at its index, in any task's table. Cleared with the slot, which
    /// `ShmRegion::empty()` does at the last reference and at the OOM rollback
    /// — never at a holder's decrement, which leaves the region live for its
    /// other holders.
    pub generation: u32,
    /// Per-task reference accounting. See [`ShmHolder`].
    pub holders: [ShmHolder; MAX_SHM_HOLDERS],
    /// RFC-0049 M1: the frames were charged to `owner_task`'s budget at
    /// create (the creator was the calling task), so freeing them gives the
    /// charge back to it (`mm_discharge_tid`), from whichever task drops the
    /// last reference.
    pub charged: bool,
}

impl ShmRegion {
    pub const fn empty() -> Self {
        const EMPTY_HOLDER: ShmHolder = ShmHolder::empty();
        Self {
            phys_pages: [0; MAX_SHM_PAGES],
            page_count: 0,
            ref_count: AtomicU32::new(0),
            owner_task: 0,
            perms: ShmPerms::ReadOnly,
            active: false,
            generation: 0,
            holders: [EMPTY_HOLDER; MAX_SHM_HOLDERS],
            charged: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global shm region table.
///
/// Protected by a single `SpinLock` covering the whole table (same shape as
/// `port.rs`'s `PORTS` / `lease.rs`'s `LEASES`). Was previously a bare
/// `static mut` with every accessor (`shm_create`/`shm_acquire`/
/// `shm_page_phys`/`shm_release`/`shm_info`) touching it under an `unsafe`
/// block with zero synchronization — reachable concurrently from any hart
/// via the syscall dispatch table, so e.g. two harts racing `shm_create`
/// could both find the same "free" slot and both write into it. Uses
/// `lock_irqsave()` (not plain `lock()`) for the same reason `PORTS` does:
/// keeping every accessor on the same IRQ-safe discipline is what makes it
/// safe to add an IRQ-context caller later without silently reopening a
/// same-hart deadlock.
const EMPTY_SHM: ShmRegion = ShmRegion::empty();

/// The region table plus its per-slot generation sources (RFC-0040 gap 1,
/// revised, owner decision 2026-09-26), under the same lock. `Deref`/
/// `DerefMut` to the region array so every existing `regions[i]` /
/// `regions.iter()` accessor below is unchanged; only `create_core` reads
/// `next_gen`.
struct ShmTable {
    regions: [ShmRegion; MAX_SHM_REGIONS],
    /// Entry `i` is the generation index `i`'s *next* create will stamp.
    /// Starts at 1 (`0` doubles as the mid-sweep marker), never reset by an
    /// ordinary release — only by that slot's own targeted wrap sweep. See
    /// `objref`'s module doc ("Per-slot generations...").
    next_gen: [u32; MAX_SHM_REGIONS],
}

impl core::ops::Deref for ShmTable {
    type Target = [ShmRegion; MAX_SHM_REGIONS];
    fn deref(&self) -> &Self::Target {
        &self.regions
    }
}

impl core::ops::DerefMut for ShmTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.regions
    }
}

static SHM_REGIONS: SpinLock<ShmTable> = SpinLock::new(ShmTable {
    regions: [EMPTY_SHM; MAX_SHM_REGIONS],
    next_gen: [1u32; MAX_SHM_REGIONS],
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a shared memory region with `page_count` pages.
/// Returns shm_id or None if no slots or OOM.
/// Most shared-memory regions ONE task may hold at once.
///
/// **The obligation the minting rule creates.** RFC-0003's addendum states it
/// plainly: a task may be handed a capability over an object it just created,
/// and *minting without a per-task quota is exhaustion*. `MAX_SHM_REGIONS` bounds
/// the pool for the WHOLE MACHINE, so before this a single ring-3 program
/// calling `shm_create` in a loop took every slot and denied shared-memory regions to
/// everyone — the kernel's own users included.
///
/// Half the pool, mirroring `MAX_SOCKETS_PER_TASK` and `MAX_FDS_PER_TASK`:
/// enough for a program doing ordinary work, never enough for one task to lock
/// the machine out.
pub const MAX_SHM_REGIONS_PER_TASK: usize = MAX_SHM_REGIONS / 2;

pub fn shm_create(owner_task: u32, page_count: usize, perms: ShmPerms) -> Option<u32> {
    create_core(owner_task, page_count, perms).map(|r| LAYOUT.idx(r))
}

/// [`shm_create`], answering the packed `(index, generation)` reference of the
/// new region: the value a `Cap<Shm>` stores (see `objref`).
pub fn shm_create_ref(owner_task: u32, page_count: usize, perms: ShmPerms) -> Option<u32> {
    create_core(owner_task, page_count, perms)
}

/// The create body. Returns the new region's packed `(index, generation)`
/// reference.
///
/// **Per-slot generation, swept only at its own index (RFC-0040 gap 1,
/// revised, owner decision 2026-09-26).** Each slot's generation is its own
/// (`ShmTable::next_gen`); when slot `i`'s reaches `LAYOUT.gen_max()`, this
/// marks it mid-sweep (`next_gen[i] = 0`, which the free-slot scan already
/// treats as unavailable), releases the table lock, runs
/// `objref::sweep_index(CapKind::Shm, i)` — which revokes only the stale
/// `Cap<Shm>`s left over at index `i`, nothing live — resets `next_gen[i]` to
/// `1`, and retries. At most two passes: the second always finds `Gen(1)`.
/// Must not be called with a cap-table lock held.
///
/// **Pages are allocated before the table lock is taken, and zeroed once.**
/// `pmm::alloc_page` hands back a zeroed page; that is the only zero, and it
/// is what keeps a new region from showing a previous owner's bytes. This
/// used to allocate inside `SHM_REGIONS.lock_irqsave()` and then `write_bytes`
/// every page a second time: up to 64 pages x two 4 KiB zeroes (~1,560
/// instructions each, scalar) with interrupts off on this hart. Now the
/// interrupts-off window holds no zeroing at all. The price is ordering: a
/// cheap quota/free-slot check runs under the lock first, so an ordinary
/// refusal costs no allocation; the authoritative check is repeated when the
/// slot is claimed, and a refusal there gives every page back.
fn create_core(owner_task: u32, page_count: usize, perms: ShmPerms) -> Option<u32> {
    if page_count == 0 || page_count > MAX_SHM_PAGES {
        return None;
    }
    if !has_room(&SHM_REGIONS.lock_irqsave(), owner_task) {
        return None;
    }

    // RFC-0049 M1: the frames count against the creator's budget, charged
    // before one is taken, when the creator is the calling task. A kernel
    // caller creating on a task's behalf is covered by the kernel reserve.
    let charged = azos_sched::current_task_tid() == owner_task;
    if charged && !azos_sched::mm_charge(page_count as u32) {
        return None;
    }
    let uncharge = || if charged { azos_sched::mm_discharge(page_count as u32) };

    let mut pages = [0usize; MAX_SHM_PAGES];
    for i in 0..page_count {
        match azos_mm::pmm::alloc_page() {
            Ok(page) => pages[i] = page.as_usize(),
            Err(_) => {
                // OOM: give back what this call already took.
                free_frames(&pages[..i]);
                uncharge();
                return None;
            }
        }
    }

    let r = claim_slot(owner_task, &pages[..page_count], perms, charged);
    if r.is_none() {
        // Refused at claim time (quota or table filled since the pre-check):
        // the pages were never published, so they go straight back.
        free_frames(&pages[..page_count]);
        uncharge();
    }
    r
}

/// The owner a kernel-created region is booked to: no task has this TID, so
/// no task's exit (`shm_release_all`) and no task's quota ever touches it.
pub const SHM_KERNEL_OWNER: u32 = u32::MAX;

/// A region the KERNEL owns, on physically CONTIGUOUS frames, for a kernel
/// producer that writes it through the direct map as one span (wave 11,
/// SHMRING: `crate::stream_ring`). Answers the packed reference and the
/// physical address of its first byte.
///
/// Booked to [`SHM_KERNEL_OWNER`] with that owner's one reference, never
/// charged to a task budget (the kernel reserve covers it), never released:
/// a consumer's capability and mapping come and go, the kernel's reference
/// keeps the frames. Frames are zeroed (`alloc_contiguous`) and, should the
/// region ever be freed, go back one `free_page` each, which is how
/// `alloc_contiguous` frames are released.
pub fn shm_create_kernel_contig_ref(page_count: usize, perms: ShmPerms) -> Option<(u32, usize)> {
    if page_count == 0 || page_count > MAX_SHM_PAGES {
        return None;
    }
    let page = azos_arch::mmu::PAGE_SIZE;
    let base = azos_mm::pmm::alloc_contiguous(page_count).ok()?.as_usize();
    let mut pages = [0usize; MAX_SHM_PAGES];
    for (i, p) in pages.iter_mut().enumerate().take(page_count) {
        *p = base + i * page;
    }
    match claim_slot(SHM_KERNEL_OWNER, &pages[..page_count], perms, false) {
        Some(r) => Some((r, base)),
        None => {
            free_frames(&pages[..page_count]);
            None
        }
    }
}

/// Would `owner_task` get a slot right now: under its quota, and a free slot
/// that is not mid-sweep. Counted under the SAME lock that claims: checking the
/// quota and then taking the lock would let two of a task's own threads both
/// pass the check and both claim, which is the bug one level down. Same rule
/// and same reasoning as `socket_create`'s quota. `create_core` runs it twice:
/// as a pre-check before allocating, and again in `claim_slot`.
fn has_room(regions: &ShmTable, owner_task: u32) -> bool {
    let held = regions.iter().filter(|r| r.active && r.owner_task == owner_task).count();
    held < MAX_SHM_REGIONS_PER_TASK
        && (0..MAX_SHM_REGIONS).any(|i| !regions[i].active && regions.next_gen[i] != 0)
}

/// Give back frames `create_core` allocated but never published.
fn free_frames(pages: &[usize]) {
    for &p in pages {
        let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(p));
    }
}

/// Claim a slot for the already-allocated, already-zeroed `pages` and publish
/// them. `None` leaves `pages` owned by the caller.
fn claim_slot(owner_task: u32, pages: &[usize], perms: ShmPerms, charged: bool) -> Option<u32> {
    // Two passes at most: the second runs only after this call's own
    // per-slot wrap sweep finishes.
    for _ in 0..2 {
        let mut regions = SHM_REGIONS.lock_irqsave();

        // Find and claim a free slot. Marking `active` before releasing the
        // lock (we hold it for the whole function) is what stops two harts
        // racing shm_create() from finding and writing into the same slot.
        if !has_room(&regions, owner_task) {
            return None;
        }
        // `next_gen[i] != 0` excludes a slot this call has marked mid-sweep.
        let slot = (0..MAX_SHM_REGIONS).find(|&i| !regions[i].active && regions.next_gen[i] != 0)?;
        // The generation is taken once a free slot is known, so a full table
        // or a quota refusal consumes none.
        let gen = match objref::take_slot_gen(regions.next_gen[slot], LAYOUT) {
            objref::SlotGen::Gen(g) => g,
            objref::SlotGen::Wrap => {
                regions.next_gen[slot] = 0;
                drop(regions);
                objref::sweep_index(CapKind::Shm, slot as u32);
                regions = SHM_REGIONS.lock_irqsave();
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
        region.perms = perms;
        region.charged = charged;
        // The creator's initial reference is booked against *it*, so its own
        // later `shm_release` is the only thing that can give it back.
        region.holders[0] = ShmHolder {
            tid: owner_task,
            refs: 1,
            map_va: 0,
            map_pages: 0,
            pinned: false,
        };

        return Some(LAYOUT.pack(slot as u32, gen));
    }
    None
}

/// TID of the task that created `shm_id`, or `None` if the slot is not active.
///
/// **WHY this is public (W3-F1):** `owner_task` was written by `shm_create`
/// and then never read anywhere in the tree, so the field documented an
/// ownership model that nothing enforced. `SYS_IPC_MAP` (retired) read it to
/// reject a non-owner before mapping another task's camera / LiDAR /
/// inference buffers into its address space — the region index is a small
/// integer chosen by userspace, so without this the whole table was
/// enumerable in sixteen guesses.
pub fn shm_owner(shm_id: u32) -> Option<u32> {
    if shm_id as usize >= MAX_SHM_REGIONS {
        return None;
    }
    let regions = SHM_REGIONS.lock_irqsave();
    let region = &regions[shm_id as usize];
    if region.active { Some(region.owner_task) } else { None }
}

/// The packed reference of live region `shm_id`, or `None` if its slot is not
/// active: for a caller holding a validated index that needs the value a
/// `Cap<Shm>` stores.
pub fn shm_ref(shm_id: u32) -> Option<u32> {
    if shm_id as usize >= MAX_SHM_REGIONS {
        return None;
    }
    let regions = SHM_REGIONS.lock_irqsave();
    let region = &regions[shm_id as usize];
    if region.active { Some(LAYOUT.pack(shm_id, region.generation)) } else { None }
}

/// Resolve a packed reference to its slot, with the table lock held by the
/// caller.
///
/// `Stale` unless the slot is active and carries the reference's generation: a
/// freed slot (generation 0), a slot reused by another region, and a bare index
/// (generation 0) all answer `Stale`.
fn live_index(regions: &[ShmRegion; MAX_SHM_REGIONS], r: u32) -> Result<usize, ShmCapError> {
    let i = LAYOUT.idx(r) as usize;
    let g = LAYOUT.gen(r);
    if g == 0 || i >= MAX_SHM_REGIONS || !regions[i].active || regions[i].generation != g {
        return Err(ShmCapError::Cap(CapError::Stale));
    }
    Ok(i)
}

/// Find the holder slot for `tid`, or the first free slot. Returns
/// `(index, is_existing)`. Caller holds the table lock.
fn holder_slot(region: &ShmRegion, tid: u32) -> Option<(usize, bool)> {
    let mut free: Option<usize> = None;
    for i in 0..MAX_SHM_HOLDERS {
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
pub fn shm_acquire_ref(tid: u32, r: u32) -> Result<(usize, ShmPerms), ShmCapError> {
    let mut regions = SHM_REGIONS.lock_irqsave();
    let i = live_index(&regions, r)?;
    acquire_locked(&mut regions[i], tid).ok_or(ShmCapError::Closed)
}

/// The acquire body, on an active region with the table lock held.
fn acquire_locked(region: &mut ShmRegion, tid: u32) -> Option<(usize, ShmPerms)> {
    let (idx, existing) = holder_slot(region, tid)?;
    // `checked_add`: `refs` is driven by an unprivileged syscall loop, and
    // with `overflow-checks = true` a bare `+= 1` at u32::MAX would panic —
    // and a panic here is `panic = "abort"`, i.e. a board reset. Refuse the
    // acquire instead.
    let next = region.holders[idx].refs.checked_add(1)?;
    if existing {
        region.holders[idx].refs = next;
    } else {
        region.holders[idx] = ShmHolder { tid, refs: 1, map_va: 0, map_pages: 0, pinned: false };
    }
    region.ref_count.fetch_add(1, Ordering::AcqRel);
    Some((region.page_count, region.perms))
}

/// Does `tid` already have a live mapping of `shm_id`?
///
/// `SYS_SHM_MAP_TYPED`, as the retired `SYS_IPC_MAP` did, records exactly one
/// VA per (task, region) so that the release path can always find the mapping it must tear down.
/// A second map by the same task is refused rather than silently creating an
/// untracked alias to pages the refcount thinks it can free.
pub fn shm_has_mapping(tid: u32, shm_id: u32) -> bool {
    if shm_id as usize >= MAX_SHM_REGIONS {
        return false;
    }
    let regions = SHM_REGIONS.lock_irqsave();
    let region = &regions[shm_id as usize];
    if !region.active {
        return false;
    }
    has_mapping_locked(region, tid)
}

/// [`shm_has_mapping`] through a packed reference.
pub fn shm_has_mapping_ref(tid: u32, r: u32) -> Result<bool, ShmCapError> {
    let regions = SHM_REGIONS.lock_irqsave();
    let i = live_index(&regions, r)?;
    Ok(has_mapping_locked(&regions[i], tid))
}

fn has_mapping_locked(region: &ShmRegion, tid: u32) -> bool {
    for i in 0..MAX_SHM_HOLDERS {
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
pub fn shm_mapping_of_ref(tid: u32, r: u32) -> Result<Option<(usize, usize)>, ShmCapError> {
    let regions = SHM_REGIONS.lock_irqsave();
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
/// precisely the state that lets `shm_release` free pages out from under a
/// live user PTE.
pub fn shm_note_mapping_ref(tid: u32, r: u32, va: usize, pages: usize) -> Result<bool, ShmCapError> {
    let mut regions = SHM_REGIONS.lock_irqsave();
    let i = live_index(&regions, r)?;
    if va == 0 || pages == 0 {
        return Ok(false);
    }
    Ok(note_mapping_locked(&mut regions[i], tid, va, pages))
}

fn note_mapping_locked(region: &mut ShmRegion, tid: u32, va: usize, pages: usize) -> bool {
    for i in 0..MAX_SHM_HOLDERS {
        let h = &mut region.holders[i];
        if h.refs > 0 && h.tid == tid {
            if h.map_va != 0 {
                return false; // already mapped — see shm_has_mapping()
            }
            h.map_va = va;
            h.map_pages = pages;
            return true;
        }
    }
    false
}

/// Clear and return `tid`'s recorded mapping of `shm_id` as `(va, pages)`.
///
/// The syscall layer calls this **before** `shm_release` and unmaps the
/// returned range from the caller's page table. That ordering is the whole
/// invariant: no reference may be dropped while the dropper still has PTEs
/// pointing into the region, so the refcount can never reach zero — and the
/// pages can never return to the PMM — with a live user mapping outstanding.
pub fn shm_take_mapping(tid: u32, shm_id: u32) -> Option<(usize, usize)> {
    if shm_id as usize >= MAX_SHM_REGIONS {
        return None;
    }
    let mut regions = SHM_REGIONS.lock_irqsave();
    let region = &mut regions[shm_id as usize];
    if !region.active {
        return None;
    }
    take_mapping_locked(region, tid)
}

/// [`shm_take_mapping`] through a packed reference.
pub fn shm_take_mapping_ref(tid: u32, r: u32) -> Result<Option<(usize, usize)>, ShmCapError> {
    let mut regions = SHM_REGIONS.lock_irqsave();
    let i = live_index(&regions, r)?;
    Ok(take_mapping_locked(&mut regions[i], tid))
}

fn take_mapping_locked(region: &mut ShmRegion, tid: u32) -> Option<(usize, usize)> {
    for i in 0..MAX_SHM_HOLDERS {
        let h = &mut region.holders[i];
        if h.refs > 0 && h.tid == tid && h.map_va != 0 {
            let out = (h.map_va, h.map_pages);
            h.map_va = 0;
            h.map_pages = 0;
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
/// address. A mapping is recorded only by `SYS_SHM_MAP_TYPED`, which demands
/// `READ` on a `Cap<Shm>`, so resolving through it asks the same authority
/// question — without needing the handle, which the creator loses when it
/// moves the capability to a peer (`cap_store::move_cap`). Answered under the
/// table lock on every call, so a released mapping stops resolving at once.
pub fn shm_resolve_mapped(tid: u32, va: usize) -> Option<(u32, usize, usize)> {
    let page = azos_arch::mmu::PAGE_SIZE;
    let regions = SHM_REGIONS.lock_irqsave();
    for (i, region) in regions.iter().enumerate() {
        if !region.active { continue; }
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
pub fn shm_is_mapped_by_any_ref(r: u32) -> bool {
    let regions = SHM_REGIONS.lock_irqsave();
    match live_index(&regions, r) {
        Ok(i) => regions[i].holders.iter().any(|h| h.refs != 0 && h.map_va != 0),
        Err(_) => false,
    }
}

/// The physical address of page `page_idx` of the region a packed reference
/// names: `Ok(None)` past the region's last page.
pub fn shm_page_phys_ref(r: u32, page_idx: usize) -> Result<Option<usize>, ShmCapError> {
    let regions = SHM_REGIONS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &regions[i];
    Ok(if page_idx < region.page_count { Some(region.phys_pages[page_idx]) } else { None })
}

/// Run `f` on the 32-bit word at byte `offset` of the region a packed
/// reference names, **with the region table locked across `f`**: `Ok(None)` for
/// an offset past the region's last page. The caller checks 4-alignment.
///
/// For `OP_NOTIFY_WAIT`'s look at its word (OVSwrap review F5). It used to
/// read the page address under this lock ([`shm_page_phys_ref`]) and load the
/// word after dropping it, so a last-holder release on another hart in between
/// put the frame back in the PMM and the load read whatever owned it next —
/// an equality oracle on a reallocated frame, since the wait completes when the
/// word equals the caller's `expected`. A region's frames are freed only in
/// `drop_refs_locked`, under this lock, so holding it pins the page for the
/// length of `f`. `f` must be short and must not take this lock (one atomic
/// load, in the kernel's use).
///
/// The offset is split with the build's translation granule
/// (`azos_arch::mmu::PAGE_SIZE`), as [`shm_resolve_mapped`] splits it:
/// each entry of `phys_pages` is one granule. It used a fixed 4096, so on an
/// aarch64 16/64 KiB build a word past the first 4 KiB of a region was read
/// from a later frame (or refused past `page_count` 4 KiB "pages").
pub fn shm_with_word_ref<R>(
    r: u32,
    offset: usize,
    f: impl FnOnce(&AtomicU32) -> R,
) -> Result<Option<R>, ShmCapError> {
    let page_size = azos_arch::mmu::PAGE_SIZE;
    let regions = SHM_REGIONS.lock_irqsave();
    let i = live_index(&regions, r)?;
    let region = &regions[i];
    let page = offset / page_size;
    if page >= region.page_count || offset % 4 != 0 {
        return Ok(None);
    }
    // `offset` is the caller's (`OP_NOTIFY_WAIT`'s SQE): the page index is
    // masked after the check (Spectre v1, `azos_limits::nospec`), as in
    // `shm_resolve_mapped`.
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
/// [`shm_with_word_ref`] only: called from inside its closure, `false` proves
/// the table was locked across the load.
pub fn __shm_table_unlocked_for_tests() -> bool {
    SHM_REGIONS.try_lock().is_some()
}

/// The index of the region a packed reference names, or `Stale`: the inverse
/// of [`shm_ref`]. For `SYS_IPC_LEASE_GRANT_TYPED` (603), which resolves a
/// `Cap<Shm>` and hands the lease table the region index it records.
pub fn shm_index_ref(r: u32) -> Result<u32, ShmCapError> {
    let regions = SHM_REGIONS.lock_irqsave();
    live_index(&regions, r).map(|i| i as u32)
}

/// The access mode of the region a packed reference names, or `Stale`. For
/// `SYS_SHM_MAP_TYPED` (574), which needs `WRITE` only for a writable region.
pub fn shm_perms_ref(r: u32) -> Result<ShmPerms, ShmCapError> {
    let regions = SHM_REGIONS.lock_irqsave();
    let i = live_index(&regions, r)?;
    Ok(regions[i].perms)
}

/// Pin `tid`'s references on the region a packed reference names
/// ([`ShmHolder::pinned`]): for `SYS_SHM_MAP_TYPED` when a map fails after its
/// reference was taken, which may leave PTEs no record names. From then on the
/// typed release keeps one of `tid`'s references; the exit gives it back.
/// `Ok(false)` if `tid` holds no reference; `Stale` as the other forms.
pub fn shm_pin_ref(tid: u32, r: u32) -> Result<bool, ShmCapError> {
    let mut regions = SHM_REGIONS.lock_irqsave();
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
///     hazard one step removed. Callers must `shm_take_mapping` + unmap
///     first; see [`shm_take_mapping`].
///
/// Freeing the pages only when the *last* reference goes away is unchanged.
pub fn shm_release(tid: u32, shm_id: u32) -> bool {
    if shm_id as usize >= MAX_SHM_REGIONS {
        return false;
    }
    let mut regions = SHM_REGIONS.lock_irqsave();
    let region = &mut regions[shm_id as usize];
    if !region.active {
        return false;
    }
    release_locked(region, tid)
}

/// [`shm_release`] through a packed reference: `Stale` if the region at its
/// index is not the one it names, `Closed` if no reference was dropped.
pub fn shm_release_ref(tid: u32, r: u32) -> Result<(), ShmCapError> {
    let mut regions = SHM_REGIONS.lock_irqsave();
    let i = live_index(&regions, r)?;
    if release_locked(&mut regions[i], tid) {
        Ok(())
    } else {
        Err(ShmCapError::Closed)
    }
}

/// The release body, on an active region with the table lock held.
fn release_locked(region: &mut ShmRegion, tid: u32) -> bool {
    let mut found: Option<usize> = None;
    for i in 0..MAX_SHM_HOLDERS {
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
/// names, except one a failed map pinned ([`ShmHolder::pinned`]): the pool half
/// of the typed release ([`shm_release_cap`]). `Stale` if the region at its
/// index is not the one it names; `Closed` if nothing was given back — `tid`
/// holds no reference, still has a mapping recorded (unmap first, see
/// [`shm_take_mapping`]), or holds only its pinned one.
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
pub fn shm_release_holder_ref(tid: u32, r: u32) -> Result<(), ShmCapError> {
    let mut regions = SHM_REGIONS.lock_irqsave();
    let i = live_index(&regions, r)?;
    if release_holder_locked(&mut regions[i], tid) {
        Ok(())
    } else {
        Err(ShmCapError::Closed)
    }
}

/// The [`shm_release_holder_ref`] body, on an active region with the table
/// lock held.
fn release_holder_locked(region: &mut ShmRegion, tid: u32) -> bool {
    let Some(idx) = (0..MAX_SHM_HOLDERS).find(|&i| region.holders[i].refs > 0 && region.holders[i].tid == tid)
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
fn drop_refs_locked(region: &mut ShmRegion, idx: usize, n: u32) {
    // `saturating_sub` rather than `-`: the callers bound `n` by the holder's
    // `refs`, but with `overflow-checks = true` an underflow here would abort
    // the board.
    region.holders[idx].refs = region.holders[idx].refs.saturating_sub(n);
    if region.holders[idx].refs == 0 {
        // The generation stays: the region is still live for its other
        // holders, and their capabilities must keep resolving.
        region.holders[idx] = ShmHolder::empty();
    }

    let prev = region.ref_count.load(Ordering::Acquire);
    let now = prev.saturating_sub(n);
    region.ref_count.store(now, Ordering::Release);
    if now == 0 {
        // Last reference — and, by the callers' refusal of a holder with a
        // recorded mapping, no holder can still have one, so freeing the
        // frames is safe. `empty()` clears the generation, so every capability
        // naming this region is stale from here on, whichever table holds it.
        for i in 0..region.page_count {
            if region.phys_pages[i] != 0 {
                let _ = azos_mm::pmm::free_page(
                    azos_mm::addr::PhysAddr::new(region.phys_pages[i]),
                );
            }
        }
        if region.charged {
            azos_sched::mm_discharge_tid(region.owner_task, region.page_count as u32);
        }
        *region = ShmRegion::empty();
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
pub fn shm_release_all(tid: u32) {
    // One look under the lock for the regions that exist at all (wave 13): a
    // task with nothing to release used to take the lock twice per region,
    // ~2,800 instructions on every exit. A region created after the look is
    // not this exiting task's.
    let mut live = [false; MAX_SHM_REGIONS];
    {
        let regions = SHM_REGIONS.lock_irqsave();
        for (l, r) in live.iter_mut().zip(regions.iter()) {
            *l = r.active;
        }
    }
    for id in 0..MAX_SHM_REGIONS {
        if !live[id] {
            continue;
        }
        loop {
            // Clear the mapping record first so `shm_release` will proceed;
            // see the note above on why not unmapping is sound here.
            let _ = shm_take_mapping(tid, id as u32);
            if !shm_release(tid, id as u32) {
                break;
            }
        }
    }
}

/// Get info about a shared memory region: (page_count, ref_count, perms).
pub fn shm_info(shm_id: u32) -> Option<(usize, u32, ShmPerms)> {
    if shm_id as usize >= MAX_SHM_REGIONS {
        return None;
    }
    let regions = SHM_REGIONS.lock_irqsave();
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
// Cap<Shm> typed wrappers (RFC-0003 W5 batch 2)
// ──────────────────────────────────────────────────────────────────────────
//
// Same shape as `port_*_cap`: each typed entry validates the cap against
// the caller's per-task `CapTable`, then delegates to the existing
// integer-handle logic. `shm_create_cap` allocates a region *and* mints
// the cap atomically (it cannot leave a region orphaned on cap-table
// exhaustion — the region is freed if the grant fails).

/// Errors returned by the typed `shm_*_cap` functions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShmCapError {
    /// Capability dereference failed (stale / wrong kind / missing perms).
    Cap(crate::cap::CapError),
    /// Out of memory or no free region slot.
    NoMem,
    /// Caller asked for 0 pages or > [`MAX_SHM_PAGES`].
    BadArg,
    /// Region doesn't exist or has been released.
    Closed,
    /// Cap-table slot table is full — the region was rolled back.
    Full,
}

impl From<crate::cap::CapError> for ShmCapError {
    fn from(e: crate::cap::CapError) -> Self {
        Self::Cap(e)
    }
}

/// Derive `CapPerms` for a freshly-minted Shm cap from the region's
/// own access mode. ReadOnly → READ; ReadWrite → RW. Callers that
/// want a more restricted grant (e.g. duplicating read-only into a
/// child) can `revoke` + `grant` with a tighter mask afterwards.
fn cap_perms_for(perms: ShmPerms) -> crate::cap::CapPerms {
    match perms {
        ShmPerms::ReadOnly => crate::cap::CapPerms::READ,
        ShmPerms::ReadWrite => crate::cap::CapPerms::RW,
    }
}

/// Typed `shm_create`: allocates a region with `page_count` pages and
/// mints a `Cap<Shm>` into `tid`'s cap-table.
///
/// On cap-table exhaustion the region is released so the caller never
/// observes a partial state.
pub fn shm_create_cap(
    tid: u32,
    page_count: usize,
    perms: ShmPerms,
) -> Result<crate::cap::Cap<crate::cap::targets::Shm>, ShmCapError> {
    if page_count == 0 || page_count > MAX_SHM_PAGES {
        return Err(ShmCapError::BadArg);
    }
    let r = create_core(tid, page_count, perms).ok_or(ShmCapError::NoMem)?;
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
            // exhaustion. `shm_create` booked ref_count=1 against `tid`, so a
            // single release will free all pages and clear the slot. The
            // region has never been mapped at this point, so the "no live
            // mapping" refusal cannot fire.
            let _ = shm_release_ref(tid, r);
            Err(ShmCapError::Full)
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
pub fn shm_acquire_cap(
    tid: u32,
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
) -> Result<(usize, ShmPerms), ShmCapError> {
    let r = table.get(cap, crate::cap::CapPerms::READ)?;
    shm_acquire_ref(tid, r)
}

/// Typed release: validates the cap (requires `READ`, since release is
/// paired with acquire and any holder may give back its own references),
/// gives back **every** reference `tid` holds on the region except a pinned
/// one ([`shm_release_holder_ref`]), **and revokes the cap**. Refused
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
/// `SYS_SHM_RELEASE_TYPED` removes the caller's mapping before it calls this.
pub fn shm_release_cap(
    tid: u32,
    table: &mut crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
) -> Result<(), ShmCapError> {
    let r = table.get(cap, crate::cap::CapPerms::READ)?;
    let released = shm_release_holder_ref(tid, r);
    table.revoke(cap);
    released
}

/// Wipe the region table without returning pages, and restart every slot's
/// generation source. Host-test hygiene only: the suite shares one static
/// table, and the page allocator shim is reset separately. Never built into
/// the kernel.
#[cfg(test)]
pub fn __shm_reset_for_tests() {
    let mut regions = SHM_REGIONS.lock_irqsave();
    for i in 0..MAX_SHM_REGIONS {
        regions[i] = ShmRegion::empty();
        regions.next_gen[i] = 1;
    }
}

/// Fast-forward slot `i`'s own generation source, so a host test reaches its
/// wrap without `LAYOUT.gen_max()` create/release cycles at that index.
#[cfg(test)]
pub fn __shm_set_next_gen_for_tests(i: usize, next_gen: u32) {
    SHM_REGIONS.lock_irqsave().next_gen[i] = next_gen;
}

/// The generation stamped in slot `shm_id` (host tests).
#[cfg(test)]
pub fn __shm_generation_for_tests(shm_id: u32) -> u32 {
    SHM_REGIONS.lock_irqsave()[shm_id as usize].generation
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
    const STALE: ShmCapError = ShmCapError::Cap(CapError::Stale);

    /// The crate-wide serial lock (the page shim is shared with the io_ring
    /// and lease suites), an empty region table and three empty cap tables.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        __shm_reset_for_tests();
        for tid in [A, B, C] {
            cap_store::reset(tid);
        }
        g
    }

    /// A region created by `tid` through the typed path: its capability and the
    /// packed reference the capability stores.
    fn create(tid: u32) -> (Cap<Shm>, u32) {
        let cap = shm_create_cap(tid, 1, ShmPerms::ReadWrite).expect("create");
        (cap, cap_store::get(tid, cap, CapPerms::READ).expect("a fresh capability resolves"))
    }

    /// Another holder's capability for `r`, minted the way every packed
    /// capability is.
    fn mint(tid: u32, r: u32) -> Cap<Shm> {
        objref::grant_packed::<Shm>(tid, CapPerms::RW, r).expect("mint")
    }

    /// `shm_acquire_cap` through `tid`'s own table; answers the page count.
    fn acquire(tid: u32, cap: Cap<Shm>) -> Result<usize, ShmCapError> {
        cap_store::with_table(tid, |t| shm_acquire_cap(tid, t, cap))
            .expect("a live tid")
            .map(|(pages, _)| pages)
    }

    fn release(tid: u32, cap: Cap<Shm>) -> Result<(), ShmCapError> {
        cap_store::with_table(tid, |t| shm_release_cap(tid, t, cap)).expect("a live tid")
    }

    fn refs(shm_id: u32) -> Option<u32> {
        shm_info(shm_id).map(|(_, refs, _)| refs)
    }

    /// **OVSwrap review F5: the notify word is read with its page pinned.**
    /// `shm_with_word_ref` runs its closure with the region table locked, so a
    /// last-holder release (which frees frames only under that lock) cannot
    /// land between the lookup and the load. Asserted from inside the closure:
    /// the table's lock is held. The word read is the one written through the
    /// region's own page, and an offset past the region answers `None`.
    ///
    /// **Canary (by hand, 2026-10-02).** In `shm_with_word_ref`, `drop(regions)`
    /// before calling `f` (the old shape: address under the lock, load after):
    /// red on "the region table was unlocked during the load".
    #[test]
    fn the_notify_word_is_loaded_with_the_region_table_locked() {
        let _g = setup();
        let (_cap, r) = create(A);
        let phys = shm_page_phys_ref(r, 0).unwrap().unwrap();
        let w = azos_mm::addr::phys_to_virt(phys) + 8;
        unsafe { (*(w as *const AtomicU32)).store(0x5eed_f00d, Ordering::Release) };
        let (v, unlocked) = shm_with_word_ref(r, 8, |word| {
            (word.load(Ordering::Acquire), __shm_table_unlocked_for_tests())
        })
        .expect("a live reference")
        .expect("offset 8 is inside the region");
        assert_eq!(v, 0x5eed_f00d, "the word was not read through the region's page");
        assert!(!unlocked, "the region table was unlocked during the load");
        assert!(__shm_table_unlocked_for_tests(), "the lock outlived the call");
        let page = azos_arch::mmu::PAGE_SIZE;
        assert_eq!(shm_with_word_ref(r, page, |w| w.load(Ordering::Acquire)), Ok(None));
        assert_eq!(shm_with_word_ref(r, 6, |w| w.load(Ordering::Acquire)), Ok(None));
    }

    /// **The notify word is the word the mapping shows (wave 11 fix).** For
    /// every 4-aligned offset of a multi-page region, at the start, middle and
    /// end of each page: a word written through the frame `shm_resolve_mapped`
    /// names for the mapped address is the word `shm_with_word_ref` reads at
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
        let page = azos_arch::mmu::PAGE_SIZE;
        let cap = shm_create_cap(A, PAGES, ShmPerms::ReadWrite).expect("create");
        let r = cap_store::get(A, cap, CapPerms::READ).expect("a fresh capability resolves");
        assert_eq!(shm_note_mapping_ref(A, r, VA, PAGES), Ok(true));
        let mut tag = 0x5100_0000u32;
        for p in 0..PAGES {
            for off in [p * page, p * page + page / 2 + 4, p * page + page - 4] {
                tag += 1;
                let (rr, roff, phys) = shm_resolve_mapped(A, VA + off).expect("mapped");
                assert_eq!((rr, roff), (r, off));
                let w = azos_mm::addr::phys_to_virt(phys);
                unsafe { (*(w as *const AtomicU32)).store(tag, Ordering::Release) };
                let v = shm_with_word_ref(r, off, |word| word.load(Ordering::Acquire));
                assert_eq!(v, Ok(Some(tag)), "offset {off:#x}: the notify word is not the mapped word");
            }
        }
        assert_eq!(shm_with_word_ref(r, PAGES * page, |w| w.load(Ordering::Acquire)), Ok(None));
        assert_eq!(shm_resolve_mapped(A, VA + PAGES * page), None);
    }

    /// The source half of the fix above: the two functions that split a
    /// region offset into (frame, offset in frame) both take the granule from
    /// `azos_arch::mmu::PAGE_SIZE`, and neither carries a page size of its
    /// own. Red on the old `shm_with_word_ref` (`const PAGE: usize = 4096`).
    ///
    /// Both also index `phys_pages` with a page number derived from a ring-3
    /// value, so both mask it after the bounds check (Spectre v1, Kconfig
    /// `MITIGATION_SPECTRE_V1_INDEX`). A speculative load is invisible to any
    /// host test, so the mask's presence is asserted in the source.
    /// **Canary (wave 12).** Delete the `array_index_nospec` line from
    /// `shm_with_word_ref`: red, naming it.
    #[test]
    fn no_fixed_page_size_in_the_offset_split() {
        const SRC: &str = include_str!("shm.rs");
        let body = |name: &str| {
            let start = SRC.find(&format!("pub fn {name}")).unwrap_or_else(|| panic!("{name} not found"));
            let end = start + SRC[start..].find("\n}\n").expect("end of fn");
            &SRC[start..end]
        };
        for name in ["shm_with_word_ref", "shm_resolve_mapped"] {
            let b = body(name);
            assert!(b.contains("azos_arch::mmu::PAGE_SIZE"), "{name} does not take the build's granule");
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
    /// through the untyped `shm_release`, which revokes nothing, so only the
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
        assert!(shm_release(B, idx), "B's reference");
        assert!(shm_release(A, idx), "A's reference: the region is freed");

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
    /// **Canaries.** Keep the generation across `*region = ShmRegion::empty()`
    /// in `release_locked`: the slot's generation reads non-zero. Resolve by
    /// index only (drop the `g == 0`, active and generation tests from
    /// `live_index`): B's acquire books a reference on the freed slot.
    #[test]
    fn a_kernel_release_of_the_last_reference_stales_a_holder() {
        let _g = setup();
        let (_cap_a, r) = create(A);
        let in_b = mint(B, r);
        azos_sched::shim_set_current(0, 0);
        assert!(shm_release(A, LAYOUT.idx(r)), "the kernel drops A's only reference");
        assert_eq!(__shm_generation_for_tests(LAYOUT.idx(r)), 0, "the freed slot is vacant");
        assert_eq!(acquire(B, in_b), Err(STALE));
        assert_eq!(refs(LAYOUT.idx(r)), None, "nothing was booked on the freed slot");
    }

    /// (3) The exit of the last holder (`shm_release_all`) stales the
    /// capabilities in other tables.
    ///
    /// **Canary.** `break` in `shm_release_all` right after `shm_take_mapping`:
    /// the region stays live and B's acquire reads `Ok(1)`.
    #[test]
    fn the_exit_of_the_last_holder_stales_the_other_tables() {
        let _g = setup();
        let (_cap_a, r) = create(A);
        let in_b = mint(B, r);
        shm_release_all(A);
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
        shm_release_all(C);
        assert_eq!(acquire(A, cap_a), Ok(1), "after C's exit");
        assert_eq!(__shm_generation_for_tests(LAYOUT.idx(r)), LAYOUT.gen(r));
        assert_eq!(refs(LAYOUT.idx(r)), Some(3), "A's create reference and two acquires");
    }

    /// The typed release gives back every reference its holder booked (the
    /// creation reference and two acquires here) and no other holder's: B's
    /// capability still resolves, and B's release frees the region.
    ///
    /// **Canaries.** Give back one reference in `shm_release_cap`
    /// (`shm_release_ref`): the count after A's release reads `Some(3)`. Give
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
        assert_eq!(__shm_generation_for_tests(idx), LAYOUT.gen(r), "the region is live");
        assert_eq!(acquire(B, in_b), Ok(1), "B's capability still resolves");
        assert_eq!(release(B, in_b), Ok(()), "B's two references");
        assert_eq!(refs(idx), None, "the last holder's release freed the region");
        assert_eq!(__shm_generation_for_tests(idx), 0);
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
        assert_eq!(shm_acquire_ref(A, r).map(|(n, _)| n), Ok(1), "a map's reference");
        assert_eq!(shm_pin_ref(A, r), Ok(true), "the map failed part-way");
        assert_eq!(shm_pin_ref(B, r), Ok(false), "B holds nothing to pin");
        assert_eq!(release(A, cap_a), Ok(()), "the creation reference");
        assert_eq!(refs(idx), Some(1), "the pinned reference stays");
        assert_eq!(shm_release_holder_ref(A, r), Err(ShmCapError::Closed), "only the pinned one is left");
        shm_release_all(A);
        assert_eq!(refs(idx), None, "the exit gave it back");

        let (cap_c, rc) = create(C);
        assert_eq!(shm_note_mapping_ref(C, rc, 0x6000_0000, 1), Ok(true));
        assert_eq!(release(C, cap_c), Err(ShmCapError::Closed), "a recorded mapping");
        assert_eq!(refs(LAYOUT.idx(rc)), Some(1), "nothing was given back");
        shm_release_all(C);
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
        __shm_set_next_gen_for_tests(1, LAYOUT.gen_max() - 1);

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
        assert_eq!(shm_ref(0), Some(r_b), "B's region is still live");
        assert_eq!(cap_store::get(C, in_c, CapPerms::READ), Err(CapError::Stale), "C's stale capability, swept");
        assert_eq!(shm_ref(1), Some(r_new), "slot 1 now answers for the new incarnation");
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
        assert_eq!(shm_acquire_ref(B, idx).map(|(n, _)| n), Err(STALE));
        assert_eq!(refs(idx), Some(1), "no reference was booked");
    }

    /// The packed-reference forms answer like their index forms for a live
    /// reference, and `Stale` for an old one without touching the region now
    /// at that index.
    ///
    /// **Canary.** Resolve `shm_note_mapping_ref` by `objref::idx` instead of
    /// `live_index`: the stale note reads `Ok(false)`.
    #[test]
    fn the_reference_forms_refuse_an_old_reference() {
        let _g = setup();
        let old = shm_create_ref(A, 2, ShmPerms::ReadWrite).expect("create");
        assert_eq!(shm_has_mapping_ref(A, old), Ok(false));
        assert_eq!(shm_page_phys_ref(old, 1).map(|p| p.is_some()), Ok(true));
        assert_eq!(shm_page_phys_ref(old, 2), Ok(None), "past the region");
        assert_eq!(shm_note_mapping_ref(A, old, 0x6000_0000, 2), Ok(true));
        assert_eq!(shm_has_mapping_ref(A, old), Ok(true));
        assert_eq!(shm_release_ref(A, old), Err(ShmCapError::Closed), "a live mapping refuses");
        assert_eq!(shm_take_mapping_ref(A, old), Ok(Some((0x6000_0000, 2))));
        assert_eq!(shm_release_ref(A, old), Ok(()), "the last reference");

        let new = shm_create_ref(B, 1, ShmPerms::ReadOnly).expect("create");
        assert_eq!(LAYOUT.idx(new), LAYOUT.idx(old), "precondition: the index was reused");
        let answers = [
            ("has_mapping", shm_has_mapping_ref(A, old).map(|_| ())),
            ("page_phys", shm_page_phys_ref(old, 0).map(|_| ())),
            ("note_mapping", shm_note_mapping_ref(A, old, 0x6100_0000, 1).map(|_| ())),
            ("take_mapping", shm_take_mapping_ref(A, old).map(|_| ())),
            ("acquire", shm_acquire_ref(A, old).map(|_| ())),
            ("release", shm_release_ref(A, old)),
        ];
        for (what, got) in answers {
            assert_eq!(got, Err(STALE), "{what}");
        }
        assert!(!shm_has_mapping(B, LAYOUT.idx(new)));
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
        let old = shm_create_ref(A, 1, ShmPerms::ReadWrite).expect("create");
        let p = shm_page_phys_ref(old, 0).expect("live").expect("page 0");
        unsafe { core::ptr::write_bytes(p as *mut u8, 0xAA, azos_arch::mmu::PAGE_SIZE) };
        assert_eq!(shm_release_ref(A, old), Ok(()), "the last reference");
        assert_eq!(azos_mm::shim_free_count(p), 1, "the region's page went back");

        let new = shm_create_ref(B, 1, ShmPerms::ReadWrite).expect("create");
        let q = shm_page_phys_ref(new, 0).expect("live").expect("page 0");
        assert_eq!(q, p, "precondition: the new region got the poisoned page back");
        let bytes = unsafe { core::slice::from_raw_parts(q as *const u8, azos_arch::mmu::PAGE_SIZE) };
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
        assert!(more_than_the_pool <= MAX_SHM_PAGES, "precondition: a legal size");
        assert_eq!(shm_create_ref(A, more_than_the_pool, ShmPerms::ReadWrite), None);
        assert_eq!(azos_mm::shim_pages_in_use(), 0, "pages leaked on the OOM path");
        assert!(shm_create_ref(A, 1, ShmPerms::ReadWrite).is_some(), "the table slot was not consumed");
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
        for k in 0..MAX_SHM_REGIONS_PER_TASK {
            let r = shm_create_ref(A, 1, ShmPerms::ReadWrite).expect("under quota");
            if k == 0 {
                first = shm_page_phys_ref(r, 0).expect("live").expect("page 0");
            }
        }
        let held = azos_mm::shim_pages_in_use();
        assert_eq!(held, MAX_SHM_REGIONS_PER_TASK);
        assert_eq!(shm_create_ref(A, 4, ShmPerms::ReadWrite), None, "over quota");
        assert_eq!(azos_mm::shim_pages_in_use(), held, "pages leaked on a quota refusal");
        let page = azos_arch::mmu::PAGE_SIZE;
        for k in held..held + 4 {
            assert_eq!(azos_mm::shim_free_count(first + k * page), 0,
                       "a refused create allocated page {k} before checking the quota");
        }
    }

    /// RFC-0049 M1: a region's frames count against its CREATOR's budget from
    /// create until they are freed, whoever drops the last reference; a
    /// create that does not fit the budget is refused before any frame is
    /// taken; a kernel caller creating on a task's behalf charges nobody.
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
            let cap = shm_create_cap(A, 4, ShmPerms::ReadWrite).expect("create");
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
        assert!(shm_create_cap(A, 4, ShmPerms::ReadWrite).is_err());
        assert_eq!(azos_mm::shim_pages_in_use(), before, "no frame taken");
        assert_eq!(azos_sched::shim_charged(A), 0);

        // A kernel caller creating for A charges nobody.
        azos_sched::shim_set_current(0, 0);
        assert!(shm_create_cap(A, 4, ShmPerms::ReadWrite).is_ok());
        assert_eq!(azos_sched::shim_charged(A), 0);
    }
}

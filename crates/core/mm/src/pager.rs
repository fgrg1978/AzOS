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
//! **Pagers.** One exists: [`AnonPager`], zero-filled anonymous memory.
//!
//! * A file pager is not here. The file layer has no read path a fault could
//!   use: `FileOps` (in the syscall crate, which this crate cannot call) reads
//!   at a descriptor's seek position, so a page-in would have to `lseek` and
//!   `read` on the task's own descriptor, racing the task's own file position
//!   and failing once the task closes it. A file pager needs an open-file
//!   handle that outlives the descriptor and a positional read; neither
//!   exists.
//! * An IPC pager (a ring-3 server answering page requests) is what
//!   [`Supply::Pending`] and the `obj`/`off` fields of [`Region`] are shaped
//!   for: a pager that cannot answer at once returns `Pending`, the faulting
//!   task waits, and the server's reply installs the page through the same
//!   region re-check [`resolve_fault`] does. Not implemented; no pager returns
//!   `Pending` today, and a `Pending` answer is treated as unresolved.
//!
//! **Accounting.** Reserve-time charging, kept from RFC-0049 M1 (the model
//! `sys_alloc_demand` already follows) and owner decision 102 (charge the
//! whole request before taking a frame): `mmap` charges every reserved page to
//! the task's quota when it reserves, so a fault never refuses on quota — the
//! same reason a copy-on-write break is "observed, not charged". Overcommit
//! policy: the per-task quota is never overcommitted; physical frames are,
//! within what memory admission allows, so a fault that finds the page
//! allocator empty kills the task, as a COW break does. One residual: the
//! intermediate page-table frames a first touch allocates are charged then,
//! through the table hook, so a task at its exact limit can still be refused
//! a table at fault time.
//!
//! **State.** One [`RegionSet`] per user page-table root, in a fixed table of
//! `MAX_TASKS` slots (an address space belongs to at least one task, so the
//! table cannot run out of slots before the task table does), under one
//! IRQ-safe lock held only for lookups and the install itself, never across
//! the 4 KiB zero or a table walk. Every install happens under that lock
//! after re-finding the region, and `munmap` removes the region under it
//! before sweeping the committed pages: a commit can never land after the
//! sweep.

use azos_arch::ARCH;
use azos_arch_api::{Mmu, PagePerms, PAGE_SIZE};
use azos_common::error::{KResult, KernelError};
use azos_sync::SpinLock;

use crate::addr::PhysAddr;
pub use crate::region::{PagerKind, Region, RegionError, RegionSet};
use crate::{pmm, vmm};

/// Kconfig `MM_DEMAND_PAGING`: anonymous `mmap` reserves instead of commits.
pub const DEMAND_PAGING: bool = azos_limits::MM_DEMAND_PAGING;
/// Kconfig `MM_PRECOMMIT_RT`: real-time-class tasks' mappings are committed
/// at map time.
pub const PRECOMMIT_RT: bool = azos_limits::MM_PRECOMMIT_RT;
/// Region records per address space (Kconfig `MM_REGIONS_PER_SPACE`).
pub const REGIONS_PER_SPACE: usize = azos_limits::MM_REGIONS_PER_SPACE as usize;
const SPACES: usize = azos_limits::MAX_TASKS as usize;

/// What a pager is asked for: page `page` of object `obj`.
#[derive(Clone, Copy, Debug)]
pub struct PageRequest {
    pub obj: u32,
    pub page: usize,
    pub write: bool,
}

/// A pager's answer.
#[derive(Clone, Copy, Debug)]
pub enum Supply {
    /// A frame holding the page's contents, owned by the caller from now on.
    Frame(PhysAddr),
    /// The answer comes later (an IPC pager's server has to be asked). No
    /// in-kernel pager returns this.
    Pending,
}

/// The pager interface. `supply` runs in the faulting task's trap context with
/// no lock held (see [`resolve_fault`]); an in-kernel pager answers at once,
/// a pager that has to wait answers `Pending` instead.
pub trait Pager {
    fn supply(&self, req: &PageRequest) -> KResult<Supply>;
}

/// Zero-filled anonymous memory.
pub struct AnonPager;

impl Pager for AnonPager {
    #[inline]
    fn supply(&self, _req: &PageRequest) -> KResult<Supply> {
        // `alloc_page` zero-fills, and that is the only zero: a task must
        // never see a previous owner's bytes (see `demand.rs`).
        Ok(Supply::Frame(pmm::alloc_page()?))
    }
}

/// Static dispatch: one arm per pager kind, no vtable on the fault path.
#[inline]
fn supply(kind: PagerKind, req: &PageRequest) -> KResult<Supply> {
    match kind {
        PagerKind::Anon => AnonPager.supply(req),
    }
}

struct Space {
    root: usize,
    /// Region pages whose frame is installed (page table entries this module
    /// made valid and that `munmap` has not taken back).
    committed: usize,
    set: RegionSet<REGIONS_PER_SPACE>,
}

impl Space {
    const fn new() -> Self {
        Space { root: 0, committed: 0, set: RegionSet::new() }
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
        self.s[i].set.clear();
        self.used += 1;
        Some(i)
    }

    fn drop_slot(&mut self, i: usize) {
        let last = self.used - 1;
        if i != last {
            self.s[i].root = self.s[last].root;
            self.s[i].committed = self.s[last].committed;
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
pub fn resolve_fault(root: usize, va: usize) -> KResult<()> {
    let page = va & !(PAGE_SIZE - 1);
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
    let req = PageRequest { obj: r.obj, page: r.page_index(page), write: r.write };
    let frame = match supply(r.pager, &req)? {
        Supply::Frame(f) => f,
        Supply::Pending => return Err(KernelError::NotMapped),
    };
    let pte_ptr = match vmm::walk(root, page, true) {
        Ok(p) => p,
        Err(e) => {
            let _ = pmm::free_page(frame);
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
            let _ = pmm::free_page(frame);
            return Err(KernelError::InvalidArg);
        }
    };

    let mut t = TABLE.lock_irqsave();
    let same = t.slot(root).and_then(|i| {
        t.s[i].set.find(page).filter(|now| now.write == r.write && now.pager == r.pager && now.obj == r.obj).map(|_| i)
    });
    let Some(i) = same else {
        // Unmapped or re-protected since the lookup: retry and let the new
        // layout answer (a removed region then kills, as any hole does).
        drop(t);
        let _ = pmm::free_page(frame);
        return Ok(());
    };
    // SAFETY: `pte_ptr` is an aligned entry of a live table page (the region
    // still exists, so `munmap` has not swept it).
    let old = unsafe { core::ptr::read_volatile(pte_ptr) };
    if ARCH.pte_is_valid(old) || ARCH.pte_is_demand(old) {
        // Installed since the trap (or a marker, which regions never hold).
        drop(t);
        let _ = pmm::free_page(frame);
        return if ARCH.pte_is_valid(old) { Ok(()) } else { Err(KernelError::AlreadyMapped) };
    }
    // Compare-and-swap, as `demand.rs` does: installs are serialised by the
    // table lock, but the entry is shared with walkers that do not take it.
    // SAFETY: as above.
    let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
    if slot
        .compare_exchange(old, new, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire)
        .is_err()
    {
        drop(t);
        let _ = pmm::free_page(frame);
        return Ok(());
    }
    t.s[i].committed += 1;
    drop(t);
    ARCH.flush_tlb_page(page);
    Ok(())
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

/// Take `[s, e)` out of every region under `root`, for `munmap` and
/// `mprotect(PROT_NONE)`. Returns the reserved pages in the range that were
/// never committed: the caller discharges those itself, and its sweep frees
/// (and discharges) the committed ones. Call it **before** the sweep: once
/// it returns, no fault can commit a page in the range.
///
/// `Full` (nothing changed) when cutting a region in two needs a record the
/// space does not have.
pub fn release_range(root: usize, s: usize, e: usize) -> Result<usize, RegionError> {
    let mut pieces = [(0usize, 0usize); MAX_PIECES];
    let mut np = 0;
    {
        let mut t = TABLE.lock_irqsave();
        let Some(i) = t.slot(root) else { return Ok(0) };
        t.s[i].set.for_each_overlap(s, e, |a, b, _| {
            pieces[np] = (a, b);
            np += 1;
        });
        if np == 0 {
            return Ok(0);
        }
        t.s[i].set.remove_range(s, e)?;
    }
    // Outside the lock: nothing can commit in these pieces any more, and the
    // walk is up to 16,384 entries (64 MiB) — not with interrupts off.
    let mut covered = 0usize;
    let mut committed = 0usize;
    for &(a, b) in &pieces[..np] {
        let mut va = a;
        while va < b {
            covered += 1;
            if let vmm::UserPage::Leaf { .. } = vmm::user_page(root, va) {
                committed += 1;
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
    Ok(covered - committed)
}

/// Set the write permission of every region page in `[s, e)` (`mprotect` to
/// `PROT_READ` or read-write). Pages already committed are the caller's to
/// re-protect (`vmm::protect_user_range`). `Full`, nothing changed, when a
/// cut needs records the space does not have.
pub fn protect_range(root: usize, s: usize, e: usize, write: bool) -> Result<(), RegionError> {
    let mut t = TABLE.lock_irqsave();
    match t.slot(root) {
        Some(i) => t.s[i].set.protect_range(s, e, write),
        None => Ok(()),
    }
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
        }
        for r in t.s[p].set.as_slice() {
            if ns < spans.len() {
                spans[ns] = (r.start, r.end);
                ns += 1;
            }
        }
        t.s[p].set.reserved_pages()
    };
    // Outside the lock, as `release_range`'s sweep: a walk of the child's
    // own leaf tables over the regions.
    let committed: usize = if cfg!(feature = "fork-commit-race-canary") {
        let t = TABLE.lock_irqsave();
        t.slot(parent).map_or(0, |p| t.s[p].committed)
    } else {
        spans[..ns].iter().map(|&(a, b)| vmm::user_leaves_in(child, a, b)).sum()
    };
    let mut t = TABLE.lock_irqsave();
    if let Some(c) = t.slot(child) {
        t.s[c].committed = committed;
    }
    Ok(reserved.saturating_sub(committed))
}

/// Forget every region of `root` (its page table is being destroyed).
pub fn forget(root: usize) {
    let mut t = TABLE.lock_irqsave();
    if let Some(i) = t.slot(root) {
        t.drop_slot(i);
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

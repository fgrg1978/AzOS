// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Copy-on-Write (COW) support for user address spaces (AQ9).
//!
//! Tracks per-physical-page reference counts so that `fork()` can share
//! pages between parent and child read-only.  A store page fault on a page
//! with the COW flag triggers `handle_cow_fault()`, which allocates a new
//! physical page, copies the data, restores the WRITE bit, and decrements
//! the refcount on the original page.
//!
//! A fork shares the pages of anonymous mappings through their objects
//! (`pager::fork_clone`: slot by slot, no walk of the parent's table). The
//! walk here is for the pages no anonymous mapping holds: the image, the
//! stack, the trampoline, eager commits and private file pages.
//!
//! Design notes:
//!   - The refcount is one `u16` per managed physical frame, indexed by frame
//!     number (`cow_table.rs`): no heap, no search, no capacity to exhaust.
//!   - A count of 0 means "untracked", i.e. single-owner.  This keeps the
//!     common case free: private user pages that never fork are never touched.
//!   - The COW marker bit is stored in PTE bit 8 (RSW field, OS-defined) —
//!     see `PteFlags::COW` in `azos_arch::mmu`.
//!   - Works only under a real MMU.
//!
//! Known limitations:
//!   - `page_addref()` refuses a frame that is not a managed, page-aligned RAM
//!     frame (`InvalidArg`), and `fork_cow` aborts the fork and tears down what
//!     it built.  No user page is ever anything else.
//!   - The share count is one atomic per frame (`cow_table.rs`), changed by
//!     compare-and-swap. Two concurrent COW fault handlers touching the
//!     *same* physical page both count correctly, but the PTE write
//!     that flips WRITE back on is not atomic with the refcount decrement;
//!     this is acceptable because the fault is per-PT and a given PT has
//!     only one running task inside it at a time (fork creates a new PT).

use azos_arch::ARCH;
use azos_arch_api::{Mmu, PAGE_SIZE};
use azos_common::error::{KResult, KernelError};
use crate::addr::PhysAddr;
use crate::aspace::SpaceRef;
use crate::{pmm, vmm};

// The share count lives in `cow_table.rs` (see its header for why).
pub use crate::cow_table::{page_addref, page_decref, page_forget_if_sole, page_getref, page_is_sole};
// The COW-break counter, same file, same reason (see its header): visibility
// for the frames a break adds, without charging them against the quota.
pub use crate::cow_table::{cow_break_frames, note_cow_break};
#[cfg(not(target_os = "none"))]
pub use crate::cow_table::shim_set_cow_breaks;

// ── COW fork (AQ9) ───────────────────────────────────────────────────────────

/// Create a COW copy of a user page table.
///
/// Marks every USER leaf (4 KiB) page outside the anonymous mappings of the
/// space (`pager::fork_clone` clones those) and outside its mappings of other
/// owners' frames as read-only + COW in both parent and child.  Kernel entries
/// (megapages / no USER bit) are skipped — use
/// `vmm::copy_kernel_entries_to_user()` separately.
///
/// Returns the new page table's physical address.
///
/// The pages of the parent's shared-object, shared-file and physical-range
/// mappings (its records say which) stay writable in the parent and are not
/// mapped in the child by the walk. Their frames belong to a region, a cache or
/// a device, not to the address space. Made COW, the parent's next store landed
/// on a private copy while the owner kept the original; once both tasks had
/// written, the second copy's decref returned the owner's frame to the
/// allocator while it was still owned; and a page nobody wrote kept its
/// refcount entry for good, because teardown never decrefs them. The child
/// holds no capability or mapping record for them unless the fork gives it one
/// (`pager::fork_clone`).
///
/// On any error the partially built `child_pt` is torn down here (see
/// [`vmm::destroy_user_pagetable`]) before returning. It used to be the
/// caller's job, and no caller did it: `fork()` is reachable from ring 3 in a
/// loop, so every `CapacityFull` from the refcount table leaked a root page
/// table plus every intermediate table built so far.
pub fn fork_cow(parent_pt: usize) -> KResult<usize> {
    // (See [`fork_share_range`] for what a fork gives the child out of the
    // mappings the walk passes: a shared-memory mapping the child inherits.)
    let parent = crate::aspace::current_with_root(parent_pt);
    fork_cow_walk_held(parent, parent_pt, false).map(|(pt, _)| pt)
}

/// The fork rule for a shared-memory mapping (the
/// POSIX pipe over a `Cap<Shm>`): a child that inherits the capability
/// inherits the mapping **shared, not copy-on-write**. Its leaves are the
/// parent's, entry for entry, so a store by either side lands in the region
/// both see; no frame is counted (the region owns them, as it does for the
/// parent), and the child's teardown spares them: the child's record of the
/// mapping (`pager::reserve_obj`) clears its leaves first.
///
/// `[va, va + pages * PAGE_SIZE)` is a mapping of the parent's that the walk
/// left out of the child; the caller has booked the child's reference and
/// records the mapping once the leaves are copied. Every page must
/// be a valid user leaf in the parent, unless `sparse` (a swappable object's
/// page that is out, or restored by another mapper, has none: the child faults
/// it in). On an error the pages done are unmapped again, so a refused fork
/// leaves nothing of the range.
pub fn fork_share_range(parent_pt: usize, child_pt: usize, va: usize, pages: usize, sparse: bool) -> KResult<()> {
    let mut done = 0usize;
    let r = (|| {
        for i in 0..pages {
            let v = va.checked_add(i * PAGE_SIZE).ok_or(KernelError::InvalidArg)?;
            let src = match vmm::walk(parent_pt, v, false) {
                Ok(src) => src,
                Err(_) if sparse => continue,
                Err(e) => return Err(e),
            };
            // SAFETY: `walk` answered a pointer to the parent's leaf entry for `v`.
            let pte = unsafe { core::ptr::read_volatile(src) };
            if !ARCH.pte_is_valid(pte) || !ARCH.pte_is_leaf(pte, 0) || !ARCH.pte_perms(pte).user {
                if sparse && pte == ARCH.pte_empty() {
                    continue;
                }
                return Err(KernelError::NotMapped);
            }
            let dst = vmm::walk(child_pt, v, true)?;
            // SAFETY: the child's leaf entry for `v`, in a table its root owns
            // and no CPU runs on yet.
            unsafe { crate::pt::pt_set(dst, pte) };
            done += 1;
        }
        Ok(())
    })();
    if r.is_err() {
        for i in 0..done {
            vmm::unmap(child_pt, va + i * PAGE_SIZE);
        }
    }
    r
}

/// A fork child's leaves for one inherited shm mapping, as
/// [`crate::memobj::memobj_inherit_ref`] drives them: copied with
/// [`fork_share_range`], read back without faulting anything in, given their
/// write permission with the shootdown a protect makes, removed one by one.
pub struct ForkLeaves {
    pub parent_pt: usize,
    pub child_pt: usize,
    pub va: usize,
    pub pages: usize,
    /// The parent may lack a leaf for a page of the mapping
    /// ([`fork_share_range`]).
    pub sparse: bool,
}

impl crate::memobj::ChildLeaves for ForkLeaves {
    fn copy(&mut self) -> bool {
        fork_share_range(self.parent_pt, self.child_pt, self.va, self.pages, self.sparse).is_ok()
    }
    fn leaf(&self, va: usize) -> Option<(usize, bool)> {
        let phys = vmm::translate_user_readable_nofault(self.child_pt, va)?;
        Some((phys, vmm::translate_user_writable_nofault(self.child_pt, va).is_some()))
    }
    fn set_write(&mut self, write: bool) {
        let _ = vmm::set_user_range_write(self.child_pt, self.va, self.va + self.pages * PAGE_SIZE, write);
    }
    fn remove(&mut self) {
        for i in 0..self.pages {
            vmm::unmap(self.child_pt, self.va + i * PAGE_SIZE);
        }
    }
}

/// [`fork_cow`] of an address space other threads may be changing meanwhile
/// (`concurrent`: the parent is one thread of a group). Their
/// faults (a copy-on-write break, a first touch) rewrite parent entries
/// while the walk runs, so each parent entry is flipped by compare-and-swap
/// and retaken when it changed. A single-threaded parent's entries change
/// only under its own syscalls, so its walk stores them plainly.
///
/// Returns the child's root. Its mappings, and what they reserve, are the
/// pager's to clone (`pager::fork_clone`).
/// The fork's hold on the parent ([`crate::pager::ForkHold`]) comes with the
/// child's root: the caller drops it once the child's mappings are cloned
/// (`pager::fork_clone`), so the parent's pages stay as the walk saw them
/// meanwhile.
pub fn fork_cow_shared_held(parent: SpaceRef, concurrent: bool) -> KResult<(usize, crate::pager::ForkHold)> {
    fork_cow_walk_held(Some(parent), parent.root(), concurrent)
}

/// The walk of `parent_pt`, with the space's pager held off it (`parent`:
/// none for a root with no records).
fn fork_cow_walk_held(
    parent: Option<SpaceRef>,
    parent_pt: usize,
    concurrent: bool,
) -> KResult<(usize, crate::pager::ForkHold)> {
    // Superpage reservations (Kconfig `MM_THP_RESV`): the walk below skips
    // level-1 leaves, so promoted blocks are split first and no block may be
    // promoted while it runs.
    if let Some(p) = parent {
        if !crate::pager::fork_begin(p) {
            crate::pager::fork_end(p);
            return Err(KernelError::OutOfMemory);
        }
    }
    let hold = crate::pager::ForkHold::new(parent);
    // The anonymous mappings' pages are the clone's, and a shared mapping's
    // frames are not the child's: the walk passes them.
    let anon = match parent {
        Some(p) => crate::pager::passed_ranges(p).map_err(|_| KernelError::OutOfMemory)?,
        None => alloc::vec::Vec::new(),
    };
    let pt = fork_cow_walk(parent_pt, &anon, concurrent)?;
    Ok((pt, hold))
}

fn fork_cow_walk(parent_pt: usize, anon: &[PassedRange], concurrent: bool) -> KResult<usize> {
    let child_pt = vmm::create_pagetable()?;

    let mut pruned = Pruned { tables: [0; PRUNE_MAX], n: 0 };
    let skip = Skip { anon };
    let r = if concurrent {
        fork_cow_inner::<true>(parent_pt, child_pt, &skip, &mut pruned)
    } else {
        fork_cow_inner::<false>(parent_pt, child_pt, &skip, &mut pruned)
    };
    match r {
        Ok(()) => {
            // Parent's WRITE bits changed — shoot its translations down so
            // the first store actually traps into `handle_cow_fault` on
            // whichever hart makes it (a downgrade: a stale writable entry
            // would let the parent write the frame the child now shares).
            crate::vmm::user_shootdown(parent_pt, 0, azos_arch_api::TLB_ALL);
            // Blank leaf tables the walk unhooked go only now, after every
            // hart has dropped its translations through them.
            vmm::release_pruned_tables(parent_pt, &pruned.tables[..pruned.n]);
            Ok(child_pt)
        }
        Err(e) => {
            // The parent's PTEs we already flipped to COW stay flipped: that
            // is harmless (a store just takes one extra fault and copies), and
            // the pages the child did reach were addref'd *before* being
            // installed, so the teardown's decref leaves them alive for the
            // parent. Flush anyway — some parent PTEs lost their WRITE bit.
            vmm::destroy_user_pagetable(child_pt);
            crate::vmm::user_shootdown(parent_pt, 0, azos_arch_api::TLB_ALL);
            vmm::release_pruned_tables(parent_pt, &pruned.tables[..pruned.n]);
            Err(e)
        }
    }
}

/// Leaf tables a fork unhooks from its parent per call, at most.
const PRUNE_MAX: usize = 16;

/// The parent's blank leaf tables a fork unhooked: `munmap` frees
/// pages, not tables, so an address space that once mapped a large region
/// keeps tables with nothing in them, and every later fork walked them, and
/// every child's teardown again (vsbench: 7 such tables, ~21k instructions
/// per fork+exit+wait). The first fork that finds one unhooks it; the caller
/// frees it after its shootdown.
struct Pruned {
    tables: [usize; PRUNE_MAX],
    n: usize,
}

/// What the walk passes: the anonymous mappings, the physical ranges a fork
/// gives the child and the shared mappings (sorted, disjoint; `true`: the clone
/// makes the child's pages, which needs its leaf table).
/// A mapping a fork's walk passes: its range, whether the clone fills the child's
/// pages (`true`), and whether its frames are another owner's, a shared
/// object's or the cache's, whose walkers reach the table through records
/// without the space's lock.
pub(crate) type PassedRange = (usize, usize, bool, bool);

struct Skip<'a> {
    anon: &'a [PassedRange],
}

/// How much of a leaf table's span the anonymous mappings hold.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Held {
    None,
    Part,
    All,
}

impl Skip<'_> {
    /// The anonymous mappings' hold on `[lo, hi)`.
    #[inline]
    fn held(&self, lo: usize, hi: usize) -> Held {
        let i = self.anon.partition_point(|&(_, e, _, _)| e <= lo);
        match self.anon.get(i) {
            Some(&(s, e, _, _)) if s <= lo && e >= hi => Held::All,
            Some(&(s, _, _, _)) if s < hi => Held::Part,
            _ => Held::None,
        }
    }

    /// Does a mapping the clone fills hold a page of `[lo, hi)`? Its pages are
    /// the clone's, which needs the child's leaf table.
    #[inline]
    fn anon_holds(&self, lo: usize, hi: usize) -> bool {
        let i = self.anon.partition_point(|&(_, e, _, _)| e <= lo);
        self.anon[i..].iter().take_while(|&&(s, _, _, _)| s < hi).any(|&(_, _, a, _)| a)
    }

    /// Does a shared mapping hold a page of `[lo, hi)`? The reclaim of its
    /// object reaches this table through the object's records, with no lock of
    /// the space or the fork's hold, so the table stays hooked even when blank.
    ///
    /// Canary `fork-prunes-shared-canary`: no table is kept for them.
    #[inline]
    fn shared_holds(&self, lo: usize, hi: usize) -> bool {
        let i = self.anon.partition_point(|&(_, e, _, _)| e <= lo);
        !cfg!(feature = "fork-prunes-shared-canary") && self.anon[i..].iter().take_while(|&&(s, _, _, _)| s < hi).any(|&(_, _, _, sh)| sh)
    }

    /// Does a mapping the walk passes hold the page at `va`?
    #[inline]
    fn anon_at(&self, va: usize) -> bool {
        let i = self.anon.partition_point(|&(_, e, _, _)| e <= va);
        self.anon.get(i).is_some_and(|&(s, _, _, _)| s <= va)
    }
}

fn fork_cow_inner<const CONCURRENT: bool>(
    parent_pt: usize,
    child_pt: usize,
    skip: &Skip,
    pruned: &mut Pruned,
) -> KResult<()> {
    let entries = ARCH.entries_per_table();
    // The trampoline's frame, read once (0 on aarch64).
    let tramp = crate::vdso::sigtramp_phys();
    let kpt = vmm::kernel_pagetable();
    // Every level-2 table the parent owns: its root on riscv64 and aarch64
    // (called directly, so the page loop below is the one it was), each
    // PDPT on x86_64 (`vmm::for_each_user_l2`, borrowed kernel tables
    // skipped).
    if vmm::root_level() <= 2 {
        return fork_cow_l2::<CONCURRENT>(parent_pt, kpt, 0, child_pt, skip, pruned, entries, tramp);
    }
    vmm::for_each_user_l2(parent_pt, kpt, |parent_l2, k_l2, base| {
        fork_cow_l2::<CONCURRENT>(parent_l2, k_l2, base, child_pt, skip, pruned, entries, tramp)
    })
}

/// [`fork_cow_inner`] for one level-2 table of the parent (`parent_l2`, the
/// kernel's table on the same path `k_l2`, the VA its index 0 maps `base`).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn fork_cow_l2<const CONCURRENT: bool>(
    parent_l2: usize,
    k_l2: usize,
    base: usize,
    child_pt: usize,
    skip: &Skip,
    pruned: &mut Pruned,
    entries: usize,
    tramp: usize,
) -> KResult<()> {
    // Walk L2. Every root slot, also under an aarch64 16/64 KiB granule whose
    // root indexes only 8/64 of them: the root is a whole zeroed page, so the
    // rest read empty. Kept at `entries` so this loop is the one c1afd98 had.
    let mut vpn2_next = 0usize;
    loop {
        let vpn2 = crate::vmm::next_valid(parent_l2, vpn2_next, entries);
        if vpn2 >= entries { break; }
        vpn2_next = vpn2 + 1;
        let l2_pte = unsafe {
            core::ptr::read_volatile((crate::addr::phys_to_virt(parent_l2 + vpn2 * 8)) as *const u64)
        };
        if !ARCH.pte_is_valid(l2_pte) || ARCH.pte_is_leaf(l2_pte, 2) {
            continue; // Skip gigapages (kernel mapping).
        }
        let l1_pt = ARCH.pte_phys(l2_pte);

        // Defence in depth against the loader ordering bug (audit finding 2 /
        // 3): if `copy_kernel_entries_to_user` ever runs on an empty user PT
        // again, `parent_pt.L2[vpn2]` is a pointer to the *kernel's* L1 table,
        // and this walk would rewrite kernel PTEs — clearing WRITE and setting
        // the COW marker on the kernel's own mappings, in every address space
        // at once. Recognise a borrowed kernel table and never descend into it;
        // there is nothing forkable down there in any case (kernel leaves have
        // no USER bit).
        let kernel_l1 = vmm::kernel_l1_in(k_l2, vpn2);
        if kernel_l1 == Some(l1_pt) || vmm::kernel_only_slot(vpn2) {
            continue;
        }

        // Walk L1.
        let mut vpn1_next = 0usize;
        loop {
            let vpn1 = crate::vmm::next_valid(l1_pt, vpn1_next, entries);
            if vpn1 >= entries { break; }
            vpn1_next = vpn1 + 1;
            let l1_pte = unsafe {
                core::ptr::read_volatile((crate::addr::phys_to_virt(l1_pt + vpn1 * 8)) as *const u64)
            };
            if !ARCH.pte_is_valid(l1_pte) || ARCH.pte_is_leaf(l1_pte, 1) {
                continue; // Skip megapages.
            }
            let l0_pt = ARCH.pte_phys(l1_pte);

            // Same guard one level down: at VPN[2]=0 the user owns the L1
            // table but individual slots point at the kernel's L0 tables
            // (CLINT, PLIC, UART), merged in by
            // `copy_kernel_entries_to_user`.
            if let Some(k_l1) = kernel_l1 {
                let kl1_pte = unsafe {
                    core::ptr::read_volatile((crate::addr::phys_to_virt(k_l1 + vpn1 * 8)) as *const u64)
                };
                if ARCH.pte_is_valid(kl1_pte) && !ARCH.pte_is_leaf(kl1_pte, 1)
                    && ARCH.pte_phys(kl1_pte) == l0_pt
                {
                    continue;
                }
            }

            // Walk L0 (4 KiB pages). The child's leaf table for this range is
            // walked to (and made) once, at its first page, and its entries
            // written by index after that (a walk per page was
            // ~150 of a fork's ~600 instructions per page).
            let mut child_l0: *mut u64 = core::ptr::null_mut();
            let mut vpn0_next = 0usize;
            // A leaf table one anonymous or shared mapping holds whole is the
            // clone's or nobody's: not walked at all.
            const L0_SPAN_SHIFT: usize = azos_arch_api::PAGE_SHIFT + (azos_arch_api::PAGE_SHIFT - 3);
            const L1_SPAN_SHIFT: usize = L0_SPAN_SHIFT + (azos_arch_api::PAGE_SHIFT - 3);
            let lo = base | (vpn2 << L1_SPAN_SHIFT) | (vpn1 << L0_SPAN_SHIFT);
            let hi = lo + (1usize << L0_SPAN_SHIFT);
            let part = {
                let held = skip.held(lo, hi);
                // The child's leaf table for the clone, made now, before the
                // kernel's entries are merged into the child's root: the merge
                // and its collision check then see the slot as the user's.
                if skip.anon_holds(lo, hi) && crate::vmm::next_valid(l0_pt, 0, entries) < entries {
                    vmm::walk(child_pt, lo, true)?;
                }
                match held {
                    Held::All => continue,
                    Held::Part => true,
                    Held::None => false,
                }
            };
            // A table with no entry of any kind is unhooked from the parent
            // (not while other threads may walk it): "nothing from index 0"
            // under `next_present` is the whole-table blank test.
            if !CONCURRENT
                && pruned.n < PRUNE_MAX
                && !skip.shared_holds(lo, hi)
                && crate::vmm::next_present(l0_pt, 0, entries) >= entries
            {
                let l1_ptr = crate::addr::phys_to_virt(l1_pt + vpn1 * 8) as *mut u64;
                unsafe { crate::pt::pt_set(l1_ptr, 0) };
                pruned.tables[pruned.n] = l0_pt;
                pruned.n += 1;
                continue;
            }
            loop {
                let vpn0 = crate::vmm::next_valid(l0_pt, vpn0_next, entries);
                if vpn0 >= entries { break; }
                vpn0_next = vpn0 + 1;
                let l0_pte_ptr = (crate::addr::phys_to_virt(l0_pt + vpn0 * 8)) as *mut u64;
                let l0_pte = unsafe { core::ptr::read_volatile(l0_pte_ptr) };
                if !ARCH.pte_is_valid(l0_pte) {
                    continue;
                }
                if !ARCH.pte_is_leaf(l0_pte, 0) {
                    continue;
                }

                // Only COW user pages. One decode of the permissions serves
                // this test and the writable test below.
                let mut perms = ARCH.pte_perms(l0_pte);
                if !perms.user {
                    continue;
                }

                let vaddr = base | leaf_vaddr(vpn2, vpn1, vpn0);

                // A page of a mapping the walk passes is neither COW nor shared
                // by it (see `fork_cow`). Checked before the addref, or every
                // skipped page would still take a refcount entry.
                if part && skip.anon_at(vaddr) {
                    continue;
                }

                // The child's leaf table, before any reference is taken: a
                // failure here leaves nothing to give back.
                if child_l0.is_null() {
                    let p = vmm::walk(child_pt, vaddr, true)?;
                    child_l0 = unsafe { p.sub(vpn0) };
                }

                let mut l0_pte = l0_pte;
                let cow_pte = loop {
                let phys = ARCH.pte_phys(l0_pte);

                // The riscv64 sigreturn trampoline is the kernel's,
                // read-execute in every address space. The child gets the
                // same leaf: never copy-on-write, so no store fault can ever
                // turn it into a private writable copy of an executable page.
                // (Inside the compare-and-swap loop: `break None` leaves it
                // and moves on to the next entry with nothing to give back.)
                if tramp != 0 && phys == tramp {
                    // SAFETY: the child's leaf table walked above, entry vpn0.
                    unsafe { crate::pt::pt_set(child_l0.add(vpn0), l0_pte) };
                    break None;
                }

                // Track the shared page BEFORE either PTE is touched.
                //
                // Ordering matters for safety, not just tidiness: if the
                // refcount table fills up after the child's PTE is written,
                // the child maps a page the table does not know about, and the
                // error teardown then decrefs it, gets `true` ("sole owner"),
                // and frees a frame the parent is still executing out of.
                // Addref-first means "present in the child" implies "tracked
                // with refcount >= 2", so teardown can never free a live page.
                page_addref(phys)?;

                // Only a WRITABLE page becomes copy-on-write (
                // security). A read-only or executable page (text, rodata)
                // is shared as it is, frame counted, entry unchanged: a store
                // to it must fault as the protection violation it is. Marked
                // COW, the break used to hand the storer a private WRITABLE
                // copy that kept the execute bit: writable code in the child,
                // W^X broken (found by the SIGNALS front). Gate canary
                // `cow-ro-canary` brings that back.
                let writable = perms.write;
                if !writable && !cfg!(feature = "cow-ro-canary") {
                    unsafe { crate::pt::pt_set(child_l0.add(vpn0), l0_pte) };
                    break None;
                }
                // Parent: clear WRITE, set COW marker. By compare-and-swap
                //: a thread of the process may break or unmap this
                // page meanwhile (the fork holds its layout lock, not its
                // faults). Then the reference goes back and the entry is
                // taken again as it now is.
                let cow_pte = ARCH.pte_share_cow(l0_pte);
                if !CONCURRENT {
                    unsafe { crate::pt::pt_set(l0_pte_ptr, cow_pte) };
                    break Some(cow_pte);
                }
                // SAFETY: an aligned entry of the parent's live leaf table.
                let slot = unsafe { &*(l0_pte_ptr as *const core::sync::atomic::AtomicU64) };
                match crate::pt::pt_cas(slot, l0_pte, cow_pte) {
                    Ok(_) => break Some(cow_pte),
                    Err(cur) => {
                        let _ = page_decref(phys);
                        perms = ARCH.pte_perms(cur);
                        if !ARCH.pte_is_valid(cur) || !ARCH.pte_is_leaf(cur, 0) || !perms.user {
                            break None;
                        }
                        l0_pte = cur;
                    }
                }
                };
                let Some(cow_pte) = cow_pte else { continue };

                // Child: same physical page, same COW word, same index in its
                // own leaf table.
                unsafe { crate::pt::pt_set(child_l0.add(vpn0), cow_pte) };
            }
        }
    }
    Ok(())
}

/// The virtual address of leaf `vpn0` under `vpn2`/`vpn1` (Sv39 VPN layout
/// at 4 KiB: 30, 21, 12; a table is one page of 8-byte entries).
#[inline(always)]
fn leaf_vaddr(vpn2: usize, vpn1: usize, vpn0: usize) -> usize {
    const VPN0_SHIFT: usize = azos_arch_api::PAGE_SHIFT;
    const VPN1_SHIFT: usize = VPN0_SHIFT + (VPN0_SHIFT - 3);
    const VPN2_SHIFT: usize = VPN1_SHIFT + (VPN0_SHIFT - 3);
    (vpn2 << VPN2_SHIFT) | (vpn1 << VPN1_SHIFT) | (vpn0 << VPN0_SHIFT)
}

/// Handle a store page fault on a COW-marked page.
///
/// If the faulting PTE has the COW flag: allocate a fresh physical page,
/// copy the contents, restore the WRITE bit (+ clear COW), and decrement
/// the refcount on the old page (freeing it if it hit zero).
///
/// Returns `Ok(())` on success, `NotMapped` if the fault isn't actually COW.
/// A copy that finds the space held by a fork waits for the fork's end and
/// tries again (`pager::cow_swap`).
pub fn handle_cow_fault(pt: usize, fault_addr: usize) -> KResult<()> {
    while !cow_break_once(pt, fault_addr)? {}
    Ok(())
}

/// One try of [`handle_cow_fault`]: `false` when a fork held the space and the
/// try waited for its end, and the break is to be tried again.
fn cow_break_once(pt: usize, fault_addr: usize) -> KResult<bool> {
    // Null guard, same rule as the demand-paging path (see
    // `vmm::USER_GUARD_LIMIT`). The hole here is narrower — a COW break needs
    // an already-VALID, COW-marked leaf at that VA, so page 0 has to have been
    // mapped by the parent before the fork — but it is not closed: the ELF
    // loader in `sched::process` bounds `p_vaddr` only from ABOVE
    // (`p_vaddr >= USER_LOW_MAX` is rejected, nothing rejects `p_vaddr == 0`),
    // so an image that declares a PT_LOAD at VA 0 gets page 0 mapped and its
    // children inherit it as COW. Refusing here means a store through a null
    // pointer kills the task instead of quietly gaining a private zero page.
    //
    // This also gates `vmm::translate_user`, the other caller: a syscall
    // pointer below the guard limit now fails translation outright rather
    // than breaking COW on it first.
    if crate::vmm::in_null_guard(fault_addr) {
        return Err(KernelError::InvalidArg);
    }

    let aligned_addr = fault_addr & !(PAGE_SIZE - 1);
    let pte_ptr = vmm::walk(pt, aligned_addr, false)?;
    let pte = unsafe { core::ptr::read_volatile(pte_ptr) };

    // Must be a valid, leaf, COW-marked PTE.
    if !ARCH.pte_is_valid(pte) || !ARCH.pte_is_cow(pte) || !ARCH.pte_is_leaf(pte, 0) {
        // Already broken (CTXHUNT): two threads of one process
        // stored to the same COW page on two harts; one broke it, the other
        // faulted through its own read-only translation before the
        // shootdown reached it and walked to the broken entry. That store
        // was always allowed: retry it. It used to answer `NotMapped`, and
        // the trap killed the thread (a fork child's two threads bumping one
        // counter: 27-43 kills in 400 iterations). Only an entry a store
        // cannot fault on (writable, accessed, dirty: what `pte_break_cow`
        // makes) is retried, so a genuine write to a read-only page still
        // dies. Gate canary only: the old answer.
        if ARCH.pte_is_valid(pte) && ARCH.pte_is_leaf(pte, 0) && !ARCH.pte_is_cow(pte)
            && !cfg!(feature = "cow-spurious-canary")
        {
            let p = ARCH.pte_perms(pte);
            if p.user && p.write && p.dirty && p.accessed {
                ARCH.flush_tlb_page(aligned_addr);
                return Ok(true);
            }
        }
        return Err(KernelError::NotMapped);
    }
    // Defence in depth (W^X): `fork_cow` marks only writable pages
    // copy-on-write, and a writable page is never executable, so a COW entry
    // with the execute bit is not one this kernel made. Refuse rather than
    // hand out a writable copy of code.
    if ARCH.pte_perms(pte).exec && !cfg!(feature = "cow-ro-canary") {
        return Err(KernelError::NotMapped);
    }

    let old_phys = ARCH.pte_phys(pte);

    // The last holder keeps the frame (Linux's `wp_page_reuse`).
    // Once the other sharers have broken their copies or exited, the count is
    // 1 and the page is this task's alone: a copy would allocate a frame,
    // copy 4 KiB into it and free the original, to end where restoring the
    // write bit ends. A fork+exit child's exit leaves its parent with only
    // such pages.
    //
    // The count is read, the entry rewritten and the count cleared as three
    // steps, no lock between them. A concurrent fork from another thread of
    // this process (`fork_cow_shared_held`: addref, then swap the parent's entry)
    // either counted the frame before the read (2: this takes the copy path),
    // or finds the entry already writable (its swap fails and it retakes it),
    // or counts it between the read and the clear: `page_forget_if_sole`
    // fails, and the entry goes back to copy-on-write below, so no space ends
    // up writing a frame the fork's child maps. Unlike a copy, this needs no
    // wait for a fork that holds the space: the frame stays the parent's, so a
    // store through a stale writable translation lands where the parent reads.
    // Same permissions as a copy (`pte_break_cow`), so W^X holds as above.
    if !cfg!(feature = "cow-reuse-canary") {
        if crate::cow_table::page_is_sole(old_phys) {
            let broken = ARCH.pte_break_cow(pte);
            let Ok(new_pte) = ARCH.pte_make_leaf(old_phys, ARCH.pte_perms(broken), 0) else {
                return Err(KernelError::EncodeFailed);
            };
            // SAFETY: `pte_ptr` is an aligned entry of a live table page.
            let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
            let won = crate::pt::pt_cas(slot, pte, new_pte).is_ok();
            if won && !crate::cow_table::page_forget_if_sole(old_phys) {
                // A fork counted the frame since the read: undo the write
                // bit. A lost swap back means that fork already rewrote the
                // entry itself, which is the state this wanted.
                let _ = crate::pt::pt_cas(slot, new_pte, pte);
                crate::vmm::user_shootdown(pt, aligned_addr, PAGE_SIZE);
                return Ok(true);
            }
            if won {
                // The read-only translation goes, as after a copy: a hart
                // still holding it would fault on its next store.
                crate::vmm::user_shootdown(pt, aligned_addr, PAGE_SIZE);
            }
            // Lost: another thread changed the entry; the access retries on
            // whatever it says now, as the copy path's loser does.
            return Ok(true);
        }
    }

    // Allocate, uninitialised: the `copy_nonoverlapping` right below
    // overwrites every byte before anything can read this page, so
    // `alloc_page`'s zero-fill (U09-11) would be ~1500 RV64 instructions
    // spent producing 4 KiB that the copy immediately discards — 8 KiB
    // written (zero, then copy) to land 4 KiB of live data. `alloc_page` is
    // still correct for the pager's zero page (`pager::AnonPager`), which has no data
    // to copy in and must not hand a task a stale sibling's bytes; a COW
    // break always has real data, so it does not need that guarantee.
    // SAFETY: initialised immediately below, before the PTE (the only way
    // anything can reach this physical page) is installed.
    let new_page = unsafe { pmm::alloc_page_uninit()? };
    let new_phys = new_page.as_usize();
    // Observed, not charged against the per-task quota — see the note on
    // `note_cow_break` (`cow_table.rs`) for why refusing here is the wrong
    // shape. Recorded now, past the only failure path this function has left
    // (`OutOfMemory` already returned above): every call reaching here does
    // add a frame to some task's footprint.
    note_cow_break();
    unsafe {
        core::ptr::copy_nonoverlapping(
            crate::addr::phys_to_virt(old_phys) as *const u8,
            crate::addr::phys_to_virt(new_phys) as *mut u8,
            PAGE_SIZE,
        );
    }

    // Install the new PTE: WRITE back, COW off, DIRTY set (we just wrote),
    // pointing at the freshly copied frame.
    let broken = ARCH.pte_break_cow(pte);
    let new_pte = match ARCH.pte_make_leaf(new_phys, ARCH.pte_perms(broken), 0) {
        Ok(w) => w,
        Err(_) => {
            let _ = pmm::free_page(PhysAddr::new(new_phys));
            // Distinct from the null-guard `InvalidArg` above (U09-11):
            // this is `pte_make_leaf` — an arch-level encode call — refusing
            // inputs THIS FUNCTION built (`new_phys` fresh from the PMM,
            // `broken`'s perms carried over from an already-valid PTE). The
            // task did nothing wrong here; a caller must not log this the
            // way it logs the null-guard case. `kernel/src/entry/riscv64/trap.rs`'s COW-fault arm
            // already carves `OutOfMemory` out of the same "InvalidArg"
            // bucket for the same reason.
            return Err(KernelError::EncodeFailed);
        }
    };
    // Compare-and-swap: another thread of the process may have
    // broken the same page, or unmapped it, since the read above. The loser
    // frees its copy and returns as resolved, keeping its hands off the old
    // frame's count: its access retries on whatever the entry now says. The
    // page's slot, if an anonymous object holds it, moves with the leaf.
    // SAFETY: `pte_ptr` is an aligned entry of a live table page.
    let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
    match crate::pager::cow_swap(pt, aligned_addr, slot, pte, new_pte) {
        crate::pager::Swap::Swapped => {}
        crate::pager::Swap::Lost => {
            let _ = pmm::free_page(PhysAddr::new(new_phys));
            return Ok(true);
        }
        // A fork holds the space (`pager::cow_swap`): the copy goes, the
        // break waits for the fork's end, and the store faults again.
        crate::pager::Swap::Held(seq) => {
            let _ = pmm::free_page(PhysAddr::new(new_phys));
            crate::pager::wait_fork_end(seq);
            return Ok(false);
        }
    }

    // The PTE now names a different frame: shoot the old translation down on
    // every hart that may hold it BEFORE the old frame can be freed below — a
    // hart still reading through a stale entry would otherwise read (and,
    // once reissued, see) a frame this address space no longer owns.
    crate::vmm::user_shootdown(pt, aligned_addr, PAGE_SIZE);

    // Drop our reference on the old page.  If we were the last holder,
    // free it back to the PMM.
    if page_decref(old_phys) {
        let _ = pmm::free_page(PhysAddr::new(old_phys));
    }

    Ok(true)
}

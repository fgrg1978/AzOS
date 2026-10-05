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
//! Design notes:
//!   - The refcount is one `u16` per managed physical frame, indexed by frame
//!     number (`cow_table.rs`): no heap, no search, no capacity to exhaust.
//!   - A count of 0 means "untracked", i.e. single-owner.  This keeps the
//!     common case free: private user pages that never fork are never touched.
//!   - The COW marker bit is stored in PTE bit 8 (RSW field, OS-defined) —
//!     see `PteFlags::COW` in `azos_arch::mmu`.
//!   - Works only under a real MMU.  On `no-mmu` builds the module still
//!     compiles, but nothing drives it: there are no page tables to mark
//!     COW and no page-fault path to resolve them.
//!
//! Known limitations:
//!   - `page_addref()` refuses a frame that is not a managed, page-aligned RAM
//!     frame (`InvalidArg`), and `fork_cow` aborts the fork and tears down what
//!     it built.  No user page is ever anything else.
//!   - Refcount decrement is guarded by a `SpinLock`, not atomic increment
//!     on the raw entry.  Two concurrent COW fault handlers touching the
//!     *same* physical page are serialized correctly, but the PTE write
//!     that flips WRITE back on is not atomic with the refcount decrement;
//!     this is acceptable because the fault is per-PT and a given PT has
//!     only one running task inside it at a time (fork creates a new PT).

use azos_arch::ARCH;
use azos_arch_api::{Mmu, PAGE_SIZE};
use azos_common::error::{KResult, KernelError};
use crate::addr::PhysAddr;
use crate::{pmm, vmm};

// The refcount table lives in `cow_table.rs` (see its header for why).
pub use crate::cow_table::{page_addref, page_decref, page_getref, ref_batch, RefBatch};
#[cfg(not(target_os = "none"))]
pub use crate::cow_table::shim_reset_refs;
// The COW-break counter, same file, same reason (see its header): visibility
// for the frames a break adds, without charging them against the quota.
pub use crate::cow_table::{cow_break_frames, note_cow_break};
#[cfg(not(target_os = "none"))]
pub use crate::cow_table::shim_set_cow_breaks;

// ── COW fork (AQ9) ───────────────────────────────────────────────────────────

/// Create a COW copy of a user page table.
///
/// Marks every USER leaf (4 KiB) page outside `[skip_lo, skip_hi)` as
/// read-only + COW in both parent and child.  Kernel entries (megapages / no
/// USER bit) are skipped — use `vmm::copy_kernel_entries_to_user()` separately.
///
/// Returns the new page table's physical address.
///
/// Leaves inside `[skip_lo, skip_hi)` — the shm/MMIO window, the same range
/// exec and exit pass to [`vmm::destroy_user_pagetable_skip_range`] — stay
/// writable in the parent and are not mapped in the child. Their frames belong
/// to a shm region or a device, not to the address space. Made COW, the
/// parent's next store landed on a private copy while the region kept the
/// original; once both tasks had written, the second copy's decref returned
/// the region's frame to the allocator while the region still owned it; and
/// a page nobody wrote kept its refcount entry for good, because teardown
/// never decrefs the window. The child holds no capability or mapping record
/// for the window in any case.
///
/// On any error the partially built `child_pt` is torn down here (see
/// [`vmm::destroy_user_pagetable`]) before returning. It used to be the
/// caller's job, and no caller did it: `fork()` is reachable from ring 3 in a
/// loop, so every `CapacityFull` from the refcount table leaked a root page
/// table plus every intermediate table built so far.
pub fn fork_cow(parent_pt: usize, skip_lo: usize, skip_hi: usize) -> KResult<usize> {
    fork_cow_shared(parent_pt, skip_lo, skip_hi, false).map(|(pt, _)| pt)
}

/// [`fork_cow`] of an address space other threads may be changing meanwhile
/// (`concurrent`, wave 13: the parent is one thread of a group). Their
/// faults (a copy-on-write break, a demand fault) rewrite parent entries
/// while the walk runs, so each parent entry is flipped by compare-and-swap
/// and retaken when it changed. A single-threaded parent's entries change
/// only under its own syscalls, so its walk stores them plainly.
///
/// Returns the child's root and the demand reservations it was given (wave
/// 14): each is a page the child may commit later, charged to it by the
/// caller as the parent's were charged at reservation.
pub fn fork_cow_shared(parent_pt: usize, skip_lo: usize, skip_hi: usize, concurrent: bool) -> KResult<(usize, usize)> {
    let child_pt = vmm::create_pagetable()?;

    let mut pruned = Pruned { tables: [0; PRUNE_MAX], n: 0 };
    let mut markers = 0usize;
    let r = if concurrent {
        fork_cow_inner::<true>(parent_pt, child_pt, skip_lo, skip_hi, &mut pruned, &mut markers)
    } else {
        fork_cow_inner::<false>(parent_pt, child_pt, skip_lo, skip_hi, &mut pruned, &mut markers)
    };
    match r {
        Ok(()) => {
            // Parent's WRITE bits changed — shoot its translations down so
            // the first store actually traps into `handle_cow_fault` on
            // whichever hart makes it (a downgrade: a stale writable entry
            // would let the parent write the frame the child now shares).
            ARCH.tlb_shootdown(parent_pt, 0, azos_arch_api::TLB_ALL);
            // Blank leaf tables the walk unhooked go only now, after every
            // hart has dropped its translations through them.
            vmm::release_pruned_tables(parent_pt, &pruned.tables[..pruned.n]);
            Ok((child_pt, markers))
        }
        Err(e) => {
            // The parent's PTEs we already flipped to COW stay flipped: that
            // is harmless (a store just takes one extra fault and copies), and
            // the pages the child did reach were addref'd *before* being
            // installed, so the teardown's decref leaves them alive for the
            // parent. Flush anyway — some parent PTEs lost their WRITE bit.
            vmm::destroy_user_pagetable(child_pt);
            ARCH.tlb_shootdown(parent_pt, 0, azos_arch_api::TLB_ALL);
            vmm::release_pruned_tables(parent_pt, &pruned.tables[..pruned.n]);
            Err(e)
        }
    }
}

/// Leaf tables a fork unhooks from its parent per call, at most.
const PRUNE_MAX: usize = 16;

/// The parent's blank leaf tables a fork unhooked (wave 13): `munmap` frees
/// pages, not tables, so an address space that once mapped a large region
/// keeps tables with nothing in them, and every later fork walked them, and
/// every child's teardown again (vsbench: 7 such tables, ~21k instructions
/// per fork+exit+wait). The first fork that finds one unhooks it; the caller
/// frees it after its shootdown.
struct Pruned {
    tables: [usize; PRUNE_MAX],
    n: usize,
}

fn fork_cow_inner<const CONCURRENT: bool>(
    parent_pt: usize,
    child_pt: usize,
    skip_lo: usize,
    skip_hi: usize,
    pruned: &mut Pruned,
    markers: &mut usize,
) -> KResult<()> {
    let entries = ARCH.entries_per_table();
    // Wave 13: the trampoline's frame, read once (0 on aarch64).
    let tramp = crate::vdso::sigtramp_phys();
    // Walk L2. Every root slot, also under an aarch64 16/64 KiB granule whose
    // root indexes only 8/64 of them: the root is a whole zeroed page, so the
    // rest read empty. Kept at `entries` so this loop is the one c1afd98 had.
    let mut vpn2_next = 0usize;
    loop {
        let vpn2 = crate::vmm::next_valid(parent_pt, vpn2_next, entries);
        if vpn2 >= entries { break; }
        vpn2_next = vpn2 + 1;
        let l2_pte = unsafe {
            core::ptr::read_volatile((crate::addr::phys_to_virt(parent_pt + vpn2 * 8)) as *const u64)
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
        let kernel_l1 = vmm::kernel_l1_table(vpn2);
        if kernel_l1 == Some(l1_pt) {
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
            // written by index after that; the refcount table is held over
            // the whole leaf table (wave 13: a walk and a lock per page were
            // ~150 of a fork's ~600 instructions per page).
            let mut child_l0: *mut u64 = core::ptr::null_mut();
            let mut refs: Option<crate::cow_table::RefBatch<'static>> = None;
            let mut vpn0_next = 0usize;
            // A leaf table wholly inside the shm/MMIO window holds nothing a
            // child gets (see `fork_cow`): not walked at all (wave 13).
            {
                const L0_SPAN_SHIFT: usize = azos_arch_api::PAGE_SHIFT + (azos_arch_api::PAGE_SHIFT - 3);
                const L1_SPAN_SHIFT: usize = L0_SPAN_SHIFT + (azos_arch_api::PAGE_SHIFT - 3);
                let lo = (vpn2 << L1_SPAN_SHIFT) | (vpn1 << L0_SPAN_SHIFT);
                let hi = lo + (1usize << L0_SPAN_SHIFT);
                if lo >= skip_lo && hi <= skip_hi {
                    continue;
                }
            }
            // A table with no valid entry, and no demand marker either, is
            // unhooked from the parent (not while other threads may walk it).
            // `next_present` finds both, so "nothing from index 0" is the
            // whole-table blank test (it was a valid-entry scan followed by a
            // second, word-by-word one).
            if !CONCURRENT
                && pruned.n < PRUNE_MAX
                && crate::vmm::next_present(l0_pt, 0, entries) >= entries
            {
                let l1_ptr = crate::addr::phys_to_virt(l1_pt + vpn1 * 8) as *mut u64;
                unsafe { core::ptr::write_volatile(l1_ptr, 0) };
                pruned.tables[pruned.n] = l0_pt;
                pruned.n += 1;
                continue;
            }
            loop {
                let vpn0 = crate::vmm::next_present(l0_pt, vpn0_next, entries);
                if vpn0 >= entries { break; }
                vpn0_next = vpn0 + 1;
                let l0_pte_ptr = (crate::addr::phys_to_virt(l0_pt + vpn0 * 8)) as *mut u64;
                let l0_pte = unsafe { core::ptr::read_volatile(l0_pte_ptr) };
                if !ARCH.pte_is_valid(l0_pte) {
                    // A demand reservation (wave 14): the child gets the same
                    // marker, so its first touch of the page faults in a
                    // fresh zero page of its own, as the parent's would. No
                    // frame, so no refcount and no change to the parent's
                    // entry. Until wave 14 the walk saw valid entries only
                    // and a child silently lost every reservation: a store to
                    // one killed it. Since `brk` reserves instead of
                    // allocating, that would have been every child's heap.
                    if ARCH.pte_is_demand(l0_pte) && !cfg!(feature = "fork-demand-canary") {
                        let vaddr = leaf_vaddr(vpn2, vpn1, vpn0);
                        if vaddr >= skip_lo && vaddr < skip_hi {
                            continue;
                        }
                        if child_l0.is_null() {
                            let p = vmm::walk(child_pt, vaddr, true)?;
                            child_l0 = unsafe { p.sub(vpn0) };
                        }
                        // SAFETY: the child's leaf table walked above, entry vpn0.
                        unsafe { core::ptr::write_volatile(child_l0.add(vpn0), l0_pte) };
                        *markers += 1;
                        // The run of reservations after it (a grown heap is
                        // one) is copied word for word, about six
                        // instructions each, without going back through the
                        // walk's search and per-entry decoding.
                        // `vaddr` is outside the window: below it, the run
                        // stops where the window starts; above, nothing does.
                        let lim = if vaddr < skip_lo {
                            entries.min(vpn0 + (skip_lo - vaddr) / PAGE_SIZE)
                        } else {
                            entries
                        };
                        let src = crate::addr::phys_to_virt(l0_pt) as *const u64;
                        let mut i = vpn0_next;
                        while i < lim {
                            // SAFETY: entry `i` of the same two leaf tables.
                            let w = unsafe { core::ptr::read_volatile(src.add(i)) };
                            if ARCH.pte_is_valid(w) || !ARCH.pte_is_demand(w) {
                                break;
                            }
                            unsafe { core::ptr::write_volatile(child_l0.add(i), w) };
                            i += 1;
                        }
                        *markers += i - vpn0_next;
                        vpn0_next = i;
                    }
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

                let vaddr = leaf_vaddr(vpn2, vpn1, vpn0);

                // The shm/MMIO window is neither COW nor shared (see
                // `fork_cow`). Checked before the addref, or every skipped
                // page would still take a refcount entry.
                if vaddr >= skip_lo && vaddr < skip_hi {
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

                // Wave 13: the riscv64 sigreturn trampoline is the kernel's,
                // read-execute in every address space. The child gets the
                // same leaf: never copy-on-write, so no store fault can ever
                // turn it into a private writable copy of an executable page.
                // (Inside the compare-and-swap loop: `break None` leaves it
                // and moves on to the next entry with nothing to give back.)
                if tramp != 0 && phys == tramp {
                    // SAFETY: the child's leaf table walked above, entry vpn0.
                    unsafe { core::ptr::write_volatile(child_l0.add(vpn0), l0_pte) };
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
                refs.get_or_insert_with(crate::cow_table::ref_batch).addref(phys)?;

                // Only a WRITABLE page becomes copy-on-write (wave 13,
                // security). A read-only or executable page (text, rodata)
                // is shared as it is, frame counted, entry unchanged: a store
                // to it must fault as the protection violation it is. Marked
                // COW, the break used to hand the storer a private WRITABLE
                // copy that kept the execute bit: writable code in the child,
                // W^X broken (found by the SIGNALS front). Gate canary
                // `cow-ro-canary` brings that back.
                let writable = perms.write;
                if !writable && !cfg!(feature = "cow-ro-canary") {
                    unsafe { core::ptr::write_volatile(child_l0.add(vpn0), l0_pte) };
                    break None;
                }
                // Parent: clear WRITE, set COW marker. By compare-and-swap
                // (wave 13): a thread of the process may break or unmap this
                // page meanwhile (the fork holds its layout lock, not its
                // faults). Then the reference goes back and the entry is
                // taken again as it now is.
                let cow_pte = ARCH.pte_share_cow(l0_pte);
                if !CONCURRENT {
                    unsafe { core::ptr::write_volatile(l0_pte_ptr, cow_pte) };
                    break Some(cow_pte);
                }
                // SAFETY: an aligned entry of the parent's live leaf table.
                let slot = unsafe { &*(l0_pte_ptr as *const core::sync::atomic::AtomicU64) };
                match slot.compare_exchange(l0_pte, cow_pte, core::sync::atomic::Ordering::AcqRel,
                                            core::sync::atomic::Ordering::Acquire) {
                    Ok(_) => break Some(cow_pte),
                    Err(cur) => {
                        let _ = refs.as_mut().map(|r| r.decref(phys));
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
                unsafe { core::ptr::write_volatile(child_l0.add(vpn0), cow_pte) };
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
pub fn handle_cow_fault(pt: usize, fault_addr: usize) -> KResult<()> {
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
        return Err(KernelError::NotMapped);
    }
    // Defence in depth (wave 13, W^X): `fork_cow` marks only writable pages
    // copy-on-write, and a writable page is never executable, so a COW entry
    // with the execute bit is not one this kernel made. Refuse rather than
    // hand out a writable copy of code.
    if ARCH.pte_perms(pte).exec && !cfg!(feature = "cow-ro-canary") {
        return Err(KernelError::NotMapped);
    }

    let old_phys = ARCH.pte_phys(pte);

    // The last holder keeps the frame (wave 14; Linux's `wp_page_reuse`).
    // Once the other sharers have broken their copies or exited, the count is
    // 1 and the page is this task's alone: a copy would allocate a frame,
    // copy 4 KiB into it and free the original, to end where restoring the
    // write bit ends. A fork+exit child's exit leaves its parent with only
    // such pages.
    //
    // The count is read and the entry rewritten under ONE hold of the table:
    // `fork_cow_shared` takes its addref and swaps the parent's entry under
    // the same lock, so a concurrent fork from another thread of this
    // process either counts the frame first (2: this takes the copy path) or
    // finds the entry already writable (its swap fails and it retakes it).
    // Same permissions as a copy (`pte_break_cow`), so W^X holds as above.
    if !cfg!(feature = "cow-reuse-canary") {
        let mut refs = crate::cow_table::ref_batch();
        if refs.sole(old_phys) {
            let broken = ARCH.pte_break_cow(pte);
            let Ok(new_pte) = ARCH.pte_make_leaf(old_phys, ARCH.pte_perms(broken), 0) else {
                return Err(KernelError::EncodeFailed);
            };
            // SAFETY: `pte_ptr` is an aligned entry of a live table page.
            let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
            let won = slot
                .compare_exchange(pte, new_pte, core::sync::atomic::Ordering::AcqRel,
                                  core::sync::atomic::Ordering::Acquire)
                .is_ok();
            if won {
                refs.forget(old_phys);
            }
            drop(refs);
            if won {
                // The read-only translation goes, as after a copy: a hart
                // still holding it would fault on its next store.
                ARCH.tlb_shootdown(pt, aligned_addr, PAGE_SIZE);
            }
            // Lost: another thread changed the entry; the access retries on
            // whatever it says now, as the copy path's loser does.
            return Ok(());
        }
    }

    // Allocate, uninitialised: the `copy_nonoverlapping` right below
    // overwrites every byte before anything can read this page, so
    // `alloc_page`'s zero-fill (U09-11) would be ~1500 RV64 instructions
    // spent producing 4 KiB that the copy immediately discards — 8 KiB
    // written (zero, then copy) to land 4 KiB of live data. `alloc_page` is
    // still correct for demand.rs's anonymous-page path, which has no data
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
            // way it logs the null-guard case. `kernel/src/trap/exception.rs`'s COW-fault arm
            // already carves `OutOfMemory` out of the same "InvalidArg"
            // bucket for the same reason.
            return Err(KernelError::EncodeFailed);
        }
    };
    // Compare-and-swap (wave 13): another thread of the process may have
    // broken the same page, or unmapped it, since the read above. The loser
    // frees its copy and returns as resolved, keeping its hands off the old
    // frame's count: its access retries on whatever the entry now says.
    // SAFETY: `pte_ptr` is an aligned entry of a live table page.
    let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
    if slot
        .compare_exchange(pte, new_pte, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire)
        .is_err()
    {
        let _ = pmm::free_page(PhysAddr::new(new_phys));
        return Ok(());
    }

    // The PTE now names a different frame: shoot the old translation down on
    // every hart that may hold it BEFORE the old frame can be freed below — a
    // hart still reading through a stale entry would otherwise read (and,
    // once reissued, see) a frame this address space no longer owns.
    ARCH.tlb_shootdown(pt, aligned_addr, PAGE_SIZE);

    // Drop our reference on the old page.  If we were the last holder,
    // free it back to the PMM.
    if page_decref(old_phys) {
        let _ = pmm::free_page(PhysAddr::new(old_phys));
    }

    Ok(())
}

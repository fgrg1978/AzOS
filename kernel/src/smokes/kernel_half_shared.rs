// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest `kernel_half_shared_by_every_root` (N12f, Kconfig `RV_KERNEL_GLOBAL`).
//!
//! On riscv64 the kernel half sits in every user root: each kernel-only
//! VPN[2] slot (at and above the user ceiling, `vmm::kernel_only_from`) is
//! one fixed L1 the kernel root owns, linked into every root; a G entry
//! there is sound only because every root maps it identically. The merge
//! slots below (user code and the kernel's low MMIO) keep the root's own L1
//! and must carry no G. `vmm::kernel_half_mismatch` checks one root; this
//! runs it on a root built through the production path (a user page, then
//! `copy_kernel_entries_to_user`) and on every root of the merged-root
//! roster (every live task's), read under `PT_META` through
//! `vmm::with_merged_roots`: teardown leaves the roster under that lock
//! before it frees a table, so an exiting task cannot hand this a freed
//! root. Nothing it runs under the lock sleeps. The lock is held per root,
//! for that root's links only (`vmm::kernel_half_links_mismatch`); the
//! kernel's own leaves (`vmm::kernel_leaves_mismatch`) are read once,
//! outside it, so no hold walks every kernel level-0 table.
//!
//! N12g (owner decision 10-10): with the probe root built, it maps one low
//! MMIO page in a free merge-slot block (`vmm::free_merge_block`) through
//! `vmm::map_mmio_region`, then requires every roster root to translate it
//! (`vmm::propagate_kernel_entries`). The page stays mapped: ktest image
//! only, at a block no root used.
//!
//! Canary (runtime): `canary=kernel-l1-copy` gives every root built after it
//! a private copy of the first kernel-only slot's L1 and turns propagation
//! off: `not ok` (the late MMIO page is missing from the roots first).
//!
//! Where it says nothing: aarch64 (the kernel half is `TTBR1_EL1`) and
//! x86_64 (merged below a four-level root) have no kernel-only slots in a
//! user root and return `ok` without running.

use azos_arch_api::{PagePerms, PAGE_SIZE};
use azos_mm::{pmm, vmm};

/// Where the probe root maps its one user page (where ring-3 images link).
const PROBE_VA: usize = 0x1_0000;

/// Map one low MMIO page after the roots exist; every roster root must get it.
fn late_mmio_reaches_every_root() -> Result<(), &'static str> {
    let va = vmm::free_merge_block().ok_or("no free merge-slot block for the late MMIO page")?;
    vmm::map_mmio_region(va, PAGE_SIZE).map_err(|_| "map_mmio_region failed")?;
    if vmm::translate(vmm::kernel_pagetable(), va) != Some(va) {
        return Err("the late MMIO page is not in the kernel root");
    }
    let roots = vmm::with_merged_roots(|pt| {
        if vmm::translate(pt, va) == Some(va) {
            Ok(())
        } else {
            Err("a root built before the late MMIO page lacks it (not propagated)")
        }
    })?;
    if roots == 0 {
        return Err("the merged-root roster is empty (the probe root never entered it)");
    }
    Ok(())
}

azos_ktest::ktest_late! {
    fn kernel_half_shared_by_every_root() {
        if vmm::kernel_only_from() == usize::MAX {
            return Ok(());
        }
        let root = vmm::create_pagetable().map_err(|_| "no frame for the probe root")?;
        let frame = match pmm::alloc_page() {
            Ok(p) => p,
            Err(_) => {
                vmm::destroy_user_pagetable(root);
                return Err("no frame for the probe page");
            }
        };
        let perms = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
        if vmm::map(root, PROBE_VA, frame.as_usize(), perms).is_err() {
            let _ = pmm::free_page(frame);
            vmm::destroy_user_pagetable(root);
            return Err("the probe page did not map");
        }
        vmm::copy_kernel_entries_to_user(root);
        let late = late_mmio_reaches_every_root();
        let fresh = vmm::kernel_half_mismatch(root);
        // The kernel's own leaves once, outside `PT_META`; under it, per
        // root, only the root's links (FX7: the whole check on every root in
        // one hold took 140 us, past LOCK_MAX_HOLD_US).
        let every = match vmm::kernel_leaves_mismatch() {
            Some(why) => Err(why),
            None => vmm::with_merged_roots(|pt| match vmm::kernel_half_links_mismatch(pt) {
                Some(why) => Err(why),
                None => Ok(()),
            }),
        };
        vmm::destroy_user_pagetable(root);
        late?;
        if let Some(why) = fresh {
            return Err(why);
        }
        every?;
        Ok(())
    }
}

/// ktest `user_mega_refused_in_a_shared_kernel_table` (N12i). A writer on a
/// user root must not install into a table the kernel shares. `map_mega` has
/// no pre-check of its own, so it is the deterministic driver: on a root
/// built through `copy_kernel_entries_to_user`, a kernel-only slot's level-2
/// word IS the kernel's level-1 table, exactly the word a push links into a
/// merge slot mid-walk. The walk's kernel shadow (`pte_install::shadow_step`)
/// must refuse it, and the kernel's table must be unchanged.
///
/// Canary (host-side edit, ktest image only): `shadow_step` returning
/// `Ok(0)` lets the USER 2 MiB leaf into the kernel's level-1 table:
/// `not ok`. riscv64 only; elsewhere there is no kernel-only slot in a user
/// root and it returns `ok` without running, as the test above does.
fn shared_kernel_l1_block(root: usize) -> Option<usize> {
    let kpt = vmm::kernel_pagetable();
    // `kernel_only_from` is a VPN[2] slot; the lower half of Sv39 ends at
    // slot 256 (256 GiB).
    let mut va = vmm::kernel_only_from().checked_mul(vmm::GIGA_SIZE)?;
    while va < 256 * vmm::GIGA_SIZE {
        if vmm::write_would_enter_kernel_table(root, va) && vmm::l1_slot_is_empty(kpt, va) {
            return Some(va);
        }
        va = va.checked_add(vmm::MEGA_SIZE)?;
    }
    None
}

azos_ktest::ktest_late! {
    fn user_mega_refused_in_a_shared_kernel_table() {
        if vmm::kernel_only_from() == usize::MAX {
            return Ok(());
        }
        let root = vmm::create_pagetable().map_err(|_| "no frame for the probe root")?;
        vmm::copy_kernel_entries_to_user(root);
        let Some(va) = shared_kernel_l1_block(root) else {
            vmm::destroy_user_pagetable(root);
            return Err("no empty 2 MiB block under a kernel-only slot's shared L1");
        };
        // Any 2 MiB-aligned frame: the write must never happen.
        let pa = 0usize;
        let r = vmm::map_mega(root, va, pa, PagePerms::USER_RW);
        let kernel_clean = vmm::l1_slot_is_empty(vmm::kernel_pagetable(), va);
        vmm::destroy_user_pagetable(root);
        if r.is_ok() || !kernel_clean {
            return Err("a USER 2 MiB leaf went into the kernel's shared level-1 table");
        }
        Ok(())
    }
}

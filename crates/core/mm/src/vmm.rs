// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Virtual Memory Manager (VMM).
///
/// 3-level page table management with identity mapping, COW, and page
/// table reference counting — level-aware and ISA-neutral since the
/// page-table abstraction (B2): every word this file reads or writes is a
/// raw `u64` built and decoded through `azos_arch_api::Mmu`
/// (`ARCH.pte_*`), never a RISC-V `Pte`/`PteFlags` value. Trait level `0`
/// is the leaf level (4 KiB pages), level `2` the root — RISC-V Sv39
/// `L0..L2`; the walk loops below (`for level in (1..=2).rev()`, VPN2 →
/// VPN1 → VPN0) are unchanged from the Sv39-only version because the
/// numbering already matched.
///
/// Ported from kernel/mm/vmm.c

use azos_arch::ARCH;
use azos_arch::ArchPlatform;
use azos_arch_api::{MemType, Mmu, MmuError, PagePerms, PAGE_SHIFT, PAGE_SIZE};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicUsize, Ordering};
use azos_common::error::{KResult, KernelError};
use crate::addr::PhysAddr;
use crate::pmm;
use crate::wx;
use crate::zone::Zone;

/// Entries per table (512 on both RISC-V Sv39 and aarch64 VMSAv8-64 at 4
/// KiB granule) — read once through the trait rather than at every call
/// site.
#[inline]
fn entries_per_table() -> usize { ARCH.entries_per_table() }

/// Root-table slots the walk can select (`entries_per_table()` except on an
/// aarch64 16/64 KiB granule, whose root indexes 8/64 slots).
#[inline]
fn root_entries() -> usize { ARCH.root_entries() }

/// The root's trait level: 2 on riscv64 (Sv39) and aarch64, whose roots are
/// level-2 tables; 3 on x86_64 (PML4), 4 under LA57 (PML5). A constant on
/// the first two, so every walk below folds to its three-level form there
/// and costs nothing it did not cost before.
#[inline(always)]
pub(crate) fn root_level() -> usize { ARCH.levels() - 1 }

/// The level-2 table that maps `vaddr` under `root`, or 0 when an upper
/// entry is empty. `root` itself on a three-level MMU (the loop is dead
/// there); on x86_64 the walk through the PML4 (and PML5) entry, which are
/// always tables (PS is reserved above level 2).
#[inline(always)]
pub(crate) fn l2_table(root: usize, vaddr: usize) -> usize {
    if root_level() <= 2 || root == 0 {
        return root;
    }
    l2_table_upper(root, vaddr)
}

/// [`l2_table`] found no level-2 table. Constant `false` on a three-level
/// MMU (the root is the table), so the check costs nothing there.
#[inline(always)]
fn no_l2(l2t: usize) -> bool {
    root_level() > 2 && l2t == 0
}

#[inline(never)]
fn l2_table_upper(root: usize, vaddr: usize) -> usize {
    let mut pt = root;
    let mut level = root_level();
    while level > 2 {
        let e = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + ARCH.vpn(vaddr, level) * 8)) as *const u64) };
        if !ARCH.pte_is_table(e, level) {
            return 0;
        }
        pt = ARCH.pte_phys(e);
        level -= 1;
    }
    pt
}

/// [`l2_table`], allocating (charged to `root`'s owner) any upper table that
/// is missing: the `walk(.., alloc = true)` half. Also returns the kernel's
/// level-2 table on the same path (0 if none, or for the kernel's own root),
/// for the caller's next shadow step: like `walk`, this refuses to descend
/// into an upper table the kernel shares (N12i).
#[inline(always)]
fn l2_table_alloc(root: usize, vaddr: usize) -> KResult<(usize, usize)> {
    if root_level() <= 2 {
        return Ok((root, writer_shadow_root(root)));
    }
    l2_table_alloc_upper(root, vaddr)
}

#[inline(never)]
fn l2_table_alloc_upper(root: usize, vaddr: usize) -> KResult<(usize, usize)> {
    let mut pt = root;
    let mut kt = writer_shadow_root(root);
    let mut level = root_level();
    while level > 2 {
        let vpn = ARCH.vpn(vaddr, level);
        let pte_ptr = (crate::addr::phys_to_virt(pt + vpn * 8)) as *mut u64;
        let pte = pt_word(pt, vpn).load(Ordering::Relaxed);
        if ARCH.pte_is_table(pte, level) {
            pt = ARCH.pte_phys(pte);
            if kt != 0 {
                core::sync::atomic::fence(Ordering::Acquire);
                kt = kernel_shadow_step(kt, vpn, level, pt)?;
            }
        } else if ARCH.pte_is_valid(pte) {
            return Err(KernelError::AlreadyMapped);
        } else {
            let new_pt = alloc_table(root)?;
            let new_pte = ARCH.pte_make_table(new_pt.as_usize());
            // SAFETY: `pte_ptr` is an aligned entry of a live table page. CAS
            // as in `walk`: threads of one process share the root.
            let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
            match slot.compare_exchange(pte, new_pte, core::sync::atomic::Ordering::AcqRel,
                                        core::sync::atomic::Ordering::Acquire) {
                Ok(_) => pt = new_pt.as_usize(),
                Err(cur) => {
                    let _ = pmm::free_page(new_pt);
                    let _ = table_charge(root, false);
                    if !ARCH.pte_is_table(cur, level) {
                        return Err(KernelError::NotMapped);
                    }
                    pt = ARCH.pte_phys(cur);
                }
            }
            if kt != 0 {
                kt = kernel_shadow_step(kt, vpn, level, pt)?;
            }
        }
        level -= 1;
    }
    Ok((pt, kt))
}

/// Slots of a level-2 table: the root's count on a three-level MMU (an
/// aarch64 16/64 KiB granule's root indexes 8/64), a full table otherwise.
#[inline(always)]
pub(crate) fn l2_slots() -> usize {
    if root_level() <= 2 { root_entries() } else { entries_per_table() }
}

/// The VA bits an index at `level` selects, the top level's upper half
/// sign-extended (x86_64's canonical form; riscv64's Sv39 never gets here).
#[inline]
fn upper_va(level: usize, idx: usize) -> usize {
    let shift = PAGE_SHIFT + level * IDX_BITS;
    let va = idx << shift;
    if level == root_level() && idx >= entries_per_table() / 2 {
        va | !((1usize << (shift + IDX_BITS)) - 1)
    } else {
        va
    }
}

/// Run `f(user_l2, kernel_l2, va_base)` for every level-2 table `user_pt`
/// reaches through tables of its own: `(user_pt, kernel root, 0)` once on a
/// three-level MMU. On x86_64 every PML4 (PML5) entry is followed, except
/// one that is the kernel's own entry copied in by
/// [`copy_kernel_entries_to_user`] (borrowed wholesale: nothing of the
/// task's is below it). `kernel_l2` is the kernel's level-2 table on the
/// same path, 0 if it has none; `va_base` the VA the table's index 0 maps.
#[inline(always)]
pub(crate) fn for_each_user_l2(user_pt: usize, kpt: usize,
                               mut f: impl FnMut(usize, usize, usize) -> KResult<()>) -> KResult<()> {
    if root_level() <= 2 {
        return f(user_pt, kpt, 0);
    }
    user_l2_upper(user_pt, kpt, root_level(), 0, &mut f)
}

#[inline(never)]
fn user_l2_upper(u: usize, k: usize, level: usize, base: usize,
                 f: &mut dyn FnMut(usize, usize, usize) -> KResult<()>) -> KResult<()> {
    if level <= 2 {
        return f(u, k, base);
    }
    let n = if level == root_level() { root_entries() } else { entries_per_table() };
    let mut next = 0usize;
    loop {
        let i = next_valid(u, next, n);
        if i >= n { break; }
        next = i + 1;
        let ue = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(u + i * 8)) as *const u64) };
        if !ARCH.pte_is_table(ue, level) { continue; }
        let uc = ARCH.pte_phys(ue);
        let kc = if k != 0 {
            let ke = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(k + i * 8)) as *const u64) };
            if ARCH.pte_is_table(ke, level) { ARCH.pte_phys(ke) } else { 0 }
        } else { 0 };
        if kc != 0 && kc == uc {
            continue; // the kernel's table, borrowed wholesale
        }
        user_l2_upper(uc, kc, level - 1, base | upper_va(level, i), f)?;
    }
    Ok(())
}

/// Free the tables below the root and at or above level 2 that `user_pt`
/// owns (x86_64's PDPTs and, under LA57, PML4s), leaving any borrowed from
/// the kernel; their contents below level 2 are already gone. Nothing on a
/// three-level MMU, where the root is the level-2 table.
#[inline(always)]
fn free_user_upper_tables(user_pt: usize, kpt: usize) {
    if root_level() > 2 {
        free_upper(user_pt, kpt, root_level());
    }
}

#[inline(never)]
fn free_upper(u: usize, k: usize, level: usize) {
    if level <= 2 { return; }
    let n = if level == root_level() { root_entries() } else { entries_per_table() };
    for i in 0..n {
        let ue = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(u + i * 8)) as *const u64) };
        if !ARCH.pte_is_table(ue, level) { continue; }
        let uc = ARCH.pte_phys(ue);
        let kc = if k != 0 {
            let ke = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(k + i * 8)) as *const u64) };
            if ARCH.pte_is_table(ke, level) { ARCH.pte_phys(ke) } else { 0 }
        } else { 0 };
        if kc != 0 && kc == uc { continue; }
        if level > 3 {
            free_upper(uc, kc, level - 1);
        }
        // `uc` is the task's table at level - 1 (at level 3, a level-2
        // table whose own tables the level-2 teardown already freed).
        let _ = pmm::free_page(PhysAddr::new(uc));
    }
}

/// Index bits per level: a table is one page of 8-byte entries (9 at 4 KiB).
const IDX_BITS: usize = PAGE_SHIFT - 3;
/// Entries per table as a constant, for loops over one table's worth of
/// leaves (`split_mega_range`, the megapage split in `unmap_inner`).
const PTES: usize = PAGE_SIZE / 8;
/// The VA bit the level-1 and level-2 indices start at (21 and 30 at 4 KiB).
const L1_SHIFT: usize = PAGE_SHIFT + IDX_BITS;
const L2_SHIFT: usize = PAGE_SHIFT + 2 * IDX_BITS;

#[inline]
fn mmu_error_to_kernel_error(e: MmuError) -> KernelError {
    match e {
        MmuError::NotAligned | MmuError::BadPhys => KernelError::NotAligned,
        MmuError::UnrepresentablePerms => KernelError::InvalidArg,
    }
}

/// Lowest user VA a page-fault handler is allowed to materialize a page at.
///
/// Everything strictly below this is a **null guard region**: no fault in it
/// is ever resolvable, so the faulting task dies instead of continuing.
///
/// Why 64 KiB, and why this is not an invented number:
///   - Every ring-3 `user.ld` in `userspace/*/` starts its first section at
///     `. = 0x10000`, and the ten ELFs currently in `build/` all report
///     `min PT_LOAD p_vaddr = 0x10000` (entry points at `0x10000..0x10bb2`).
///     So `0x10000` is exactly the lowest VA any legitimate binary uses —
///     the guard is as wide as it can be without touching a real image.
///   - Everything else a user address space contains sits far above it:
///     the `brk` heap grows up from the image and is capped at
///     `USER_LOW_MAX = 0x0200_0000`, the vDSO is at `VDSO_USER_BASE =
///     0x2000_0000` (`crates/core/abi/src/vdso.rs`, moved 2026-09-22 from
///     `0x5000_0000` — see that module's doc for why), the driver/shm MMIO
///     window at `0x6000_0000` (same class of VPN[2]=1 collision with
///     VF2/aarch64 RAM the vDSO had, not fixed by this task — see
///     `crates/core/abi/src/vdso.rs`'s report), the stack just under
///     `USER_STACK_TOP = 0x8000_0000` (see `sched::process`).
///
/// What it closes: an instruction fetch or a load/store at VA 0 is the most
/// common bug there is (null pointer / jump through a null function
/// pointer). Before this, the fault path tried COW, then demand paging, and
/// a demand-marked PTE at a low VA — `sys_alloc_demand` bases its
/// reservation at `update_user_brk(0)`, which is 0 for a task whose brk was
/// never initialized — made the *demand* attempt SUCCEED: the kernel mapped
/// a zero page over the null pointer and let ring 3 keep running on it.
/// A null dereference then executes zeros silently instead of killing the
/// task. On a robot that is a control task that never stops and never
/// reports; a dead task at least trips the supervisor.
///
/// If this is ever widened, check `userspace/*/user.ld` first: a binary
/// linked below the new limit stops loading (it will fault on its own entry
/// point and be killed, which is the correct-but-confusing symptom).
pub const USER_GUARD_LIMIT: usize = 0x1_0000; // 64 KiB — lowest legit user VA

/// True when `vaddr` falls in the null guard region (see [`USER_GUARD_LIMIT`]).
#[inline]
pub fn in_null_guard(vaddr: usize) -> bool {
    vaddr < USER_GUARD_LIMIT
}

/// Faults resolved without any UART output, split by kind.
///
/// Bumped by the kernel's page-fault arm (`kernel/src/trap/exception.rs`) on the paths
/// that used to print a `[PAGE FAULT]` banner for a fault that was about to
/// be fixed. They exist so removing that print does not remove the evidence:
/// the counters are dumped in the post-mortem block of an *unresolved* fault
/// (and by `trace_dump` consumers), so a crash report still says "this
/// system fixed N COW faults and M demand faults before dying here".
///
/// Cost on the common path is one relaxed `fetch_add` — no lock, no UART.
static COW_FAULTS_RESOLVED:    core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static DEMAND_FAULTS_RESOLVED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Record one silently-resolved COW fault. See [`faults_resolved`].
#[inline]
pub fn note_cow_resolved() {
    COW_FAULTS_RESOLVED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    fault_hook();
}

/// Record one silently-resolved demand-paging fault. See [`faults_resolved`].
#[inline]
pub fn note_demand_resolved() {
    DEMAND_FAULTS_RESOLVED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    fault_hook();
}

// ── RFC-0049 M1: charging page tables and counting faults per task ─────────
//
// This crate cannot see tasks (`azos_sched` depends on it), so the
// scheduler installs two plain function pointers at boot, the same seam
// `task_exit`'s hooks use. Unset (host tests, early boot) they charge nothing.

/// `fn(root, charge) -> allowed`: called with `charge = true` before a page
/// table is allocated under the user root `root`, and with `false` if that
/// allocation then failed. `false` from a charge refuses the table.
static TABLE_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// `fn()`: one user page fault was resolved for the current task.
static FAULT_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Install the page-table charge hook. See [`TABLE_HOOK`].
pub fn set_table_hook(f: fn(usize, bool) -> bool) {
    TABLE_HOOK.store(f as usize, core::sync::atomic::Ordering::Release);
}

/// Install the per-task fault hook. See [`FAULT_HOOK`].
pub fn set_fault_hook(f: fn()) {
    FAULT_HOOK.store(f as usize, core::sync::atomic::Ordering::Release);
}

#[inline]
fn table_charge(root: usize, charge: bool) -> bool {
    let f = TABLE_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if f == 0 { return true; }
    // SAFETY: only `set_table_hook` stores here, from a `fn(usize, bool) -> bool`.
    let f: fn(usize, bool) -> bool = unsafe { core::mem::transmute(f) };
    f(root, charge)
}

#[inline]
fn fault_hook() {
    let f = FAULT_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if f == 0 { return; }
    // SAFETY: only `set_fault_hook` stores here, from a `fn()`.
    let f: fn() = unsafe { core::mem::transmute(f) };
    f()
}

/// Allocate a page-table frame under `root`, charged through [`TABLE_HOOK`].
fn alloc_table(root: usize) -> KResult<crate::addr::PhysAddr> {
    if !table_charge(root, true) {
        return Err(KernelError::OutOfMemory);
    }
    match pmm::alloc_page_zone(Zone::PageTable) {
        Ok(p) => Ok(p),
        Err(e) => {
            let _ = table_charge(root, false);
            Err(e)
        }
    }
}

/// `(cow, demand)` faults resolved since boot, system-wide.
///
/// Consulted from the unresolved-fault post-mortem in `kernel/src/trap/exception.rs`
/// (both the U-mode kill path and the S-mode fatal path). Free to call from
/// a shell command too — it is a pair of relaxed loads.
pub fn faults_resolved() -> (u64, u64) {
    (
        COW_FAULTS_RESOLVED.load(core::sync::atomic::Ordering::Relaxed),
        DEMAND_FAULTS_RESOLVED.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Maximum number of page tables we track for reference counting.
///
/// U09-7: this used to be a bare `128` — a ceiling on live address spaces
/// independent of, and far below, Kconfig `MAX_TASKS` (up to 16384; 4096 on
/// the fleet profile). `create_pagetable` is called once per live task
/// (`sched::process`) and once per COW fork (`cow.rs`), so a task count
/// Kconfig says the board supports could not actually run: the 129th
/// `fork`/`exec` failed with `CapacityFull` while `MAX_TASKS` still had
/// thousands of room left. Derived from the same limit the scheduler sizes
/// its own task table from, so the two ceilings cannot drift apart again.
///
/// **Cost of the derivation, stated rather than hidden.** `PT_META` is a
/// flat `[PtMetadata; MAX_PT_TRACKED]` behind one lock, and `meta_find` is a
/// linear scan of it on every `fork`/`exit`/`pt_getref`: sizing this from
/// `MAX_TASKS` trades a hard cap that was too low for a working set that is
/// correct but, on a `MAX_TASKS = 16384` profile, 128× larger to scan and
/// 128× more `.bss` (`PtMetadata` is 16 bytes; 128 slots = 2 KiB, 16384 =
/// 256 KiB). Turning `meta_find` into something other than a linear scan is
/// a separate change; this one only removes the silent ceiling below what
/// Kconfig promises.
const MAX_PT_TRACKED: usize = azos_limits::MAX_TASKS;

struct PtMetadata {
    pt: usize,    // Physical address of page table (0 = empty slot)
    refcount: i32,
    /// The root holds the kernel half ([`copy_kernel_entries_to_user`] ran
    /// on it) and is not being torn down: the roster
    /// [`propagate_kernel_entries`] and [`with_merged_roots`] walk. Fits in
    /// the struct's padding (still 16 bytes).
    merged: bool,
}

static PT_META: SpinLock<[PtMetadata; MAX_PT_TRACKED]> = SpinLock::new({
    const EMPTY: PtMetadata = PtMetadata { pt: 0, refcount: 0, merged: false };
    [EMPTY; MAX_PT_TRACKED]
});

/// The kernel page table (set during vmm_init).
static KERNEL_PT: SpinLock<usize> = SpinLock::new(0);

// ---- Reference counting ----

fn meta_find(meta: &[PtMetadata; MAX_PT_TRACKED], pt: usize) -> Option<usize> {
    meta.iter().position(|m| m.pt == pt && pt != 0)
}

fn meta_add(pt: usize) -> KResult<()> {
    let mut meta = PT_META.lock();
    if meta_find(&meta, pt).is_some() {
        return Ok(()); // Already tracked
    }
    for slot in meta.iter_mut() {
        if slot.pt == 0 {
            slot.pt = pt;
            slot.refcount = 1;
            slot.merged = false;
            return Ok(());
        }
    }
    Err(KernelError::CapacityFull)
}

/// Drop a page table's tracking slot.
///
/// Must be called by every teardown path that frees a root page table
/// obtained from [`create_pagetable`]. `PT_META` has only `MAX_PT_TRACKED`
/// (128) slots and `meta_add` never reclaims them on its own: a loader that
/// frees the root page but leaves the slot occupied turns a repeatable
/// ring-3 failure (a malformed ELF handed to `exec`) into a permanent kernel
/// resource kill — after 128 attempts `create_pagetable` returns
/// `CapacityFull` forever and no process can ever be created again.
fn meta_remove(pt: usize) {
    if pt == 0 { return; }
    let mut meta = PT_META.lock();
    if let Some(idx) = meta_find(&meta, pt) {
        meta[idx].pt = 0;
        meta[idx].refcount = 0;
        meta[idx].merged = false;
    }
}

/// Take `pt` out of (or put it into) the merged-root roster. A root enters
/// when [`copy_kernel_entries_to_user`] has merged it; it leaves before
/// teardown frees its first table, so the roster never names a half-freed
/// root. No-op for a table `PT_META` does not track (smoke roots built by
/// hand).
fn meta_set_merged(pt: usize, merged: bool) {
    if pt == 0 { return; }
    let mut meta = PT_META.lock();
    if let Some(idx) = meta_find(&meta, pt) {
        meta[idx].merged = merged;
    }
}

/// Increment reference count for a page table.
pub fn pt_addref(pt: usize) -> KResult<i32> {
    let mut meta = PT_META.lock();
    if let Some(idx) = meta_find(&meta, pt) {
        meta[idx].refcount += 1;
        Ok(meta[idx].refcount)
    } else {
        Err(KernelError::NotFound)
    }
}

/// Decrement reference count. If it reaches 0, the page table is destroyed.
pub fn pt_release(pt: usize) -> KResult<i32> {
    let mut meta = PT_META.lock();
    if let Some(idx) = meta_find(&meta, pt) {
        meta[idx].refcount -= 1;
        let rc = meta[idx].refcount;
        if rc <= 0 {
            meta[idx].pt = 0;
            meta[idx].refcount = 0;
            meta[idx].merged = false;
            // Drop lock before destroying (destroy_pagetable may allocate locks)
            drop(meta);
            destroy_pagetable(pt);
        }
        Ok(rc)
    } else {
        Err(KernelError::NotFound)
    }
}

/// Get current reference count.
pub fn pt_getref(pt: usize) -> Option<i32> {
    let meta = PT_META.lock();
    meta_find(&meta, pt).map(|idx| meta[idx].refcount)
}

// ---- Page table operations ----

/// Create a new (zeroed) page table. Registered with refcount=1.
pub fn create_pagetable() -> KResult<usize> {
    let page = pmm::alloc_page_zone(Zone::PageTable)?; // zeroed, as alloc_page
    let pt_phys = page.as_usize();
    // Give the page back if we cannot track it. Propagating `?` here used to
    // drop the freshly allocated frame on the floor: once `PT_META` is full
    // every further `create_pagetable` both fails *and* burns a physical page,
    // so a ring-3 fork/exec loop drains the PMM rather than just being denied.
    if let Err(e) = meta_add(pt_phys) {
        let _ = pmm::free_page(page);
        return Err(e);
    }
    Ok(pt_phys)
}

/// Walk the page table to find the PTE for `vaddr`.
/// If `alloc` is true, allocate missing intermediate tables.
/// Returns a pointer to the leaf PTE (L0 for 4K pages).
/// If a megapage (leaf at L1) is encountered, returns a pointer to that PTE.
///
/// `pub(crate)` so sibling modules (`cow`, `demand`) can share this walker.
/// The physical address of the table the KERNEL uses for this slot, or 0.
///
/// `vpn1 = None` asks for the kernel's L1 under `vpn2`; `Some(v)` asks for its
/// L0 under that L1. These are the same two comparisons
/// `destroy_user_pagetable_skip_range` already makes to decide what it must
/// not free — stated once here so the two cannot drift.
fn kernel_table_at(vaddr: usize, vpn1: Option<usize>) -> usize {
    let kpt = l2_table(*KERNEL_PT.lock(), vaddr);
    if kpt == 0 { return 0; }
    let vpn2 = ARCH.vpn(vaddr, 2);
    let kl2: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(kpt + vpn2 * 8)) as *const u64) };
    if !ARCH.pte_is_valid(kl2) || ARCH.pte_is_leaf(kl2, 2) { return 0; }
    let k_l1 = ARCH.pte_phys(kl2);
    match vpn1 {
        None => k_l1,
        Some(v) => {
            let kl1: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(k_l1 + v * 8)) as *const u64) };
            if ARCH.pte_is_valid(kl1) && !ARCH.pte_is_leaf(kl1, 1) { ARCH.pte_phys(kl1) } else { 0 }
        }
    }
}

/// Would mutating `vaddr` in `pt_phys` write into a table the kernel owns?
///
/// **The question a per-address ceiling cannot answer, and the reason this is
/// a predicate on TABLES rather than on addresses.** A user page table does not
/// hold a copy of the kernel's mappings: `copy_kernel_entries_to_user` writes
/// the kernel's non-leaf PTE, which is a POINTER, so the user's L1 and L0 for
/// the shared region ARE the kernel's tables. Anything that walks a user page
/// table and writes a PTE for an address in that region writes into the kernel
/// page table, and it does not need the address to be mapped for that to be
/// true — an EMPTY slot in a kernel-owned L0 is still the kernel's to fill.
///
/// That is the difference between "is this address mapped by the kernel", which
/// `va_is_kernel_mapped` answers, and "does this write land in the kernel's
/// table", which is the one that matters. The first misses every hole; a
/// mapper marching upward through a user address space reaches a hole before it
/// reaches a mapping.
///
/// Returns false for the kernel's own page table: the kernel may write its own
/// tables, which is what boot does.
pub fn write_would_enter_kernel_table(pt_phys: usize, vaddr: usize) -> bool {
    let kpt = *KERNEL_PT.lock();
    if kpt == 0 || pt_phys == kpt { return false; }

    let ul2 = l2_table(pt_phys, vaddr);
    if no_l2(ul2) { return false; }               // nothing there yet; walk will allocate ours
    // x86_64: a PML4 (PML5) entry copied from the kernel makes the whole
    // level-2 table the kernel's.
    if root_level() > 2 && ul2 == l2_table(kpt, vaddr) { return true; }
    let vpn2 = ARCH.vpn(vaddr, 2);
    let l2: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(ul2 + vpn2 * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l2) { return false; }  // nothing there yet; walk will allocate ours
    if ARCH.pte_is_leaf(l2, 2) { return false; } // a gigapage is not a table to descend into

    let u_l1 = ARCH.pte_phys(l2);
    if u_l1 == kernel_table_at(vaddr, None) {
        return true;                            // L1 borrowed wholesale from the kernel
    }

    let vpn1 = ARCH.vpn(vaddr, 1);
    let l1: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(u_l1 + vpn1 * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l1) || ARCH.pte_is_leaf(l1, 1) { return false; }
    ARCH.pte_phys(l1) == kernel_table_at(vaddr, Some(vpn1))
}

/// Is `[start, end)` (page-aligned) empty in the user table `pt_phys` — no
/// leaf, no demand marker, no entry of any kind — and reachable without
/// entering a table the kernel shares? Wave 14 (DEMANDPAGE): a reservation
/// must answer what the eager `mmap` loop answered through `map`'s
/// `AlreadyMapped`, or a region could be laid over a page something else
/// owns, or over the kernel's MMIO tables, and only fail at first touch.
///
/// Cost is per leaf table, not per page: a missing table vacates its whole
/// span at once, and a present one is read entry by entry without a walk.
pub fn user_range_vacant(pt_phys: usize, start: usize, end: usize) -> bool {
    const SPAN: usize = PAGE_SIZE << (azos_arch_api::PAGE_SHIFT - 3);
    let empty = ARCH.pte_empty();
    let mut va = start;
    while va < end {
        let stop = match (va | (SPAN - 1)).checked_add(1) {
            Some(b) => b.min(end),
            None => end,
        };
        if write_would_enter_kernel_table(pt_phys, va) {
            return false;
        }
        if let Ok(p) = walk(pt_phys, va, false) {
            // `p` is `va`'s entry in its leaf table, or a higher-level leaf
            // (valid, so the first read already refuses).
            let n = (stop - va) >> azos_arch_api::PAGE_SHIFT;
            for i in 0..n {
                // SAFETY: entries `vpn0(va)..vpn0(va) + n` lie in the same
                // leaf table page (`stop` never crosses its span).
                if unsafe { core::ptr::read_volatile(p.add(i)) } != empty {
                    return false;
                }
            }
        }
        va = stop;
    }
    true
}

/// Word `i` of the page-table frame at physical `table`, as an atomic: the
/// words two writers may install concurrently go through
/// [`crate::pte_install`] (N12h).
#[inline(always)]
fn pt_word<'a>(table: usize, i: usize) -> &'a core::sync::atomic::AtomicU64 {
    // SAFETY: `table` is a live, mapped page-table frame and `i` indexes
    // within it; `AtomicU64` has the layout of the `u64` word.
    unsafe { &*((crate::addr::phys_to_virt(table + i * 8)) as *const core::sync::atomic::AtomicU64) }
}

/// The whole page-table frame at physical `table`, as atomic words.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn table_words<'a>(table: usize) -> &'a [core::sync::atomic::AtomicU64] {
    // SAFETY: as `pt_word`, for every index below `entries_per_table()`.
    unsafe {
        core::slice::from_raw_parts(
            crate::addr::phys_to_virt(table) as *const core::sync::atomic::AtomicU64,
            entries_per_table(),
        )
    }
}

/// Where a writer walking `root` starts its kernel shadow (N12i): the kernel
/// root, or 0 — no shadow — for the kernel's own table (the kernel writes
/// its tables) and before `init` set one.
#[inline(always)]
fn writer_shadow_root(root: usize) -> usize {
    let k = KERNEL_ROOT.load(Ordering::Relaxed);
    if k == root { 0 } else { k }
}

/// May a user unmap path clear `w`, the leaf at `level` that maps `va` in a
/// user root (N12i)? Not a copy of the kernel's own translation; see
/// [`crate::pte_install::user_may_modify`].
#[inline]
fn user_may_modify(w: u64, va: usize, level: usize) -> bool {
    crate::pte_install::user_may_modify(
        w,
        |w| ARCH.pte_is_valid(w),
        |w| ARCH.pte_perms(w).user,
        || {
            let k = KERNEL_ROOT.load(Ordering::Relaxed);
            let page = va & !(PAGE_SIZE - 1);
            let span = PAGE_SIZE << (level * (PAGE_SHIFT - 3));
            k != 0 && translate(k, page) == Some(ARCH.pte_phys(w) + (page & (span - 1)))
        },
    )
}

/// One shadow step at `level` (N12i): refuse `child` when it is the table
/// the kernel table `kt` links at `vpn`, else the kernel's next table (0 if
/// none). See [`crate::pte_install::shadow_step`].
#[inline]
fn kernel_shadow_step(kt: usize, vpn: usize, level: usize, child: usize) -> KResult<usize> {
    crate::pte_install::shadow_step(
        kt,
        child,
        || pt_word(kt, vpn).load(Ordering::Relaxed),
        |w| ARCH.pte_is_table(w, level),
        |w| ARCH.pte_phys(w),
    )
    .map_err(|()| KernelError::AlreadyMapped)
}

pub(crate) fn walk(pt_phys: usize, vaddr: usize, alloc: bool) -> KResult<*mut u64> {
    let mut pt = pt_phys;
    // N12i: an allocating walk is a writer. On a user root it walks the
    // kernel root in step and refuses to descend into a table the kernel
    // shares, at every level and on the word it actually follows: a push
    // (`propagate_kernel_entries`) may link the kernel's table into a word
    // the caller's `write_would_enter_kernel_table` saw empty, and a leaf
    // written below it would be mapped in every address space. The callers'
    // pre-checks stay as the early answer; this is the one that holds.
    let mut kt = if alloc { writer_shadow_root(pt_phys) } else { 0 };

    for level in (1..=root_level()).rev() {
        let vpn = ARCH.vpn(vaddr, level);

        let pte_ptr = (crate::addr::phys_to_virt(pt + vpn * 8)) as *mut u64;
        // An atomic load, so the acquire fence below pairs with the push's
        // release CAS of this word (same code as the volatile read).
        let pte = pt_word(pt, vpn).load(Ordering::Relaxed);

        if ARCH.pte_is_valid(pte) {
            // If this is a leaf PTE (megapage at L1 or gigapage at L2),
            // return it directly — do NOT follow phys_addr as a PT pointer.
            if ARCH.pte_is_leaf(pte, level) {
                return Ok(pte_ptr);
            }
            let child = ARCH.pte_phys(pte);
            if kt != 0 {
                // Pairs with the push's release CAS: a link read here makes
                // the kernel word it was copied from visible below.
                core::sync::atomic::fence(Ordering::Acquire);
                kt = kernel_shadow_step(kt, vpn, level, child)?;
            }
            pt = child;
        } else {
            if !alloc {
                return Err(KernelError::NotMapped);
            }
            // Allocate intermediate page table, charged to whoever owns
            // `pt_phys` (RFC-0049 M1).
            let new_pt = alloc_table(pt_phys)?;
            let new_pte = ARCH.pte_make_table(new_pt.as_usize());
            // Installed by compare-and-swap (wave 13): the threads of one
            // process walk one table, and two of them may both find this slot
            // empty. The loser frees its table and follows the winner's.
            // SAFETY: `pte_ptr` is an aligned entry of a live table page.
            let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
            let child = match slot.compare_exchange(pte, new_pte, core::sync::atomic::Ordering::AcqRel,
                                        core::sync::atomic::Ordering::Acquire) {
                Ok(_) => new_pt.as_usize(),
                Err(cur) => {
                    let _ = pmm::free_page(new_pt);
                    let _ = table_charge(pt_phys, false);
                    if !ARCH.pte_is_valid(cur) {
                        return Err(KernelError::NotMapped);
                    }
                    if ARCH.pte_is_leaf(cur, level) {
                        return Ok(pte_ptr);
                    }
                    // The word that beat ours may be the push's link to the
                    // kernel's table: the step below refuses it.
                    ARCH.pte_phys(cur)
                }
            };
            // Our own new table is never the kernel's, but the kernel may
            // still have one a level down: the merge fills OUR table's words
            // with links to it, so the shadow keeps going.
            if kt != 0 {
                kt = kernel_shadow_step(kt, vpn, level, child)?;
            }
            pt = child;
        }
    }

    // Return pointer to level-0 PTE
    let vpn0 = ARCH.vpn(vaddr, 0);
    Ok((crate::addr::phys_to_virt(pt + vpn0 * 8)) as *mut u64)
}

/// The first index at or after `from`, below `n`, whose entry in the table at
/// physical `table` is valid; `n` if none. Reads four entries per step and
/// tests their OR (validity is one bit on both ISAs, so the OR is valid iff
/// one of them is): a fork and a teardown walk whole leaf tables, mostly
/// empty, and this is where they spent most of their time (wave 13: ~8
/// instructions per empty entry, ~6,000 entries per fork of vsbench).
#[inline]
pub(crate) fn next_valid(table: usize, from: usize, n: usize) -> usize {
    next_entry::<false>(table, from, n)
}

/// [`next_valid`] for any entry that is not zero: a valid entry or a demand
/// marker (wave 14). A fork walks leaf tables with this, because a child
/// inherits its parent's demand reservations (a lazily grown heap) as well as
/// its pages; and an index with nothing at or after it means the table is
/// blank from there, which is the whole-table test the fork's pruning needs.
#[inline]
pub(crate) fn next_present(table: usize, from: usize, n: usize) -> usize {
    next_entry::<true>(table, from, n)
}

/// `ANY`: stop at a non-zero word ([`next_present`]); else at a valid one.
#[inline(always)]
fn next_entry<const ANY: bool>(table: usize, from: usize, n: usize) -> usize {
    let hit = |w: u64| if ANY { w != 0 } else { ARCH.pte_is_valid(w) };
    let t = crate::addr::phys_to_virt(table) as *const u64;
    let mut i = from;
    // SAFETY: `table` is a page-table page of `n` entries.
    unsafe {
        // The next entry first: in a dense run (a heap, an image) it is the
        // answer, and an eight-wide look past it would load eight to find one.
        if i < n && hit(core::ptr::read_volatile(t.add(i))) {
            return i;
        }
        // Eight at a time (wave 13: ~2.4 instructions per empty entry, from
        // ~3.7 four at a time), then four, then one.
        while i + 8 <= n {
            let any = core::ptr::read_volatile(t.add(i))
                | core::ptr::read_volatile(t.add(i + 1))
                | core::ptr::read_volatile(t.add(i + 2))
                | core::ptr::read_volatile(t.add(i + 3))
                | core::ptr::read_volatile(t.add(i + 4))
                | core::ptr::read_volatile(t.add(i + 5))
                | core::ptr::read_volatile(t.add(i + 6))
                | core::ptr::read_volatile(t.add(i + 7));
            if hit(any) {
                break;
            }
            i += 8;
        }
        while i + 4 <= n {
            let any = core::ptr::read_volatile(t.add(i))
                | core::ptr::read_volatile(t.add(i + 1))
                | core::ptr::read_volatile(t.add(i + 2))
                | core::ptr::read_volatile(t.add(i + 3));
            if hit(any) {
                break;
            }
            i += 4;
        }
        while i < n {
            if hit(core::ptr::read_volatile(t.add(i))) {
                return i;
            }
            i += 1;
        }
    }
    n
}

/// Valid 4 KiB user leaves in `[s, e)` of the table at `root` (wave 14): one
/// walk per leaf table, then its entries read in place. For a fork's child,
/// whose region pages are exactly the leaves its copy-on-write walk gave it
/// (`pager::fork_clone`).
pub fn user_leaves_in(root: usize, s: usize, e: usize) -> usize {
    let span = PAGE_SIZE * entries_per_table();
    let mut n = 0usize;
    let mut va = s & !(PAGE_SIZE - 1);
    while va < e {
        let table_end = (va | (span - 1)).saturating_add(1).min(e);
        if let Ok(p) = walk(root, va, false) {
            for k in 0..(table_end - va).div_ceil(PAGE_SIZE) {
                // SAFETY: entries `vpn0(va) + k` of one leaf table, all below
                // `table_end`, the table's own end.
                let w = unsafe { core::ptr::read_volatile(p.add(k)) };
                if ARCH.pte_is_valid(w) && ARCH.pte_is_leaf(w, 0) {
                    n += 1;
                }
            }
        }
        if table_end == va { break; }
        va = table_end;
    }
    n
}

/// Map a virtual address to a physical address with the given permissions.
pub fn map(pt_phys: usize, vaddr: usize, paddr: usize, flags: PagePerms) -> KResult<()> {
    // Placed here, at the mapper, and not in each syscall that calls it. Seven
    // paths reach a user page table this way -- `sys_mmap`, `sys_alloc_demand`,
    // `sys_brk`, the shm and mmio window mappers, the ELF loader and the COW
    // fork -- and only some of them carry a VA ceiling. A ceiling is the wrong
    // instrument anyway: it encodes where one board's MMIO happens to start,
    // and the tables a user page table borrows are a fact about the page
    // table, not about the address.
    if write_would_enter_kernel_table(pt_phys, vaddr) {
        return Err(KernelError::AlreadyMapped);
    }
    if vaddr & (PAGE_SIZE - 1) != 0 || paddr & (PAGE_SIZE - 1) != 0 {
        return Err(KernelError::NotAligned);
    }

    let pte_ptr = walk(pt_phys, vaddr, true)?;
    let old = unsafe { core::ptr::read_volatile(pte_ptr) };
    if ARCH.pte_is_valid(old) {
        return Err(KernelError::AlreadyMapped);
    }

    let pte = ARCH.pte_make_leaf(paddr, flags, 0).map_err(mmu_error_to_kernel_error)?
        | kernel_global_bit(pt_phys, vaddr);
    // By CAS from the word read above (N12i), as `map_mega` and the merge do:
    // in a level-0 table the root shares with the kernel-half merge, the
    // push (`fill_empty`) or another thread may have installed a leaf here
    // since that read; a plain store would overwrite it. `old` may be a
    // demand marker, which this replaces as it did before.
    // SAFETY: `walk` returned an aligned entry of a live table page, and
    // `AtomicU64` has the layout of the `u64` word.
    let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
    crate::pte_install::install(slot, old, pte).map_err(|_| KernelError::AlreadyMapped)
}

/// A level-1 leaf ("megapage"): 2 MiB at a 4 KiB base page, 32 MiB at an
/// aarch64 16 KiB granule, 512 MiB at 64 KiB.
pub const MEGA_SIZE: usize = 1 << L1_SHIFT;
/// A level-2 leaf. `init` does not create these, but `for_each_leaf_outside_image`
/// handles them so a future change that does cannot silently skip a gigabyte.
pub const GIGA_SIZE: usize = 1 << L2_SHIFT;
const _: () = assert!(PAGE_SHIFT != 12 || (MEGA_SIZE == 2 * 1024 * 1024 && GIGA_SIZE == 512 * MEGA_SIZE));

/// Map a 2 MiB megapage (leaf PTE at L1 level).
///
/// Both `vaddr` and `paddr` must be 2 MiB aligned.
pub fn map_mega(pt_phys: usize, vaddr: usize, paddr: usize, flags: PagePerms) -> KResult<()> {
    if vaddr & (MEGA_SIZE - 1) != 0 || paddr & (MEGA_SIZE - 1) != 0 {
        return Err(KernelError::NotAligned);
    }

    // Walk L2 to find/create the L1 table
    let (l2t, kt) = l2_table_alloc(pt_phys, vaddr)?;
    let vpn2 = ARCH.vpn(vaddr, 2);
    let l2_pte = pt_word(l2t, vpn2).load(Ordering::Acquire);

    let l1_pt = if ARCH.pte_is_valid(l2_pte) {
        if ARCH.pte_is_leaf(l2_pte, 2) {
            return Err(KernelError::AlreadyMapped); // gigapage here
        }
        ARCH.pte_phys(l2_pte)
    } else {
        let new_pt = alloc_table(pt_phys)?;
        let new_pte = ARCH.pte_make_table(new_pt.as_usize());
        // By CAS (N12h), as in `walk`: the kernel-half merge or another
        // thread of this process may install this word meanwhile; the loser
        // frees its table and follows the winner's.
        match crate::pte_install::install(pt_word(l2t, vpn2), l2_pte, new_pte) {
            Ok(()) => new_pt.as_usize(),
            Err(cur) => {
                let _ = pmm::free_page(new_pt);
                let _ = table_charge(pt_phys, false);
                if !ARCH.pte_is_table(cur, 2) {
                    return Err(KernelError::AlreadyMapped);
                }
                ARCH.pte_phys(cur)
            }
        }
    };
    // N12i: the level-1 table this leaf goes into must be the root's own, not
    // the kernel's (a kernel-only slot the push linked after the caller's
    // check): a USER leaf there would map in every address space.
    if kt != 0 {
        kernel_shadow_step(kt, vpn2, 2, l1_pt)?;
    }

    // Write leaf PTE at L1 (megapage)
    let vpn1 = ARCH.vpn(vaddr, 1);
    let l1 = pt_word(l1_pt, vpn1);
    let old = l1.load(Ordering::Relaxed);
    if ARCH.pte_is_valid(old) {
        return Err(KernelError::AlreadyMapped);
    }

    let pte = ARCH.pte_make_leaf(paddr, flags, 1).map_err(mmu_error_to_kernel_error)?
        | kernel_global_bit(pt_phys, vaddr);
    // By CAS (N12h): a kernel-half merge into this block may have installed
    // its L0 table since the check above; never overwrite it.
    crate::pte_install::install(l1, old, pte).map_err(|_| KernelError::AlreadyMapped)
}

/// Unmap a single 4 KiB virtual page.
///
/// If `vaddr` falls inside a 2 MiB megapage, the megapage is split into
/// 512 individual 4 KiB pages first, then the target page is unmapped.
/// This avoids accidentally invalidating the entire 2 MiB region.
/// Add permission bits to an existing **user** leaf mapping, refusing any
/// combination that would produce a writable-executable page.
///
/// Exists because a single 4 KiB page can be shared by two ELF `PT_LOAD`
/// segments: the loader maps the page when the first segment touches it and,
/// until this function existed, never revisited the flags. An ELF laid out as
///
/// ```text
///     LOAD 0x10b48  R    (ends 0x11391 — page 0x11)
///     LOAD 0x11394  RW   (starts    — page 0x11)
/// ```
///
/// therefore ran with page 0x11 read-only, and the first store to a `static
/// mut` living there took a Store/AMO page fault. That is not hypothetical:
/// `userspace/tests/abitest` hit it the first time it ran, and `userspace/tests/captest`
/// has the same layout and survives only because it never writes its failure
/// counter — the bug was latent behind a passing test.
///
/// **W^X is preserved deliberately.** Granting WRITE on a page that already
/// carries EXEC is refused, so an `.rodata`/`.data` overlap can be repaired
/// while a `.text`/`.data` overlap still cannot — the second is a genuinely
/// unsafe layout and should fail loudly rather than silently produce a W+X
/// page. Returns `Err(KernelError::InvalidArg)` in that case.
///
/// Wave 15: the loader now refuses, before it gets here, an image in which
/// two segments mapped differently share a page
/// (`elf_bounds::check_page_sharing`), so the widening finds the bits already
/// there; this stays the backstop for W^X on a shared page.
///
/// Only ever widens: bits already present are kept, and the USER bit is
/// required up front so this cannot be aimed at a kernel mapping.
///
/// **Verified true, not just asserted (2026-09-06 audit).** Two refusals
/// below make it hold: `if level != 0` at the leaf check rejects any
/// superpage — where the kernel's merged, non-`USER` entries appear in a user
/// page table, and where a locked row's `USER` region is (Kconfig
/// `LOCKED_HUGE_LEAVES`, fixed read-write for life; see the walk comment
/// right below) — and
/// `if !f.user` rejects any L0 leaf that is not already
/// user-owned. Between the two, the only PTE this function can ever write
/// through is one the user-image mapper produced. `vmm.rs`'s teardown audit
/// (`destroy_user_pagetable`'s per-arm enumeration, "not that guard" —
/// search for this function's name there) independently re-derives the same
/// two lines as the reason this one is not `write_would_enter_kernel_table`
/// and does not need to be; the two comments are meant to be read together.
pub fn add_user_leaf_perms(pt_phys: usize, vaddr: usize, add: PagePerms) -> KResult<()> {
    let mut pt = pt_phys;
    // Walk to the leaf. Only L0 leaves are produced by the user-image mapper,
    // so a superpage here is the kernel's merged entries or a locked row's
    // region (`map_user_mega_range`, read-write for the task's life): not
    // ours to widen either way.
    for level in (0..root_level() + 1).rev() {
        let vpn = ARCH.vpn(vaddr, level);
        let pte_ptr = (crate::addr::phys_to_virt(pt + vpn * 8)) as *mut u64;
        let pte: u64 = unsafe { core::ptr::read_volatile(pte_ptr) };
        if !ARCH.pte_is_valid(pte) { return Err(KernelError::InvalidArg); }
        if ARCH.pte_is_leaf(pte, level) {
            if level != 0 { return Err(KernelError::InvalidArg); }
            let f = ARCH.pte_perms(pte);
            if !f.user { return Err(KernelError::InvalidArg); }
            if add.write && f.exec {
                return Err(KernelError::InvalidArg);
            }
            // Only WRITE/EXEC ever widen; every other field is carried over
            // from the existing leaf unchanged — the shape `f | add` had when
            // `add` was a `PteFlags` bitmask (VALID/READ/USER in `add` were
            // always already set in `f`, so OR-ing them was a no-op; A/D are
            // not part of the caller's `add` at all).
            let merged = PagePerms { write: f.write || add.write, exec: f.exec || add.exec, ..f };
            if merged == f { return Ok(()); } // already sufficient
            let new_word = match ARCH.pte_make_leaf(ARCH.pte_phys(pte), merged, level) {
                Ok(w) => w | keep_global(pte),
                Err(e) => return Err(mmu_error_to_kernel_error(e)),
            };
            unsafe {
                core::ptr::write_volatile(pte_ptr, new_word);
            }
            ARCH.flush_tlb_page(vaddr);
            return Ok(());
        }
        pt = ARCH.pte_phys(pte);
    }
    Err(KernelError::InvalidArg)
}

/// Remove the 4 KiB translation for `vaddr` from the table rooted at
/// `pt_phys` — a USER address space — and shoot it down on every hart that may
/// hold it (`Mmu::tlb_shootdown`). The single-page user removals go through
/// here — shm unshare, the io_ring page, `mmap`'s unwind, the MMIO-map
/// rollback; `munmap` uses [`unmap_user_range_and_free`], which batches the
/// same shootdown. A caller may free the frame the PTE named once this returns.
pub fn unmap(pt_phys: usize, vaddr: usize) {
    unmap_inner(pt_phys, vaddr, true);
}

/// [`unmap`] for the KERNEL's own table (the task-stack guard pages), with the
/// old local-only invalidation. The satp-root hart mask the shootdown uses
/// cannot describe a kernel mapping — every user table shares the kernel's
/// upper levels, so every hart may hold it — and the only caller runs once at
/// boot. Not a user-mapping path; kept separate so `unmap` can be exact.
pub fn unmap_kernel(pt_phys: usize, vaddr: usize) {
    unmap_inner(pt_phys, vaddr, false);
}

fn unmap_inner(pt_phys: usize, vaddr: usize, shoot: bool) {
    // Silent no-op rather than an error because `unmap` already returns
    // nothing and every caller treats "not mapped" as success. What must not
    // happen is the WRITE: clearing a PTE in a table the kernel owns is the
    // same store whether the slot was full or empty, and an empty slot in a
    // kernel-owned L0 is still the kernel's.
    if write_would_enter_kernel_table(pt_phys, vaddr) {
        return;
    }
    // Walk L2 → L1 to detect megapage before reaching walk().
    let l2t = l2_table(pt_phys, vaddr);
    if no_l2(l2t) { return; }
    let vpn2 = ARCH.vpn(vaddr, 2);
    let l2_pte = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(l2t + vpn2 * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l2_pte) || ARCH.pte_is_leaf(l2_pte, 2) {
        // Not mapped, or gigapage (1 GiB) — cannot split, just return.
        return;
    }
    let l1_pt = ARCH.pte_phys(l2_pte);
    let vpn1 = ARCH.vpn(vaddr, 1);
    let l1_pte_ptr = (crate::addr::phys_to_virt(l1_pt + vpn1 * 8)) as *mut u64;
    let l1_pte = unsafe { core::ptr::read_volatile(l1_pte_ptr) };

    if !ARCH.pte_is_valid(l1_pte) {
        return; // Not mapped.
    }
    // N12i: on a user root, never a copy of the kernel's own translation: a
    // device window the kernel-half merge put in the task's own table (an L1
    // fill here, `fill_empty` below). The kernel resolves that device through
    // this table while the task is current, so the task must not split it or
    // clear it.
    let user_root = writer_shadow_root(pt_phys) != 0;
    if user_root && ARCH.pte_is_leaf(l1_pte, 1) && !user_may_modify(l1_pte, vaddr, 1) {
        return;
    }

    if ARCH.pte_is_leaf(l1_pte, 1) {
        // Megapage at L1 — must split into 512 × 4 KiB pages before unmapping.
        let mega_base = ARCH.pte_phys(l1_pte);
        let flags = ARCH.pte_perms(l1_pte);

        let l0_pt = match pmm::alloc_page_zone(Zone::PageTable) {
            Ok(p) => p.as_usize(),
            Err(_) => return, // OOM — cannot split, bail out.
        };

        // Populate L0 table: 512 PTEs mapping each 4 KiB page of the megapage.
        for i in 0..entries_per_table() {
            let paddr = mega_base + i * PAGE_SIZE;
            // `flags` decoded from a valid leaf is always representable
            // again — `pte_make_leaf` only rejects unaligned `paddr` or
            // perms an ISA cannot express, neither of which changed here.
            let pte = ARCH.pte_make_leaf(paddr, flags, 0).expect("re-encoding a decoded leaf")
                | keep_global(l1_pte);
            unsafe { core::ptr::write_volatile((crate::addr::phys_to_virt(l0_pt + i * 8)) as *mut u64, pte) };
        }

        // Replace the L1 leaf PTE with a pointer to the new L0 table.
        let new_l1_pte = ARCH.pte_make_table(l0_pt);
        unsafe { core::ptr::write_volatile(l1_pte_ptr, new_l1_pte) };

        // Full TLB flush — the megapage TLB entry must be invalidated.
        if shoot {
            ARCH.tlb_shootdown(pt_phys, 0, azos_arch_api::TLB_ALL);
        } else {
            ARCH.flush_tlb_all();
        }
    }

    // Now walk normally to the L0 PTE and unmap the single 4 KiB page.
    if let Ok(pte_ptr) = walk(pt_phys, vaddr, false) {
        if user_root && !user_may_modify(unsafe { core::ptr::read_volatile(pte_ptr) }, vaddr, 0) {
            return;
        }
        unsafe { core::ptr::write_volatile(pte_ptr, ARCH.pte_empty()) };
        if shoot {
            ARCH.tlb_shootdown(pt_phys, vaddr, PAGE_SIZE);
        } else {
            ARCH.flush_tlb_page(vaddr);
        }
    }
}

/// The trait level of the leaf that maps `vaddr` under `pt_phys` (0 for a
/// page, 1 for a 2 MiB leaf at 4 KiB, 2 for a 1 GiB one), or `None` when
/// nothing maps it. A plain walk, for the exec-time evidence that a locked
/// region really is mapped with level-1 leaves (Kconfig `LOCKED_HUGE_LEAVES`).
pub fn leaf_level(pt_phys: usize, vaddr: usize) -> Option<usize> {
    let mut pt = pt_phys;
    for level in (0..root_level() + 1).rev() {
        let pte: u64 = unsafe {
            core::ptr::read_volatile((crate::addr::phys_to_virt(pt + ARCH.vpn(vaddr, level) * 8)) as *const u64)
        };
        if !ARCH.pte_is_valid(pte) { return None; }
        if ARCH.pte_is_leaf(pte, level) { return Some(level); }
        pt = ARCH.pte_phys(pte);
    }
    None
}

/// Does any level-1 USER leaf map an address in `[start, end)` of the user
/// table `pt_phys`? Such a leaf is a locked row's region (Kconfig
/// `LOCKED_HUGE_LEAVES`), which `sys_munmap` must refuse rather than report
/// as unmapped: `take_user_leaf` leaves it alone, so a "successful" munmap
/// would remove nothing.
pub fn user_range_has_mega_leaf(pt_phys: usize, start: usize, end: usize) -> bool {
    let mut va = start & !(MEGA_SIZE - 1);
    while va < end {
        if leaf_level(pt_phys, va) == Some(1)
            && user_leaf(pt_phys, va).map_or(false, |(w, _)| ARCH.pte_perms(w).user)
        {
            return true;
        }
        va = match va.checked_add(MEGA_SIZE) { Some(v) => v, None => break };
    }
    false
}

/// [`user_range_has_mega_leaf`] behind Kconfig `LOCKED_HUGE_LEAVES`: `false`
/// without a walk when the option is off (the constant folds once inlined),
/// so `sys_munmap` pays nothing for a region that cannot exist.
#[inline]
pub fn locked_region_in_range(pt_phys: usize, start: usize, end: usize) -> bool {
    azos_limits::LOCKED_HUGE_LEAVES && user_range_has_mega_leaf(pt_phys, start, end)
}

/// Map `[vaddr, vaddr + len)` of a USER table to `[paddr, ..)` with level-1
/// (2 MiB at 4 KiB) leaves: a locked row's boot-reserved region (Kconfig
/// `LOCKED_HUGE_LEAVES`). The only path that puts a level-1 leaf in a user
/// table. Refuses — before writing anything — unaligned or empty ranges, a
/// slot whose table is borrowed from the kernel (a write there would land in
/// the kernel's own table), and any slot already mapped.
pub fn map_user_mega_range(pt_phys: usize, vaddr: usize, paddr: usize, len: usize, flags: PagePerms) -> KResult<()> {
    if len == 0 || len & (MEGA_SIZE - 1) != 0 || vaddr & (MEGA_SIZE - 1) != 0 || paddr & (MEGA_SIZE - 1) != 0 {
        return Err(KernelError::NotAligned);
    }
    if !flags.user || flags.exec {
        return Err(KernelError::InvalidArg);
    }
    // Every slot's level-1 entry must be EMPTY — not merely "nothing at the
    // slot's first byte": a table there with one page anywhere in its 2 MiB
    // would make `map_mega` refuse halfway, after earlier slots were written.
    let mut off = 0;
    while off < len {
        if write_would_enter_kernel_table(pt_phys, vaddr + off) || !l1_slot_is_empty(pt_phys, vaddr + off) {
            return Err(KernelError::AlreadyMapped);
        }
        off += MEGA_SIZE;
    }
    off = 0;
    while off < len {
        if let Err(e) = map_mega(pt_phys, vaddr + off, paddr + off, flags) {
            // An allocation failure, or a slot another writer filled since
            // the check (a lost CAS, N12h): take back the leaves this call
            // wrote.
            let mut undo = 0;
            while undo < off {
                if let Ok(p) = walk(pt_phys, vaddr + undo, false) {
                    unsafe { core::ptr::write_volatile(p, ARCH.pte_empty()) };
                }
                undo += MEGA_SIZE;
            }
            return Err(e);
        }
        off += MEGA_SIZE;
    }
    Ok(())
}

/// Is the level-1 entry that would map `vaddr`'s 2 MiB slot empty (no leaf,
/// no table)? `true` also when the root has no table for it yet. `pub` for
/// the ktest `user_mega_refused_in_a_shared_kernel_table` (N12i).
pub fn l1_slot_is_empty(pt_phys: usize, vaddr: usize) -> bool {
    let l2t = l2_table(pt_phys, vaddr);
    if no_l2(l2t) { return true; }
    let l2: u64 = unsafe {
        core::ptr::read_volatile((crate::addr::phys_to_virt(l2t + ARCH.vpn(vaddr, 2) * 8)) as *const u64)
    };
    if !ARCH.pte_is_valid(l2) { return true; }
    if ARCH.pte_is_leaf(l2, 2) { return false; }
    let l1: u64 = unsafe {
        core::ptr::read_volatile((crate::addr::phys_to_virt(ARCH.pte_phys(l2) + ARCH.vpn(vaddr, 1) * 8)) as *const u64)
    };
    !ARCH.pte_is_valid(l1)
}

/// Page-table frames under `root`: the root plus every table reachable
/// from it (leaves are not counted, whatever their level). For the boot-time
/// granule report; on riscv64 a user table's count includes the kernel
/// tables its merged entries point at.
pub fn table_frames(root: usize) -> usize {
    if root == 0 { return 0; }
    table_frames_at(root, root_level())
}

/// `pt` (a table at `level`) plus every table below it; a level-1 table's
/// level-0 children are counted, not read.
fn table_frames_at(pt: usize, level: usize) -> usize {
    let mut n = 1usize;
    let slots = if level == root_level() { root_entries() } else { entries_per_table() };
    for i in 0..slots {
        let e: u64 = unsafe {
            core::ptr::read_volatile((crate::addr::phys_to_virt(pt + i * 8)) as *const u64)
        };
        if !ARCH.pte_is_table(e, level) { continue; }
        n += if level == 1 { 1 } else { table_frames_at(ARCH.pte_phys(e), level - 1) };
    }
    n
}

/// Translate a virtual address to a physical address.
/// Returns `None` if not mapped.
/// Handles pages and level-1/level-2 leaves (2 MiB / 1 GiB at 4 KiB) correctly.
pub fn translate(pt_phys: usize, vaddr: usize) -> Option<usize> {
    // Walk inline to detect megapages at each level.
    let mut pt = l2_table(pt_phys, vaddr);
    if no_l2(pt) { return None; }

    // L2
    let vpn2 = ARCH.vpn(vaddr, 2);
    let l2_pte = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + vpn2 * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l2_pte) { return None; }
    if ARCH.pte_is_leaf(l2_pte, 2) {
        // 1 GiB gigapage
        return Some(ARCH.pte_phys(l2_pte) + (vaddr & (GIGA_SIZE - 1)));
    }
    pt = ARCH.pte_phys(l2_pte);

    // L1
    let vpn1 = ARCH.vpn(vaddr, 1);
    let l1_pte = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + vpn1 * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l1_pte) { return None; }
    if ARCH.pte_is_leaf(l1_pte, 1) {
        // 2 MiB megapage
        return Some(ARCH.pte_phys(l1_pte) + (vaddr & (MEGA_SIZE - 1)));
    }
    pt = ARCH.pte_phys(l1_pte);

    // L0
    let vpn0 = ARCH.vpn(vaddr, 0);
    let l0_pte = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + vpn0 * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l0_pte) { return None; }
    Some(ARCH.pte_phys(l0_pte) + (vaddr & (PAGE_SIZE - 1)))
}

/// Translate a **user** virtual address for a `copy_from_user` /
/// `copy_to_user` access, enforcing the permission bits that separate user
/// memory from kernel/MMIO memory.
///
/// Unlike [`translate`] (which checks only `VALID`), this rejects any address
/// whose leaf PTE lacks the `USER` bit. That distinction is load-bearing:
/// [`copy_kernel_entries_to_user`] merges every kernel L2/L1 entry — kernel
/// text/data **and all MMIO** (UART, CLINT, PLIC, …) — into every user page
/// table. Those pages are `VALID` but not `USER`, so a plain `translate` of a
/// kernel VA (e.g. `0x1000_0000` UART, `0x8020_xxxx` kernel text) succeeds and
/// hands the syscall path a pointer it will read or write on the caller's
/// behalf — a sandbox escape / arbitrary-write primitive. Requiring `USER`
/// closes both directions.
///
/// The `USER` bit is the authoritative user/kernel boundary here; a numeric
/// `vaddr < USER_STACK_TOP` split would be both redundant (the bit already
/// separates them) and insufficient (MMIO at `0x0200_0000` / `0x1000_0000`
/// lives *below* any such split).
///
/// Permission checked on the leaf PTE:
///   - always: `VALID` + `USER` + `READ`
///   - when `write`: also `WRITE`. A user page whose `WRITE` bit is clear but
///     which carries the OS-defined `COW` marker (a shared page from a
///     copy-on-write `fork`) is broken via [`crate::cow::handle_cow_fault`]
///     and re-translated, so a legitimate post-fork write copies into a
///     private page instead of spuriously failing (or corrupting the shared
///     page, which is what the old unchecked `translate` path did). A
///     genuinely read-only user page (e.g. the vDSO, `.text`) is rejected.
///
/// Returns the physical address on success, `None` on any permission failure
/// or unmapped page. Never panics.
pub fn translate_user(pt_phys: usize, vaddr: usize, write: bool) -> Option<usize> {
    match user_leaf(pt_phys, vaddr) {
        Some((pte, mask)) => user_leaf_ok(pt_phys, vaddr, pte, mask, write),
        // A tail call with the caller's own arguments: nothing stays live
        // across it, so the hit path above keeps the prologue it had before
        // (a miss handled inline cost every hit three extra saved registers,
        // measured on riscv64).
        None => translate_user_reserved(pt_phys, vaddr, write),
    }
}

/// [`translate_user`]'s miss: wave 14 (DEMANDPAGE). A reserved page (`mmap`
/// region or `sys_alloc_demand` marker) not touched yet is committed here, as
/// the fault the copy would have taken from ring 3 would commit it — a
/// `read()` into fresh `mmap` memory must not answer EFAULT — and the
/// translation is then done afresh.
#[cold]
#[inline(never)]
fn translate_user_reserved(pt_phys: usize, vaddr: usize, write: bool) -> Option<usize> {
    handle_demand_fault(pt_phys, vaddr).ok()?;
    let (pte, mask) = user_leaf(pt_phys, vaddr)?;
    user_leaf_ok(pt_phys, vaddr, pte, mask, write)
}

/// The physical address of `vaddr` when its user page is ALREADY writable:
/// never breaks copy-on-write, never commits a reserved page, never
/// allocates nor shoots TLBs down (wave 15 N10b, for a futex word under a
/// spinlock; Linux `futex_atomic_cmpxchg_inatomic`). `None` otherwise: the
/// caller drops its lock, faults the page in with [`translate_user`]
/// (`write = true`) and retries.
pub fn translate_user_writable_nofault(pt_phys: usize, vaddr: usize) -> Option<usize> {
    let (pte, mask) = user_leaf(pt_phys, vaddr)?;
    let f = ARCH.pte_perms(pte);
    (f.user && f.read && f.write).then(|| ARCH.pte_phys(pte) + (vaddr & mask))
}

/// Would a write to `vaddr` be permitted — **without breaking copy-on-write?**
///
/// [`translate_user`] with `write = true` is not a question, it is an action:
/// on a COW leaf it calls `crate::cow::handle_cow_fault`, which ALLOCATES a
/// private copy. That is right for a caller about to write, and wrong for one
/// that is only checking, which then pays for a page it may never use — and
/// leaves a function named like a query having mutated the address space.
///
/// This answers the same question and changes nothing: a COW leaf reports
/// writable, because a write to it WILL succeed (the fault handler runs then).
/// The caller that actually writes still goes through `copy_to_user`, which
/// breaks the COW at the moment it is needed.
///
/// Returns `false` for a leaf that is not USER-readable, and for a read-only
/// page that is not COW — the genuinely-not-writable case.
pub fn user_write_would_be_permitted(pt_phys: usize, vaddr: usize) -> bool {
    match user_leaf(pt_phys, vaddr) {
        Some((pte, _)) => {
            let f = ARCH.pte_perms(pte);
            f.user && f.read && (f.write || ARCH.pte_is_cow(pte))
        }
        // Wave 14: a reserved page is writable if its region (or demand
        // marker) says so; the copy that follows commits it.
        None => reserved_write_permitted(pt_phys, vaddr),
    }
}

#[cold]
#[inline(never)]
fn reserved_write_permitted(pt_phys: usize, vaddr: usize) -> bool {
    if in_null_guard(vaddr) || write_would_enter_kernel_table(pt_phys, vaddr) {
        return false;
    }
    if let Ok(p) = walk(pt_phys, vaddr & !(PAGE_SIZE - 1), false) {
        // SAFETY: `walk` returned an aligned entry of a live table page.
        let pte = unsafe { core::ptr::read_volatile(p) };
        if !ARCH.pte_is_valid(pte) && ARCH.pte_is_demand(pte) {
            return ARCH.pte_demand_perms(pte).write;
        }
    }
    crate::pager::reserved_writable(pt_phys, vaddr) == Some(true)
}

/// The leaf PTE `vaddr` resolves to in `pt_phys`, and its in-page offset mask.
///
/// Extracted so [`translate_user`] and [`user_write_would_be_permitted`] share
/// ONE walk: two copies of a three-level page-table descent is two places for a
/// level to be read at the wrong shift, and only one of them would have a test
/// pointing at it.
fn user_leaf(pt_phys: usize, vaddr: usize) -> Option<(u64, usize)> {
    let mut pt = l2_table(pt_phys, vaddr);
    if no_l2(pt) { return None; }

    // L2 — kernel gigapages reach this leaf (copied wholesale into user PTs),
    // so the USER check must be applied here too.
    let l2_pte = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + ARCH.vpn(vaddr, 2) * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l2_pte) { return None; }
    if ARCH.pte_is_leaf(l2_pte, 2) { return Some((l2_pte, GIGA_SIZE - 1)); }
    pt = ARCH.pte_phys(l2_pte);

    // L1 — kernel megapages (MMIO, kernel image) reach this leaf.
    let l1_pte = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + ARCH.vpn(vaddr, 1) * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l1_pte) { return None; }
    if ARCH.pte_is_leaf(l1_pte, 1) { return Some((l1_pte, MEGA_SIZE - 1)); }
    pt = ARCH.pte_phys(l1_pte);

    // L0 — ordinary 4 KiB user pages (and any 4 KiB kernel leaves).
    let l0_pte = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + ARCH.vpn(vaddr, 0) * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l0_pte) { return None; }
    Some((l0_pte, PAGE_SIZE - 1))
}

/// Permission gate for one leaf PTE reached by [`translate_user`].
/// `offset_mask` selects the in-page offset for the leaf's page size.
#[inline]
fn user_leaf_ok(
    pt_phys: usize,
    vaddr: usize,
    pte: u64,
    offset_mask: usize,
    write: bool,
) -> Option<usize> {
    let f = ARCH.pte_perms(pte);
    // Reject kernel/MMIO (no USER bit) and unreadable pages outright.
    if !f.user || !f.read {
        return None;
    }
    if write && !f.write {
        // A copy-on-write page: break it (allocate a private copy) and re-walk.
        // Any other read-only user page is genuinely not writable → reject.
        if ARCH.pte_is_cow(pte) {
            crate::cow::handle_cow_fault(pt_phys, vaddr).ok()?;
            // Re-translate: the fresh leaf now has WRITE set. Guard against a
            // pathological re-fault by using the plain permission read.
            let mut pt = l2_table(pt_phys, vaddr);
            if no_l2(pt) { return None; }
            let l2 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + ARCH.vpn(vaddr, 2) * 8)) as *const u64) };
            if !ARCH.pte_is_valid(l2) { return None; }
            if ARCH.pte_is_leaf(l2, 2) {
                return if ARCH.pte_perms(l2).write {
                    Some(ARCH.pte_phys(l2) + (vaddr & (GIGA_SIZE - 1)))
                } else { None };
            }
            pt = ARCH.pte_phys(l2);
            let l1 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + ARCH.vpn(vaddr, 1) * 8)) as *const u64) };
            if !ARCH.pte_is_valid(l1) { return None; }
            if ARCH.pte_is_leaf(l1, 1) {
                return if ARCH.pte_perms(l1).write {
                    Some(ARCH.pte_phys(l1) + (vaddr & (MEGA_SIZE - 1)))
                } else { None };
            }
            pt = ARCH.pte_phys(l1);
            let l0 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(pt + ARCH.vpn(vaddr, 0) * 8)) as *const u64) };
            if !ARCH.pte_is_valid(l0) || !ARCH.pte_perms(l0).write { return None; }
            return Some(ARCH.pte_phys(l0) + (vaddr & (PAGE_SIZE - 1)));
        }
        return None;
    }
    Some(ARCH.pte_phys(pte) + (vaddr & offset_mask))
}

/// Switch to a page table (writes SATP on RISC-V, TTBR0_EL1 on aarch64).
pub fn switch_pagetable(pt_phys: usize) {
    ARCH.switch_pt(pt_phys, 0);
}

/// Get the kernel page table physical address.
/// Forget the kernel page table. **Host test harnesses only.**
///
/// Not a kernel operation and compiled out on the target: on a board, losing
/// the kernel page table mid-flight is the fault this file exists to prevent.
///
/// Host suites recycle the page arena between tests, and a recycled page is
/// handed straight back out. `KERNEL_PT` survived that reset holding the
/// physical address of a page some later test now owns, so the next walk read
/// another test's data as page-table entries -- returning arbitrary answers on
/// a good day and segfaulting on a bad one. The failure looked like a bug in
/// whichever test ran second, which is the worst shape a harness defect can
/// take.
///
/// Nothing read `KERNEL_PT` outside the two tests that set it, so this sat
/// dormant until `va_is_kernel_mapped` gave every memory syscall a reason to
/// consult it.
#[cfg(not(target_os = "none"))]
pub fn shim_forget_kernel_pt() {
    *KERNEL_PT.lock() = 0;
    KERNEL_ROOT.store(0, Ordering::Relaxed);
}

pub fn kernel_pagetable() -> usize {
    *KERNEL_PT.lock()
}

/// Recursively destroy a page table, freeing all intermediate PT pages.
/// Does NOT free leaf (mapped) physical pages.
pub fn destroy_pagetable(pt_phys: usize) {
    // Out of the merged-root roster before any table is freed, whatever the
    // caller (`pt_release` already cleared it; a direct caller may not have).
    meta_set_merged(pt_phys, false);
    destroy_pagetable_at_level(pt_phys, 2)
}

/// [`destroy_pagetable`], tracking `level` through the recursion so
/// `pte_is_leaf` is asked at the level it is actually reading — the root
/// call is level 2 (RISC-V L2), its recursion into a table pointer is
/// level 1, and so on. RISC-V's leaf check ignores `level` entirely, so
/// this was equivalent to a level-blind recursion before the page-table
/// abstraction; aarch64's genuinely needs the right level at each depth.
fn destroy_pagetable_at_level(pt_phys: usize, level: usize) {
    if pt_phys == 0 {
        return;
    }
    for i in 0..entries_per_table() {
        let pte_ptr = (crate::addr::phys_to_virt(pt_phys + i * 8)) as *const u64;
        let pte = unsafe { core::ptr::read_volatile(pte_ptr) };
        if ARCH.pte_is_valid(pte) && !ARCH.pte_is_leaf(pte, level) && level > 0 {
            // Intermediate table — recurse one level down.
            destroy_pagetable_at_level(ARCH.pte_phys(pte), level - 1);
        }
    }
    // Free this page table page
    let _ = pmm::free_page(PhysAddr::new(pt_phys));
}

/// Split megapages covering a range into 4K pages.
///
/// This is necessary before enforce_wx(), because different kernel sections
/// (text, rodata, data) within the same 2 MiB megapage need different
/// permissions. A megapage is one PTE covering 2 MiB — we can't set
/// text=RX and data=RW within the same PTE.
///
/// For each megapage that overlaps [start, end): allocate an L0 table,
/// create 512 individual 4K PTEs with the same physical addresses,
/// and replace the megapage L1 entry with a pointer to the L0 table.
/// Returns the number of megapages it could NOT split because `alloc_page`
/// failed. A non-zero count means `enforce_wx` is about to write 4 KiB flags
/// into a 2 MiB leaf and retag the whole thing — `verify_wx` reports the same
/// megapages as `UnsplitMegapage`, so the two agree by construction, but the
/// caller gets the number before any damage rather than after.
pub fn split_mega_range(start: usize, end: usize) -> usize {
    let kpt = *KERNEL_PT.lock();

    // Align to megapage boundaries
    let mega_start = start & !(MEGA_SIZE - 1);
    let mega_end = (end + MEGA_SIZE - 1) & !(MEGA_SIZE - 1);

    let mut unsplit = 0usize;
    let mut addr = mega_start;
    while addr < mega_end {
        // Check if this address is mapped as a megapage
        let vpn2 = ARCH.vpn(addr, 2);
        let vpn1 = ARCH.vpn(addr, 1);

        let l2t = l2_table(kpt, addr);
        if no_l2(l2t) {
            addr += MEGA_SIZE;
            continue;
        }
        let l2_pte_ptr = (crate::addr::phys_to_virt(l2t + vpn2 * 8)) as *const u64;
        let l2_pte = unsafe { core::ptr::read_volatile(l2_pte_ptr) };
        if !ARCH.pte_is_valid(l2_pte) || ARCH.pte_is_leaf(l2_pte, 2) {
            addr += MEGA_SIZE;
            continue;
        }

        let l1_pt = ARCH.pte_phys(l2_pte);
        let l1_pte_ptr = (crate::addr::phys_to_virt(l1_pt + vpn1 * 8)) as *mut u64;
        let l1_pte = unsafe { core::ptr::read_volatile(l1_pte_ptr) };

        if !ARCH.pte_is_valid(l1_pte) || !ARCH.pte_is_leaf(l1_pte, 1) {
            // Not a megapage (already 4K or invalid) — skip
            addr += MEGA_SIZE;
            continue;
        }

        // This is a megapage at L1. Split it into 512 × 4K pages.
        let mega_phys = ARCH.pte_phys(l1_pte);
        // Carry the megapage's OWN permissions down to the 512 leaves. This
        // used to read `PteFlags::KERNEL_RWX; // preserve original flags`,
        // which preserved nothing — it forced RWX onto every page of every
        // megapage it touched, including the part past `kernel_end` that
        // `enforce_wx` never revisits. Today `init` maps all of RAM RWX so
        // the constant happened to equal the truth; the comment was a
        // promise the code did not keep, and the first mapping created with
        // anything else would have been silently widened.
        let mega_flags = ARCH.pte_perms(l1_pte);

        // Allocate a new L0 page table
        let l0_page = match pmm::alloc_page_zone(Zone::PageTable) {
            Ok(p) => p,
            Err(_) => {
                // OOM — this megapage stays a 2 MiB leaf. Counted, not
                // swallowed: leaving it silent is what made the boot log say
                // "W^X enforced" over an unenforced kernel.
                unsplit += 1;
                addr += MEGA_SIZE;
                continue;
            }
        };
        let l0_pt = l0_page.as_usize();

        // Fill L0 with 512 entries pointing to consecutive 4K pages
        for i in 0..PTES {
            let pa = mega_phys + i * PAGE_SIZE;
            let pte = ARCH.pte_make_leaf(pa, mega_flags, 0)
                .expect("re-encoding a decoded leaf at a page-aligned address")
                | keep_global(l1_pte);
            unsafe {
                core::ptr::write_volatile((crate::addr::phys_to_virt(l0_pt + i * 8)) as *mut u64, pte);
            }
        }

        // Replace the L1 megapage entry with a pointer to the L0 table
        let new_l1 = ARCH.pte_make_table(l0_pt);
        unsafe { core::ptr::write_volatile(l1_pte_ptr, new_l1) };

        // Flush TLB for this range
        for i in 0..PTES {
            ARCH.flush_tlb_page(addr + i * PAGE_SIZE);
        }

        addr += MEGA_SIZE;
    }
    unsplit
}

/// Initialize the VMM: create kernel page table with identity mapping.
///
/// `mem_start`: physical RAM start (e.g., 0x8000_0000)
/// `mem_size`: total RAM in bytes
///
/// Uses 2 MiB megapages for the bulk of RAM (reduces PT pages from ~90 to ~2
/// for 128 MiB), with 4 KiB pages for unaligned head/tail regions.
/// The VA the kernel's own mappings live at for a given physical address.
///
/// Identity on riscv64 (one address space, `satp`). On aarch64 the kernel
/// executes in the upper half through `TTBR1_EL1`, so its table must be
/// keyed on the SAME virtual addresses the linker gave its symbols —
/// `crate::addr::phys_to_virt` is that one offset, shared with the linker
/// script and `boot.S` through a single constant.
#[inline]
fn kernel_va(pa: usize) -> usize {
    crate::addr::phys_to_virt(pa)
}

/// The physical end of the RAM [`init`] mapped (0 before it ran).
static RAM_END: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The physical end of the RAM the kernel maps (wave 15: `text_poke` places
/// its alias above it).
pub fn ram_end() -> usize {
    RAM_END.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn init(mem_start: usize, mem_size: usize) -> KResult<()> {
    let kpt = create_pagetable()?;
    *KERNEL_PT.lock() = kpt;
    KERNEL_ROOT.store(kpt, Ordering::Relaxed);

    let mem_end = mem_start + mem_size;
    RAM_END.store(mem_end, core::sync::atomic::Ordering::Relaxed);

    // Phase 1: 4 KiB pages for any unaligned head (mem_start → first 2M boundary)
    let mega_start = (mem_start + MEGA_SIZE - 1) & !(MEGA_SIZE - 1);
    let mut addr = mem_start;
    while addr < mega_start && addr < mem_end {
        let _ = map(kpt, kernel_va(addr), addr, PagePerms::KERNEL_RWX);
        addr += PAGE_SIZE;
    }

    // Phase 2: 2 MiB megapages for the aligned bulk
    let mega_end = mem_end & !(MEGA_SIZE - 1);
    addr = mega_start;
    while addr < mega_end {
        let _ = map_mega(kpt, kernel_va(addr), addr, PagePerms::KERNEL_RWX);
        addr += MEGA_SIZE;
    }

    // Phase 3: 4 KiB pages for any unaligned tail (last partial 2M block)
    while addr < mem_end {
        let _ = map(kpt, kernel_va(addr), addr, PagePerms::KERNEL_RWX);
        addr += PAGE_SIZE;
    }

    // NOTE: MMIO mappings are NOT done here — they are platform-specific
    // and are added by kernel_main() after vmm::init() returns.
    // Use map_mmio_region() for each platform's device addresses.

    Ok(())
}

/// The kernel root, readable without [`KERNEL_PT`]'s lock: [`map`] and
/// [`map_mega`] compare against it while a caller may hold that lock.
static KERNEL_ROOT: AtomicUsize = AtomicUsize::new(0);

/// The first VPN[2] slot no user root reaches, or `usize::MAX` before
/// [`set_user_ceiling`]. Every slot from here up is a kernel-only slot: one
/// L1 table the kernel root owns and [`copy_kernel_entries_to_user`] links
/// (the root PTE copied word for word, never the table) into every user
/// root, so all roots map it identically. Below it are the merge slots,
/// where the kernel's entries sit in the user root's own L1.
static KERNEL_ONLY_FROM: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Kconfig `RV_KERNEL_GLOBAL`: kernel leaves of a kernel-only slot carry the
/// Sv39 G bit. riscv64 only: aarch64's kernel half is `TTBR1_EL1` (global by
/// construction), x86_64 would use `PG_GLOBAL` and does not yet.
const KERNEL_GLOBAL: bool = KERNEL_HALF_IN_ROOT && azos_limits::RV_KERNEL_GLOBAL;

/// riscv64: the kernel half lives in the user root's own level-2 table
/// (one `satp`), so kernel-only slots exist there. aarch64 keeps the kernel
/// in `TTBR1_EL1` (its user roots hold device windows above the stack, owned
/// by the root) and x86_64 merges at the PDPT level below a four-level root.
// arch-only: Sv39 is the one layout whose kernel slots sit in the user root.
const KERNEL_HALF_IN_ROOT: bool = cfg!(all(target_arch = "riscv64", target_os = "none"));

/// Record where the user address space ends (`USER_STACK_TOP`, from the
/// board's layout): the slots at and above the one holding `ceiling`'s
/// round-up are kernel-only. Called once by the boot hart before [`init`],
/// so the kernel map is built with G already in place. Slot 0 is never
/// kernel-only (user code links at `0x1_0000`).
pub fn set_user_ceiling(ceiling: usize) {
    if !KERNEL_HALF_IN_ROOT {
        return;
    }
    let span = PAGE_SIZE * entries_per_table() * entries_per_table();
    let slot = ceiling.div_ceil(span).max(1);
    KERNEL_ONLY_FROM.store(slot, Ordering::Relaxed);
}

/// The first kernel-only VPN[2] slot ([`set_user_ceiling`]), `usize::MAX`
/// when none is recorded.
pub fn kernel_only_from() -> usize {
    KERNEL_ONLY_FROM.load(Ordering::Relaxed)
}

/// Whether kernel leaves carry G on this build (Kconfig `RV_KERNEL_GLOBAL`).
pub const fn kernel_global() -> bool {
    KERNEL_GLOBAL
}

/// The G bit for a leaf `map`/`map_mega` writes at `va` into `pt`: set only
/// in the kernel root, only in a kernel-only slot. A merge slot (the
/// kernel's low MMIO beside user code and the user window) never gets it:
/// a G entry matches under any ASID, so it is sound only at a VA every root
/// maps the same way.
#[inline(always)]
fn kernel_global_bit(pt: usize, va: usize) -> u64 {
    if !KERNEL_GLOBAL
        || pt != KERNEL_ROOT.load(Ordering::Relaxed)
        || ARCH.vpn(va, 2) < KERNEL_ONLY_FROM.load(Ordering::Relaxed)
    {
        return 0;
    }
    ARCH.pte_global_bit()
}

/// A leaf re-encoded through `pte_perms` keeps the G bit of the word it
/// replaces (`PagePerms` does not carry it).
#[inline(always)]
fn keep_global(old: u64) -> u64 {
    if KERNEL_GLOBAL { old & ARCH.pte_global_bit() } else { 0 }
}

/// Map the kernel image `[va_start, va_end)` (its link addresses) onto the
/// frames it occupies (`addr::virt_to_phys`), where that differs from the RAM
/// map [`init`] built (x86_64: the image in the top 2 GiB, RAM in the direct
/// map); nothing to do where they are one map. The frames are wherever the
/// loader put the image, so a megapage is used only where the virtual and
/// physical addresses are both 2 MiB-aligned; `KERNEL_RWX` as `init` maps
/// RAM: the W^X pass that follows splits and tightens it. Returns the bytes
/// mapped.
pub fn map_kernel_image(va_start: usize, va_end: usize) -> KResult<usize> {
    if crate::addr::KERNEL_IMAGE_OFFSET == crate::addr::KERNEL_PHYS_TO_VIRT_OFFSET {
        return Ok(0);
    }
    let kpt = *KERNEL_PT.lock();
    let start = va_start & !(PAGE_SIZE - 1);
    let end = (va_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let mut va = start;
    while va < end {
        let pa = crate::addr::virt_to_phys(va);
        if va & (MEGA_SIZE - 1) == 0 && pa & (MEGA_SIZE - 1) == 0 && va + MEGA_SIZE <= end {
            map_mega(kpt, va, pa, PagePerms::KERNEL_RWX)?;
            va += MEGA_SIZE;
        } else {
            map(kpt, va, pa, PagePerms::KERNEL_RWX)?;
            va += PAGE_SIZE;
        }
    }
    Ok(end - start)
}

/// Map an MMIO region with identity mapping (vaddr == paddr).
///
/// Maps `size` bytes of device memory starting at `base` using 4 KiB pages
/// with KERNEL_RW flags (no execute).
/// Device windows the kernel has mapped, recorded so they can be replayed
/// into a task's page table.
///
/// **Why a task's table needs them at all.** On aarch64 the kernel executes
/// from `TTBR1_EL1` while every task switch rewrites `TTBR0_EL1`, and device
/// registers live at LOW physical addresses — the half a task owns. A kernel
/// that touches a device while a user task is current (a `write` syscall
/// reaching the UART, a virtio doorbell on the task's own behalf) resolves
/// that address through the TASK's table, so the window has to be there.
/// They are mapped `KERNEL_RW`: present for EL1, absent for EL0.
///
/// Fixed capacity, no allocation: this runs before the heap on some paths.
/// Kconfig `MAX_MMIO_REGIONS` (N12h; was the literal 16).
const MAX_MMIO_REGIONS: usize = azos_limits::MAX_MMIO_REGIONS;
static MMIO_REGIONS: SpinLock<[(usize, usize); MAX_MMIO_REGIONS]> =
    SpinLock::new([(0, 0); MAX_MMIO_REGIONS]);
static MMIO_REGION_COUNT: SpinLock<usize> = SpinLock::new(0);

/// The device-only table installed in the low half once the kernel moved to
/// the upper half, or 0 before that. Device windows mapped after it is built
/// have to reach it too, or the kernel loses the register it just mapped the
/// moment a task's table is installed.
static DEVICE_PT: SpinLock<usize> = SpinLock::new(0);

/// Replay the recorded device windows into `pt`.
///
/// Returns how many pages were mapped, so a caller can print a read-back
/// number rather than asserting that it worked.
pub fn map_recorded_mmio_into(pt: usize) -> usize {
    let regions = *MMIO_REGIONS.lock();
    let count = *MMIO_REGION_COUNT.lock();
    let mut entries = 0usize;
    for &(base, size) in regions.iter().take(count) {
        if size == 0 {
            continue;
        }
        // **2 MiB blocks, not 4 KiB pages.** This runs for every task's page
        // table, so the cost lands on `fork`: mapping the GIC's
        // redistributor window page by page (a megabyte for eight cores)
        // took `fork+exit` on aarch64 from 139,955 to 283,454 instructions,
        // measured. One entry per 2 MiB brings it back. A block is safe here
        // because every recorded window is device space that no task maps:
        // the lowest is at 0x0800_0000, far above the 0x1_0000 a ring-3 ELF
        // links at, and nothing rounds down into VA 0 (the null guard).
        //
        // **Pages, not blocks, above a 4 KiB granule.** A level-1 block is
        // 32 MiB at an aarch64 16 KiB granule and 512 MiB at 64 KiB: rounded
        // out to that, the window at 0x0800_0000 would claim the slot the
        // ring-3 image links into (0x1_0000) under 64 KiB, and a 32 MiB slot
        // around every window under 16 KiB. A page there is 16 or 64 KiB, so
        // the page-by-page cost that motivated the blocks is 4x / 16x
        // smaller to begin with.
        if MEGA_SIZE == 2 * 1024 * 1024 {
            let block_start = base & !(MEGA_SIZE - 1);
            let block_end = (base + size + MEGA_SIZE - 1) & !(MEGA_SIZE - 1);
            let mut addr = block_start;
            while addr < block_end {
                if map_mega(pt, addr, addr, PagePerms::KERNEL_RW).is_ok() {
                    entries += 1;
                }
                addr += MEGA_SIZE;
            }
        } else {
            let mut addr = base & !(PAGE_SIZE - 1);
            let end = (base + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            while addr < end {
                if map(pt, addr, addr, PagePerms::KERNEL_RW).is_ok() {
                    entries += 1;
                }
                addr += PAGE_SIZE;
            }
        }
    }
    entries
}

/// The first recorded device-window page `user_pt` already maps, as
/// `(vpn2, vpn1)` for the exec refusal message, or `None`. The page-granular
/// counterpart of [`kernel_entry_collision`]'s slot check, for the layout
/// where device windows are mapped into a task's table page by page.
// arch-only: aarch64 maps device windows page by page into user tables.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn mmio_page_collision(user_pt: usize) -> Option<(usize, usize)> {
    let regions = *MMIO_REGIONS.lock();
    let count = *MMIO_REGION_COUNT.lock();
    for &(base, size) in regions.iter().take(count) {
        if size == 0 { continue; }
        let mut va = base & !(PAGE_SIZE - 1);
        let end = (base + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        while va < end {
            if translate(user_pt, va).is_some() {
                return Some((ARCH.vpn(va, 2), ARCH.vpn(va, 1)));
            }
            va += PAGE_SIZE;
        }
    }
    None
}

/// Device windows [`map_mmio_region`] refused because the record was full
/// (N12i): the kernel reports the first refusal on the console, this counts
/// every one.
static MMIO_REGIONS_REFUSED: AtomicUsize = AtomicUsize::new(0);

/// How many device windows [`map_mmio_region`] refused for a full record.
pub fn mmio_regions_refused() -> usize {
    MMIO_REGIONS_REFUSED.load(Ordering::Relaxed)
}

/// Map the device window `[base, base + size)` into the kernel's table (and
/// the aarch64 device-only table), record it for replay into task tables,
/// and push it into the live roots.
///
/// `Err(CapacityFull)`, with NOTHING mapped, when the record already holds
/// Kconfig `MAX_MMIO_REGIONS` windows (N12i; it used to map the window and
/// drop the record silently, so the kernel reached the device and every task
/// table built later did not). The refusal is counted
/// ([`mmio_regions_refused`]); the caller says it.
pub fn map_mmio_region(base: usize, size: usize) -> KResult<()> {
    {
        let mut count = MMIO_REGION_COUNT.lock();
        if *count >= MAX_MMIO_REGIONS {
            MMIO_REGIONS_REFUSED.fetch_add(1, Ordering::Relaxed);
            return Err(KernelError::CapacityFull);
        }
        MMIO_REGIONS.lock()[*count] = (base, size);
        *count += 1;
    }
    let kpt = *KERNEL_PT.lock();
    let device_pt = *DEVICE_PT.lock();
    let aligned_base = base & !(PAGE_SIZE - 1);
    let end = (base + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let mut addr = aligned_base;
    while addr < end {
        let _ = map(kpt, addr, addr, PagePerms::KERNEL_RW);
        if device_pt != 0 {
            let _ = map(device_pt, addr, addr, PagePerms::KERNEL_RW);
        }
        addr += PAGE_SIZE;
    }
    // Roots built before this window (owner decision 10-10, N12g): without
    // this a task current on another hart could not reach the device.
    let _ = propagate_kernel_entries();
    Ok(())
}

/// Map the framebuffer `[pa, pa + len)` into the kernel's table as read/write,
/// never-executable memory of type `mem` (write-combining for pixels), at
/// `phys_to_virt(pa)`. Returns that address and the memory type the leaf
/// really carries: on a machine where `mem` has no encoding of its own (a
/// riscv64 hart without Svpbmt, whose PTE has no type field) the pages stay
/// plain and the answer is `WB`.
///
/// A page the kernel already maps (the ramfb buffer is `.bss`, direct-mapped
/// write-back; a framebuffer inside RAM is in the direct map too) is
/// REWRITTEN in place, so there is never a second, cacheable alias of the
/// same frame: it is cleaned out of the data cache (aarch64), unmapped (which
/// splits a 2 MiB leaf) and mapped again with the new type. A page nothing
/// maps (the Limine framebuffer, a PCI BAR) is mapped fresh. Not recorded as
/// an MMIO window: the replay into task tables is `KERNEL_RW` write-back,
/// which would put a cacheable alias back.
///
/// The caller owns the range: nothing else may touch it while it is remapped.
pub fn map_framebuffer(pa: usize, len: usize, mem: MemType) -> KResult<(usize, MemType)> {
    let start = pa & !(PAGE_SIZE - 1);
    let end = (pa + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let kpt = *KERNEL_PT.lock();
    let want = PagePerms { mem, ..PagePerms::KERNEL_RW };
    // A type with no encoding of its own leaves the pages as they are.
    let distinct = ARCH.pte_make_leaf(0, want, 0) != ARCH.pte_make_leaf(0, PagePerms::KERNEL_RW, 0);
    let perms = if distinct { want } else { PagePerms::KERNEL_RW };
    let mut p = start;
    while p < end {
        let va = crate::addr::phys_to_virt(p);
        let mapped = translate(kpt, va).is_some();
        if mapped && !distinct {
            p += PAGE_SIZE;
            continue;
        }
        if mapped {
            // SAFETY: `va` is mapped (just translated) and the caller owns the page.
            unsafe { ARCH.dcache_clean(va, PAGE_SIZE) };
            unmap_kernel(kpt, va);
        }
        map(kpt, va, p, perms)?;
        p += PAGE_SIZE;
    }
    ARCH.flush_tlb_all();
    let _ = propagate_kernel_entries();
    Ok((crate::addr::phys_to_virt(pa), perms.mem))
}

/// Enforce W^X policy: remap kernel sections with correct permissions.
///
/// After init(), everything is KERNEL_RWX (needed during boot before paging).
/// This function tightens permissions per section:
///   .text      → RX (no write — prevent code injection)
///   .rodata    → RO (no write, no execute)
///   .data/.bss → RW (no execute — prevent data execution)
///
/// Page-boundary handling: if .text and .rodata share a 4K page (the
/// boundary falls mid-page), that page stays RX (text wins, since
/// removing X would crash any code in that page).
///
/// Must be called AFTER split_mega_range() and enable_paging().
pub fn enforce_wx(
    text_start: usize, text_end: usize,
    rodata_start: usize, rodata_end: usize,
    data_start: usize, kernel_end: usize,
) {
    let kpt = *KERNEL_PT.lock();

    // The boundary arithmetic lives in `wx::plan` so `verify_wx` below reads
    // the SAME ranges rather than re-deriving them. A verifier with its own
    // copy of this rule would agree everywhere except the shared boundary
    // pages, which are the only part worth checking.
    for r in wx::plan(text_start, text_end, rodata_start, rodata_end,
                      data_start, kernel_end) {
        if !r.is_empty() {
            remap_range(kpt, r.start, r.end, r.flags);
        }
    }

    // Flush TLB on ALL harts to apply new permissions
    ARCH.flush_tlb_all();
}

/// Read the kernel page table back and report what W^X actually achieved.
///
/// `enforce_wx` returns nothing, `remap_range` silently skips anything that is
/// not a valid 4 KiB leaf, and `split_mega_range` skips a megapage without a
/// word when `alloc_page` fails. Every one of those failures leaves the boot
/// log printing `W^X enforced` over a kernel that is still writable and
/// executable. This is the readback that turns that line into a measurement.
///
/// Takes the same six section bounds as `enforce_wx` and must be called with
/// the same values — it re-plans from them rather than trusting a cached
/// result, so passing different bounds reports on different memory, which is
/// the caller's business.
///
/// Reports on the kernel image ONLY. Everything outside it — the heap, page
/// frames, task stacks — is mapped `KERNEL_RWX` by `init` and loses EXEC in a
/// separate pass once paging is on ([`strip_exec_outside_image`]); the
/// readback for that pass is a different function, not this one.
pub fn verify_wx(
    text_start: usize, text_end: usize,
    rodata_start: usize, rodata_end: usize,
    data_start: usize, kernel_end: usize,
) -> wx::WxReport {
    let kpt = *KERNEL_PT.lock();
    let mut report = wx::WxReport::default();

    for r in wx::plan(text_start, text_end, rodata_start, rodata_end,
                      data_start, kernel_end) {
        if r.is_empty() { continue; }
        let mut addr = r.start;
        while addr < r.end {
            let verdict = if megapage_leaf_at(kpt, addr) {
                // One unsplit 2 MiB leaf covers this address and 511 others.
                // Counting it 512 times would drown the report, so charge it
                // once and skip the megapage.
                wx::PageVerdict::UnsplitMegapage
            } else {
                match walk(kpt, addr, false) {
                    Ok(ptr) => {
                        let pte = unsafe { core::ptr::read_volatile(ptr) };
                        if ARCH.pte_is_valid(pte) && ARCH.pte_is_leaf(pte, 0) {
                            wx::judge(r.flags, ARCH.pte_perms(pte))
                        } else {
                            wx::PageVerdict::Unmapped
                        }
                    }
                    Err(_) => wx::PageVerdict::Unmapped,
                }
            };
            report.record(addr, verdict);
            if verdict == wx::PageVerdict::UnsplitMegapage {
                addr = (addr & !(MEGA_SIZE - 1)) + MEGA_SIZE;
            } else {
                addr += PAGE_SIZE;
            }
        }
    }
    report
}

/// Walk the RAM *outside* the kernel image, one leaf at a time.
///
/// Factored out so the sweep that strips EXEC and the sweep that verifies it
/// cannot disagree about what "outside the image" means or about how to step
/// over a megapage. `f` is handed `(vaddr, pte_ptr, level)` — `level` is the
/// trait level the leaf was found at (2 = gigapage, 1 = megapage, 0 = 4 KiB
/// page), not just a "is this big" bool, so a caller that needs to rebuild
/// the word (e.g. after `wx::without_exec`) has what `pte_make_leaf` needs.
///
/// Megapages are visited ONCE and then skipped whole. Walking them 4 KiB at a
/// time would rewrite the same L1 entry 512 times — harmless for the flags,
/// but it would make any count returned mean "addresses visited" rather than
/// "mappings changed", which is the kind of number that reads as a
/// measurement and is not one.
fn for_each_leaf_outside_image(
    pt_phys: usize,
    mem_start: usize, mem_end: usize,
    image_start: usize, image_end: usize,
    mut f: impl FnMut(usize, *mut u64, usize),
) {
    let mut addr = mem_start & !(PAGE_SIZE - 1);
    while addr < mem_end {
        // Skip the kernel image: `enforce_wx` owns it and `.text` must keep X.
        if addr >= image_start && addr < image_end {
            addr = image_end;
            continue;
        }
        let l2t = l2_table(pt_phys, addr);
        if no_l2(l2t) {
            addr = (addr & !(MEGA_SIZE - 1)) + MEGA_SIZE;
            continue;
        }
        let l2_ptr = (crate::addr::phys_to_virt(l2t + ARCH.vpn(addr, 2) * 8)) as *mut u64;
        let l2 = unsafe { core::ptr::read_volatile(l2_ptr) };
        if !ARCH.pte_is_valid(l2) {
            addr = (addr & !(MEGA_SIZE - 1)) + MEGA_SIZE;
            continue;
        }
        if ARCH.pte_is_leaf(l2, 2) {
            // A gigapage. Not produced by `init` today, handled so a future
            // change to it cannot silently skip a gigabyte.
            f(addr, l2_ptr, 2);
            addr = (addr & !(GIGA_SIZE - 1)) + GIGA_SIZE;
            continue;
        }
        let l1_ptr = (crate::addr::phys_to_virt(ARCH.pte_phys(l2) + ARCH.vpn(addr, 1) * 8)) as *mut u64;
        let l1 = unsafe { core::ptr::read_volatile(l1_ptr) };
        if !ARCH.pte_is_valid(l1) {
            addr = (addr & !(MEGA_SIZE - 1)) + MEGA_SIZE;
            continue;
        }
        if ARCH.pte_is_leaf(l1, 1) {
            let mega_base = addr & !(MEGA_SIZE - 1);
            // Only whole megapages, and only ones that do not overlap the
            // image. A megapage straddling `image_end` would have been split
            // by `split_mega_range`, so this is belt to that brace: retagging
            // a straddling leaf would strip X from kernel `.text`.
            if mega_base >= image_end || mega_base + MEGA_SIZE <= image_start {
                f(addr, l1_ptr, 1);
            }
            addr = mega_base + MEGA_SIZE;
            continue;
        }
        let l0_ptr = (crate::addr::phys_to_virt(ARCH.pte_phys(l1) + ARCH.vpn(addr, 0) * 8)) as *mut u64;
        let l0 = unsafe { core::ptr::read_volatile(l0_ptr) };
        if ARCH.pte_is_valid(l0) && ARCH.pte_is_leaf(l0, 0) {
            f(addr, l0_ptr, 0);
        }
        addr += PAGE_SIZE;
    }
}

/// Remove EXEC from every RAM mapping that is not the kernel image.
///
/// **Why this is a separate pass and not a flag change in [`init`].** `init`
/// runs before `enable_paging()`, and the kernel is executing out of the very
/// memory it is mapping. Mapping `.text` without X there would fault on the
/// first instruction fetch after paging comes on — a silent boot death with
/// no output to diagnose it from. So `init` keeps `KERNEL_RWX`, `enforce_wx`
/// tightens the image, and this strips everything else, with paging already
/// live so a mistake presents as a fault at a known PC.
///
/// **What this closes.** `init` maps ALL of RAM `KERNEL_RWX` and `enforce_wx`
/// only ever touched the image — on a 128 MiB board that left ~121 MiB
/// writable and executable in the kernel's own page table: the heap, every
/// frame `pmm` hands out, every task stack. Ring 3 never executed through
/// those mappings (it runs from its own table with `USER_RX`), so this is a
/// mitigation that was missing rather than a hole that was being used.
///
/// Verified before doing it that nothing executes outside `.text`:
/// `kernel/linker.ld` has the sections in order with `_kernel_end` after
/// `.bss`, the tree's only `#[link_section]` is the secure-boot public key,
/// and the vDSO page holds atomics, not code.
///
/// Returns what it changed.
pub fn strip_exec_outside_image(
    mem_start: usize, mem_end: usize,
    image_start: usize, image_end: usize,
) -> wx::RamExecReport {
    let kpt = *KERNEL_PT.lock();
    let mut rep = wx::RamExecReport::default();
    for_each_leaf_outside_image(kpt, mem_start, mem_end, image_start, image_end,
        |vaddr, ptr, level| {
            let pte = unsafe { core::ptr::read_volatile(ptr) };
            if let Some(flags) = wx::without_exec(ARCH.pte_perms(pte)) {
                let new_word = ARCH.pte_make_leaf(ARCH.pte_phys(pte), flags, level)
                    .expect("re-encoding a decoded leaf")
                    | keep_global(pte);
                unsafe { core::ptr::write_volatile(ptr, new_word) };
                if level > 0 { rep.record_mega(vaddr) } else { rep.record_page(vaddr) }
            }
        });
    ARCH.flush_tlb_all();
    rep
}

/// Read back what is still executable outside the kernel image.
///
/// The companion to [`strip_exec_outside_image`], and the reason that function
/// is worth trusting: it reports what it changed, this reports what remains.
/// A clean sweep is the two agreeing that nothing is left.
pub fn verify_no_exec_outside_image(
    mem_start: usize, mem_end: usize,
    image_start: usize, image_end: usize,
) -> wx::RamExecReport {
    let kpt = *KERNEL_PT.lock();
    let mut rep = wx::RamExecReport::default();
    for_each_leaf_outside_image(kpt, mem_start, mem_end, image_start, image_end,
        |vaddr, ptr, level| {
            let pte = unsafe { core::ptr::read_volatile(ptr) };
            if wx::is_exec(ARCH.pte_perms(pte)) {
                if level > 0 { rep.record_mega(vaddr) } else { rep.record_page(vaddr) }
            }
        });
    rep
}

/// Is `vaddr` covered by a 2 MiB leaf at L1 (i.e. never split)?
///
/// `walk` returns a megapage leaf and a 4 KiB leaf through the same
/// `*mut u64`, with nothing to tell them apart — which is exactly how an
/// unsplit megapage would read as a well-behaved page here. So this descends
/// by hand instead of asking `walk`.
fn megapage_leaf_at(pt_phys: usize, vaddr: usize) -> bool {
    let l2t = l2_table(pt_phys, vaddr);
    if no_l2(l2t) { return false; }
    let l2 = unsafe {
        core::ptr::read_volatile((crate::addr::phys_to_virt(l2t + ARCH.vpn(vaddr, 2) * 8)) as *const u64)
    };
    if !ARCH.pte_is_valid(l2) || ARCH.pte_is_leaf(l2, 2) {
        // A gigapage leaf at L2 is the same problem one level up; an invalid
        // entry is not a megapage and is reported as unmapped by the caller.
        return ARCH.pte_is_valid(l2) && ARCH.pte_is_leaf(l2, 2);
    }
    let l1 = unsafe {
        core::ptr::read_volatile((crate::addr::phys_to_virt(ARCH.pte_phys(l2) + ARCH.vpn(vaddr, 1) * 8)) as *const u64)
    };
    ARCH.pte_is_valid(l1) && ARCH.pte_is_leaf(l1, 1)
}

/// Unmap page 0 (null pointer guard).
///
/// Dereferencing a null pointer (address 0x0) will cause a page fault
/// Replace the boot-time identity map in `TTBR0_EL1` with a table that maps
/// ONLY the device windows.
///
/// aarch64 only, and only once the kernel is executing from `TTBR1_EL1`.
/// Until this runs, the low half still carries the bootstrap identity map,
/// which means two things that are both wrong once the split exists: the
/// kernel can still reach any physical RAM by its raw address (the very
/// aliasing this migration removes), and VA 0 is covered by the bootstrap's
/// 1 GiB device block, so a null dereference does NOT fault — the null-guard
/// probe caught exactly that.
///
/// Returns the pages mapped, so the caller can print a read-back count.
// arch-only: the aarch64 TTBR0/TTBR1 split.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn install_device_only_ttbr0() -> KResult<usize> {
    let pt = create_pagetable()?;
    let pages = map_recorded_mmio_into(pt);
    *DEVICE_PT.lock() = pt;
    ARCH.switch_pt(pt, 0);
    ARCH.flush_tlb_all();
    Ok(pages)
}

/// instead of silently reading/writing address 0.
pub fn null_guard() {
    let kpt = *KERNEL_PT.lock();
    unmap(kpt, 0);
}

/// Remap a range of 4K pages with new flags (for W^X enforcement).
/// Only modifies leaf PTEs that are already valid.
fn remap_range(pt_phys: usize, start: usize, end: usize, flags: PagePerms) {
    let mut addr = start & !(PAGE_SIZE - 1);
    while addr < end {
        if let Ok(pte_ptr) = walk(pt_phys, addr, false) {
            let old = unsafe { core::ptr::read_volatile(pte_ptr) };
            if ARCH.pte_is_valid(old) && ARCH.pte_is_leaf(old, 0) {
                let new_pte = ARCH.pte_make_leaf(ARCH.pte_phys(old), flags, 0)
                    .expect("re-encoding a page-aligned leaf at level 0")
                    | keep_global(old);
                unsafe { core::ptr::write_volatile(pte_ptr, new_pte) };
            }
        }
        addr += PAGE_SIZE;
    }
}

/// Activate the kernel page table (write SATP, enable Sv39 paging).
pub fn enable_paging() {
    let kpt = *KERNEL_PT.lock();
    // The KERNEL's table, not a task's: on aarch64 these are different
    // registers (TTBR1 vs TTBR0) and going through `switch_pt` here would
    // put the kernel's mappings somewhere the next user task overwrites.
    // On riscv64 both are `satp` and the implementation says so.
    ARCH.switch_kernel_pt(kpt);
}

// COW (AQ9) and Demand Paging (AQ10) live in sibling modules `cow` and
// `demand`.  Re-export their public API here for backward compatibility
// with callers that still reference them via `vmm::`.
pub use crate::cow::{fork_cow, fork_cow_shared, handle_cow_fault, page_addref, page_decref, page_getref};
pub use crate::demand::{map_demand, map_demand_range};

/// Resolve a demand-paging fault, refusing anything in the null guard region.
///
/// This is the entry point the kernel's page-fault arm uses. It is a wrapper
/// rather than a plain re-export of [`crate::demand::handle_demand_fault`]
/// because that function will happily materialize a page for *any* VA that
/// carries a `DEMAND`-marked PTE, VA 0 included — and a demand PTE at VA 0 is
/// reachable (`sys_alloc_demand` bases its reservation at the task's `brk`,
/// which is 0 for a task that never got one). Materializing it turns a jump
/// through a null pointer into a task that keeps running on a page of zeros
/// instead of dying. See [`USER_GUARD_LIMIT`] for the threshold's derivation.
///
/// `InvalidArg` (not `NotMapped`) on a guard hit, so the caller can tell
/// "there was nothing to resolve here" from "I refuse to resolve this".
///
/// Wave 14 (DEMANDPAGE): a fault the marker path does not own (`NotMapped`:
/// no table, or an empty entry) goes to the region pagers
/// ([`crate::pager::resolve_fault`]); one outside every region stays
/// `NotMapped` and the caller kills the task as before.
pub fn handle_demand_fault(pt: usize, fault_addr: usize) -> KResult<()> {
    if in_null_guard(fault_addr) {
        return Err(KernelError::InvalidArg);
    }
    match crate::demand::handle_demand_fault(pt, fault_addr) {
        Err(KernelError::NotMapped) if !cfg!(feature = "demand-region-canary") => {
            crate::pager::resolve_fault(pt, fault_addr)
        }
        r => r,
    }
}

/// Copy kernel page-table entries into a user page table.
///
/// After this call the user PT contains all kernel mappings (code, MMIO)
/// alongside the user-space mappings.  Kernel pages have no USER bit so
/// U-mode code cannot access them directly; they are only reachable in
/// S-mode (trap handler, syscall dispatch).
///
/// This is required so that when an ecall fires while the user PT is active
/// the CPU can still fetch from trap_vector (~0x80200000, VPN[2]=2) and
/// the trap handler can write to UART/MMIO (VPN[2]=0, high VPN[1] slots).
///
/// For VPN[2] entries present only in the kernel PT, the L2 PTE is copied
/// directly.  For VPN[2]=0, where both PTs have an intermediate L1 table,
/// the two tables are merged at L1 level: kernel L1 entries (MMIO) are
/// written into any empty slots in the user L1 table (user code occupies
/// different VPN[1] slots, so there is no collision).
///
/// # Ordering invariant — call this LAST
///
/// This must run **after** every user mapping is installed, never before.
/// On an empty user PT the wholesale branch below fires for *every* kernel
/// L2 slot, so `user_pt.L2[vpn2]` ends up holding a pointer to the kernel's
/// own L1 table — shared, not copied. Userspace links at `0x10000` and the
/// kernel maps the CLINT at `0x0200_0000`; both are VPN[2]=0, so a
/// subsequent `map(user_pt, 0x10000, ..)` allocates an L0 table *inside the
/// kernel's L1* and installs USER leaves in the kernel page table. Every
/// address space then inherits the previous process's mappings, user pages
/// become visible to (and clobberable by) the kernel, and the next
/// `load_elf` memcpy's over the live `.text` of an already-running process.
/// Mapping first means the user PT owns its own L1 tables and the merge
/// path below — the branch that keeps kernel and user separate — is the one
/// that actually runs.
///
/// Because the copy grafts kernel-owned tables into `user_pt`, any teardown
/// of that PT must go through [`destroy_user_pagetable`], which knows how to
/// tell the borrowed kernel tables from the user's own.
pub fn copy_kernel_entries_to_user(user_pt: usize) {
    // aarch64: the kernel lives in the OTHER half. `TTBR1_EL1` holds its
    // table and a task's `TTBR0_EL1` cannot reach it, so there are no kernel
    // entries to copy and copying any would hand a task exactly the reach
    // this split exists to remove. What a task's table DOES need is the
    // device windows, because the kernel touches devices while that task is
    // current and device registers live in the low half — mapped KERNEL_RW,
    // so EL0 still cannot see them.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let _ = map_recorded_mmio_into(user_pt);
        return;
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
    // Into the roster only once merged, so a roster walker never sees a
    // half-merged root. A kernel mapping `propagate_kernel_entries` pushed
    // while this merge ran (it bumps `PROPAGATE_GEN` under `PT_META`, after
    // the kernel write) may have been missed by the reads above and the root
    // was not in its roster yet: merge again under the lock, then mark. The
    // caller has installed every user mapping by now, so the roster never
    // names a root the wholesale branch would corrupt.
    let gen = PROPAGATE_GEN.load(Ordering::Acquire);
    let kpt = *KERNEL_PT.lock();
    let _ = merge_kernel_entries(kpt, user_pt, root_level());
    let mut meta = PT_META.lock();
    if PROPAGATE_GEN.load(Ordering::Relaxed) != gen {
        let _ = merge_kernel_entries(kpt, user_pt, root_level());
    }
    if let Some(idx) = meta_find(&meta, user_pt) {
        meta[idx].merged = true;
    }
    }
}

/// Bumped under `PT_META` by every [`propagate_kernel_entries`] (N12g), so a
/// merge that ran outside the lock can tell it may have missed a push.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
static PROPAGATE_GEN: AtomicUsize = AtomicUsize::new(0);

/// Push the kernel's current entries into every root of the merged-root
/// roster (owner decision 10-10, N12g): a kernel mapping created after task
/// roots exist — a driver's low MMIO in a merge slot, or a kernel-only slot
/// first used late — reaches them. It is the same idempotent merge
/// [`copy_kernel_entries_to_user`] runs: a kernel-only slot the root lacks
/// is linked word for word (the kernel's fixed L1; G as the kernel root has
/// it), a merge-slot L1 entry the root lacks is filled (never G: only
/// kernel-only slots get G, see [`kernel_global_bit`]). Each of those words
/// goes in by CAS from empty (N12h, [`crate::pte_install`]): a user `map`
/// racing for the same word is never overwritten. Where the root owns its own
/// L0 table and the kernel has one too (it won that race, or mapped its pages
/// there first), the kernel's leaves are copied into the root's empty words;
/// a word the root uses is left alone (not counted), and a kernel 2 MiB leaf
/// over a root's table cannot be copied. Walks the roster with
/// [`with_merged_roots`], one `PT_META` hold per root (FX8): teardown takes
/// that lock before it frees a root, so each root is live through its merge,
/// and no hold grows with the task count. No allocation, no other lock,
/// nothing that sleeps.
/// Each root that received an entry gets an all-range shootdown (all-ASID
/// form where its ASID is not recorded), after the local all-ASID
/// `flush_tlb_all` the kernel-table paths use.
///
/// Returns `(roots walked, entries written)`, the readback a caller prints.
/// aarch64: `(0, 0)`; its task roots hold device windows replayed from
/// `MMIO_REGIONS` at creation, and none is mapped late (N12h). Every
/// `map_mmio_region` caller an aarch64 boot reaches runs in `kernel_main`
/// before the first task root exists: `boot::early` (UART, GIC), the
/// `map_late_mmio` hook (VirtIO-MMIO), the PCI ECAM window, and the PCI BAR
/// maps of the MSI-X self-test, the SDHCI flush smoke and `virtio::net::
/// init_pci` (all before `net_init` and task creation). Kernel tasks run on
/// `DEVICE_PT`, which `map_mmio_region` writes directly. A future runtime
/// caller needs a push, and two things differ from the riscv64/x86_64 one:
/// the roster is empty here (the aarch64 branch of
/// [`copy_kernel_entries_to_user`] never sets `merged`), and a root that
/// lacks the window's level-1 table needs a new table, so `map_mega` would
/// reach `alloc_table` and `TABLE_HOOK` under `PT_META`. Allocate one table
/// per roster root outside the lock, install inside, retry if
/// `PROPAGATE_GEN` moved, free what was not used. Under
/// canary `kernel-l1-copy` also `(0, 0)`: the property that canary breaks
/// is "a kernel mapping added later reaches every root".
pub fn propagate_kernel_entries() -> (usize, usize) {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        (0, 0)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
    if CANARY_L1_COPY.load(Ordering::Relaxed) {
        return (0, 0);
    }
    let kpt = *KERNEL_PT.lock();
    if kpt == 0 {
        return (0, 0);
    }
    // The bump has its own hold, before the walk's first, and is taken
    // even when the roster is empty: a root that is marked `merged` after
    // it sees the moved generation under `PT_META` and re-merges in
    // `copy_kernel_entries_to_user`; a root marked before it is in the
    // roster when the walk starts and is visited unless it leaves first.
    {
        let _meta = PT_META.lock();
        PROPAGATE_GEN.fetch_add(1, Ordering::Release);
    }
    // One `PT_META` hold per root (FX8, the FX7 walk): the root is live
    // through its merge and its shootdown, and the hold no longer grows
    // with the task count.
    let mut written = 0usize;
    let roots = with_merged_roots(|pt| {
        let n = merge_kernel_entries(kpt, pt, root_level());
        if n != 0 {
            written += n;
            ARCH.tlb_shootdown(pt, 0, azos_arch_api::TLB_ALL);
        }
        Ok::<(), core::convert::Infallible>(())
    })
    .unwrap_or_else(|e| match e {});
    if written != 0 {
        ARCH.flush_tlb_all();
    }
    (roots, written)
    }
}

/// Run `f` on every root of the merged-root roster, each under `PT_META`: a
/// root cannot be freed while `f` reads it (teardown leaves the roster under
/// the same lock before its first free). The lock is taken once per root and
/// dropped between roots (FX7), so one hold is one roster scan plus one `f`,
/// whatever the roster's length: under the lock for the whole walk, a ktest
/// checking every root held it 140 us (`LOCK_MAX_HOLD_US` 100) under
/// -icount. A root that enters or leaves the roster between two holds may or
/// may not be visited; every root that is visited is live through its `f`.
/// `f` must not sleep, allocate a page table or take `PT_META`. Stops at the
/// first `Err`; `Ok(roots visited)`.
pub fn with_merged_roots<E>(mut f: impl FnMut(usize) -> Result<(), E>) -> Result<usize, E> {
    let kpt = KERNEL_ROOT.load(Ordering::Relaxed);
    crate::roster::resume_walk(
        MAX_PT_TRACKED,
        || PT_META.lock(),
        |meta, i| meta[i].pt != 0 && meta[i].merged && meta[i].pt != kpt,
        |meta, i| f(meta[i].pt),
    )
}

/// [`copy_kernel_entries_to_user`] at one level: above level 2 (x86_64) a
/// kernel entry the task lacks is copied, one both have is descended; at
/// level 2 the merge below.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
#[inline(always)]
fn merge_kernel_entries(kpt: usize, user_pt: usize, level: usize) -> usize {
    if level <= 2 {
        merge_kernel_l2(kpt, user_pt)
    } else {
        merge_kernel_upper(kpt, user_pt, level)
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
#[inline(never)]
fn merge_kernel_upper(kpt: usize, user_pt: usize, level: usize) -> usize {
    let n = if level == root_level() { root_entries() } else { entries_per_table() };
    let mut next = 0usize;
    let mut written = 0usize;
    loop {
        let i = next_valid(kpt, next, n);
        if i >= n { break; }
        next = i + 1;
        let kpte: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(kpt + i * 8)) as *const u64) };
        if !ARCH.pte_is_table(kpte, level) { continue; }
        let slot = pt_word(user_pt, i);
        let mut upte = slot.load(Ordering::Relaxed);
        if !ARCH.pte_is_valid(upte) {
            // By CAS (N12h): the task's own mapper may install a table here
            // at the same moment; the loser adopts the winner's.
            match crate::pte_install::install(slot, upte, kpte) {
                Ok(()) => { written += 1; continue; }
                Err(cur) => upte = cur,
            }
        }
        if ARCH.pte_is_table(upte, level) && ARCH.pte_phys(upte) != ARCH.pte_phys(kpte) {
            written += merge_kernel_entries(ARCH.pte_phys(kpte), ARCH.pte_phys(upte), level - 1);
        }
    }
    written
}

/// The two-level merge: `kpt` and `user_pt` are level-2 tables (the roots on
/// riscv64; on x86_64 the PDPTs one path reaches).
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn merge_kernel_l2(kpt: usize, user_pt: usize) -> usize {
    let mut vpn2_next = 0usize;
    let mut written = 0usize;
    loop {
        let vpn2 = next_valid(kpt, vpn2_next, l2_slots());
        if vpn2 >= l2_slots() { break; }
        vpn2_next = vpn2 + 1;
        let kpte: u64 = unsafe {
            core::ptr::read_volatile((crate::addr::phys_to_virt(kpt + vpn2 * 8)) as *const u64)
        };
        if !ARCH.pte_is_valid(kpte) {
            continue;
        }

        let uslot = pt_word(user_pt, vpn2);
        let mut upte = uslot.load(Ordering::Relaxed);

        if !ARCH.pte_is_valid(upte) {
            // User has no L2 entry here — link the kernel's: the root PTE
            // word for word, so the root shares the kernel's L1 (a
            // kernel-only slot's fixed table, `KERNEL_ONLY_FROM`). By CAS
            // (N12h): if the task's mapper installed its own L1 meanwhile,
            // merge into that one below instead of overwriting it.
            let link = canary_private_l1(kpt, vpn2, kpte);
            match crate::pte_install::install(uslot, upte, link) {
                Ok(()) => { written += 1; continue; }
                Err(cur) => upte = cur,
            }
        }
        if ARCH.pte_is_valid(upte) && !ARCH.pte_is_leaf(kpte, 2) && !ARCH.pte_is_leaf(upte, 2) {
            // Both sides have intermediate L1 tables — merge kernel L1
            // entries into user L1.  Kernel entries fill only empty slots
            // (user mappings are never overwritten).
            let k_l1 = ARCH.pte_phys(kpte);
            let u_l1 = ARCH.pte_phys(upte);
            let mut vpn1_next = 0usize;
            loop {
                let vpn1 = next_valid(k_l1, vpn1_next, entries_per_table());
                if vpn1 >= entries_per_table() { break; }
                vpn1_next = vpn1 + 1;
                let kl1pte: u64 = unsafe {
                    core::ptr::read_volatile((crate::addr::phys_to_virt(k_l1 + vpn1 * 8)) as *const u64)
                };
                if !ARCH.pte_is_valid(kl1pte) {
                    continue;
                }
                let ul1 = pt_word(u_l1, vpn1);
                let mut ul1pte = ul1.load(Ordering::Relaxed);
                if !ARCH.pte_is_valid(ul1pte) {
                    // By CAS (N12h): a user `map` in this 2 MiB block may
                    // install its own L0 table at the same moment. A plain
                    // store here would drop that table and its pages.
                    match crate::pte_install::install(ul1, ul1pte, kl1pte) {
                        Ok(()) => { written += 1; continue; }
                        Err(cur) => ul1pte = cur,
                    }
                }
                // The root owns an L0 table where the kernel has one (it won
                // the race above, or the kernel mapped this block after the
                // root mapped its own pages here): adopt it, copying the
                // kernel's leaves into its empty words. Kernel leaves have no
                // USER bit, so teardown never frees their frames; a word the
                // root uses (a page or a demand marker) is left alone.
                if ARCH.pte_is_table(kl1pte, 1) && ARCH.pte_is_table(ul1pte, 1)
                    && ARCH.pte_phys(kl1pte) != ARCH.pte_phys(ul1pte)
                {
                    written += crate::pte_install::fill_empty(
                        table_words(ARCH.pte_phys(ul1pte)),
                        table_words(ARCH.pte_phys(kl1pte)),
                        ARCH.pte_empty(),
                        |w| ARCH.pte_is_valid(w),
                        |w| ARCH.pte_is_leaf(w, 0) && !ARCH.pte_perms(w).user,
                    );
                }
            }
        }
        // Both sides have leaf entries (megapages) — kernel PT owns it, skip.
    }
    written
}
/// Runtime canary `kernel-l1-copy` (ktest `kernel_half_shared_by_every_root`).
static CANARY_L1_COPY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Arm canary `kernel-l1-copy`: the first kernel-only slot of every root
/// built from now on gets a private copy of the kernel's L1 instead of a
/// link, so a kernel mapping added to that slot later is missing there.
/// It also turns [`propagate_kernel_entries`] off, so a merge-slot entry
/// mapped after a root exists is missing there too (N12g). Teardown and
/// fork skip kernel-only slots, so the copy is leaked, never walked.
pub fn canary_kernel_l1_copy() {
    CANARY_L1_COPY.store(true, Ordering::Relaxed);
}

/// The root PTE [`merge_kernel_l2`] installs for kernel slot `vpn2`: `kpte`
/// itself, or under canary `kernel-l1-copy` a link to a private copy of the
/// first kernel-only slot's L1.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
#[inline(always)]
fn canary_private_l1(_kpt: usize, vpn2: usize, kpte: u64) -> u64 {
    if !CANARY_L1_COPY.load(Ordering::Relaxed)
        || root_level() > 2
        || vpn2 != KERNEL_ONLY_FROM.load(Ordering::Relaxed)
        || !ARCH.pte_is_table(kpte, 2)
    {
        return kpte;
    }
    let Ok(copy) = pmm::alloc_page_zone(Zone::PageTable) else { return kpte };
    let src = crate::addr::phys_to_virt(ARCH.pte_phys(kpte)) as *const u64;
    let dst = crate::addr::phys_to_virt(copy.as_usize()) as *mut u64;
    for i in 0..entries_per_table() {
        // SAFETY: both are whole, mapped page-table frames.
        unsafe { core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i))) };
    }
    ARCH.pte_make_table(copy.as_usize())
}

/// Is `vpn2` a kernel-only slot of a three-level root ([`KERNEL_ONLY_FROM`])?
/// Teardown and fork never descend into one: its table is the kernel's
/// fixed L1, never the task's to free or copy.
#[inline(always)]
pub(crate) fn kernel_only_slot(vpn2: usize) -> bool {
    root_level() <= 2 && vpn2 >= KERNEL_ONLY_FROM.load(Ordering::Relaxed)
}

/// Why `root`'s kernel half differs from the kernel root's, or `None`
/// (ktest `kernel_half_shared_by_every_root`): [`kernel_leaves_mismatch`],
/// then [`kernel_half_links_mismatch`]. `None` at once where there are no
/// kernel-only slots.
pub fn kernel_half_mismatch(root: usize) -> Option<&'static str> {
    kernel_leaves_mismatch().or_else(|| kernel_half_links_mismatch(root))
}

/// The kernel root's half of [`kernel_half_mismatch`], which no user root
/// changes: no kernel leaf of a merge slot may carry G; with
/// [`kernel_global`] every kernel leaf of a kernel-only slot must, without
/// it none. Reads every kernel level-0 table, so it runs once, not once per
/// root and not under `PT_META` (FX7). `None` where there are no kernel-only
/// slots.
pub fn kernel_leaves_mismatch() -> Option<&'static str> {
    let from = KERNEL_ONLY_FROM.load(Ordering::Relaxed);
    let kpt = KERNEL_ROOT.load(Ordering::Relaxed);
    if from == usize::MAX || kpt == 0 || root_level() > 2 {
        return None;
    }
    let g = ARCH.pte_global_bit();
    // `want_g`: whether every kernel leaf under `l1` must carry G.
    let leaves_ok = |l1: usize, want_g: bool| -> bool {
        for j in 0..entries_per_table() {
            let e = pt_read(l1, j);
            if !ARCH.pte_is_valid(e) { continue; }
            if ARCH.pte_is_leaf(e, 1) {
                if (e & g != 0) != want_g { return false; }
                continue;
            }
            let l0 = ARCH.pte_phys(e);
            for k in 0..entries_per_table() {
                let w = pt_read(l0, k);
                if ARCH.pte_is_valid(w) && ARCH.pte_is_leaf(w, 0) && (w & g != 0) != want_g {
                    return false;
                }
            }
        }
        true
    };
    for vpn2 in 0..l2_slots() {
        let k = pt_read(kpt, vpn2);
        if !ARCH.pte_is_table(k, 2) { continue; }
        if vpn2 >= from {
            if !leaves_ok(ARCH.pte_phys(k), KERNEL_GLOBAL) {
                return Some(if KERNEL_GLOBAL {
                    "a kernel leaf of a kernel-only slot lacks G"
                } else {
                    "a kernel leaf carries G with RV_KERNEL_GLOBAL off"
                });
            }
        } else if !leaves_ok(ARCH.pte_phys(k), false) {
            return Some("a kernel leaf of a merge slot carries G");
        }
    }
    None
}

/// `root`'s half of [`kernel_half_mismatch`]: every kernel-only slot must
/// hold the kernel root's PTE word for word (a link to the same fixed L1);
/// every kernel L1 entry of a merge slot must be in `root`'s own L1, equal.
/// Reads the root, its merge-slot L1s and the kernel's: what one
/// [`with_merged_roots`] hold covers per root. `None` where there are no
/// kernel-only slots.
pub fn kernel_half_links_mismatch(root: usize) -> Option<&'static str> {
    let from = KERNEL_ONLY_FROM.load(Ordering::Relaxed);
    let kpt = KERNEL_ROOT.load(Ordering::Relaxed);
    if from == usize::MAX || kpt == 0 || root == 0 || root_level() > 2 {
        return None;
    }
    for vpn2 in 0..l2_slots() {
        let k = pt_read(kpt, vpn2);
        if !ARCH.pte_is_valid(k) { continue; }
        let u = pt_read(root, vpn2);
        if vpn2 >= from {
            if u != k {
                return Some("a kernel-only slot is not the kernel root's PTE (copied, not linked)");
            }
            continue;
        }
        if !ARCH.pte_is_table(k, 2) { continue; }
        if !ARCH.pte_is_table(u, 2) {
            return Some("a merge slot the kernel maps is missing from the root");
        }
        let (k_l1, u_l1) = (ARCH.pte_phys(k), ARCH.pte_phys(u));
        if u_l1 == k_l1 { continue; }
        for j in 0..entries_per_table() {
            let e = pt_read(k_l1, j);
            if ARCH.pte_is_valid(e) && pt_read(u_l1, j) != e {
                return Some("a kernel entry of a merge slot is missing from the root's L1");
            }
        }
    }
    None
}

/// One page-table word, read volatile. `t` must be a live page-table frame
/// and `i` below its entry count.
#[inline(always)]
fn pt_read(t: usize, i: usize) -> u64 {
    // SAFETY: the callers' contract above.
    unsafe { core::ptr::read_volatile(crate::addr::phys_to_virt(t + i * 8) as *const u64) }
}

/// A VA for ktest `kernel_half_shared_by_every_root` to map one low MMIO
/// page at after roots exist (N12g): the first page of the highest 2 MiB
/// block (VPN[1] > 0; user code links in block 0) of a merge slot where the
/// kernel root has an L1 table but no entry, and no roster root owns that L1
/// entry either. Chosen under `PT_META`, so no root enters or leaves the
/// roster mid-scan. `None` with no kernel-only slots, or when every block is
/// taken. Board-neutral: QEMU virt's slot 0 is MMIO and user code, VF2's
/// also holds the user stack.
pub fn free_merge_block() -> Option<usize> {
    let from = KERNEL_ONLY_FROM.load(Ordering::Relaxed);
    let kpt = KERNEL_ROOT.load(Ordering::Relaxed);
    if from == usize::MAX || kpt == 0 || root_level() > 2 {
        return None;
    }
    let rd = |t: usize, i: usize| -> u64 {
        // SAFETY: `t` is a live page-table frame, `i` below its entry count.
        unsafe { core::ptr::read_volatile(crate::addr::phys_to_virt(t + i * 8) as *const u64) }
    };
    let meta = PT_META.lock();
    for vpn2 in 0..from.min(l2_slots()) {
        let k = rd(kpt, vpn2);
        if !ARCH.pte_is_table(k, 2) { continue; }
        let k_l1 = ARCH.pte_phys(k);
        'block: for vpn1 in (1..entries_per_table()).rev() {
            if ARCH.pte_is_valid(rd(k_l1, vpn1)) { continue; }
            for m in meta.iter() {
                if m.pt == 0 || !m.merged || m.pt == kpt { continue; }
                let u = rd(m.pt, vpn2);
                if !ARCH.pte_is_table(u, 2) { continue 'block; }
                let u_l1 = ARCH.pte_phys(u);
                if u_l1 != k_l1 && ARCH.pte_is_valid(rd(u_l1, vpn1)) { continue 'block; }
            }
            return Some((vpn2 << L2_SHIFT) | (vpn1 << L1_SHIFT));
        }
    }
    None
}

/// The kernel's L1 table for VPN[2] slot `vpn2` of the kernel level-2 table
/// `kpt` ([`for_each_user_l2`]'s `kernel_l2`), if it has one.
///
/// Returns `None` when the kernel has no entry there, or when the entry is a
/// gigapage leaf (no L1 table to speak of). Used by the teardown and COW
/// walkers to recognise a table that is *borrowed* from the kernel PT rather
/// than owned by the user PT they are traversing.
#[inline(never)]
pub(crate) fn kernel_l1_in(kpt: usize, vpn2: usize) -> Option<usize> {
    if kpt == 0 || vpn2 >= entries_per_table() { return None; }
    let kpte: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(kpt + vpn2 * 8)) as *const u64) };
    if ARCH.pte_is_valid(kpte) && !ARCH.pte_is_leaf(kpte, 2) { Some(ARCH.pte_phys(kpte)) } else { None }
}

/// Check, without writing anything, whether [`copy_kernel_entries_to_user`]
/// would be able to install *every* kernel mapping into `user_pt`.
///
/// The merge only fills empty slots — it never overwrites a user mapping. That
/// is the right precedence for memory safety, but it means a user layout that
/// happens to occupy a VPN[2] (or VPN[2]/VPN[1]) slot the kernel also needs
/// silently *loses* the kernel entry. The failure is not a fault at load time:
/// the process starts, runs, and then the first timer interrupt or `kprintln`
/// taken while its SATP is live faults in S-mode on a CLINT/UART address the
/// kernel believes is identity-mapped. On a robot that is a hang with the
/// actuators still energised.
///
/// So exec refuses the image instead. Returns `None` when everything fits, or
/// `Some((vpn2, vpn1))` naming the first slot that collides (`vpn1 ==
/// entries_per_table()` means the collision is at L2 itself). Call it *before*
/// `copy_kernel_entries_to_user` so the rejection path still sees a page table
/// that contains nothing but user-owned tables.
///
/// Note for platforms whose RAM base is 0 (K1: `RAM_BASE = 0x0000_0000`): the
/// kernel identity-maps a megapage over the very VA range userspace links at
/// (`0x10000`), so this predicate fires and exec fails. That is intentional and
/// strictly better than today's behaviour there — see the report on the K1 VA
/// layout; fixing it needs a user-image relocation, not a change here.
/// Is `vaddr` mapped in the KERNEL's own page table?
///
/// The question a ring-3 memory syscall has to answer before it walks a user
/// page table, and the reason it cannot be answered with a constant.
///
/// Every user page table carries the kernel's mappings, merged in at exec and
/// fork by [`copy_kernel_entries_to_user`]. That merge copies the kernel's
/// PTE, and a non-leaf PTE is a POINTER to the kernel's next-level table -- so
/// the user's page table does not hold a COPY of the kernel's mappings, it
/// holds the kernel's actual tables. A walk down a user page table to any
/// address in the shared region arrives at the kernel's own L0 entry, and a
/// write there is a write to the kernel's page table.
///
/// A VA ceiling cannot express this. `USER_VA_TOP` is 2 GiB and every MMIO
/// window this OS maps -- CLINT at 32 MiB, PLIC at 192 MiB, UART at 256 MiB --
/// sits below it, so a ceiling check waves all of them through. Nor can a
/// floor: which addresses the kernel maps is a per-board fact, and a constant
/// tracking it would be one board port away from being wrong in the direction
/// that loses the console.
///
/// So ask the page table. It is the same source of truth that made the mapping,
/// it cannot drift from the board, and a new MMIO window is protected the
/// moment it is mapped rather than the moment someone remembers this function.
pub fn va_is_kernel_mapped(vaddr: usize) -> bool {
    let kpt = *KERNEL_PT.lock();
    if kpt == 0 {
        // No kernel page table yet means no MMU, and nothing to protect from a
        // walk that cannot happen. Reporting "mapped" here would refuse every
        // memory syscall before `vmm::init`.
        return false;
    }
    translate(kpt, vaddr).is_some()
}

pub fn kernel_entry_collision(user_pt: usize) -> Option<(usize, usize)> {
    // aarch64 above a 4 KiB granule: the kernel's own table is in TTBR1 and a
    // task's table receives no kernel entries, only the device windows, page
    // by page (`map_recorded_mmio_into`). The slot comparison below would
    // then report the device windows' level-1 slot — 512 MiB at 64 KiB,
    // which also holds the ring-3 image at 0x1_0000 — although nothing is
    // shared. What must not collide is a user page with a device page.
    // arch-only: aarch64 granules above 4 KiB (see above).
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    if MEGA_SIZE != 2 * 1024 * 1024 {
        return mmio_page_collision(user_pt);
    }
    let kpt = *KERNEL_PT.lock();
    if kpt == 0 { return None; }
    kernel_collision_at(kpt, user_pt, root_level())
}

#[inline(always)]
fn kernel_collision_at(kpt: usize, user_pt: usize, level: usize) -> Option<(usize, usize)> {
    if level <= 2 {
        kernel_collision_l2(kpt, user_pt)
    } else {
        kernel_collision_upper(kpt, user_pt, level)
    }
}

/// Above level 2 (x86_64): a kernel entry the task lacks is copied whole by
/// the merge; one both have as different tables is compared one level down.
#[inline(never)]
fn kernel_collision_upper(kpt: usize, user_pt: usize, level: usize) -> Option<(usize, usize)> {
    let n = if level == root_level() { root_entries() } else { entries_per_table() };
    let mut next = 0usize;
    loop {
        let i = next_valid(kpt, next, n);
        if i >= n { break; }
        next = i + 1;
        let kpte: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(kpt + i * 8)) as *const u64) };
        if !ARCH.pte_is_table(kpte, level) { continue; }
        let upte: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(user_pt + i * 8)) as *const u64) };
        if !ARCH.pte_is_valid(upte) { continue; }
        if !ARCH.pte_is_table(upte, level) { return Some((i, entries_per_table())); }
        if ARCH.pte_phys(upte) == ARCH.pte_phys(kpte) { continue; }
        if let Some(c) = kernel_collision_at(ARCH.pte_phys(kpte), ARCH.pte_phys(upte), level - 1) {
            return Some(c);
        }
    }
    None
}

fn kernel_collision_l2(kpt: usize, user_pt: usize) -> Option<(usize, usize)> {
    let mut vpn2_next = 0usize;
    loop {
        let vpn2 = next_valid(kpt, vpn2_next, l2_slots());
        if vpn2 >= l2_slots() { break; }
        vpn2_next = vpn2 + 1;
        let kpte: u64 = unsafe {
            core::ptr::read_volatile((crate::addr::phys_to_virt(kpt + vpn2 * 8)) as *const u64)
        };
        if !ARCH.pte_is_valid(kpte) { continue; }

        let upte: u64 = unsafe {
            core::ptr::read_volatile((crate::addr::phys_to_virt(user_pt + vpn2 * 8)) as *const u64)
        };
        if !ARCH.pte_is_valid(upte) {
            continue; // wholesale copy will install it
        }
        if ARCH.pte_is_leaf(kpte, 2) || ARCH.pte_is_leaf(upte, 2) {
            // A gigapage on either side cannot be merged — the kernel entry
            // would be dropped entirely.
            return Some((vpn2, entries_per_table()));
        }

        let k_l1 = ARCH.pte_phys(kpte);
        let u_l1 = ARCH.pte_phys(upte);
        let mut vpn1_next = 0usize;
        loop {
            let vpn1 = next_valid(k_l1, vpn1_next, entries_per_table());
            if vpn1 >= entries_per_table() { break; }
            vpn1_next = vpn1 + 1;
            let kl1: u64 = unsafe {
                core::ptr::read_volatile((crate::addr::phys_to_virt(k_l1 + vpn1 * 8)) as *const u64)
            };
            if !ARCH.pte_is_valid(kl1) { continue; }
            let ul1: u64 = unsafe {
                core::ptr::read_volatile((crate::addr::phys_to_virt(u_l1 + vpn1 * 8)) as *const u64)
            };
            if ARCH.pte_is_valid(ul1) {
                return Some((vpn2, vpn1));
            }
        }
    }
    None
}

/// Tear down a **user** page table: free its own intermediate tables and its
/// USER leaf pages, and release its `PT_META` slot.
///
/// This is the teardown [`destroy_pagetable`] cannot be: that one recurses
/// into every valid non-leaf entry, which on a user PT that has been through
/// [`copy_kernel_entries_to_user`] means walking into — and freeing — the
/// kernel's own L1/L0 tables. Handing those frames back to the PMM while the
/// kernel is still executing out of them is not a leak, it is a machine that
/// stops.
///
/// Kernel tables are grafted in at two different depths and both must be
/// recognised:
///   - **L2**: a VPN[2] slot the user never touched holds a copy of the
///     kernel's L2 PTE, i.e. a pointer to the kernel's L1 table.
///   - **L1**: at VPN[2]=0 the user owns the L1 table, but individual slots
///     inside it (CLINT, PLIC, UART, …) point at the kernel's L0 tables.
///     A teardown that compared only at L2 would recurse into the user's own
///     L1, reach slot 16, and free the kernel's CLINT L0 table — a corruption
///     that surfaces at a random later moment, nowhere near this code.
///
/// Leaf pages are released through [`crate::cow::page_decref`], so a page
/// still shared with a forked peer survives; an untracked (sole-owner) page is
/// freed. The vDSO frame is kernel-owned and mapped USER_RO into every address
/// space, so it is skipped explicitly.
pub fn destroy_user_pagetable(pt_phys: usize) {
    // No reserved window: on the construction paths nothing can have mapped
    // shm/MMIO into this PT yet (see `destroy_user_pagetable_skip_range`).
    let _ = destroy_user_pagetable_skip_range(pt_phys, 0, 0);
}

/// Page-table teardowns [`destroy_user_pagetable_skip_range`] refused because
/// a hart still translated through the root. Zero on a correct kernel: every
/// path that frees a lived table first moves every hart off it.
pub static LIVE_ROOT_REFUSALS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Is the frame behind this user leaf the task's own, and therefore its to
/// release?
///
/// Four conditions, and each excludes a different kind of frame that a user
/// page table can legitimately point at without owning:
///
/// * **No `USER` bit** — a kernel mapping that reached a user table. Never
///   ours. This arm has **no test and cannot be given a useful one**: mutating
///   it away fails nothing, because nothing upstream can put a kernel leaf
///   where this function would see one. Kept as defence in depth, and
///   recorded here as an untested guard rather than given a test that would
///   pass against any mutation of it.
///
///   "Nothing upstream" is an enumeration, not a hope — re-derived 2026-09-06
///   because the previous wording credited it all to one guard and there are
///   two. Every function in this file that WRITES a PTE, and what stops each:
///
///   - `map` and `unmap` — `write_would_enter_kernel_table`, which is the
///     guard the old comment named.
///   - `demand::handle_page_fault` — the same call, at `demand.rs`.
///   - `add_user_leaf_perms` — **not that guard.** It has its own: it refuses
///     any leaf above L0 (a superpage means the kernel's merged entries, or
///     a locked row's region, which must stay as mapped) and
///     refuses any leaf without `USER`, so it can only ever rewrite a user
///     leaf. Remove that `USER` check and this arm becomes reachable; the
///     other guard will not catch it. (Its own doc comment, "Verified true,
///     not just asserted", cites these same two lines back at this one.)
///   - `remap_range` — never called with a user root: its only callers pass
///     `kpt`, the kernel table, during boot-time permission hardening.
///   - `map_mega` — with a user root from two callers, neither of which
///     reaches this function: `map_recorded_mmio_into` (aarch64 device
///     windows, `KERNEL_RW`: no `USER` bit) and `map_user_mega_range` (a
///     locked row's boot-reserved region, Kconfig `LOCKED_HUGE_LEAVES`).
///     Both are LEVEL-1 leaves, which teardown and `take_user_leaf` skip
///     before they get here: only level-0 leaves are judged by this function.
///
///   So the property holds, and it holds through two independent mechanisms
///   in different functions. A reader deleting one of them on the strength of
///   the other is the failure this note exists to prevent.
/// * **Inside `skip_lo..skip_hi`** — the shared-memory and MMIO window.
///   `shm_map_user` and `mmio_map_user` install real `USER` leaves there whose
///   frames belong to a device or to another task.
/// * **The vDSO page** — one frame, mapped into every address space.
/// * **`cow::page_decref` says no** — a COW page another task still holds.
///
/// Extracted so `unmap_user_and_free` and `destroy_user_pagetable_skip_range`
/// cannot disagree about what a task owns. They used to be the same rule
/// written once: teardown had it, and `sys_munmap` had nothing at all, which
/// is how every mmap/munmap pair leaked its frames for the life of the boot.
fn user_leaf_is_task_owned(
    l0: u64, va: usize, skip_lo: usize, skip_hi: usize, vdso_phys: usize, tramp_phys: usize,
) -> bool {
    if !ARCH.pte_perms(l0).user { return false; }
    if va >= skip_lo && va < skip_hi { return false; }
    let phys = ARCH.pte_phys(l0);
    if vdso_phys != 0 && phys == vdso_phys { return false; }
    // Wave 13: nor the riscv64 sigreturn trampoline (the kernel's own page).
    if tramp_phys != 0 && phys == tramp_phys { return false; }
    crate::cow::page_decref(phys)
}

/// Unmap one user page and release its frame if the task owns it.
///
/// `sys_munmap` used `unmap`, which clears the PTE and frees nothing. There is
/// no per-task frame list, and exit teardown only frees what is still mapped —
/// so every `mmap` + `munmap` pair leaked its frames permanently. A fork+exec
/// loop repeats it with a fresh break each time, and the end state is a PMM
/// with nothing left: no further fork, exec, mmap or page-table allocation for
/// the rest of the boot. For a robot that is not a crash, it is a machine that
/// cannot respawn its controller.
///
/// Returns whether a frame was actually released, so a caller can count.
///
/// **`page_decref` has a side effect and is called exactly once per page**, in
/// `user_leaf_is_task_owned`. Calling it twice for one unmap would drop a
/// shared COW page while another task still reads it — the failure mode of a
/// double free here is not a leak but kernel memory handed to two owners.
///
/// Single-page form of [`unmap_user_range_and_free`]; `sys_munmap` uses the
/// range form. Kept for callers that remove one page (host tests today).
pub fn unmap_user_and_free(
    pt_phys: usize, vaddr: usize, skip_lo: usize, skip_hi: usize,
) -> bool {
    match take_user_leaf(pt_phys, vaddr, skip_lo, skip_hi) {
        None => false,
        Some(owned) => {
            // Shoot down BEFORE the free: another hart must not read a frame
            // the allocator may already have reissued.
            ARCH.tlb_shootdown(pt_phys, vaddr & !(PAGE_SIZE - 1), PAGE_SIZE);
            if owned != 0 {
                let _ = pmm::free_page(PhysAddr::new(owned));
                return true;
            }
            false
        }
    }
}

/// Pages cleared per shootdown by [`unmap_user_range_and_free`]: the frames
/// waiting for it are held on the stack (8 B each).
pub const UNMAP_BATCH_PAGES: usize = 32;

/// [`unmap_user_and_free`] over `[start, end)`, with ONE shootdown per batch of
/// up to [`UNMAP_BATCH_PAGES`] pages instead of one per page: clear the batch's
/// PTEs, shoot the batch's range down, and only then free its frames. On a
/// board where another hart holds the address space that is one SBI
/// `remote_sfence_vma` (one IPI round) per batch; where none does (every
/// address space today — one hart per task) it is one scan of the published
/// roots per batch. Returns the frames released.
pub fn unmap_user_range_and_free(
    pt_phys: usize, start: usize, end: usize, skip_lo: usize, skip_hi: usize,
) -> u32 {
    let mut freed: u32 = 0;
    let mut va = start & !(PAGE_SIZE - 1);
    while va < end {
        let batch_start = va;
        let mut frames = [0usize; UNMAP_BATCH_PAGES];
        let mut n = 0;
        let mut cleared = false;
        let mut i = 0;
        while i < UNMAP_BATCH_PAGES && va < end {
            if let Some(owned) = take_user_leaf(pt_phys, va, skip_lo, skip_hi) {
                cleared = true;
                if owned != 0 { frames[n] = owned; n += 1; }
            }
            va += PAGE_SIZE;
            i += 1;
        }
        if cleared {
            ARCH.tlb_shootdown(pt_phys, batch_start, va - batch_start);
        }
        for &f in &frames[..n] {
            let _ = pmm::free_page(PhysAddr::new(f));
            freed = freed.saturating_add(1);
        }
    }
    freed
}

/// Free leaf tables a fork found empty and already unhooked from the
/// parent's root (`cow::fork_cow`'s pruning), after the caller's shootdown of
/// that root: each frame goes back, and its charge to the root's owner.
pub(crate) fn release_pruned_tables(root: usize, tables: &[usize]) {
    for &t in tables {
        let _ = pmm::free_page(PhysAddr::new(t));
        let _ = table_charge(root, false);
    }
}

/// What one user page of an address space is, for `mprotect` (wave 13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserPage {
    /// Nothing there (no leaf, no demand marker).
    Missing,
    /// A 4 KiB user leaf; `exec`: its execute bit.
    Leaf { exec: bool },
    /// A demand-paging reservation not touched yet.
    Demand,
    /// Something `mprotect` does not touch: a kernel table or mapping, a
    /// megapage or gigapage, a non-user leaf.
    Other,
}

/// Classify the page at `vaddr` (page-aligned) of the user table `pt_phys`.
/// The kernel's frames every address space maps the same (the vDSO data page,
/// the signal trampoline): a user's page table never gets write on them.
/// `mprotect(RW)` on the vDSO wrote the one global frame in place while it
/// had no other counted holder, and made it copy-on-write otherwise. Gate
/// canary `vdso-write-canary`: answers `false`.
fn kernel_shared_user_frame(phys: usize) -> bool {
    if cfg!(feature = "vdso-write-canary") {
        return false;
    }
    let vdso = crate::vdso::vdso_phys();
    let tramp = crate::vdso::sigtramp_phys();
    (vdso != 0 && phys == vdso) || (tramp != 0 && phys == tramp)
}

/// Does the user leaf at `vaddr` map a [`kernel_shared_user_frame`]? What
/// `mprotect` refuses a write over (`-EACCES`).
pub fn user_leaf_is_kernel_shared(pt_phys: usize, vaddr: usize) -> bool {
    match user_l0_leaf(pt_phys, vaddr) {
        Some(ptr) => {
            let pte = unsafe { core::ptr::read_volatile(ptr) };
            ARCH.pte_perms(pte).user && kernel_shared_user_frame(ARCH.pte_phys(pte))
        }
        None => false,
    }
}

pub fn user_page(pt_phys: usize, vaddr: usize) -> UserPage {
    if write_would_enter_kernel_table(pt_phys, vaddr) {
        return UserPage::Other;
    }
    let Ok(ptr) = walk(pt_phys, vaddr, false) else { return UserPage::Missing };
    let pte = unsafe { core::ptr::read_volatile(ptr) };
    if pte == 0 {
        return UserPage::Missing;
    }
    if !ARCH.pte_is_valid(pte) {
        return if ARCH.pte_is_demand(pte) { UserPage::Demand } else { UserPage::Other };
    }
    if !ARCH.pte_is_leaf(pte, 0) {
        return UserPage::Other;
    }
    let f = ARCH.pte_perms(pte);
    if !f.user { UserPage::Other } else { UserPage::Leaf { exec: f.exec } }
}

/// Give every user leaf and demand reservation in `[start, end)` exactly the
/// write permission `write` (wave 13, `mprotect`), then one shootdown of the
/// range if anything changed. Read stays; execute is never combined with
/// write (a leaf with execute is left alone when `write`; the caller refuses
/// that range first).
///
/// **Copy-on-write.** A COW leaf is read-only and shared with another
/// address space. Made writable it stays COW: the next store breaks it, as it
/// would have before (the page was writable when the fork made it COW). Made
/// read-only it loses the COW marker, so a store faults instead of breaking
/// it into a writable copy; its frame stays shared and counted. Wave 14
/// (security): a plain read-only leaf whose frame another space maps (a fork
/// shares read-only pages as they are) made writable becomes COW too, never
/// writable in place (`rewrite_leaf_write`). Returns how many entries
/// changed.
pub fn protect_user_range(pt_phys: usize, start: usize, end: usize, write: bool) -> usize {
    let mut changed = 0usize;
    let first = start & !(PAGE_SIZE - 1);
    let mut va = first;
    while va < end {
        if !write_would_enter_kernel_table(pt_phys, va) {
            if let Ok(ptr) = walk(pt_phys, va, false) {
                let pte = unsafe { core::ptr::read_volatile(ptr) };
                let new = if ARCH.pte_is_valid(pte) && ARCH.pte_is_leaf(pte, 0) {
                    let f = ARCH.pte_perms(pte);
                    let cow = ARCH.pte_is_cow(pte);
                    if !f.user || (write && (f.exec || kernel_shared_user_frame(ARCH.pte_phys(pte)))) {
                        None
                    } else if write && cow {
                        None
                    } else if f.write == write && !cow {
                        None
                    } else {
                        // Written here, under the refcount table: adding
                        // write to a frame another space maps is a COW grant.
                        if rewrite_leaf_write(ptr, pte, f, write) { changed += 1; }
                        None
                    }
                } else if !ARCH.pte_is_valid(pte) && ARCH.pte_is_demand(pte) {
                    let f = ARCH.pte_demand_perms(pte);
                    if f.write == write || (write && f.exec) {
                        None
                    } else {
                        Some(ARCH.pte_make_demand(PagePerms { write, ..f }))
                    }
                } else {
                    None
                };
                if let Some(word) = new {
                    unsafe { core::ptr::write_volatile(ptr, word) };
                    changed += 1;
                }
            }
        }
        va += PAGE_SIZE;
    }
    if changed != 0 {
        ARCH.tlb_shootdown(pt_phys, first, va - first);
    }
    changed
}

/// Rewrite the user leaf at `ptr` (now `pte`, permissions `f`, never
/// executable when `write`) with `write` as its write permission and no COW
/// marker. Wave 14 (security): when write is ADDED and the frame has another
/// holder (a fork shared it read-only, or it is copy-on-write), the leaf is
/// made copy-on-write instead, so the first store breaks it into this space's
/// own copy; setting the bit would let this space write a frame another
/// space maps (a fork child's `mprotect(RW)` wrote its parent's page). The
/// count is read, the entry written, and the count read again: a fork that
/// counts the frame (`fork_cow_shared`: addref, then swap the parent's entry)
/// between the first read and the write either swaps the entry after it (and
/// makes it copy-on-write itself) or is seen by the second read, which makes
/// it copy-on-write here.
/// Gate canary `mprotect-shared-canary`: the bit is set whatever the count.
fn rewrite_leaf_write(ptr: *mut u64, pte: u64, f: PagePerms, write: bool) -> bool {
    let phys = ARCH.pte_phys(pte);
    let Ok(word) = ARCH.pte_make_leaf(phys, PagePerms { write, ..f }, 0) else { return false };
    let checked = write && !cfg!(feature = "mprotect-shared-canary");
    let cow = checked && crate::cow_table::page_is_shared(phys);
    let word = if cow { ARCH.pte_share_cow(word) } else { word };
    // SAFETY: `ptr` is an aligned L0 entry of a live user table.
    unsafe { core::ptr::write_volatile(ptr, word) };
    if checked && !cow && crate::cow_table::page_is_shared(phys) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(ptr, ARCH.pte_share_cow(word)) };
    }
    true
}

/// Set (`write == true`) or clear (`false`) the write permission of every
/// 4 KiB USER leaf in `[start, end)` of the user table rooted at `pt_phys`,
/// then shoot the range down on every hart that may hold it — ONE shootdown
/// for the whole range, and only if a leaf changed. Returns how many leaves
/// changed. Wave 11 (LEASE3): the producer-side lease seal
/// (`azos_ipc::lease`, `SealHook`).
///
/// Touches only what [`add_user_leaf_perms`] would: L0 leaves that are
/// already `USER`, below any kernel table (`write_would_enter_kernel_table`
/// refuses the rest), never a megapage or gigapage. Write is never added to
/// an executable leaf (W^X). A missing leaf is skipped: a page that is not
/// mapped has nothing to seal. Every other permission bit is carried over.
///
/// The removal needs its shootdown before it is a guarantee (another hart may
/// cache the writable translation); the give-back is shot down as well, so a
/// hart holding the read-only translation does not fault once more on it.
pub fn set_user_range_write(pt_phys: usize, start: usize, end: usize, write: bool) -> usize {
    let mut changed = 0usize;
    let first = start & !(PAGE_SIZE - 1);
    let mut va = first;
    while va < end {
        if let Some(l0_ptr) = user_l0_leaf(pt_phys, va) {
            let pte: u64 = unsafe { core::ptr::read_volatile(l0_ptr) };
            let f = ARCH.pte_perms(pte);
            if f.user && f.write != write
                && !(write && (f.exec || kernel_shared_user_frame(ARCH.pte_phys(pte))))
                && rewrite_leaf_write(l0_ptr, pte, f, write)
            {
                changed += 1;
            }
        }
        va += PAGE_SIZE;
    }
    if changed != 0 {
        ARCH.tlb_shootdown(pt_phys, first, va - first);
    }
    changed
}

/// Flip every 4 KiB USER leaf in `[start, end)` from read-write to
/// read-execute, ALL OR NOTHING, then shoot the range down on every hart.
/// RFC-0053 stage L0b: `DOMAIN_MODULE_MAP_X`, the only path in the tree that
/// turns ring-3 data into ring-3 code. Returns the number of pages flipped,
/// or `Err` with nothing changed.
///
/// Every page must be, before anything is written:
///
/// * a valid L0 leaf the user-image mapper produced (no megapage, no kernel
///   table: [`user_l0_leaf`]), `USER`, readable, **writable, not executable**
///   (a page that is already executable, or read-only, was not produced by
///   `sys_mmap` for this purpose);
/// * not copy-on-write and held by no other task (`page_getref` <= 1): a
///   frame another address space still maps would become executable there
///   through a write here, or change under this task's code;
/// * outside `[skip_lo, skip_hi)` (the shared-memory/MMIO window, whose
///   frames other tasks or devices write) and not the vDSO page.
///
/// The write permission is removed in the same PTE update that adds execute,
/// so no instant exists where the page is both (W^X). Instruction-cache
/// synchronisation is the caller's (`DOMAIN_MODULE_MAP_X`), after this returns.
pub fn set_user_range_exec(pt_phys: usize, start: usize, end: usize, skip_lo: usize, skip_hi: usize) -> KResult<usize> {
    if start & (PAGE_SIZE - 1) != 0 || end <= start || end & (PAGE_SIZE - 1) != 0 {
        return Err(KernelError::InvalidArg);
    }
    let vdso = crate::vdso::vdso_phys();
    let mut va = start;
    while va < end {
        if va < skip_hi && va.saturating_add(PAGE_SIZE) > skip_lo { return Err(KernelError::InvalidArg); }
        let Some(l0_ptr) = user_l0_leaf(pt_phys, va) else { return Err(KernelError::InvalidArg) };
        let pte: u64 = unsafe { core::ptr::read_volatile(l0_ptr) };
        let f = ARCH.pte_perms(pte);
        let phys = ARCH.pte_phys(pte);
        if !f.user || !f.read || !f.write || f.exec || ARCH.pte_is_cow(pte)
            || (vdso != 0 && phys == vdso) || crate::cow::page_getref(phys) > 1
        {
            return Err(KernelError::InvalidArg);
        }
        va += PAGE_SIZE;
    }
    let mut changed = 0usize;
    va = start;
    while va < end {
        if let Some(l0_ptr) = user_l0_leaf(pt_phys, va) {
            let pte: u64 = unsafe { core::ptr::read_volatile(l0_ptr) };
            let f = ARCH.pte_perms(pte);
            // Gate canary only (`lx-wx-canary`): leave the page writable as
            // well, so the readback in `DOMAIN_MODULE_MAP_X` must catch it.
            let rx = PagePerms { write: cfg!(feature = "lx-wx-canary"), exec: true, ..f };
            let word = ARCH.pte_make_leaf(ARCH.pte_phys(pte), rx, 0).map_err(mmu_error_to_kernel_error)?;
            unsafe { core::ptr::write_volatile(l0_ptr, word) };
            changed += 1;
        }
        va += PAGE_SIZE;
    }
    ARCH.tlb_shootdown(pt_phys, start, end - start);
    Ok(changed)
}

/// The valid 4 KiB leaf PTE at `vaddr` in a user table, by the hand descent
/// [`take_user_leaf`] uses, or `None` (a kernel table, a megapage/gigapage,
/// nothing mapped).
fn user_l0_leaf(pt_phys: usize, vaddr: usize) -> Option<*mut u64> {
    if write_would_enter_kernel_table(pt_phys, vaddr) { return None; }
    let l2t = l2_table(pt_phys, vaddr);
    if no_l2(l2t) { return None; }
    let vpn2 = ARCH.vpn(vaddr, 2);
    let l2: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(l2t + vpn2 * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l2) || ARCH.pte_is_leaf(l2, 2) { return None; }
    let vpn1 = ARCH.vpn(vaddr, 1);
    let l1: u64 = unsafe {
        core::ptr::read_volatile((crate::addr::phys_to_virt(ARCH.pte_phys(l2) + vpn1 * 8)) as *const u64)
    };
    if !ARCH.pte_is_valid(l1) || ARCH.pte_is_leaf(l1, 1) { return None; }
    let vpn0 = ARCH.vpn(vaddr, 0);
    let l0_ptr = (crate::addr::phys_to_virt(ARCH.pte_phys(l1) + vpn0 * 8)) as *mut u64;
    let l0: u64 = unsafe { core::ptr::read_volatile(l0_ptr) };
    if !ARCH.pte_is_valid(l0) || !ARCH.pte_is_leaf(l0, 0) { return None; }
    Some(l0_ptr)
}

/// Clear the 4 KiB user leaf at `vaddr` WITHOUT invalidating any TLB, and say
/// what the caller must release once it has: `None` if there was no leaf of
/// ours to clear (not mapped, a megapage/gigapage — the kernel's, or a locked
/// row's region —, a kernel table), `Some(0)`
/// if one was cleared but its frame is not the task's (shm window, vDSO, a
/// COW sibling still holds it), `Some(phys)` if the frame is the task's own.
/// The caller MUST shoot the address down before freeing `phys`.
fn take_user_leaf(pt_phys: usize, vaddr: usize, skip_lo: usize, skip_hi: usize) -> Option<usize> {
    if write_would_enter_kernel_table(pt_phys, vaddr) { return None; }

    // Descend by hand rather than through `walk`, for the same reason `unmap`
    // does: `walk` returns a megapage or gigapage leaf directly, and treating
    // one as a 4 KiB page would hand `page_decref` the base of a 2 MiB region.
    // Neither is ever created by `map`, so reaching one means a kernel mapping,
    // and it is not ours to touch.
    let l2t = l2_table(pt_phys, vaddr);
    if no_l2(l2t) { return None; }
    let vpn2 = ARCH.vpn(vaddr, 2);
    let l2: u64 = unsafe { core::ptr::read_volatile((crate::addr::phys_to_virt(l2t + vpn2 * 8)) as *const u64) };
    if !ARCH.pte_is_valid(l2) || ARCH.pte_is_leaf(l2, 2) { return None; }

    let vpn1 = ARCH.vpn(vaddr, 1);
    let l1: u64 = unsafe {
        core::ptr::read_volatile((crate::addr::phys_to_virt(ARCH.pte_phys(l2) + vpn1 * 8)) as *const u64)
    };
    if !ARCH.pte_is_valid(l1) || ARCH.pte_is_leaf(l1, 1) { return None; }

    let vpn0 = ARCH.vpn(vaddr, 0);
    let l0_ptr = (crate::addr::phys_to_virt(ARCH.pte_phys(l1) + vpn0 * 8)) as *mut u64;
    let l0: u64 = unsafe { core::ptr::read_volatile(l0_ptr) };
    if !ARCH.pte_is_valid(l0) || !ARCH.pte_is_leaf(l0, 0) { return None; }
    // N12i: a copy of the kernel's own translation (a device window the
    // merge put in this table) is not the task's to clear or hand to the
    // frame free.
    if !user_may_modify(l0, vaddr, 0) { return None; }

    let owned = user_leaf_is_task_owned(
        l0, vaddr & !(PAGE_SIZE - 1), skip_lo, skip_hi, crate::vdso::vdso_phys(),
        crate::vdso::sigtramp_phys(),
    );
    let phys = ARCH.pte_phys(l0);

    unsafe { core::ptr::write_volatile(l0_ptr, ARCH.pte_empty()) };

    Some(if owned { phys } else { 0 })
}

/// [`destroy_user_pagetable`] for a *post-construction* address space: leaf
/// frames whose VA falls in `[skip_lo, skip_hi)` are left un-freed.
///
/// K-C22 wired teardown into exec replacement and task-slot reuse — page
/// tables that have LIVED, which the plain variant was never safe for: a
/// running process may have shm and MMIO frames mapped USER into its PT
/// (`shm_map_user` / `mmio_map_user` in the sched crate), and those frames
/// are not the address space's to free. Shm pages are PMM pages owned by the
/// shm registry and possibly mapped by other processes — `page_decref` has
/// never tracked them, so it would report "sole owner" and this walk would
/// hand a page another process is actively using back to the allocator. MMIO
/// frames merely bounce off `pmm::free_page`'s range check, but skipping
/// them keeps the ownership rule uniform instead of leaning on that.
///
/// Both kinds only ever land in one VA window (`reserve_window_va` in the
/// sched crate is the single allocator for it), so callers pass that window. The window's own
/// L1/L0 *tables* were allocated by `vmm::map` on this PT and ARE freed —
/// the mappings die with the address space; the frames survive under their
/// real owner.
///
/// **Free order**: the ROOT frame is freed last, after the full 512-slot L2
/// walk. That used to be the whole argument for the reuse-time reclaim in the
/// scheduler (`try_task_create_affinity`, K-C22(B)) running while the hart
/// that zombified this address space was still a few instructions short of
/// its `csrw satp` away from it: the root is the only frame that hart still
/// translates through, and it goes last. A few instructions of guest time are
/// not a bound once the host deschedules that hart's vCPU, and the root was
/// then reissued under it (see the refusal below). The order stays; the
/// refusal is what makes it safe.
///
/// **Refused, whole, while any hart still translates through `pt_phys`**
/// ([`azos_arch_api::Mmu::root_holders`]): returns that hart mask and
/// frees nothing — leaf pages, L0/L1 tables and the root alike, because a
/// live root reaches all of them. A leaked address space is a bounded loss;
/// its frames reissued under a hart that still walks them is the page fault
/// on kernel text this check was added for (a dying hart kept the root in
/// `satp` while another hart's slot claim freed it and reused the frame).
/// Returns 0 when the table was torn down (or `pt_phys` is 0).
pub fn destroy_user_pagetable_skip_range(pt_phys: usize, skip_lo: usize, skip_hi: usize) -> usize {
    if pt_phys == 0 { return 0; }
    // Out of the merged-root roster before the first frame is freed (N12g):
    // `propagate_kernel_entries` writes into roster roots under `PT_META`,
    // one hold per root, and this lock acquisition orders after any
    // per-root merge in progress. A refused
    // teardown below leaks the root; it stays out of the roster.
    meta_set_merged(pt_phys, false);
    // Wave 14 (DEMANDPAGE): the root's region records go with it, refused
    // teardown included (a refused root is leaked, never reused). Left in
    // place, a later address space given the same root frame would inherit
    // reservations it never made.
    crate::pager::forget(pt_phys);

    let holders = ARCH.root_holders(pt_phys);
    if holders != 0 {
        LIVE_ROOT_REFUSALS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return holders;
    }

    let kpt = *KERNEL_PT.lock();
    let vdso_phys = crate::vdso::vdso_phys();
    let tramp_phys = crate::vdso::sigtramp_phys();

    let _ = for_each_user_l2(pt_phys, kpt, |u_l2, k_l2, base| {
        let mut vpn2_next = 0usize;
        loop {
            let vpn2 = crate::vmm::next_valid(u_l2, vpn2_next, l2_slots());
            if vpn2 >= l2_slots() { break; }
            vpn2_next = vpn2 + 1;
            let l2: u64 = unsafe {
                core::ptr::read_volatile((crate::addr::phys_to_virt(u_l2 + vpn2 * 8)) as *const u64)
            };
            // Gigapage leaves are only ever created by the kernel mapper.
            if !ARCH.pte_is_valid(l2) || ARCH.pte_is_leaf(l2, 2) { continue; }
            let u_l1 = ARCH.pte_phys(l2);

            // Which L1 table does the kernel use for this slot (if any)?
            let k_l1 = if k_l2 != 0 {
                let kpte: u64 = unsafe {
                    core::ptr::read_volatile((crate::addr::phys_to_virt(k_l2 + vpn2 * 8)) as *const u64)
                };
                if ARCH.pte_is_valid(kpte) && !ARCH.pte_is_leaf(kpte, 2) { ARCH.pte_phys(kpte) } else { 0 }
            } else { 0 };

            if k_l1 != 0 && k_l1 == u_l1 {
                continue; // borrowed wholesale from the kernel PT — not ours to free
            }
            // A kernel-only slot is the kernel's fixed L1 (linked into every
            // root), never freed; a table that is not the kernel's there is
            // canary `kernel-l1-copy`'s copy, leaked rather than walked.
            if base == 0 && kernel_only_slot(vpn2) {
                continue;
            }

            let mut vpn1_next = 0usize;
            loop {
                let vpn1 = crate::vmm::next_valid(u_l1, vpn1_next, entries_per_table());
                if vpn1 >= entries_per_table() { break; }
                vpn1_next = vpn1 + 1;
                let l1: u64 = unsafe {
                    core::ptr::read_volatile((crate::addr::phys_to_virt(u_l1 + vpn1 * 8)) as *const u64)
                };
                // A level-1 leaf is never this table's to free: a kernel mapping
                // (the aarch64 device windows) or a locked row's region
                // (`map_user_mega_range`, Kconfig LOCKED_HUGE_LEAVES), whose frames
                // are the row's for the whole boot (`crate::huge`) — leave it alone.
                if !ARCH.pte_is_valid(l1) || ARCH.pte_is_leaf(l1, 1) { continue; }
                let u_l0 = ARCH.pte_phys(l1);

                if k_l1 != 0 {
                    let kl1: u64 = unsafe {
                        core::ptr::read_volatile((crate::addr::phys_to_virt(k_l1 + vpn1 * 8)) as *const u64)
                    };
                    if ARCH.pte_is_valid(kl1) && !ARCH.pte_is_leaf(kl1, 1) && ARCH.pte_phys(kl1) == u_l0 {
                        continue; // merged kernel L0 table — not ours to free
                    }
                }

                let mut vpn0_next = 0usize;
                // A leaf table wholly inside the skipped window owns no frame:
                // only the table itself goes (wave 13: not walked).
                let lo = base | (vpn2 << L2_SHIFT) | (vpn1 << L1_SHIFT);
                if lo >= skip_lo && lo + (1usize << L1_SHIFT) <= skip_hi {
                    vpn0_next = entries_per_table();
                }
                loop {
                    let vpn0 = crate::vmm::next_valid(u_l0, vpn0_next, entries_per_table());
                    if vpn0 >= entries_per_table() { break; }
                    vpn0_next = vpn0 + 1;
                    let l0: u64 = unsafe {
                        core::ptr::read_volatile((crate::addr::phys_to_virt(u_l0 + vpn0 * 8)) as *const u64)
                    };
                    if !ARCH.pte_is_valid(l0) || !ARCH.pte_is_leaf(l0, 0) { continue; }
                    // A leaf without USER is a kernel mapping that found its way
                    // in — never ours to free.
                    //
                    // USER leaves installed by `shm_map_user`/`mmio_map_user` are
                    // *not* owned by this address space either — that is what
                    // `skip_lo..skip_hi` exists for (see the function doc); the
                    // construction-failure paths pass an empty window because no
                    // such mapping can exist before the loader/fork returns.
                    let va = base | (vpn2 << L2_SHIFT) | (vpn1 << L1_SHIFT) | (vpn0 << PAGE_SHIFT);
                    if user_leaf_is_task_owned(l0, va, skip_lo, skip_hi, vdso_phys, tramp_phys) {
                        let _ = pmm::free_page(PhysAddr::new(ARCH.pte_phys(l0)));
                    }
                }
                let _ = pmm::free_page(PhysAddr::new(u_l0));
            }
            let _ = pmm::free_page(PhysAddr::new(u_l1));
        }

        Ok(())
    });
    free_user_upper_tables(pt_phys, kpt);

    meta_remove(pt_phys);
    let _ = pmm::free_page(PhysAddr::new(pt_phys));
    0
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The structured kernel log's region (Kconfig `KLOG`): the ring
//! `azos_drv_sys::klog` pushes every log line into, as a kernel-owned memory
//! object a ring-3 reader maps.
//!
//! The object is created read-only for any mapper (the kernel writes it
//! through its direct map), published to the minter (`azos_ipc::kregion`), and
//! granted by a topology row, `MemObj klog.ring` (`READ|MAP`): `LOGD.ELF`'s,
//! which drains it into files. No other task has it.
//!
//! Called from `kernel_main` once the page allocator can make a memory object
//! and before any task is seeded. The lines printed before it sit in the
//! small ring `azos_drv_sys::klog` keeps in `.bss`; `attach` copies them over.

use azos_ipc::memobj::{memobj_create_kernel, MemPerms, MemSpec};

/// Create the region, hand the log over to it and publish it.
pub(crate) fn install() {
    use azos_drv_sys::klog;
    if !klog::ENABLED {
        return;
    }
    // The one minter of every kernel-owned region, installed here too so a
    // build without the introspection tree or the terminal regions has it.
    azos_ipc::cap_seed::set_shm_inspect_minter(azos_ipc::kregion::seed_mint_any);
    let pages = klog::wire::region_bytes(klog::ENTRIES).div_ceil(azos_arch::PAGE_SIZE);
    let Some((obj, phys)) = memobj_create_kernel(pages, &MemSpec::contig(MemPerms::ReadOnly, false)) else {
        azos_drv_sys::kwarn!("[KLOG] no memory for the ring ({} pages): the structured log stays in the early ring", pages);
        return;
    };
    let base = azos_mm::addr::phys_to_virt(phys) as *mut u8;
    // SAFETY: a fresh, zeroed, page-aligned, kernel-owned object that is never
    // freed; called once, on the boot hart, before the other harts start.
    let Some(early_lost) = (unsafe { klog::attach(base, pages * azos_arch::PAGE_SIZE) }) else {
        azos_drv_sys::kwarn!("[KLOG] the ring did not take over from the early one");
        return;
    };
    azos_ipc::kregion::publish(azos_ipc::kregion::Region::KlogRing, obj);
    azos_drv_sys::kprintln!(
        "[KLOG] ring {} records ({} KiB), granted as MemObj klog.ring; early ring {} records, {} lost",
        klog::ENTRIES, pages * azos_arch::PAGE_SIZE / 1024, klog::EARLY_ENTRIES, early_lost
    );
}

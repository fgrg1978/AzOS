// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The record substrate's region (Kconfig `KLOG`): the rings
//! `azos_records` places the kernel log, the decision records and the
//! actuation telemetry in, as a kernel-owned memory object a ring-3 reader
//! maps.
//!
//! The object is created read-only for any mapper (the kernel writes it
//! through its direct map), published to the minter (`azos_ipc::kregion`), and
//! granted by a topology row, `MemObj klog.ring` (`READ|MAP`): `LOGD.ELF`'s,
//! which drains it into files. No other task has it.
//!
//! Called from `kernel_main` once the page allocator can make a memory object
//! and before any task is seeded. The records written before it sit in the
//! small region `azos_records` keeps in `.bss`; `attach` copies them over.

use azos_ipc::memobj::{memobj_create_kernel, MemPerms, MemSpec};

const _: () = assert!(
    azos_records::REGION_BYTES <= azos_mm::memobj::MAX_MEMOBJ_PAGES * azos_arch::PAGE_SIZE,
    "the record region (KLOG_ENTRIES x 320 + DECISION_RECORDS_ENTRIES x 64 bytes) must fit one memory object"
);

/// Create the region, hand the records over to it and publish it.
pub(crate) fn install() {
    if !azos_records::KLOG {
        return;
    }
    // The one minter of every kernel-owned region, installed here too so a
    // build without the introspection tree or the terminal regions has it.
    azos_ipc::cap_seed::set_shm_inspect_minter(azos_ipc::kregion::seed_mint_any);
    let pages = azos_records::REGION_BYTES.div_ceil(azos_arch::PAGE_SIZE);
    let Some((obj, phys)) = memobj_create_kernel(pages, &MemSpec::contig(MemPerms::ReadOnly, false)) else {
        azos_drv_sys::kwarn!("[KLOG] no memory for the record region ({} pages): the records stay in the early region", pages);
        return;
    };
    let base = azos_mm::addr::phys_to_virt(phys) as *mut u8;
    let h = {
        let _masked = HANDOVER.lock_irqsave();
        // SAFETY: a fresh, zeroed, page-aligned, kernel-owned object that is
        // never freed; called once, on the boot hart, with interrupts masked,
        // before the other harts start.
        unsafe { azos_records::attach(base, pages * azos_arch::PAGE_SIZE, azos_drv_sys::timebase::TIMER_FREQ) }
    };
    let Some(h) = h else {
        azos_drv_sys::kwarn!("[KLOG] the record region did not take over from the early one");
        return;
    };
    azos_ipc::kregion::publish(azos_ipc::kregion::Region::KlogRing, obj);
    azos_drv_sys::kprintln!(
        "[KLOG] record region {} KiB, granted as MemObj klog.ring: kernel log {} records ({} lost before the handover), decisions {} lost",
        pages * azos_arch::PAGE_SIZE / 1024, ring_entries(azos_records::SOURCE_KLOG), h.klog_lost, h.decisions_lost
    );
}

/// Held, with interrupts masked, across the handover.
static HANDOVER: azos_sync::SpinLock<()> = azos_sync::SpinLock::new(());

fn ring_entries(source: u8) -> u32 {
    azos_records::RINGS.iter().find(|r| r.source == source).map_or(0, |r| r.entries)
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 boot hooks — SKELETON, matched to `entry/{riscv64,aarch64}/
//! boot_hooks.rs`. `arch_entry.rs` exposes them as the `ArchEntry` impl.

use crate::EarlyBoot;
use azos_drv_sys::kprintln;

/// PVH `hvm_start_info` (xen/include/public/arch-x86/hvm/start_info.h).
#[repr(C)]
struct HvmStartInfo {
    magic: u32,
    version: u32,
    flags: u32,
    nr_modules: u32,
    modlist_paddr: u64,
    cmdline_paddr: u64,
    rsdp_paddr: u64,
    memmap_paddr: u64,
    memmap_entries: u32,
    reserved: u32,
}

/// One PVH memory-map entry (E820 types: 1 = RAM).
#[repr(C)]
struct HvmMemmapEntry {
    addr: u64,
    size: u64,
    kind: u32,
    reserved: u32,
}

const PVH_MAGIC: u32 = 0x336e_c578;

/// First Rust on the boot CPU. Done: the console (COM1, polled), the banner,
/// the PVH start_info and its memory map. Not yet: the ACPI tables (RSDP ->
/// MADT for the CPUs, `crate::boot::discover_cpus` with `source: "MADT"`),
/// the frame allocator, the kernel page tables (Mmu), the heap, the
/// LAPIC/IOAPIC, the TSC calibration — the boot stops at the first of those
/// with a `todo!()` the panic handler prints.
pub fn arch_early_boot(hart_id: usize, fw_table: usize) -> EarlyBoot {
    azos_drv_sys::uart::init();
    azos_drv_sys::uart::console_register(&azos_drv_sys::uart::CONSOLE);

    kprintln!();
    kprintln!("========================================");
    kprintln!("  AzOS Rust kernel booted! (x86_64)");
    kprintln!("========================================");
    kprintln!();
    kprintln!("[BOOT] Hart ID:    {}", hart_id);
    kprintln!("[BOOT] PVH start_info: {:#x}", fw_table);
    kprintln!("[BOOT] Baseline:   x86-64-v{} (checked by boot.S before Rust)", crate::X86_64_LEVEL);

    // SAFETY: boot.S passes the PVH start_info's physical address, identity
    // mapped (0..4 GiB) by boot.S's page tables.
    let si = unsafe { &*(fw_table as *const HvmStartInfo) };
    if si.magic != PVH_MAGIC {
        kprintln!("[BOOT] PVH start_info magic {:#x} != {:#x}", si.magic, PVH_MAGIC);
    } else {
        kprintln!("[BOOT] PVH v{} flags={:#x} modules={} rsdp={:#x}",
                  si.version, si.flags, si.nr_modules, si.rsdp_paddr);
        let mut ram = 0u64;
        if si.version >= 1 && si.memmap_paddr != 0 {
            for i in 0..si.memmap_entries as usize {
                // SAFETY: memmap_entries entries at memmap_paddr (identity mapped).
                let e = unsafe { &*((si.memmap_paddr as usize + i * core::mem::size_of::<HvmMemmapEntry>()) as *const HvmMemmapEntry) };
                kprintln!("[MEM] {:#012x}+{:#010x} type {}", e.addr, e.size, e.kind);
                if e.kind == 1 {
                    ram += e.size;
                }
            }
        }
        kprintln!("[MEM] RAM: {} KiB", ram / 1024);
    }
    let _ = si.cmdline_paddr;
    let _ = si.modlist_paddr;
    let _ = si.reserved;

    todo!("x86_64: arch_early_boot: ACPI MADT CPUs, frame allocator, kernel page tables (Mmu), heap, LAPIC/IOAPIC")
}

/// Device windows mapped once the heap exists (PCIe ECAM from the MCFG,
/// the HPET, the IOAPIC).
pub fn arch_map_late_mmio() {
    todo!("x86_64: arch_map_late_mmio: ECAM (MCFG), HPET, IOAPIC")
}

/// INIT-SIPI-SIPI to each MADT APIC ID up to `num_cpus`, with the real-mode
/// trampoline copied below 1 MiB.
pub fn arch_wake_secondaries(_num_cpus: usize) {
    todo!("x86_64: arch_wake_secondaries: INIT-SIPI-SIPI per MADT entry")
}

/// Arm the boot CPU's LAPIC TSC-deadline tick and enter the scheduler.
pub fn arch_enter_scheduler(_hart_id: usize) -> ! {
    todo!("x86_64: arch_enter_scheduler: LAPIC tick, sti, idle")
}

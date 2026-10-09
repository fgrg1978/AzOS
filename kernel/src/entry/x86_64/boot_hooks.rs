// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 boot hooks — SKELETON, matched to `entry/{riscv64,aarch64}/
//! boot_hooks.rs`. `arch_entry.rs` exposes them as the `ArchEntry` impl;
//! the generic early boot (`boot::early_main`) calls them. Each hook past
//! the banner and the PVH memory map is a `todo!()` naming the x86 mechanism.

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

/// Nothing to read before the console.
pub fn pre_console() {}

/// Nothing yet: no IDT is built, so a fault before the banner triple-faults
/// (boot.S runs with interrupts off). The x86 mechanism is `lidt` with a
/// 256-entry IDT and IST stacks from the TSS.
pub fn trap_init() {}

/// The banner and the PVH entry facts.
pub fn boot_banner(hart_id: usize, fw_table: usize) {
    kprintln!();
    kprintln!("========================================");
    kprintln!("  AzOS Rust kernel booted! (x86_64)");
    kprintln!("========================================");
    kprintln!();
    kprintln!("[BOOT] Hart ID:    {}", hart_id);
    kprintln!("[BOOT] PVH start_info: {:#x}", fw_table);
    kprintln!("[BOOT] Baseline:   x86-64-v{} (checked by boot.S before Rust)", crate::X86_64_LEVEL);
}

/// The PVH `start_info` command line, NUL-terminated at `cmdline_paddr`
/// (`ArchEntry::kernel_cmdline`).
pub fn kernel_cmdline(fw_table: usize, out: &mut [u8]) -> Option<usize> {
    if fw_table == 0 {
        return None;
    }
    // SAFETY: boot.S passes the PVH start_info's physical address, identity
    // mapped (0..4 GiB) by boot.S's page tables.
    let si = unsafe { &*(fw_table as *const HvmStartInfo) };
    if si.magic != PVH_MAGIC || si.cmdline_paddr == 0 {
        return None;
    }
    let p = si.cmdline_paddr as usize as *const u8;
    let mut n = 0;
    while n < out.len() {
        // SAFETY: a NUL-terminated string at cmdline_paddr (identity mapped),
        // read up to its NUL or `out`'s length.
        let b = unsafe { p.add(n).read() };
        if b == 0 {
            break;
        }
        out[n] = b;
        n += 1;
    }
    Some(n)
}

/// The PVH `hvm_start_info` and its memory map, printed. Done: the console
/// (COM1, polled), the banner, this. Not yet: the ACPI tables (RSDP -> MADT
/// for the CPUs, `discover_cpus` with `source: "MADT"`), the frame
/// allocator, the kernel page tables, the heap, the LAPIC/IOAPIC, the TSC
/// calibration: the boot stops here with a `todo!()` the panic handler
/// prints.
pub fn firmware_table(_hart_id: usize, fw_table: usize, _dt: Option<azos_dtb::DtbInfo>) {
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


    todo!("x86_64: firmware_table: ACPI RSDP -> MADT CPUs, the PVH E820 map into FirmwareMemory")
}

pub fn irqchip_probe(_fw: &()) {
    todo!("x86_64: irqchip_probe: MADT LAPIC/IOAPIC entries, x2APIC (CPUID.01H:ECX[21])")
}

pub fn timer_probe(_fw: &()) {
    todo!("x86_64: timer_probe: TSC-deadline (CPUID.01H:ECX[24]), invariant TSC, HPET from ACPI")
}

/// The `[ISA]` line: each extension's Kconfig choice (X86_*, n / probe /
/// require) against CPUID (`features::detect`, not ported yet). Each user
/// must also gate on the same policy (`azos_arch_api::isa::x86_64`).
pub fn cpu_features(_fw: &()) {
    use azos_arch_api::isa::{x86_64 as p, Ext};
    if let Err(missing) = azos_arch::features::check_baseline() {
        crate::boot::isa::refuse_level(p::LEVEL, missing);
    }
    let f = azos_arch::features::detect();
    let e = |name, symbol, policy, present| Ext { name, symbol, policy, present };
    crate::boot::isa::report(p::LEVEL, &[
        e("smep", "X86_SMEP", p::SMEP, f.smep),
        e("smap", "X86_SMAP", p::SMAP, f.smap),
        e("pcid", "X86_PCID", p::PCID, f.pcid && f.invpcid),
        e("fsgsbase", "X86_FSGSBASE", p::FSGSBASE, f.fsgsbase),
        e("tsc-deadline", "X86_TSC_DEADLINE", p::TSC_DEADLINE, f.tsc_deadline),
        e("x2apic", "X86_X2APIC", p::X2APIC, f.x2apic),
        e("xsaveopt", "X86_XSAVEOPT", p::XSAVEOPT, f.xsaveopt),
        e("avx2", "X86_AVX2", p::AVX2, f.avx2),
        e("sha-ni", "X86_SHA_NI", p::SHA_NI, f.sha_ni),
    ]);
}

pub fn firmware_memory(_fw: &()) -> azos_arch::FirmwareMemory {
    todo!("x86_64: firmware_memory: E820 RAM ranges, MADT processor count, BSP APIC id")
}

pub fn firmware_done(_fw_table: usize, _num_cpus: usize) {
    todo!("x86_64: firmware_done: print the APIC/timer choices")
}

pub fn reserve_firmware_table(_fw_table: usize) {
    todo!("x86_64: reserve_firmware_table: the ACPI tables and the PVH start_info page")
}

pub fn kernel_mmio_windows() -> core::iter::Empty<(usize, usize)> {
    todo!("x86_64: kernel_mmio_windows: LAPIC (0xFEE00000), IOAPIC, HPET as UC pages")
}

pub fn mmu_enabled() {
    todo!("x86_64: mmu_enabled: CR3 loaded with the kernel PML4, CR4.PGE/PCIDE")
}

pub fn restrict_low_half() {
    todo!("x86_64: restrict_low_half: drop the boot identity map from the low PML4 half")
}

pub fn verify_guards() {
    todo!("x86_64: verify_guards: page-walk readback of page 0 and the stack guards")
}

pub fn post_heap(_heap_start: usize, _kernel_end_aligned: usize) {
    todo!("x86_64: post_heap: SMEP/SMAP enable (CR4) and their readback")
}

pub fn timebase_hz() -> u64 {
    todo!("x86_64: timebase_hz: invariant TSC frequency (CPUID.15H, or HPET calibration)")
}

pub fn irqchip_init(_hart_id: usize, _fw_table: usize) {
    todo!("x86_64: irqchip_init: mask the 8259 PICs, x2APIC enable, IOAPIC redirection table")
}

pub fn irq_enable_early() {
    todo!("x86_64: irq_enable_early: sti once the IDT and LAPIC are live")
}

pub fn console_irq(_hart_id: usize, _fw_table: usize) {
    todo!("x86_64: console_irq: COM1 IRQ 4 through the IOAPIC, IER RX/TX")
}

pub fn irq_trigger_controller() -> Option<azos_dtb::IrqController> {
    todo!("x86_64: irq_trigger_controller: none (no device tree); triggers come from the MADT")
}

pub fn irq_triggers(_triggers: Option<azos_dtb::IrqTriggers>) {
    todo!("x86_64: irq_triggers: MADT interrupt source overrides (polarity, trigger)")
}

pub fn line_release() -> fn(u32) {
    todo!("x86_64: line_release: mask the IOAPIC redirection entry")
}

pub fn irq_routing_init(_hart_id: usize) {
    todo!("x86_64: irq_routing_init: MSI/MSI-X address = LAPIC of the boot CPU")
}

pub fn smp_probe(_fw_table: usize) {
    todo!("x86_64: smp_probe: MADT APIC ids for INIT-SIPI-SIPI, the real-mode trampoline page")
}

pub fn timer_init() {
    todo!("x86_64: timer_init: TSC frequency (CPUID.15H or HPET calibration), LAPIC TSC-deadline tick")
}

pub fn boot_selftests() {
    todo!("x86_64: boot_selftests: int3 returns, ticks arrive, IST stack used")
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

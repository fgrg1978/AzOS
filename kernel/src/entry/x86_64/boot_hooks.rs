// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 boot hooks, matched to `entry/{riscv64,aarch64}/boot_hooks.rs`.
//! `arch_entry.rs` exposes them as the `ArchEntry` impl; the generic early
//! boot (`boot::early_main`) calls them. The platform hooks (boot
//! information, ACPI, APIC, timer, SMP) are implemented over
//! `azos_arch::{platform_impl, acpi, apic, ioapic, timer, smp}`; the others
//! are still `todo!()`s naming the x86 mechanism.

use azos_drv_sys::kprintln;

use azos_arch::platform_impl::{platform, Source};

fn source_name(s: Source) -> &'static str {
    match s {
        Source::None => "none",
        Source::Pvh => "PVH start_info",
        Source::Scan => "BIOS-area scan",
        Source::Madt => "MADT",
        Source::Fallback => "fallback",
        Source::Cmdline => "kernel command line",
        Source::MicrovmLayout => "microvm layout",
    }
}

/// Nothing to read before the console.
pub fn pre_console() {}

/// The boot CPU's GDT + TSS (IST stacks), the 256-vector IDT, the
/// `syscall` MSRs and ring 3's FP state (`entry::x86_64::cpu_init`).
/// Interrupts stay masked.
pub fn trap_init() {
    crate::entry::x86_64::cpu_init::init_boot_cpu();
    // The paging depth (CR4.LA57, boot.S's choice) before `vmm::init`
    // builds the kernel's tables at it.
    azos_arch::mmu::cpu::note_paging_depth();
}

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
    // SAFETY: boot.S passes the PVH start_info's physical address, mapped
    // 1:1 (0..4 GiB) by boot.S's page tables, which are still the live ones
    // (`early_main` reads the command line before `vmm::enable_paging`).
    let si = unsafe { &*(fw_table as *const azos_arch::bootinfo::HvmStartInfo) };
    if si.magic != azos_arch::bootinfo::PVH_MAGIC || si.cmdline_paddr == 0 {
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

/// The PVH `hvm_start_info` (memory map, command line, RSDP) and the ACPI
/// tables, read once into `azos_arch::platform_impl` while boot.S's
/// identity map is live; then the AP trampoline is installed.
pub fn firmware_table(_hart_id: usize, fw_table: usize, _dt: Option<azos_dtb::DtbInfo>) {
    // SAFETY: boot CPU, once, before any other CPU or interrupt; boot.S's
    // 0..4 GiB identity map is still the live one.
    unsafe { azos_arch::platform_impl::discover(fw_table) };
    let p = platform();
    match p.start_info {
        None => azos_drv_sys::kwarn!("[BOOT] PVH start_info at {:#x}: bad magic (want {:#x})",
                                     fw_table, azos_arch::bootinfo::PVH_MAGIC),
        Some(si) => kprintln!("[BOOT] PVH v{} flags={:#x} modules={} rsdp={:#x}",
                              si.version, si.flags, si.nr_modules, si.rsdp_paddr),
    }
    let mut ram = 0u64;
    for e in p.memmap() {
        kprintln!("[MEM] {:#012x}+{:#010x} type {}", e.addr, e.size, e.kind);
        if e.kind == azos_arch::bootinfo::E820_RAM {
            ram += e.size;
        }
    }
    if p.memmap_dropped != 0 {
        azos_drv_sys::kwarn!("[MEM] {} memory-map entries past the {} kept were ignored",
                             p.memmap_dropped, azos_arch::bootinfo::MAX_MEM_ENTRIES);
    }
    kprintln!("[MEM] RAM: {} KiB", ram / 1024);
    if p.cmdline_len != 0 {
        let line = core::str::from_utf8(p.cmdline()).unwrap_or("<not UTF-8>");
        kprintln!("[BOOT] cmdline: {}", line);
        if p.cmdline_full_len > p.cmdline_len {
            azos_drv_sys::kwarn!("[BOOT] cmdline cut at {} of {} bytes (X86_CMDLINE_MAX)",
                                 p.cmdline_len, p.cmdline_full_len);
        }
    }
    match p.acpi_err {
        None => kprintln!("[ACPI] RSDP {:#x} ({}) rev {} via {}: {} tables, {} bad",
                          p.acpi.rsdp, source_name(p.rsdp_source), p.acpi.revision,
                          if p.acpi.xsdt { "XSDT" } else { "RSDT" }, p.acpi.n_tables, p.acpi.bad_tables),
        Some(e) => azos_drv_sys::kwarn!("[ACPI] no usable tables ({:?}): one CPU, IOAPIC at {:#x}",
                                        e, azos_limits::X86_IOAPIC_FALLBACK_BASE),
    }
    for &(sig, pa, len) in p.acpi.tables() {
        kprintln!("[ACPI]   {} {:#x} len {}", core::str::from_utf8(&sig).unwrap_or("????"), pa, len);
    }
    for m in p.acpi.mcfg() {
        kprintln!("[ACPI] MCFG: segment {} buses {}..={} ECAM {:#x}", m.segment, m.bus_start, m.bus_end, m.base);
    }
    if p.virtio_bad != 0 {
        azos_drv_sys::kwarn!("[VIRTIO] {} malformed virtio_mmio.device= entries ignored", p.virtio_bad);
    }
    kprintln!("[VIRTIO] {} virtio-mmio transport(s) from the {}", p.n_virtio, source_name(p.virtio_source));
    let kernel_end = unsafe { &crate::_kernel_end as *const u8 as usize };
    // SAFETY: boot CPU, after `discover`, identity map live, no AP started.
    match unsafe { azos_arch::smp::install(kernel_end) } {
        Ok(pa) => kprintln!("[SMP] AP trampoline at {:#x} (STARTUP vector {:#x})", pa, pa >> 12),
        Err(e) => azos_drv_sys::kwarn!("[SMP] no AP start possible: {:?}", e),
    }
}

/// The MADT's interrupt controllers, and the LAPIC mode for every CPU.
pub fn irqchip_probe(_fw: &()) {
    let p = platform();
    let x2 = azos_arch::apic::select_mode();
    kprintln!("[APIC] {} mode, LAPIC {:#x}, boot CPU APIC ID {}",
              if x2 { "x2APIC" } else { "xAPIC" }, p.lapic_pa, p.bsp_apic_id);
    if let Some(m) = p.madt() {
        for io in m.ioapics() {
            kprintln!("[APIC] IOAPIC id {} at {:#x}, GSI base {}", io.id, io.addr, io.gsi_base);
        }
        for o in m.isos() {
            kprintln!("[APIC] override: ISA IRQ {} -> GSI {} (flags {:#x})", o.source, o.gsi, o.flags);
        }
        if m.malformed != 0 {
            azos_drv_sys::kwarn!("[APIC] {} malformed MADT entries skipped", m.malformed);
        }
    }
}

/// The TSC rate (the clock switches to TIMER_FREQ units here, before any
/// timestamp the PMM or later code keeps) and the timer mode.
pub fn timer_probe(_fw: &()) {
    use azos_arch::timer;
    let src = timer::calibrate();
    let deadline = timer::select_mode();
    kprintln!("[TIMER] TSC {} Hz from {}{}, clock at {} Hz; timer: {}",
              timer::tsc_hz(), src.name(),
              if timer::invariant_tsc() { " (invariant)" } else { " (NOT invariant)" },
              timer::TICK_HZ,
              if deadline { "TSC-deadline" } else { "LAPIC one-shot" });
    if let Some(h) = platform().acpi.hpet {
        kprintln!("[TIMER] HPET at {:#x}", h.addr);
    }
}

/// The `[ISA]` line: the baseline level (`features::check_baseline`, which
/// powers off below it, naming the missing feature) and each extension's
/// Kconfig choice (X86_*, n / probe / require) against CPUID
/// (`features::detect`); a `require` the CPU lacks powers off too. Each
/// user must also gate on the same policy (`azos_arch_api::isa::x86_64`).
pub fn cpu_features(_fw: &()) {
    use azos_arch_api::isa::{x86_64 as p, Ext};
    if let Err(missing) = azos_arch::features::check_baseline(p::LEVEL_NUM) {
        crate::boot::isa::refuse_level(p::LEVEL, missing);
    }
    let f = azos_arch::features::detect();
    let e = |name, symbol, policy, present| Ext { name, symbol, policy, present };
    crate::boot::isa::report(p::LEVEL, &[
        e("sse4.2", "X86_SSE4_2", p::SSE4_2, f.sse4_2),
        e("popcnt", "X86_POPCNT", p::POPCNT, f.popcnt),
        e("xsave", "X86_XSAVE", p::XSAVE, f.xsave),
        e("avx", "X86_AVX", p::AVX, f.avx),
        e("avx2", "X86_AVX2", p::AVX2, f.avx2),
        e("bmi1", "X86_BMI1", p::BMI1, f.bmi1),
        e("bmi2", "X86_BMI2", p::BMI2, f.bmi2),
        e("fma", "X86_FMA", p::FMA, f.fma),
        e("movbe", "X86_MOVBE", p::MOVBE, f.movbe),
        e("avx512f", "X86_AVX512F", p::AVX512F, f.avx512f),
        e("avx512bw", "X86_AVX512BW", p::AVX512BW, f.avx512bw),
        e("avx512cd", "X86_AVX512CD", p::AVX512CD, f.avx512cd),
        e("avx512dq", "X86_AVX512DQ", p::AVX512DQ, f.avx512dq),
        e("avx512vl", "X86_AVX512VL", p::AVX512VL, f.avx512vl),
        e("aes", "X86_AES", p::AES, f.aes),
        e("pclmulqdq", "X86_PCLMULQDQ", p::PCLMULQDQ, f.pclmulqdq),
        e("sha-ni", "X86_SHA_NI", p::SHA_NI, f.sha_ni),
        e("rdrand", "X86_RDRAND", p::RDRAND, f.rdrand),
        e("rdseed", "X86_RDSEED", p::RDSEED, f.rdseed),
        e("adx", "X86_ADX", p::ADX, f.adx),
        e("fsgsbase", "X86_FSGSBASE", p::FSGSBASE, f.fsgsbase),
        e("pcid", "X86_PCID", p::PCID, f.pcid),
        e("invpcid", "X86_INVPCID", p::INVPCID, f.invpcid),
        e("smep", "X86_SMEP", p::SMEP, f.smep),
        e("smap", "X86_SMAP", p::SMAP, f.smap),
        e("umip", "X86_UMIP", p::UMIP, f.umip),
        e("pku", "X86_PKU", p::PKU, f.pku),
        e("la57", "X86_LA57", p::LA57, f.la57),
        e("gbpages", "X86_GBPAGES", p::GBPAGES, f.gbpages),
        e("cet-ibt", "X86_CET_IBT", p::CET_IBT, f.cet_ibt),
        e("cet-shstk", "X86_CET_SHSTK", p::CET_SHSTK, f.cet_shstk),
        e("xsaveopt", "X86_XSAVEOPT", p::XSAVEOPT, f.xsaveopt),
        e("xsaves", "X86_XSAVES", p::XSAVES, f.xsaves),
        e("x2apic", "X86_X2APIC", p::X2APIC, f.x2apic),
        e("tsc-deadline", "X86_TSC_DEADLINE", p::TSC_DEADLINE, f.tsc_deadline),
        e("invariant-tsc", "X86_INVARIANT_TSC", p::INVARIANT_TSC, f.invariant_tsc),
    ]);
}

/// RAM above this is left out: the direct map
/// (`azos_arch::mmu::DIRECT_MAP_BASE`) covers `DIRECT_MAP_BYTES` (64 TiB)
/// from PA 0. The PMM's span crosses the PC's 32-bit MMIO hole when RAM
/// continues above 4 GiB; `kernel_mmio_windows` takes every E820 hole back
/// out of the direct map before the kernel's table goes live, so no device
/// page is mapped as normal memory.
const RAM_LIMIT: u64 = azos_arch::mmu::DIRECT_MAP_BYTES;

/// One range for the PMM: 0 to the end of the highest RAM entry (the holes
/// inside it are reserved by `reserve_firmware_table`); the CPUs the MADT
/// lists, the boot CPU first. The PMM manages at most Kconfig `RAM_SIZE`
/// MiB of that span (its bitmap), said here when the span is larger.
pub fn firmware_memory(_fw: &()) -> azos_arch::FirmwareMemory {
    let p = platform();
    let high: u64 = p.memmap().iter()
        .filter(|e| e.kind == azos_arch::bootinfo::E820_RAM)
        .map(|e| e.addr.saturating_add(e.size).saturating_sub(e.addr.max(RAM_LIMIT)))
        .sum();
    if high != 0 {
        azos_drv_sys::kwarn!("[MEM] {} MiB of RAM above the direct map's {} GiB not used",
                             high >> 20, RAM_LIMIT >> 30);
    }
    let (mem_start, mem_size, from_firmware) = match azos_arch::bootinfo::ram_span(p.memmap(), RAM_LIMIT) {
        Some((s, e)) => (s as usize, (e - s) as usize, true),
        None => (0, crate::FALLBACK_MEM_SIZE, false),
    };
    if mem_size > azos_limits::RAM_SIZE << 20 {
        azos_drv_sys::kwarn!("[MEM] RAM span {} MiB, the frame allocator manages Kconfig RAM_SIZE = {} MiB of it",
                             mem_size >> 20, azos_limits::RAM_SIZE);
    }
    azos_arch::FirmwareMemory {
        mem_start,
        mem_size,
        from_firmware,
        cpu_count: p.n_cpus,
        boot_cpu: 0,
        cpu_source: if p.cpu_source == Source::Madt { "MADT" } else { "CPUID (no MADT)" },
    }
}

/// The CPU table as numbered: dense index -> APIC ID.
pub fn firmware_done(_fw_table: usize, num_cpus: usize) {
    let p = platform();
    for cpu in 0..num_cpus.min(p.n_cpus) {
        kprintln!("[SMP] CPU {}: APIC ID {}", cpu, p.apic_ids[cpu]);
    }
    if p.cpus_over_limit != 0 {
        azos_drv_sys::kwarn!("[SMP] {} CPU(s) past NR_CPUS={} not used", p.cpus_over_limit, azos_limits::NR_CPUS);
    }
}

/// Everything in the PMM's span that is not RAM (E820 holes, reserved, ACPI,
/// NVS), and the boot information (start_info, memory map, command line,
/// ACPI tables) wherever it sits in RAM.
pub fn reserve_firmware_table(_fw_table: usize) {
    let p = platform();
    let end = (azos_mm::pmm::total_pages() * azos_arch::PAGE_SIZE) as u64;
    let mut holes = 0u64;
    azos_arch::bootinfo::for_each_hole(p.memmap(), end, |s, l| {
        azos_mm::pmm::reserve_range(s as usize, l as usize);
        holes += l;
    });
    let mut boot = 0u64;
    p.for_each_boot_span(|s, l| {
        if s < end {
            let a = s & !0xFFF;
            let len = ((s + l + 0xFFF) & !0xFFF) - a;
            azos_mm::pmm::reserve_range(a as usize, len as usize);
            boot += len;
        }
    });
    // The AP trampoline page (`smp::install` wrote it): every INIT-SIPI-SIPI
    // starts an AP there, so the PMM must never hand it out.
    if let Some(t) = p.trampoline_pa {
        azos_mm::pmm::reserve_range(t as usize, azos_arch::PAGE_SIZE);
        boot += azos_arch::PAGE_SIZE as u64;
    }
    kprintln!("[MM] Reserved {} KiB of memory-map holes, {} KiB of boot information", holes >> 10, boot >> 10);
}

/// [`azos_arch::mmu::TableMem`] over the direct map (every table frame is
/// RAM the direct map covers, under boot.S's tables and the kernel's).
struct DirectTables;
impl azos_arch::mmu::TableMem for DirectTables {
    fn read(&self, table: usize, idx: usize) -> u64 {
        // SAFETY: a table frame reached from a live root: RAM in the direct map.
        unsafe { core::ptr::read_volatile((azos_mm::addr::phys_to_virt(table) + idx * 8) as *const u64) }
    }
    fn write(&mut self, table: usize, idx: usize, word: u64) {
        // SAFETY: as `read`; the boot CPU edits the kernel's table before
        // any other CPU or task uses it.
        unsafe { core::ptr::write_volatile((azos_mm::addr::phys_to_virt(table) + idx * 8) as *mut u64, word) }
    }
    fn alloc_table(&mut self) -> Option<usize> { None }
}

/// `vmm::init` mapped the PMM's whole span into the direct map as normal
/// memory, E820 holes included: on a PC with RAM above 4 GiB that span
/// crosses the 32-bit MMIO hole (LAPIC, IOAPIC, HPET, PCI windows). Take
/// every page no RAM entry covers back out, whole 2 MiB leaves where a hole
/// spans one, single pages (split) at its edges, so no device page has a
/// write-back alias. Returns the bytes removed.
fn unmap_direct_map_holes() -> u64 {
    const MEGA: usize = 2 << 20;
    let kpt = azos_mm::vmm::kernel_pagetable();
    let end = azos_mm::vmm::ram_end() as u64;
    let levels = azos_arch::mmu::levels();
    let mut removed = 0u64;
    azos_arch::bootinfo::for_each_hole(platform().memmap(), end, |s, l| {
        let (mut pa, e) = (s as usize, (s + l) as usize);
        while pa < e {
            let va = azos_mm::addr::phys_to_virt(pa);
            if pa & (MEGA - 1) == 0 && pa + MEGA <= e && azos_mm::vmm::leaf_level(kpt, va) == Some(1) {
                let _ = azos_arch::mmu::unmap(&mut DirectTables, kpt, levels, va);
                pa += MEGA;
                removed += MEGA as u64;
            } else {
                azos_mm::vmm::unmap_kernel(kpt, va);
                pa += azos_arch::PAGE_SIZE;
                removed += azos_arch::PAGE_SIZE as u64;
            }
        }
    });
    removed
}

/// The device windows the kernel tables map before paging is on: the xAPIC
/// page (none in x2APIC mode), each IOAPIC, the HPET, the virtio-mmio
/// transports. First, the E820 holes leave the direct map
/// ([`unmap_direct_map_holes`]): this is the hook that runs between
/// `vmm::init` and the table going live.
pub fn kernel_mmio_windows() -> impl Iterator<Item = (usize, usize)> {
    const PAGE: usize = 0x1000;
    let holes = unmap_direct_map_holes();
    // Read it back: no direct-map leaf may touch an E820 hole.
    let (dmb, top) = (azos_arch::mmu::DIRECT_MAP_BASE as usize, azos_arch::mmu::levels() - 1);
    let slot = azos_arch::mmu::vpn(dmb, top);
    let end = azos_mm::vmm::ram_end() as u64;
    let (mut leaves, mut bad, mut first) = (0usize, 0usize, 0usize);
    azos_arch::mmu::for_each_leaf(&DirectTables, azos_mm::vmm::kernel_pagetable(), top + 1, slot..slot + 1,
        &mut |va, leaf| {
            if va < dmb || va - dmb >= azos_arch::mmu::DIRECT_MAP_BYTES as usize {
                return; // the image's map, which shares the root slot under LA57
            }
            leaves += 1;
            let (s, e) = (leaf.phys as u64, (leaf.phys + azos_arch::mmu::level_size(leaf.level)) as u64);
            let mut hit = false;
            azos_arch::bootinfo::for_each_hole(platform().memmap(), end, |hs, hl| hit |= hs < e && s < hs + hl);
            if hit {
                bad += 1;
                if first == 0 { first = va; }
            }
        });
    if bad == 0 {
        kprintln!("[MM] Direct map at {:#x}: RAM 0..{:#x} in {} leaves, {} KiB of E820 holes left unmapped",
                  dmb, end, leaves, holes >> 10);
    } else {
        azos_drv_sys::kerr!("[MM] FAILED: direct map: {} of {} leaves touch an E820 hole (first VA {:#x})",
                            bad, leaves, first);
    }
    let p = platform();
    let mut w = [(0usize, 0usize); 4 + azos_arch::acpi::MAX_IOAPICS];
    let mut n = 0;
    let mut add = |base: usize, len: usize| {
        if n < w.len() && len != 0 {
            w[n] = (base, len);
            n += 1;
        }
    };
    if let Some(base) = azos_arch::apic::mmio_window() {
        add(base, PAGE);
    }
    azos_arch::ioapic::for_each_window(|base| add(base, PAGE));
    if let Some(h) = p.acpi.hpet {
        add(h.addr as usize, PAGE);
    }
    // The window the drivers scan (`platform::hw::VIRTIO_MMIO_*`: every slot
    // is read, present or not), plus any command-line transport outside it.
    let (wbase, wlen) = (azos_limits::X86_VIRTIO_MMIO_BASE,
                         azos_limits::X86_VIRTIO_MMIO_MAX * azos_limits::X86_VIRTIO_MMIO_STRIDE);
    let page_span = |lo: usize, hi: usize| (lo & !(PAGE - 1), ((hi + PAGE - 1) & !(PAGE - 1)) - (lo & !(PAGE - 1)));
    if wlen != 0 {
        let (b, l) = page_span(wbase, wbase + wlen);
        add(b, l);
    }
    let outside = p.virtio().iter().filter(|d| (d.base as usize) < wbase || (d.base + d.size) as usize > wbase + wlen);
    if let (Some(lo), Some(hi)) = (outside.clone().map(|d| d.base as usize).min(),
                                   outside.map(|d| (d.base + d.size) as usize).max()) {
        let (b, l) = page_span(lo, hi);
        add(b, l);
    }
    w.into_iter().take(n)
}

/// The paging choices: each extension's Kconfig policy over the probe.
pub(crate) fn paging_caps() -> azos_arch::mmu::PagingCaps {
    use azos_arch_api::isa::x86_64 as p;
    let f = azos_arch::features::detect();
    azos_arch::mmu::PagingCaps {
        pcid: p::PCID.gate(f.pcid),
        invpcid: p::PCID.gate(f.invpcid),
        gbpages: p::GBPAGES.gate(f.gbpages),
        smep: p::SMEP.gate(f.smep),
        smap: p::SMAP.gate(f.smap),
    }
}

/// PAT, CR0.WP, CR4.PGE/PCIDE (`mmu::cpu::setup_paging_regs`), read back. A
/// clear EFER.NXE (boot.S sets it) or a `require`d LA57 / 1 GiB pages the
/// CPU lacks stops the boot here.
///
/// Runtime canary `x86-low-alias`: the first page of kernel text is mapped
/// 1:1 again in the kernel table's low half, as it was before the kernel
/// linked high; `restrict_low_half` and ktest `x86_low_half_maps_no_ram`
/// must then report it.
pub fn mmu_enabled() {
    if canary!("x86-low-alias") {
        // SAFETY: a linker symbol's address, not dereferenced.
        let pa = azos_mm::addr::virt_to_phys(unsafe { &crate::_text_start as *const u8 as usize });
        let ok = azos_mm::vmm::map(azos_mm::vmm::kernel_pagetable(), pa, pa,
                                   azos_arch::PagePerms::KERNEL_RO).is_ok();
        azos_drv_sys::kwarn!("[CANARY] x86-low-alias: kernel text PA {:#x} mapped 1:1 in the low half ({})",
                             pa, if ok { "mapped" } else { "map failed" });
    }
    use azos_arch_api::isa::{x86_64 as p, ExtPolicy};
    let st = azos_arch::mmu::cpu::setup_paging_regs(&paging_caps());
    kprintln!("[MM] x86_64 paging: {}-level, NXE={} WP={} PGE={} PCIDE={} PAT={:#x}",
        st.levels, st.nxe, st.wp, st.pge, st.pcide, st.pat);
    if !st.nxe {
        panic!("x86_64: EFER.NXE is clear: every NX leaf would be a reserved-bit fault");
    }
    if p::LA57 == ExtPolicy::Require && st.levels != azos_arch::mmu::LEVELS_5 {
        panic!("x86_64: Kconfig X86_LA57=require and the CPU has no LA57");
    }
    if p::GBPAGES == ExtPolicy::Require && !azos_arch::mmu::gbpages() {
        panic!("x86_64: Kconfig X86_GBPAGES=require and the CPU has no 1 GiB pages");
    }
}

/// What the user half (root slots below `KERNEL_HALF_FIRST_SLOT`) of a
/// table maps, read back from the table itself.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LowHalf {
    /// 4 KiB pages of leaves outside every RAM entry (device windows).
    pub device_pages: usize,
    /// 4 KiB pages of leaves that touch an E820 RAM entry (the image, the
    /// heap, every PMM frame).
    pub ram_pages: usize,
    /// The first such RAM leaf, `(va, pa)`.
    pub first_ram: Option<(usize, usize)>,
    /// Its leaves that are user-accessible (US).
    pub user_leaves: usize,
}

/// Walk the user half of `root` (a kernel or a task root): every leaf
/// sorted into device and RAM pages (E820). Pure reads through the direct map.
/// A task's own pages are RAM too, so a task root is audited before its
/// user pages exist, or the caller counts `user_leaves` apart.
pub(crate) fn audit_low_half(root: usize) -> LowHalf {
    use azos_arch::mmu as m;
    let map = platform().memmap();
    let is_ram = |pa: usize, len: usize| map.iter().any(|e| {
        e.kind == azos_arch::bootinfo::E820_RAM && (e.addr as usize) < pa + len && pa < e.addr.saturating_add(e.size) as usize
    });
    let mut a = LowHalf::default();
    m::for_each_leaf(&DirectTables, root, m::levels(), 0..m::KERNEL_HALF_FIRST_SLOT, &mut |va, leaf| {
        let size = m::level_size(leaf.level);
        let pages = size / azos_arch::PAGE_SIZE;
        if leaf.word & m::US != 0 {
            a.user_leaves += 1;
        }
        if is_ram(leaf.phys, size) {
            a.ram_pages += pages;
            a.first_ram.get_or_insert((va, leaf.phys));
        } else {
            a.device_pages += pages;
        }
    });
    a
}

/// The low half after the switch: `vmm::enable_paging` replaced boot.S's
/// tables (PA 0..4 GiB 1:1 beside the direct map and the image map) with
/// the kernel's own, which map RAM in the direct map, the image at
/// `KERNEL_VA_OFFSET` and the recorded device windows 1:1. Read that back
/// from the live root: no RAM page below the kernel half, so the user image
/// range (`0x1_0000` up) is free on every ISA and a kernel bug cannot reach
/// a frame by its physical number. The AP trampoline needs nothing here: an
/// AP starts on `smp::install`'s own tables and jumps high before it loads
/// this root.
pub fn restrict_low_half() {
    let kpt = azos_mm::vmm::kernel_pagetable();
    let live = azos_arch::mmu::cr3_root(azos_arch::mmu::cpu::read_cr3()) == kpt;
    let a = audit_low_half(kpt);
    match a.first_ram {
        None if live => kprintln!("[MM] Low half is device-only: {} MMIO pages, RAM unreachable by PA",
                                  a.device_pages),
        None => azos_drv_sys::kerr!("[MM] FAILED: low half: the live CR3 is not the kernel's table {:#x}", kpt),
        Some((va, pa)) => azos_drv_sys::kerr!(
            "[MM] FAILED: low half maps {} RAM page(s) (first VA {:#x} -> PA {:#x}) beside {} MMIO pages",
            a.ram_pages, va, pa, a.device_pages),
    }
}

/// The null and stack guards read back from the page table (the aarch64
/// hook's readback): page 0 sits in the low half, which `restrict_low_half`
/// just showed holds device windows only.
pub fn verify_guards() {
    let kpt = azos_mm::vmm::kernel_pagetable();
    if azos_mm::vmm::translate(kpt, 0).is_none() {
        kprintln!("[MM] Null guard readback: page 0 unmapped");
    } else {
        azos_drv_sys::kerr!("[MM] FAILED: null guard readback — page 0 still translates");
    }
    let (unmapped, total) = azos_sched::stack_guard_readback();
    if unmapped == total {
        kprintln!("[MM] Stack guard readback: {}/{} stack bottoms unmapped", unmapped, total);
    } else {
        azos_drv_sys::kerr!("[MM] FAILED: stack guard readback — {}/{} stack bottoms unmapped",
                            unmapped, total);
    }
}

// The image's text and read-only data, reached through the direct map, are
// read-only and not executable (`boot::early_main`'s alias pass), and the image's own
// text mapping stays read-execute.
#[cfg(feature = "ktest")]
azos_ktest::ktest! {
    fn x86_direct_map_image_alias_read_only() {
        use azos_arch::mmu as m;
        let kpt = azos_mm::vmm::kernel_pagetable();
        // SAFETY: linker symbols' addresses, not dereferenced.
        let (t, r) = unsafe { (&crate::_text_start as *const u8 as usize, &crate::_rodata_start as *const u8 as usize) };
        let leaf = |va: usize| m::translate(&DirectTables, kpt, m::levels(), va);
        for va in [t, r] {
            let alias = azos_mm::addr::phys_to_virt(azos_mm::addr::virt_to_phys(va));
            let Some(l) = leaf(alias) else { return Err("the image's direct-map alias is not mapped") };
            if l.word & m::RW != 0 {
                return Err("the image's direct-map alias is writable");
            }
            if l.word & m::NX == 0 {
                return Err("the image's direct-map alias is executable");
            }
        }
        match leaf(t) {
            Some(l) if l.word & m::NX == 0 && l.word & m::RW == 0 => Ok(()),
            _ => Err("the image's own text mapping is not read-execute"),
        }
    }
}

// The user half of the kernel's table and of a fresh task table holds no
// RAM: the kernel lives in the upper half (`KERNEL_VA_OFFSET`). Canary:
// `canary=x86-low-alias` (`mmu_enabled`) maps the kernel's first text page
// 1:1 again; this test alone goes not ok.
#[cfg(feature = "ktest")]
azos_ktest::ktest! {
    fn x86_low_half_maps_no_ram() {
        let kpt = azos_mm::vmm::kernel_pagetable();
        let k = audit_low_half(kpt);
        if k.first_ram.is_some() {
            return Err("the kernel table's user half maps RAM");
        }
        if k.device_pages == 0 {
            return Err("the kernel table's user half maps no device window: the walk saw nothing");
        }
        if k.user_leaves != 0 {
            return Err("the kernel table's user half has a user-accessible leaf");
        }
        // A task's table as exec builds it: its kernel entries merged in.
        let root = azos_mm::vmm::create_pagetable().map_err(|_| "no page table")?;
        azos_mm::vmm::copy_kernel_entries_to_user(root);
        let u = audit_low_half(root);
        // The kernel half reaches the image as the kernel's table does.
        // SAFETY: a linker symbol's address, not dereferenced.
        let text = unsafe { &crate::_text_start as *const u8 as usize };
        let t = azos_mm::vmm::translate(root, text);
        let same = t.is_some() && t == azos_mm::vmm::translate(kpt, text);
        azos_mm::vmm::destroy_user_pagetable(root);
        if u.first_ram.is_some() {
            return Err("a task table's user half maps kernel RAM");
        }
        if u.device_pages != k.device_pages {
            return Err("a task table's user half lacks the kernel's device windows");
        }
        if !same {
            return Err("a task table does not reach the kernel image through the shared upper half");
        }
        Ok(())
    }
}

/// CR4.SMEP / CR4.SMAP (`mmu::cpu::enable_access_protection`), read back.
pub fn post_heap(_heap_start: usize, _kernel_end_aligned: usize) {
    let st = azos_arch::mmu::cpu::enable_access_protection(&paging_caps());
    // From the next trap entry on, `trap_entry.S` runs `clac` (delivery
    // does not clear RFLAGS.AC). Interrupts are still off here.
    crate::entry::x86_64::cpu_init::X86_64_SMAP_ON
        .store(st.smap as u8, core::sync::atomic::Ordering::Release);
    kprintln!("[MM] x86_64 SMEP={} SMAP={}", st.smep, st.smap);
    crate::boot_stack_report();
}

/// The clock's rate: `now_ticks` counts TIMER_FREQ (the TSC scaled).
pub fn timebase_hz() -> u64 {
    azos_arch::timer::TICK_HZ
}

/// The IOAPIC GSI of the virtio-mmio transport at `base` (Kconfig
/// `NET_RX_IRQ`): the boot's discovery, already redirected to the boot CPU
/// and masked by [`irqchip_init`].
#[inline(always)]
pub fn net_mmio_line(_slot: usize, base: usize) -> Option<u32> {
    platform().virtio_gsi(base as u64)
}

/// Unmask `line` (redirected by [`irqchip_init`]); `irq::device` dispatches
/// it to the NIC.
#[inline(always)]
pub fn net_mmio_unmask(_hart: usize, line: u32) {
    let _ = azos_arch::ioapic::set_masked(line, false);
}

/// The 8259s remapped and masked, this CPU's LAPIC on, every IOAPIC pin
/// masked.
pub fn irqchip_init(hart_id: usize, _fw_table: usize) {
    if platform().madt().map_or(true, |m| m.flags & 1 != 0) {
        azos_arch::platform_impl::mask_8259();
    }
    azos_arch::apic::init_local(hart_id);
    // The TLB shootdown: a fixed-vector IPI per target CPU, served by
    // `tlb::handle_ipi` on each (x86 has no broadcast invalidate).
    azos_arch::tlb::register_ipi_sender(send_tlb_ipi);
    crate::entry::x86_64::irq::set_tlb_ipi_handler(serve_tlb_ipi);
    let gsis = azos_arch::ioapic::init();
    kprintln!("[APIC] LAPIC ID {} on, {} IOAPIC GSIs masked, device vectors from {}",
              azos_arch::apic::id(), gsis, azos_arch::apic::IRQ_VECTOR_BASE);
    // The virtio-mmio lines: redirected to this CPU, still masked; a driver
    // that takes interrupts only unmasks.
    let me = azos_arch::apic::id();
    let mut routed = 0;
    for d in platform().virtio() {
        let (level, active_low) = azos_arch::ioapic::default_trigger(d.gsi);
        if azos_arch::ioapic::route(d.gsi, me, level, active_low, true) {
            routed += 1;
        }
    }
    if routed != 0 {
        kprintln!("[APIC] {} virtio-mmio GSI(s) redirected (masked)", routed);
    }
}

fn send_tlb_ipi(mut mask: usize) {
    while mask != 0 {
        let cpu = mask.trailing_zeros() as usize;
        mask &= mask - 1;
        if !azos_arch::apic::send_ipi(cpu, azos_arch::encode::TLB_VECTOR) {
            azos_drv_sys::kerr!("[TLB] CPU {} has no reachable APIC ID: shootdown IPI not sent", cpu);
        }
    }
}

fn serve_tlb_ipi() {
    use azos_arch::{Cpu, ARCH};
    azos_arch::tlb::handle_ipi(ARCH.hart_id());
}

/// Nothing: `timer_init` unmasks (RFLAGS.IF) once the tick is armed, as
/// on aarch64.
pub fn irq_enable_early() {}

/// COM1 (ISA IRQ 4, or its MADT override) through the IOAPIC to this CPU:
/// RX interrupts on, and console output through the TX ring, fed by the
/// THR-empty interrupt on the same line (`uart::enable_tx_irq`).
pub fn console_irq(_hart_id: usize, _fw_table: usize) {
    let p = platform();
    let (gsi, level, active_low) = p.isa_irq(4);
    if azos_arch::ioapic::route(gsi, azos_arch::apic::id(), level, active_low, false) {
        azos_drv_irqchip::user_irq::mark_kernel(gsi);
        crate::entry::x86_64::irq::COM1_GSI.store(gsi, core::sync::atomic::Ordering::Relaxed);
        azos_drv_sys::uart::enable_irq();
        kprintln!("[UART] COM1 RX interrupt on GSI {} ({}, active-{})", gsi,
                  if level { "level" } else { "edge" }, if active_low { "low" } else { "high" });
        // The same line now feeds COM1 from the console's TX ring.
        azos_drv_sys::uart::enable_tx_irq();
    } else {
        azos_drv_sys::kwarn!("[UART] COM1 GSI {} not routable: console stays polled", gsi);
    }
}

/// None: no device tree; triggers come from the MADT overrides at route time.
pub fn irq_trigger_controller() -> Option<azos_dtb::IrqController> {
    None
}

/// Nothing to record: `ioapic::default_trigger` reads the MADT overrides.
pub fn irq_triggers(_triggers: Option<azos_dtb::IrqTriggers>) {}

/// A ring-3 line's release: mask and reset its redirection entry.
pub fn line_release() -> fn(u32) {
    azos_drv_irqchip::user_irq::release
}

/// The boot CPU takes ring-3 lines first; MSI/MSI-X target its LAPIC
/// (`apic::msi`).
pub fn irq_routing_init(hart_id: usize) {
    azos_drv_irqchip::user_irq::set_boot_hart(hart_id as u32);
    if let Some((addr, _)) = azos_arch::apic::msi(hart_id, azos_arch::apic::IRQ_VECTOR_BASE) {
        kprintln!("[IRQ] MSI address for CPU {}: {:#x}", hart_id, addr);
    }
}

/// The MADT gave the APIC IDs and `firmware_table` installed the
/// trampoline: say what AP start will use.
pub fn smp_probe(_fw_table: usize) {
    let p = platform();
    match p.trampoline_pa {
        Some(pa) => kprintln!("[SMP] {} CPU(s); APs start by INIT-SIPI-SIPI at {:#x}", p.n_cpus, pa),
        None => kprintln!("[SMP] {} CPU(s); no trampoline page: boot CPU only", p.n_cpus),
    }
}

/// The LAPIC timer (measured against the TSC when it is the one-shot
/// counter), the periodic tick, then interrupts on.
pub fn timer_init() {
    use azos_arch::timer;
    if !timer::deadline_mode() {
        match timer::calibrate_lapic() {
            Some(hz) => kprintln!("[TIMER] LAPIC timer {} Hz (divide {})", hz, azos_limits::X86_LAPIC_TIMER_DIVIDE),
            None => azos_drv_sys::kerr!("[TIMER] FAILED: the LAPIC timer did not count"),
        }
    }
    timer::init_local();
    let hz = azos_drv_sys::timebase::sched_hz_get();
    let period = core::cmp::max(1, timer::TICK_HZ / hz);
    crate::entry::x86_64::irq::arm_periodic_timer(period);
    kprintln!("[TIMER] periodic tick armed: period={} ticks (~{} Hz)", period, hz);
    {
        use azos_arch::Interrupts;
        azos_arch::ARCH.enable_all();
    }
    kprintln!("[TRAP] interrupts on (RFLAGS.IF)");
}

/// Three facts the rest of the boot relies on, each printed PASS/FAILED:
/// an `int3` in ring 0 comes back (IDT, the trap frame, `iretq`), an NMI
/// sent to this CPU comes back (its IST stack and the paranoid GS entry),
/// and the periodic tick arrives at about its rate.
pub fn boot_selftests() {
    use core::sync::atomic::Ordering;
    use azos_arch::{Cpu, ARCH};
    let x = crate::entry::x86_64::KERNEL_BREAKPOINTS.load(Ordering::Relaxed);
    // SAFETY: #BP is a trap the handler counts and returns from.
    unsafe { core::arch::asm!("int3", options(nostack)) };
    let after = crate::entry::x86_64::KERNEL_BREAKPOINTS.load(Ordering::Relaxed);
    if after == x + 1 {
        kprintln!("[TRAP] int3 self-test: PASS (returned)");
    } else {
        azos_drv_sys::kerr!("[TRAP] FAILED: int3 self-test: {} breakpoints counted, expected {}", after - x, 1);
    }

    let n = crate::entry::x86_64::NMIS.load(Ordering::Relaxed);
    let sent = azos_arch::apic::send_raw(azos_arch::apic::id(), azos_arch::encode::ICR_DM_NMI | azos_arch::encode::ICR_ASSERT);
    let hz = azos_arch::timer::TICK_HZ;
    let deadline = ARCH.now_ticks().wrapping_add(hz / 10);
    while crate::entry::x86_64::NMIS.load(Ordering::Relaxed) == n && ARCH.now_ticks() < deadline {
        core::hint::spin_loop();
    }
    if sent && crate::entry::x86_64::NMIS.load(Ordering::Relaxed) > n {
        kprintln!("[TRAP] NMI self-test: PASS (IST {} returned)", azos_arch::idt::ist_for(azos_arch::idt::NMI));
    } else {
        azos_drv_sys::kerr!("[TRAP] FAILED: NMI self-test: sent={} taken={}", sent,
            crate::entry::x86_64::NMIS.load(Ordering::Relaxed) - n);
    }

    const TICK_TARGET: u64 = 5;
    let tick = &crate::entry::x86_64::irq::TICK_COUNT;
    let before = tick.load(Ordering::Acquire);
    let start = ARCH.now_ticks();
    let deadline = start.wrapping_add(hz.saturating_mul(2));
    while tick.load(Ordering::Acquire) < before + TICK_TARGET && ARCH.now_ticks() < deadline {
        ARCH.wfi();
    }
    let got = tick.load(Ordering::Acquire) - before;
    let ms = ARCH.now_ticks().wrapping_sub(start) / (hz / 1000).max(1);
    let want_ms = 1000 * TICK_TARGET / azos_drv_sys::timebase::sched_hz_get().max(1);
    if got >= TICK_TARGET {
        kprintln!("[TIMER] tick self-test: PASS ({} ticks in {} ms, expected ~{} ms)", got, ms, want_ms);
    } else {
        azos_drv_sys::kerr!("[TIMER] FAILED: only {} of {} ticks in {} ms (expected ~{} ms)", got, TICK_TARGET, ms, want_ms);
    }
}

/// Device windows mapped once the heap exists (PCIe ECAM from the MCFG,
/// the HPET, the IOAPIC).
/// The PCIe ECAM windows of the MCFG (the HPET, the IOAPICs and virtio-mmio
/// were mapped with the kernel tables). A not-present -> present change
/// needs no TLB flush on x86.
pub fn arch_map_late_mmio() {
    for m in platform().acpi.mcfg() {
        if azos_mm::vmm::map_mmio_region(m.base as usize, m.size() as usize).is_err() {
            azos_drv_sys::kwarn!("[PCI] ECAM {:#x} (+{:#x}) not mapped", m.base, m.size());
        }
    }
}

/// INIT-SIPI-SIPI to each MADT APIC ID up to `num_cpus`, with the real-mode
/// trampoline copied below 1 MiB.
pub fn arch_wake_secondaries(num_cpus: usize) {
    crate::entry::x86_64::smp::wake_secondaries(num_cpus)
}

/// Arm the boot CPU's LAPIC TSC-deadline tick and enter the scheduler.
/// Hand off to the scheduler with interrupts off: `start()` dispatches the
/// first task, whose context enables them (the window aarch64's K-A12 note
/// describes).
pub fn arch_enter_scheduler(_hart_id: usize) -> ! {
    // C1: by now the boot output since `console_irq` went out through the TX
    // ring, a FIFO load per THR-empty interrupt (interrupts are on since
    // `timer_init`). The x86 boot row reads this line; `console-tx-sync`
    // (its canary) leaves the console polled.
    let (tx_on, tx_hwm, tx_irqs) = azos_drv_sys::uart::console_tx_stats();
    kprintln!("[UART] COM1 TX {} ({} THR-empty interrupt(s), ring high-water {} B)",
              if tx_on && tx_irqs > 0 { "interrupt-driven" } else { "polled" }, tx_irqs, tx_hwm);
    kprintln!("[SCHED] Starting scheduler on boot CPU — tasks will now preempt...");
    {
        use azos_arch::Interrupts;
        let _ = azos_arch::ARCH.disable_all();
    }
    // Open the preemption gate with interrupts off, as riscv64 and aarch64
    // do: `x86_64_trap_resched` returns early until this is set.
    crate::entry::x86_64::SCHED_LIVE.store(true, core::sync::atomic::Ordering::Release);
    azos_sched::start()
}

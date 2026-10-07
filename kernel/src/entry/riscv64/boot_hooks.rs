// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 boot hooks: the ISA-specific steps of the generic early boot
//! (`boot::early_main`, kernel/src/boot/early.rs), which calls them through
//! this ISA's `ArchEntry` (`arch_entry.rs`), plus the SBI HSM secondary-hart
//! wake and the hand-off to the scheduler.
//!
//! What is riscv64's own here: `stvec` and the interrupt stacks, the
//! PLIC/AIA choice and its init, Sstc vs SBI `set_timer`, Zicboz, the QEMU
//! and board MMIO windows, the PMP audit log, the `sie` enables. The common
//! steps (console, memory map, page tables, W^X/NX, guards, heap) are in
//! `early_main`; a common step kept here carries a `boot-seq:` reason
//! (`tools/boot_seq_lint.py`).

use core::sync::atomic::Ordering;
use azos_drv_sys::kprintln;
use azos_arch::csr;
use azos_arch::Interrupts;
use azos_arch::FirmwareMemory;

/// The parsed device tree (`None`: no pointer, or one that did not parse),
/// and the hart it was parsed on.
pub struct Firmware {
    info: Option<azos_dtb::DtbInfo>,
    hart_id: usize,
}

/// Nothing to read before the console on riscv64.
#[inline(always)]
pub fn pre_console() {}

/// The trap vector, installed before any code that could fault: until
/// `stvec` is set, an exception jumps to address 0. `trap_init` needs only
/// the UART (for `kprintln`) and CSRs: no heap, no MMU. The interrupt stacks
/// are armed FIRST: from the instant `stvec` is live a trap can arrive, and
/// the exit path reads the magic word of the slot it ran on. Secondaries
/// share these slots by hart id, so arming them here covers every hart.
#[inline(always)]
pub fn trap_init() {
    crate::irq_stacks_arm();
    crate::trap_init();
}

/// The banner, then a boot hart at or past `NR_CPUS` halts.
#[inline(always)]
pub fn boot_banner(hart_id: usize, dtb_ptr: usize) {
    kprintln!();
    kprintln!("========================================");
    kprintln!("  AzOS Rust kernel booted!");
    kprintln!("========================================");
    kprintln!();
    kprintln!("[BOOT] Hart ID:  {}", hart_id);
    kprintln!("[BOOT] DTB addr: {:#x}", dtb_ptr);

    // The boot hart is whoever won `boot_lock`: boot.S range-checks only
    // SECONDARY harts. A CPU id is the hart id here (`tp`), and every per-CPU
    // table is indexed by it, so a boot hart at or past `NR_CPUS` has no slot
    // anywhere: halt loudly with the id rather than index out of bounds on
    // the first scheduler touch. (VF2: S7 is hart 0 and the U74s 1..4, so
    // its default is 5.)
    if hart_id >= crate::MAX_HARTS {
        azos_drv_sys::kerr!("[BOOT] FATAL: boot hart id {} >= NR_CPUS {} — it has no per-CPU \
                   slot. Halting. (Raise NR_CPUS in make config.)", hart_id, crate::MAX_HARTS);
        loop { azos_arch::cpu::wfi(); }
    }
}

/// Parse the DTB and print what it says.
#[inline(always)]
pub fn firmware_table(hart_id: usize, dtb_ptr: usize) -> Firmware {
    let info = if dtb_ptr != 0 {
        // boot-seq: the firmware-table format is the ISA's (a DTB here and on
        // aarch64, PVH/ACPI on x86_64), and each prints its own lines.
        let parsed = unsafe { azos_dtb::dtb_parse(dtb_ptr as *const u8) };
        match &parsed {
            Some(info) => {
                let compat = azos_dtb::dtb_compatible_str(info);
                kprintln!("[DTB] Parsed FDT — {} CPUs, mem={:#x}+{:#x}, timer={}",
                    info.num_cpus, info.mem_base, info.mem_size, info.timer_freq);
                if info.plic_base != 0 {
                    kprintln!("[DTB] UART={:#x}, PLIC={:#x}", info.uart_base, info.plic_base);
                } else {
                    kprintln!("[DTB] UART={:#x}, PLIC=none", info.uart_base);
                }
                kprintln!("[DTB] Compatible: {}", core::str::from_utf8(compat).unwrap_or("?"));
            }
            None => azos_drv_sys::kerr!("[DTB] Parse failed (invalid or unsupported FDT)"),
        }
        parsed
    } else {
        None
    };
    Firmware { info, hart_id }
}

/// RFC-0046 stage 1a: an S-domain APLIC plus an S-level IMSIC group in the
/// DTB (`virt,aia=aplic-imsic`) selects the AIA path of `irqchip`; plain
/// `virt` keeps the PLIC. Must run before the MMIO mapping and the IRQ init,
/// which both consult the selection. Then the drivers front: QEMU virt's
/// bus/device/driver table, bound from the DTB (VF2/K1 have compile-time
/// device tables instead).
#[inline(always)]
pub fn irqchip_probe(fw: &Firmware) {
    let Some(info) = &fw.info else { return };
    if info.aplic_base != 0 && info.imsic_base != 0 {
        let layout = azos_drv_irqchip::imsic::GroupLayout {
            base: info.imsic_base,
            num_ids: info.imsic_num_ids,
            hart_stride: azos_drv_irqchip::imsic::GroupLayout::stride_for_guest_bits(
                info.imsic_guest_index_bits),
        };
        azos_drv_irqchip::irqchip::select_aia(info.aplic_base, info.aplic_num_sources, layout);
        kprintln!("[DTB] AIA: APLIC={:#x} sources={} IMSIC={:#x} ids={} stride={:#x}",
            info.aplic_base, info.aplic_num_sources, info.imsic_base,
            info.imsic_num_ids, layout.hart_stride);
    }
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    azos_drv_bus::hwbus::probe_qemu_virt_riscv64(
        info.uart_base, info.plic_base, azos_drv_irqchip::irqchip::is_aia());
}

/// RFC-0041 §B: `stimecmp` when cpu@0 declares Sstc and S-mode can read the
/// CSR (`clint::timer_select` probes it); SBI otherwise. Then the DTB's
/// timebase against the kernel's fixed `TIMER_FREQ`: if they disagree, every
/// µs/ms calculation (WCET, sleeps, timeouts) is off, so say so loudly.
#[inline(always)]
pub fn timer_probe(fw: &Firmware) {
    let Some(info) = &fw.info else { return };
    azos_drv_irqchip::clint::timer_select(
        cfg!(not(feature = "timer-sbi-only")) && info.isa_sstc,
    );
    let kernel_timer_hz = azos_drv_base::platform::hw::TIMER_FREQ;
    if info.timer_freq != 0 && info.timer_freq != kernel_timer_hz {
        azos_drv_sys::kwarn!("[DTB] WARNING: timer_freq mismatch — DTB={}Hz kernel={}Hz, \
            timing calculations will drift", info.timer_freq, kernel_timer_hz);
    }
}

/// RFC-0045 Tier 0 item 3: `cbo.zero` for the page allocator's zero-fill
/// when cpu@0 declares Zicboz and a trap-safe probe confirms it executes and
/// zeroes correctly on this hart (`cbo::zicboz_select`; the same "the DTB
/// claims it, then verify on the real hart" shape as Sstc). Before
/// `pmm::init`: `alloc_page`'s zero-fill consults it on its first call.
/// Gate canary `zicboz-skip-canary`: the DTB's Zicboz is ignored. Then the
/// vDSO `hwcap` inputs (wave 13, published by `install_vdso`).
#[inline(always)]
pub fn cpu_features(fw: &Firmware) {
    let Some(info) = &fw.info else { return };
    #[cfg(not(feature = "zicboz-skip-canary"))]
    azos_arch::cbo::zicboz_select(info.isa_zicboz, info.cboz_block_size);
    crate::boot::note_dtb_isa(info.isa_zbb, info.isa_zbc, info.isa_zknh, info.isa_v);
}

/// RAM from the DTB's `/memory` node, or the platform fallback. The boot
/// CPU's logical id is its hart id on this ISA.
#[inline(always)]
pub fn firmware_memory(fw: &Firmware) -> FirmwareMemory {
    use azos_drv_base::platform::hw;
    let (mem_start, mem_size, from_firmware) = match &fw.info {
        Some(i) if i.mem_base != 0 && i.mem_size != 0 => (i.mem_base, i.mem_size, true),
        _ => (hw::RAM_BASE, crate::FALLBACK_MEM_SIZE, false),
    };
    let (cpu_count, cpu_source) = match &fw.info {
        Some(i) => (i.num_cpus, "DTB"),
        None => (0, "none"),
    };
    FirmwareMemory { mem_start, mem_size, from_firmware, cpu_count, boot_cpu: fw.hart_id, cpu_source }
}

/// Before `pmm::init`, which may reuse the blob's pages (nothing reserves
/// them on this ISA): the ring-3 trigger types, then the final timer and
/// Zicboz choices, each finalized here when the DTB made none.
#[inline(always)]
pub fn firmware_done(dtb_ptr: usize, num_cpus: usize) {
    // Trigger types for ring-3 lines (wave 9 IRQ4). Only the APLIC takes a
    // trigger (`sourcecfg`); a PLIC has none and its binding
    // (`#interrupt-cells = 1`) carries none, so plain `virt` reads nothing.
    if azos_drv_irqchip::irqchip::is_aia() && dtb_ptr != 0 {
        // boot-seq: read before `pmm::init` here (the blob is not reserved
        // on riscv64); aarch64 reserves it and reads after its GIC is up.
        let found = unsafe {
            azos_dtb::dtb_irq_triggers(dtb_ptr as *const u8, azos_dtb::IrqController::AplicS)
        };
        match found {
            Some(t) => {
                for line in 1..azos_drv_irqchip::plic::MAX_IRQS {
                    if let Some(edge) = t.edge(line) {
                        azos_drv_irqchip::user_irq::note_dtb_trigger(line, edge);
                    }
                }
                let (n, e) = t.counts();
                kprintln!("[IRQ] DTB triggers (APLIC-S): {} sources, {} edge", n, e);
            }
            None => kprintln!("[IRQ] DTB triggers: no S-domain APLIC with 2-cell specifiers"),
        }
    }

    // Selects SBI when nothing above did (no DTB, or one that did not parse);
    // otherwise returns the choice already made.
    match azos_drv_irqchip::clint::timer_select(false) {
        azos_drv_irqchip::clint::TimerMode::Sstc => kprintln!("[TIMER] stimecmp (Sstc)"),
        azos_drv_irqchip::clint::TimerMode::Sbi => kprintln!("[TIMER] SBI set_timer"),
    }
    // The probe's own trap path, taken on purpose: under `-cpu rv64,sstc=off`
    // the read traps, and the boot must carry on past this line.
    #[cfg(feature = "qemu")]
    kprintln!("[TIMER] stimecmp probe: {}",
        if azos_drv_irqchip::clint::stimecmp_probe() { "readable" } else { "trapped" });
    // Selects "absent" when nothing above did; same "finalize the decision"
    // role as `timer_select(false)` just above.
    let zicboz_on = azos_arch::cbo::zicboz_select(false, 0);
    kprintln!("[MM] Zicboz cbo.zero fast path: {}",
        if zicboz_on { "enabled" } else { "scalar fallback" });
    kprintln!("[BOOT] Online CPUs: {} (NR_CPUS: {})", num_cpus, crate::MAX_HARTS);
    kprintln!();
}

/// Nothing to reserve: the blob is read in full before `pmm::init`
/// (`firmware_done`), and `pstore::reserve` already rules out an overlap.
#[inline(always)]
pub fn reserve_firmware_table(_dtb_ptr: usize) {}

/// The interrupt controller, the timer block and the board's devices,
/// identity-mapped before `enable_paging` (the console is mapped by
/// `early_main`).
///
/// boot-seq: the device windows are the platform's; only the console's is
/// common.
#[inline(always)]
pub fn kernel_mmio_map() {
    use azos_drv_base::platform::hw;

    // PLIC (all platforms — up to 4 MiB is sufficient for enable/threshold/claim)
    let _ = azos_mm::vmm::map_mmio_region(hw::PLIC_BASE, 0x40_0000);

    // S-domain APLIC (32 KiB), only when the DTB selected AIA. The IMSIC
    // needs no mapping: the kernel reaches its own file through CSRs; only
    // devices write the file's physical page.
    if let Some(aplic_base) = azos_drv_irqchip::irqchip::aplic_mmio_base() {
        let _ = azos_mm::vmm::map_mmio_region(aplic_base, 0x8000);
    }

    // QEMU-specific MMIO
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    {
        // VirtIO MMIO 0x10001000 - 0x10008000 (8 devices)
        let _ = azos_mm::vmm::map_mmio_region(0x1000_1000, 0x8000);
        // CLINT 0x02000000 (64 KiB) — mtime/mtimecmp via SBI but read rdtime
        let _ = azos_mm::vmm::map_mmio_region(0x0200_0000, 0x1_0000);
        // fw_cfg (--features ramfb only — crates/drivers/display/src/ramfb.rs).
        // Found by booting with ramfb and getting a page fault at 0x10100008
        // (the selector register).
        #[cfg(feature = "ramfb")]
        let _ = azos_mm::vmm::map_mmio_region(hw::FW_CFG_BASE, 0x1000);
    }

    // VF2-specific MMIO
    #[cfg(feature = "vf2")]
    {
        let _ = azos_mm::vmm::map_mmio_region(0x0200_0000, 0x1_0000); // CLINT
        let _ = azos_mm::vmm::map_mmio_region(hw::GPIO_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::PWM_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::I2C0_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::I2C1_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::MMC0_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::MMC1_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::ETH0_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::UART1_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::WDT_BASE, 0x1000);
        // Display (--features hdmi only — crates/drivers/display), added after
        // the same class of missing mapping was caught on QEMU's ramfb.
        #[cfg(feature = "hdmi")]
        {
            let _ = azos_mm::vmm::map_mmio_region(hw::DC8200_TOP_BASE, 0x1000);
            let _ = azos_mm::vmm::map_mmio_region(hw::DC8200_MAIN_BASE, 0x2000);
            let _ = azos_mm::vmm::map_mmio_region(hw::HDMI_TX_BASE, 0x1000);
        }
    }

    // K1-specific MMIO
    #[cfg(feature = "k1")]
    {
        let _ = azos_mm::vmm::map_mmio_region(hw::GPIO_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::PWM_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::I2C0_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::I2C1_BASE, 0x1000);
        let _ = azos_mm::vmm::map_mmio_region(hw::MMC0_BASE, 0x2000);
        let _ = azos_mm::vmm::map_mmio_region(hw::WDT_BASE, 0x1000);
        // F14: NPU MMIO (1 MiB, covers all command/data registers).
        let _ = azos_mm::vmm::map_mmio_region(hw::NPU_BASE, hw::NPU_SIZE);
    }
}

/// `satp` now holds the kernel table.
#[inline(always)]
pub fn mmu_enabled() {
    kprintln!("[MM] Sv39 paging ENABLED");
}

/// Nothing to restrict: user tables copy only the kernel's own half on
/// riscv64, and RAM is not mapped in the user range.
#[inline(always)]
pub fn restrict_low_half() {}

/// The guards' "active" lines are the riscv64 report; its fault probes are
/// the generic ones (`early_main`).
#[inline(always)]
pub fn verify_guards() {}

/// The Zicboz zero-fill self-check and bench (QEMU), the PMP audit log, and
/// the vDSO page.
#[inline(always)]
pub fn post_heap(heap_start: usize, kernel_end_aligned: usize) {
    zicboz_selfcheck();
    kprintln!();

    // F04: PMP policy audit log. The kernel runs in S-mode and cannot write
    // PMP CSRs (M-mode only); every boot path runs under OpenSBI, which sets
    // a permissive PMP, and W^X is enforced by the page tables. (B2-02: the
    // no-OpenSBI M-mode stub that once called pmp_early_init() was deleted.)
    // Log the intended stricter policy for operator audit.
    {
        use azos_arch::pmp::{pmp_regions, N_PMP_REGIONS};
        use azos_drv_base::platform::hw::KERNEL_LOAD;
        let pmp = pmp_regions(KERNEL_LOAD, kernel_end_aligned, heap_start, crate::HEAP_SIZE);
        kprintln!("[PMP] Intended policy ({} regions + deny catch-all):", N_PMP_REGIONS);
        for (i, r) in pmp.iter().enumerate() {
            kprintln!("[PMP]  {}: {:20}  {:010x}-{:010x}  {}{}{}",
                i, r.name,
                r.base, r.base + r.size,
                if r.perm.r { 'R' } else { '-' },
                if r.perm.w { 'W' } else { '-' },
                if r.perm.x { 'X' } else { '-' },
            );
        }
        kprintln!("[PMP] Running under OpenSBI — W^X enforced by VMM page tables");
        kprintln!();
    }

    // M01: the vDSO timing page user space reads directly. `rdtime` from
    // U-mode is enabled (`scounteren.TM`), so libsys may read the counter
    // instead of trapping for SYS_UPTIME (RFC-0041 §A); `vdso-force-syscall`
    // keeps the trap, for measuring it.
    // boot-seq: riscv64's timebase is the fixed TIMER_FREQ, known here, before
    // the PLIC; aarch64 installs it after reading CNTFRQ_EL0 (`timer_init`).
    crate::install_vdso(azos_drv_sys::timebase::TIMER_FREQ);
}

/// RFC-0045 Tier 0 item 3 canary (QEMU only): poison a page, free it, force a
/// first-fit reallocation of the same physical page, and confirm it comes
/// back all zero, under whichever zero-fill `zicboz_select` chose. A stride
/// or block-size bug in `cbo.zero`'s loop would leave `0xAA` behind.
///
/// Placed after `kheap::init`, not right after `pmm::init`, on purpose:
/// `vmm::init`'s page tables rely on first-fit placing them right after
/// `kernel_end`, and an alloc/free cycle before it moves the allocator's
/// scan position, so `kheap::init`'s `range_is_free` check fails.
///
/// Then the bench (RFC-0045 §10): under `-icount shift=0,sleep=off`,
/// `rdcycle` is a deterministic proxy for retired instructions; a batch of
/// pages is freed and re-allocated through the chosen zero-fill, and the
/// cycle delta printed, to compare against `-cpu rv64,zicboz=off`.
#[inline(always)]
fn zicboz_selfcheck() {
    #[cfg(feature = "qemu")]
    {
        use azos_arch::mmu::PAGE_SIZE;
        let ok = (|| -> Option<bool> {
            let p = azos_mm::pmm::alloc_page().ok()?;
            let addr = p.as_usize();
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0xAA, PAGE_SIZE) };
            azos_mm::pmm::free_page(p).ok()?;
            let again = azos_mm::pmm::alloc_page().ok()?;
            let same_page = again.as_usize() == addr;
            let bytes = unsafe {
                core::slice::from_raw_parts(again.as_usize() as *const u8, PAGE_SIZE)
            };
            let all_zero = bytes.iter().all(|&b| b == 0);
            let _ = azos_mm::pmm::free_page(again);
            Some(same_page && all_zero)
        })().unwrap_or(false);
        // The bad path says `FAILED:` on purpose: `QEMU_FAIL_RE` in
        // tools/ci_check.sh matches it, so a broken zero-fill turns EVERY
        // QEMU scenario red, not just a dedicated row.
        if ok {
            kprintln!("[MM] Zicboz zero-fill self-check: PASS");
        } else {
            azos_drv_sys::kerr!("[MM] Zicboz zero-fill self-check FAILED: reallocated page \
                       was not all zero");
        }

        const BENCH_PAGES: usize = 32;
        let mut held: [Option<azos_mm::addr::PhysAddr>; BENCH_PAGES] = [None; BENCH_PAGES];
        let mut filled = 0usize;
        while filled < BENCH_PAGES {
            match azos_mm::pmm::alloc_page() {
                Ok(p) => { held[filled] = Some(p); filled += 1; }
                Err(_) => break,
            }
        }
        for slot in held.iter().take(filled) {
            if let Some(p) = slot { let _ = azos_mm::pmm::free_page(*p); }
        }
        let bench_start = azos_arch::rvv::rdcycle();
        for slot in held.iter_mut().take(filled) {
            *slot = azos_mm::pmm::alloc_page().ok();
        }
        let bench_end = azos_arch::rvv::rdcycle();
        for slot in held.iter().take(filled) {
            if let Some(p) = slot { let _ = azos_mm::pmm::free_page(*p); }
        }
        kprintln!("[MM] Zicboz zero-fill bench: {} pages, {} cycles ({} cycles/page)",
            filled, bench_end - bench_start,
            if filled > 0 { (bench_end - bench_start) / filled as u64 } else { 0 });
    }
}

/// `irqchip` dispatches to `plic::init` on plain `virt`, or to this hart's
/// IMSIC file plus the APLIC domain (MSI mode) on AIA.
#[inline(always)]
pub fn irqchip_init(hart_id: usize, _dtb_ptr: usize) {
    if azos_drv_irqchip::irqchip::is_aia() {
        kprintln!("[IRQ] Initializing AIA (APLIC MSI mode + IMSIC)...");
    } else {
        kprintln!("[IRQ] Initializing PLIC...");
    }
    azos_drv_irqchip::irqchip::init(hart_id as u32);
    azos_drv_irqchip::irqchip::init_aia_domain();
}

/// EXTERNAL + SOFTWARE interrupts (PLIC, IPI). The timer (STIE) waits until
/// just before `scheduler::start()`: otherwise the timer ISR preempts
/// `kernel_main` with already-created RT tasks and the boot CPU never
/// reaches `wake_harts()`, starving every secondary.
#[inline(always)]
pub fn irq_enable_early() {
    let sie = csr::read_sie();
    csr::write_sie(sie | csr::SIE_SEIE | csr::SIE_SSIE);
    azos_arch::ARCH.enable_all();
}

/// UART RX interrupt (IRQ 10): characters go to the ring buffer. On AIA the
/// APLIC source is first routed to this hart, identity 10.
#[inline(always)]
pub fn console_irq(hart_id: usize, _dtb_ptr: usize) {
    if let Some(cfg) = azos_drv_irqchip::irqchip::wire_aia_source(
        azos_drv_sys::uart::UART_IRQ, hart_id as u32)
    {
        kprintln!("[IRQ] APLIC source {} -> hart {} sourcecfg={:#x}",
            azos_drv_sys::uart::UART_IRQ, hart_id, cfg);
    }
    azos_drv_irqchip::irqchip::enable_irq(hart_id as u32, azos_drv_sys::uart::UART_IRQ);
    azos_drv_sys::uart::enable_irq();
    // RFC-0055 S1: the PLIC arm (`trap::interrupt`) wakes a reader parked on
    // console input, as aarch64's PL011 arm does.
    azos_drv_sys::uart::set_rx_wake_wired();
    kprintln!("[IRQ] UART IRQ enabled (ring buffer RX)");
    // The same line now feeds the UART from the console's TX ring.
    azos_drv_sys::uart::enable_tx_irq();
}

/// Read already, before `pmm::init` (`firmware_done`).
#[inline(always)]
pub fn irq_triggers(_dtb_ptr: usize) {}

/// The PLIC/APLIC line, masked and handed back.
#[inline(always)]
pub fn line_release() -> fn(u32) {
    azos_drv_irqchip::user_irq::release
}

/// The boot hart: the kernel's own lines are routed here, and it is the
/// first hart a ring-3 line may be routed to; each secondary joins in
/// `secondary_main` (`user_irq::hart_ready`).
#[inline(always)]
pub fn irq_routing_init(hart_id: usize) {
    azos_drv_irqchip::user_irq::set_boot_hart(hart_id as u32);
    kprintln!("[IRQ] Traps + interrupts active");
    kprintln!();
}

/// SBI HSM needs no probe: `hart_start` is the interface on every board.
#[inline(always)]
pub fn smp_probe(_dtb_ptr: usize) {}

/// The tick is armed in `arch_enter_scheduler` (see `irq_enable_early`).
#[inline(always)]
pub fn timer_init() {}

/// riscv64's boot self-checks run where their subject comes up
/// (`[MM] Zicboz`, `[TIMER] stimecmp probe`).
#[inline(always)]
pub fn boot_selftests() {}

/// No-op on riscv64: nothing this ISA maps late. See
/// `entry::aarch64::boot_hooks::arch_map_late_mmio` for why aarch64 needs
/// one (VirtIO-MMIO is not live before this point on that ISA).
pub fn arch_map_late_mmio() {}

/// Start every secondary hart via SBI HSM `hart_start`, correct
/// `NUM_ONLINE_CPUS` down to the real count, and rescue any task an
/// optimistic pre-wake `task_create*` stranded on a hart that never came
/// up. Verbatim cut from the former riscv64 `kernel_main`'s own tail.
pub fn arch_wake_secondaries(num_cpus: usize) {
    // Enable SMP UART lock before secondary CPUs can print.
    azos_drv_sys::uart::enable_smp_lock();
    kprintln!("[SMP] UART lock enabled");

    // Start secondary harts via SBI HSM hart_start (OpenSBI parks them by default).
    {
        kprintln!("[SMP] Starting {} secondary harts via SBI HSM...", num_cpus - 1);
        let online = unsafe { azos_sched::smp::wake_harts(num_cpus) };
        if online != num_cpus {
            azos_drv_sys::kwarn!(
                "[SMP] WARNING: only {}/{} harts started — degraded to {} online CPU(s)",
                online, num_cpus, online
            );
        }
        // Correct NUM_ONLINE_CPUS from the optimistic pre-boot estimate
        // (set above, before task creation, so the boot-time task_create
        // calls could spread across the intended CPU count) to the real
        // count wake_harts() confirmed. This is what protects any task
        // created from here on (e.g. fork() in crates/core/sched/src/process.rs)
        // from being load-balanced onto a hart that never came up — see
        // NUM_ONLINE_CPUS's doc comment in crates/core/sched/src/smp.rs.
        azos_sched::smp::NUM_ONLINE_CPUS.store(online, Ordering::SeqCst);

        // Rescue tasks that the *pre-boot optimistic* task_create calls
        // (above, before wake_harts() ran) assigned to a hart that then
        // failed to start — those per-CPU ready queues would otherwise sit
        // forever, since this scheduler has no runtime work-stealing
        // (verified: no steal/rebalance/migrate logic anywhere in
        // crates/core/sched/src/scheduler.rs). This is the only point in the
        // whole boot sequence where ready queues can be moved between CPUs
        // without racing another consumer: the boot hart hasn't called
        // sched::start() yet, hasn't enabled its own timer interrupt yet
        // (a few lines below), and dead harts by definition never run any
        // code at all. See `rebalance_from_offline_cpus`'s doc comment for
        // why it still routes every touch through the locked queue
        // wrappers regardless (an *alive* secondary hart can start ticking
        // independently of the boot hart's progress here).
        // **The condition is `online < MAX_CPUS`, NOT `online != num_cpus`.**
        //
        // The previous version assumed tasks can only be stranded when fewer
        // harts came up than the DTB promised. That is false: several tasks
        // are created with **explicit affinity** to a specific hart, and that
        // pin is not bounded by `num_cpus`. With `-smp 1`,
        // `online == num_cpus == 1`, the condition was false and the rescue
        // **was never called** — with six tasks, `autorun` among them, queued
        // on CPUs 1, 2 and 3.
        //
        // Measured before: `per_cpu_queues = [0, 3, 1, 2]`, and the ring-3 ELF
        // never executing a single instruction while the kernel looked
        // healthy.
        //
        // Every queue above `online` must be drained, whether or not the DTB
        // says that hart exists.
        if online < azos_sched::MAX_CPUS {
            azos_sched::rebalance_from_offline_cpus(online, num_cpus);
        }
    }
}

/// Final hand-off to the scheduler: boot-stack usage report, the SIE-armed-
/// too-early canary, the shared "[SCHED] Starting scheduler..." line, arm
/// the timer, re-establish `tp = hart_id` (Rust calls up to this point may
/// have clobbered it as a caller-saved scratch register), then
/// `azos_sched::start()` — never returns. Verbatim cut from the former
/// riscv64 `kernel_main`'s own tail.
pub fn arch_enter_scheduler(hart_id: usize) -> ! {
    crate::boot_stack_report();

    // Only now may a tick switch the boot hart to a task. kernel_main is no
    // task, so `do_schedule` saves nothing when it switches away from it:
    // with the timer enabled any earlier, the first switching tick discards
    // the rest of this function, hw_init above included. SIE stays clear
    // until the first task's entry wrapper sets it, so no tick lands before
    // sched::start() either. The "Starting scheduler" line is the gate's proof
    // that this point was reached. Losing the tail is a race (it takes a tick
    // that finds a ready task on this hart), so a timer enabled too early can
    // also get here by luck; the check below turns that case red as well.
    if csr::read_sie() & csr::SIE_STIE != 0 {
        azos_drv_sys::kerr!("[SCHED] Boot hart FAILED: timer interrupt enabled before the end of kernel_main");
    }
    kprintln!("[SCHED] Starting scheduler on boot CPU — tasks will now preempt...");
    kprintln!();
    let _ = azos_arch::ARCH.disable_all();

    // U01-4: open the SCHED_LIVE gate before anything re-enables interrupts
    // below — same ordering as `entry::aarch64::boot_hooks::arch_enter_
    // scheduler`. `trap_resched()` (kernel/src/trap/interrupt.rs) now checks this
    // first and returns early while it is false, so SIE_SEIE/SIE_SSIE
    // having been live since Phase 3 (arch_hardware_init) can no longer
    // walk a cross-hart IPI into `schedule()` on a hart that has not
    // called `sched::start()` yet.
    crate::entry::riscv64::SCHED_LIVE.store(true, core::sync::atomic::Ordering::Release);

    azos_drv_sys::timebase::set_next_tick(hart_id as u32);
    csr::write_sie(csr::read_sie() | csr::SIE_STIE);

    // Re-establish tp = hart_id immediately before entering the scheduler.
    // Rust functions called during kernel_main (including kprintln) may have used
    // tp as a caller-saved scratch register, corrupting current_cpu_id().
    // After this point no Rust functions are called before context_switch.S saves/restores tp.
    unsafe { core::arch::asm!("mv tp, {}", in(reg) hart_id, options(nostack, nomem)); }

    // Start the scheduler on the boot CPU (never returns).
    azos_sched::start()
}

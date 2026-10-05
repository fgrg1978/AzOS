// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 boot hooks — kernel-main-merge task (2026-09-24).
//!
//! Extracted verbatim from the former riscv64-only `kernel_main`'s early-init
//! block (Phase 1/1b/2/3: UART, trap vector, DTB parse, PMM/VMM/heap, W^X/NX,
//! PLIC + interrupt enable), the SBI HSM secondary-hart wake, and the tail
//! that hands off to the scheduler. Called from the single shared
//! `kernel_main` in `main.rs` at the points where the two ISAs' boot
//! sequences genuinely diverge — see that function and
//! `entry::aarch64::boot_hooks` for the aarch64 counterparts, and
//! `ordering-decisions.md` (kernel-main-merge task) for why each cut point
//! is where it is.
//!
//! Every symbol here that used to be a bare reference into `main.rs` is now
//! `crate::`-qualified — this file is a sibling module, not an `include!`.

use core::sync::atomic::Ordering;
use azos_drv_sys::kprintln;
use azos_arch::csr;
use azos_arch::Interrupts;
use azos_arch::mmu::PAGE_SIZE;
use crate::EarlyBoot;

/// Phase 1/1b/2/3: UART, trap vector armed before any faulting code, DTB
/// parse, PMM/VMM/heap bring-up (W^X + NX enforced), PLIC + interrupt
/// enable. Verbatim cut from the former riscv64 `kernel_main`'s own body —
/// see this file's module doc.
pub fn arch_early_boot(hart_id: usize, dtb_ptr: usize) -> EarlyBoot {
    // ---- Phase 1: UART ----
    azos_drv_sys::uart::init();
    // Which device is the console, chosen here rather than hardcoded at every
    // call site. `sys_write` to fd 1/2 goes through `uart::console_write`,
    // which dispatches on this registration; the kernel's own `kprintln!` and
    // `kernel/src/panic.rs` deliberately stay on the direct path — a panic
    // handler that depends on a registered implementation prints nothing
    // exactly when it matters. Runs on the boot hart before
    // `enable_smp_lock()`, which is the contract `console_register` states.
    #[cfg(not(feature = "console-route-canary"))]
    azos_drv_sys::uart::console_register(&azos_drv_sys::uart::CONSOLE);
    // Gate-only: a console whose effect is VISIBLE, so the row can tell a live
    // registration from the silent fallback. See `uart::CanaryConsole`.
    #[cfg(feature = "console-route-canary")]
    azos_drv_sys::uart::console_register(&azos_drv_sys::uart::CANARY_CONSOLE);

    // ---- Phase 1b: Install trap vector EARLY (before any code that could fault).
    // Until stvec is set, any exception jumps to address 0 → triple fault.
    // crate::trap_init() only needs UART (for kprintln) and CSRs — no heap, no MMU.
    // The interrupt stacks are armed FIRST: from the instant stvec is live a
    // trap can arrive, and the exit path reads the magic word of the slot it
    // ran on. Secondaries share these slots by hart id, so arming them here,
    // on the boot hart, covers every hart that starts later.
    crate::irq_stacks_arm();
    crate::trap_init();

    kprintln!();
    kprintln!("========================================");
    kprintln!("  AzOS Rust kernel booted!");
    kprintln!("========================================");
    kprintln!();
    kprintln!("[BOOT] Hart ID:  {}", hart_id);
    kprintln!("[BOOT] DTB addr: {:#x}", dtb_ptr);

    // The boot hart is whoever won `boot_lock` — boot.S range-checks only
    // SECONDARY harts, and against MAX_HARTS (stack + trap-vector slots),
    // not crate::MAX_CPUS. Every scheduler structure is `[_; crate::MAX_CPUS]` indexed by
    // a raw `PER_CPU[current_cpu_id()]`, so a boot hart id past crate::MAX_CPUS is
    // not degraded service — it is an out-of-bounds write into .bss on the
    // first scheduler touch and a silent board reset. The VF2/JH7110 case
    // is real (S7 + four U74s enumerate 5 harts):
    // if firmware ever elects a boot hart >= crate::MAX_CPUS, halting loudly here
    // with the id on the UART is the only honest outcome. The real fix for
    // such boards is a physical→logical hart map (post-hardware work);
    // until then the id doubles as the index and must be in range.
    if hart_id >= crate::MAX_CPUS {
        azos_drv_sys::kerr!("[BOOT] FATAL: boot hart id {} >= crate::MAX_CPUS {} — every \
                   PER_CPU access would index out of bounds. Halting. \
                   (Board needs a physical->logical hart map, or boot-hart \
                   selection in firmware.)", hart_id, crate::MAX_CPUS);
        loop { azos_arch::cpu::wfi(); }
    }

    // Parse DTB (Flattened Device Tree) if pointer looks valid.
    // Extract mem_base/mem_size to feed PMM and VMM with real hardware RAM.
    // Extract num_cpus to size the SMP scheduler at runtime (capped at crate::MAX_CPUS).
    // Validate timer_freq against the kernel's hardcoded value — a mismatch
    // means every µs/ms calculation in the kernel is off and must be flagged.
    let (mem_start, mem_size, mem_from_dtb, num_cpus) = if dtb_ptr != 0 {
        if let Some(info) = unsafe { azos_dtb::dtb_parse(dtb_ptr as *const u8) } {
            let compat = azos_dtb::dtb_compatible_str(&info);
            kprintln!("[DTB] Parsed FDT — {} CPUs, mem={:#x}+{:#x}, timer={}",
                info.num_cpus, info.mem_base, info.mem_size, info.timer_freq);
            if info.plic_base != 0 {
                kprintln!("[DTB] UART={:#x}, PLIC={:#x}", info.uart_base, info.plic_base);
            } else {
                kprintln!("[DTB] UART={:#x}, PLIC=none", info.uart_base);
            }
            kprintln!("[DTB] Compatible: {}", core::str::from_utf8(compat).unwrap_or("?"));

            // RFC-0046 stage 1a: an S-domain APLIC plus an S-level IMSIC
            // group in the DTB (`virt,aia=aplic-imsic`) selects the AIA
            // path of `irqchip`; plain `virt` has neither and keeps the
            // PLIC path. Must run before the MMIO mapping and the IRQ init
            // below, which both consult the selection.
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

            // Drivers front: instantiate the bus/device/driver table from
            // the DTB on QEMU virt and bind whatever matches — one line per
            // bound device (`hwbus::probe_qemu_virt_riscv64`,
            // `crates/drivers/bus/src/hwbus.rs`). VF2/K1 have their own
            // compile-time device tables (not DTB-probed), so this is
            // QEMU-virt-only; those boards keep whatever `hw::` gives them.
            #[cfg(not(any(feature = "vf2", feature = "k1")))]
            azos_drv_bus::hwbus::probe_qemu_virt_riscv64(
                info.uart_base, info.plic_base, azos_drv_irqchip::irqchip::is_aia());

            // RFC-0041 §B: `stimecmp` when cpu@0 declares Sstc and S-mode can
            // read the CSR (`clint::timer_select` probes it); SBI otherwise.
            azos_drv_irqchip::clint::timer_select(
                cfg!(not(feature = "timer-sbi-only")) && info.isa_sstc,
            );

            // RFC-0045 Tier 0 item 3: `cbo.zero` for the page allocator's
            // zero-fill when cpu@0 declares Zicboz and a trap-safe probe
            // confirms `cbo.zero` actually executes and zeroes correctly on
            // this hart (`azos_arch::cbo::zicboz_select` — same
            // "device tree claims it, then verify on the real hart" shape
            // as the Sstc call just above). Must run before `pmm::init`
            // below: `alloc_page`'s zero-fill consults this decision on its
            // very first call.
            azos_arch::cbo::zicboz_select(info.isa_zicboz, info.cboz_block_size);

            // Wave 13: the vDSO `hwcap` inputs (published by `install_vdso`).
            crate::boot::note_dtb_isa(info.isa_zbb, info.isa_zbc, info.isa_zknh, info.isa_v);

            // Validate timer_freq vs hardcoded constant — if they disagree, every
            // time-based calculation (WCET, sleeps, timeouts) is wrong. Warn loudly.
            {
                let kernel_timer_hz = azos_drv_base::platform::hw::TIMER_FREQ;
                if info.timer_freq != 0 && info.timer_freq != kernel_timer_hz {
                    azos_drv_sys::kwarn!("[DTB] WARNING: timer_freq mismatch — DTB={}Hz kernel={}Hz, \
                        timing calculations will drift", info.timer_freq, kernel_timer_hz);
                }
            }

            // Cap DTB-reported CPUs by compile-time crate::MAX_CPUS (stack slots reserved).
            let cpus = if info.num_cpus > 0 {
                core::cmp::min(crate::MAX_CPUS, info.num_cpus)
            } else {
                crate::MAX_CPUS
            };
            if info.mem_base != 0 && info.mem_size != 0 {
                (info.mem_base, info.mem_size, true, cpus)
            } else {
                (azos_drv_base::platform::hw::RAM_BASE, crate::FALLBACK_MEM_SIZE, false, cpus)
            }
        } else {
            azos_drv_sys::kerr!("[DTB] Parse failed (invalid or unsupported FDT)");
            (azos_drv_base::platform::hw::RAM_BASE, crate::FALLBACK_MEM_SIZE, false, crate::MAX_CPUS)
        }
    } else {
        (azos_drv_base::platform::hw::RAM_BASE, crate::FALLBACK_MEM_SIZE, false, crate::MAX_CPUS)
    };
    // The PCI host bridge's ECAM and `ranges`, for `kernel_main`'s PCI
    // block. Read now: nothing reserves the DTB's pages from the page
    // allocator on this ISA, so the blob is not guaranteed to survive
    // `pmm::init` below.
    let pci_host = if dtb_ptr != 0 {
        unsafe { azos_dtb::dtb_pci_host(dtb_ptr as *const u8) }
    } else {
        None
    };
    // Trigger types for ring-3 lines (wave 9 IRQ4), read now for the same
    // reason. Only the APLIC takes a trigger (`sourcecfg`); a PLIC has no
    // trigger configuration and its binding (`#interrupt-cells = 1`) carries
    // none, so on plain `virt` there is nothing to read.
    if azos_drv_irqchip::irqchip::is_aia() && dtb_ptr != 0 {
        match unsafe {
            azos_dtb::dtb_irq_triggers(dtb_ptr as *const u8, azos_dtb::IrqController::AplicS)
        } {
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
    // Selects "absent" when nothing above did (no DTB, or one that did not
    // parse); otherwise returns the choice already made. Same "finalize the
    // decision" role as the timer_select(false) call just above.
    let zicboz_on = azos_arch::cbo::zicboz_select(false, 0);
    kprintln!("[MM] Zicboz cbo.zero fast path: {}",
        if zicboz_on { "enabled" } else { "scalar fallback" });
    kprintln!("[BOOT] Online CPUs: {} (max compile-time: {})", num_cpus, crate::MAX_CPUS);
    kprintln!();

    // ---- Phase 2: Memory Management ----

    let kernel_end = unsafe { &crate::_kernel_end as *const u8 as usize };
    let kernel_end_aligned = (kernel_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    kprintln!("[MM] Kernel end:  {:#x} (aligned: {:#x})", kernel_end, kernel_end_aligned);
    if mem_from_dtb {
        kprintln!("[MM] RAM detected via DTB: {:#x} - {:#x} ({} MiB)",
            mem_start, crate::mem_range_end(mem_start, mem_size), mem_size >> 20);
    } else {
        kprintln!("[MM] RAM fallback (no DTB): {:#x} - {:#x} ({} MiB)",
            mem_start, crate::mem_range_end(mem_start, mem_size), mem_size >> 20);
    }

    // MARKER, asserted by the gate. Canary: hand-build a DTB `/memory`
    // node with `mem_base` > this image's own `crate::_kernel_end` (impossible on
    // real hardware — the image is loaded INTO the range it reports) and
    // this line prints instead of `pmm::init` underflowing
    // `kernel_end - mem_start` into a board reset.
    if !azos_mm::pmm::init(mem_start, mem_size, kernel_end_aligned) {
        azos_drv_sys::kerr!("[MM] FAILED: refused memory map — mem_start {:#x} > kernel_end {:#x} \
                   (DTB claims RAM starts after the kernel's own image, which is impossible \
                   on real hardware)", mem_start, kernel_end_aligned);
        loop { azos_arch::cpu::wfi(); }
    }

    // The boot stack is the linker scripts' `.stack` section, below
    // crate::_kernel_end, so `pmm::init` has just reserved it with the image. It used
    // to sit at the top of the RAM window: reserved here by hand, and still
    // inside the kernel heap's range, which `kheap` takes as one block.
    {
        let stack_start = unsafe { &crate::_stack_start as *const u8 as usize };
        let stack_end   = unsafe { &crate::_stack_end   as *const u8 as usize };
        kprintln!("[MM] Boot stack reserved: {:#x} - {:#x} ({} KiB)",
            stack_start, stack_end, (stack_end - stack_start) >> 10);
    }

    // Panic record region (pstore): the top of RAM, out of the allocator
    // before anything allocates. QEMU puts the DTB 2 MiB-aligned below the
    // top of RAM, so the blob's range is passed to rule out an overlap.
    let dtb_range = if dtb_ptr != 0 {
        unsafe { azos_dtb::dtb_probe(dtb_ptr as *const u8) }
            .map(|(_, total)| (dtb_ptr, dtb_ptr + total as usize))
    } else {
        None
    };
    crate::pstore::reserve(mem_start, mem_size, kernel_end_aligned, dtb_range);

    kprintln!("[MM] PMM: {} total pages, {} free, {} used",
        azos_mm::pmm::total_pages(),
        azos_mm::pmm::free_pages(),
        azos_mm::pmm::used_pages());
    // A PMM with no free page after reserving the image cannot build a page
    // table; vmm::init is next. Name the reason instead of failing there.
    if azos_mm::pmm::free_pages() == 0 {
        azos_drv_sys::kerr!("[MM] FAILED: no free pages after reserving the kernel \
                   ({} pages managed, image ends at {:#x})",
            azos_mm::pmm::total_pages(), kernel_end_aligned);
        loop { azos_arch::cpu::wfi(); }
    }

    // VMM init BEFORE heap: vmm::init() allocates ~66 page-table pages from PMM
    // starting at kernel_end.  Initializing the heap first would corrupt those
    // pages (pmm::alloc_page zeroes each page it returns).  So: VMM first, then
    // heap starts at the first PMM page that VMM didn't touch.
    #[cfg(not(feature = "no-mmu"))]
    {
        kprintln!("[MM] Initializing VMM (Sv39 page tables)...");
        match azos_mm::vmm::init(mem_start, mem_size) {
            Ok(()) => kprintln!("[MM] VMM initialized (megapages), kernel PT created"),
            Err(e) => {
                azos_drv_sys::kerr!("[MM] VMM init FAILED: {:?}", e);
                loop { azos_arch::cpu::wfi(); }
            }
        }

        // Map platform-specific MMIO regions BEFORE enabling paging.
        // Each platform needs its device addresses identity-mapped.
        {
            use azos_drv_base::platform::hw;

            // UART (all platforms — 4 KiB)
            let _ = azos_mm::vmm::map_mmio_region(hw::UART_BASE, 0x1000);

            // PLIC (all platforms — up to 4 MiB is sufficient for enable/threshold/claim)
            let _ = azos_mm::vmm::map_mmio_region(hw::PLIC_BASE, 0x40_0000);

            // S-domain APLIC (32 KiB), only when the DTB selected AIA. The
            // IMSIC needs no mapping: the kernel reaches its own file
            // through CSRs; only devices write the file's physical page.
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
                // Found by actually booting with ramfb and getting a page
                // fault at 0x10100008 (the selector register) — this
                // mapping was simply forgotten when FW_CFG_BASE was added.
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
                // Display (--features hdmi only — crates/drivers/display). Added
                // preemptively after the SAME class of missing-mapping bug
                // was caught for the QEMU ramfb path above (real page
                // fault, not a guess) — this would fault identically on
                // real VF2 hardware without it.
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

            kprintln!("[MM] Platform MMIO mapped ({})", hw::PLATFORM_NAME);
        }

        azos_mm::vmm::enable_paging();
        kprintln!("[MM] Sv39 paging ENABLED");

        // W^X enforcement: remap kernel sections with correct permissions.
        // Must split megapages that cover the kernel image into 4K pages
        // first, because different sections need different permissions.
        unsafe {
            let text_start = &crate::_text_start as *const u8 as usize;
            let text_end   = &crate::_text_end as *const u8 as usize;
            let ro_start   = &crate::_rodata_start as *const u8 as usize;
            let ro_end     = &crate::_rodata_end as *const u8 as usize;
            let data_start = &crate::_data_start as *const u8 as usize;

            // Split megapages covering the kernel into 4K pages.
            let unsplit = azos_mm::vmm::split_mega_range(text_start, kernel_end_aligned);
            if unsplit != 0 {
                azos_drv_sys::kwarn!("[MM] W^X WARN: {} megapage(s) unsplit (out of memory)", unsplit);
            }

            // Now remap with per-section permissions.
            azos_mm::vmm::enforce_wx(
                text_start, text_end,
                ro_start, ro_end,
                data_start, kernel_end_aligned,
            );

            // And read the page table back. This line used to be printed
            // unconditionally right after the call, which made it an
            // announcement rather than a result: `enforce_wx` returns
            // nothing, `remap_range` skips anything that is not a valid 4 KiB
            // leaf, and the split above can fail silently. Now the numbers
            // come from the PTEs themselves.
            let rep = azos_mm::vmm::verify_wx(
                text_start, text_end,
                ro_start, ro_end,
                data_start, kernel_end_aligned,
            );
            if rep.is_clean() {
                // MARKER, asserted by the gate's `mm: W^X verified` scenario.
                // Deliberately free of regex metacharacters: `qemu_run` greps
                // it with a plain BRE, and a marker containing `W^X` does NOT
                // match there — the caret is taken as an anchor and the
                // scenario passes on a log it never found. Checked against a
                // real boot log rather than assumed.
                kprintln!(
                    "[MM] W^X ok: {} pages checked, RX/RO/RW as planned",
                    rep.checked,
                );
            } else {
                // Loud and specific. A kernel whose text is writable is a
                // finding, not a warning, and the counts say which of the
                // four ways it failed.
                azos_drv_sys::kerr!(
                    "[MM] W^X FAILED: {} pages checked, {} W+X, {} wrong-flags, \
                     {} unmapped, {} unsplit-mega, first bad {:#x}",
                    rep.checked, rep.write_exec, rep.wrong_flags,
                    rep.unmapped, rep.unsplit_megapage, rep.first_bad,
                );
            }

            // The other half of W^X: everything that is NOT the kernel image.
            //
            // `vmm::init` maps all of RAM `KERNEL_RWX` because it runs before
            // `enable_paging()` and the kernel executes out of that memory —
            // mapping `.text` without X there faults on the first instruction
            // fetch after paging comes on, with no output to diagnose it from.
            // So the X comes off here instead, with paging already live.
            //
            // Owner decision, 2026-09-08. Before it, ~121 MiB of a 128 MiB
            // board were writable AND executable in the kernel's own table:
            // the heap, every frame `pmm` hands out, every task stack.
            let mem_end = crate::mem_range_end(mem_start, mem_size);
            let stripped = azos_mm::vmm::strip_exec_outside_image(
                mem_start, mem_end, text_start, kernel_end_aligned,
            );
            // Read back rather than trust the sweep's own count: they are two
            // passes over the same walker, and a clean result is the two
            // agreeing that nothing executable is left.
            let left = azos_mm::vmm::verify_no_exec_outside_image(
                mem_start, mem_end, text_start, kernel_end_aligned,
            );
            if left.is_empty() {
                // MARKER, asserted by the gate's `mm: W^X verified` scenario.
                kprintln!(
                    "[MM] NX outside the image: {} MiB stripped, none left executable",
                    stripped.bytes() >> 20,
                );
            } else {
                azos_drv_sys::kerr!(
                    "[MM] NX FAILED: {} MiB still executable outside the image \
                     ({} megapages, {} pages, first {:#x})",
                    left.bytes() >> 20, left.megapages, left.pages, left.first,
                );
            }
        }

        // Null pointer guard: unmap page 0 so null derefs fault immediately.
        azos_mm::vmm::null_guard();
        kprintln!("[MM] Null pointer guard active (page 0 unmapped)");

        // Guard pages: unmap bottom 4 KiB of each task stack so overflow
        // triggers an immediate page fault instead of silent corruption.
        azos_sched::setup_stack_guard_pages();
        kprintln!("[MM] Stack guard pages active");

        // ── Guard-page fault probes (opt-in only; never in a normal boot) ──
        //
        // The two "active" lines above prove the PTE is gone. They do NOT
        // prove a real access traps there rather than reading stale data
        // through a TLB entry the unmap forgot to flush. These two features
        // each touch ONE guard and never return: the boot is expected to die
        // in the SAME `[PAGE FAULT]`/`[FATAL] Kernel page fault` path an
        // accidental kernel-mode overflow or null deref would hit — a
        // scripted trigger for the policy already there, not new policy.
        //
        // **This is the riscv64 half of a pair that was aarch64-only until
        // 2026-09-25.** The features and the probe shape are aarch64's
        // (`entry/aarch64/boot_hooks.rs`, same two `#[cfg]`s, same messages)
        // — deliberately identical so one pair of gate rows per ISA reads the
        // same markers. RISC-V is the ISA this project MEASURES on, and its
        // kernel fault path had no row at all: `tools/ci_check.sh`'s
        // `riscv64 guard: ...` rows are that gap closed.
        //
        // riscv64's fault handler prints the faulting address on the
        // `[PAGE FAULT] CPU n — <cause> at <stval>` line (aarch64 puts it on
        // its FATAL line), and for a null-guard hit it adds a `null guard:`
        // note. The rows read the address back off that line and require it
        // to equal the one printed here.
        #[cfg(feature = "guard-fault-probe-stack")]
        {
            let addr = azos_sched::stack_guard_addr(0);
            kprintln!("[MM] GUARD PROBE: writing to stack guard at {:#x} (must fault)", addr);
            unsafe { core::ptr::write_volatile(addr as *mut u8, 0xAA) };
            azos_drv_sys::kerr!("[MM] GUARD PROBE FAILED: write to {:#x} did not fault", addr);
        }
        #[cfg(feature = "guard-fault-probe-null")]
        {
            kprintln!("[MM] GUARD PROBE: writing to null guard at {:#x} (must fault)", 0usize);
            unsafe { core::ptr::write_volatile(0usize as *mut u8, 0xAA) };
            azos_drv_sys::kerr!("[MM] GUARD PROBE FAILED: write to {:#x} did not fault", 0usize);
        }
    }
    #[cfg(feature = "no-mmu")]
    kprintln!("[MM] No MMU (flat memory mode)");

    // Now safe to initialize the heap: PMM page-table pages are already allocated,
    // so the heap starts at the first *remaining* free PMM page.
    // Reserve FIRST, then init — eliminates any window where alloc_page() could
    // hand out pages that belong to the heap.
    let heap_start = azos_mm::pmm::next_free_addr();
    kprintln!("[MM] Heap: {:#x}, {} KiB", heap_start, crate::HEAP_SIZE / 1024);
    // `kheap` takes the range as one block, so every page of it must be free
    // RAM: a page already in use gets two writers (the boot stack was one),
    // and a page past the end of RAM does not exist.
    if !azos_mm::pmm::range_is_free(heap_start, crate::HEAP_SIZE) {
        azos_drv_sys::kerr!("[MM] Heap FAILED: [{:#x}, {:#x}) is not all free RAM",
            heap_start, heap_start + crate::HEAP_SIZE);
        loop { azos_arch::cpu::wfi(); }
    }
    azos_mm::pmm::reserve_range(heap_start, crate::HEAP_SIZE);
    unsafe { azos_mm::kheap::init(heap_start, crate::HEAP_SIZE) };
    kprintln!("[MM] Heap initialized");

    {
        let mut v = alloc::vec![1u32, 2, 3, 4, 5];
        v.push(6);
        kprintln!("[MM] Heap test: Vec = {:?}", v);
    }

    // RFC-0045 Tier 0 item 3 canary: poison a page, free it, force a
    // first-fit reallocation of the exact same physical page, and confirm
    // the reallocated page is genuinely all zero. Mirrors
    // `tests/host/mm-tests`' `a_reallocated_page_is_zeroed_not_the_old_content`
    // exactly, but that test runs the host's scalar `write_bytes` stand-in
    // (`tests/host/mm-tests/shims/arch` has no CPU-feature probe); this runs
    // under real QEMU, right after `zicboz_select` decided whether
    // `alloc_page` is using `cbo.zero` or the scalar fallback — so it is
    // the one place either path's actual zero-fill *content* gets verified,
    // not just that the boot log claims a mode was selected. A stride or
    // block-size bug in `cbo.zero`'s loop (crates/core/arch-riscv64/src/cbo.rs)
    // would leave part of the reallocated page still `0xAA` and this fails
    // (verified by deliberately breaking the stride and confirming this
    // line reads FAIL, then reverting — see the RFC-0045 implementation
    // notes for the exact mutation).
    //
    // Placed here — after `kheap::init`, not right after `pmm::init` — on
    // purpose: `vmm::init`'s own page-table allocations rely on first-fit
    // placing them immediately after `kernel_end` (nothing having touched
    // the allocator yet), and any alloc/free cycle run *before* that moves
    // `PmmInner::next_scan_word` forward, making `vmm::init`'s page tables
    // land with a free gap ahead of them instead of contiguous with the
    // kernel image. `kheap::init`'s own `range_is_free` check demands
    // exactly that contiguity for its fixed-size region, so running this
    // diagnostic earlier reliably broke boot with "Heap FAILED: ... is not
    // all free RAM" — a real ordering hazard this task found in the
    // existing allocator, not a Zicboz-specific bug, and worth documenting
    // here since it decided where this block could safely go. By this
    // point the heap already exists and reserved its own range, so nothing
    // downstream depends on `alloc_page`'s next-fit position anymore.
    #[cfg(feature = "qemu")]
    {
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
        // `tools/ci_check.sh` already matches that token, so a broken
        // zero-fill turns EVERY QEMU scenario red wherever it boots, not
        // just a dedicated row — the same free-failure-half trick
        // "[MM] W^X FAILED:" and "[MM] NX FAILED:" already rely on. The
        // good path is a distinct marker a scenario can grep for.
        if ok {
            kprintln!("[MM] Zicboz zero-fill self-check: PASS");
        } else {
            azos_drv_sys::kerr!("[MM] Zicboz zero-fill self-check FAILED: reallocated page \
                       was not all zero");
        }

        // RFC-0045 §10 measurement discipline: instruction count, not
        // wall-clock. Under `-icount shift=0,sleep=off` `rdcycle` is a
        // deterministic proxy for retired instructions (QEMU's own
        // documented behavior for `-icount`; without it `instret`/`cycle`
        // track the host clock instead — see RFC-0045 §1's standing rule
        // note on why that measurement was a dead end elsewhere in this
        // RFC). Free a batch of pages and re-allocate them — each
        // reallocation runs exactly the zero-fill path `zicboz_select`
        // chose at boot — and print the cycle delta so it can be compared,
        // build-to-build, against `-cpu rv64,zicboz=off`. The batch is
        // freed again immediately after measuring.
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
    kprintln!();

    // F04: PMP policy audit log.
    // The kernel runs in S-mode and cannot write PMP CSRs directly (M-mode
    // only). Every remaining boot path runs under OpenSBI, which configures
    // a permissive PMP; W^X is enforced by VMM page tables. (B2-02: the
    // no-OpenSBI M-mode boot stub that once called pmp_early_init() here was
    // deleted — its ELF entry was never wired to `_start_mmode`.) Log the
    // intended stricter policy for operator audit either way.
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

    // M01: vDSO — allocate the shared timing page that user-space reads
    // directly. Shared with aarch64's kernel_main — see `crate::install_vdso`'s
    // own doc. `rdtime` from U-mode is enabled (scounteren.TM, below), so
    // libsys may read the counter instead of trapping for SYS_UPTIME
    // (RFC-0041 §A); `vdso-force-syscall` keeps the trap, for measuring it.
    crate::install_vdso(azos_drv_sys::timebase::TIMER_FREQ);

    // AQ8: Enable kernel tracing (ring buffer of last 512 events).
    azos_ipc::trace_start();
    kprintln!("[TRACE] Kernel tracing enabled ({} event buffer)", azos_ipc::TRACE_BUF_SIZE);
    kprintln!();

    // ---- Phase 3: Interrupt controllers + enable interrupts ----
    // (crate::trap_init was already done in Phase 1b before any potentially faulting code.)

    {
        // `irqchip` dispatches to `plic::init` on plain `virt`, or to this
        // hart's IMSIC file plus the APLIC domain (MSI mode) on AIA.
        if azos_drv_irqchip::irqchip::is_aia() {
            kprintln!("[IRQ] Initializing AIA (APLIC MSI mode + IMSIC)...");
        } else {
            kprintln!("[IRQ] Initializing PLIC...");
        }
        azos_drv_irqchip::irqchip::init(hart_id as u32);
        azos_drv_irqchip::irqchip::init_aia_domain();
    }
    // Enable EXTERNAL + SOFTWARE interrupts now (PLIC, IPI). Timer (STIE) is
    // deferred until just before scheduler::start() — otherwise the timer ISR
    // preempts kernel_main with already-created RT tasks and the boot CPU
    // never reaches wake_harts(), starving every secondary CPU forever.
    let sie = csr::read_sie();
    csr::write_sie(sie | csr::SIE_SEIE | csr::SIE_SSIE);
    azos_arch::ARCH.enable_all();
    {
        // Enable UART RX interrupt (IRQ 10) — characters go to ring buffer.
        // On AIA the APLIC source is first routed to this hart, identity 10.
        if let Some(cfg) = azos_drv_irqchip::irqchip::wire_aia_source(
            azos_drv_sys::uart::UART_IRQ, hart_id as u32)
        {
            kprintln!("[IRQ] APLIC source {} -> hart {} sourcecfg={:#x}",
                azos_drv_sys::uart::UART_IRQ, hart_id, cfg);
        }
        azos_drv_irqchip::irqchip::enable_irq(hart_id as u32, azos_drv_sys::uart::UART_IRQ);
        azos_drv_sys::uart::enable_irq();
        // RFC-0055 S1: the PLIC arm (`trap::interrupt`) wakes a reader parked
        // on console input, as aarch64's PL011 arm does.
        azos_drv_sys::uart::set_rx_wake_wired();
        kprintln!("[IRQ] UART IRQ enabled (ring buffer RX)");
        // The same line now feeds the UART from the console's TX ring.
        azos_drv_sys::uart::enable_tx_irq();
    }
    // A line whose last ring-3 binding goes at task exit is masked and handed
    // back (wave 9 IRQ4; `irq_bind::irq_unbind_all`).
    azos_ipc::irq_bind::set_line_release_hook(azos_drv_irqchip::user_irq::release);
    // The boot hart: the kernel's own lines are routed here, and it is the
    // first hart a ring-3 line may be routed to; each secondary joins in
    // `smp_secondary_start` (`user_irq::hart_ready`).
    azos_drv_irqchip::user_irq::set_boot_hart(hart_id as u32);
    kprintln!("[IRQ] Traps + interrupts active");
    kprintln!();


    EarlyBoot { num_cpus, heap_start, kernel_end_aligned, pci_host }
}

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

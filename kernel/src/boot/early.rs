// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The generic early boot: `boot::early_main`, the first Rust on the boot CPU
//! after `kernel_main` is entered, on every ISA.
//!
//! It owns the steps every ISA runs, their order and their log lines:
//! console, firmware table, CPU discovery, page allocator, panic-record
//! region, kernel page tables, W^X/NX, null and stack guards, heap. Where the
//! ISAs differ it calls the [`ArchEntry`] hooks of `crate::ARCH_ENTRY`
//! (kernel/src/entry/<isa>/arch_entry.rs over `boot_hooks.rs`), in the order
//! the trait declares them. The hooks are `#[inline(always)]` on a
//! zero-sized type: no `dyn`, no table, the call is the hook body.
//!
//! Linux splits the same way: `start_kernel` (generic) and `setup_arch`
//! plus its `*_init` callbacks (per ISA). `tools/boot_seq_lint.py` keeps the
//! common steps here, in one order for every ISA.

use azos_arch::{ArchEntry, Cpu, PAGE_SIZE};
use azos_drv_sys::kprintln;

use crate::{EarlyBoot, ARCH_ENTRY};

/// Stop the boot CPU for good after a FAILED line: nothing past this point
/// can run without what just failed.
fn halt() -> ! {
    loop {
        azos_arch::ARCH.wfi();
    }
}

/// Console, trap vector, firmware table, memory map, page tables (W^X/NX,
/// guards), heap, then the ISA's interrupt controller, console interrupt,
/// timer and self-tests. Returns what `kernel_main` needs past this point.
pub(crate) fn early_main(hart_id: usize, fw_table: usize) -> EarlyBoot {
    let a = &ARCH_ENTRY;
    a.pre_console();

    // Which device is the console, chosen here rather than hardcoded at every
    // call site. `sys_write` to fd 1/2 goes through `uart::console_write`,
    // which dispatches on this registration; the kernel's own `kprintln!` and
    // `kernel/src/panic.rs` deliberately stay on the direct path: a panic
    // handler that depends on a registered implementation prints nothing
    // exactly when it matters. Runs on the boot CPU before
    // `enable_smp_lock()`, which is the contract `console_register` states.
    azos_drv_sys::uart::init();
    #[cfg(not(feature = "console-route-canary"))]
    azos_drv_sys::uart::console_register(&azos_drv_sys::uart::CONSOLE);
    // Gate-only: a console whose effect is VISIBLE, so the row can tell a live
    // registration from the silent fallback. See `uart::CanaryConsole`.
    #[cfg(feature = "console-route-canary")]
    azos_drv_sys::uart::console_register(&azos_drv_sys::uart::CANARY_CONSOLE);

    a.trap_init();
    a.boot_banner(hart_id, fw_table);

    // ---- Firmware table: interrupt controller, timer and CPU extensions are
    // chosen from it BEFORE `pmm::init` (the page allocator's zero-fill
    // consults the CPU-extension choice on its very first call).
    // The device tree, when the firmware handed one (`dtb_parse` checks the
    // FDT magic first, so a non-FDT table such as x86_64's PVH start_info
    // parses to `None`).
    let dt = if fw_table != 0 {
        unsafe { azos_dtb::dtb_parse(fw_table as *const u8) }
    } else {
        None
    };
    // Kconfig CANARY_RUNTIME: `canary=` on the command line, before the
    // first `canary!` site (the stack guards below).
    crate::canary_rt::arm_from_cmdline(|out| a.kernel_cmdline(fw_table, out));
    // Kconfig CHAOS / DECISION_RECORDS: `chaos=` held until boot init is
    // done, and both subsystems' runtime canaries.
    crate::boot::chaos::arm_from_cmdline(|out| a.kernel_cmdline(fw_table, out));
    // The boot protocol, from the table itself: an FDT (riscv64, aarch64) or
    // not (x86_64's PVH start_info). Only an FDT has a `totalsize` to keep
    // out of pstore's way below.
    let fw_is_fdt = dt.is_some();
    let fw = a.firmware_table(hart_id, fw_table, dt);
    a.irqchip_probe(&fw);
    a.timer_probe(&fw);
    a.cpu_features(&fw);
    let mem = a.firmware_memory(&fw);
    // The firmware's CPU count, cut to the Kconfig ceiling `NR_CPUS` (with a
    // warning) and never 0: this CPU is running, whatever the table says.
    let num_cpus = crate::boot::discover_cpus(azos_percpu::FirmwareCpus {
        count: mem.cpu_count,
        boot_cpu: mem.boot_cpu,
        source: mem.cpu_source,
    });
    let (mem_start, mem_size) = (mem.mem_start, mem.mem_size);
    // The PCI host bridge's ECAM and `ranges`, for `kernel_main`'s PCI block.
    // Read now: on riscv64 nothing reserves the blob's pages from the page
    // allocator, so it is not guaranteed to survive `pmm::init` below, and on
    // aarch64 the low half stops mapping it once it holds devices only.
    let pci_host = if fw_table != 0 {
        unsafe { azos_dtb::dtb_pci_host(fw_table as *const u8) }
    } else {
        None
    };
    // Trigger types (edge/level) for ring-3 lines (wave 9 IRQ4), read now for
    // the same reason, on every ISA.
    if fw_table != 0 {
        if let Some(ctl) = a.irq_trigger_controller() {
            a.irq_triggers(unsafe { azos_dtb::dtb_irq_triggers(fw_table as *const u8, ctl) });
        }
    }
    a.firmware_done(fw_table, num_cpus);

    // ---- Page allocator ----
    let kernel_end = unsafe { &crate::_kernel_end as *const u8 as usize };
    let kernel_end_aligned = (kernel_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    // `pmm` manages PHYSICAL frames (the table's `/memory` range is physical);
    // `kernel_end_aligned` is the image's own VA, which the W^X sweep below
    // takes. The two are equal where the kernel runs identity-mapped
    // (riscv64) and differ by `KERNEL_VA_OFFSET` where it runs in the upper
    // half (aarch64).
    let kernel_end_pa = azos_mm::addr::virt_to_phys(kernel_end_aligned);
    kprintln!("[MM] Kernel end:  {:#x} (aligned: {:#x})", kernel_end, kernel_end_aligned);
    if mem.from_firmware {
        kprintln!("[MM] RAM detected via {}: {:#x} - {:#x} ({} MiB)",
            if fw_is_fdt { "DTB" } else { "the firmware memory map" }, mem_start, crate::mem_range_end(mem_start, mem_size), mem_size >> 20);
    } else {
        kprintln!("[MM] RAM fallback (no DTB): {:#x} - {:#x} ({} MiB)",
            mem_start, crate::mem_range_end(mem_start, mem_size), mem_size >> 20);
    }

    // MARKER, asserted by the gate. Canary: hand-build a DTB `/memory` node
    // with `mem_base` > this image's own `_kernel_end` (impossible on real
    // hardware: the image is loaded INTO the range it reports) and this line
    // prints instead of `pmm::init` underflowing `kernel_end - mem_start`
    // into a board reset.
    if !azos_mm::pmm::init(mem_start, mem_size, kernel_end_pa) {
        azos_drv_sys::kerr!("[MM] FAILED: refused memory map — mem_start {:#x} > kernel_end {:#x} \
                   (DTB claims RAM starts after the kernel's own image, which is impossible \
                   on real hardware)", mem_start, kernel_end_pa);
        halt();
    }

    // The boot stack is the linker scripts' `.stack` section, below
    // `_kernel_end`, so `pmm::init` has just reserved it with the image.
    {
        let stack_start = unsafe { &crate::_stack_start as *const u8 as usize };
        let stack_end = unsafe { &crate::_stack_end as *const u8 as usize };
        kprintln!("[MM] Boot stack reserved: {:#x} - {:#x} ({} KiB)",
            stack_start, stack_end, (stack_end - stack_start) >> 10);
    }

    a.reserve_firmware_table(fw_table);

    // Panic record region (pstore): the top of RAM, out of the allocator
    // before anything allocates. QEMU may put the firmware table near the top
    // of RAM, so its range is passed to rule out an overlap.
    let fw_range = if fw_is_fdt {
        unsafe { azos_dtb::dtb_probe(fw_table as *const u8) }
            .map(|(_, total)| (fw_table, fw_table + total as usize))
    } else {
        None
    };
    crate::pstore::reserve(mem_start, mem_size, kernel_end_pa, fw_range);

    kprintln!("[MM] PMM: {} total pages, {} free, {} used",
        azos_mm::pmm::total_pages(),
        azos_mm::pmm::free_pages(),
        azos_mm::pmm::used_pages());
    // MARKER, asserted by the gate (PMM frame count > 0). A PMM with no free
    // page after reserving the image cannot build a page table; vmm::init is
    // next. Name the reason instead of failing there.
    if azos_mm::pmm::free_pages() == 0 {
        azos_drv_sys::kerr!("[MM] FAILED: no free pages after reserving the kernel \
                   ({} pages managed, image ends at {:#x})",
            azos_mm::pmm::total_pages(), kernel_end_aligned);
        halt();
    }

    // ---- Kernel page tables. VMM before the heap: `vmm::init` takes its
    // page-table pages from the PMM right after the image, and the heap starts
    // at the first PMM page it did not take.
    #[cfg(not(feature = "no-mmu"))]
    {
        kprintln!("[MM] Initializing VMM ({})...", <crate::arch_entry::Entry as ArchEntry>::PAGE_TABLES);
        match azos_mm::vmm::init(mem_start, mem_size) {
            Ok(()) => kprintln!("[MM] VMM initialized (megapages), kernel PT created"),
            Err(e) => {
                azos_drv_sys::kerr!("[MM] VMM init FAILED: {:?}", e);
                halt();
            }
        }
        // The image at its link address, where that is not inside the RAM
        // map `init` built (x86_64: image in the top 2 GiB, RAM in the
        // direct map). Constant-folded away on riscv64 and aarch64.
        if azos_mm::addr::KERNEL_IMAGE_OFFSET != azos_mm::addr::KERNEL_PHYS_TO_VIRT_OFFSET {
            let text_pa = azos_mm::addr::virt_to_phys(unsafe { &crate::_text_start as *const u8 as usize });
            match azos_mm::vmm::map_kernel_image(text_pa, kernel_end_pa) {
                Ok(n) => kprintln!("[MM] Kernel image mapped at {:#x} ({} KiB), RAM in the direct map at {:#x}",
                                   azos_mm::addr::KERNEL_IMAGE_OFFSET + text_pa, n >> 10,
                                   azos_mm::addr::phys_to_virt(0)),
                Err(e) => {
                    azos_drv_sys::kerr!("[MM] FAILED: kernel image map: {:?}", e);
                    halt();
                }
            }
        }

        // Device windows, mapped before the table goes live: the console
        // (where it is memory-mapped), then the ISA's and board's own. Each is
        // recorded, so a device-only user half (aarch64 TTBR0) gets the same
        // windows.
        {
            use azos_drv_base::platform::hw;
            if <crate::arch_entry::Entry as ArchEntry>::CONSOLE_MMIO {
                let _ = azos_mm::vmm::map_mmio_region(hw::UART_BASE, 0x1000);
            }
            for (base, bytes) in a.kernel_mmio_windows() {
                let _ = azos_mm::vmm::map_mmio_region(base, bytes);
            }
            kprintln!("[MM] Platform MMIO mapped ({})", hw::PLATFORM_NAME);
        }

        azos_mm::vmm::enable_paging();
        a.mmu_enabled();

        // ASID space: Kconfig ASID_BITS narrowed to what this MMU implements.
        {
            use azos_arch::Mmu;
            let hw = azos_arch::ARCH.asid_bits();
            let max = azos_sched::set_hw_asid_bits(hw);
            kprintln!("[MM] ASID: hw {} bits, ASID_BITS {}, user ASIDs 1..={} (full TLB flush on every switch)",
                      hw, azos_limits::ASID_BITS, max);
        }

        // W^X: remap the image with per-section permissions. The megapages
        // covering it are split into 4 KiB pages first, because different
        // sections need different permissions.
        unsafe {
            let text_start = &crate::_text_start as *const u8 as usize;
            let text_end = &crate::_text_end as *const u8 as usize;
            let ro_start = &crate::_rodata_start as *const u8 as usize;
            let ro_end = &crate::_rodata_end as *const u8 as usize;
            let data_start = &crate::_data_start as *const u8 as usize;

            let unsplit = azos_mm::vmm::split_mega_range(text_start, kernel_end_aligned);
            if unsplit != 0 {
                azos_drv_sys::kwarn!("[MM] W^X WARN: {} megapage(s) unsplit (out of memory)", unsplit);
            }

            // Gate canary `wx-skip-canary`: the image keeps its boot-time leaves.
            #[cfg(not(feature = "wx-skip-canary"))]
            azos_mm::vmm::enforce_wx(
                text_start, text_end,
                ro_start, ro_end,
                data_start, kernel_end_aligned,
            );

            // Read the page table back rather than trust the remap:
            // `enforce_wx` returns nothing, `remap_range` skips anything that
            // is not a valid 4 KiB leaf, and the split above can fail.
            let rep = azos_mm::vmm::verify_wx(
                text_start, text_end,
                ro_start, ro_end,
                data_start, kernel_end_aligned,
            );
            if rep.is_clean() {
                // MARKER, asserted by the gate's `mm: W^X verified` scenario.
                // Free of regex metacharacters on purpose: `qemu_run` greps it
                // with a plain BRE, where `W^X` would not match.
                kprintln!(
                    "[MM] W^X ok: {} pages checked, RX/RO/RW as planned",
                    rep.checked,
                );
            } else {
                // A kernel whose text is writable is a finding, not a warning;
                // the counts say which of the four ways it failed.
                azos_drv_sys::kerr!(
                    "[MM] W^X FAILED: {} pages checked, {} W+X, {} wrong-flags, \
                     {} unmapped, {} unsplit-mega, first bad {:#x}",
                    rep.checked, rep.write_exec, rep.wrong_flags,
                    rep.unmapped, rep.unsplit_megapage, rep.first_bad,
                );
            }

            // The other half of W^X: everything that is NOT the image.
            // `vmm::init` maps all of RAM executable because the kernel runs
            // out of it before `enable_paging`; the X comes off here, with
            // paging live (owner decision, 2026-09-08). The sweep walks the
            // kernel's own table, so its range is in kernel VAs: on aarch64 a
            // low VA and its upper-half alias resolve to the SAME entries, and
            // a sweep started at a physical address would strip X from the
            // kernel's own text.
            let mem_start_va = azos_mm::addr::phys_to_virt(mem_start);
            let mem_end_va = azos_mm::addr::phys_to_virt(crate::mem_range_end(mem_start, mem_size));
            let stripped = {
                // Gate canary `nx-skip-canary`: the sweep covers nothing.
                #[cfg(feature = "nx-skip-canary")]
                let mem_end_va = mem_start_va;
                azos_mm::vmm::strip_exec_outside_image(
                    mem_start_va, mem_end_va, text_start, kernel_end_aligned,
                )
            };
            // Read back rather than trust the sweep's own count.
            let left = azos_mm::vmm::verify_no_exec_outside_image(
                mem_start_va, mem_end_va, text_start, kernel_end_aligned,
            );
            // The `mm_wx_image` / `mm_nx_outside_image` ktests re-read these.
            #[cfg(feature = "ktest")]
            crate::ktest::note_image(crate::ktest::Image {
                text: (text_start, text_end), ro: (ro_start, ro_end),
                data: (data_start, kernel_end_aligned), mem: (mem_start_va, mem_end_va),
            });
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

            // Where the image is mapped twice (x86_64: its link address and
            // its frames in the direct map), the alias of its text and
            // read-only data is made read-only too: the NX sweep took X off
            // it (RAM outside the image's VAs) but left it writable, and a
            // writable alias of the text is the write W^X denies. The same
            // planner and readback, with an empty text range. Constant-folded
            // away where the image and RAM share one map (riscv64, aarch64).
            if azos_mm::addr::KERNEL_IMAGE_OFFSET != azos_mm::addr::KERNEL_PHYS_TO_VIRT_OFFSET {
                use azos_mm::addr::{phys_to_virt, virt_to_phys};
                let a0 = phys_to_virt(virt_to_phys(text_start)) & !(PAGE_SIZE - 1);
                let e0 = (phys_to_virt(virt_to_phys(ro_end)) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                let unsplit = azos_mm::vmm::split_mega_range(a0, e0);
                azos_mm::vmm::enforce_wx(a0, a0, a0, e0, e0, e0);
                let rep = azos_mm::vmm::verify_wx(a0, a0, a0, e0, e0, e0);
                if rep.is_clean() && unsplit == 0 {
                    kprintln!("[MM] Image alias in the RAM map: {} pages read-only, not executable", rep.checked);
                } else {
                    azos_drv_sys::kerr!(
                        "[MM] FAILED: image alias in the RAM map: {} checked, {} W+X, {} wrong-flags, \
                         {} unmapped, {} unsplit, first bad {:#x}",
                        rep.checked, rep.write_exec, rep.wrong_flags, rep.unmapped,
                        rep.unsplit_megapage + unsplit, rep.first_bad,
                    );
                }
            }
        }

        a.restrict_low_half();

        // Null pointer guard: page 0 unmapped, so a null dereference faults.
        azos_mm::vmm::null_guard();
        kprintln!("[MM] Null pointer guard active (page 0 unmapped)");

        // Guard pages: the bottom 4 KiB of every task's kernel stack
        // unmapped, so an overflow faults instead of corrupting silently.
        // Runtime gate canary `canary=stack-guard-skip`: no task stack gets
        // its guard.
        if !canary!("stack-guard-skip") {
            azos_sched::setup_stack_guard_pages();
        }
        kprintln!("[MM] Stack guard pages active");

        a.verify_guards();

        // ── Guard-page fault probes (opt-in only; never in a normal boot) ──
        //
        // The "active" lines prove the PTE is gone, not that an access traps
        // there rather than reading stale data through a TLB entry the unmap
        // forgot to flush. Each feature touches ONE guard and never returns:
        // the boot must die in the same kernel page-fault path an accidental
        // overflow or null dereference takes. The gate's `<isa> guard: ...`
        // rows read the address back off the fault line and require it to
        // equal the one printed here.
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

    // ---- Heap: reserve FIRST, then init, so no window exists where
    // `alloc_page()` could hand out a page the heap is about to claim.
    let heap_start = azos_mm::pmm::next_free_addr();
    kprintln!("[MM] Heap: {:#x}, {} KiB", heap_start, crate::HEAP_SIZE / 1024);
    // `kheap` takes the range as one block, so every page of it must be free
    // RAM: a page already in use gets two writers, and a page past the end of
    // RAM does not exist.
    if !azos_mm::pmm::range_is_free(heap_start, crate::HEAP_SIZE) {
        azos_drv_sys::kerr!("[MM] Heap FAILED: [{:#x}, {:#x}) is not all free RAM",
            heap_start, heap_start + crate::HEAP_SIZE);
        halt();
    }
    azos_mm::pmm::reserve_range(heap_start, crate::HEAP_SIZE);
    // `heap_start` is PHYSICAL; the allocator writes its own free list through
    // this pointer, so it gets the kernel's view of that memory.
    unsafe { azos_mm::kheap::init(azos_mm::addr::phys_to_virt(heap_start), crate::HEAP_SIZE) };
    kprintln!("[MM] Heap initialized");

    {
        // MARKER, asserted by the gate: a real heap allocation, not just an
        // announcement that `kheap::init` returned.
        let mut v = alloc::vec![1u32, 2, 3, 4, 5];
        v.push(6);
        kprintln!("[MM] Heap test: Vec = {:?}", v);
    }

    a.post_heap(heap_start, kernel_end_aligned);

    // M01: the vDSO timing page user space reads directly, at the timebase
    // the ISA reports. Before any task can exec.
    crate::install_vdso(a.timebase_hz());

    // ---- Interrupts: the controller, the console line, ring-3 lines, then
    // the timer. The boot CPU's own tick is armed where the ISA's
    // `timer_init` says (riscv64 defers it to `enter_scheduler`).
    a.irqchip_init(hart_id, fw_table);
    a.irq_enable_early();
    a.console_irq(hart_id, fw_table);
    // A line whose last ring-3 binding goes at task exit is masked and handed
    // back (wave 9 IRQ4; `irq_bind::irq_unbind_all`).
    azos_ipc::irq_bind::set_line_release_hook(a.line_release());
    a.irq_routing_init(hart_id);
    a.smp_probe(fw_table);
    a.timer_init();
    a.boot_selftests();

    EarlyBoot { num_cpus, heap_start, kernel_end_aligned, pci_host }
}

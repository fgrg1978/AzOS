// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 boot hooks: the ISA-specific steps of the generic early boot
//! (`boot::early_main`, kernel/src/boot/early.rs), which calls them through
//! this ISA's `ArchEntry` (`arch_entry.rs`), plus the late VirtIO mapping,
//! the PSCI `CPU_ON` secondary wake with its online readback and cross-core
//! SGI proof, and the hand-off to the scheduler.
//!
//! What is aarch64's own here: the entry-EL and SCTLR/FDT/FP proofs, the DTB
//! reservation, TTBR1 publication and the device-only TTBR0, the guard
//! readbacks and PAN probe, GICv3 + ITS, the PL011 interrupt, PSCI, the EL1
//! virtual timer and the boot self-tests that need interrupts (svc, ticks,
//! FP across an interrupt, IRQ stack, TTBR1 alias, granule, TCR). The common
//! steps (console, memory map, page tables, W^X/NX, guards, heap) are in
//! `early_main`; a common step kept here carries a `boot-seq:` reason
//! (`tools/boot_seq_lint.py`).

use core::sync::atomic::{AtomicU64, Ordering};
use azos_drv_sys::kprintln;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch::FirmwareMemory;
use azos_arch::{gic, timer as arch_timer, Cpu, Interrupts, ARCH};
use azos_drv_base::platform::hw;
use core::sync::atomic::Ordering as AOrdering;

/// `SCTLR_EL1` as read before the first lock (`pre_console`), printed by
/// `boot_banner` once `kprintln!` is safe.
static SCTLR_BEFORE_FIRST_LOCK: AtomicU64 = AtomicU64::new(0);

/// The scheduler tick on aarch64. Mirrors `clint::SCHED_HZ`'s boot default
/// (100 Hz): read by `timer_init` (the period) and `boot_selftests` (the
/// expected tick time).
const AARCH64_SCHED_HZ: u64 = 100;

/// The parsed device tree (`None`: no pointer, or one that did not parse).
pub struct Firmware {
    info: Option<azos_dtb::DtbInfo>,
}

/// `true` when boot.S dropped from EL2 to EL1. Written by boot.S before the
/// drop (or left 0 if none was needed); see that file's header comment.
fn entered_at_el2() -> bool {
    unsafe extern "C" {
        static boot_entry_el: u8;
    }
    unsafe { core::ptr::read_volatile(&raw const boot_entry_el) != 0 }
}

/// Read BEFORE `uart::init()`: the very first atomic `kernel_main` reaches
/// is inside it (`UartGuard`'s spinlock, a `compare_exchange`), so this is
/// the closest a Rust-level read can get to proving the constraint boot.S's
/// `aarch64_early_mmu_init` call exists to satisfy: the MMU is ON before
/// that first atomic runs. Printed by `boot_banner`.
#[inline(always)]
pub fn pre_console() {
    SCTLR_BEFORE_FIRST_LOCK.store(azos_arch::sysregs::read_sctlr_el1(), Ordering::Relaxed);
}

/// Nothing: boot.S sets `VBAR_EL1` before any Rust runs.
#[inline(always)]
pub fn trap_init() {}

/// The banner, the entry EL, then the proofs that need only the console:
/// MMU on before the first lock, the FDT handoff in x0, FP/SIMD at EL1.
#[inline(always)]
pub fn boot_banner(hart_id: usize, dtb_ptr: usize) {
    let entry_el_2 = entered_at_el2();
    let sctlr_before_first_lock = SCTLR_BEFORE_FIRST_LOCK.load(Ordering::Relaxed);

    kprintln!();
    kprintln!("========================================");
    kprintln!("  AzOS Rust kernel booted! (aarch64)");
    kprintln!("========================================");
    kprintln!();
    kprintln!("[BOOT] Hart ID:    {}", hart_id);
    kprintln!("[BOOT] DTB addr:   {:#x}", dtb_ptr);
    kprintln!("[BOOT] Entered at: EL{} ({})", if entry_el_2 { 2 } else { 1 },
        if entry_el_2 { "dropped to EL1 via _azos_drop_to_el1" } else { "QEMU started us at EL1 directly" });
    kprintln!();

    // MARKER, asserted by the gate: proves `aarch64_early_mmu_init` ran,
    // and ran BEFORE the spinlock `uart::init()` just took — the ordering
    // task 2 exists to guarantee, not merely the end state. Canary: drop
    // the `bl aarch64_early_mmu_init` from `boot.S` and this reads OFF —
    // QEMU tolerates the exclusive access to Device memory that follows
    // (real silicon is not obliged to), so this readback is the only
    // thing in the boot log that goes red.
    kprintln!("[MM] SCTLR_EL1.M before first spinlock: {} ({:#x})",
        if sctlr_before_first_lock & azos_arch::sysregs::SCTLR_EL1_M != 0 { "ON" } else { "OFF" },
        sctlr_before_first_lock);

    // ---- FDT handoff proof (task 1) ----
    //
    // `dtb_probe` reads only the header (magic + totalsize); `dtb_parse`
    // below does the full structure-block walk for mem_base/mem_size.
    // Kept separate so this marker asserts the x0 handoff itself,
    // independent of whether the fuller walk finds a `/memory` node.
    let dtb_probe = if dtb_ptr != 0 {
        unsafe { azos_dtb::dtb_probe(dtb_ptr as *const u8) }
    } else {
        None
    };
    match dtb_probe {
        // MARKER, asserted by the gate. Canary: boot the plain ELF
        // (skip the `llvm-objcopy -O binary` step) instead of the
        // `.img` — QEMU hands x0 == 0 for that load method (established
        // fact, this task's brief), so this line never prints and the
        // gate's grep for it fails.
        Some((magic, totalsize)) => kprintln!(
            "[BOOT] FDT at x0: magic={:#010x} totalsize={} bytes", magic, totalsize),
        None => kprintln!(
            "[BOOT] FDT at x0: none (x0={:#x}) — no Image-format DTB handoff, \
             falling back to platform defaults", dtb_ptr),
    }

    // FP/SIMD self-check. **Deliberately executes FP instructions**, so a
    // boot that lost EL1's FP/SIMD permission traps here (EC=0x07) instead
    // of passing. That permission — CPACR_EL1.FPEN, set in boot.S — was
    // missing on the EL1 crate::entry path until 2026-09-21, and this minimal
    // kernel_main emitted no FP of its own, so nothing noticed. The operands
    // go through `black_box` so the compiler cannot fold the result into a
    // constant and skip the instructions; the printed value pins that they
    // actually ran. The gate's `aarch64 kernel boots` rows require this line.
    //
    // The kernel is soft-float, so `1.5 * 1.5 + 0.25` written in Rust would
    // run in software and prove nothing about CPACR_EL1. `fp_self_check`
    // executes the real `fmul`/`fadd` in asm; EL1 still needs FPEN because
    // the lazy user-FP save/restore runs at EL1. Printing the result through
    // `f64::from_bits` keeps the gate's marker text unchanged.
    let fp = f64::from_bits(fp_self_check(1.5f64.to_bits(), 0.25f64.to_bits()));
    kprintln!("[BOOT] FP/SIMD at EL1: 1.5*1.5+0.25 = {}", fp);
}

/// Parse the DTB and print what it says.
#[inline(always)]
pub fn firmware_table(_hart_id: usize, dtb_ptr: usize) -> Firmware {
    if dtb_ptr == 0 {
        return Firmware { info: None };
    }
    // boot-seq: the firmware-table format is the ISA's (a DTB here and on
    // riscv64, PVH/ACPI on x86_64), and each prints its own lines.
    let info = unsafe { azos_dtb::dtb_parse(dtb_ptr as *const u8) };
    match &info {
        Some(info) if info.mem_base != 0 && info.mem_size != 0 => {
            kprintln!("[DTB] Parsed FDT — mem={:#x}+{:#x} ({} CPUs)",
                info.mem_base, info.mem_size, info.num_cpus);
        }
        Some(_) => kprintln!("[DTB] Parsed FDT but no usable /memory node — falling back"),
        None => azos_drv_sys::kerr!("[DTB] Parse failed (invalid or unsupported FDT)"),
    }
    Firmware { info }
}

/// Nothing to choose: QEMU `virt` with `gic-version=3` is the only interrupt
/// controller this ISA drives (`gic`), at fixed addresses.
#[inline(always)]
pub fn irqchip_probe(_fw: &Firmware) {}

/// Nothing to choose: the EL1 virtual timer; its frequency is read live from
/// `CNTFRQ_EL0` in `timer_init`.
#[inline(always)]
pub fn timer_probe(_fw: &Firmware) {}

/// Nothing taken from the DTB: aarch64 features come from the ID registers
/// (`azos_arch::features`), probed by the ISA crate.
#[inline(always)]
pub fn cpu_features(_fw: &Firmware) {}

/// RAM from the DTB's `/memory` node, or the platform fallback. The boot
/// core is logical CPU 0 on this ISA (boot.S: `TPIDR_EL1` = 0).
#[inline(always)]
pub fn firmware_memory(fw: &Firmware) -> FirmwareMemory {
    let (mem_start, mem_size, from_firmware) = match &fw.info {
        Some(i) if i.mem_base != 0 && i.mem_size != 0 => (i.mem_base, i.mem_size, true),
        _ => (hw::RAM_BASE, crate::FALLBACK_MEM_SIZE, false),
    };
    let (cpu_count, cpu_source) = match &fw.info {
        Some(i) => (i.num_cpus, "DTB"),
        None => (0, "none"),
    };
    FirmwareMemory { mem_start, mem_size, from_firmware, cpu_count, boot_cpu: 0, cpu_source }
}

/// Nothing: the blob is reserved (`reserve_firmware_table`) and read again
/// after the GIC is up.
#[inline(always)]
pub fn firmware_done(_dtb_ptr: usize, _num_cpus: usize) {}

/// The DTB blob itself, out of the page allocator: QEMU places the FDT
/// INSIDE the managed RAM window here, so the allocator must never hand out
/// a page still holding it (riscv64 reads its blob in full before
/// `pmm::init` instead).
#[inline(always)]
pub fn reserve_firmware_table(dtb_ptr: usize) {
    let dtb_probe = if dtb_ptr != 0 {
        unsafe { azos_dtb::dtb_probe(dtb_ptr as *const u8) }
    } else {
        None
    };
    if let Some((_, totalsize)) = dtb_probe {
        let dtb_start = dtb_ptr & !(PAGE_SIZE - 1);
        let dtb_end = (dtb_ptr + totalsize as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if azos_mm::pmm::range_is_free(dtb_start, dtb_end - dtb_start) {
            azos_mm::pmm::reserve_range(dtb_start, dtb_end - dtb_start);
            kprintln!("[MM] DTB reserved: {:#x} - {:#x} ({} bytes)",
                dtb_start, dtb_end, totalsize);
        } else {
            azos_drv_sys::kwarn!("[MM] DTB WARN: {:#x} - {:#x} not all free — not reserved \
                       (outside the managed range, or overlaps the kernel image)",
                dtb_start, dtb_end);
        }
    }
}

/// Nothing beyond the console before the table goes live: the GIC is mapped
/// in `irqchip_init` (after the heap) and VirtIO in `arch_map_late_mmio`.
#[inline(always)]
pub fn kernel_mmio_map() {}

/// The kernel table now in `TTBR1_EL1` (`vmm::enable_paging` calls
/// `ARCH.switch_kernel_pt`); the MMU itself has been on since boot.S's
/// `aarch64_early_mmu_init`, and TTBR0 is untouched until
/// `restrict_low_half`.
#[inline(always)]
pub fn mmu_enabled() {
    kprintln!("[MM] Kernel page tables active (TTBR1_EL1 switched)");

    // U01-1: publish the REAL kernel table's PA for every secondary's
    // TTBR1_EL1 attach (`crate::entry::aarch64::aarch64_secondary_ttbr1_attach`)
    // — safe to read `vmm::kernel_pagetable()` (it takes a `Mutex`) HERE
    // because this PE's own MMU has been on since `aarch64_early_mmu_init`
    // ran in `boot.S`, before `kernel_main` was even called. Before this
    // store, `SECONDARY_TTBR1_PA` reads `0` and that function falls back to
    // the early-boot alias — see `SECONDARY_TTBR1_PA`'s own doc for why a
    // secondary attaching that alias instead is exactly U01-1.
    crate::entry::aarch64::SECONDARY_TTBR1_PA.store(
        azos_mm::vmm::kernel_pagetable(), Ordering::Release);

    // U01-2: `SECONDARY_TTBR0_PA`/`AARCH64_KERNEL_TTBR0` are deliberately
    // NOT published here. At this point `TTBR0_EL1` on THIS hart is still
    // `azos_mm::vmm::kernel_pagetable()` — the SAME table just installed
    // above into `TTBR1_EL1` — because `install_device_only_ttbr0()` (a few
    // lines below, after W^X/NX) has not replaced it yet. Publishing that
    // value here is exactly the bug those two statics' doc comments record:
    // every secondary, and hart 0's own first idle dispatch, would keep the
    // whole kernel image (RAM included) reachable by physical address
    // through TTBR0 forever. The real publish is after the device-only
    // table is installed, below.
}

/// Before the null guard means anything on this ISA: the low half must stop
/// being the bootstrap identity map.
#[inline(always)]
pub fn restrict_low_half() {
    // Before the null guard means anything on this ISA: the low half must
    // stop being the bootstrap identity map. Until this runs, TTBR0 still
    // maps all RAM (so a kernel bug can reach any page by its physical
    // number) and covers VA 0 with a device block (so a null dereference
    // does not fault). After it, the low half holds device windows only —
    // and each task's own table gets those same windows when it is created.
    match azos_mm::vmm::install_device_only_ttbr0() {
        Ok(pages) => {
            kprintln!(
                "[MM] Low half is device-only: {} MMIO pages in TTBR0, RAM unreachable by PA", pages);
            // U01-1/U01-2: publish the device-only root NOW, not the full
            // kernel table published-then-abandoned above — this is the
            // value every secondary's own TTBR0_EL1 attaches
            // (`aarch64_secondary_mmu_init`) and the value context_switch.S
            // re-installs into TTBR0_EL1 on hart 0's first switch into an
            // idle kernel task. `install_device_only_ttbr0()` returns a page
            // count, not the root's PA, and it already ran `ARCH.switch_pt`
            // (a `TTBR0_EL1` write) on THIS hart as its last step — so the
            // PA is recovered with a plain readback rather than a second
            // `crates/core/mm` call (out of this migration's ownership; see
            // `sysregs::read_ttbr0_el1`'s own doc).
            let device_only_pa = (azos_arch::sysregs::read_ttbr0_el1() & !0xFFF) as usize;
            crate::entry::aarch64::SECONDARY_TTBR0_PA.store(device_only_pa, Ordering::Release);
            crate::entry::aarch64::AARCH64_KERNEL_TTBR0.store(device_only_pa as u64, Ordering::Release);
        }
        Err(_) => {
            azos_drv_sys::kerr!("[MM] FAILED: could not build the device-only TTBR0 table");
            // Fall back to publishing the FULL kernel table rather than
            // leaving SECONDARY_TTBR0_PA/AARCH64_KERNEL_TTBR0 at their
            // zero-init value. `0` is not "keep whatever was there" the
            // way it is for TTBR1's fallback (SECONDARY_TTBR1_PA's `0`
            // means "attach the boot alias instead" — a real table);
            // TTBR0_EL1 = 0 on a secondary that then attaches it
            // (`aarch64_secondary_mmu_init`) makes EVERY translation
            // through the low half fault, including the UART/GIC MMIO
            // windows that secondary needs to bring itself up at all — a
            // silent hang, not a degraded-but-running kernel. The
            // already-red FAILED line above is what should make this
            // build fail the gate; stranding every secondary on top of it
            // is not an extra proof of the same bug, just a worse one.
            let kpt = azos_mm::vmm::kernel_pagetable();
            crate::entry::aarch64::SECONDARY_TTBR0_PA.store(kpt, Ordering::Release);
            crate::entry::aarch64::AARCH64_KERNEL_TTBR0.store(kpt as u64, Ordering::Release);
        }
    }
}

/// The null and stack guards read back from the page table, and the opt-in
/// PAN probe (`pan-probe`).
#[inline(always)]
pub fn verify_guards() {
    // Read back BOTH guards rather than trust the calls above returned —
    // the same principle `verify_wx`/`verify_no_exec_outside_image` apply to
    // W^X/NX a few lines up. MARKERS, asserted by the gate.
    //
    // The null guard's `unmapped` readback is expected to be `true` even
    // with `null_guard()` deleted: VA 0 sits below `hw::RAM_BASE`, so
    // `vmm::init()` never mapped it in the first place — see that call's
    // doc. This readback proves "a null dereference finds nothing mapped",
    // not specifically that `null_guard()`'s own `unmap()` did the work; the
    // gate's canary for this line temporarily maps page 0 before reading
    // it back, not just removes the call (removing the call alone does not
    // discriminate here — see the task's closing report for why).
    {
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

    // O3.2 (owner decision, PAN): a fresh USER-tagged page, read from EL1
    // OUTSIDE any UserAccess window — must fault now that SCTLR_EL1.SPAN=0
    // (boot.rs) sets PSTATE.PAN on every EL0->EL1 exception. A scratch VA
    // well clear of the kernel image/heap so this cannot collide with a
    // real mapping (`AlreadyMapped` would abort the probe, not the boot).
    #[cfg(feature = "pan-probe")]
    {
        use azos_arch::PagePerms;
        const PAN_PROBE_VA: usize =
            azos_arch::mmu::KERNEL_VA_OFFSET as usize + 0x6000_0000;
        match azos_mm::pmm::alloc_page() {
            Ok(page) => {
                let pt = azos_mm::vmm::kernel_pagetable();
                match azos_mm::vmm::map(pt, PAN_PROBE_VA, page.as_usize(), PagePerms::USER_RW) {
                    Ok(()) => {
                        kprintln!("[MM] PAN PROBE: reading user page at {:#x} \
                                   from EL1 outside UserAccess (must fault)", PAN_PROBE_VA);
                        let v = unsafe { core::ptr::read_volatile(PAN_PROBE_VA as *const u8) };
                        azos_drv_sys::kerr!("[MM] PAN PROBE FAILED: read {:#x} did not fault (byte={:#x})",
                            PAN_PROBE_VA, v);
                    }
                    Err(e) => kprintln!("[MM] PAN PROBE: could not map scratch page: {:?}", e),
                }
            }
            Err(_) => kprintln!("[MM] PAN PROBE: could not allocate a scratch page"),
        }
    }
}

/// The boot stack's high-water mark (the same report riscv64 prints from
/// `arch_enter_scheduler`).
#[inline(always)]
pub fn post_heap(_heap_start: usize, _kernel_end_aligned: usize) {
    crate::boot_stack_report();
}

/// GICv3: the IRQ stacks first, then the GIC MMIO and the distributor,
/// redistributor(0) and CPU interface, with the timer PPI and SGI 0.
///
/// boot-seq: the GIC/ITS windows are mapped here, after the heap, not in
/// `kernel_mmio_map`: moving them would move the `[GIC] MMIO mapped` line.
#[inline(always)]
pub fn irqchip_init(_hart_id: usize, _dtb_ptr: usize) {
    kprintln!();

    // Per-CPU IRQ stack: magic word + published [base, top), BEFORE
    // anything below can take an interrupt — same ordering
    // constraint riscv64's `irq_stacks_arm()` documents.
    crate::aarch64_irq_stacks_arm();

    // GIC MMIO — Device memory, mapped the same way UART already is
    // above. `GICR_STRIDE` covers ONE PE's 128 KiB redistributor frame;
    // Phase 2 mapped only the first (hart 0 was the only PE that would
    // ever walk this range). Phase 4 (SMP) needs the WHOLE range mapped
    // BEFORE any secondary starts: `arch-aarch64::smp::secondary_init`
    // walks `find_redistributor` up to `crate::MAX_HARTS` frames looking for
    // its own affinity, and a walk past a single mapped frame data-
    // aborts on unmapped Device space. Canary (a): map only one frame
    // here again — see this task's report for whether the row actually
    // fails (`map_mmio_region`'s own granularity may already cover more
    // than one frame, which would make this canary a non-discriminating
    // one; verified, not assumed).
    let _ = azos_mm::vmm::map_mmio_region(gic::GICD_BASE, 0x1_0000);
    let _ = azos_mm::vmm::map_mmio_region(gic::GICR_BASE, gic::GICR_STRIDE * crate::MAX_HARTS);
    // ITS control + translation frames (RFC-0046 stage 1a). 0x2_0000
    // covers both 64 KiB frames `azos_arch::its::translater_address`
    // assumes — see that function's doc for the exact frame layout.
    let _ = azos_mm::vmm::map_mmio_region(azos_arch::its::ITS_BASE, 0x2_0000);
    // URGENT fix (coordinator, 2026-09-26): `map_mmio_region` mirrors
    // into `DEVICE_PT` too once U01-2's fix installed it (`install_
    // device_only_ttbr0`, above) — but it writes the new PTEs with a
    // plain `write_volatile`, no barrier, and by THIS point in boot
    // `DEVICE_PT` is the LIVE `TTBR0_EL1` on this hart. A brand-new
    // fault->valid PTE (and, worse, a brand-new intermediate L1/L2
    // table descriptor when the walk had to allocate one) written into
    // the table this core is CURRENTLY translating through is not
    // guaranteed visible to the next translation table walk without a
    // `dsb ishst` + TLB invalidate + `isb` — exactly what
    // `ARCH.flush_tlb_all()` (`tlbi_vmalle1is`) already does. Without
    // this, `init_redistributor(0)` below (or `init_distributor()`)
    // faults on the GICR/GICD access it JUST mapped: measured as
    // `[FATAL] aarch64 kernel page fault: read/exec at 0x80a0014`
    // (GICR_WAKER) — the mapping printed as done, the very next access
    // to it still saw a translation fault. Same class of hazard
    // applies to `arch_map_late_mmio`'s own `map_mmio_region` call
    // (virtio), fixed there too.
    {
        use azos_arch::Mmu;
        azos_arch::ARCH.flush_tlb_all();
    }
    kprintln!("[GIC] MMIO mapped: GICD={:#x} GICR={:#x} (x{} frames)",
        gic::GICD_BASE, gic::GICR_BASE, crate::MAX_HARTS);

    gic::init_distributor();
    gic::init_redistributor(0);
    // Also sets ICC_SRE_EL1.SRE=1 — task 2's EL1-path requirement.
    // On the EL2 crate::entry path `_azos_drop_to_el1` already granted EL1
    // permission to touch that bit (ICC_SRE_EL2.SRE+Enable); this is
    // what actually turns the EL1 system-register interface on,
    // needed on BOTH crate::entry paths.
    gic::init_cpu_interface();
    gic::enable_ppi(0, crate::entry::aarch64::TIMER_PPI_ENABLED); // EL1 virtual timer, PPI 27
    // SGI 0 — this kernel's cross-core IPI (Phase 4). Enabled on hart 0
    // here, on every secondary inside `smp::secondary_init`'s caller
    // (`secondary_main`) — see `crate::entry::aarch64::handle_irq`
    // for the receive side.
    gic::enable_ppi(0, 0);
    kprintln!("[GIC] distributor + redistributor(0) + CPU interface \
               initialized, PPI {} + SGI 0 enabled", crate::entry::aarch64::TIMER_PPI_ENABLED);
}

/// Nothing yet: `timer_init` unmasks IRQs once the tick is armed.
#[inline(always)]
pub fn irq_enable_early() {}

/// The PL011's receive/transmit interrupt.
#[inline(always)]
pub fn console_irq(_hart_id: usize, dtb_ptr: usize) {
    // PL011 console RX on interrupts (wave 7), the riscv64 PLIC/APLIC
    // UART path's twin. The INTID comes from the DTB's PL011 node (QEMU
    // `virt`: `interrupts = <0 1 4>`, SPI 1 level -> INTID 33), never
    // from `uart::UART_IRQ`, which is only printed next to it so a
    // disagreement shows. Wired only when that node's `reg` is the UART
    // this kernel drives; otherwise the console stays polled (the
    // shell's 20 ms `readline` poll of the FIFO), exactly as before.
    //
    // Order: publish the INTID for `handle_irq` -> route + enable the
    // SPI at the GIC -> unmask RX/RX-timeout in the PL011 (which also
    // switches `uart::can_read` to the ring). IRQs are still masked at
    // the PE here (`ARCH.enable_all()` is below), and a byte already
    // waiting in the FIFO raises the level line as soon as they are not.
    {
        let found = if dtb_ptr != 0 {
            unsafe {
                azos_dtb::dtb_pl011_irq(
                    azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8)
            }
        } else {
            None
        };
        match found {
            Some(p) if p.base == hw::UART_BASE => {
                crate::entry::aarch64::PL011_RX_INTID.store(p.intid, AOrdering::Release);
                let mpidr = azos_arch::mpidr::read_mpidr().raw;
                gic::route_spi(p.intid, mpidr, p.edge);
                let (router, edge, enabled) = gic::spi_state(p.intid);
                kprintln!("[IRQ] PL011 {:#x}: DTB INTID {} ({}) (platform const {}), \
                           IROUTER={:#x} (MPIDR {:#x}) enabled={}",
                    p.base, p.intid, if edge { "edge" } else { "level" },
                    azos_drv_sys::uart::UART_IRQ, router, mpidr, enabled);
                #[cfg(not(feature = "pl011-rx-irq-canary"))]
                {
                    azos_drv_sys::uart::enable_irq();
                    azos_drv_sys::uart::set_rx_wake_wired();
                    kprintln!("[IRQ] PL011 RX interrupt enabled (ring buffer RX)");
                    // The same SPI now feeds the PL011 from the
                    // console's TX ring. Not under the RX canary: that
                    // row's console stays polled end to end.
                    azos_drv_sys::uart::enable_tx_irq();
                }
                #[cfg(feature = "pl011-rx-irq-canary")]
                kprintln!("[IRQ] PL011 RX interrupt LEFT MASKED (pl011-rx-irq-canary): console polled");
            }
            Some(p) => kprintln!("[IRQ] PL011 in DTB at {:#x}, not the console at {:#x}: \
                                  RX interrupt not wired, console polled", p.base, hw::UART_BASE),
            None => kprintln!("[IRQ] no PL011 interrupt in the DTB (dtb={:#x}): \
                               RX interrupt not wired, console polled", dtb_ptr),
        }
    }
}

/// Trigger types for ring-3 SPIs (wave 9 IRQ4), read through the kernel's
/// own view of the blob now that the low half maps devices only.
///
/// boot-seq: read after the GIC is up (the blob is reserved on aarch64);
/// riscv64 reads its triggers before `pmm::init`.
#[inline(always)]
pub fn irq_triggers(dtb_ptr: usize) {
    // Trigger types for ring-3 SPIs (wave 9 IRQ4): `gic::user_spi_bind`
    // programs ICFGR from this instead of always level. The boot line
    // names two lines QEMU `virt` describes with opposite triggers (the
    // PL031's SPI 2 level, the first virtio-mmio slot's SPI 16 edge).
    // A line whose last ring-3 binding goes at task exit is masked and
    // handed back (`irq_bind::irq_unbind_all` -> the release hook).
    {
        let found = if dtb_ptr != 0 {
            unsafe {
                azos_dtb::dtb_irq_triggers(
                    azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8,
                    azos_dtb::IrqController::GicV3)
            }
        } else {
            None
        };
        match found {
            Some(t) => {
                for intid in 32..1020 {
                    if let Some(edge) = t.edge(intid) {
                        gic::note_dtb_trigger(intid, edge);
                    }
                }
                let (n, e) = t.counts();
                let name = |i: u32| match gic::dtb_trigger(i) {
                    Some(true) => "edge",
                    Some(false) => "level",
                    None => "absent",
                };
                kprintln!("[IRQ] DTB triggers (GICv3): {} SPIs, {} edge; INTID 34 {}, INTID 48 {}",
                    n, e, name(34), name(48));
            }
            None => kprintln!("[IRQ] DTB triggers: no GICv3 node with 3-cell specifiers"),
        }
    }
}

/// The SPI, masked and handed back.
#[inline(always)]
pub fn line_release() -> fn(u32) {
    gic::user_spi_release
}

/// The ITS on hart 0's redistributor.
#[inline(always)]
pub fn irq_routing_init(_hart_id: usize) {
    // RFC-0046 stage 1a: bring the ITS up and enable LPIs on hart 0's
    // redistributor. `rd_base` here is EXACTLY the frame
    // `init_redistributor(0)` two lines up already programmed
    // (`gic::GICR_BASE + 0 * gic::GICR_STRIDE`) — same frame, not a
    // second lookup. Kept fallible and non-fatal: a board/QEMU config
    // without `its=on` must still boot everything ELSE this hook does
    // (PCI enumeration, PSCI, timer) — only the ITS-dependent PCI IRQ
    // path (A2-main.diff) is unavailable if this errors.
    let its_rd_base = gic::GICR_BASE; // cpu_id 0 * GICR_STRIDE
    match its().init(its_rd_base) {
        Ok(()) => {
            ITS_READY.store(true, core::sync::atomic::Ordering::Release);
            kprintln!("[ITS] enabled: base={:#x} rd_base(cpu0)={:#x}",
                azos_arch::its::ITS_BASE, its_rd_base);
        }
        Err(e) => azos_drv_sys::kwarn!("[ITS] init failed: {:?} (PCI MSI-X stays unrouted)", e),
    }
}

/// The PSCI conduit.
#[inline(always)]
pub fn smp_probe(dtb_ptr: usize) {
    let entry_el_2 = entered_at_el2();
    // PSCI conduit — must be selected before ANY `cpu_on` (Phase 4's
    // `wake_harts`, near the end of this function). Prefer the FDT's
    // own `/psci` `method` property; fall back to the crate::entry-EL
    // heuristic (`psci::select_conduit_from_entry_el`) only when the
    // FDT has none — see that function's own doc for why crate::entry EL
    // alone is not always right (`virtualization=on` makes `HVC` from
    // EL1 trap to OUR OWN unhandled EL2 vector instead of reaching
    // QEMU's PSCI shim).
    let psci_from_fdt = if dtb_ptr != 0 {
        // The DTB sits in RAM at a PHYSICAL address the bootloader chose.
        // Once the low half stops mapping RAM, reading it through that raw
        // number faults — the kernel's own view is what resolves.
        unsafe {
            azos_arch::psci::select_conduit_from_fdt(
                azos_mm::addr::phys_to_virt(dtb_ptr) as u64)
        }
    } else {
        false
    };
    if !psci_from_fdt {
        azos_arch::psci::select_conduit_from_entry_el(entry_el_2);
    }
    kprintln!("[SMP] PSCI conduit: {:?} (from {})",
        azos_arch::psci::conduit(),
        if psci_from_fdt { "FDT /psci" } else { "crate::entry EL" });
}

/// The EL1 virtual timer: the live frequency, the vDSO timebase, the
/// periodic tick, then IRQs unmasked.
///
/// boot-seq: `install_vdso` runs here, with the live `CNTFRQ_EL0` read after
/// the GIC/ITS/PSCI bring-up; riscv64 installs it from `post_heap` with its
/// fixed TIMER_FREQ, before its PLIC.
#[inline(always)]
pub fn timer_init() {
    // Timer period: read CNTFRQ_EL0 LIVE rather than trust the
    // platform constant. `arch-aarch64::sysregs::read_cntfrq_el0`'s
    // own doc says QEMU virt's cortex-a72 default is 62.5 MHz, while
    // `platform::hw::TIMER_FREQ` documents 1 GHz for machine >= 9.0 —
    // the two sources disagree about which QEMU config this actually
    // is, so only a live read is trustworthy; printed either way so a
    // real mismatch is visible instead of silently mis-pacing every
    // tick by up to 16x.
    let live_hz = arch_timer::freq_hz();
    kprintln!("[TIMER] CNTFRQ_EL0: {} Hz (platform const: {} Hz)", live_hz, hw::TIMER_FREQ);
    if live_hz != hw::TIMER_FREQ {
        azos_drv_sys::kwarn!("[TIMER] WARN: live CNTFRQ_EL0 disagrees with platform::hw::TIMER_FREQ \
                   — using the live value for the tick period");
    }

    // M01: vDSO — allocate the shared timing page that user-space reads
    // directly. Shared with riscv64's kernel_main — see `crate::install_vdso`'s
    // own doc for why this was missing here (every aarch64 process took
    // a page fault reading `VDSO_USER_BASE`) and why the timebase is the
    // just-read live `CNTFRQ_EL0` value rather than a compile-time
    // constant. Called here (before ANY task can exec — autorun spawns
    // much later, past FAT32/CONFIG.INI) rather than at this
    // function's very top: it needs `live_hz`, which needs the GIC/PSCI
    // bring-up above it in this same block.
    crate::install_vdso(live_hz);
    // Publish for `handle_irq` (`kernel/src/crate::entry/aarch64.rs`) to convert
    // CNTVCT_EL0 ticks to milliseconds on every timer IRQ — see
    // `VDSO_TIMEBASE_HZ`'s own doc. Must happen before IRQs are
    // unmasked below, so the first tick never reads a stale 0.
    crate::entry::aarch64::VDSO_TIMEBASE_HZ.store(live_hz, AOrdering::Release);
    // Lets ring 3 read CNTVCT_EL0 directly (`libsys::vdso_now_ns`'s
    // RFC-0041 §A parity path) instead of trapping — see
    // `sysregs::enable_el0_cntvct`'s own doc. Hart 0 only here;
    // `secondary_main` below does the same for every
    // secondary, since this is a per-PE register.
    azos_arch::sysregs::enable_el0_cntvct();
    let period_ticks = if live_hz == 0 { 1 } else { core::cmp::max(1, live_hz / AARCH64_SCHED_HZ) };
    crate::entry::aarch64::arm_periodic_timer(period_ticks);
    kprintln!("[TIMER] periodic tick armed: period={} ticks (~{} Hz)", period_ticks, AARCH64_SCHED_HZ);

    ARCH.enable_all();
    kprintln!("[TRAP] IRQs unmasked (DAIF.I clear)");
}

/// The self-tests that need interrupts live.
#[inline(always)]
pub fn boot_selftests() {
    let live_hz = arch_timer::freq_hz();
    // ── (a) `svc #0` self-test — must RETURN, not park ──────────────
    let selftest_x0: u64;
    unsafe {
        core::arch::asm!(
            "mov x0, #0",
            "svc #0",
            "mov {0}, x0",
            out(reg) selftest_x0,
            out("x0") _,
            options(nostack),
        );
    }
    if selftest_x0 == crate::entry::aarch64::SELFTEST_SVC_REPLY {
        kprintln!("[TRAP] svc #0 self-test: PASS (returned, x0={:#x})", selftest_x0);
    } else {
        azos_drv_sys::kerr!("[TRAP] FAILED: svc #0 self-test — expected x0={:#x}, got {:#x}",
            crate::entry::aarch64::SELFTEST_SVC_REPLY, selftest_x0);
    }

    // ── (b) N ticks in bounded time ──────────────────────────────────
    //
    // The pass/fail bound below is deliberately NOT derived from
    // `period_ticks` — a bound built from the very period this loop
    // exists to verify cannot catch that period being systematically
    // wrong (the 1 GHz-vs-62.5 MHz QEMU `-cpu` disagreement
    // `arch_timer::freq_hz`'s own call site above warns about, or a
    // bad `AARCH64_SCHED_HZ`): the timeout would simply stretch or
    // shrink to match the same error, and the loop would "pass" no
    // matter what the period actually was. `EXPECTED_MS` is instead
    // computed ONCE from `TICK_TARGET`/`AARCH64_SCHED_HZ` alone — the
    // wall-clock time this test is actually supposed to take — and
    // checked against `elapsed_ms`, which comes from the LIVE
    // `CNTVCT_EL0` delta converted through the LIVE `live_hz`, not
    // from anything this test derived. The loop's own timeout is a
    // generous, unrelated 2-real-second safety cap for a timer that
    // ticks but too slowly or too rarely — it is not what decides
    // pass/fail. It does NOT bound a timer whose line never fires
    // (PPI 27 never enabled): `wfi` runs before the deadline compare, so
    // with no interrupt at all the PE parks here for good — which is
    // what the `a64clk-ppi-canary` gate row relies on.
    const TICK_TARGET: u64 = 5;
    const EXPECTED_MS: u64 = 1000 * TICK_TARGET / AARCH64_SCHED_HZ; // 50 ms
    let ticks_before = crate::entry::aarch64::TICK_COUNT.load(AOrdering::Acquire);
    let target = ticks_before + TICK_TARGET;
    let start_cntvct = ARCH.now_ticks();
    let hard_timeout_ticks = live_hz.saturating_mul(2); // 2 s, independent of period_ticks
    let deadline_cntvct = start_cntvct.wrapping_add(hard_timeout_ticks);
    loop {
        let now_count = crate::entry::aarch64::TICK_COUNT.load(AOrdering::Acquire);
        if now_count >= target { break; }
        if ARCH.now_ticks() >= deadline_cntvct { break; }
        ARCH.wfi();
    }
    let ticks_after = crate::entry::aarch64::TICK_COUNT.load(AOrdering::Acquire);
    let elapsed_cntvct = ARCH.now_ticks().wrapping_sub(start_cntvct);
    let elapsed_ms = if live_hz == 0 { 0 } else { elapsed_cntvct * 1000 / live_hz };
    // Generous 4x-either-way band around EXPECTED_MS: wide enough to
    // absorb QEMU scheduling jitter and the self-test/kprintln! work
    // already done above, tight enough that a 16x frequency mixup or a
    // re-arm-after-EOI storm (2x too fast — see `handle_irq`'s own
    // comment on ordering) still falls outside it.
    if ticks_after < target {
        azos_drv_sys::kerr!("[TIMER] FAILED: only {} of {} ticks arrived in {} ms (expected ~{} ms)",
            ticks_after - ticks_before, TICK_TARGET, elapsed_ms, EXPECTED_MS);
    } else if elapsed_ms < EXPECTED_MS / 4 || elapsed_ms > EXPECTED_MS * 4 {
        azos_drv_sys::kerr!("[TIMER] FAILED: {} ticks arrived in {} ms, expected ~{} ms \
                   (period computed wrong, or re-arming too fast/slow)",
            ticks_after - ticks_before, elapsed_ms, EXPECTED_MS);
    } else {
        kprintln!("[TIMER] ticks: {} in {} ms (target {}, expected ~{} ms)",
            ticks_after - ticks_before, elapsed_ms, TICK_TARGET, EXPECTED_MS);
    }

    // ── (c) FP/SIMD survives interrupt ────────────────────────────────
    let probe_target = ticks_after + TICK_TARGET;
    let probe_deadline = ARCH.now_ticks().wrapping_add(live_hz.saturating_mul(2));
    let (v8_lo, v8_hi, _probe_final_ticks) =
        crate::entry::aarch64::fp_survives_interrupt_probe(probe_target, probe_deadline);
    let pattern = crate::entry::aarch64::FP_PROBE_PATTERN;
    if v8_lo == pattern && v8_hi == pattern {
        kprintln!("[TRAP] FP/SIMD survives interrupt: PASS (v8=[{:#x},{:#x}])", v8_hi, v8_lo);
    } else {
        azos_drv_sys::kerr!("[TRAP] FAILED: FP/SIMD did not survive interrupt — v8=[{:#x},{:#x}], \
                   expected [{:#x},{:#x}]", v8_hi, v8_lo, pattern, pattern);
    }

    // ── IRQ-stack proof (task 1) ───────────────────────────────────────
    let (probed, took_own_stack) = crate::entry::aarch64::irq_stack_probe_result();
    if probed && took_own_stack {
        kprintln!("[AARCH64-IRQSTACK] hart 0 handles interrupts on its own stack");
    } else if probed {
        azos_drv_sys::kerr!("[AARCH64-IRQSTACK] FAILED: hart 0 handled an interrupt off its own IRQ stack");
    } else {
        azos_drv_sys::kerr!("[AARCH64-IRQSTACK] FAILED: no interrupt was observed to probe");
    }
    if !crate::aarch64_irq_stack_intact() {
        azos_drv_sys::kerr!("[AARCH64-IRQSTACK] FAILED: hart 0's IRQ-stack magic word was \
                   overwritten (overflow)");
    }

    // ── TTBR1 alias proof (aarch64 parity program, TTBR1 migration) ────
    //
    // `aarch64_early_ttbr1_alias` (boot.S, right after
    // `aarch64_early_mmu_init`) already built the alias table and
    // turned TTBR1 walks on; this reads back what the hardware
    // actually latched, decodes T0SZ/T1SZ from the LIVE TCR_EL1 (not
    // the constants that requested them), and does a live
    // cross-mapping read to prove the table itself resolves to the
    // right physical page. See `azos_arch::mmu_setup::
    // enable_ttbr1_alias`'s doc for what this does and does not
    // change about the kernel's actual translations.
    let ttbr1_boot = azos_arch::mmu_setup::TTBR1_BOOT_VALUE.load(AOrdering::Acquire);
    let tcr_boot = azos_arch::mmu_setup::TCR_BOOT_VALUE.load(AOrdering::Acquire);
    let t0sz = azos_arch::mmu::tcr_t0sz(tcr_boot);
    let t1sz = azos_arch::mmu::tcr_t1sz(tcr_boot);
    let ttbr1_now = azos_arch::sysregs::read_ttbr1_el1();
    let (canary_low, canary_high, canary_match) = crate::entry::aarch64::ttbr1_alias_verify();
    kprintln!("[AARCH64-TTBR1] T0SZ={} T1SZ={} TTBR1_EL1={:#x} \
               KERNEL_VA_OFFSET={:#x}",
        t0sz, t1sz, ttbr1_boot, azos_arch::mmu::KERNEL_VA_OFFSET);
    // 25 (39-bit halves) at a 4 or 16 KiB granule, 16 (48-bit) at 64 KiB:
    // the input range this build's granule walks in three levels.
    let want_tsz = azos_arch::mmu::GRANULE.tsz();
    if t0sz != want_tsz || t1sz != want_tsz {
        azos_drv_sys::kerr!("[AARCH64-TTBR1] FAILED: expected T0SZ=T1SZ={} ({}-bit \
                   halves), read T0SZ={} T1SZ={}", want_tsz, 64 - want_tsz, t0sz, t1sz);
    } else if ttbr1_boot == 0 {
        azos_drv_sys::kerr!("[AARCH64-TTBR1] FAILED: TTBR1_EL1 read back 0 — \
                   enable_ttbr1_alias did not run or did not publish it");
    } else if !canary_match {
        azos_drv_sys::kerr!("[AARCH64-TTBR1] FAILED: alias read mismatch — low={:#x} \
                   high={:#x}, expected both == {:#x}",
            canary_low, canary_high, crate::entry::aarch64::TTBR1_ALIAS_CANARY);
    } else if ttbr1_now as usize & !0xFFF != azos_mm::vmm::kernel_pagetable() {
        // The boot alias is SUPPOSED to be gone by now: `enable_paging`
        // replaces it with the kernel's real table, which is what carries
        // W^X, NX and the stack guards. A TTBR1 still holding the alias
        // means the kernel is executing out of a flat 1 GiB mapping with
        // none of those permissions — the exact silent hole this
        // migration exists to close, and the shape an earlier attempt
        // shipped before the guard-page probe caught it.
        azos_drv_sys::kerr!("[AARCH64-TTBR1] FAILED: TTBR1_EL1 is not the kernel page table — \
                   kernel PT {:#x}, TTBR1 {:#x} (boot alias was {:#x})",
                  azos_mm::vmm::kernel_pagetable(), ttbr1_now, ttbr1_boot);
    } else {
        kprintln!("[AARCH64-TTBR1] kernel runs in the upper half: alias low={:#x} \
                   high={:#x} match, TTBR1_EL1 = kernel PT {:#x}",
                  canary_low, canary_high, ttbr1_now);
    }

    // ── Translation granule readback (config/Kconfig.arch AARCH64_PAGE_*) ──
    //
    // Decoded from the LIVE TCR_EL1, not from the constants that asked for
    // it: TG0 (bits [15:14]) and TG1 ([31:30]) use different encodings, so
    // each is decoded on its own and both must name the granule this
    // kernel was built for. The table count is a walk of the kernel's own
    // page table (root + every table under it), so the line also says
    // what the granule costs in page-table memory on this boot.
    {
        let tcr = azos_arch::sysregs::read_tcr_el1();
        let tg0_kib = match (tcr >> 14) & 0b11 { 0b00 => 4, 0b10 => 16, 0b01 => 64, _ => 0 };
        let tg1_kib = match (tcr >> 30) & 0b11 { 0b10 => 4, 0b01 => 16, 0b11 => 64, _ => 0 };
        let g = azos_arch::mmu::GRANULE;
        let want_kib = g.page_size() / 1024;
        let kpt = azos_mm::vmm::kernel_pagetable();
        let tables = azos_mm::vmm::table_frames(kpt);
        let verdict = if tg0_kib == want_kib && tg1_kib == want_kib { "ok" } else { "MISMATCH" };
        kprintln!("[AARCH64-GRANULE] {}: TG0={} KiB TG1={} KiB (built for {} KiB), \
                   T0SZ={} T1SZ={}, root {} entries, level-1 block {} KiB; \
                   kernel page tables: {} frames = {} KiB",
            verdict, tg0_kib, tg1_kib, want_kib,
            azos_arch::mmu::tcr_t0sz(tcr), azos_arch::mmu::tcr_t1sz(tcr),
            g.root_entries(), g.level_size(1) / 1024,
            tables, tables * g.page_size() / 1024);
    }

    // ── M41 (coordinator / U10-7, audit): TCR_EL1.IPS/AS readback ────
    //
    // MARKER, per-boot proof that `tcr_value_for_this_cpu` actually
    // landed what it computed, not just that the constant looks right
    // in source. Read from the LIVE register (not `tcr_boot`, which is
    // the alias-time snapshot from before `enable_paging` — IPS/AS do
    // not change across that switch, but this line is meant to prove
    // the CURRENT state, the same discipline every other readback in
    // this block follows).
    let tcr_live = azos_arch::sysregs::read_tcr_el1();
    let ips = azos_arch::mmu::tcr_ips(tcr_live);
    let as_bit = azos_arch::mmu::tcr_as(tcr_live);
    kprintln!("[AARCH64-TCR] IPS={} AS={}", ips, as_bit);
    // Both FAILED branches are QEMU-target claims (`-cpu max`/cortex-a72
    // report PARange >= 4 and 16-bit ASID support), not an architectural
    // guarantee for every CPU this crate might run on: a real
    // implementation that only supports 8-bit ASIDs makes `AS` RES0 —
    // reading back 0 there would be correct hardware behavior, not this
    // code failing to ask. This gate boots QEMU only, so it is a fair
    // canary here; it is not a portable assertion if reused elsewhere.
    if ips == 0 {
        azos_drv_sys::kerr!("[AARCH64-TCR] FAILED: IPS=0 — TCR_EL1 still describes \
                   32-bit physical addresses only");
    }
    if as_bit == 0 {
        azos_drv_sys::kerr!("[AARCH64-TCR] FAILED: AS=0 on QEMU — TCR_EL1 still \
                   selects an 8-bit ASID");
    }
}

/// VirtIO-MMIO is not live before this point on aarch64 (Phase 1 above only
/// mapped GICD/GICR/UART) — this maps the whole window right before
/// `install_entropy()` needs it. No-op on riscv64, which already mapped
/// this window during its own early VMM bring-up — see
/// `entry::riscv64::boot_hooks::arch_map_late_mmio`.
pub fn arch_map_late_mmio() {
    use azos_drv_base::platform::hw;
    let _ = azos_mm::vmm::map_mmio_region(
        hw::VIRTIO_MMIO_BASE, hw::VIRTIO_MMIO_STRIDE * hw::VIRTIO_MMIO_COUNT);
    // Same barrier this front's own GIC mapping needed (`irqchip_init`,
    // see that call site's comment): this runs after `install_device_only_
    // ttbr0`, writing new PTEs into the table already live in `TTBR0_EL1`.
    {
        use azos_arch::Mmu;
        azos_arch::ARCH.flush_tlb_all();
    }
}

/// Start every secondary hart via PSCI `CPU_ON`, correct `NUM_ONLINE_CPUS`
/// down to the real count, rescue any stranded task, then (aarch64-only:
/// riscv64 has no equivalent proof) block on each secondary's own
/// `CORE_ONLINE` publish and prove a cross-core SGI round trip. Verbatim
/// cut from the former aarch64 `kernel_main`'s own body.
pub fn arch_wake_secondaries(num_cpus: usize) {
    let dtb_num_cpus = num_cpus;
    azos_drv_sys::uart::enable_smp_lock();
    kprintln!("[SMP] UART lock enabled");

    kprintln!("[SMP] Starting {} secondary hart(s) via PSCI CPU_ON...", dtb_num_cpus - 1);
    // A secondary reads `AZOS_SECONDARY_SP` and first uses its boot stack
    // with its MMU (so its caches) off: push the boot CPU's writes to both
    // out to the point of coherency, and drop any line of the stacks a later
    // cacheable read could find stale. A no-op on QEMU; required on silicon.
    for cpu in 0..azos_percpu::nr_cpu_ids() {
        let top = crate::AZOS_SECONDARY_SP[cpu].load(core::sync::atomic::Ordering::Relaxed);
        if top != 0 {
            let stack = azos_mm::addr::phys_to_virt(top - crate::SECONDARY_STACK_SIZE);
            unsafe { azos_arch::cache::dcache_clean_and_invalidate(stack, crate::SECONDARY_STACK_SIZE) };
        }
    }
    unsafe {
        azos_arch::cache::dcache_clean(
            crate::AZOS_SECONDARY_SP.as_ptr() as usize,
            core::mem::size_of_val(&crate::AZOS_SECONDARY_SP),
        )
    };
    let online = unsafe { azos_sched::smp::wake_harts(dtb_num_cpus) };
    if online != dtb_num_cpus {
        azos_drv_sys::kwarn!("[SMP] WARNING: only {}/{} harts started — degraded to {} online CPU(s)",
            online, dtb_num_cpus, online);
    }
    azos_sched::smp::NUM_ONLINE_CPUS.store(online, Ordering::SeqCst);
    if online < azos_sched::MAX_CPUS {
        let rescued = azos_sched::rebalance_from_offline_cpus(online, dtb_num_cpus);
        if rescued != 0 {
            kprintln!("[SMP] rescued {} task(s) off harts that never came up", rescued);
        }
    }

    // ── Online readback — MARKER, per hart ──────────────────────────────
    //
    // Each secondary publishes `CORE_ONLINE`/`CORE_MPIDR`/`CORE_HART_ID`
    // (`crate::boot::smp::secondary_main`) once its own GIC +
    // timer bring-up is done. Bounded spin, not a fixed sleep: real
    // hardware and QEMU both take a variable number of cycles from
    // `CPU_ON` to a PE's first published word, and a fixed delay would
    // either flake under load or waste boot time padding for the common
    // case.
    {
        use azos_arch::{Cpu, ARCH};
        let deadline = ARCH.now_ticks().wrapping_add(azos_arch::timer::freq_hz().saturating_mul(2));
        for hart in 1..online {
            while !crate::entry::aarch64::CORE_ONLINE[hart].load(Ordering::Acquire) {
                if ARCH.now_ticks() >= deadline {
                    azos_drv_sys::kerr!("[SMP] FAILED: hart {} never published online \
                               (CORE_ONLINE timed out)", hart);
                    break;
                }
                ARCH.wfi();
            }
            if crate::entry::aarch64::CORE_ONLINE[hart].load(Ordering::Acquire) {
                let mpidr = crate::entry::aarch64::CORE_MPIDR[hart].load(Ordering::Acquire);
                let got_id = crate::entry::aarch64::CORE_HART_ID[hart].load(Ordering::Acquire);
                kprintln!("[SMP] hart {} online: MPIDR_EL1={:#x} current_cpu_id()={}",
                    hart, mpidr, got_id);
                // MARKER, asserted by the gate — canary (b) (drop the
                // TPIDR_EL1 write on secondaries) must fail exactly this
                // line: `got_id` then reads back as whatever TPIDR_EL1
                // reset to (0 on QEMU), never `hart`.
                if got_id != hart as u64 {
                    azos_drv_sys::kerr!("[SMP] FAILED: hart {} current_cpu_id() reported {} \
                               (TPIDR_EL1 not set to this core's own id)", hart, got_id);
                }

                // ── MARKER: this hart's own TTBR0/TTBR1 readback ─────────
                //
                // U01-1/U01-2 (audit): proves this secondary attached the
                // REAL kernel table into TTBR1 (not the early-boot alias)
                // and the DEVICE-ONLY root into TTBR0 (not the full kernel
                // table) — no feature flag needed, this runs on every boot.
                // Masks off the low 12 bits (ASID/attrs) before comparing,
                // same as the primary's own `[AARCH64-TTBR1]` marker above.
                let got_ttbr0 = crate::entry::aarch64::CORE_TTBR0[hart].load(Ordering::Acquire);
                let got_ttbr1 = crate::entry::aarch64::CORE_TTBR1[hart].load(Ordering::Acquire);
                let want_ttbr0 = crate::entry::aarch64::SECONDARY_TTBR0_PA.load(Ordering::Acquire) as u64;
                let want_ttbr1 = azos_mm::vmm::kernel_pagetable() as u64;
                let ttbr0_ok = (got_ttbr0 & !0xFFF) == (want_ttbr0 & !0xFFF);
                let ttbr1_ok = (got_ttbr1 & !0xFFF) == (want_ttbr1 & !0xFFF);
                kprintln!("[SMP] hart {} TTBR0_EL1={:#x} TTBR1_EL1={:#x}",
                    hart, got_ttbr0, got_ttbr1);
                if !ttbr0_ok {
                    azos_drv_sys::kerr!("[SMP] FAILED: hart {} TTBR0_EL1={:#x}, expected the \
                               device-only root {:#x}", hart, got_ttbr0, want_ttbr0);
                }
                if !ttbr1_ok {
                    azos_drv_sys::kerr!("[SMP] FAILED: hart {} TTBR1_EL1={:#x}, expected the \
                               kernel page table {:#x} (still the boot alias?)",
                               hart, got_ttbr1, want_ttbr1);
                }

                // ── MARKER: this hart took at least N ticks ──────────────
                // A bounded wait, same shape as the online-publish spin
                // above: this hart's own periodic timer was armed inside
                // `secondary_main`, right before it published
                // `CORE_ONLINE`, so a few ticks should already be close.
                const MIN_TICKS: u64 = 3;
                let tick_deadline = ARCH.now_ticks()
                    .wrapping_add(azos_arch::timer::freq_hz().saturating_mul(2));
                while crate::entry::aarch64::TICK_PER_HART[hart].load(Ordering::Acquire) < MIN_TICKS {
                    if ARCH.now_ticks() >= tick_deadline {
                        break;
                    }
                    ARCH.wfi();
                }
                let ticks = crate::entry::aarch64::TICK_PER_HART[hart].load(Ordering::Acquire);
                if ticks < MIN_TICKS {
                    azos_drv_sys::kerr!("[SMP] FAILED: hart {} took only {} tick(s), expected >= {}",
                        hart, ticks, MIN_TICKS);
                } else {
                    // MARKER, asserted by the gate.
                    kprintln!("[SMP] hart {} took {} ticks (>= {})", hart, ticks, MIN_TICKS);
                }
            }
        }
    }

    // ── Cross-core SGI — MARKER: sent by X, received by Y ───────────────
    //
    // Only meaningful with a real secondary online; `-smp 1` (or every
    // `wake_harts` call failing) skips it rather than printing a marker
    // that never had anything to prove.
    // Lazy FP resting state on every online hart: CPACR_EL1.FPEN must read
    // back 0b01 (EL0 traps) after its last boot-time writer. A hart left at
    // 0b11 would run user FP without ever trapping, so its state would never
    // be saved on a switch — silent cross-task corruption.
    for hart in 0..online {
        let cpacr = crate::entry::aarch64::CORE_CPACR[hart].load(Ordering::Acquire);
        let fpen = (cpacr >> 20) & 0b11;
        if fpen == 0b01 {
            kprintln!("[FP] hart {} CPACR_EL1.FPEN=0b01: EL0 FP traps (lazy save)", hart);
        } else {
            azos_drv_sys::kerr!("[FP] FAILED: hart {} CPACR_EL1={:#x} (FPEN={:#04b}), expected FPEN=0b01",
                hart, cpacr, fpen);
        }
    }

    if online > 1 {
        use azos_arch::{Cpu, Interrupts, ARCH};
        let target_hart = 1usize;
        let before = crate::entry::aarch64::SGI_RECEIVED[target_hart].load(Ordering::Acquire);
        kprintln!("[SGI] hart 0 sending SGI 0 to hart {}...", target_hart);
        ARCH.send_ipi(target_hart);
        let deadline = ARCH.now_ticks().wrapping_add(azos_arch::timer::freq_hz().saturating_mul(2));
        loop {
            let now_count = crate::entry::aarch64::SGI_RECEIVED[target_hart].load(Ordering::Acquire);
            if now_count > before { break; }
            if ARCH.now_ticks() >= deadline {
                azos_drv_sys::kerr!("[SGI] FAILED: hart 0 sent SGI 0 to hart {} — never received \
                           ({} == {})", target_hart, now_count, before);
                break;
            }
            ARCH.wfi();
        }
        let after = crate::entry::aarch64::SGI_RECEIVED[target_hart].load(Ordering::Acquire);
        if after > before {
            // MARKER, asserted by the gate.
            kprintln!("[SGI] sent by hart 0, received by hart {}: count={}",
                target_hart, after);
        }
    }
}

/// Final hand-off to the scheduler: the shared "[SCHED] Starting
/// scheduler..." line, close the window between `SCHED_LIVE` going true and
/// the first dispatch (K-A12), then `azos_sched::start()` — never
/// returns. Verbatim cut from the former aarch64 `kernel_main`'s own tail.
pub fn arch_enter_scheduler(_hart_id: usize) -> ! {
    kprintln!("[SCHED] Starting scheduler on boot CPU — tasks will now preempt...");
    // Close the same window `start()`'s own doc comment (K-A12) warns
    // about: IRQs are unmasked and the timer has been ticking since Phase
    // 2, so without this a tick could land between `SCHED_LIVE` going true
    // and `start()` actually dispatching a task, reaching `schedule()`
    // with no current task ever set. `start()` disables interrupts again
    // itself right after this (`let _`, same discard-the-token shape,
    // same reason: it never returns) — this call only has to survive the
    // few instructions between here and that one.
    {
        use azos_arch::Interrupts;
        let _ = azos_arch::ARCH.disable_all();
    }
    crate::entry::aarch64::SCHED_LIVE.store(true, Ordering::Release);
    azos_sched::start()
}

// ── The ITS instance (RFC-0046 stage 1a) ────────────────────────────────
//
// One per system, initialised once in the boot hook above, then used only
// by `kernel_main`'s single-threaded PCI bring-up (`map_device` /
// `map_vector` / `msi_target`) before the scheduler starts — no locking.
static mut ITS: azos_arch::its::ItsDriver =
    azos_arch::its::ItsDriver::new(azos_arch::its::ITS_BASE);
static ITS_READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The boot ITS. Callers: this file's boot hook and `kernel_main`'s PCI
/// section, both on the boot hart before any task runs.
pub fn its() -> &'static mut azos_arch::its::ItsDriver {
    // SAFETY: single-threaded boot-time use only (see the note above).
    unsafe { &mut *core::ptr::addr_of_mut!(ITS) }
}

/// Did `ItsDriver::init` succeed? `false` on a machine without an ITS.
pub fn its_ready() -> bool {
    ITS_READY.load(core::sync::atomic::Ordering::Acquire)
}

/// `a * a + b` on the FP unit, operands and result as raw f64 bits.
///
/// Boot-only (called from `kernel_main`'s early self-check, before any user
/// task exists), so clobbering d0/d1 cannot destroy anyone's FP state. Named
/// in `tools/aarch64_fp_free_check.sh`'s allowed list — the one place kernel
/// code outside the user-FP save/restore executes an FP instruction.
#[inline(never)]
fn fp_self_check(a_bits: u64, b_bits: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!(
            ".arch_extension fp",
            "fmov d0, {a}",
            "fmov d1, {b}",
            "fmul d0, d0, d0",
            "fadd d0, d0, d1",
            "fmov {out}, d0",
            a = in(reg) a_bits,
            b = in(reg) b_bits,
            out = lateout(reg) out,
            options(nomem, nostack),
        );
    }
    out
}

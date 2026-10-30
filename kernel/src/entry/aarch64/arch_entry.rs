// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64's [`ArchEntry`]: the boot hooks (`boot_hooks.rs`) and the
//! secondary-core steps the shared `boot::smp::secondary_main` calls.
//! Every method is `#[inline(always)]` on a zero-sized type, so a call
//! through `crate::ARCH_ENTRY` compiles to the hook body itself.

use azos_arch::irq::gic;
use azos_arch::ArchEntry;
use core::sync::atomic::Ordering;

/// The aarch64 boot sequence (`crate::ARCH_ENTRY`).
pub struct Entry;

impl ArchEntry for Entry {
    type Firmware = crate::boot_hooks::Firmware;
    type DeviceTree = azos_dtb::DtbInfo;
    type IrqController = azos_dtb::IrqController;
    type IrqTriggers = azos_dtb::IrqTriggers;
    const PAGE_TABLES: &'static str = "aarch64 3-level page tables";

    #[inline(always)]
    fn pre_console(&self, fw_table: usize, dt: Option<&azos_dtb::DtbInfo>) { crate::boot_hooks::pre_console(fw_table, dt) }
    #[inline(always)]
    fn trap_init(&self) { crate::boot_hooks::trap_init() }
    #[inline(always)]
    fn boot_banner(&self, hart_id: usize, fw_table: usize) { crate::boot_hooks::boot_banner(hart_id, fw_table) }
    #[inline(always)]
    fn firmware_table(&self, hart_id: usize, fw_table: usize, dt: Option<azos_dtb::DtbInfo>)
        -> Self::Firmware
    {
        crate::boot_hooks::firmware_table(hart_id, fw_table, dt)
    }
    #[inline(always)]
    fn kernel_cmdline(&self, fw_table: usize, out: &mut [u8]) -> Option<usize> {
        crate::boot_hooks::kernel_cmdline(fw_table, out)
    }
    fn irqchip_probe(&self, fw: &Self::Firmware) { crate::boot_hooks::irqchip_probe(fw) }
    #[inline(always)]
    fn timer_probe(&self, fw: &Self::Firmware) { crate::boot_hooks::timer_probe(fw) }
    #[inline(always)]
    fn cpu_features(&self, fw: &Self::Firmware) { crate::boot_hooks::cpu_features(fw) }
    #[inline(always)]
    fn firmware_memory(&self, fw: &Self::Firmware) -> azos_arch::FirmwareMemory {
        crate::boot_hooks::firmware_memory(fw)
    }
    #[inline(always)]
    fn irq_trigger_controller(&self) -> Option<azos_dtb::IrqController> {
        crate::boot_hooks::irq_trigger_controller()
    }
    #[inline(always)]
    fn firmware_done(&self, fw_table: usize, num_cpus: usize) { crate::boot_hooks::firmware_done(fw_table, num_cpus) }
    #[inline(always)]
    fn kernel_mmio_windows(&self) -> impl Iterator<Item = (usize, usize)> {
        crate::entry::aarch64::board_map::kernel_mmio_windows()
    }
    #[inline(always)]
    fn mmu_enabled(&self) { crate::boot_hooks::mmu_enabled() }
    #[inline(always)]
    fn restrict_low_half(&self) { crate::boot_hooks::restrict_low_half() }
    #[inline(always)]
    fn verify_guards(&self) { crate::boot_hooks::verify_guards() }
    #[inline(always)]
    fn post_heap(&self, heap_start: usize, kernel_end_aligned: usize) {
        crate::boot_hooks::post_heap(heap_start, kernel_end_aligned)
    }
    #[inline(always)]
    fn timebase_hz(&self) -> u64 { crate::boot_hooks::timebase_hz() }
    #[inline(always)]
    fn irqchip_init(&self, hart_id: usize, fw_table: usize) { crate::boot_hooks::irqchip_init(hart_id, fw_table) }
    #[inline(always)]
    fn irq_enable_early(&self) { crate::boot_hooks::irq_enable_early() }
    #[inline(always)]
    fn console_irq(&self, hart_id: usize, fw_table: usize) { crate::boot_hooks::console_irq(hart_id, fw_table) }
    #[inline(always)]
    fn irq_triggers(&self, triggers: Option<azos_dtb::IrqTriggers>) {
        crate::boot_hooks::irq_triggers(triggers)
    }
    #[inline(always)]
    fn line_hooks(&self) -> azos_arch_api::LineHooks { crate::boot_hooks::line_hooks() }
    #[inline(always)]
    fn irq_routing_init(&self, hart_id: usize) { crate::boot_hooks::irq_routing_init(hart_id) }
    #[inline(always)]
    fn smp_probe(&self, fw_table: usize) { crate::boot_hooks::smp_probe(fw_table) }
    #[inline(always)]
    fn timer_init(&self) { crate::boot_hooks::timer_init() }
    #[inline(always)]
    fn boot_selftests(&self) { crate::entry::aarch64::ext::selftests::boot_selftests() }

    #[inline(always)]
    fn map_late_mmio(&self) {
        crate::boot_hooks::arch_map_late_mmio()
    }

    #[inline(always)]
    fn boot_patch(&self, text_start: usize, text_end: usize) {
        crate::entry::aarch64::ext::pan_patch::patch(text_start, text_end);
        crate::boot::spin_patch::patch(text_start, text_end)
    }
    fn wake_secondaries(&self, num_cpus: usize) {
        crate::entry::aarch64::smp::wake_secondaries(num_cpus)
    }

    #[inline(always)]
    fn enter_scheduler(&self, hart_id: usize) -> ! {
        crate::boot_hooks::arch_enter_scheduler(hart_id)
    }

    /// Nothing: this ISA's shootdown is a broadcast `TLBI ...IS`, which
    /// reaches every PE in the inner-shareable domain with no scan set to
    /// join (riscv64's SBI remote fence needs the hart in its mask).
    #[inline(always)]
    fn secondary_tlb_online(&self, _cpu: usize) {}

    /// Per-PE GIC: find THIS PE's own redistributor by its own MPIDR affinity
    /// (never assume frame index == hart id — `gic::find_redistributor`),
    /// wake it, enable the CPU interface, enable SGI 0 (this kernel's
    /// cross-core IPI) and the EL1 virtual timer PPI. `MAX_HARTS` bounds the
    /// walk to exactly the frames `kernel_main` mapped (`GICR_STRIDE *
    /// MAX_HARTS`): further would read unmapped Device space. Under a GICv2
    /// there is no redistributor: the CPU interface and the banked SGI/PPI
    /// registers are this PE's own (`secondary_init` returns 0, which
    /// `enable_ppi_at` does not read).
    ///
    /// Then this PE's EL0-visible state (`sysregs::init_el0_state`:
    /// `CNTKCTL_EL1`, `TPIDRRO_EL0`), which is per PE: the boot CPU's own
    /// call does not cover this core; a ring-3 task migrated here would trap
    /// on its first `CNTVCT_EL0` read and read firmware's `TPIDRRO_EL0`.
    #[inline(always)]
    fn secondary_irq_init(&self, _cpu: usize) {
        let rd_base = azos_arch::smp::secondary_init(crate::MAX_HARTS);
        gic::enable_ppi_at(rd_base, 0);
        gic::enable_ppi_at(rd_base, crate::entry::aarch64::TIMER_PPI_ENABLED);
        // The PMU's overflow PPI, when the boot CPU found one (`pmu_irq`).
        if azos_arch::pmu::irq() != 0 {
            gic::enable_ppi_at(rd_base, azos_arch::pmu::irq());
        }
        azos_arch::sysregs::init_el0_state();
        // This PE's own counters (`Pmu`, the tracer's cycle timestamps):
        // PMUv3 state is per PE.
        azos_arch::pmu::start_this_cpu();
    }

    /// This core's own periodic tick at the SAME period the boot CPU computed
    /// from the live `CNTFRQ_EL0` (`entry::aarch64::TICK_PERIOD`).
    /// `CNTV_CTL_EL0`/`CNTV_CVAL_EL0` are banked per PE.
    #[inline(always)]
    fn secondary_timer_init(&self, _cpu: usize) {
        let period = crate::entry::aarch64::TICK_PERIOD.load(Ordering::Relaxed);
        if period != 0 {
            crate::entry::aarch64::irq::arm_periodic_timer(period);
        }
    }

    /// Publish this core for `kernel_main`'s readback loop: MPIDR and hart id
    /// first (Relaxed), `CORE_ONLINE` last (Release) — the boot CPU's Acquire
    /// load of `CORE_ONLINE` makes every store before it visible in one step.
    /// The hart id is re-derived through `current_cpu_id()` (a fresh
    /// `MRS TPIDR_EL1`), not the argument. boot.S's canary (b) — drop its
    /// `msr TPIDR_EL1` — does NOT fail this readback: `secondary_main` has
    /// already rewritten `TPIDR_EL1` (`set_percpu_base`). It fails the
    /// TTBR0/TTBR1 and CPACR_EL1 readbacks the earlier boot code publishes.
    #[inline(always)]
    fn secondary_publish_online(&self, cpu: usize) {
        let mpidr_raw = azos_arch::cpu::read_mpidr().raw;
        azos_arch::cpu::note_cpu_mpidr(cpu, mpidr_raw);
        if let Some(slot) = crate::entry::aarch64::CORE_MPIDR.get(cpu) {
            slot.store(mpidr_raw, Ordering::Relaxed);
        }
        if let Some(slot) = crate::entry::aarch64::CORE_HART_ID.get(cpu) {
            slot.store(azos_sched::smp::current_cpu_id() as u64, Ordering::Relaxed);
        }
        if let Some(slot) = crate::entry::aarch64::CORE_ONLINE.get(cpu) {
            slot.store(true, Ordering::Release);
        }
    }

    /// The vDSO clock on aarch64: the tick count and `CNTVCT_EL0` in ms at
    /// the live `CNTFRQ_EL0` captured at boot. `None` until both are known.
    #[inline(always)]
    fn vdso_counter_scale(&self) -> Option<(u64, u64, u64)> {
        Some((0, 0, azos_arch::timer::counter_to_ticks_mult()))
    }

    fn vdso_clock(&self) -> Option<(u64, u64)> {
        let hz = crate::entry::aarch64::VDSO_TIMEBASE_HZ.load(Ordering::Relaxed);
        let now = azos_drv_sys::timebase::now();
        if now != 0 && hz >= 1000 {
            Some((crate::entry::aarch64::TICK_COUNT.load(Ordering::Relaxed), now / (hz / 1000)))
        } else {
            None
        }
    }
}

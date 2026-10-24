// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64's `ArchEntry`, matched to `entry/{riscv64,aarch64}/
//! arch_entry.rs`: the boot hooks, and the secondary-CPU steps the shared
//! `boot::smp::secondary_main` calls.

use azos_arch::ArchEntry;

/// The x86_64 boot sequence (`crate::ARCH_ENTRY`).
pub struct Entry;

impl ArchEntry for Entry {
    type Firmware = ();
    type DeviceTree = azos_dtb::DtbInfo;
    type IrqController = azos_dtb::IrqController;
    type IrqTriggers = azos_dtb::IrqTriggers;
    const PAGE_TABLES: &'static str = "x86-64 4-level page tables, 5 under LA57";
    /// COM1 is port I/O.
    const CONSOLE_MMIO: bool = false;

    fn pre_console(&self, fw_table: usize, dt: Option<&azos_dtb::DtbInfo>) { crate::boot_hooks::pre_console(fw_table, dt) }
    fn trap_init(&self) { crate::boot_hooks::trap_init() }
    fn boot_banner(&self, hart_id: usize, fw_table: usize) { crate::boot_hooks::boot_banner(hart_id, fw_table) }
    fn firmware_table(&self, hart_id: usize, fw_table: usize, dt: Option<azos_dtb::DtbInfo>)
        -> Self::Firmware
    {
        crate::boot_hooks::firmware_table(hart_id, fw_table, dt)
    }
    fn kernel_cmdline(&self, fw_table: usize, out: &mut [u8]) -> Option<usize> {
        crate::boot_hooks::kernel_cmdline(fw_table, out)
    }
    fn irqchip_probe(&self, fw: &Self::Firmware) { crate::boot_hooks::irqchip_probe(fw) }
    fn timer_probe(&self, fw: &Self::Firmware) { crate::boot_hooks::timer_probe(fw) }
    fn cpu_features(&self, fw: &Self::Firmware) { crate::boot_hooks::cpu_features(fw) }
    fn firmware_memory(&self, fw: &Self::Firmware) -> azos_arch::FirmwareMemory {
        crate::boot_hooks::firmware_memory(fw)
    }
    fn irq_trigger_controller(&self) -> Option<azos_dtb::IrqController> {
        crate::boot_hooks::irq_trigger_controller()
    }
    fn firmware_done(&self, fw_table: usize, num_cpus: usize) { crate::boot_hooks::firmware_done(fw_table, num_cpus) }
    fn pmm_floor(&self, mem_start: usize, mem_size: usize, image_start_pa: usize, image_end_pa: usize) -> usize {
        crate::boot_hooks::pmm_floor(mem_start, mem_size, image_start_pa, image_end_pa)
    }
    fn reserve_firmware_table(&self, fw_table: usize) { crate::boot_hooks::reserve_firmware_table(fw_table) }
    fn kernel_mmio_windows(&self) -> impl Iterator<Item = (usize, usize)> {
        crate::boot_hooks::kernel_mmio_windows()
    }
    fn mmu_enabled(&self) { crate::boot_hooks::mmu_enabled() }
    fn restrict_low_half(&self) { crate::boot_hooks::restrict_low_half() }
    fn verify_guards(&self) { crate::boot_hooks::verify_guards() }
    fn post_heap(&self, heap_start: usize, kernel_end_aligned: usize) {
        crate::boot_hooks::post_heap(heap_start, kernel_end_aligned)
    }
    fn timebase_hz(&self) -> u64 { crate::boot_hooks::timebase_hz() }
    fn irqchip_init(&self, hart_id: usize, fw_table: usize) { crate::boot_hooks::irqchip_init(hart_id, fw_table) }
    fn irq_enable_early(&self) { crate::boot_hooks::irq_enable_early() }
    fn console_irq(&self, hart_id: usize, fw_table: usize) { crate::boot_hooks::console_irq(hart_id, fw_table) }
    fn irq_triggers(&self, triggers: Option<azos_dtb::IrqTriggers>) {
        crate::boot_hooks::irq_triggers(triggers)
    }
    fn line_hooks(&self) -> azos_arch_api::LineHooks { crate::boot_hooks::line_hooks() }
    fn irq_routing_init(&self, hart_id: usize) { crate::boot_hooks::irq_routing_init(hart_id) }
    fn smp_probe(&self, fw_table: usize) { crate::boot_hooks::smp_probe(fw_table) }
    fn timer_init(&self) { crate::boot_hooks::timer_init() }
    fn boot_selftests(&self) { crate::boot_hooks::boot_selftests() }

    fn map_late_mmio(&self) {
        crate::boot_hooks::arch_map_late_mmio()
    }

    /// The shared spin-site rewrite, as on riscv64 and aarch64: x86_64 links
    /// no `SpinWait` probe site, so it finds none and returns.
    fn boot_patch(&self, text_start: usize, text_end: usize) {
        crate::boot::spin_patch::patch(text_start, text_end)
    }
    fn wake_secondaries(&self, num_cpus: usize) {
        crate::boot_hooks::arch_wake_secondaries(num_cpus)
    }

    fn enter_scheduler(&self, hart_id: usize) -> ! {
        crate::boot_hooks::arch_enter_scheduler(hart_id)
    }

    /// Join the shootdown IPI set (x86 has no broadcast TLB invalidate):
    /// the scan bound and this CPU's live CR3 (`tlb::join`), so a CPU that
    /// only ever runs kernel tasks, whose CR3 the context switch never
    /// writes, is a target of every kernel-wide shootdown and of
    /// `icache_sync_all`. After `secondary_irq_init` (the LAPIC takes the
    /// vector), before interrupts are unmasked.
    fn secondary_tlb_online(&self, cpu: usize) {
        // Runtime canary `x86-tlb-join-skip`: the scan bound only, as before
        // the online publication.
        if canary!("x86-tlb-join-skip") {
            azos_arch::tlb::note_hart_online(cpu);
            return;
        }
        azos_arch::tlb::join(cpu);
    }

    /// This CPU's LAPIC in the boot CPU's mode (x2APIC or xAPIC): spurious
    /// vector, TPR 0, LINT/NMI, error vector; then it may take ring-3 lines.
    fn secondary_irq_init(&self, cpu: usize) {
        azos_arch::irq::apic::init_local(cpu);
        // This CPU's counters and its `CR4.PCE` (the plan is the boot CPU's).
        azos_arch::pmu::start_this_cpu();
        azos_drv_irqchip::user_irq::hart_ready(cpu as u32);
    }

    /// The LAPIC timer in the boot CPU's mode, at the boot CPU's period.
    fn secondary_timer_init(&self, _cpu: usize) {
        azos_arch::timer::init_local();
        let period = crate::entry::x86_64::irq::TICK_PERIOD.load(core::sync::atomic::Ordering::Relaxed);
        if period != 0 {
            crate::entry::x86_64::irq::arm_periodic_timer(period);
        }
    }

    /// The online flag the boot CPU's `wake_secondaries` waits on.
    fn secondary_publish_online(&self, cpu: usize) {
        if let Some(slot) = crate::entry::x86_64::irq::CORE_ONLINE.get(cpu) {
            slot.store(true, core::sync::atomic::Ordering::Release);
        }
    }

    /// The TSC's scale to the clock (`azos_arch::timer`'s calibration, final
    /// before the vDSO is installed): ring 3 reads the TSC (`CR4.TSD`
    /// clear) and converts it exactly as `now_ticks` does. None while the
    /// clock is not the TSC (Kconfig `X86_TSC_CLOCK`): ring 3 then asks the
    /// kernel, as after a demotion (`ext::tsc_watchdog`).
    fn vdso_counter_scale(&self) -> Option<(u64, u64, u64)> {
        if cfg!(feature = "vdso-force-syscall") || azos_arch::timer::clock() != azos_arch::timer::Clocksource::Tsc {
            return None;
        }
        Some(azos_arch::timer::counter_scale())
    }

    /// The vDSO clock: tick count and the clock (TIMER_FREQ) in ms.
    fn vdso_clock(&self) -> Option<(u64, u64)> {
        let hz = azos_arch::timer::TICK_HZ;
        let now = azos_drv_sys::timebase::now();
        if now != 0 && hz >= 1000 {
            Some((crate::entry::x86_64::irq::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed), now / (hz / 1000)))
        } else {
            None
        }
    }
}

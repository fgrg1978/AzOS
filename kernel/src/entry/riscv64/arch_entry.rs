// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64's [`ArchEntry`]: the early-boot hooks `boot::early_main` calls
//! and the rest of the boot (`boot_hooks.rs`), and the secondary-hart steps
//! the shared `boot::smp::secondary_main` calls.
//! Every method is `#[inline(always)]` on a zero-sized type, so a call
//! through `crate::ARCH_ENTRY` compiles to the hook body itself.

use azos_arch::{csr, ArchEntry};

/// The riscv64 boot sequence (`crate::ARCH_ENTRY`).
pub struct Entry;

impl ArchEntry for Entry {
    type Firmware = crate::boot_hooks::Firmware;
    type DeviceTree = azos_dtb::DtbInfo;
    type IrqController = azos_dtb::IrqController;
    type IrqTriggers = azos_dtb::IrqTriggers;
    const PAGE_TABLES: &'static str = "Sv39 page tables";

    #[inline(always)]
    fn pre_console(&self) { crate::boot_hooks::pre_console() }
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
    fn reserve_firmware_table(&self, fw_table: usize) { crate::boot_hooks::reserve_firmware_table(fw_table) }
    #[inline(always)]
    fn kernel_mmio_windows(&self) -> impl Iterator<Item = (usize, usize)> {
        crate::boot_hooks::kernel_mmio_windows()
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
    fn line_release(&self) -> fn(u32) { crate::boot_hooks::line_release() }
    #[inline(always)]
    fn irq_routing_init(&self, hart_id: usize) { crate::boot_hooks::irq_routing_init(hart_id) }
    #[inline(always)]
    fn smp_probe(&self, fw_table: usize) { crate::boot_hooks::smp_probe(fw_table) }
    #[inline(always)]
    fn timer_init(&self) { crate::boot_hooks::timer_init() }
    #[inline(always)]
    fn boot_selftests(&self) { crate::boot_hooks::boot_selftests() }

    #[inline(always)]
    fn map_late_mmio(&self) {
        crate::boot_hooks::arch_map_late_mmio()
    }

    #[inline(always)]
    fn wake_secondaries(&self, num_cpus: usize) {
        crate::boot_hooks::arch_wake_secondaries(num_cpus)
    }

    #[inline(always)]
    fn enter_scheduler(&self, hart_id: usize) -> ! {
        crate::boot_hooks::arch_enter_scheduler(hart_id)
    }

    /// Also noted by the waker before `hart_start`; a hart that arrives here
    /// without being started (firmware HSM state, a resumed hart) must still
    /// be in the shootdown's scan before it can publish a root.
    #[inline(always)]
    fn secondary_tlb_online(&self, cpu: usize) {
        azos_arch::tlb::note_hart_online(cpu);
    }

    /// This hart's controller state, then timer, software AND external
    /// interrupts in `sie` (boot.S cleared it).
    ///
    /// `SIE_SSIE` was once missing here, and that was the whole K-C15
    /// doorbell: a cross-hart wake set `sip.SSIP` on a hart whose
    /// `sie.SSIE` was clear, so the wake waited for the next tick (vsbench
    /// `ipc-rt`: 5-15 ms against Linux's 276-417 us, gone at `-smp 1`).
    ///
    /// `SEIE` (wave 10 IRQ5): a ring-3 line is routed to the hart its binding
    /// task is pinned to (`azos_drv_irqchip::user_irq`), so every hart claims
    /// external interrupts. PLIC: this hart's S-context threshold 0 (OpenSBI
    /// leaves 7, "mask all"; the global priorities, set once by the boot
    /// hart, hold ring 3's masks and are not rewritten). AIA: this hart's
    /// IMSIC file and the wired identities (`user_irq::hart_ready`). The
    /// context's enable bits are only set by a ring-3 route to this hart.
    #[inline(always)]
    fn secondary_irq_init(&self, cpu: usize) {
        azos_drv_irqchip::irqchip::init(cpu as u32);
        let sie = csr::read_sie();
        #[cfg(not(feature = "irq-secondary-seie-canary"))]
        csr::write_sie(sie | csr::SIE_STIE | csr::SIE_SSIE | csr::SIE_SEIE);
        // Canary: the secondary entry as it was, SEIE clear. A ring-3 line
        // routed here is never taken: captest's first delivery times out.
        #[cfg(feature = "irq-secondary-seie-canary")]
        csr::write_sie(sie | csr::SIE_STIE | csr::SIE_SSIE);
        azos_drv_irqchip::user_irq::hart_ready(cpu as u32);
    }

    /// The first tick for this hart (SBI `set_timer` / `stimecmp`).
    #[inline(always)]
    fn secondary_timer_init(&self, cpu: usize) {
        azos_drv_sys::timebase::set_next_tick(cpu as u32);
    }

    /// Nothing to publish: `kernel_main` on riscv64 does not wait for a
    /// per-hart online flag (the HSM `hart_start` return is its readback).
    #[inline(always)]
    fn secondary_publish_online(&self, _cpu: usize) {}

    /// The vDSO clock on riscv64: the watchdog tick count and `rdtime` in ms
    /// at the fixed `TIMER_FREQ`. No vDSO page under `no-mmu`.
    #[inline(always)]
    fn vdso_clock(&self) -> Option<(u64, u64)> {
        #[cfg(not(feature = "no-mmu"))]
        {
            let now = azos_drv_sys::timebase::now();
            Some((azos_actuation::watchdog::ticks(), now / (azos_drv_sys::timebase::TIMER_FREQ / 1000)))
        }
        #[cfg(feature = "no-mmu")]
        {
            None
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64's `ArchEntry` — SKELETON, matched to `entry/{riscv64,aarch64}/
//! arch_entry.rs`: the boot hooks, and the secondary-CPU steps the shared
//! `boot::smp::secondary_main` calls.

use azos_arch::ArchEntry;

/// The x86_64 boot sequence (`crate::ARCH_ENTRY`).
pub struct Entry;

impl ArchEntry for Entry {
    type Early = crate::EarlyBoot;

    fn early_boot(&self, hart_id: usize, fw_table: usize) -> crate::EarlyBoot {
        crate::boot_hooks::arch_early_boot(hart_id, fw_table)
    }

    fn map_late_mmio(&self) {
        crate::boot_hooks::arch_map_late_mmio()
    }

    fn wake_secondaries(&self, num_cpus: usize) {
        crate::boot_hooks::arch_wake_secondaries(num_cpus)
    }

    fn enter_scheduler(&self, hart_id: usize) -> ! {
        crate::boot_hooks::arch_enter_scheduler(hart_id)
    }

    /// Join the shootdown IPI set (x86 has no broadcast TLB invalidate).
    fn secondary_tlb_online(&self, _cpu: usize) {
        todo!("x86_64: secondary_tlb_online: add this CPU to the shootdown IPI mask")
    }

    /// This CPU's LAPIC: x2APIC enable (IA32_APIC_BASE), spurious vector,
    /// TPR 0; the IPI vector unmasked.
    fn secondary_irq_init(&self, _cpu: usize) {
        todo!("x86_64: secondary_irq_init: LAPIC x2APIC enable, SVR, TPR")
    }

    /// The LAPIC timer in TSC-deadline mode at the boot CPU's period.
    fn secondary_timer_init(&self, _cpu: usize) {
        todo!("x86_64: secondary_timer_init: LAPIC TSC-deadline tick")
    }

    /// The online flag the boot CPU's `wake_secondaries` waits on.
    fn secondary_publish_online(&self, _cpu: usize) {
        todo!("x86_64: secondary_publish_online: Release-store this CPU's online flag")
    }

    /// The vDSO clock: tick count and TSC in ms.
    fn vdso_clock(&self) -> Option<(u64, u64)> {
        todo!("x86_64: vdso_clock: ticks, rdtsc / (tsc_hz / 1000)")
    }
}

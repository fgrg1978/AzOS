// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 secondary-CPU wake (the `wake_secondaries` hook): PSCI
//! `CPU_ON` per DTB `cpu@` node, the online readback and the cross-core SGI
//! proof.

use core::sync::atomic::Ordering;
use azos_drv_sys::kprintln;

/// Start every secondary hart via PSCI `CPU_ON`, correct `NUM_ONLINE_CPUS`
/// down to the real count, rescue any stranded task, then (aarch64-only:
/// riscv64 has no equivalent proof) block on each secondary's own
/// `CORE_ONLINE` publish and prove a cross-core SGI round trip. Verbatim
/// cut from the former aarch64 `kernel_main`'s own body.
pub(crate) fn wake_secondaries(num_cpus: usize) {
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

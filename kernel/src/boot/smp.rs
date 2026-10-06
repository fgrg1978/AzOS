// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Secondary-hart Rust entry points, one per ISA (called from `boot.S`).

use crate::*;

/// Secondary-core entry point, called from `boot.S`'s
/// `_aarch64_secondary_entry` after that core's own MMU is already on
/// (`aarch64_secondary_mmu_init`) — the aarch64 counterpart of riscv64's
/// `smp_secondary_start` (this file, `#[cfg(target_arch = "riscv64")]`):
/// per-core interrupt controller + timer bring-up, publish this core online,
/// unmask IRQs, then park. Never returns; the first tick on this core
/// reaches `aarch64_trap_resched` -> `schedule()` with no current task set
/// for this core yet, which dispatches the idle task `kernel_main` pinned
/// here — exactly the same "raw entry loop is never re-entered after the
/// first dispatch" shape riscv64's own `smp_secondary_start` documents.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_smp_secondary_start(hart_id: usize) -> ! {
    use azos_arch::{gic, Cpu, Interrupts, ARCH};

    // Per-PE GIC: find THIS PE's own redistributor frame by its own MPIDR
    // affinity (never assume frame index == hart id — `gic::
    // find_redistributor`'s own doc), wake it, enable the CPU interface,
    // park the generic timer in a known state. `MAX_HARTS` bounds the walk
    // to exactly as many frames `kernel_main`'s Phase 2 block mapped
    // (`gic::GICR_STRIDE * MAX_HARTS`) — walking further would read
    // unmapped Device space.
    let rd_base = azos_arch::smp::secondary_init(MAX_HARTS);
    gic::enable_ppi_at(rd_base, 0);  // SGI 0 — this kernel's cross-core IPI
    gic::enable_ppi_at(rd_base, entry::aarch64::TIMER_PPI_ENABLED); // EL1 virtual timer, PPI 27

    // CNTKCTL_EL1 is per-PE — the boot CPU's own `enable_el0_cntvct` call
    // (`kernel_main`'s Phase 2 block) does not cover this core. Without
    // this, a ring-3 task migrated here (`aarch64_migrate_probe_task`
    // above proves migration happens) traps the first time it reads
    // CNTVCT_EL0 on this specific core, even though it worked fine before
    // the migration.
    azos_arch::sysregs::enable_el0_cntvct();
    // Wave 15 (TRACE): this core's own tracer set-up (its cycle counter, when
    // that is the timestamp source); nothing otherwise.
    azos_trace::cpu_online();

    // Arm this core's own periodic tick at the SAME period the boot CPU
    // computed from the live `CNTFRQ_EL0` (`entry::aarch64::TICK_PERIOD`,
    // set once by `arm_periodic_timer` in `kernel_main`'s Phase 2 block).
    // `CNTV_CTL_EL0`/`CNTV_CVAL_EL0` are banked per-PE — nothing here is
    // shared with the boot CPU's own timer state.
    let period = entry::aarch64::TICK_PERIOD.load(Ordering::Relaxed);
    if period != 0 {
        entry::aarch64::arm_periodic_timer(period);
    }

    // Publish this core online for kernel_main's readback loop. MPIDR +
    // hart-id first (Relaxed — cheap, and ordered by the Release store
    // below regardless), CORE_ONLINE last (Release): the boot CPU's
    // Acquire load of CORE_ONLINE is what makes every store before it here
    // visible in one step, not a promise carried by the individual stores'
    // own orderings — see `entry::aarch64::CORE_ONLINE`'s doc.
    let mpidr_raw = azos_arch::mpidr::read_mpidr().raw;
    if let Some(slot) = entry::aarch64::CORE_MPIDR.get(hart_id) {
        slot.store(mpidr_raw, Ordering::Relaxed);
    }
    if let Some(slot) = entry::aarch64::CORE_HART_ID.get(hart_id) {
        // Re-derived through the SAME call the scheduler itself uses
        // (`current_cpu_id()`, i.e. a fresh `MRS TPIDR_EL1`) rather than
        // trusting the `hart_id` argument — canary (b) (drop `boot.S`'s
        // `msr TPIDR_EL1, x20`) must fail THIS readback, not merely fail to
        // update it.
        slot.store(azos_sched::smp::current_cpu_id() as u64, Ordering::Relaxed);
    }

    ARCH.enable_all();

    if let Some(slot) = entry::aarch64::CORE_ONLINE.get(hart_id) {
        slot.store(true, Ordering::Release);
    }

    loop {
        ARCH.wfi();
    }
}

/// Secondary CPU entry point.
///
/// Called from `_secondary_start` in boot.S after OpenSBI starts this hart via HSM.
/// Sets up the timer interrupt and enters a WFI idle loop.
/// The first timer interrupt on this CPU will call `schedule()`, which picks up
/// the tasks assigned to this CPU during `kernel_main`.
#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
pub extern "C" fn smp_secondary_start(hart_id: usize) -> ! {
    // boot.S sets tp = hart_id via `mv tp, a0` before calling here.
    // Re-establish it in case any early Rust call clobbered tp.
    unsafe { core::arch::asm!("mv tp, {}", in(reg) hart_id, options(nostack, nomem)); }

    // boot.S range-checked us against MAX_HARTS — that guards the stack and
    // trap-vector slots, which are `[_; MAX_HARTS]`. The scheduler arrays
    // are `[_; MAX_CPUS]` (smaller), and `wake_harts` never *starts* a hart
    // past MAX_CPUS — but a hart can arrive here without us starting it
    // (firmware HSM state, a resumed hart, a future warm-boot path). Park it
    // before it enables the timer: one tick later it would be inside
    // `schedule()` indexing `PER_CPU[hart_id]` out of bounds. Interrupts are
    // still off (boot.S cleared sie), so parking here is final.
    if hart_id >= MAX_CPUS {
        kprintln!("[SMP] hart {} >= MAX_CPUS {} — parking (no PER_CPU slot)",
                  hart_id, MAX_CPUS);
        loop { azos_arch::cpu::wfi(); }
    }
    azos_trace::cpu_online();

    // Also noted by the waker before `hart_start`; a hart that arrives here
    // without being started (see above) must still be in the shootdown's scan
    // before it can publish a root.
    azos_arch::tlb::note_hart_online(hart_id);

    // Enable timer AND software interrupts (boot.S cleared sie to 0).
    //
    // **`SIE_SSIE` was missing here, and that is the whole K-C15 doorbell.**
    // The boot hart enables `SEIE | SSIE` in `kernel_main`; this path — every
    // secondary — enabled only the timer. A cross-hart wake therefore set
    // `sip.SSIP` on a hart whose `sie.SSIE` was clear, so the software
    // interrupt never trapped and `INT_SOFTWARE_S` never ran. Measured:
    // **222 doorbells sent, 0 received.**
    //
    // The consequence is not that wakes were lost — the timer tick rescues
    // them — it is that a wake targeting a secondary hart waited for the tick.
    // That is exactly the `ipc-rt` worst case vsbench measured:
    // 5–15 ms against Linux's 276–417 us, gone at `-smp 1` (hart 0 only, which
    // has SSIE), and shrinking 10x when the tick goes to 1000 Hz.
    //
    // It hid because the median stayed healthy: most wakes land on a hart that
    // is about to reschedule anyway, so only the unlucky ones pay a tick.
    //
    // `SEIE` too (wave 10 IRQ5): a ring-3 line is routed to the hart its
    // binding task is pinned to (`azos_drv_irqchip::user_irq`), so every hart
    // claims external interrupts. This hart's own controller state first:
    // PLIC, its S-context threshold 0 (OpenSBI leaves 7, "mask all"; the
    // global priorities were set once by the boot hart and are NOT rewritten
    // here — they hold ring 3's masks); AIA, its IMSIC file (delivery on,
    // threshold 0) and the wired identities (`user_irq::hart_ready`). The
    // context's enable bits are only ever set by a ring-3 route to this hart:
    // the kernel's own lines stay on the boot hart, so nothing arrives here
    // that this hart's handler does not claim and complete itself.
    azos_drv_irqchip::irqchip::init(hart_id as u32);
    let sie = csr::read_sie();
    #[cfg(not(feature = "irq-secondary-seie-canary"))]
    csr::write_sie(sie | csr::SIE_STIE | csr::SIE_SSIE | csr::SIE_SEIE);
    // Canary: the secondary entry as it was, SEIE clear. A ring-3 line routed
    // here is never taken: captest's first delivery times out.
    #[cfg(feature = "irq-secondary-seie-canary")]
    csr::write_sie(sie | csr::SIE_STIE | csr::SIE_SSIE);
    azos_drv_irqchip::user_irq::hart_ready(hart_id as u32);

    // Set the first timer tick for this CPU.
    azos_drv_sys::timebase::set_next_tick(hart_id as u32);

    // Enable global S-mode interrupts.
    azos_arch::ARCH.enable_all();

    // WFI loop — timer interrupt will call schedule() → pick first task for this CPU.
    // Re-set tp = hart_id on every iteration: SBI calls (set_next_tick above) and
    // Rust functions inside the timer ISR are allowed to use tp as a scratch register
    // (RISC-V caller-saved).  The timer fires while wfi is executing; at that instant
    // tp must equal hart_id so current_cpu_id() returns the correct CPU index in schedule().
    loop {
        unsafe { core::arch::asm!("mv tp, {}", in(reg) hart_id, options(nostack, nomem)); }
        azos_arch::cpu::wfi();
    }
}

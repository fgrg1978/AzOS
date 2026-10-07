// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The secondary-CPU Rust entry, one for every ISA (called from `boot.S`).
//!
//! The skeleton is shared; what differs per ISA is an [`ArchEntry`] hook
//! (`kernel/src/entry/<isa>/arch_entry.rs`), named for the step it performs.
//! Divergences that used to hide in two copies of this function, and where
//! each one went:
//!
//! * the "not a possible CPU" park ran on riscv64 only; it now runs on both
//!   (aarch64's boot.S parks a PE with no stack, but a PE inside the stack
//!   table and outside the possible mask reached the scheduler);
//! * riscv64 notes the hart in the TLB shootdown's scan set, aarch64 does
//!   not (broadcast `TLBI ...IS`): [`ArchEntry::secondary_tlb_online`];
//! * riscv64 rewrites `tp` on every idle iteration, aarch64 did not: both do
//!   now (`set_percpu_base`, one register write per wake of a loop that only
//!   runs until the first dispatch);
//! * aarch64 published `CORE_ONLINE` AFTER unmasking interrupts, so a tick
//!   taken in between dispatched this core's idle task and the store never
//!   ran: publication now precedes `enable_all` on both. A wake sent in that
//!   window stays pending and is taken at `enable_all`.

use crate::*;
use azos_arch::{ArchEntry, Cpu, Interrupts, ARCH};

/// Secondary-CPU entry point, the ONE symbol both `boot.S` files call once
/// this CPU has a stack, its trap vector and (aarch64) its MMU. Never
/// returns: the first tick on this CPU reaches `schedule()` with no current
/// task, which dispatches the idle task `kernel_main` pinned here, and this
/// raw loop is never re-entered after that first dispatch.
#[unsafe(no_mangle)]
pub extern "C" fn secondary_main(hart_id: usize) -> ! {
    // boot.S already put the per-CPU base (the hart id) in place; set it
    // again in case an early Rust call clobbered it (riscv64's `tp` is an
    // ordinary register to the ABI).
    ARCH.set_percpu_base(hart_id);

    // boot.S range-checked us against MAX_HARTS (Kconfig `NR_CPUS`), which
    // guards the stack and trap-vector slots. A CPU below that ceiling but
    // outside the possible mask (above the firmware's count) has no per-CPU
    // area, and `wake_secondaries` never starts one — but a CPU can arrive
    // here without us starting it (firmware state, a resumed CPU, a future
    // warm-boot path). Park it before it enables the timer: one tick later
    // it would be inside `schedule()` reaching for an area it does not have.
    // Interrupts are still masked (boot.S), so parking here is final.
    if !azos_percpu::cpu_possible(hart_id) {
        kprintln!("[SMP] hart {} is not a possible CPU (nr_cpu_ids {}) — parking (no per-CPU area)",
                  hart_id, azos_percpu::nr_cpu_ids());
        loop { ARCH.wfi(); }
    }
    // This CPU's own tracer set-up (its cycle counter, when that is the
    // timestamp source); nothing otherwise.
    azos_trace::cpu_online();

    ARCH_ENTRY.secondary_tlb_online(hart_id);
    ARCH_ENTRY.secondary_irq_init(hart_id);
    ARCH_ENTRY.secondary_timer_init(hart_id);
    ARCH_ENTRY.secondary_publish_online(hart_id);

    ARCH.enable_all();

    // The first tick calls `schedule()`, which picks the tasks `kernel_main`
    // assigned to this CPU. The per-CPU base is re-set on every iteration:
    // on riscv64 SBI calls and Rust code in the timer ISR may use `tp` as a
    // scratch register, and the tick must find it equal to the hart id for
    // `current_cpu_id()`.
    loop {
        ARCH.set_percpu_base(hart_id);
        ARCH.wfi();
    }
}

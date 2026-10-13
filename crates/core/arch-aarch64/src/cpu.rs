// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-CPU identity + low-level idle on ARMv8-A.

/// Read `TPIDR_EL1` and return this PE's logical hart index.
///
/// U10-4 (audit): this used to decode `MPIDR_EL1` directly
/// (`Aff0 | Aff1 << 8 | Aff2 << 16`), a SECOND hart-identity source
/// disagreeing with the one the scheduler actually indexes by —
/// `crates/core/sched/src/smp.rs::current_cpu_id()` reads `TPIDR_EL1`, the
/// logical id `boot.S` publishes (`msr TPIDR_EL1, x20`, both the primary
/// and secondary paths, before any Rust runs — see `entry/aarch64/asm/
/// boot.S`). On QEMU virt's flat `-smp N` the two values coincide (Aff1/
/// Aff2 are 0, so the MPIDR decode happens to equal the logical index),
/// which hid the divergence; on any topology with Aff1 != 0 the old decode
/// returned a value >= 256, and every caller keying a fixed-size per-hart
/// table by `hart_id()` — `crates/core/sync::preempt::slot()` (`SLOTS = 8`),
/// `domains/robot/safety-core::txn`/`watchdog`, `crates/core/ipc::fast_ipc`/`trace`,
/// `crates/core/syscall::dispatch`, `kernel::panic` — silently fell outside the
/// table's range on that hart (`preempt::slot()` returns `None`, i.e.
/// preemption control OFF; the others index out of range or misfile the
/// diagnostic).
///
/// Reading `TPIDR_EL1` here instead makes this crate's `hart_id()` and
/// `crates/core/sched`'s `current_cpu_id()` the SAME read of the SAME register —
/// one hart-identity source on this ISA, matching riscv64 (`tp`, read by
/// both). The raw `MPIDR_EL1` decode is still available, for topology
/// purposes only, via [`crate::mpidr::Mpidr::read`].
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn hart_id() -> usize {
    let id: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, TPIDR_EL1",
            out(reg) id,
            options(nomem, nostack, preserves_flags),
        );
    }
    id as usize
}

/// Wait For Interrupt — low-power idle. Maps directly to the ARM
/// `WFI` instruction.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn wfi() {
    unsafe {
        core::arch::asm!(
            "wfi",
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read the monotonic tick counter — `CNTVCT_EL0`, the generic timer's
/// virtual count register.
///
/// Free-function twin of `Cpu::now_ticks`, matching `arch-riscv64`'s `cpu`
/// module so the `azos_arch` facade exposes the same name on both ISAs.
/// Same timebase `set_timer_deadline` writes `CNTV_CVAL_EL0` against.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn now_ticks() -> u64 {
    crate::sysregs::read_cntvct_el0()
}

/// Read the generic timer's live counter frequency (`CNTFRQ_EL0`), set by
/// firmware at boot. Lets a boot path cross-check a compile-time constant
/// (`azos_drv_base::platform::hw::TIMER_FREQ`) against the real
/// register, the same role `kernel/src/main.rs` already gives the RISC-V
/// `TIMER_FREQ` vs the parsed DTB on that ISA.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn timer_freq_hw() -> u64 {
    crate::sysregs::read_cntfrq_el0()
}

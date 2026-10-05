// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Halt the CPU until an interrupt arrives.
#[inline(always)]
pub fn wfi() {
    unsafe {
        core::arch::asm!("wfi");
    }
}

/// Read the hart ID from the tp register.
#[inline(always)]
pub fn hart_id() -> usize {
    let id: usize;
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) id);
    }
    id
}

/// Read the monotonic tick counter — `rdtime`, the unprivileged read of the
/// `time` CSR.
///
/// The free-function twin of [`crate::api_impl::Riscv64`]'s
/// `Cpu::now_ticks`, in the same shape `hart_id` and `wfi` above have: the
/// kernel reaches these through the `azos_arch` facade without
/// constructing a trait object.
///
/// Units are platform-defined; the kernel needs only monotonicity, and this is
/// deliberately the same timebase `set_timer` programs against, so a deadline
/// computed from a reading needs no conversion.
#[inline(always)]
pub fn now_ticks() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    t
}

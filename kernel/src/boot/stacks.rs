// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot-stack depth report (paint pattern written by `boot.S`), and aarch64's
//! interrupt-stack arming and its boot-time intactness check.

use crate::*;

/// Pattern boot.S writes over the boot stack and its red zone before the first
/// call. Must match the `li t2` value there.
const BOOT_STACK_PAINT: u64 = 0x5354_414B_5354_414B;

/// How deep `kernel_main` went into the boot stack, and whether it went past
/// it: the lowest word that no longer holds `BOOT_STACK_PAINT` is the deepest
/// write. One in the red zone means the stack overflowed; `FAILED:` in that
/// line fails every gate scenario. Called at the end of kernel_main, before
/// the boot hart enables its timer interrupt and leaves this stack for good.
///
/// **WHY.** With the stack at the top of the RAM window, an overflow wrote into
/// pages the kernel heap covers and nothing noticed. Directly under `.bss` it
/// lands on the last statics (the per-hart preemption counters, today): a hart
/// that reads a nonzero depth refuses every sleep and spins.
pub(crate) fn boot_stack_report() {
    let redzone = unsafe { &_stack_redzone as *const u8 as usize };
    let start   = unsafe { &_stack_start   as *const u8 as usize };
    let end     = unsafe { &_stack_end     as *const u8 as usize };
    let deepest = (redzone..end)
        .step_by(8)
        .find(|&a| unsafe { core::ptr::read_volatile(a as *const u64) } != BOOT_STACK_PAINT)
        .unwrap_or(end);
    if deepest == redzone {
        // The bottom word is written: the overflow went through the whole red
        // zone and into .bss, so how far is unknown.
        azos_drv_sys::kerr!("[MM] Boot stack FAILED: overflowed through its {} KiB red zone ({} KiB stack)",
            (start - redzone) >> 10, (end - start) >> 10);
    } else if deepest < start {
        azos_drv_sys::kerr!("[MM] Boot stack FAILED: overflowed {} KiB into its {} KiB red zone ({} KiB stack)",
            (start - deepest) >> 10, (start - redzone) >> 10, (end - start) >> 10);
    } else {
        kprintln!("[MM] Boot stack: {} of {} KiB used", (end - deepest) >> 10, (end - start) >> 10);
    }
}

/// Write the magic word at the bottom of every IRQ-stack slot and publish
/// hart 0's `[base, top)` to `entry::aarch64::set_irq_stack_bounds` — both
/// BEFORE IRQs are unmasked, same ordering constraint riscv64's
/// `irq_stacks_arm()` documents (a hart that took its first interrupt
/// before this ran would be checking an unpublished bound / an
/// uninitialised magic word).
#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_irq_stacks_arm() {
    for hart in 0..MAX_HARTS {
        unsafe {
            let base = (&raw const aarch64_irq_stacks).add(hart * AARCH64_IRQ_STACK_SIZE) as *mut u64;
            base.write_volatile(AARCH64_IRQ_STACK_MAGIC);
        }
    }
    let base0 = (&raw const aarch64_irq_stacks) as usize;
    entry::aarch64::set_irq_stack_bounds(base0, base0 + AARCH64_IRQ_STACK_SIZE);
}

/// True while hart 0's IRQ stack still carries its magic word — the
/// aarch64 analogue of riscv64's `irq_stack_intact`, checked the same way
/// (after the tick-wait loop, not from inside a handler).
#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_irq_stack_intact() -> bool {
    unsafe { (&raw const aarch64_irq_stacks as *const u64).read_volatile() == AARCH64_IRQ_STACK_MAGIC }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64's saved-context path (Kconfig `CPU_IDLE_POWERDOWN`, `CPU_HOTPLUG`):
//! a PE that loses its context (a power-down `CPU_SUSPEND`, or a stop the
//! kernel will undo) keeps it in its [`SaveArea`] and comes back through
//! `_aarch64_secondary_entry`, the entry every secondary PE boots through.
//!
//! * `azos_cpu_save_run(area, finisher, arg)`: store `x19..x29`, `lr`, `sp`,
//!   `SP_EL0`, `TTBR0_EL1` and the EL0 thread registers in `area`, clean the
//!   area to the point of coherency (a power-down loses the PE's caches), call
//!   `finisher(arg)` (the firmware call that takes the PE away) and return its
//!   value, which is an error: when the call works the PE does not come back
//!   here.
//! * `_aarch64_secondary_entry` (boot.S), once the PE has its EL, stack, MMU
//!   and signed returns, asks `azos_cpu_resume_check(cpu)` for a slot; a slot
//!   goes to `azos_cpu_resume_restore`, no slot to `secondary_main` as ever.
//! * `azos_cpu_resume_restore(area)`: reinstall the saved `TTBR0_EL1` (the entry
//!   has put the kernel table there; the idle task may run on another) with a
//!   local TLB invalidate, the thread registers, then `sp`, `lr` and the
//!   registers the AAPCS64 keeps, and return `RESUMED` from `azos_cpu_save_run`.
//!
//! The firmware starts the PE with the MMU off at the PHYSICAL entry given to
//! `CPU_SUSPEND` (`virt_to_phys` of the secondary entry), like a `CPU_ON`
//! target. The vector base, `TPIDR_EL1`, `CPACR_EL1`, the translation control
//! registers and the signed-return keys are the entry's, not the slot's.

use azos_arch::firmware::SaveArea;
use core::mem::{offset_of, size_of};

/// The path is built: a build with neither option never asks for a slot and
/// links no slot table.
const WANTED: bool = azos_limits::CPU_HOTPLUG || azos_limits::CPU_IDLE_POWERDOWN;

/// One slot per possible PE. Referenced only from [`install`], so not linked
/// when [`WANTED`] is false.
static mut CPU_SAVE: [SaveArea; crate::MAX_HARTS] = [const { SaveArea::EMPTY }; crate::MAX_HARTS];

core::arch::global_asm!(
    r#"
.pushsection .text.azos_cpu_resume, "ax"
.p2align 2
.globl azos_cpu_save_run
azos_cpu_save_run:                       // x0 = area, x1 = finisher, x2 = arg
    hint    #34                          // bti c
    add     x9, x0, #{x}
    stp     x19, x20, [x9]
    stp     x21, x22, [x9, #16]
    stp     x23, x24, [x9, #32]
    stp     x25, x26, [x9, #48]
    stp     x27, x28, [x9, #64]
    str     x29, [x9, #80]
    str     x30, [x0, #{lr}]
    mov     x10, sp
    str     x10, [x0, #{sp}]
    mrs     x10, sp_el0
    str     x10, [x0, #{sp_el0}]
    mrs     x10, ttbr0_el1
    str     x10, [x0, #{ttbr0}]
    mrs     x10, tpidr_el0
    str     x10, [x0, #{tpidr_el0}]
    mrs     x10, tpidrro_el0
    str     x10, [x0, #{tpidrro_el0}]
    mrs     x10, contextidr_el1
    str     x10, [x0, #{contextidr}]
    // Clean the slot to the point of coherency: the PE's caches are lost in a
    // power-down, and the resume reads it back.
    mrs     x13, ctr_el0
    ubfx    x13, x13, #16, #4            // CTR_EL0.DminLine: log2(words)
    mov     x14, #4
    lsl     x13, x14, x13                // line size in bytes
    sub     x14, x13, #1
    bic     x12, x0, x14                 // first line
    add     x11, x0, #{size}
1:  dc      civac, x12
    add     x12, x12, x13
    cmp     x12, x11
    b.lo    1b
    dsb     sy
    stp     x29, x30, [sp, #-16]!
    mov     x9, x1
    mov     x0, x2
    blr     x9                           // finisher(arg): returns only on failure
    ldp     x29, x30, [sp], #16
    ret

.globl azos_cpu_resume_restore
azos_cpu_resume_restore:                 // x0 = area; MMU on, on the boot stack
    ldr     x9, [x0, #{ttbr0}]
    msr     ttbr0_el1, x9
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    ldr     x9, [x0, #{sp_el0}]
    msr     sp_el0, x9
    ldr     x9, [x0, #{tpidr_el0}]
    msr     tpidr_el0, x9
    ldr     x9, [x0, #{tpidrro_el0}]
    msr     tpidrro_el0, x9
    ldr     x9, [x0, #{contextidr}]
    msr     contextidr_el1, x9
    ldr     x9, [x0, #{sp}]
    mov     sp, x9
    ldr     x30, [x0, #{lr}]
    add     x9, x0, #{x}
    ldp     x19, x20, [x9]
    ldp     x21, x22, [x9, #16]
    ldp     x23, x24, [x9, #32]
    ldp     x25, x26, [x9, #48]
    ldp     x27, x28, [x9, #64]
    ldr     x29, [x9, #80]
    movn    x0, #0x8000, lsl #48         // RESUMED = isize::MAX
    ret
.popsection
"#,
    x = const offset_of!(SaveArea, x),
    lr = const offset_of!(SaveArea, lr),
    sp = const offset_of!(SaveArea, sp),
    sp_el0 = const offset_of!(SaveArea, sp_el0),
    ttbr0 = const offset_of!(SaveArea, ttbr0),
    tpidr_el0 = const offset_of!(SaveArea, tpidr_el0),
    tpidrro_el0 = const offset_of!(SaveArea, tpidrro_el0),
    contextidr = const offset_of!(SaveArea, contextidr),
    size = const size_of::<SaveArea>(),
);

// `RESUMED` is built in the asm as `isize::MAX`.
const _: () = assert!(azos_arch::firmware::RESUMED == isize::MAX);

/// boot.S's question: the slot `cpu` must restore, or null.
#[unsafe(no_mangle)]
pub extern "C" fn azos_cpu_resume_check(cpu: usize) -> *mut SaveArea {
    if WANTED { azos_arch::firmware::resume_area(cpu) } else { core::ptr::null_mut() }
}

/// A PE is back: its interrupt controller state and its timer, as at secondary
/// start (`crate::boot::smp::secondary_hw_init`).
fn resume_hook(cpu: usize) {
    crate::boot::smp::secondary_hw_init(cpu);
}

/// The entry reads the boot stack with the MMU off and then on, so no stale
/// cacheable line of an earlier life may be left under it: clean and invalidate
/// the PE's boot stack, as `wake_secondaries` does for a first start.
fn prepare(cpu: usize) {
    let top = crate::AZOS_SECONDARY_SP[cpu].load(core::sync::atomic::Ordering::Relaxed);
    if top != 0 {
        let stack = azos_mm::addr::phys_to_virt(top - crate::SECONDARY_STACK_SIZE);
        // SAFETY: the PE's own boot stack, not in use while its idle task runs.
        unsafe { azos_arch::cache::dcache_clean_and_invalidate(stack, crate::SECONDARY_STACK_SIZE) };
    }
}

/// Give the arch crate the resume entry (the secondary entry's physical
/// address), the hooks and the slots. Boot CPU, before the idle states are used
/// and before a PE can be taken offline.
pub(crate) fn install() {
    if !WANTED {
        return;
    }
    unsafe extern "C" {
        fn _aarch64_secondary_entry();
    }
    let entry = azos_mm::addr::virt_to_phys(_aarch64_secondary_entry as *const () as usize);
    // SAFETY: the table is ours for the life of the kernel and only the arch
    // crate and the asm above touch it.
    unsafe {
        azos_arch::firmware::set_resume(entry as u64, resume_hook, prepare, &raw mut CPU_SAVE as *mut SaveArea, crate::MAX_HARTS)
    };
}

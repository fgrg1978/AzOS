// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64's saved-context path (Kconfig `CPU_IDLE_POWERDOWN`, `CPU_HOTPLUG`):
//! a hart that loses its context (a non-retentive `hart_suspend`, or a stop the
//! kernel will undo) keeps it in its [`SaveArea`] and comes back through
//! `_secondary_start`, the entry every secondary hart boots through.
//!
//! * `azos_cpu_save_run(area, finisher, arg)`: store `ra`, `sp`, `gp`, `tp`,
//!   `s0..s11` and `satp`, `stvec`, `sscratch`, `sstatus` in `area`, call
//!   `finisher(arg)` (the firmware call that takes the hart away) and return its
//!   value, which is an error: when the call works the hart does not come back
//!   here.
//! * `_secondary_start` (boot.S), once it has a stack and a trap vector, asks
//!   `azos_cpu_resume_check(hart)` for a slot; a slot goes to
//!   `azos_cpu_resume_restore`, no slot to `secondary_main` as ever.
//! * `azos_cpu_resume_restore(area)`: publish the saved root for the TLB
//!   shootdown (the context switch's order: before the `csrw`), install `satp`,
//!   `stvec`, `sscratch`, `sstatus`, reload the registers and return
//!   `RESUMED` from `azos_cpu_save_run`, to the caller that saved them.
//!
//! The hart runs at `satp = 0` until the `csrw`, at its physical addresses,
//! which are the kernel's virtual ones (the image is identity mapped), and the
//! stack it restores is mapped by the root it restores.

use azos_arch::firmware::SaveArea;
use core::mem::offset_of;

/// The path is built: a build with neither option never asks for a slot and
/// links no slot table.
const WANTED: bool = azos_limits::CPU_HOTPLUG || azos_limits::CPU_IDLE_POWERDOWN;

/// One slot per possible hart. Referenced only from [`install`], so not linked
/// when [`WANTED`] is false.
static mut CPU_SAVE: [SaveArea; crate::MAX_HARTS] = [const { SaveArea::EMPTY }; crate::MAX_HARTS];

core::arch::global_asm!(
    r#"
.pushsection .text.azos_cpu_resume, "ax"
.p2align 2
.globl azos_cpu_save_run
azos_cpu_save_run:                       # a0 = area, a1 = finisher, a2 = arg
    sd   ra, {ra}(a0)
    sd   sp, {sp}(a0)
    sd   gp, {gp}(a0)
    sd   tp, {tp}(a0)
    addi t1, a0, {s}
    sd   s0,  0(t1)
    sd   s1,  8(t1)
    sd   s2,  16(t1)
    sd   s3,  24(t1)
    sd   s4,  32(t1)
    sd   s5,  40(t1)
    sd   s6,  48(t1)
    sd   s7,  56(t1)
    sd   s8,  64(t1)
    sd   s9,  72(t1)
    sd   s10, 80(t1)
    sd   s11, 88(t1)
    csrr t0, satp
    sd   t0, {satp}(a0)
    csrr t0, stvec
    sd   t0, {stvec}(a0)
    csrr t0, sscratch
    sd   t0, {sscratch}(a0)
    csrr t0, sstatus
    sd   t0, {sstatus}(a0)
    fence rw, rw
    addi sp, sp, -16
    sd   ra, 8(sp)
    mv   t0, a1
    mv   a0, a2
    jalr t0                              # finisher(arg): returns only on failure
    ld   ra, 8(sp)
    addi sp, sp, 16
    ret

.globl azos_cpu_resume_restore
azos_cpu_resume_restore:                 # a0 = area; satp = 0, on the boot stack
    ld   tp, {tp}(a0)
    ld   t0, {satp}(a0)
    li   t1, {max_harts}
    bgeu tp, t1, 1f
    la   t1, AZOS_HART_SATP              # publish before the csrw (tlb.rs)
    slli t2, tp, 3
    add  t1, t1, t2
    sd   t0, 0(t1)
    fence rw, rw
1:  csrw satp, t0
    sfence.vma zero, zero
    ld   t0, {stvec}(a0)
    csrw stvec, t0
    ld   t0, {sscratch}(a0)
    csrw sscratch, t0
    ld   t0, {sstatus}(a0)
    csrw sstatus, t0
    ld   ra, {ra}(a0)
    ld   sp, {sp}(a0)
    ld   gp, {gp}(a0)
    addi t1, a0, {s}
    ld   s0,  0(t1)
    ld   s1,  8(t1)
    ld   s2,  16(t1)
    ld   s3,  24(t1)
    ld   s4,  32(t1)
    ld   s5,  40(t1)
    ld   s6,  48(t1)
    ld   s7,  56(t1)
    ld   s8,  64(t1)
    ld   s9,  72(t1)
    ld   s10, 80(t1)
    ld   s11, 88(t1)
    li   a0, -1
    srli a0, a0, 1                       # RESUMED = isize::MAX
    ret
.popsection
"#,
    ra = const offset_of!(SaveArea, ra),
    sp = const offset_of!(SaveArea, sp),
    gp = const offset_of!(SaveArea, gp),
    tp = const offset_of!(SaveArea, tp),
    s = const offset_of!(SaveArea, s),
    satp = const offset_of!(SaveArea, satp),
    stvec = const offset_of!(SaveArea, stvec),
    sscratch = const offset_of!(SaveArea, sscratch),
    sstatus = const offset_of!(SaveArea, sstatus),
    max_harts = const crate::MAX_HARTS,
);

// `RESUMED` is built in the asm as `isize::MAX`.
const _: () = assert!(azos_arch::firmware::RESUMED == isize::MAX);

/// boot.S's question: the slot `hart` must restore, or null.
#[unsafe(no_mangle)]
pub extern "C" fn azos_cpu_resume_check(hart: usize) -> *mut SaveArea {
    if WANTED { azos_arch::firmware::resume_area(hart) } else { core::ptr::null_mut() }
}

/// A hart is back: its interrupt controller state and its timer, as at secondary
/// start (`crate::boot::smp::secondary_hw_init`).
fn resume_hook(hart: usize) {
    crate::boot::smp::secondary_hw_init(hart);
}

/// Give the arch crate the resume entry (the secondary entry), the hook and the
/// slots. Boot CPU, before the idle states are used and before a hart can be
/// taken offline.
pub(crate) fn install() {
    if !WANTED {
        return;
    }
    unsafe extern "C" {
        fn _secondary_start();
    }
    let entry = _secondary_start as *const () as usize;
    // SAFETY: the table is ours for the life of the kernel and only the arch
    // crate and the asm above touch it.
    unsafe {
        azos_arch::firmware::set_resume(entry, resume_hook, &raw mut CPU_SAVE as *mut SaveArea, crate::MAX_HARTS)
    };
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64's saved-context path (Kconfig `CPU_HOTPLUG`): a CPU taken offline
//! keeps its context in its [`SaveArea`], halts, and comes back through
//! `_secondary_start` when `Boot::hart_start` starts it again.
//!
//! * `azos_cpu_save_run(area, finisher, arg)`: store `rbx`, `rbp`, `r12..r15`,
//!   `rsp` (which points at the return address) and CR3 in `area`, call
//!   `finisher(arg)` (the halt: it does not return) and return its value.
//! * `x86_64_secondary_entry` (entry/x86_64/smp.rs) loads the CPU's own tables
//!   as for any AP, then asks `azos_arch::smp::resume_area` for a slot: a slot
//!   goes to `azos_cpu_resume_restore`, no slot to `secondary_main` as ever.
//! * `azos_cpu_resume_restore(area)`: publish the saved CR3 for the TLB
//!   shootdown (before the write), install it, reload the registers and the
//!   stack and return `RESUMED` from `azos_cpu_save_run`.
//!
//! There is no deep-idle counterpart (Kconfig `CPU_IDLE_POWERDOWN` is not an
//! x86_64 option): HLT, MWAIT and C6 keep the architectural state in hardware.

use azos_arch::smp::SaveArea;
use core::mem::offset_of;

/// The path is built: a build without `CPU_HOTPLUG` never asks for a slot and
/// links no slot table.
pub(super) const WANTED: bool = azos_limits::CPU_HOTPLUG;

/// One slot per possible CPU. Referenced only from [`install`], so not linked
/// when [`WANTED`] is false.
static mut CPU_SAVE: [SaveArea; crate::MAX_HARTS] = [const { SaveArea::EMPTY }; crate::MAX_HARTS];

core::arch::global_asm!(
    r#"
.pushsection .text.azos_cpu_resume, "ax"
.code64
.globl azos_cpu_save_run
azos_cpu_save_run:                       // %rdi = area, %rsi = finisher, %rdx = arg
    endbr64
    movq %rbx, {rbx}(%rdi)
    movq %rbp, {rbp}(%rdi)
    movq %r12, {r12}(%rdi)
    movq %r13, {r13}(%rdi)
    movq %r14, {r14}(%rdi)
    movq %r15, {r15}(%rdi)
    movq %rsp, {rsp}(%rdi)
    movq %cr3, %rax
    movq %rax, {cr3}(%rdi)
    mfence
    subq $8, %rsp                        // 16-byte aligned at the call
    movq %rdx, %rdi
    callq *%rsi                          // finisher(arg): does not return
    addq $8, %rsp
    ret

.globl azos_cpu_resume_restore
azos_cpu_resume_restore:                 // %rdi = area; the AP's own tables are live
    movq {cpu}(%rdi), %rcx
    movq {cr3}(%rdi), %rax
    cmpq ${max_harts}, %rcx
    jae 1f
    leaq AZOS_HART_CR3(%rip), %rdx       // publish before the write (tlb.rs)
    movq %rax, (%rdx,%rcx,8)
    mfence
1:  movq %rax, %cr3
    movq {rbx}(%rdi), %rbx
    movq {rbp}(%rdi), %rbp
    movq {r12}(%rdi), %r12
    movq {r13}(%rdi), %r13
    movq {r14}(%rdi), %r14
    movq {r15}(%rdi), %r15
    movq {rsp}(%rdi), %rsp
    movabsq $0x7fffffffffffffff, %rax    // RESUMED = isize::MAX
    ret
.popsection
"#,
    cpu = const offset_of!(SaveArea, cpu),
    rbx = const offset_of!(SaveArea, rbx),
    rbp = const offset_of!(SaveArea, rbp),
    r12 = const offset_of!(SaveArea, r12),
    r13 = const offset_of!(SaveArea, r13),
    r14 = const offset_of!(SaveArea, r14),
    r15 = const offset_of!(SaveArea, r15),
    rsp = const offset_of!(SaveArea, rsp),
    cr3 = const offset_of!(SaveArea, cr3),
    max_harts = const crate::MAX_HARTS,
    options(att_syntax)
);

// `RESUMED` is built in the asm as `isize::MAX`.
const _: () = assert!(azos_arch::smp::RESUMED == isize::MAX);

unsafe extern "C" {
    /// Restore `area` and return `RESUMED` from the `azos_cpu_save_run` that
    /// saved it: it does not return here.
    pub(super) fn azos_cpu_resume_restore(area: *mut SaveArea) -> !;
}

/// A CPU is back: its interrupt controller state and its timer, as at secondary
/// start (`crate::boot::smp::secondary_hw_init`).
fn resume_hook(cpu: usize) {
    crate::boot::smp::secondary_hw_init(cpu);
}

/// Give the arch crate the hook and the slots. Boot CPU, before a CPU can be
/// taken offline.
pub(crate) fn install() {
    if !WANTED {
        return;
    }
    // SAFETY: the table is ours for the life of the kernel and only the arch
    // crate and the asm above touch it.
    unsafe { azos_arch::smp::set_resume(resume_hook, &raw mut CPU_SAVE as *mut SaveArea, crate::MAX_HARTS) };
}

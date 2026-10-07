// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// x86_64 context switch — SKELETON. Not assembled by any build; it lists
// what the real file must do, matched to kernel/src/entry/(riscv64, aarch64)/
// asm/context_switch.S.
//
// Exports:
//   context_switch(old: *mut TaskContext, new: *const TaskContext)
//                          the symbol azos_sched calls on every ISA
//
// Must:
//   1. Save the callee-saved registers (rbx, rbp, r12-r15) and RSP into
//      *old, at the offsets the scheduler's TaskContext declares
//      (crates/core/sched/src/task.rs: TASK_*_OFFSET per ISA).
//   2. Switch address space when the incoming task's root (TASK_SATP_OFFSET:
//      the CR3 word, PML4 PA | PCID) differs from the live CR3; with PCID,
//      set CR3 bit 63 to keep the incoming context's TLB entries.
//   3. Restore the incoming registers and RSP, update the TSS RSP0 and the
//      per-CPU kernel stack pointer the syscall entry uses.
//   4. FP/SIMD state is switched EAGERLY here: fpu::save_eager of the
//      outgoing task, fpu::restore_eager of the incoming one (XSAVEOPT /
//      XRSTOR). Never CR0.TS-lazy: that is the LazyFP leak (CVE-2018-3665).
//      aarch64's lazy path (entry/aarch64/fp_lazy.rs) is its own choice.
//   5. ret into the incoming task.

    .text
    .globl context_switch
context_switch:
    ud2

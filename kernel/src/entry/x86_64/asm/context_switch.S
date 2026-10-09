// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// x86_64 context switch (AT&T syntax), matched to kernel/src/entry/
// (riscv64, aarch64)/asm/context_switch.S.
//
// context_switch(old: *mut TaskContext [rdi], new: *const TaskContext [rsi])
//   the symbol azos_sched calls on every ISA; `old` is null when the
//   outgoing task is gone. TaskContext sits at offset 0 of Task, so the
//   Task offsets below apply to the same pointers.
//
//   1. FP/SIMD: if this CPU has ring-3 state live (%gs:fp_live), save it
//      into that area (x86_64_fp_save) unless the outgoing task is gone;
//      clear fp_live either way. The incoming task's state is loaded on its
//      way back to ring 3 (trap_entry.S), never by a #NM trap (fpu.rs:
//      LazyFP, CVE-2018-3665).
//   2. Save rbx, rbp, r12-r15, RSP and the return address (ra = pc) into
//      *old, then release the old task's `context_saving` byte: x86 stores
//      are not reordered with older stores, so the release follows every
//      save without a fence.
//   3. Restore the incoming callee-saved set and RSP.
//   4. CR3: the incoming task's root word (TASK_SATP_OFFSET: PML4 | PCID,
//      maybe bit 63 = keep the PCID's TLB entries) when it differs from the
//      live CR3 (bit 63 ignored: a read never returns it); task_satp 0 keeps
//      the live root (no kernel root is published yet). Published in
//      AZOS_HART_CR3[cpu] for the TLB shootdown scan, before the write. The kernel half is in every
//      PML4, so this code keeps running across the write.
//   5. Jump to the incoming PC.
//
// The kernel stack top for the next ring-3 entry (TSS.RSP0, %gs:kernel_rsp)
// is not written here: trap_return writes it on every return to ring 3,
// from the frame it returns through (riscv64's sscratch).
// `tp` is scheduler bookkeeping on x86_64 (the CPU id lives in GS): not
// touched, as on aarch64.

.equ CTX_RA,   {ctx_ra}
.equ CTX_SP,   {ctx_sp}
.equ CTX_RBX,  {ctx_rbx}
.equ CTX_RBP,  {ctx_rbp}
.equ CTX_R12,  {ctx_r12}
.equ CTX_R13,  {ctx_r13}
.equ CTX_R14,  {ctx_r14}
.equ CTX_R15,  {ctx_r15}
.equ CTX_PC,   {ctx_pc}
.equ TASK_SATP_OFFSET,       {task_satp_off}
.equ TASK_CTX_SAVING_OFFSET, {context_saving_off}
.equ PC_FP_LIVE, {pc_fp_live}

.section .text
.balign 16
.globl context_switch
context_switch:
    // 1. FP/SIMD
    movq %gs:PC_FP_LIVE, %rax
    testq %rax, %rax
    jz 1f
    movq $0, %gs:PC_FP_LIVE
    testq %rdi, %rdi
    jz 1f
    pushq %rdi
    pushq %rsi
    subq $8, %rsp                    // 16-byte aligned for the call
    movq %rax, %rdi
    call x86_64_fp_save
    addq $8, %rsp
    popq %rsi
    popq %rdi
1:  testq %rdi, %rdi
    jz restore_new_task

    // 2. save the outgoing task
    movq %rbx, CTX_RBX(%rdi)
    movq %rbp, CTX_RBP(%rdi)
    movq %r12, CTX_R12(%rdi)
    movq %r13, CTX_R13(%rdi)
    movq %r14, CTX_R14(%rdi)
    movq %r15, CTX_R15(%rdi)
    movq (%rsp), %rax                // the return address
    movq %rax, CTX_RA(%rdi)
    movq %rax, CTX_PC(%rdi)
    leaq 8(%rsp), %rax               // RSP after the return
    movq %rax, CTX_SP(%rdi)
    movb $0, TASK_CTX_SAVING_OFFSET(%rdi)

restore_new_task:
    // 3. restore the incoming task
    movq CTX_RBX(%rsi), %rbx
    movq CTX_RBP(%rsi), %rbp
    movq CTX_R12(%rsi), %r12
    movq CTX_R13(%rsi), %r13
    movq CTX_R14(%rsi), %r14
    movq CTX_R15(%rsi), %r15
    movq CTX_SP(%rsi), %rsp
    movq CTX_PC(%rsi), %rax

    // 4. address space
    movq TASK_SATP_OFFSET(%rsi), %rcx
    testq %rcx, %rcx
    jz ctx_skip_pt_switch            // no root published yet: keep this one
    movq %cr3, %rdx
    movq %rcx, %r8
    btrq $63, %r8                    // a CR3 read never returns the no-flush bit
    cmpq %rdx, %r8
    je ctx_skip_pt_switch
    // Publish before the write (tlb::publish's order): AZOS_HART_CR3[cpu],
    // the array the shootdown scans; the CPU id is %gs:0.
    movq %gs:0, %r9
    leaq AZOS_HART_CR3(%rip), %r10
    movq %rcx, (%r10,%r9,8)
    movq %rcx, %cr3
ctx_skip_pt_switch:
    // 5.
    jmp *%rax

.size context_switch, . - context_switch

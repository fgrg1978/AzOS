// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// x86_64 trap entry (AT&T syntax), matched to kernel/src/entry/(riscv64,
// aarch64)/asm/trap_entry.S.
//
// Exports:
//   x86_64_vector_stubs    256 stub addresses, one per IDT vector
//                          (cpu_init.rs builds the IDT from them)
//   syscall_entry          the `syscall` target (IA32_LSTAR)
//   x86_64_ret_to_user     first entry to ring 3 (riscv64 sret_to_user,
//                          aarch64 aarch64_ret_to_user): rdi = frame,
//                          rsi = CR3 word or 0
// Calls:
//   x86_64_trap_entry(&mut TrapFrame) -> cr3   kernel/src/entry/x86_64.rs
//   x86_64_trap_resched(&mut TrapFrame)        after an interrupt
//   x86_64_fp_restore()                        ring-3 return, nothing live
//
// The frame (TrapFrame, every offset injected from offset_of!):
//   [cr2][gs_saved][rax..r15][vector][error code][rip cs rflags rsp ss]
// The CPU aligns RSP to 16 before it pushes the iretq frame, and the frame
// is 192 bytes, so it starts 16-byte aligned and the asm calls Rust with
// RSP = frame.
//
// GS. The kernel GS base is this CPU's PerCpu (`%gs:0` = the CPU id). An
// entry from ring 3 (CS.RPL = 3 in the pushed frame) runs `swapgs` first;
// an entry from ring 0 does not. That rule fails only for an exception that
// can interrupt `syscall_entry` before its `swapgs`: NMI and #MC (they
// ignore IF), and #DF. Those three run on IST stacks through `ist_common`,
// which never trusts GS: it saves IA32_GS_BASE, loads this CPU's PerCpu
// from the word above its IST stack (cpu_init.rs), and puts the saved base
// back on the way out (Linux's paranoid entry). A nested #MC on the #MC
// stack would overwrite the outer frame; like Linux, that is not handled.
//
// Interrupts (vector >= 32) move to this CPU's interrupt stack
// (AZOS_IRQ_STACK_BASE[cpu], below its IST slices) unless already on it,
// run the handler, come back to the frame on the interrupted stack, and
// spend a pending reschedule there (x86_64_trap_resched), as riscv64 does.
//
// Return to ring 3 (trap_return): interrupts masked; CR3 when the
// dispatcher asked; the FP state when none is live; this task's kernel stack
// top (frame + size) into %gs:kernel_rsp (syscall_entry) and TSS.RSP0
// (interrupts), the sscratch of riscv64's trap_return; then `sysretq` when
// the frame is still what `syscall` saved (RIP = RCX, RFLAGS = R11, RIP
// canonical, no TF/RF; Kconfig X86_SYSRET), `iretq` otherwise. Spectre/MDS
// hygiene on the boundary (verw, IBRS) is the mitigation Kconfig's, not
// wired here yet.

.equ TF_SIZE,       {tf_size}
.equ TF_CR2,        {tf_cr2}
.equ TF_GS_SAVED,   {tf_gs_saved}
.equ TF_VECTOR,     {tf_vector}
.equ TF_RIP,        {tf_rip}
.equ TF_CS,         {tf_cs}
.equ TF_RFLAGS,     {tf_rflags}
.equ TF_RSP,        {tf_rsp}
.equ R_RAX,         {r_rax}
.equ R_RBX,         {r_rbx}
.equ R_RCX,         {r_rcx}
.equ R_RDX,         {r_rdx}
.equ R_RSI,         {r_rsi}
.equ R_RDI,         {r_rdi}
.equ R_RBP,         {r_rbp}
.equ R_R8,          {r_r8}
.equ R_R9,          {r_r9}
.equ R_R10,         {r_r10}
.equ R_R11,         {r_r11}
.equ R_R12,         {r_r12}
.equ R_R13,         {r_r13}
.equ R_R14,         {r_r14}
.equ R_R15,         {r_r15}
.equ PC_KERNEL_RSP, {pc_kernel_rsp}
.equ PC_USER_RSP,   {pc_user_rsp}
.equ PC_FP_LIVE,    {pc_fp_live}
.equ PC_TSS_RSP0,   {pc_tss_rsp0}
.equ SYSCALL_VEC,   {syscall_vector}
.equ FIRST_IRQ_VEC, {first_interrupt}
.equ USER_CS,       {user_cs}
.equ USER_DS,       {user_ds}
.equ IRQ_HANDLER_STACK, {irq_handler_stack}
.equ RFLAGS_TF_RF,  {rflags_tf_rf}
.equ USE_SYSRET,    {use_sysret}
.equ SMAP_CLAC,     {smap_clac}
.equ IA32_GS_BASE,  0xC0000101
.equ STUB_ALIGN,    16

// SMAP: interrupt and trap gates do not clear RFLAGS.AC, so a ring-3 task
// with AC set (or a trap inside a stac/clac window) would run the handler
// with SMAP open. `clac` first, once SMAP is on (X86_64_SMAP_ON, set by
// whoever sets CR4.SMAP: `clac` is #UD on a CPU without SMAP); `iretq`
// restores the interrupted AC. Kconfig X86_SMAP=n compiles it out.
// `syscall` needs none: FMASK clears AC.
.macro CLAC_IF_SMAP
.if SMAP_CLAC
    cmpb $0, X86_64_SMAP_ON(%rip)
    je 77f
    clac
77:
.endif
.endm

// rax..r15 into the frame at %rsp, and the two software words cleared.
.macro SAVE_REGS
    movq %rax, R_RAX(%rsp)
    movq %rbx, R_RBX(%rsp)
    movq %rcx, R_RCX(%rsp)
    movq %rdx, R_RDX(%rsp)
    movq %rsi, R_RSI(%rsp)
    movq %rdi, R_RDI(%rsp)
    movq %rbp, R_RBP(%rsp)
    movq %r8,  R_R8(%rsp)
    movq %r9,  R_R9(%rsp)
    movq %r10, R_R10(%rsp)
    movq %r11, R_R11(%rsp)
    movq %r12, R_R12(%rsp)
    movq %r13, R_R13(%rsp)
    movq %r14, R_R14(%rsp)
    movq %r15, R_R15(%rsp)
    movq $0, TF_CR2(%rsp)
    movq $0, TF_GS_SAVED(%rsp)
.endm

.macro RESTORE_REGS
    movq R_RAX(%rsp), %rax
    movq R_RBX(%rsp), %rbx
    movq R_RCX(%rsp), %rcx
    movq R_RDX(%rsp), %rdx
    movq R_RSI(%rsp), %rsi
    movq R_RDI(%rsp), %rdi
    movq R_RBP(%rsp), %rbp
    movq R_R8(%rsp),  %r8
    movq R_R9(%rsp),  %r9
    movq R_R10(%rsp), %r10
    movq R_R11(%rsp), %r11
    movq R_R12(%rsp), %r12
    movq R_R13(%rsp), %r13
    movq R_R14(%rsp), %r14
    movq R_R15(%rsp), %r15
.endm

.section .text
.globl syscall_entry
.globl x86_64_ret_to_user

// ── 256 stubs, STUB_ALIGN bytes apart ───────────────────────────────────────
// Each pushes a 0 error code when the CPU does not push one (so the frame
// has one shape), then its vector, and jumps to the common path; #DF, NMI
// and #MC go to ist_common. Vectors with a CPU error code: 8, 10-14, 17,
// 21, 29, 30 (azos_arch::idt::has_error_code; the IST indices the gates
// carry come from idt::ist_for in cpu_init.rs).
.balign STUB_ALIGN
x86_64_vector_entry:
.set vec, 0
.rept 256
    .balign STUB_ALIGN
.if (vec == 8) || ((vec >= 10) && (vec <= 14)) || (vec == 17) || (vec == 21) || (vec == 29) || (vec == 30)
.else
    pushq $0
.endif
    pushq $vec
.if (vec == 2) || (vec == 8) || (vec == 18)
    jmp ist_common
.else
    jmp trap_common
.endif
.set vec, vec + 1
.endr

// ── the common path ─────────────────────────────────────────────────────────
// Stack on arrival: vector, error code, rip, cs, rflags, rsp, ss.
trap_common:
    CLAC_IF_SMAP
    testb $3, 24(%rsp)               // the pushed CS: from ring 3?
    jz 1f
    swapgs
1:  subq $TF_VECTOR, %rsp
    SAVE_REGS
    cld                              // the C ABI's DF = 0
    movq %rsp, %rdi
    cmpq $FIRST_IRQ_VEC, TF_VECTOR(%rsp)
    jb trap_call_here                // an exception: stay on this stack

    // An interrupt: this CPU's interrupt stack, from AZOS_IRQ_STACK_BASE,
    // unless already on it (unsigned rsp - base < IRQ_HANDLER_STACK).
    movq %gs:0, %rax
    leaq AZOS_IRQ_STACK_BASE(%rip), %rcx
    movq (%rcx,%rax,8), %rcx
    testq %rcx, %rcx
    jz trap_irq_here                 // none armed: stay
    movq %rsp, %rdx
    subq %rcx, %rdx
    cmpq $IRQ_HANDLER_STACK, %rdx
    jb trap_irq_here                 // nested: keep the outer handler's
    leaq IRQ_HANDLER_STACK(%rcx), %rsp
    pushq %rdi                       // the frame, twice: RSP stays 16-aligned
    pushq %rdi
    call x86_64_trap_entry
    movq 8(%rsp), %rsp               // back onto the frame
    jmp trap_irq_out
trap_irq_here:
    call x86_64_trap_entry
trap_irq_out:
    movq %rax, %rbx                  // CR3 word (callee-saved across resched)
    // A timer or IPI only RAISES a flag; it is spent here, on the task's
    // own stack, where a context switch can save and resume it.
    movq %rsp, %rdi
    call x86_64_trap_resched
    jmp trap_return

trap_call_here:
    call x86_64_trap_entry
    movq %rax, %rbx
    // fall through

// ── trap_return: rsp = frame, rbx = CR3 word or 0 ───────────────────────────
trap_return:
    cli
    testq %rbx, %rbx
    jz 1f
    // Published for the TLB shootdown scan (AZOS_HART_CR3[cpu]), before
    // the write, as tlb::publish orders it.
    movq %gs:0, %rcx
    leaq AZOS_HART_CR3(%rip), %rdx
    movq %rbx, (%rdx,%rcx,8)
    movq %rbx, %cr3
1:  testb $3, TF_CS(%rsp)
    jz ret_kernel

    // Back to ring 3. The FP state first, if no task's is live here.
    cmpq $0, %gs:PC_FP_LIVE
    jne 2f
    call x86_64_fp_restore
2:  leaq TF_SIZE(%rsp), %rax         // this task's kernel stack top
    movq %rax, %gs:PC_KERNEL_RSP
    movq %rax, %gs:PC_TSS_RSP0
.if USE_SYSRET
    cmpq $SYSCALL_VEC, TF_VECTOR(%rsp)
    jne iret_user
    movq TF_RIP(%rsp), %rcx
    cmpq R_RCX(%rsp), %rcx           // RIP still what syscall left in RCX
    jne iret_user
    movq TF_RFLAGS(%rsp), %r11
    cmpq R_R11(%rsp), %r11           // RFLAGS still what syscall left in R11
    jne iret_user
    testq $RFLAGS_TF_RF, %r11
    jnz iret_user
    shrq $47, %rcx                   // canonical user RIP (CVE-2012-0217)
    jnz iret_user
    RESTORE_REGS                     // rcx = RIP, r11 = RFLAGS (checked)
    movq TF_RSP(%rsp), %rsp
    swapgs
    sysretq
.endif
iret_user:
    RESTORE_REGS
    addq $TF_RIP, %rsp
    swapgs
    iretq

ret_kernel:
    RESTORE_REGS
    addq $TF_RIP, %rsp
    iretq

// ── #DF, NMI, #MC: the paranoid path (see the header) ───────────────────────
ist_common:
    CLAC_IF_SMAP
    subq $TF_VECTOR, %rsp
    SAVE_REGS
    cld
    movl $IA32_GS_BASE, %ecx
    rdmsr
    shlq $32, %rdx
    orq %rdx, %rax
    movq %rax, TF_GS_SAVED(%rsp)
    movq TF_SIZE(%rsp), %rax         // this CPU's PerCpu, above the IST top
    movq %rax, %rdx
    shrq $32, %rdx
    wrmsr
    movq %rsp, %rdi
    call x86_64_trap_entry
    movl $IA32_GS_BASE, %ecx
    movq TF_GS_SAVED(%rsp), %rax
    movq %rax, %rdx
    shrq $32, %rdx
    wrmsr
    RESTORE_REGS
    addq $TF_RIP, %rsp
    iretq

// ── syscall_entry: build the same frame by hand ─────────────────────────────
// `syscall` left RIP in RCX, RFLAGS in R11, cleared the FMASK bits (IF
// among them), and did not switch stacks.
syscall_entry:
    swapgs
    movq %rsp, %gs:PC_USER_RSP
    movq %gs:PC_KERNEL_RSP, %rsp
    pushq $USER_DS                   // ss
    pushq %gs:PC_USER_RSP            // rsp
    pushq %r11                       // rflags
    pushq $USER_CS                   // cs
    pushq %rcx                       // rip
    pushq $0                         // error code
    pushq $SYSCALL_VEC               // vector: outside 0..255
    subq $TF_VECTOR, %rsp
    SAVE_REGS
    movq %rsp, %rdi
    call x86_64_trap_entry
    movq %rax, %rbx
    jmp trap_return

// ── x86_64_ret_to_user(frame, cr3): one ring-3 return sequence ──────────────
x86_64_ret_to_user:
    cli
    movq %rsi, %rbx
    movq %rdi, %rsp
    jmp trap_return

// ── the stub table ─────────────────────────────────────────────────────────
.section .rodata
.balign 8
.globl x86_64_vector_stubs
x86_64_vector_stubs:
.set vec, 0
.rept 256
    .quad x86_64_vector_entry + vec * STUB_ALIGN
.set vec, vec + 1
.endr

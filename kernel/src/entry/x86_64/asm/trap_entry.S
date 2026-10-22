// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// x86_64 trap entry (AT&T syntax), matched to kernel/src/entry/(riscv64,
// aarch64)/asm/trap_entry.S.
//
// Exports:
//   x86_64_vector_stubs    256 stub addresses, one per IDT vector
//                          (ext/cpu_init.rs builds the IDT from them)
//   syscall_entry          the `syscall` target (IA32_LSTAR)
//   x86_64_ret_to_user     first entry to ring 3 (riscv64 sret_to_user,
//                          aarch64 aarch64_ret_to_user): rdi = frame,
//                          rsi = CR3 word or 0
// Calls:
//   x86_64_trap_entry(&mut TrapFrame) -> cr3   kernel/src/entry/x86_64/trap.rs
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
// from the word above its IST stack (ext/cpu_init.rs), and puts the saved base
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
// canonical, no TF/RF; Kconfig X86_SYSRET), `iretq` otherwise. A
// `syscall` returns through `syscall_return` instead (Chain E commit 8,
// Kconfig SYSCALL_LEAN_ENTRY): rcx/r11 neither saved nor compared, unless the
// kernel rebuilt the frame (vector no longer SYSCALL_VEC), which takes
// `trap_return`. MDS hygiene on the boundary is `VERW_ON_EXIT` below; IBRS is
// not wired here.

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
.equ MIT_VERW,      {mit_verw}
.equ KERNEL_DS,     {kernel_ds}
// Chain E commit 8 (Kconfig SYSCALL_LEAN_ENTRY): the native syscall path
// (`syscall_entry` below), and its canary (`syscall-abi-canary`: the exit
// flips bit 0 of rbx when the call's rsi was SYSCALL_ABI_CANARY_A1).
.equ SYSCALL_LEAN,  {syscall_lean}
.equ TASK_REAP_OFFSET, {task_reap_off}  // Task::reap_on_resume (Chain E commit 9)
.equ RESUME_EXIT_CALL, {resume_exit_call}  // azos_sched::scheduler::IPC_FAST_EXIT_CALL
// Chain E cut 7 (Kconfig IPC_FASTPATH): the native path's branch for the two
// IPC fast calls, SYS_IPC_FAST_REPLY_ACCEPT (IPC_FAST_LO) and
// SYS_IPC_FAST_CALL_EP (IPC_FAST_LO + 2, asserted where these are bound).
.equ IPC_FAST_ENTRY,  {ipc_fast_entry}
.equ IPC_FAST_LO,     {ipc_fast_lo}
.equ SYSCALL_ABI_CANARY, {syscall_abi_canary}
.equ SYSCALL_ABI_CANARY_A1, {syscall_abi_canary_a1}
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

// MDS / TAA / RFDS (Kconfig X86_MIT_MDS_TAA, X86_MIT_RFDS): `verw` as the last
// thing before ring 3, when the boot decided the CPU needs it
// (X86_VERW_ON_EXIT, `azos_arch::ext::mitigations`; the microcode makes `verw` with a
// memory operand clear the CPU's buffers). Only flags are touched, so the
// registers `sysret` and `iretq` read are intact. Both choices `n` compile it out.
.macro VERW_ON_EXIT
.if MIT_VERW
    cmpb $0, X86_VERW_ON_EXIT(%rip)
    je 78f
    verw x86_verw_sel(%rip)
78:
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

// The `syscall` path's save and restore (SYSCALL_LEAN): every GPR but rcx
// and r11, which `syscall` itself overwrote with the return RIP and RFLAGS
// (both in the hardware part of the frame) and the contract clobbers.
.macro SAVE_REGS_SYSCALL
    movq %rax, R_RAX(%rsp)
    movq %rbx, R_RBX(%rsp)
    movq %rdx, R_RDX(%rsp)
    movq %rsi, R_RSI(%rsp)
    movq %rdi, R_RDI(%rsp)
    movq %rbp, R_RBP(%rsp)
    movq %r8,  R_R8(%rsp)
    movq %r9,  R_R9(%rsp)
    movq %r10, R_R10(%rsp)
    movq %r12, R_R12(%rsp)
    movq %r13, R_R13(%rsp)
    movq %r14, R_R14(%rsp)
    movq %r15, R_R15(%rsp)
    movq $0, TF_CR2(%rsp)
    movq $0, TF_GS_SAVED(%rsp)
.endm

.macro RESTORE_REGS_SYSCALL
    movq R_RAX(%rsp), %rax
    movq R_RBX(%rsp), %rbx
    movq R_RDX(%rsp), %rdx
    movq R_RSI(%rsp), %rsi
    movq R_RDI(%rsp), %rdi
    movq R_RBP(%rsp), %rbp
    movq R_R8(%rsp),  %r8
    movq R_R9(%rsp),  %r9
    movq R_R10(%rsp), %r10
    movq R_R12(%rsp), %r12
    movq R_R13(%rsp), %r13
    movq R_R14(%rsp), %r14
    movq R_R15(%rsp), %r15
.if SYSCALL_ABI_CANARY
    cmpq $SYSCALL_ABI_CANARY_A1, %rsi
    jne 78f
    xorq $1, %rbx                    // the canary: one callee-saved bit lost
78:
.endif
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
// 21, 29, 30 (azos_arch::trap::idt::has_error_code; the IST indices the gates
// carry come from trap::idt::ist_for in ext/cpu_init.rs).
.balign STUB_ALIGN
x86_64_vector_entry:
.set vec, 0
.rept 256
    .balign STUB_ALIGN
    .set stub_start, .
    endbr64                          // CFI landing pad (Kconfig X86_CET_IBT)
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
    // The table indexes the stubs by STUB_ALIGN: `.org` pads this one to its
    // slot and is an assembler error if the stub (pad included) outgrew it.
    .org stub_start + STUB_ALIGN, 0xcc
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
    VERW_ON_EXIT
    swapgs
    sysretq
.endif
iret_user:
    RESTORE_REGS
    addq $TF_RIP, %rsp
    VERW_ON_EXIT
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
    endbr64                          // CFI landing pad (Kconfig X86_CET_IBT)
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
.if SYSCALL_LEAN
    SAVE_REGS_SYSCALL
    movq %rsp, %rdi
    // Only a `syscall` reaches here, so no `x86_64_trap_entry` decode: the
    // syscall's own entry, with the trap entry's guards.
.if IPC_FAST_ENTRY
    // Chain E cut 7: rax = IPC_FAST_LO or IPC_FAST_LO + 2 exactly when
    // (rax - IPC_FAST_LO) & ~2 is 0. Those two go straight to the frame
    // that runs the fast path (`x86_64_fast_ipc_syscall`); three
    // instructions on every other syscall. rcx is free (the return RIP is
    // in the frame already, and the contract clobbers rcx).
    leaq -IPC_FAST_LO(%rax), %rcx
    testq $-3, %rcx
    jz .Lsyscall_fast_ipc
.endif
    call x86_64_native_syscall
    movq %rax, %rbx
    // fall through to syscall_return
.else
    SAVE_REGS
    movq %rsp, %rdi
    call x86_64_trap_entry
    movq %rax, %rbx
    jmp trap_return
.endif

.if SYSCALL_LEAN
// ── Chain E commit 8: the return from a `syscall` ───────────────────────────
//
// THE CONTRACT (crates/core/abi/src/syscall_nr.rs, "Register contract"): on
// return from a native syscall ring 3 may rely on rbx, rbp, r12-r15, rsp,
// the FS/GS bases and the call's outputs (rax, and rdx/rsi/rdi/r8-r10 when
// the call writes them; otherwise they come back as passed). rcx and r11 are
// clobbered, which is what `syscall`/`sysret` do to them anyway, and the
// x86_64 Linux ABI says the same: no task needs them back, so this path
// neither stores them nor compares them, and `sysretq` returns them as the
// RIP and RFLAGS it resumes with. Every other trap returns through
// `trap_return`.
//
// A frame the kernel rebuilt rather than saved is not this path's: a
// foreign-ABI resume (`foreign_return`, Resume arm) hands the runtime's
// rcx/r11 to the thread, and an exec's fresh image starts with every
// register zero. Both leave `TrapFrame::vector` = REBUILT_VECTOR
// (entry/x86_64/mod.rs), not SYSCALL_VEC, and go to `trap_return`, whose
// `iretq` restores every register from the frame (K1 M1: rcx/r11 came back
// as RIP/RFLAGS, not as the runtime asked).
//
// Otherwise the frame's rcx/r11 slots keep what an earlier full save left;
// nothing on a syscall reads them: the fork snapshot clears them
// (`SYSCALL_CLOBBERED`, crates/core/arch-x86_64/src/fork_regs.rs) and a
// reflected foreign trap reports RIP/RFLAGS there.
//
// rsp = frame, rbx = CR3 word or 0. The frame is ring 3's (only `syscall`
// from ring 3 reaches `syscall_entry`), so there is no CS test.
syscall_return:
    cli
    cmpq $SYSCALL_VEC, TF_VECTOR(%rsp)
    jne trap_return                  // rebuilt: every register from the frame
    testq %rbx, %rbx
    jz 1f
    movq %gs:0, %rcx
    leaq AZOS_HART_CR3(%rip), %rdx
    movq %rbx, (%rdx,%rcx,8)
    movq %rbx, %cr3
1:  cmpq $0, %gs:PC_FP_LIVE
    jne 2f
    call x86_64_fp_restore
2:  leaq TF_SIZE(%rsp), %rax         // this task's kernel stack top
    movq %rax, %gs:PC_KERNEL_RSP
    movq %rax, %gs:PC_TSS_RSP0
    movq TF_RIP(%rsp), %rcx
    movq TF_RFLAGS(%rsp), %r11
.if USE_SYSRET
    testq $RFLAGS_TF_RF, %r11
    jnz 3f
    movq %rcx, %rax
    shrq $47, %rax                   // canonical user RIP (CVE-2012-0217)
    jnz 3f
    RESTORE_REGS_SYSCALL             // rcx = RIP, r11 = RFLAGS
    movq TF_RSP(%rsp), %rsp
    VERW_ON_EXIT
    swapgs
    sysretq
3:
.endif
    // `iretq`: rcx/r11 keep the RIP/RFLAGS just loaded, not a kernel value.
    RESTORE_REGS_SYSCALL
    addq $TF_RIP, %rsp
    VERW_ON_EXIT
    swapgs
    iretq

.if IPC_FAST_ENTRY
.Lsyscall_fast_ipc:
    call x86_64_fast_ipc_syscall
    movq %rax, %rbx
    jmp syscall_return
.endif
.endif

// ── Chain E commit 9: the IPC fast path's resume point ──────────────────────
//
// Kconfig IPC_FASTPATH_RESUME (crates/core/syscall/src/fastpath.rs, "Resume
// points"). A task that blocked in the fast path's hand-off from a `syscall`
// left this stub and its trap frame as its resume point. The fast path that
// claimed it finished its syscall for it (rax and the extra return registers
// in the frame) and pointed its saved context here, so `context_switch`
// arrives (`jmp` to CTX_PC) with rsp = that frame (CTX_SP: aligned as at
// `syscall_entry`'s own call), rsi = this task (its `new`), interrupts off,
// the kernel GS and the task's address space installed. The frames it blocked
// in are abandoned. First `azos_ipc_fast_exit` when the switch left a Zombie
// to reap (`finish_switch`), or always when this build has checks on the
// return to ring 3 (RESUME_EXIT_CALL: lockdep, ctx-probe);
// then the exit `syscall_entry` took; no CR3 write (rbx = 0).
.globl x86_64_ipc_resume_stub
x86_64_ipc_resume_stub:
    endbr64                          // CFI landing pad: its address is a resume PC, context_switch returns to it
.if RESUME_EXIT_CALL
    call azos_ipc_fast_exit
.else
    cmpq $0, TASK_REAP_OFFSET(%rsi)
    je 1f
    call azos_ipc_fast_exit
1:
.endif
    xorl %ebx, %ebx
.if SYSCALL_LEAN
    jmp syscall_return
.else
    jmp trap_return
.endif
.size x86_64_ipc_resume_stub, . - x86_64_ipc_resume_stub

// ── x86_64_ret_to_user(frame, cr3): one ring-3 return sequence ──────────────
x86_64_ret_to_user:
    endbr64                          // CFI landing pad (Kconfig X86_CET_IBT)
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

// The selector `verw` names: the kernel data segment, readable and writable.
.section .rodata
.balign 2
x86_verw_sel:
    .word KERNEL_DS

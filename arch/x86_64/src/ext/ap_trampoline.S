// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// x86_64 AP start (AT&T; `global_asm!(.., options(att_syntax))` in smp.rs).
//
// INIT-SIPI-SIPI starts an AP in real mode at CS = page << 8, IP = 0, where
// `smp::install` copied everything between x86_ap_trampoline_start and
// _end to a RAM page under 1 MiB: the 16-bit stub, the parameter block, the
// GDT, the 32-bit stage and the 64-bit hop. Nothing in the copy names the
// kernel image's physical address (the loader put the image wherever it
// found room): the stages are position independent and every address they
// need is a parameter `install` patches (the page's own address, the
// tables' CR3, LA57).
//
//   16-bit:  DS = CS; EBP = this page's address; lgdt the GDT below; CR0.PE;
//            far jump to the 32-bit stage. (No stack: an AP wakes with ESP 0.)
//   32-bit:  flat segments; CR4.PAE (and LA57 per the parameter); CR3 = the
//            parameter (X86_AP_PML4 or X86_AP_PML5: the first GiB 1:1, which
//            holds this page, and the image at its link address);
//            EFER.LME|NXE; CR0.PG|WP; far jump to the 64-bit hop.
//   64-bit:  still in this page (1:1): jump to the image's link address, an
//            absolute virtual address the AP's tables map.
//   64-bit, in the image (`x86_ap_start64_high`, .text.x86_ap): the boot
//            CPU's CR3/CR4/EFER/CR0, GDT, CS/SS and IDT from X86_AP_BOOT
//            (published by `smp::hart_start` before the SIPI); then ack
//            (arg + 1) and jump to `entry` with %rdi = arg. `entry` sets the
//            stack.

.pushsection .rodata.x86_ap_trampoline, "a"
.balign 16
.code16
.globl x86_ap_trampoline_start
.globl x86_ap_trampoline_end
x86_ap_trampoline_start:
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    // This page's address (CS << 4), kept in EBP across the mode switches:
    // the stages address their parameters off it. An AP wakes with ESP = 0,
    // and paging is off through the 32-bit stage, so no `call`/`push` may run
    // before the 64-bit hop's stack is set.
    movzwl %ax, %ebp
    shll $4, %ebp
    lgdtl x86_ap_tr_gdtr - x86_ap_trampoline_start
    movl %cr0, %eax
    orl $1, %eax                        // PE
    movl %eax, %cr0
    ljmpl *x86_ap_tr_far32 - x86_ap_trampoline_start

// The parameter block (patched by `smp::install`; zero in the image).
.balign 8
.globl x86_ap_tr_gdtr, x86_ap_tr_far32, x86_ap_tr_far64, x86_ap_tr_cr3, x86_ap_tr_la57
x86_ap_tr_gdtr:                         // limit; base = this page + (gdt - start)
    .word x86_ap_gdt_end - x86_ap_gdt - 1
    .long 0
x86_ap_tr_far32:                        // m16:32 of the 32-bit stage
    .long 0
    .word 0x18
x86_ap_tr_far64:                        // m16:32 of the 64-bit hop
    .long 0
    .word 0x08
x86_ap_tr_cr3:
    .long 0
x86_ap_tr_la57:
    .long 0

.balign 8
.globl x86_ap_gdt
x86_ap_gdt:
    .quad 0
    .quad 0x00AF9A000000FFFF            // 0x08: 64-bit code
    .quad 0x00CF92000000FFFF            // 0x10: flat 4 GiB data
    .quad 0x00CF9A000000FFFF            // 0x18: flat 4 GiB 32-bit code
x86_ap_gdt_end:

.code32
.globl x86_ap_start32
x86_ap_start32:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl %cr4, %eax
    orl $(1 << 5), %eax                 // PAE
    // CR4.LA57 cannot change in long mode: an AP joins a 5-level boot CPU
    // with LA57 set here and a PML5 above its first PML4 (the CR3 parameter).
    // The parameters are at EBP (this page) + their offset in it.
    cmpl $0, (x86_ap_tr_la57 - x86_ap_trampoline_start)(%ebp)
    je 2f
    orl $(1 << 12), %eax                // LA57
2:  movl %eax, %cr4
    movl (x86_ap_tr_cr3 - x86_ap_trampoline_start)(%ebp), %eax
    movl %eax, %cr3
    movl $0xC0000080, %ecx              // EFER
    rdmsr
    orl $((1 << 8) | (1 << 11)), %eax   // LME | NXE
    wrmsr
    movl %cr0, %eax
    orl $((1 << 31) | (1 << 16)), %eax  // PG | WP
    movl %eax, %cr0
    ljmpl *(x86_ap_tr_far64 - x86_ap_trampoline_start)(%ebp)

.code64
.globl x86_ap_start64
x86_ap_start64:
    // At this page's 1:1 address: go to the image's link address before the
    // kernel's CR3, which maps no low RAM.
    movabsq $x86_ap_start64_high, %rax
    jmpq *%rax
x86_ap_trampoline_end:
.popsection

.pushsection .text.x86_ap, "ax"
.code64
.globl x86_ap_start64_high
x86_ap_start64_high:
    // A SIPI leaves RSP 0: the far return below needs a stack. One AP runs
    // this at a time (the boot CPU waits for its ack, written after the
    // last push), and `_secondary_start` loads the CPU's own stack first.
    leaq X86_AP_STACK_TOP(%rip), %rsp
    leaq X86_AP_BOOT(%rip), %rsi
    // The kernel's own tables and control state, as the boot CPU runs.
    movq {off_cr3}(%rsi), %rax
    movq %rax, %cr3
    movq {off_cr4}(%rsi), %rax
    movq %rax, %cr4
    movl $0xC0000080, %ecx
    movl {off_efer}(%rsi), %eax
    movl {off_efer}+4(%rsi), %edx
    wrmsr
    movq {off_cr0}(%rsi), %rax
    movq %rax, %cr0
    lgdt {off_gdtr}(%rsi)
    lidt {off_idtr}(%rsi)
    // Reload CS through a far return, then the data segments.
    pushq {off_cs}(%rsi)
    leaq 1f(%rip), %rax
    pushq %rax
    lretq
1:  movq {off_ss}(%rsi), %rax
    movw %ax, %ss
    movw %ax, %ds
    movw %ax, %es
    xorl %eax, %eax
    movw %ax, %fs
    movw %ax, %gs
    movq {off_entry}(%rsi), %rax
    movq {off_arg}(%rsi), %rdi
    // Ack: the block is consumed; the boot CPU may reuse it.
    leaq 1(%rdi), %rcx
    movq %rcx, {off_ack}(%rsi)
    jmpq *%rax
.popsection

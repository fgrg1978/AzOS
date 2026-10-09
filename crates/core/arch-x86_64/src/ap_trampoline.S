// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// x86_64 AP start (AT&T; `global_asm!(.., options(att_syntax))` in smp.rs).
//
// INIT-SIPI-SIPI starts an AP in real mode at CS = page << 8, IP = 0, where
// `smp::install` copied the 16-bit stub below (x86_ap_trampoline_start..
// _end) to a RAM page under 1 MiB. Every address in it is absolute and
// resolved by the linker or relative to CS, so the copy needs no patching
// and the page is never written again. The kernel is LINKED at KVA
// (`mmu::KERNEL_VA_OFFSET`) above its physical address: the 16- and 32-bit
// stages run with paging off and name every symbol `sym - KVA`.
//
//   16-bit (the copy):  DS = CS; lgdt the AP GDT below; CR0.PE; far jump.
//   32-bit (.text):     flat segments; CR4.PAE; CR3 = X86_AP_PML4 (the
//                       first GiB, the kernel image, both 1:1 and at KVA);
//                       EFER.LME|NXE; CR0.PG|WP; far jump to 64-bit.
//   64-bit (.text):     jump from the 1:1 address to the link address; the
//                       boot CPU's CR3/CR4/EFER/CR0, GDT, CS/SS and IDT
//                       from X86_AP_BOOT (published by `smp::hart_start`
//                       before the SIPI); then ack (arg + 1) and jump to
//                       `entry` with %rdi = arg. `entry` sets the stack.

.equ KVA, {kva}

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
    lgdtl x86_ap_tr_gdtr - x86_ap_trampoline_start
    movl %cr0, %eax
    orl $1, %eax                        // PE
    movl %eax, %cr0
    ljmpl *x86_ap_tr_far - x86_ap_trampoline_start
.balign 8
x86_ap_tr_gdtr:
    .word x86_ap_gdt_end - x86_ap_gdt - 1
    .long x86_ap_gdt - KVA
x86_ap_tr_far:
    .long x86_ap_start32 - KVA
    .word 0x18
x86_ap_trampoline_end:

.balign 8
x86_ap_gdt:
    .quad 0
    .quad 0x00AF9A000000FFFF            // 0x08: 64-bit code
    .quad 0x00CF92000000FFFF            // 0x10: flat 4 GiB data
    .quad 0x00CF9A000000FFFF            // 0x18: flat 4 GiB 32-bit code
x86_ap_gdt_end:
.popsection

.pushsection .text.x86_ap, "ax"
.code32
x86_ap_start32:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl %cr4, %eax
    orl $(1 << 5), %eax                 // PAE
    // CR4.LA57 cannot change in long mode: an AP joins a 5-level boot CPU
    // with LA57 set here and a PML5 above its first PML4.
    movl X86_AP_BOOT - KVA + {off_cr4}, %ecx
    testl $(1 << 12), %ecx
    jz 3f
    orl $(1 << 12), %eax                // LA57
    movl %eax, %cr4
    movl $(X86_AP_PML5 - KVA), %eax
    jmp 4f
3:  movl %eax, %cr4
    movl $(X86_AP_PML4 - KVA), %eax
4:  movl %eax, %cr3
    movl $0xC0000080, %ecx              // EFER
    rdmsr
    orl $((1 << 8) | (1 << 11)), %eax   // LME | NXE
    wrmsr
    movl %cr0, %eax
    orl $((1 << 31) | (1 << 16)), %eax  // PG | WP
    movl %eax, %cr0
    ljmp $0x08, $(x86_ap_start64 - KVA)

.code64
x86_ap_start64:
    // At the 1:1 address: go to the link address before the kernel's CR3,
    // which maps no low RAM.
    movabsq $x86_ap_start64_high, %rax
    jmpq *%rax
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

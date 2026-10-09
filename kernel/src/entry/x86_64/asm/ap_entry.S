// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// x86_64 secondary-CPU entry (AT&T; included by entry/x86_64/smp.rs).
//
// `Boot::hart_start(cpu, _secondary_start, cpu)` lands here from the AP
// trampoline (crates/core/arch-x86_64/src/ap_trampoline.S) in 64-bit mode,
// on the kernel's page tables, GDT and IDT, interrupts off, with %rdi = the
// dense CPU number and no stack. As riscv64's `_secondary_start`: range
// check, stack = AZOS_SECONDARY_SP[cpu] (0 = no per-CPU area: park), the
// provisional GS base, then `x86_64_secondary_entry(cpu)` (entry/x86_64/smp.rs),
// which loads this CPU's own tables before `secondary_main(cpu)`.
// AZOS_SECONDARY_SP holds physical addresses (the stack top as a frame
// address, what every ISA publishes); the kernel's tables are live here and
// map RAM in the direct map only (`azos_arch::mmu::DIRECT_MAP_BASE`), so
// its base is added (aarch64 adds its offset once its MMU is on).

.pushsection .text.x86_secondary, "ax"
.code64
.globl _secondary_start
_secondary_start:
    cli
    cmpq ${max_harts}, %rdi
    jae 2f
    leaq AZOS_SECONDARY_SP(%rip), %rax
    movq (%rax,%rdi,8), %rsp
    testq %rsp, %rsp
    jz 2f
    movabsq ${dmb}, %rax
    addq %rax, %rsp
    movl $0xC0000101, %ecx              // IA32_GS_BASE = cpu
    movl %edi, %eax
    xorl %edx, %edx
    wrmsr
    xorl %ebp, %ebp
    call x86_64_secondary_entry
2:  cli
    hlt
    jmp 2b
.popsection

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// x86_64 boot entry (AT&T syntax; `global_asm!(.., options(att_syntax))`).
//
// Entered through PVH (QEMU `-kernel` on `-M microvm`, qboot): the ELF note
// below names the 32-bit physical entry `_start`. The CPU arrives in 32-bit
// protected mode, flat segments, paging off, interrupts off, %ebx = the
// physical address of the `hvm_start_info` (magic 0x336ec578).
//
// Exports:
//   _start                 boot CPU entry (the PVH note's target)
//   _secondary_start       AP entry after INIT-SIPI-SIPI (not wired yet: a
//                          real AP needs a 16-bit trampoline below 1 MiB)
// Calls:
//   kernel_main(hart_id = 0, fw_table = start_info)
//   x86_64_early_exception(vector, error_code, rip)   any CPU exception
//
// Boot CPU, in order:
//   1. 32-bit stack; save start_info.
//   2. The Kconfig BASELINE (X86_64_LEVEL), from CPUID, before any code
//      compiled for it runs; below it, print why on COM1 and stop (exit
//      through isa-debug-exit when QEMU has one, then halt).
//   3. Clear .bss; identity page tables for 0..4 GiB in 2 MiB pages (RAM,
//      and the LAPIC/IOAPIC windows for later).
//      With Kconfig X86_LA57 allowing it and CPUID reporting it, a PML5
//      above that PML4 and CR4.LA57 (5-level paging; mmu.rs reads CR4).
//   4. CR4.PAE, CR3, EFER.LME|NXE, CR0.PG|WP, the 64-bit GDT, far jump.
//   5. 64-bit: data segments, stack, GS base = hart id 0 (Cpu::hart_id),
//      the IDT (every exception vector reports and stops: no triple fault).
//   6. call kernel_main; halt if it returns.
// The FPU/SSE state is not enabled: the kernel is soft-float
// (x86_64-unknown-none). User FP will be switched EAGERLY (fpu.rs).

.equ X86_LEVEL, {x86_level}
.equ COM1, 0x3F8
.equ DEBUG_EXIT, 0xF4

// ── PVH ELF note: XEN_ELFNOTE_PHYS32_ENTRY (18) ─────────────────────────────
.section .note.Xen, "a", @note
    .balign 4
    .long 4
    .long 4
    .long 18
    .asciz "Xen"
    .balign 4
    .long _start
    .balign 4

.section .text.boot, "ax"
.code32
.globl _start
.globl _secondary_start
_start:
    cli
    cld
    movl $_stack_end, %esp
    movl %ebx, pvh_start_info

    // ── 2. baseline: CPUID bits of the configured level ─────────────────
.if X86_LEVEL >= 2
    // v2: CPUID.1:ECX SSE3(0) SSSE3(9) CX16(13) SSE4.1(19) SSE4.2(20) POPCNT(23)
    movl $1, %eax
    cpuid
    andl $0x00982201, %ecx
    cmpl $0x00982201, %ecx
    jne refuse_baseline
    // CPUID.80000001:ECX LAHF/SAHF(0)
    movl $0x80000001, %eax
    cpuid
    testl $1, %ecx
    jz refuse_baseline
.endif
.if X86_LEVEL >= 3
    // v3: CPUID.1:ECX FMA(12) MOVBE(22) XSAVE(26) AVX(28) F16C(29).
    // XSAVE, not OSXSAVE(27): OSXSAVE mirrors CR4.OSXSAVE, which nothing
    // has set yet, so testing it refused every CPU. The XCR0 YMM state is
    // checked from Rust (features::check_baseline, CPUID 0xD).
    movl $1, %eax
    cpuid
    andl $0x34401000, %ecx
    cmpl $0x34401000, %ecx
    jne refuse_baseline
    // CPUID.7.0:EBX BMI1(3) AVX2(5) BMI2(8)
    movl $7, %eax
    xorl %ecx, %ecx
    cpuid
    andl $0x00000128, %ebx
    cmpl $0x00000128, %ebx
    jne refuse_baseline
    // CPUID.80000001:ECX LZCNT(5)
    movl $0x80000001, %eax
    cpuid
    testl $0x20, %ecx
    jz refuse_baseline
.endif
.if X86_LEVEL >= 4
    // v4: CPUID.7.0:EBX AVX512F(16) AVX512DQ(17) AVX512CD(28) AVX512BW(30) AVX512VL(31)
    movl $7, %eax
    xorl %ecx, %ecx
    cpuid
    andl $0xD0030000, %ebx
    cmpl $0xD0030000, %ebx
    jne refuse_baseline
.endif

    // ── 3. clear .bss, build the identity map ───────────────────────────
    movl $_bss_start, %edi
    movl $_bss_end, %ecx
    subl %edi, %ecx
    xorl %eax, %eax
    rep stosb

    // PML4[0] -> PDPT; PDPT[0..3] -> PD0..PD3; PDn[j] = 2 MiB leaf
    movl $boot_pdpt, %eax
    orl $0x3, %eax
    movl %eax, boot_pml4
    xorl %esi, %esi
1:  movl %esi, %eax
    shll $12, %eax
    addl $boot_pd, %eax
    orl $0x3, %eax
    movl %eax, boot_pdpt(,%esi,8)
    incl %esi
    cmpl $4, %esi
    jne 1b
    xorl %esi, %esi
2:  movl %esi, %eax
    shll $21, %eax
    orl $0x83, %eax                  // P | RW | PS
    movl %esi, %edx
    shrl $11, %edx                   // bits 32..33 of the 2 MiB frame
    movl %eax, boot_pd(,%esi,8)
    movl %edx, boot_pd+4(,%esi,8)
    incl %esi
    cmpl $2048, %esi
    jne 2b

    // LA57 (Kconfig X86_LA57, AZOS_X86_LA57_POLICY: 0 n, 1 probe,
    // 2 require): CR4.LA57 can change only with long mode off, so the
    // depth is chosen here. PML5[0] -> the PML4 above; CR3 names the PML5.
    // A `require` on a CPU without it is refused by the mmu_enabled hook.
    movl $boot_pml4, %edi            // the root CR3 gets
    cmpl $0, AZOS_X86_LA57_POLICY
    je la57_done
    movl $7, %eax
    xorl %ecx, %ecx
    cpuid
    testl $(1 << 16), %ecx           // CPUID.(7,0):ECX.LA57
    jz la57_done
    movl $boot_pml4, %eax
    orl $0x3, %eax
    movl %eax, boot_pml5
    movl %cr4, %eax
    orl $(1 << 12), %eax             // LA57
    movl %eax, %cr4
    movl $boot_pml5, %edi
la57_done:

    // ── 4. long mode ────────────────────────────────────────────────────
    movl %cr4, %eax
    orl $(1 << 5), %eax              // PAE
    movl %eax, %cr4
    movl %edi, %cr3
    movl $0xC0000080, %ecx           // EFER
    rdmsr
    orl $((1 << 8) | (1 << 11)), %eax   // LME | NXE
    wrmsr
    movl %cr0, %eax
    orl $((1 << 31) | (1 << 16) | 1), %eax   // PG | WP | PE
    movl %eax, %cr0
    lgdt gdt64_ptr
    ljmp $0x08, $long_entry

// Below the baseline: say why on COM1 (8N1, 115200) and stop.
refuse_baseline:
    movw $(COM1 + 3), %dx
    movb $0x80, %al
    outb %al, %dx
    movw $COM1, %dx
    movb $1, %al
    outb %al, %dx
    movw $(COM1 + 1), %dx
    xorb %al, %al
    outb %al, %dx
    movw $(COM1 + 3), %dx
    movb $0x03, %al
    outb %al, %dx
    movl $refuse_msg, %esi
3:  movb (%esi), %al
    testb %al, %al
    jz 5f
    movb %al, %bl
    movw $(COM1 + 5), %dx
4:  inb %dx, %al
    testb $0x20, %al
    jz 4b
    movw $COM1, %dx
    movb %bl, %al
    outb %al, %dx
    incl %esi
    jmp 3b
5:  movw $DEBUG_EXIT, %dx
    movl $0x1, %eax                  // QEMU exit status (1 << 1) | 1 = 3
    outl %eax, %dx
6:  cli
    hlt
    jmp 6b

_secondary_start:
    // APs are not started yet (Boot::hart_start is todo!()).
    cli
    hlt
    jmp _secondary_start

.code64
long_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorw %ax, %ax
    movw %ax, %fs
    movw %ax, %gs
    movabsq $_stack_end, %rax
    movq %rax, %rsp
    // GS base = 0: the per-CPU base is the hart id, as on riscv64 (tp) and
    // aarch64 (TPIDR_EL1).
    movl $0xC0000101, %ecx
    xorl %eax, %eax
    xorl %edx, %edx
    wrmsr

    // ── 5. IDT: vectors 0..31 report and stop ───────────────────────────
    leaq boot_idt(%rip), %rdi
    leaq exc_stub_table(%rip), %rsi
    xorl %ecx, %ecx
7:  movq (%rsi,%rcx,8), %rax
    movw %ax, (%rdi)                 // offset 15:0
    movw $0x08, 2(%rdi)              // kernel code selector
    movw $0x8E00, 4(%rdi)            // present, DPL0, 64-bit interrupt gate
    shrq $16, %rax
    movw %ax, 6(%rdi)                // offset 31:16
    shrq $16, %rax
    movl %eax, 8(%rdi)               // offset 63:32
    movl $0, 12(%rdi)
    addq $16, %rdi
    incl %ecx
    cmpl $32, %ecx
    jne 7b
    lidt boot_idt_ptr(%rip)

    // ── 6. Rust ─────────────────────────────────────────────────────────
    xorl %edi, %edi                  // hart_id
    movl pvh_start_info(%rip), %esi  // fw_table: the PVH start_info
    call kernel_main
8:  cli
    hlt
    jmp 8b

// ── exception stubs: (vector, error code, rip) -> x86_64_early_exception ──
.macro EXC_NOERR n
exc_\n:
    pushq $0
    pushq $\n
    jmp exc_common
.endm
.macro EXC_ERR n
exc_\n:
    pushq $\n
    jmp exc_common
.endm
EXC_NOERR 0
EXC_NOERR 1
EXC_NOERR 2
EXC_NOERR 3
EXC_NOERR 4
EXC_NOERR 5
EXC_NOERR 6
EXC_NOERR 7
EXC_ERR 8
EXC_NOERR 9
EXC_ERR 10
EXC_ERR 11
EXC_ERR 12
EXC_ERR 13
EXC_ERR 14
EXC_NOERR 15
EXC_NOERR 16
EXC_ERR 17
EXC_NOERR 18
EXC_NOERR 19
EXC_NOERR 20
EXC_ERR 21
EXC_NOERR 22
EXC_NOERR 23
EXC_NOERR 24
EXC_NOERR 25
EXC_NOERR 26
EXC_NOERR 27
EXC_NOERR 28
EXC_ERR 29
EXC_ERR 30
EXC_NOERR 31

exc_common:
    popq %rdi                        // vector
    popq %rsi                        // error code
    movq (%rsp), %rdx                // rip from the interrupt frame
    andq $-16, %rsp
    call x86_64_early_exception
9:  cli
    hlt
    jmp 9b

.section .rodata
.balign 8
exc_stub_table:
    .quad exc_0, exc_1, exc_2, exc_3, exc_4, exc_5, exc_6, exc_7
    .quad exc_8, exc_9, exc_10, exc_11, exc_12, exc_13, exc_14, exc_15
    .quad exc_16, exc_17, exc_18, exc_19, exc_20, exc_21, exc_22, exc_23
    .quad exc_24, exc_25, exc_26, exc_27, exc_28, exc_29, exc_30, exc_31
refuse_msg:
    .asciz "\r\n[X86] CPU below the configured baseline (Kconfig X86_64_LEVEL): refusing to boot\r\n"

.balign 8
gdt64:
    .quad 0
    .quad 0x00209A0000000000         // 0x08: 64-bit code, DPL0
    .quad 0x0000920000000000         // 0x10: data
gdt64_ptr:
    .word gdt64_ptr - gdt64 - 1
    .long gdt64

.balign 8
boot_idt_ptr:
    .word 32 * 16 - 1
    .quad boot_idt

.section .data
.balign 4
pvh_start_info:
    .long 0

.section .bss
.balign 4096
boot_pml5:
    .skip 4096
boot_pml4:
    .skip 4096
boot_pdpt:
    .skip 4096
boot_pd:
    .skip 4096 * 4
boot_idt:
    .skip 32 * 16

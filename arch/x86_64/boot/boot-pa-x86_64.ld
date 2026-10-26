/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * The physical addresses boot.S's 32-bit stage names, INCLUDEd at the end of
 * SECTIONS by both x86_64 scripts after they define KERNEL_VA_OFFSET_LITERAL.
 *
 * The 32-bit stage runs with paging off, at the physical address the image
 * was loaded to, and has always written every symbol it names as `sym - KVA`:
 * an absolute 32-bit relocation. A position-independent link (Kconfig KASLR,
 * `-pie`) refuses those against a symbol that moves, so the stage names these
 * instead: each `<sym>_pa` is an ABSOLUTE symbol, the link-time address of
 * `<sym>` minus the kernel's virtual offset (the physical address the script's
 * `AT()` placed it at), a constant the linker may use anywhere. `ABSOLUTE`
 * wraps the whole difference: lld keeps a symbol section-relative when the
 * subtraction is applied to an `ABSOLUTE` operand. In a link
 * that is not position-independent the machine code is byte for byte what the
 * `sym - KVA` form assembled to. The 64-bit part of boot.S reaches its
 * symbols RIP-relative or with `movabsq`, which a slide relocates.
 */
    _start_pa                = ABSOLUTE(_start - KERNEL_VA_OFFSET_LITERAL);
    _stack_end_pa            = ABSOLUTE(_stack_end - KERNEL_VA_OFFSET_LITERAL);
    _bss_start_pa            = ABSOLUTE(_bss_start - KERNEL_VA_OFFSET_LITERAL);
    _bss_end_pa              = ABSOLUTE(_bss_end - KERNEL_VA_OFFSET_LITERAL);
    pvh_start_info_pa        = ABSOLUTE(pvh_start_info - KERNEL_VA_OFFSET_LITERAL);
    boot_pml4_pa             = ABSOLUTE(boot_pml4 - KERNEL_VA_OFFSET_LITERAL);
    boot_pml5_pa             = ABSOLUTE(boot_pml5 - KERNEL_VA_OFFSET_LITERAL);
    boot_pdpt_pa             = ABSOLUTE(boot_pdpt - KERNEL_VA_OFFSET_LITERAL);
    boot_pdpt_hi_pa          = ABSOLUTE(boot_pdpt_hi - KERNEL_VA_OFFSET_LITERAL);
    boot_pd_pa               = ABSOLUTE(boot_pd - KERNEL_VA_OFFSET_LITERAL);
    AZOS_X86_LA57_POLICY_pa  = ABSOLUTE(AZOS_X86_LA57_POLICY - KERNEL_VA_OFFSET_LITERAL);
    gdt64_pa                 = ABSOLUTE(gdt64 - KERNEL_VA_OFFSET_LITERAL);
    gdt64_ptr_pa             = ABSOLUTE(gdt64_ptr - KERNEL_VA_OFFSET_LITERAL);
    long_entry_pa            = ABSOLUTE(long_entry - KERNEL_VA_OFFSET_LITERAL);
    refuse_msg_pa            = ABSOLUTE(refuse_msg - KERNEL_VA_OFFSET_LITERAL);

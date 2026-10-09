/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for the x86_64 kernel (`make ARCH=x86_64`): a PVH ELF
 * QEMU `-M microvm -kernel` loads at its physical addresses. It names the
 * sections and symbols the shared kernel code reads, matched to
 * kernel/linker.ld and kernel/linker-aarch64.ld.
 *
 * Layout the real port must decide:
 *   - load address: 1 MiB physical (Multiboot2), or wherever the UEFI loader
 *     put the PE image;
 *   - link address: the higher half (-2 GiB, mcmodel=kernel), with
 *     KERNEL_VA_OFFSET the difference, as aarch64's TTBR1 split does;
 *   - .text.boot first, holding the Multiboot2 header within its first
 *     32 KiB and the 16-bit AP trampoline (copied below 1 MiB at boot).
 *
 * Symbols the shared code reads (same names on every ISA):
 *   _text_start _text_end _rodata_start _rodata_end _data_start _data_end
 *   _bss_start _bss_end _stack_start _stack_end _kernel_end
 *   __azos_keys_start __azos_keys_end   (the signed-boot key section)
 *   __azos_ktest_start __azos_ktest_end (the in-kernel test registry)
 */

OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

INCLUDE kernel/linker-common.ld

KERNEL_PHYS = 0x100000;

SECTIONS
{
    . = KERNEL_PHYS;

    /* The PVH entry note (boot.S): QEMU reads it through PT_NOTE. */
    .note.Xen : { KEEP(*(.note.Xen)) }

    . = ALIGN(4K);
    _text_start = .;
    .text : { KEEP(*(.text.boot)) *(.text .text.*) }
    _text_end = .;

    . = ALIGN(4K);
    _rodata_start = .;
    .rodata : { *(.rodata .rodata.*) }
    . = ALIGN(4K);
    __azos_keys_start = .;
    .azos_keys : { KEEP(*(.azos_keys)) }
    __azos_keys_end = .;
    /* The in-kernel test registry (Kconfig KTEST, crates/core/ktest); empty
     * with KTEST off. */
    .azos_ktest : { __azos_ktest_start = .; KEEP(*(.azos_ktest)) __azos_ktest_end = .; }
    _rodata_end = .;

    . = ALIGN(4K);
    _data_start = .;
    .data : { *(.data .data.*) }
    _data_end = .;

    . = ALIGN(4K);
    _bss_start = .;
    .bss : { *(.bss .bss.*) *(COMMON) }
    _bss_end = .;

    /* The red zone below the boot stack separates it from the last statics
     * of .bss; boot.S paints both and `boot_stack_report` reads them back. */
    . = ALIGN(4K);
    _stack_redzone = .;
    . += BOOT_STACK_REDZONE;
    _stack_start = .;
    . += BOOT_STACK_SIZE;
    _stack_end = .;

    _kernel_end = .;
}

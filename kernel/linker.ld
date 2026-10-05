/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for AzOS (Rust)
 * Target: RISC-V 64-bit (QEMU virt)
 *
 * Memory layout with OpenSBI:
 *   0x80000000 - 0x801FFFFF : OpenSBI firmware (2MB)
 *   0x80200000 - ...        : Kernel (loaded here)
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/*
 * BOOT_STACK_SIZE / BOOT_STACK_REDZONE (B1-01): single source in
 * linker-common.ld, INCLUDEd by every board/profile linker script so the
 * five copies cannot drift apart. See that file for the measurement this
 * value is based on.
 */
INCLUDE kernel/linker-common.ld

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80200000, LENGTH = 32M
}

SECTIONS
{
    . = 0x80200000;

    /* Boot code first */
    _text_start = .;
    .text.boot : ALIGN(4K)
    {
        *(.text.boot)
    } > RAM

    /* All other code */
    .text : ALIGN(4K)
    {
        *(.text .text.*)
    } > RAM
    _text_end = .;

    /* Read-only data */
    _rodata_start = .;
    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    } > RAM
    _rodata_end = .;

    /* Initialized data */
    _data_start = .;
    .data : ALIGN(4K)
    {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > RAM
    _data_end = .;

    /* Uninitialized data (BSS) */
    .bss : ALIGN(4K)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(8);           /* ensure _bss_end is 8-byte aligned for sd-based clear */
        _bss_end = .;
    } > RAM

    /* Boot stack, inside the image: below _kernel_end, so `pmm::init` reserves
     * it with the kernel and nothing placed after _kernel_end can cover it.
     * At the top of the RAM window it sat inside the kernel heap's range.
     * NOLOAD: no bytes in the file. Outside [_bss_start, _bss_end), so the
     * BSS clear in boot.S, which runs on this stack, leaves it alone.
     * The red zone below it separates the stack from the last statics of
     * .bss; boot.S paints both and `boot_stack_report` in kernel/src/boot/stacks.rs reads them
     * back, so an overflow is reported before it reaches a static. */
    .stack (NOLOAD) : ALIGN(4K)
    {
        _stack_redzone = .;
        . += BOOT_STACK_REDZONE;
        _stack_start = .;
        . += BOOT_STACK_SIZE;
        _stack_end = .;
    } > RAM

    . = ALIGN(4K);
    _kernel_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
        *(.note*)
    }
}

ASSERT(_stack_end <= _kernel_end, "Boot stack must lie inside the kernel image")

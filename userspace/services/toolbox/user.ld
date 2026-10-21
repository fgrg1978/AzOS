/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* Linker script for a ring-3 user ELF. Loads at VA 0x10000.
 *
 * Each segment starts on a page of its own, on purpose: the kernel loader
 * gives every page exactly the permissions of the one PT_LOAD segment it
 * belongs to, and refuses an image in which two segments with different
 * permissions share a page (their union would make .rodata executable or
 * writable). Without the alignment below the binary does not load.
 *
 * .rodata moves to the next page at the same offset in it (what lld and GNU
 * ld do for a new segment): no file padding, one more page of address space.
 * The first writable byte is page-aligned (at most 4 KiB of padding).
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/* Named segments: the ABI note libsys embeds gets a PT_NOTE of its own and
 * must not start a read-only segment on the page `.text` ends in. */
PHDRS
{
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    note   PT_NOTE FLAGS(4);
    data   PT_LOAD FLAGS(6);
    stack  PT_GNU_STACK FLAGS(6);
}

SECTIONS
{
    . = 0x10000;

    .text : {
        *(.text .text.*)
    } :text

    /* Read-only data starts a page of its own: the loader refuses a page
     * shared by segments with different permissions. */
    . = ALIGN(4096) + (. & 4095);

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    /* The ABI note libsys embeds (`azos_abi::ABI_VERSION`): in the read-only
     * segment, and a PT_NOTE of its own for the loader. */
    .note.azos.abi : {
        KEEP(*(.note.azos.abi))
    } :rodata :note

    /* First writable byte starts its own page — see the header. */
    . = ALIGN(4096);

    .data : {
        *(.data .data.*)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /* The stack this image asks for: 20 KiB.
     * Its deepest static chain is 14.6 KiB: ps holds the task table (6 KiB, twice).
     * A NOLOAD section assigned to the PT_GNU_STACK header gives it that
     * p_memsz, which the loader reads (crates/core/sched/src/process.rs,
     * elf_bounds::stack_bytes): no file bytes, and no PT_LOAD covers it.
     * An image without one gets USER_STACK_SIZE_KB. tools/user_stacks.py
     * checks the figure against the image's deepest static call chain. */
    .azos_stack (NOLOAD) : {
        . += 20K;
    } :stack

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}

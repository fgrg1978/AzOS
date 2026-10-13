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

SECTIONS
{
    . = 0x10000;

    .text : {
        *(.text .text.*)
    }

    /* Read-only data starts a page of its own: the loader refuses a page
     * shared by segments with different permissions. */
    . = ALIGN(4096) + (. & 4095);

    .rodata : {
        *(.rodata .rodata.*)
    }

    /* First writable byte starts its own page — see the header. */
    . = ALIGN(4096);

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}

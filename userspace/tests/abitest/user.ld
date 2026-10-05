/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* Linker script for a ring-3 user ELF. Loads at VA 0x10000.
 *
 * Every writable section is aligned to a 4 KiB page boundary, on purpose.
 *
 * The kernel loader maps a page once, with the permissions of the first
 * PT_LOAD segment that touches it, and it refuses to add WRITE to a page that
 * already carries EXEC — W^X is not negotiable for a robot that runs code
 * loaded off a USB-exported FAT volume. Without this alignment .text and
 * .data land in the same page, and the binary either fails to load or (worse,
 * and what actually happened) loads read-only and takes a Store page fault on
 * the first write to a `static mut`. `abitest` hit the fault; `captest` had
 * the identical layout and passed for months only because it never wrote its
 * failure counter.
 *
 * Costs at most 8 KiB of padding per binary. That is nothing next to a fault
 * that only appears once a test starts failing.
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
    . = 0x10000;

    .text : {
        *(.text .text.*)
    }

    /* Read-only data may share the .text page: both are non-writable. */
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

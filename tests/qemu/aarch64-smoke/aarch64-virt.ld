/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* AZOS B1.boot — linker script for qemu-system-aarch64 -M virt.
 *
 *   Memory map (from QEMU virt machine source):
 *     0x0900_0000 ─ PL011 UART0 (4 KiB)
 *     0x4000_0000 ─ DRAM start (up to -m bytes)
 *
 *   QEMU `-kernel <elf>` loads program headers verbatim, so we lay
 *   everything out starting at the start of DRAM. Reserve the
 *   first 32 KiB for QEMU's own setup (FDT pointer in x0, etc.)
 *   and start our text at 0x4008_0000 to match what QEMU's
 *   built-in mini-bootloader expects.
 */

ENTRY(_start)

MEMORY {
    ram (rwx) : ORIGIN = 0x40080000, LENGTH = 128M
}

SECTIONS {
    . = ORIGIN(ram);

    /* Boot trampoline runs first. */
    .text : ALIGN(4096) {
        KEEP(*(.text.boot))
        KEEP(*(.text.vectors))
        *(.text*)
    } > ram

    /* B1.user.split — user_main and friends get their own page so
       the L3 entry we widen to AP[2:1]=01 only ever covers user
       code, not anything in the kernel exception-entry path. */
    __user_text_start = .;
    .user_text : ALIGN(4096) {
        KEEP(*(.user_text))
        . = ALIGN(4096);
    } > ram
    __user_text_end = .;

    .rodata : ALIGN(4096) {
        *(.rodata*)
    } > ram

    .data : ALIGN(4096) {
        *(.data*)
    } > ram

    .bss : ALIGN(4096) {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    } > ram

    /* B1.user.split — USER_STACK lives in its own page (in .bss
       on its own section) so the AP=01 L3 entry covers exactly
       one user-owned page, no kernel data alongside. */
    .user_bss : ALIGN(4096) {
        __user_bss_start = .;
        KEEP(*(.user_bss))
        . = ALIGN(4096);
        __user_bss_end = .;
    } > ram

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.ARM.attributes*)
    }
}

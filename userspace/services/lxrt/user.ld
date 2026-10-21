/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* Linker script for the Linux runtime, riscv64. Loads in the runtime window
 * (azos_abi::foreign::RUNTIME_BASE = VDSO_USER_BASE + 0x10000 = 0x20010000),
 * the page after the vDSO's two, inside the vDSO's 2 MiB slot.
 *
 * Each segment starts on a page of its own, because the kernel maps every
 * page with exactly the permissions of the one PT_LOAD segment it belongs to
 * (azos_sched::foreign::attach_runtime): text RX, rodata R, data RW. The
 * segments are named (PHDRS) so the ABI note libsys embeds gets a PT_NOTE of
 * its own and cannot start the read-only segment on the page `.text` ends in.
 * The runtime has no .eh_frame: nothing unwinds. */

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
}

SECTIONS
{
    . = 0x20010000;

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

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}

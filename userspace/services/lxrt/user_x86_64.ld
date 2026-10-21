/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* Linker script for the Linux runtime, x86_64. Loads in the runtime window
 * (azos_abi::foreign::RUNTIME_BASE = VDSO_USER_BASE + 0x10000 = 0x20010000),
 * as `user.ld` does on riscv64 and `user_aarch64.ld` on aarch64, with the
 * segments named explicitly: text RX, rodata R, data RW, each starting on a
 * page of its own (`-z max-page-size=4096` and `-z norelro` from
 * `.cargo/config.toml`). The kernel maps every page with exactly the
 * permissions of its PT_LOAD segment (azos_sched::foreign::attach_runtime). */

OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

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
    . = 0x20010000;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(4096) + (. & 4095);

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    /* The ABI note libsys embeds (`azos_abi::ABI_VERSION`): in the read-only
     * segment, and a PT_NOTE of its own for the loader. */
    .note.azos.abi : {
        KEEP(*(.note.azos.abi))
    } :rodata :note

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
        *(.note.*)
    }
}

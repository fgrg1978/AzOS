/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* Linker script of a C program on relibc, aarch64. The layout rules are those of
 * userspace/tests/hello/user_aarch64.ld (load at 0x10000, one page-aligned PT_LOAD per
 * permission, the ABI note in a PT_NOTE, the granule `-z max-page-size`), plus the TLS template: a PT_TLS
 * segment and the four symbols relibc's entry reads (`start.rs`), because the
 * loader maps no program headers. */

OUTPUT_ARCH(aarch64)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    note   PT_NOTE FLAGS(4);
    data   PT_LOAD FLAGS(6);
    tls    PT_TLS FLAGS(4);
    stack  PT_GNU_STACK FLAGS(6);
}

SECTIONS
{
    /* Above a 4 KiB page the ELF and program headers share the first page with
     * `.text` (see user_aarch64.ld); at 4 KiB the start is exactly 0x10000. */
    . = 0x10000 + (CONSTANT(MAXPAGESIZE) > 0x1000 ? SIZEOF_HEADERS : 0);

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE)) + (. & (CONSTANT(MAXPAGESIZE) - 1));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    .note.azos.abi : {
        KEEP(*(.note.azos.abi))
    } :rodata :note

    /* The init and constructor tables relibc's start code walks. */
    .preinit_array : {
        PROVIDE_HIDDEN(__preinit_array_start = .);
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN(__preinit_array_end = .);
    } :rodata
    .init_array : {
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP(*(.init_array .ctors))
        PROVIDE_HIDDEN(__init_array_end = .);
    } :rodata
    .fini_array : {
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP(*(.fini_array .dtors))
        PROVIDE_HIDDEN(__fini_array_end = .);
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    /* The TLS template: `.tdata` is initialised data copied into every thread's
     * TLS, `.tbss` its zero tail. Both are read-only in the image; only the copy
     * is written. */
    .tdata : {
        __azos_tls_start = .;
        *(.tdata .tdata.*)
    } :data :tls
    __azos_tls_filesz = SIZEOF(.tdata);
    .tbss : {
        *(.tbss .tbss.*)
        *(.tcommon)
    } :data :tls
    __azos_tls_memsz = SIZEOF(.tdata) + SIZEOF(.tbss);
    __azos_tls_align = MAX(ALIGNOF(.tdata), ALIGNOF(.tbss));

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } :data

    .bss : {
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}

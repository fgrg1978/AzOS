/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* Linker script for a ring-3 user ELF, x86_64 (`userspace/x86_64-azos-user.json`).
 *
 * Same layout as `user.ld` and `user_aarch64.ld`: loads at VA 0x10000, and
 * each segment starts on a page of its own, because the loader gives every
 * page exactly the permissions of the one PT_LOAD segment it belongs to and
 * refuses an image in which two segments with different permissions share a
 * page (crates/core/sched/src/process.rs).
 *
 * The target is `userspace/x86_64-azos-user.json` (hard-float, static,
 * small code model); `.cargo/config.toml` passes `-zmax-page-size=4096`
 * (rust-lld's x86_64 default already; spelled out so the program headers
 * cannot drift with the linker) and `-z norelro` (no RELRO segment:
 * nothing is relocated, so nothing is made read-only after it, and a RELRO
 * page of its own would be one more permission boundary the loader sees).
 */

OUTPUT_FORMAT(elf64-x86-64)
/* libsys's `_azos_entry` aligns the stack as System V asks and calls
 * `_start` (crates/core/libsys/src/lib.rs). */
ENTRY(_azos_entry)

SECTIONS
{
    . = 0x10000;

    .text : {
        *(.text .text.*)
    }

    /* Read-only data starts a page of its own (the next page, at the same
     * offset in it: no file padding): the loader refuses a page shared by
     * segments with different permissions. */
    . = ALIGN(CONSTANT(MAXPAGESIZE)) + (. & (CONSTANT(MAXPAGESIZE) - 1));

    .rodata : {
        *(.rodata .rodata.*)
    }

    /* First writable byte starts its own page — see the header. The GOT
     * (static: the linker fills it, nothing relocates it at load) is
     * writable data like any other here; left to orphan placement it became
     * a RELRO segment of its own on the last `.rodata` page, a page the
     * loader then refuses as shared by two permissions. */
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .got : {
        *(.got .got.plt)
    }

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
        *(.note.*)
    }
}

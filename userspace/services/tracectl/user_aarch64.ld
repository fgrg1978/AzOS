/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* Linker script for a ring-3 user ELF, aarch64 (phase 6 prep — no kernel-side
 * aarch64 exec path exists yet; see the "Register convention" section of
 * `crates/core/abi/src/syscall_nr.rs`).
 *
 * Mirrors `user.ld` (the RISC-V script every userspace program already uses)
 * register-for-register in intent: loads at VA 0x10000, and each segment
 * starts on a page of its own, because the loader refuses an image in which
 * two segments with different permissions share a page (see `user.ld`).
 *
 * **aarch64-specific wrinkle RISC-V does not have.** `rust-lld`'s default
 * `-z max-page-size` for `aarch64-unknown-none` is 64 KiB, not 4 KiB — so
 * `ALIGN(4096)` alone would still leave `p_align`/file offsets rounded to
 * 64 KiB in the program headers. `.cargo/config.toml` passes
 * `-C link-arg=-zmax-page-size=4096` alongside this script for that reason:
 * without it, a phase-6 loader written for a 4 KiB granule would misread the
 * segment boundaries this script defines.
 */

OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS
{
    /* Above a 4 KiB page (`make AARCH64_PAGE_SIZE=16384|65536`) the ELF and
     * program headers share the first page with `.text`: otherwise the
     * linker pads the file so `.text`'s offset matches its address modulo the
     * page, and a 64 KiB image crosses the 128 KiB exec/autorun cap on
     * padding alone. At 4 KiB the start is exactly 0x10000, as always. */
    . = 0x10000 + (CONSTANT(MAXPAGESIZE) > 0x1000 ? SIZEOF_HEADERS : 0);

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

    /* First writable byte starts its own page — see the header. The page is
     * `-z max-page-size`: 4096 from `.cargo/config.toml`, or the granule the
     * Makefile passes for an aarch64 16/64 KiB build (`AARCH64_PAGE_SIZE`). */
    . = ALIGN(CONSTANT(MAXPAGESIZE));

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

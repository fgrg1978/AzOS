/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* Linker script for the LINUX side of vsbench.
 *
 * Same layout as `user.ld`, one difference: the load base is 0x200000 (2 MiB)
 * instead of 0x10000 (64 KiB).
 *
 * WHY. Loading a static ET_EXEC at exactly 0x10000 puts it on Linux's default
 * `mmap_min_addr` boundary. Measured: the guest parsed the ELF, jumped to the
 * entry, and took an instruction page fault *at the entry itself*
 * (`epc == badaddr == 0x101f0`, `cause=0xc`) — the segment was never usably
 * mapped. Segment alignment was not the problem: `p_offset % 4096 ==
 * p_vaddr % 4096` held for both PT_LOADs.
 *
 * The Azos side keeps 0x10000 deliberately — that value is load-bearing over
 * there (it is `vmm::USER_GUARD_LIMIT`, the null-guard floor every user image
 * is checked against). This file exists so the two sides can differ in where
 * they load without either of them bending for the other.
 */
OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
    . = 0x200000;

    .text : {
        *(.text .text.*)
    }

    /* Read-only data may share the .text page: both are non-writable. */
    /* Page-align .rodata as well, not just the writable sections.
     *
     * Linux maps each PT_LOAD in order with its own permissions. With .text
     * (R+X) and .rodata (R) sharing one page, the second mapping lands on top
     * of the first and takes EXEC away from it — and the entry point is in
     * that page. Measured before this line existed: the guest parsed the ELF,
     * jumped to the entry, and took an instruction page fault *at the entry*
     * (`epc == badaddr`, `cause=0xc`), which reads as "the binary is corrupt"
     * and is nothing of the sort.
     *
     * Same class as the loader bug already recorded for the Azos side
     * (segments sharing a page); the difference is only which kernel
     * complains. */
    . = ALIGN(4096);
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

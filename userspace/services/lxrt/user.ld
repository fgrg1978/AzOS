/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* Linker script for the Linux runtime, riscv64. Loads in the runtime window
 * (azos_abi::foreign::RUNTIME_BASE = VDSO_USER_BASE + 0x10000 = 0x20010000),
 * the page after the vDSO's two, inside the vDSO's 2 MiB slot.
 *
 * Each segment starts on a page of its own, because the kernel maps every
 * page with exactly the permissions of the one PT_LOAD segment it belongs to
 * (azos_sched::foreign::attach_runtime): text RX, rodata R, data RW. The
 * runtime has no .eh_frame: nothing unwinds. */

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
    . = 0x20010000;

    .text : {
        *(.text .text.*)
    }

    . = ALIGN(4096) + (. & 4095);

    .rodata : {
        *(.rodata .rodata.*)
    }

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

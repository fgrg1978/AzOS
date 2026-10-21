/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * AzOS-micro image layout. __ram_base, __ram_len, __pool_len, __contig_len and
 * __kstack_len and __pmp_grain (the PMP granularity in bytes) come from the
 * .config (build.rs, --defsym).
 *
 * Protection model: tasks run in U-mode under PMP. The window
 * [__code_start, __code_end) -- kernel text and read-only data -- is
 * readable and executable by every task (code carries no secret and a task is
 * ordinary Rust compiled into the image). Everything after it, .data, .bss,
 * the kernel stack and both pools, is reachable by U-mode only through the
 * regions of the task's own domain. M-mode (the kernel) is not constrained by
 * PMP and checks every user pointer itself. The window is one PMP region, so
 * both of its ends are multiples of the granularity.
 */
ENTRY(_start)

SECTIONS
{
    . = __ram_base;
    ASSERT(__ram_base % __pmp_grain == 0, "AzOS-micro: MICRO_RAM_BASE is not a multiple of the PMP granularity")
    __code_start = .;
    .text : {
        KEEP(*(.text.init))
        *(.text .text.*)
    }
    .rodata : ALIGN(4) {
        *(.srodata .srodata.*)
        *(.rodata .rodata.*)
    }
    . = ALIGN(__pmp_grain);
    __code_end = .;

    .data : ALIGN(16) {
        __data_start = .;
        /* gp-relative relaxation reaches +-2 KiB around this. */
        __global_pointer$ = . + 0x800;
        *(.sdata .sdata.*)
        *(.data .data.*)
        __data_end = .;
    }
    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    .kstack (NOLOAD) : ALIGN(16) {
        __kstack_bottom = .;
        . += __kstack_len;
        . = ALIGN(16);
        __kstack_top = .;
    }
    .pool (NOLOAD) : ALIGN(16) {
        __pool_start = .;
        . += __pool_len;
        __pool_end = .;
    }
    /* A contiguous region is a power-of-two block aligned to its size; the
       kernel aligns each one it carves, so the pool itself only needs the
       granularity of its smallest block. */
    .contig (NOLOAD) : ALIGN(4096) {
        __contig_start = .;
        . += __contig_len;
        __contig_end = .;
    }
    __image_end = .;
    ASSERT(__image_end <= __ram_base + __ram_len, "AzOS-micro: the image and its pools do not fit MICRO_RAM_KIB")

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}

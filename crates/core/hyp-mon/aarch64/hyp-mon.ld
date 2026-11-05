/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * The resident monitor's flat image. Position-independent (built with
 * relocation-model=pic): every address is formed PC-relative at run time, so
 * the link base is a convenience, not a load constraint — the kernel's `.hyp`
 * section decides the physical address and the monitor discovers it from the
 * PC. EL2 stage-1 is a 1:1 identity map, so the running VA equals that PA and
 * every PC-relative address stays valid once the MMU is on.
 *
 * .bss (the stacks, the table pool, the violation ring) is kept inside the
 * loaded image and zero-filled by objcopy (--set-section-flags .bss=...,contents),
 * so the monitor needs no runtime bss clear and the kernel's `.hyp` hole is a
 * single contiguous extent.
 */
ENTRY(_hyp_entry)

PAGE = 0x1000;

SECTIONS
{
    . = 0;
    _hyp_image_start = .;

    .text : ALIGN(PAGE) {
        KEEP(*(.text.entry))
        *(.text .text.*)
    }

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(8) {
        *(.data .data.*)
        *(.got .got.*)
    }

    .bss : ALIGN(PAGE) {
        _hyp_bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(PAGE);
        _hyp_bss_end = .;
    }

    . = ALIGN(PAGE);
    _hyp_image_end = .;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame .eh_frame_hdr) *(.rela .rela.*) }
}

ASSERT(_hyp_bss_end - _hyp_image_start < 0x140000, "monitor image over 1.25 MiB")

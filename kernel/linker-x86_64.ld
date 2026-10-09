/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for the x86_64 kernel (`make ARCH=x86_64`): a PVH ELF
 * QEMU `-M microvm -kernel` loads at its PHYSICAL addresses (PT_LOAD
 * p_paddr). It names the sections and symbols the shared code reads,
 * matched to kernel/linker.ld and kernel/linker-aarch64.ld.
 *
 * Layout (the aarch64 TTBR1 model, one offset):
 *   - load address (LMA): KERNEL_PHYS, 1 MiB physical;
 *   - link address (VMA): LMA + KERNEL_VA_OFFSET_LITERAL, the top 2 GiB
 *     (`-mcmodel=kernel`: absolute symbol references are sign-extended
 *     32-bit). Every section below carries `AT(ADDR(sec) - OFFSET)`,
 *     .eh_frame and .got included; a section this script does not name
 *     inherits the previous one's VMA-LMA difference (lld), where an
 *     orphan without `AT` would keep LMA = VMA and QEMU could not load it
 *     (the boot rows go red).
 *   - boot.S runs its 32-bit stage at the LMA (every symbol it names is
 *     written `sym - KVA`), maps PA 0..2 GiB both 1:1 and at the offset,
 *     and jumps high before Rust; the AP trampoline does the same.
 *   - the offset is Rust's `azos_arch::mmu::KERNEL_VA_OFFSET`: boot.S emits
 *     it as `_kernel_va_offset_check` and the ASSERT at the end ties the
 *     literal here to it, so a drift fails to LINK.
 *
 * Symbols the shared code reads (same names on every ISA):
 *   _text_start _text_end _rodata_start _rodata_end _data_start _data_end
 *   _bss_start _bss_end _stack_start _stack_end _kernel_end
 *   __azos_keys_start __azos_keys_end   (the signed-boot key section)
 *   __azos_ktest_start __azos_ktest_end (the in-kernel test registry)
 */

OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

INCLUDE kernel/linker-common.ld

KERNEL_PHYS = 0x100000;
KERNEL_VA_OFFSET_LITERAL = 0xFFFFFFFF80000000;

SECTIONS
{
    . = KERNEL_PHYS + KERNEL_VA_OFFSET_LITERAL;

    /* The PVH entry note (boot.S): QEMU reads it through PT_NOTE. */
    .note.Xen : AT(ADDR(.note.Xen) - KERNEL_VA_OFFSET_LITERAL) { KEEP(*(.note.Xen)) }

    . = ALIGN(4K);
    _text_start = .;
    .text : AT(ADDR(.text) - KERNEL_VA_OFFSET_LITERAL) { KEEP(*(.text.boot)) *(.text .text.*) }
    _text_end = .;

    . = ALIGN(4K);
    _rodata_start = .;
    .rodata : AT(ADDR(.rodata) - KERNEL_VA_OFFSET_LITERAL) { *(.rodata .rodata.*) }
    .eh_frame_hdr : AT(ADDR(.eh_frame_hdr) - KERNEL_VA_OFFSET_LITERAL) { *(.eh_frame_hdr) }
    .eh_frame : AT(ADDR(.eh_frame) - KERNEL_VA_OFFSET_LITERAL) { KEEP(*(.eh_frame)) }
    . = ALIGN(4K);
    __azos_keys_start = .;
    .azos_keys : AT(ADDR(.azos_keys) - KERNEL_VA_OFFSET_LITERAL) { KEEP(*(.azos_keys)) }
    __azos_keys_end = .;
    /* The in-kernel test registry (Kconfig KTEST, crates/core/ktest); empty
     * with KTEST off. */
    .azos_ktest : AT(ADDR(.azos_ktest) - KERNEL_VA_OFFSET_LITERAL) {
        __azos_ktest_start = .; KEEP(*(.azos_ktest)) __azos_ktest_end = .;
    }
    _rodata_end = .;

    . = ALIGN(4K);
    _data_start = .;
    .got : AT(ADDR(.got) - KERNEL_VA_OFFSET_LITERAL) { *(.got .got.*) }
    .data : AT(ADDR(.data) - KERNEL_VA_OFFSET_LITERAL) { *(.data .data.*) }
    _data_end = .;

    . = ALIGN(4K);
    _bss_start = .;
    .bss : AT(ADDR(.bss) - KERNEL_VA_OFFSET_LITERAL) { *(.bss .bss.*) *(COMMON) }
    _bss_end = .;

    /* The red zone below the boot stack separates it from the last statics
     * of .bss; boot.S paints both and `boot_stack_report` reads them back. */
    . = ALIGN(4K);
    _stack_redzone = .;
    . += BOOT_STACK_REDZONE;
    _stack_start = .;
    . += BOOT_STACK_SIZE;
    _stack_end = .;

    _kernel_end = .;
}

/* The offset above is Rust's `azos_arch::mmu::KERNEL_VA_OFFSET` (boot.S's
 * `_kernel_va_offset_check`): a drift fails to link. */
ASSERT(_kernel_va_offset_check == KERNEL_VA_OFFSET_LITERAL,
    "linker-x86_64.ld's KERNEL_VA_OFFSET_LITERAL disagrees with arch-x86_64::mmu::KERNEL_VA_OFFSET")
ASSERT(_kernel_end - KERNEL_VA_OFFSET_LITERAL <= 0x40000000,
    "the x86_64 image must end in the first GiB: the AP start tables (smp.rs) map that GiB only")

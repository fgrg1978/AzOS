/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for AZOS fleet-profile builds.
 *
 * `PROFILE_FLEET` (RFC-0023 / RFC-0026) sizes static tables for
 * 4096 tasks × {channels,pipes,topics,caps} pools.  The image is
 * ~134 MiB (config/defconfigs/fleet.config carries the measured budget), far
 * above the default linker.ld's 8M RAM region.  The 256 MiB kernel heap
 * (KERNEL_HEAP_SIZE) is not in the image: kernel_main takes it from the
 * page allocator after `_kernel_end`, so RAM_SIZE must cover both.
 *
 * Target hardware: gateway / edge-server boards with ≥ 1 GiB RAM
 * (RK3588 8-32 GiB, AGX Orin 32 GiB, server-class SoCs).  NOT for
 * VF2 / K1 / single-robot SBCs — use linker.ld / linker-vf2.ld /
 * linker-k1.ld for those.
 *
 * Memory layout (same OpenSBI base as default; just a bigger RAM):
 *   0x80000000 - 0x801FFFFF : OpenSBI firmware (2 MiB)
 *   0x80200000 - 0xC0000000 : Kernel (1022 MiB available)
 *
 * 1022 MiB headroom is enough for:
 *   .text  ~3 MiB
 *   .rodata ~2 MiB
 *   .data  ~16 MiB (static tables + caps pool)
 *   .bss   kernel stacks, TCP rings, pipe pool, per-task buffers
 *   .stack BOOT_STACK_SIZE boot stack above a BOOT_STACK_REDZONE,
 *          after .bss and below _kernel_end
 *   heap   256 MiB from the page allocator, after _kernel_end
 *
 * The linker.ld pattern (single RAM region, sections flow in order)
 * is preserved so build.rs / kernel/src/main.rs see the same
 * `_text_start` / `_bss_end` / `_kernel_end` / `_stack_start`
 * symbols that the default script exports.
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/* BOOT_STACK_SIZE / BOOT_STACK_REDZONE (B1-01): single source, see
 * kernel/linker-common.ld. */
INCLUDE kernel/linker-common.ld

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80200000, LENGTH = 1022M
}

SECTIONS
{
    . = 0x80200000;

    /* Boot code first */
    _text_start = .;
    .text.boot : ALIGN(4K)
    {
        *(.text.boot)
    } > RAM

    /* All other code */
    .text : ALIGN(4K)
    {
        *(.text .text.*)
    } > RAM
    _text_end = .;

    /* Read-only data */
    _rodata_start = .;
    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
        /* Wave 15 (TRACE): the static-key site table, {site, target, key,
         * kind} per tracepoint (crates/core/trace/src/jump.rs). In .rodata:
         * read-only, never executable; KEEP, since nothing references an entry. */
        . = ALIGN(8);
        __azos_keys_start = .;
        KEEP(*(.azos_keys))
        __azos_keys_end = .;
    } > RAM
    _rodata_end = .;

    /* Initialized data */
    _data_start = .;
    .data : ALIGN(4K)
    {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > RAM
    _data_end = .;

    /* Uninitialized data (BSS) — fleet profile lives here in bulk. */
    .bss : ALIGN(4K)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(8);
        _bss_end = .;
    } > RAM

    /* Boot stack inside the image, below _kernel_end: see kernel/linker.ld. */
    .stack (NOLOAD) : ALIGN(4K)
    {
        _stack_redzone = .;
        . += BOOT_STACK_REDZONE;
        _stack_start = .;
        . += BOOT_STACK_SIZE;
        _stack_end = .;
    } > RAM

    . = ALIGN(4K);
    _kernel_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
        *(.note*)
    }
}

ASSERT(_stack_end <= _kernel_end, "Boot stack must lie inside the kernel image")

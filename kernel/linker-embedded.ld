/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for AZOS embedded-profile builds (config/defconfigs/embedded.config).
 *
 * Target: rv64 boards with 16-64 MiB of RAM. The layout is kernel/linker.ld's
 * (same symbols, same `.stack` section with its red zone below _kernel_end);
 * what differs is the size of the RAM region and a named budget on the image.
 *
 * Memory layout (OpenSBI base, as on QEMU virt):
 *   0x80000000 - 0x801FFFFF : OpenSBI firmware (2 MiB)
 *   0x80200000 - 0x80FFFFFF : kernel region on a 16 MiB board (14 MiB)
 *
 * The RAM region is sized for the smallest board the profile targets, 16 MiB,
 * so one binary links for both 16 and 64 MiB: the PMM takes the RAM size from
 * the device tree at boot, and `RAM_SIZE` only bounds the heap at build time.
 *
 * EMBEDDED_IMAGE_BUDGET bounds [0x80200000, _kernel_end): .text through
 * .bss plus the boot stack and its red zone. It does NOT include the kernel
 * heap (KERNEL_HEAP_SIZE), which the kernel reserves at boot right after
 * _kernel_end, nor the page-table pages and task frames the PMM hands out.
 * Those must fit in the rest of the 14 MiB region; `tools/size_report.sh`
 * prints both numbers per profile.
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/* BOOT_STACK_SIZE / BOOT_STACK_REDZONE (B1-01): single source, see
 * kernel/linker-common.ld — same sizes as kernel/linker.ld, so
 * `boot_stack_report` reads the same red zone. */
INCLUDE kernel/linker-common.ld

/* The image budget: see the header. The measured image is printed by
 * tools/size_report.sh. */
EMBEDDED_IMAGE_BUDGET = 8M;

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80200000, LENGTH = 14M
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
    /* Live-update patch pool (Kconfig LIVEPATCH_POOL_KIB, config/Kconfig.development):
     * RX room inside the image's text range, so the W^X and no-exec-outside-
     * the-image checks (_text_start.._text_end) cover it. The size reaches
     * the linker as --defsym=__patch_pool_bytes (tools/kconfig_to_cargo.py
     * --rustflags); 0 or absent = an empty section, no byte. Zero-filled:
     * a stray jump into it traps. */
    .text.patch_pool : ALIGN(4K)
    {
        __patch_pool_start = .;
        KEEP(*(.patch_pool_anchor))
        FILL(0)
        . += DEFINED(__patch_pool_bytes) ? __patch_pool_bytes : 0;
        __patch_pool_end = .;
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
        /* The in-kernel test registry (Kconfig KTEST, crates/core/ktest): one
         * 24-byte {name, fn} entry per `ktest!`. Right after the key table,
         * whose 24-byte entries leave `.` 8-aligned, so with KTEST off the
         * section is empty and costs no byte. KEEP: nothing references an entry. */
        __azos_ktest_start = .;
        KEEP(*(.azos_ktest))
        __azos_ktest_end = .;
    } > RAM
    /* Live-update site table (.azos_patch): 8-byte entries, the address of a
     * patchable function entry (the compiler's __patchable_function_entries,
     * LIVEPATCH_ENTRY_NOPS > 0) or of a hand-registered site. KEEP: nothing
     * references an entry. Empty with the hook off. */
    .azos_patch : ALIGN(8)
    {
        __azos_patch_start = .;
        KEEP(*(.azos_patch))
        KEEP(*(__patchable_function_entries))
        __azos_patch_end = .;
    } > RAM
    _rodata_end = .;

    /* Initialized data */
    _data_start = .;
    /* Set-once function-pointer hooks and the x86 IDT (azos_common::hook,
     * security audit 2026-10-17 finding D). First in the data range so the
     * W^X pass maps it RW while the boot installs the hooks, and listed
     * BEFORE `.data` because that glob would otherwise take the input
     * section. Page-aligned at both ends: the boot seals it read-only
     * (azos_mm::vmm::seal_ro_after_init) without touching a neighbour. */
    .data.ro_after_init : ALIGN(4K)
    {
        __ro_after_init_start = .;
        *(.data.ro_after_init)
        . = ALIGN(4K);
        __ro_after_init_end = .;
    } > RAM
    .data : ALIGN(4K)
    {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > RAM
    _data_end = .;

    /* Uninitialized data (BSS) */
    .bss : ALIGN(4K)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(8);           /* ensure _bss_end is 8-byte aligned for sd-based clear */
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
ASSERT(_kernel_end - 0x80200000 <= EMBEDDED_IMAGE_BUDGET,
       "embedded image exceeds EMBEDDED_IMAGE_BUDGET (kernel/linker-embedded.ld)")

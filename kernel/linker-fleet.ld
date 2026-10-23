/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for AZOS fleet-profile builds.
 *
 * The Fleet tier (`HWCLASS_SERVER`) sizes static tables for
 * 4096 tasks × {channels,pipes,topics,caps} pools.  The image is
 * ~134 MiB (config/defconfigs/generic-server-riscv64+board-generic.config carries the measured budget), far
 * above the default linker.ld's 8M RAM region.  The 256 MiB kernel heap
 * (KERNEL_HEAP_SIZE) is not in the image: kernel_main takes it from the
 * page allocator after `_kernel_end`, so the RAM must cover both.
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
    /* Live-update patch pool (Kconfig LIVEPATCH_POOL_KIB, config/kernel/Kconfig.livepatch):
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
        __start_azos_ktest = .;
        KEEP(*(azos_ktest))
        __stop_azos_ktest = .;
        /* The trusted secure-boot public key (`SECURE_BOOT_PUBKEY`,
         * crates/core/ota/src/secure_boot.rs, `#[link_section =
         * ".secure_boot_pubkey"]`). Named here, never an orphan whose place
         * lld picks: inside [_rodata_start, _rodata_end) the W^X sweep maps
         * it read-only. The ASSERT at the end of this script checks it. */
        . = ALIGN(8);
        KEEP(*(.secure_boot_pubkey))
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
    /* Virtual KASLR: the relocation table (Kconfig KASLR); empty otherwise. */
    INCLUDE kernel/reloc-riscv64.ld
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
ASSERT(!DEFINED(SECURE_BOOT_PUBKEY) || (SECURE_BOOT_PUBKEY >= _rodata_start && SECURE_BOOT_PUBKEY < _rodata_end),
       "SECURE_BOOT_PUBKEY must lie inside [_rodata_start, _rodata_end), which W^X maps read-only")

/* The start of RAM (as kernel/linker.ld), below OpenSBI: the Image header's text_offset. */
_dram_base = 0x80000000;
INCLUDE kernel/image-header-riscv64.ld

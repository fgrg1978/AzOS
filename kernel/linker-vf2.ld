/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for AzOS — StarFive VisionFive 2 (JH7110)
 *
 * JH7110 memory layout with U-Boot + OpenSBI:
 *   0x40000000 - 0x401FFFFF : OpenSBI firmware (2 MiB, reserved)
 *   0x40200000 - ...        : Kernel (loaded here by U-Boot)
 *   DDR size: 4 GiB (0x40000000 .. 0x140000000) on 4 GB board
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/* BOOT_STACK_SIZE / BOOT_STACK_REDZONE (B1-01): single source, see
 * kernel/linker-common.ld. */
INCLUDE kernel/linker-common.ld

MEMORY
{
    RAM (rwx) : ORIGIN = 0x40200000, LENGTH = 128M
}

SECTIONS
{
    . = 0x40200000;

    _text_start = .;
    .text.boot : ALIGN(4K)
    {
        *(.text.boot)
    } > RAM

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

/* The start of RAM (JH7110), below OpenSBI: the Image header's text_offset. */
_dram_base = 0x40000000;
INCLUDE kernel/image-header-riscv64.ld

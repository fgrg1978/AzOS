/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for AzOS (Rust)
 * Target: RISC-V 64-bit (QEMU virt)
 *
 * Memory layout with OpenSBI:
 *   0x80000000 - 0x801FFFFF : OpenSBI firmware (2MB)
 *   0x80200000 - ...        : Kernel (loaded here)
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/*
 * BOOT_STACK_SIZE / BOOT_STACK_REDZONE (B1-01): single source in
 * linker-common.ld, INCLUDEd by every board/profile linker script so the
 * five copies cannot drift apart. See that file for the measurement this
 * value is based on.
 */
INCLUDE kernel/linker-common.ld

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80200000, LENGTH = 32M
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
     * the linker as --defsym=__patch_pool_bytes (tools/build/kconfig_to_cargo.py
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
    INCLUDE arch/riscv64/boot/reloc-riscv64.ld
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

    /* Boot stack, inside the image: below _kernel_end, so `pmm::init` reserves
     * it with the kernel and nothing placed after _kernel_end can cover it.
     * At the top of the RAM window it sat inside the kernel heap's range.
     * NOLOAD: no bytes in the file. Outside [_bss_start, _bss_end), so the
     * BSS clear in boot.S, which runs on this stack, leaves it alone.
     * The red zone below it separates the stack from the last statics of
     * .bss; boot.S paints both and `boot_stack_report` in kernel/src/boot/stacks.rs reads them
     * back, so an overflow is reported before it reaches a static. */
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

/* The start of RAM (QEMU virt), below OpenSBI: the Image header's text_offset. */
_dram_base = 0x80000000;
INCLUDE arch/riscv64/boot/image-header-riscv64.ld

/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* UE03 — Linker script for the azos EFI stub + kernel.
 *
 * Produces an ELF image that `llvm-objcopy --target=efi-app-riscv64`
 * can convert to a PE/COFF .EFI binary suitable for UEFI boot.
 *
 * Layout:
 *   0x00200000   .text     (entry stub + kernel code)
 *   aligned     .rodata
 *   aligned     .data      (RW runtime data)
 *   aligned     .bss       (zero-initialised)
 *
 * UEFI requires 4 KiB section alignment for PE/COFF — the sections below
 * are explicitly 4 KiB aligned so llvm-objcopy's PE writer doesn't have
 * to pad.
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS {
    . = 0x00200000;                 /* PE ImageBase */

    .text ALIGN(4K) : {
        *(.text._start)
        *(.text.efi_handoff)
        *(.text .text.*)
    }

    /* Live-update patch pool (Kconfig LIVEPATCH_POOL_KIB): RX room right
     * after the code, empty when the size is 0 (see kernel/linker.ld). */
    .text.patch_pool ALIGN(4K) : {
        __patch_pool_start = .;
        KEEP(*(.patch_pool_anchor))
        FILL(0)
        . += DEFINED(__patch_pool_bytes) ? __patch_pool_bytes : 0;
        __patch_pool_end = .;
    }

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
        *(.secure_boot_pubkey)       /* F18 pubkey slot */
    }

    /* Live-update site table (see kernel/linker.ld). */
    .azos_patch ALIGN(8) : {
        __azos_patch_start = .;
        KEEP(*(.azos_patch))
        KEEP(*(__patchable_function_entries))
        __azos_patch_end = .;
    }

    .data ALIGN(4K) : {
        *(.data .data.*)
    }

    .bss ALIGN(4K) : {
        _bss_start = .;
        *(.bss._efi_stack)
        *(.bss._boot_stack_efi)
        *(.bss .bss.* COMMON)
        _bss_end = .;
    }

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
        *(.riscv.attributes)
    }
}

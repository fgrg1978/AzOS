/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for the x86_64 kernel booted through the Limine protocol
 * (`make x86_64-limine`, Kconfig X86_BOOT_LIMINE). It is
 * kernel/linker-x86_64.ld with these differences, and must be kept in step
 * with it otherwise:
 *   - ENTRY(_limine_start), the 64-bit entry at the end of boot.S, not the
 *     PVH note's `_start`; the `.note.Xen` section is discarded;
 *   - `.limine_requests`, the request structs Limine scans the loaded image
 *     for (kernel/src/entry/x86_64/limine.rs), in the writable data segment:
 *     Limine writes the response pointers into them. The start and end
 *     markers bracket the section so the loader scans only it;
 *   - the image is RELOCATABLE IN PHYSICAL MEMORY: Limine loads a higher-half
 *     ELF where IT finds room and maps it at the virtual addresses below,
 *     ignoring the PT_LOAD physical addresses. There is no link-time
 *     physical base: the kernel reads where the loader put the image and
 *     records the slide (`azos_arch::mmu::image_phys`). The load addresses
 *     below (LMA) exist only because every output section needs one;
 *   - the boot stack and its red zone are a NOBITS output section of their
 *     own, so they are inside the last PT_LOAD and the loader allocates
 *     them with the image (PVH leaves them past the loaded part).
 *
 * Layout (the aarch64 TTBR1 model, one offset):
 *   - link address (VMA): KERNEL_VA_OFFSET_LITERAL + IMAGE_LINK_BASE, in the
 *     top 2 GiB (`-mcmodel=kernel`: absolute symbol references are
 *     sign-extended 32-bit). Every section below carries
 *     `AT(ADDR(sec) - OFFSET)`, .eh_frame and .got included; a section this
 *     script does not name inherits the previous one's VMA-LMA difference
 *     (lld), where an orphan without `AT` would keep LMA = VMA;
 *   - boot.S's 64-bit tail runs on the tables `limine_prepare` builds from
 *     the loader's answer; the AP trampoline maps the image the same way
 *     (`azos_arch::smp::build_image_map`);
 *   - the offset is Rust's `azos_arch::mmu::KERNEL_VA_OFFSET`: boot.S emits
 *     it as `_kernel_va_offset_check` and the ASSERT at the end ties the
 *     literal here to it, so a drift fails to LINK.
 *
 * Symbols the shared code reads (same names on every ISA):
 *   _text_start _text_end _rodata_start _rodata_end _data_start _data_end
 *   _bss_start _bss_end _stack_start _stack_end _kernel_end
 *   __azos_keys_start __azos_keys_end   (the signed-boot key section)
 *   __start_azos_ktest __stop_azos_ktest (the in-kernel test registry)
 *   __azos_patch_start __azos_patch_end (the live-update site table)
 *   __patch_pool_start __patch_pool_end (the live-update patch pool, inside text)
 */

OUTPUT_ARCH(i386:x86-64)
ENTRY(_limine_start)

INCLUDE kernel/linker-common.ld

/* The image's offset from KERNEL_VA_OFFSET_LITERAL. Only its virtual place
 * matters (2 MiB, aligned like a large page: the kernel's own tables map the
 * image with large pages where virtual and physical agree modulo 2 MiB); the
 * physical place is the loader's. */
IMAGE_LINK_BASE = 0x200000;
KERNEL_VA_OFFSET_LITERAL = 0xFFFFFFFF80000000;

SECTIONS
{
    . = IMAGE_LINK_BASE + KERNEL_VA_OFFSET_LITERAL;

    /* The PVH entry note (boot.S) is for QEMU's -kernel; not wanted here. */
    /DISCARD/ : { *(.note.Xen) }
    /* The GNU property note of -Z cf-protection=branch objects (Kconfig
     * X86_CET_IBT): nothing reads it here, and an orphan would keep LMA = VMA. */
    /DISCARD/ : { *(.note.gnu.property) }

    . = ALIGN(4K);
    _text_start = .;
    .text : AT(ADDR(.text) - KERNEL_VA_OFFSET_LITERAL) { KEEP(*(.text.boot)) *(.text .text.*) }
    /* Live-update patch pool (Kconfig LIVEPATCH_POOL_KIB, config/Kconfig.development):
     * RX room inside the image's text range, so the W^X and no-exec-outside-
     * the-image checks (_text_start.._text_end) cover it. The size reaches
     * the linker as --defsym=__patch_pool_bytes (tools/kconfig_to_cargo.py
     * --rustflags); 0 or absent = an empty section, no byte. Zero-filled:
     * a stray jump into it traps. */
    . = ALIGN(4K);
    .text.patch_pool : AT(ADDR(.text.patch_pool) - KERNEL_VA_OFFSET_LITERAL)
    {
        __patch_pool_start = .;
        KEEP(*(.patch_pool_anchor))
        FILL(0)
        . += DEFINED(__patch_pool_bytes) ? __patch_pool_bytes : 0;
        __patch_pool_end = .;
    }
    _text_end = .;

    . = ALIGN(4K);
    _rodata_start = .;
    .rodata : AT(ADDR(.rodata) - KERNEL_VA_OFFSET_LITERAL)
    {
        *(.rodata .rodata.*)
        /* The trusted secure-boot public key (`SECURE_BOOT_PUBKEY`,
         * crates/core/ota/src/secure_boot.rs, `#[link_section =
         * ".secure_boot_pubkey"]`). Named here, never an orphan whose place
         * lld picks: inside [_rodata_start, _rodata_end) the W^X sweep maps
         * it read-only. The ASSERT at the end of this script checks it. */
        . = ALIGN(8);
        KEEP(*(.secure_boot_pubkey))
    }
    .eh_frame_hdr : AT(ADDR(.eh_frame_hdr) - KERNEL_VA_OFFSET_LITERAL) { *(.eh_frame_hdr) }
    .eh_frame : AT(ADDR(.eh_frame) - KERNEL_VA_OFFSET_LITERAL) { KEEP(*(.eh_frame)) }
    . = ALIGN(4K);
    __azos_keys_start = .;
    .azos_keys : AT(ADDR(.azos_keys) - KERNEL_VA_OFFSET_LITERAL) { KEEP(*(.azos_keys)) }
    __azos_keys_end = .;
    /* The in-kernel test registry (Kconfig KTEST, crates/core/ktest); empty
     * with KTEST off. */
    .azos_ktest : AT(ADDR(.azos_ktest) - KERNEL_VA_OFFSET_LITERAL) {
        __start_azos_ktest = .; KEEP(*(azos_ktest)) __stop_azos_ktest = .;
    }
    /* Live-update site table (.azos_patch): 8-byte entries, the address of a
     * patchable function entry (the compiler's __patchable_function_entries,
     * LIVEPATCH_ENTRY_NOPS > 0) or of a hand-registered site. KEEP: nothing
     * references an entry. Empty with the hook off. */
    . = ALIGN(8);
    .azos_patch : AT(ADDR(.azos_patch) - KERNEL_VA_OFFSET_LITERAL)
    {
        __azos_patch_start = .;
        KEEP(*(.azos_patch))
        KEEP(*(__patchable_function_entries))
        __azos_patch_end = .;
    }
    _rodata_end = .;

    . = ALIGN(4K);
    _data_start = .;
    /* Set-once function-pointer hooks and the x86 IDT (azos_common::hook,
     * security audit 2026-10-17 finding D). First in the data range so the
     * W^X pass maps it RW while the boot installs the hooks, and listed
     * BEFORE `.data` because that glob would otherwise take the input
     * section. Page-aligned at both ends: the boot seals it read-only
     * (azos_mm::vmm::seal_ro_after_init) without touching a neighbour. */
    .data.ro_after_init : AT(ADDR(.data.ro_after_init) - KERNEL_VA_OFFSET_LITERAL) ALIGN(4K)
    {
        __ro_after_init_start = .;
        *(.data.ro_after_init)
        . = ALIGN(4K);
        __ro_after_init_end = .;
    }
    .got : AT(ADDR(.got) - KERNEL_VA_OFFSET_LITERAL) { *(.got .got.*) }
    .data : AT(ADDR(.data) - KERNEL_VA_OFFSET_LITERAL) { *(.data .data.*) }
    /* Limine's requests: 8-byte aligned, writable (the loader fills in the
     * responses), between the start and end markers. KEEP: nothing in the
     * kernel's own code references the markers. */
    . = ALIGN(8);
    .limine_requests : AT(ADDR(.limine_requests) - KERNEL_VA_OFFSET_LITERAL)
    {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    }
    _data_end = .;

    . = ALIGN(4K);
    _bss_start = .;
    .bss : AT(ADDR(.bss) - KERNEL_VA_OFFSET_LITERAL) { *(.bss .bss.*) *(COMMON) }
    _bss_end = .;

    /* The red zone below the boot stack separates it from the last statics
     * of .bss; boot.S paints both and `boot_stack_report` reads them back.
     * An output section of its own (NOLOAD: SHT_NOBITS, no file bytes). lld
     * emits it SHF_ALLOC|SHF_WRITE and gives it a PT_LOAD of its own (checked
     * with llvm-readobj on the linked image: memsz = red zone + stack), so
     * the loader reserves the memory with the image. The ASSERTs at the end
     * fail the link if the section ever comes out empty (dropped) or the
     * stack stops being the end of the image, where `limine_prepare` maps
     * the image up to `_kernel_end`. */
    . = ALIGN(4K);
    .boot_stack (NOLOAD) : AT(ADDR(.boot_stack) - KERNEL_VA_OFFSET_LITERAL)
    {
        _stack_redzone = .;
        . += BOOT_STACK_REDZONE;
        _stack_start = .;
        . += BOOT_STACK_SIZE;
        _stack_end = .;
    }

    _kernel_end = .;

    /* boot.S's 32-bit stage (never run under Limine) names these. */
    INCLUDE kernel/boot-pa-x86_64.ld
}

/* The offset above is Rust's `azos_arch::mmu::KERNEL_VA_OFFSET` (boot.S's
 * `_kernel_va_offset_check`): a drift fails to link. */
ASSERT(_kernel_va_offset_check == KERNEL_VA_OFFSET_LITERAL,
    "linker-x86_64.ld's KERNEL_VA_OFFSET_LITERAL disagrees with arch-x86_64::mmu::KERNEL_VA_OFFSET")
ASSERT(_kernel_end - KERNEL_VA_OFFSET_LITERAL <= 0x40000000,
    "the x86_64 image must end in the first GiB: the AP start tables (smp.rs) map that GiB only")
ASSERT(!DEFINED(SECURE_BOOT_PUBKEY) || (SECURE_BOOT_PUBKEY >= _rodata_start && SECURE_BOOT_PUBKEY < _rodata_end),
    "SECURE_BOOT_PUBKEY must lie inside [_rodata_start, _rodata_end), which W^X maps read-only")
ASSERT(SIZEOF(.boot_stack) == BOOT_STACK_REDZONE + BOOT_STACK_SIZE,
    "the x86_64 Limine boot stack section is empty or mis-sized: the loader would not reserve the stack")
ASSERT(_stack_redzone == ADDR(.boot_stack) && _stack_end == ADDR(.boot_stack) + SIZEOF(.boot_stack) && _stack_end == _kernel_end,
    "the x86_64 Limine boot stack must be the last bytes of the image, inside the .boot_stack section")

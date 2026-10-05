/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Linker script for AzOS (Rust) — AArch64 ENTRY (Item 2 Stage 5).
 * Target: aarch64-unknown-none, QEMU `-M virt`.
 *
 * QEMU `-kernel <elf>` on `virt` loads program headers verbatim and jumps
 * to the ELF entry point — no firmware in front of us. 0x4008_0000 is the
 * address tests/qemu/aarch64-smoke's linker script already boots at (512 KiB
 * into the 0x4000_0000 DRAM base, leaving room below for QEMU's own
 * setup); reused here so the two boot paths agree on where "the start of
 * usable RAM for a `-kernel` load" is instead of picking a second answer.
 *
 * ── Build command (Item 2 Stage 5, kernel crate — task item 5) ──────────
 *
 *   env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
 *     cargo build --release --target aarch64-unknown-none \
 *     -p azos_kernel \
 *     --config 'build.rustflags=["-C","link-arg=-Tkernel/linker-aarch64.ld"]'
 *
 * `-Z build-std` is NOT passed on the command line, unlike
 * tests/qemu/aarch64-smoke's `+nightly -Z build-std=core,compiler_builtins
 * -Z build-std-features=compiler-builtins-mem` (see tools/ci_check.sh's
 * "aarch64 smoke (build)" row). The repo's own root `.cargo/config.toml`
 * already sets, workspace-wide and target-independent:
 *
 *   [unstable]
 *   build-std = ["core", "alloc"]
 *   build-std-features = ["compiler-builtins-mem"]
 *
 * — which every `cargo` invocation in this tree picks up regardless of
 * `--target`, riscv64 included (that is how the existing riscv64gc build
 * gets `core`/`alloc` rebuilt for a `none` target with no prebuilt std at
 * all). `azos_arch_aarch64`'s ci_check.sh row (`-p azos_arch_aarch64
 * --config "build.rustflags=[]"`) inherits the same `[unstable]` block for
 * the same reason; it looks unrelated only because it doesn't override
 * `build.rustflags` for a linker script, being a library with nothing to
 * link. The smoke crate's own `-Z build-std=...` is redundant with the
 * workspace root's, minus `alloc` (the smoke never allocates) — not a
 * sign that the kernel needs its own copy of the flag.
 *
 * `env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS` matters for the same reason
 * documented next to the smoke row in tools/ci_check.sh: an exported
 * `RUSTFLAGS=""` from the caller's shell OVERRIDES `build.rustflags` from
 * `--config` instead of adding to it, and the link then fails with
 * `undefined symbol: _stack_end` — a harness defect that reads like a
 * code defect.
 */

OUTPUT_ARCH(aarch64)
ENTRY(_start)

/*
 * ── TTBR1 migration: link HIGH, load LOW ────────────────────────────────
 *
 * QEMU/U-Boot still places the raw `objcopy -O binary` image at the same
 * physical address as before this migration (`RAM_LMA`'s ORIGIN below,
 * unchanged from the single-region script this superseded) — nothing about
 * how the image is LOADED changes. What changes is where the CPU executes
 * it FROM: every section's VMA (the `.` this script advances, and what
 * every symbol address resolves to) sits `KERNEL_VA_OFFSET` above its LMA
 * (where the loader actually puts the bytes), reachable only through
 * `TTBR1_EL1` once `boot.S` turns the MMU on and jumps there — see that
 * file's header comment for the low→high sequence and
 * `crates/core/arch-aarch64::mmu`'s module doc for why OFFSET's bits are
 * `[63:39]` only (matching `TCR_EL1.T1SZ = 25`).
 *
 * `KERNEL_VA_OFFSET_LITERAL` exists ONLY so `RAM_VMA`'s ORIGIN below has
 * something to add — it is not read by anything else in this file. The
 * `ASSERT` after SECTIONS is what actually ties this literal to Rust's own
 * `crate::mmu::KERNEL_VA_OFFSET`: `kernel/src/entry/aarch64.rs` emits an
 * absolute symbol via `global_asm!` from that constant
 * (`_kernel_va_offset_check`), and the ASSERT compares it against
 * `ORIGIN(RAM_VMA) - ORIGIN(RAM_LMA)` — the linker's own arithmetic, not a
 * second hand-copied number. A build where the two literals (this file's
 * and `crate::mmu`'s) drift apart fails to LINK, not fails a later runtime
 * marker — "did not compile" is this ASSERT's own discriminating bucket.
 */
/*
 * Translation granule (config/Kconfig.arch AARCH64_PAGE_*). `kernel/build.rs`
 * writes `azos_granule.ld` from the cargo features `page-16k`/`page-64k`:
 * `AZOS_PAGE_SIZE` (4 KiB unless a feature says otherwise — every
 * page-aligned section below aligns to it, so W^X never finds `.text` and
 * `.rodata` in one page) and `KERNEL_VA_OFFSET_LITERAL` (0xFFFFFF8000000000
 * at 4/16 KiB, 0xFFFF000000000000 at 64 KiB). Both are ASSERTed at the end of
 * this file against symbols boot.S emits from Rust's constants.
 */
INCLUDE azos_granule.ld

/*
 * BOOT_STACK_SIZE / BOOT_STACK_REDZONE: single source in linker-common.ld,
 * same as every riscv64 board/profile linker script — see that file for
 * the measurement the value is based on. Reusing it here rather than
 * picking a second aarch64-only number keeps the boot-stack budget one
 * fact instead of "one fact per ISA that happens to agree today."
 */
INCLUDE kernel/linker-common.ld

MEMORY
{
    /*
     * QEMU's `virt` machine defaults to 128 MiB of guest RAM when `-m` is
     * not passed. tests/qemu/aarch64-smoke's linker script declares a full
     * 128M region on top of a 512 KiB offset into that same window
     * (ORIGIN 0x4008_0000 + LENGTH 128M = 0x4808_0000), which overruns
     * the actual end of RAM (0x4800_0000) by exactly that 512 KiB —
     * harmless there only because the smoke binary is far smaller than
     * even the truncated region. Not repeated here: LENGTH is capped to
     * fit inside the same default 128 MiB window this address assumes.
     *
     * RAM_LMA: where the loader (QEMU `-kernel`/U-Boot `booti`) actually
     * places the bytes — unchanged from the pre-migration single-region
     * script. RAM_VMA: where the CPU executes those same bytes from once
     * `boot.S` jumps, `KERNEL_VA_OFFSET_LITERAL` higher. Every SECTIONS
     * entry below places its VMA in RAM_VMA and its LMA in RAM_LMA
     * (`> RAM_VMA AT> RAM_LMA`) — two disjoint regions instead of one, so
     * a section that overflows either the physical image budget or the
     * (identical-sized) virtual window fails to link instead of silently
     * overlapping something.
     */
    RAM_LMA (rwx) : ORIGIN = 0x40080000, LENGTH = 128M - 512K
    RAM_VMA (rwx) : ORIGIN = 0x40080000 + KERNEL_VA_OFFSET_LITERAL, LENGTH = 128M - 512K
}

SECTIONS
{
    . = 0x40080000 + KERNEL_VA_OFFSET_LITERAL;

    /* Boot code first — mirrors kernel/linker.ld's .text.boot placement. */
    _text_start = .;
    .text.boot : ALIGN(AZOS_PAGE_SIZE)
    {
        KEEP(*(.text.boot))
    } > RAM_VMA AT> RAM_LMA

    /*
     * Exception-vector table (entry/aarch64/asm/trap_entry.S) and the
     * EL2->EL1 trampoline (crates/core/arch-aarch64::boot, section
     * .text.azos_boot) — kept explicitly like .text.boot: both are
     * reached only via VBAR_EL1 / `bl` from hand-written asm, never a
     * Rust call the linker can see, so an LTO-unaware "nothing
     * references this" GC pass must not be allowed to drop them.
     * `_vectors` itself carries its own `.balign 2048` (ARM ARM
     * §D1.10 requires the vector table 2 KiB-aligned); that self-alignment
     * doesn't need a dedicated output section to hold.
     */
    .text.vectors : ALIGN(AZOS_PAGE_SIZE)
    {
        KEEP(*(.text.vectors))
        KEEP(*(.text.azos_boot))
    } > RAM_VMA AT> RAM_LMA

    /* All other code */
    .text : ALIGN(AZOS_PAGE_SIZE)
    {
        *(.text .text.*)
    } > RAM_VMA AT> RAM_LMA
    _text_end = .;

    /* Read-only data */
    _rodata_start = .;
    .rodata : ALIGN(AZOS_PAGE_SIZE)
    {
        *(.rodata .rodata.*)

        /*
         * The trusted secure-boot public key (`SECURE_BOOT_PUBKEY`,
         * crates/core/ota/src/secure_boot.rs, `#[link_section =
         * ".secure_boot_pubkey"]`).
         *
         * It MUST be named here, and the reason is specific to this script
         * rather than to the key. kernel/linker.ld (riscv64) maps VMA == LMA,
         * so an orphan section there gets a sane load address by accident.
         * This script runs the kernel out of the TTBR1 high half and uses
         * `AT> RAM_LMA` to put every load address back in low physical RAM —
         * and an ORPHAN section gets no `AT>`, so its LMA stays at the
         * 0xffffff80_........ VMA. `llvm-objcopy -O binary` then spans from
         * 0x40080000 to that address and dies with "failed to allocate memory
         * buffer of ffffff80000ced10 bytes", which is how this was found: the
         * aarch64 kernel linked fine and produced no .img at all.
         *
         * It only bites when the section EXISTS, i.e. when something on the
         * aarch64 path actually references the key — which nothing did until
         * `boot_validate_and_verify_slots()` started running on this ISA.
         *
         * Inside .rodata rather than in an output section of its own so it
         * stays within [_rodata_start, _rodata_end) and the W^X sweep keeps
         * it read-only. The section NAME is not load-bearing: nothing in the
         * tree looks the key up by section (the gate's embedded-key guard
         * byte-scans the ELF), only by the `SECURE_BOOT_PUBKEY` symbol.
         */
        . = ALIGN(8);
        KEEP(*(.secure_boot_pubkey))
    } > RAM_VMA AT> RAM_LMA
    _rodata_end = .;

    /* Initialized data */
    _data_start = .;
    .data : ALIGN(AZOS_PAGE_SIZE)
    {
        *(.data .data.*)
    } > RAM_VMA AT> RAM_LMA
    _data_end = .;

    /* Uninitialized data (BSS) */
    .bss : ALIGN(AZOS_PAGE_SIZE)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(8);           /* ensure _bss_end is 8-byte aligned for str-based clear */
        _bss_end = .;
    } > RAM_VMA AT> RAM_LMA

    /*
     * Boot stack, inside the image: below _kernel_end, so `pmm::init`
     * reserves it with the kernel image, exactly like kernel/linker.ld.
     * NOLOAD: no bytes in the file. Outside [_bss_start, _bss_end), so
     * the BSS clear in boot.S, which runs on this stack, leaves it
     * alone. boot.S paints both the stack and its red zone; the aarch64
     * `kernel_main` calls the SAME `boot_stack_report` riscv64 does
     * (kernel/src/boot/stacks.rs), reading these same three symbols — nothing
     * in that function is ISA-specific.
     */
    .stack (NOLOAD) : ALIGN(AZOS_PAGE_SIZE)
    {
        _stack_redzone = .;
        . += BOOT_STACK_REDZONE;
        _stack_start = .;
        . += BOOT_STACK_SIZE;
        _stack_end = .;
    } > RAM_VMA AT> RAM_LMA

    . = ALIGN(AZOS_PAGE_SIZE);
    _kernel_end = .;

    /*
     * Linker-generated, non-allocated metadata (no input object ever
     * contributes to these — LLD synthesizes them at the end of the
     * link) — kept, not discarded: `llvm-nm`/`llvm-objdump`'s symbol
     * resolution (this migration's own RISC-V-side proof, and every
     * `<function_name>` this tree's own disassembly reading already
     * leans on) reads `.symtab`/`.strtab`. Given no explicit rule,
     * `--orphan-handling=error` treats even these linker-internal
     * sections as unclaimed orphans and fails the link — an explicit
     * rule with no `> REGION` (they carry no SHF_ALLOC bit, so no VMA
     * applies) satisfies it without disturbing where they land in the
     * file.
     */
    .symtab   0 : { *(.symtab) }
    .strtab   0 : { *(.strtab) }
    .shstrtab 0 : { *(.shstrtab) }

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
        /*
         * `.eh_frame_hdr`: NOT emitted before this migration (nothing asked
         * for it), and a real orphan-section trap once the VMA/LMA split
         * landed — an earlier attempt at this same migration found LLD
         * placing it with LMA == VMA == a HIGH address (no output-section
         * rule claimed it, so it fell through to LLD's default orphan
         * placement, which follows the VMA-only view of the world). A
         * `llvm-objcopy -O binary` pass lays the flat image out by LMA, so
         * a high-LMA orphan would make it seek to a file offset near 2^64
         * before this DISCARD existed. `--orphan-handling=error`
         * (Makefile's and `tools/ci_check.sh`'s aarch64 kernel RUSTFLAGS)
         * turns every OTHER orphan into a build failure instead of a
         * repeat of this same silent trap; this one is named explicitly
         * because unwind tables are expected to appear.
         */
        *(.eh_frame_hdr)
        *(.note*)
        *(.ARM.attributes*)
        /*
         * DWARF debug sections (`.debug_info`/`.debug_line`/etc): not
         * SHF_ALLOC, so `objcopy -O binary` never reads them either way
         * (it only walks allocated sections) — discarding them here has
         * zero effect on the `.img` QEMU actually boots, only on whether
         * `--orphan-handling=error` accepts the ELF link at all. This
         * migration's own RISC-V-side `llvm-objdump`/`llvm-nm` proof reads
         * a SEPARATE (riscv64) binary, unaffected by anything in this file.
         */
        *(.debug*)
    }
}

ASSERT(_stack_end <= _kernel_end, "Boot stack must lie inside the kernel image")

/*
 * Cross-check the VMA/LMA split's offset against Rust's own
 * `crate::mmu::KERNEL_VA_OFFSET` — see this file's header comment (right
 * after `ENTRY`) for how `_kernel_va_offset_check` reaches the linker.
 * `ORIGIN(RAM_VMA) - ORIGIN(RAM_LMA)` is the linker's own arithmetic on
 * the MEMORY block above, not a second copy of the literal.
 */
ASSERT(_kernel_va_offset_check == (ORIGIN(RAM_VMA) - ORIGIN(RAM_LMA)),
    "linker-aarch64.ld's KERNEL_VA_OFFSET_LITERAL disagrees with arch-aarch64::mmu::KERNEL_VA_OFFSET")

/* Same tie for the page size: `AZOS_PAGE_SIZE` (kernel/build.rs) against
 * `azos_arch::mmu::PAGE_SIZE` (boot.S's `_azos_page_size_check`). */
ASSERT(_azos_page_size_check == AZOS_PAGE_SIZE,
    "azos_granule.ld's AZOS_PAGE_SIZE disagrees with arch-aarch64::mmu::PAGE_SIZE")

/*
 * ── arm64 Image-format boot header (Item 2 Stage 5, task 1) ────────────
 *
 * `boot.S`'s `_start` opens with the 64-byte header Documentation/arch/
 * arm64/booting.rst specifies (code0/code1, text_offset, image_size,
 * flags, three reserved u64s, "ARM\x64" magic, res5) so QEMU's `-kernel`
 * loader and U-Boot `booti` recognise this ELF's `objcopy -O binary`
 * output as a Linux-protocol Image and pass the FDT address in x0 —
 * unlike a bare ELF `-kernel` load, where x0 is always 0 (established
 * fact, see this task's brief). `boot.S` embeds the two size fields via
 * `.quad _text_offset` / `.quad _image_size`; those must be ABSOLUTE
 * (link-time-constant) symbols, computed HERE rather than in the
 * assembly, because the assembler cannot resolve a difference of two
 * symbols that live in sections it never sees laid out — only the
 * linker, after SECTIONS has placed `_start` and `_kernel_end`, can turn
 * "`_kernel_end` minus `_start`" into one plain number. That is the same
 * pattern `_bss_end - _bss_start`-style symbols use elsewhere in this
 * script; nothing here is a runtime relocation.
 *
 * `_text_offset` is deliberately `LOADADDR(.text.boot) - _dram_base`, the
 * PHYSICAL (LMA) load offset — matching the link address this whole
 * script already assumes (`0x4008_0000` = `_dram_base + 0x8_0000`) — the
 * Image loader is asked to place this exact binary at the exact address
 * it already expects to run at, so no other symbol in this script (or in
 * boot.S) needed to change to make this format switch.
 *
 * **Post-TTBR1-migration: `_start` is a VMA (high), not the LMA the
 * loader cares about.** `_start - _dram_base` (this field's pre-migration
 * form) would have baked `KERNEL_VA_OFFSET` into the header's own
 * `text_offset` field — a loader placing the image at THAT "offset" from
 * `_dram_base` would seek far past the end of RAM. `LOADADDR(.text.boot)`
 * is the section's LMA (`AT(0x40080000)`, see SECTIONS above), unaffected
 * by the VMA/LMA split — this is the fix wave 3 (an earlier attempt at
 * this same migration) needed and did not have: the loader still reads a
 * physical offset either way, and only `LOADADDR` still names one.
 *
 * `image_size` covers the FULL address range the image occupies,
 * `.bss`/`.stack` included (both NOLOAD, zero bytes in the file) — a
 * loader that reserves less than that could place the FDT or an initrd
 * inside the kernel's own uninitialised-data window. `_kernel_end - _start`
 * stays a VMA-VMA delta (both sides shifted by the same
 * `KERNEL_VA_OFFSET`, so the difference is the same byte count LMA-LMA
 * would give — no `LOADADDR` needed here, only for the single offset
 * value above that a loader adds to a base address it does not shift).
 */
_dram_base = 0x40000000;
_text_offset = LOADADDR(.text.boot) - _dram_base;
_image_size = _kernel_end - _start;

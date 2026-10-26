/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * The two numbers of the Linux RISC-V Image header that `_start` opens with
 * (kernel/src/entry/riscv64/asm/boot.S), INCLUDEd at the end of every riscv64
 * script after it sets `_dram_base`, the start of its board's RAM.
 *
 * ABSOLUTE symbols, as linker-aarch64.ld's: `.dword` of an expression that
 * names `_kernel_end` cannot be folded by the assembler, and a difference of
 * two section symbols (or LOADADDR minus a number) is a plain number to the
 * linker, so a position-independent link emits no relocation for them.
 *
 * `_text_offset` is where `booti` places the image: the start of RAM plus
 * this. It is the load address minus `_dram_base`, so the image lands where
 * it is linked. `_image_size` is what the kernel occupies (bss and boot stack
 * included); `booti` refuses an image that says 0.
 */
_text_offset = LOADADDR(.text.boot) - _dram_base;
_image_size = _kernel_end - _start;

ASSERT(_start == ADDR(.text.boot), "the Image header must be the first bytes of the image")
ASSERT(LOADADDR(.text.boot) >= _dram_base, "the image must load inside RAM")

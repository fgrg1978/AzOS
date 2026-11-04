/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Virtual KASLR (Kconfig KASLR, not n): the relocation table of the
 * position-independent link, INCLUDEd inside SECTIONS by every riscv64 script
 * that links an MMU image (linker.ld, -vf2, -k1, -fleet; not -embedded, whose
 * boards have no MMU to slide the image on). Right before `_rodata_end`, so
 * the W^X pass makes it read-only like the rest of .rodata.
 *
 * `.rela.dyn` holds one 24-byte {offset, info, addend} entry per
 * pointer-bearing word of the image, all R_RISCV_RELATIVE; boot.S hands its
 * bounds to `riscv64_early_kaslr`, which adds the slide to each target before
 * the jump to the slid address. The dynamic-linking tables lld always emits for
 * a -pie link are named here only so they stay inside the image's range and
 * its load layout: nothing reads them. All of it is empty (the output sections
 * are dropped, the two bounds are equal) in a link that is not
 * position-independent.
 */
    .rela.dyn : ALIGN(8)
    {
        __rela_start = .;
        *(.rela.dyn)
        __rela_end = .;
    } > RAM
    .dynsym   : ALIGN(8) { *(.dynsym) }   > RAM
    .gnu.hash : ALIGN(8) { *(.gnu.hash) } > RAM
    .hash     : ALIGN(8) { *(.hash) }     > RAM
    .dynstr   : ALIGN(8) { *(.dynstr) }   > RAM
    .dynamic  : ALIGN(8) { *(.dynamic) }  > RAM

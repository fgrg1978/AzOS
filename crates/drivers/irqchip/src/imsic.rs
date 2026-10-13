// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IMSIC (Incoming MSI Controller) driver — RISC-V AIA, RFC-0046 stage 1a.
//!
//! One IMSIC "interrupt file" per hart and privilege level receives
//! message-signalled interrupts: a 32-bit write of identity `id` to the
//! file's physical address makes `id` pending in that file. This module
//! drives the CURRENT hart's S-level file through the `siselect`/`sireg`/
//! `stopei` CSRs (`azos_arch::csr`). The file's MMIO page is never
//! touched by the kernel: only a device (PCI MSI-X) or the APLIC in MSI
//! mode writes it, so it needs no kernel page-table mapping.
//!
//! Indirect register numbers (AIA spec, IMSIC chapter; Linux
//! `include/linux/irqchip/riscv-imsic.h`): `eidelivery` 0x70,
//! `eithreshold` 0x72, `eip0` 0x80.., `eie0` 0xc0...
//!
//! Identity numbering: wired sources routed through the APLIC use their
//! APLIC source number as identity (`irqchip::wire_aia_source`), so a
//! wired line keeps the number the PLIC used for it (`UART_IRQ` = 10).
//! MSI-X vectors get identities above the APLIC's source range
//! (`irqchip::alloc_msi_ids`).

use azos_arch::csr;

const SEL_EIDELIVERY: usize = 0x70;
const SEL_EITHRESHOLD: usize = 0x72;
const SEL_EIE0: usize = 0xc0;

/// `IMSIC_MMIO_PAGE_SHIFT` — one interrupt file is one 4 KiB page.
pub const IMSIC_MMIO_PAGE_SHIFT: u32 = 12;

/// Where the S-level interrupt files of one IMSIC group live, from the
/// DTB's `riscv,imsics` node (the one whose `interrupts-extended` names
/// cause 9, Supervisor External).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupLayout {
    /// Physical address of hart 0's S-level file.
    pub base: usize,
    /// `riscv,num-ids` — the highest identity the files implement.
    pub num_ids: u32,
    /// Byte distance between consecutive harts' files:
    /// `1 << (IMSIC_MMIO_PAGE_SHIFT + riscv,guest-index-bits)`.
    pub hart_stride: usize,
}

impl GroupLayout {
    pub const fn stride_for_guest_bits(guest_index_bits: u32) -> usize {
        1usize << (IMSIC_MMIO_PAGE_SHIFT + guest_index_bits)
    }

    /// The MSI target address for `hart`: what a PCI MSI-X table entry's
    /// address must hold for its data (the identity) to become pending in
    /// `hart`'s S-level file. Assumes hart index == hart id, which is how
    /// QEMU `virt` orders `interrupts-extended` (cpu@0, cpu@1, ...).
    pub const fn msi_target_addr(&self, hart: u32) -> usize {
        self.base + hart as usize * self.hart_stride
    }
}

/// `eie` selector covering `id`. RV64 uses only the even selectors
/// (`eie0`, `eie2`, ...), each 64 identities wide; the odd ones do not
/// exist on RV64, so this never produces one.
pub const fn eie_selector(id: u32) -> usize {
    SEL_EIE0 + 2 * (id / 64) as usize
}

pub const fn eie_bit(id: u32) -> u64 {
    1u64 << (id % 64)
}

/// `stopei` value -> identity (bits 26:16). 0 means nothing pending.
pub const fn topei_identity(raw: u32) -> u32 {
    (raw >> csr::TOPEI_ID_SHIFT) & csr::TOPEI_ID_MASK
}

/// Initialize the CURRENT hart's S-level file: delivery on, threshold 0
/// (every enabled identity is delivered).
pub fn init() {
    csr::write_siselect(SEL_EIDELIVERY);
    csr::write_sireg(1);
    csr::write_siselect(SEL_EITHRESHOLD);
    csr::write_sireg(0);
}

/// Enable identity `id` in the CURRENT hart's file. Identity 0 does not
/// exist and is ignored.
pub fn enable(id: u32) {
    if id == 0 {
        return;
    }
    csr::write_siselect(eie_selector(id));
    let cur = csr::read_sireg() as u64;
    csr::write_sireg((cur | eie_bit(id)) as usize);
}

pub fn disable(id: u32) {
    if id == 0 {
        return;
    }
    csr::write_siselect(eie_selector(id));
    let cur = csr::read_sireg() as u64;
    csr::write_sireg((cur & !eie_bit(id)) as usize);
}

/// Claim the highest-priority pending and enabled identity of the CURRENT
/// hart's file. The `stopei` write in the same instruction clears that
/// identity's pending bit — there is no separate completion step in the
/// IMSIC. Returns 0 when nothing is pending.
pub fn claim() -> u32 {
    topei_identity(csr::swap_stopei_zero() as u32)
}

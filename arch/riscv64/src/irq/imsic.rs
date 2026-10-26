// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IMSIC (Incoming MSI Controller) driver — RISC-V AIA.
//!
//! One IMSIC "interrupt file" per hart and privilege level receives
//! message-signalled interrupts: a 32-bit write of identity `id` to the
//! file's physical address makes `id` pending in that file. This module
//! drives the CURRENT hart's S-level file through the `siselect`/`sireg`/
//! `stopei` CSRs (`crate::cpu`). The file's MMIO page is never
//! touched by the kernel: only a device (PCI MSI-X) or the APLIC in MSI
//! mode writes it, so it needs no kernel page-table mapping.
//!
//! Indirect register numbers (AIA spec, IMSIC chapter; Linux
//! `include/linux/irqchip/riscv-imsic.h`): `eidelivery` 0x70,
//! `eithreshold` 0x72, `eip0` 0x80.., `eie0` 0xc0...
//!
//! # Guest files
//!
//! Besides its supervisor file a hart has `guest-index-bits`-many guest
//! files, one page each, following it in the hart's block (file `n` at the
//! supervisor file's address plus `n` pages). A guest file is not driven like
//! the S-level one: the monitor reaches the file `hstatus.VGEIN` selects
//! through `vsiselect`/`vsireg` (the guest's own `siselect`/`sireg` when V=1)
//! and clears it ([`vs_prepare`]) before a new owner's vCPU runs; the page is
//! mapped nowhere in the kernel. The pure half (layout, selectors) runs under
//! the host tests.
//!
//! Identity numbering: wired sources routed through the APLIC use their
//! APLIC source number as identity (`irqchip::wire_aia_source`), so a
//! wired line keeps the number the PLIC used for it (`UART_IRQ` = 10).
//! MSI-X vectors get identities above the APLIC's source range
//! (`irqchip::alloc_msi_ids`).

#[cfg(target_arch = "riscv64")]
use crate::cpu;

const SEL_EIDELIVERY: usize = 0x70;
const SEL_EITHRESHOLD: usize = 0x72;
const SEL_EIP0: usize = 0x80;
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

    /// The MSI target address for logical CPU `cpu`: what a PCI MSI-X table
    /// entry's address must hold for its data (the identity) to become
    /// pending in that CPU's S-level file. The file index is the hart's
    /// hardware id (`super::hw_hart`), which is how QEMU `virt` orders
    /// `interrupts-extended` (cpu@0, cpu@1, ...).
    #[cfg(target_arch = "riscv64")]
    pub fn msi_target_addr(&self, cpu: u32) -> usize {
        self.base + super::hw_hart(cpu) as usize * self.hart_stride
    }

    /// Guest files each hart has: its block holds the supervisor file and
    /// then these.
    pub const fn guest_files(&self) -> u32 {
        ((self.hart_stride >> IMSIC_MMIO_PAGE_SHIFT) as u32).saturating_sub(1)
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

/// `eip` selector covering `id` (even selectors only, as [`eie_selector`]).
pub const fn eip_selector(id: u32) -> usize {
    SEL_EIP0 + 2 * (id / 64) as usize
}

/// 64-identity words of an `eie`/`eip` array that implements identities
/// `0..=num_ids` (`riscv,num-ids` is one less than a multiple of 64).
pub const fn file_words(num_ids: u32) -> u32 {
    (num_ids + 1).div_ceil(64)
}

/// `stopei` value -> identity (bits 26:16). 0 means nothing pending.
#[cfg(target_arch = "riscv64")]
pub const fn topei_identity(raw: u32) -> u32 {
    (raw >> cpu::TOPEI_ID_SHIFT) & cpu::TOPEI_ID_MASK
}

/// Initialize the CURRENT hart's S-level file: delivery on, threshold 0
/// (every enabled identity is delivered).
#[cfg(target_arch = "riscv64")]
pub fn init() {
    cpu::write_siselect(SEL_EIDELIVERY);
    cpu::write_sireg(1);
    cpu::write_siselect(SEL_EITHRESHOLD);
    cpu::write_sireg(0);
}

/// Enable identity `id` in the CURRENT hart's file. Identity 0 does not
/// exist and is ignored.
#[cfg(target_arch = "riscv64")]
pub fn enable(id: u32) {
    if id == 0 {
        return;
    }
    cpu::write_siselect(eie_selector(id));
    let cur = cpu::read_sireg() as u64;
    cpu::write_sireg((cur | eie_bit(id)) as usize);
}

#[cfg(target_arch = "riscv64")]
pub fn disable(id: u32) {
    if id == 0 {
        return;
    }
    cpu::write_siselect(eie_selector(id));
    let cur = cpu::read_sireg() as u64;
    cpu::write_sireg((cur & !eie_bit(id)) as usize);
}

/// Claim the highest-priority pending and enabled identity of the CURRENT
/// hart's file. The `stopei` write in the same instruction clears that
/// identity's pending bit — there is no separate completion step in the
/// IMSIC. Returns 0 when nothing is pending.
#[cfg(target_arch = "riscv64")]
pub fn claim() -> u32 {
    topei_identity(cpu::swap_stopei_zero() as u32)
}

// ── a guest file, from the monitor ──────────────────────────────────────

/// Set up guest file `gei` of THIS hart for the vCPU about to run: with
/// `clear_ids` (the file's identity count) a new owner gets delivery off,
/// threshold 0 and every enable and pending bit clear, and the identities in
/// `pend` (bit `id` of `eip0`, ids 1..=63) are made pending. The file is
/// reached by pointing `hstatus.VGEIN` at it for the duration (the guest's
/// `siselect` is `vsiselect`, which the caller saves and restores).
///
/// # Safety
/// H and the AIA must be present, `gei` at most the hart's GEILEN, and the
/// interrupts off; the caller owns `vsiselect` for the duration.
#[cfg(target_arch = "riscv64")]
pub unsafe fn vs_prepare(gei: u32, clear_ids: Option<u32>, pend: u64) {
    use crate::ext::hv::csr;
    let old: u64;
    // SAFETY: the caller guarantees H; `hstatus` is put back below.
    unsafe {
        core::arch::asm!("csrr {o}, {h}", o = out(reg) old, h = const csr::HSTATUS, options(nomem, nostack));
        core::arch::asm!("csrw {h}, {v}", v = in(reg) crate::ext::hv::inject::hstatus_with_vgein(old, gei),
            h = const csr::HSTATUS, options(nomem, nostack));
    }
    if let Some(ids) = clear_ids {
        vs_write(SEL_EIDELIVERY, 0);
        vs_write(SEL_EITHRESHOLD, 0);
        for w in 0..file_words(ids) {
            vs_write(eie_selector(w * 64), 0);
            vs_write(eip_selector(w * 64), 0);
        }
    }
    if pend != 0 {
        let sel = eip_selector(0);
        // SAFETY: the file selected above implements `eip0`.
        let cur = unsafe { vs_read(sel) };
        vs_write(sel, cur | pend);
    }
    // SAFETY: restoring what was read.
    unsafe {
        core::arch::asm!("csrw {h}, {v}", v = in(reg) old, h = const csr::HSTATUS, options(nomem, nostack));
    }
}

#[cfg(target_arch = "riscv64")]
fn vs_write(sel: usize, v: u64) {
    use crate::ext::hv::csr;
    // SAFETY: the pair addresses the guest file `vs_prepare` selected.
    unsafe {
        core::arch::asm!("csrw {s}, {sel}", "csrw {r}, {v}", sel = in(reg) sel, v = in(reg) v,
            s = const csr::VSISELECT, r = const csr::VSIREG, options(nomem, nostack));
    }
}

/// Read the `vsireg` register `sel` selects in the guest file `vs_prepare`
/// addressed.
///
/// # Safety
/// `hstatus.VGEIN` names a guest file, and that file implements `sel`.
#[cfg(target_arch = "riscv64")]
unsafe fn vs_read(sel: usize) -> u64 {
    use crate::ext::hv::csr;
    let v: u64;
    // SAFETY: as `vs_write`.
    unsafe {
        core::arch::asm!("csrw {s}, {sel}", "csrr {v}, {r}", sel = in(reg) sel, v = out(reg) v,
            s = const csr::VSISELECT, r = const csr::VSIREG, options(nomem, nostack));
    }
    v
}

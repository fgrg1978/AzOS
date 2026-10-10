// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// RISC-V CSR (Control and Status Register) access.
///
/// All functions use inline asm to read/write CSRs.

// ============================================================
// S-mode CSR functions
// ============================================================

#[inline(always)]
pub fn read_satp() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) val) };
    val
}

/// Install `val` in `satp` and flush this hart's TLB. Publishes `val` as this
/// hart's translation root first, for the shootdown (`crate::tlb`).
#[inline(always)]
pub fn write_satp(val: usize) {
    let hart = crate::cpu::hart_id();
    crate::tlb::publish(hart, val);
    // Installed outside `azos_sched::asid::prepare_switch`: the hart's TLB
    // generation is unknown from here on, so its next user switch flushes
    // (Kconfig `TLB_RETAIN`; nothing with it off).
    azos_arch_api::tlb_gen::mark_stale(hart);
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            "sfence.vma zero, zero",
            in(reg) val,
            options(nostack)
        );
    }
}

#[inline(always)]
pub fn sfence_vma() {
    unsafe { core::arch::asm!("sfence.vma zero, zero", options(nostack)) };
}

#[inline(always)]
pub fn sfence_vma_addr(vaddr: usize) {
    unsafe { core::arch::asm!("sfence.vma {}, zero", in(reg) vaddr, options(nostack)) };
}

#[inline(always)]
pub fn read_sstatus() -> usize {
    let val: usize;
    // A compiler barrier on purpose (no `nomem`): `sstatus` holds `SIE`, and
    // no memory access may move across an interrupt-mask change. The
    // `irq-nomem-canary` arm exists only for the gate's `irq order` canary.
    #[cfg(not(feature = "irq-nomem-canary"))]
    unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) val) };
    #[cfg(feature = "irq-nomem-canary")]
    unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) val, options(nomem, nostack)) };
    val
}

#[inline(always)]
pub fn write_sstatus(val: usize) {
    #[cfg(not(feature = "irq-nomem-canary"))]
    unsafe { core::arch::asm!("csrw sstatus, {}", in(reg) val, options(nostack)) };
    #[cfg(feature = "irq-nomem-canary")]
    unsafe { core::arch::asm!("csrw sstatus, {}", in(reg) val, options(nomem, nostack)) };
}

#[inline(always)]
pub fn read_stvec() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrr {}, stvec", out(reg) val) };
    val
}

#[inline(always)]
pub fn write_stvec(val: usize) {
    unsafe { core::arch::asm!("csrw stvec, {}", in(reg) val, options(nostack)) };
}

#[inline(always)]
pub fn read_sie() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrr {}, sie", out(reg) val) };
    val
}

#[inline(always)]
pub fn write_sie(val: usize) {
    unsafe { core::arch::asm!("csrw sie, {}", in(reg) val, options(nostack)) };
}

#[inline(always)]
pub fn write_sscratch(val: usize) {
    unsafe { core::arch::asm!("csrw sscratch, {}", in(reg) val, options(nostack)) };
}

#[inline(always)]
pub fn write_scounteren(val: usize) {
    unsafe { core::arch::asm!("csrw scounteren, {}", in(reg) val, options(nostack)) };
}

/// Clear S-mode software interrupt pending bit (SIP.SSIP, bit 1).
/// Used after handling an IPI to acknowledge the interrupt.
#[inline(always)]
pub fn clear_sip_ssip() {
    unsafe { core::arch::asm!("csrc sip, {}", in(reg) 1usize << 1, options(nostack)) };
}

// ---- sstatus bit definitions ----

pub const SSTATUS_SIE: usize = 1 << 1;
pub const SSTATUS_SPIE: usize = 1 << 5;
pub const SSTATUS_SPP: usize = 1 << 8;
/// `sstatus.SUM` (bit 18) — Supervisor User Memory access. 0 (this crate's
/// boot value; nothing here ever sets it — U07-7/O3.2, audit) means S-mode
/// faults on ANY access to a `U=1` PTE, full stop; the copy_* routines in
/// `crates/core/sched::process` never hit this today because they translate a
/// user VA to its physical frame and access it through the kernel's own
/// `phys_to_virt` window (a `U=0` mapping) rather than the user's own VA —
/// so SUM has been architecturally irrelevant to them. It matters for the
/// bug PAN targets on aarch64: a DIFFERENT piece of kernel code that
/// dereferences a raw ring-3 VA directly, instead of going through
/// `copy_from_user`/`copy_to_user`, faults immediately with `SUM=0` rather
/// than silently succeeding — same protection, opposite default polarity
/// (aarch64's `PAN=1` "protected", riscv64's `SUM=0` "protected").
pub const SSTATUS_SUM: usize = 1 << 18;

/// O3.2 (owner decision, PAN/SUM discipline): RAII guard setting `sstatus.
/// SUM` for its lifetime, clearing it on drop — the riscv64 twin of
/// `arch-aarch64::sysregs::UserAccess`. `csrs`/`csrc` are single
/// instructions (no read-modify-write round trip needed, unlike a plain
/// `write_sstatus`).
pub struct UserAccess;

impl UserAccess {
    #[inline(always)]
    pub fn enable() -> Self {
        unsafe {
            core::arch::asm!("csrs sstatus, {0}", in(reg) SSTATUS_SUM, options(nostack));
        }
        UserAccess
    }
}

impl Drop for UserAccess {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            core::arch::asm!("csrc sstatus, {0}", in(reg) SSTATUS_SUM, options(nostack));
        }
    }
}

// ---- sie bit definitions ----

pub const SIE_SSIE: usize = 1 << 1;
pub const SIE_STIE: usize = 1 << 5;
pub const SIE_SEIE: usize = 1 << 9;

// ============================================================
// AIA (Smaia/Ssaia) indirect CSR access — RFC-0046 stage 1a
// ============================================================
//
// `siselect`/`sireg`/`stopei` are written as numeric CSR addresses, not
// mnemonics, for the same reason `crates/drivers/irqchip/src/clint.rs` writes
// `csrw 0x14d` for `stimecmp`: the mnemonic needs the Ssaia (or Sstc)
// target feature, which this build's RUSTFLAGS do not enable. Whether the
// hart implements the CSR is a runtime question: the only caller,
// `crates/drivers/irqchip/src/imsic.rs`, is reached only after the DTB described a
// `riscv,imsics` group.
//
// Addresses as in Linux `arch/riscv/include/asm/csr.h`: CSR_SISELECT 0x150,
// CSR_SIREG 0x151, CSR_STOPEI 0x15c; TOPEI_ID_SHIFT 16, TOPEI_ID_MASK 0x7ff.

/// `siselect` CSR address.
pub const CSR_SISELECT: usize = 0x150;
/// `sireg` CSR address — indirect data window selected by `siselect`.
pub const CSR_SIREG: usize = 0x151;
/// `stopei` CSR address — Supervisor Top External Interrupt (IMSIC claim).
pub const CSR_STOPEI: usize = 0x15c;

/// Bit position of the interrupt identity field within a `stopei` read.
pub const TOPEI_ID_SHIFT: u32 = 16;
/// Mask (already shifted down) of the interrupt identity field — 11 bits.
pub const TOPEI_ID_MASK: u32 = 0x7ff;

/// Select an IMSIC indirect register for the following [`read_sireg`] /
/// [`write_sireg`]. The select/access pair may be interrupted: no interrupt
/// handler in this kernel writes `siselect` (the external-interrupt claim
/// uses `stopei` only), so the selection survives.
#[inline(always)]
pub fn write_siselect(val: usize) {
    unsafe { core::arch::asm!("csrw 0x150, {}", in(reg) val, options(nostack)) };
}

#[inline(always)]
pub fn read_sireg() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrr {}, 0x151", out(reg) val) };
    val
}

#[inline(always)]
pub fn write_sireg(val: usize) {
    unsafe { core::arch::asm!("csrw 0x151, {}", in(reg) val, options(nostack)) };
}

/// Atomically read `stopei` and write it back to 0 in one instruction
/// (`csrrw rd, stopei, x0`) — the IMSIC claim: returns the raw register
/// value (caller extracts the identity with [`TOPEI_ID_SHIFT`] /
/// [`TOPEI_ID_MASK`]), or 0 if nothing is pending (bit pattern the spec
/// defines as "no interrupt", same sentinel `plic::claim` already uses).
#[inline(always)]
pub fn swap_stopei_zero() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrrw {}, 0x15c, zero", out(reg) val) };
    val
}

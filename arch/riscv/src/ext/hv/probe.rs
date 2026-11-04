// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Is the H extension usable (Kconfig `RV_H`)?
//!
//! `misa` is M-mode only, so S-mode cannot ask the hart. Two steps, the
//! shape Sstc and Zicboz already use: cpu@0's device tree declares `h` in
//! `riscv,isa` (the caller passes that bit, `DtbInfo::isa_h`), then one
//! trap-safe read-and-write-back of `hstatus` under a private `stvec`
//! confirms S-mode can reach the hypervisor CSRs. The device tree alone is
//! not trusted: firmware may hide the extension, and a hart that is itself a
//! guest raises a virtual-instruction trap on the access instead.
//!
//! The decision is made once, on the boot hart; the harts of one machine are
//! taken to be uniform (as `riscv,isa` of cpu@0 stands for all of them).

use core::sync::atomic::{AtomicBool, Ordering};

use super::csr;

static H_ON: AtomicBool = AtomicBool::new(false);

/// Decide the H path: the Kconfig policy allows it, cpu@0 declares `h`, and
/// the execution probe confirms (run only then, so `n` and an undeclared `h`
/// execute nothing). Returns the decision.
pub fn select(policy_allows: bool, dt_declares_h: bool, probe: impl FnOnce() -> bool) -> bool {
    let on = policy_allows && dt_declares_h && probe();
    H_ON.store(on, Ordering::Release);
    on
}

/// Is H in use on this boot (see [`select`])?
#[inline]
pub fn available() -> bool {
    H_ON.load(Ordering::Acquire)
}

// `<sym>() -> usize`: `csrr`/`csrw <csr>` with the value read, so nothing
// changes. 1: no trap; 0: trapped (the CSR does not exist, or is not
// reachable from here). The `tlb::svinval_probe` shape: interrupts off, a
// private `stvec` that turns the trap into a 0 result, both restored.
// Clobbers t0-t3, a1.
#[cfg(target_arch = "riscv64")]
macro_rules! csr_probe {
    ($sym:literal, $csr:expr) => {
        core::arch::global_asm!(
            concat!(".pushsection .text.", $sym, ", \"ax\""),
            concat!(".globl ", $sym),
            ".p2align 2",
            concat!($sym, ":"),
            "    csrrci t3, sstatus, 2",
            "    csrr   t1, stvec",
            "    la     t0, 1f",
            "    csrw   stvec, t0",
            "    li     a1, 1",
            "    csrr   t2, {csr}",
            "    csrw   {csr}, t2",
            "2:",
            "    csrw   stvec, t1",
            "    andi   t3, t3, 2",
            "    csrs   sstatus, t3",
            "    mv     a0, a1",
            "    ret",
            ".p2align 2",
            "1:",
            "    li     a1, 0",
            "    la     t0, 2b",
            "    csrw   sepc, t0",
            "    sret",
            ".popsection",
            csr = const $csr,
        );
    };
}

#[cfg(target_arch = "riscv64")]
csr_probe!("azos_hv_probe", csr::HSTATUS);
#[cfg(target_arch = "riscv64")]
csr_probe!("azos_hstateen_probe", csr::HSTATEEN0);

// The probes `csr_probe!` defined above: each runs one CSR access under a
// private trap vector and returns 1 when it did not trap.
#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn azos_hv_probe() -> usize;
    fn azos_hstateen_probe() -> usize;
}

/// One run of the `hstatus` access under a private trap vector; an
/// illegal-instruction (or virtual-instruction) trap reads as absent.
#[cfg(target_arch = "riscv64")]
pub fn trap_probe() -> bool {
    // SAFETY: no memory operand; `hstatus` is written back unchanged; `stvec`
    // and `sstatus.SIE` are restored.
    unsafe { azos_hv_probe() == 1 }
}

/// Smstateen: can S-mode reach `hstateen0` (the extension is there and
/// M-mode lets the hypervisor use it)? The same run as [`trap_probe`] on that
/// register, which is written back unchanged. Call only when [`available`]:
/// without H the access traps whatever the extension.
#[cfg(target_arch = "riscv64")]
pub fn smstateen_probe() -> bool {
    // SAFETY: as `trap_probe`, with `hstateen0`.
    unsafe { azos_hstateen_probe() == 1 }
}

/// Number of `hgatp.VMID` bits this hart implements (0..=14): write ones,
/// read back (the Linux `kvm_riscv_gstage_vmid_detect` method). `hgatp` is
/// written back unchanged. Call only when [`available`].
#[cfg(target_arch = "riscv64")]
pub fn vmid_bits() -> u32 {
    let old: u64;
    let back: u64;
    // SAFETY: only `hgatp` is touched, and nothing translates through it
    // (the host runs with V=0); the old value is restored.
    unsafe {
        core::arch::asm!("csrr {o}, {hgatp}", o = out(reg) old, hgatp = const csr::HGATP,
            options(nomem, nostack));
        core::arch::asm!(
            "csrw {hgatp}, {w}",
            "csrr {b}, {hgatp}",
            "csrw {hgatp}, {o}",
            w = in(reg) old | csr::HGATP_VMID_MASK, b = out(reg) back, o = in(reg) old,
            hgatp = const csr::HGATP, options(nomem, nostack));
    }
    vmid_bits_from_readback(back)
}

/// The VMID width an `hgatp` read-back after writing all-ones VMID shows:
/// the position of its highest set bit.
pub const fn vmid_bits_from_readback(hgatp: u64) -> u32 {
    let v = (hgatp & csr::HGATP_VMID_MASK) >> csr::HGATP_VMID_SHIFT;
    u64::BITS - v.leading_zeros()
}

/// [`vmid_bits`] of this boot, read once: the harts of one machine are
/// uniform. Call only when [`available`].
#[cfg(target_arch = "riscv64")]
pub fn vmid_bits_cached() -> u32 {
    static BITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
    match BITS.load(Ordering::Relaxed) {
        u32::MAX => {
            let b = vmid_bits();
            BITS.store(b, Ordering::Relaxed);
            b
        }
        b => b,
    }
}

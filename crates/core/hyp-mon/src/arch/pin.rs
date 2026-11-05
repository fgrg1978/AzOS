// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pin: once a PE is pinned, the kernel cannot write `SCTLR_EL1`,
//! `TCR_EL1` or `TTBR1_EL1` on it, so it cannot turn its MMU off or aim it at
//! tables the monitor never saw. With FEAT_FGT only those three trap
//! (`HFGWTR_EL2`) and a context switch's `TTBR0_EL1` write costs nothing. With
//! none, `HCR_EL2.TVM` traps every virtual-memory register write: the vector
//! carries out `TTBR0_EL1` itself (`entry.rs`) and `trap` the rest.
//!
//! Arming is per PE and by call, not at the lock: a PE writes these registers
//! while it comes up, and a secondary does so after the lock. Canary
//! `hyp-pin-off-canary`: the call succeeds and arms nothing.

use super::sysreg::*;
use crate::state::HYP;
use azos_hyp_api::{Kind, DENIED, INV_PINNED, OK, PIN_FGT, PIN_TVM};
use core::sync::atomic::{AtomicU64, Ordering};

/// PEs that have pinned, one bit per `MPIDR_EL1.Aff0`.
static PINNED: AtomicU64 = AtomicU64::new(0);

fn mmfr0() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, ID_AA64MMFR0_EL1", out(reg) v) };
    v
}

fn pe() -> u32 {
    let mpidr: u64;
    unsafe { core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr) };
    (mpidr & 0xff) as u32
}

/// Per PE, before EL1 runs: no fine-grained trap armed (`fgt_open`). Registers
/// named by encoding: `HFGRTR`, `HFGWTR`, `HFGITR`, `HDFGRTR`, `HDFGWTR`.
pub fn init_pe() {
    if !has_fgt(mmfr0()) {
        return;
    }
    let (dfr0, pfr1, mmfr3): (u64, u64, u64);
    // SAFETY: ID registers.
    unsafe {
        core::arch::asm!(
            "mrs {a}, ID_AA64DFR0_EL1",
            "mrs {b}, ID_AA64PFR1_EL1",
            "mrs {c}, S3_0_C0_C7_3", // ID_AA64MMFR3_EL1
            a = out(reg) dfr0, b = out(reg) pfr1, c = out(reg) mmfr3,
        );
    }
    let f = fgt_open(&IdRegs { dfr0, pfr1, mmfr3 });
    // SAFETY: FEAT_FGT is implemented (checked above).
    unsafe {
        core::arch::asm!(
            "msr S3_4_C1_C1_4, {r}",
            "msr S3_4_C1_C1_5, {w}",
            "msr S3_4_C1_C1_6, {i}",
            "msr S3_4_C3_C1_4, {dr}",
            "msr S3_4_C3_C1_5, {dw}",
            r = in(reg) f.hfgrtr, w = in(reg) f.hfgwtr, i = in(reg) f.hfgitr, dr = in(reg) f.hdfgrtr, dw = in(reg) f.hdfgwtr,
        );
    }
}

/// `pin()`: arm this PE. `(status, mode, PEs pinned)`.
pub fn pin() -> (i64, u64, u64) {
    if !super::s2::locked() {
        return (DENIED, 0, 0);
    }
    let fgt = has_fgt(mmfr0());
    if !cfg!(feature = "hyp-pin-off-canary") {
        // SAFETY: EL2 registers of this PE only.
        unsafe {
            if fgt {
                core::arch::asm!(
                    "mrs {t}, S3_4_C1_C1_5",
                    "orr {t}, {t}, {bits}",
                    "msr S3_4_C1_C1_5, {t}",
                    "isb",
                    t = out(reg) _, bits = in(reg) HFGWTR_PIN,
                );
            } else {
                core::arch::asm!(
                    "mrs {t}, HCR_EL2",
                    "orr {t}, {t}, {bits}",
                    "msr HCR_EL2, {t}",
                    "isb",
                    t = out(reg) _, bits = in(reg) HCR_TVM,
                );
            }
        }
        PINNED.fetch_or(1u64 << (pe() & 63), Ordering::AcqRel);
        HYP.set_invariant(INV_PINNED);
    }
    (OK, if fgt { PIN_FGT } else { PIN_TVM }, PINNED.load(Ordering::Acquire).count_ones() as u64)
}

macro_rules! write_reg {
    ($name:literal, $v:expr) => {
        // SAFETY: an EL1 register, written at EL2 with the value the kernel meant.
        unsafe { core::arch::asm!(concat!("msr ", $name, ", {v}"), v = in(reg) $v) }
    };
}

/// A trapped `MSR` from EL1: a refused register is recorded and dropped, any
/// other (`TVM` only) is carried out. The instruction is skipped either way.
pub fn trap(regs: *mut u64, esr: u64) {
    let t = sysreg_trap(esr);
    let reg = t.as_ref().and_then(reg_of);
    match (&t, reg) {
        (Some(t), Some(r)) if !t.read => {
            // SAFETY: `regs` holds x0..x30 as the vector saved them; Rt 31 is XZR.
            let v = if t.rt == 31 { 0 } else { unsafe { *regs.add(t.rt as usize) } };
            if refused(r) {
                crate::record(Kind::SysregRefused, pe(), esr, encoding(t), v);
            } else {
                match r {
                    Reg::Ttbr0 => write_reg!("TTBR0_EL1", v),
                    Reg::Afsr0 => write_reg!("AFSR0_EL1", v),
                    Reg::Afsr1 => write_reg!("AFSR1_EL1", v),
                    Reg::Esr => write_reg!("ESR_EL1", v),
                    Reg::Far => write_reg!("FAR_EL1", v),
                    Reg::Mair => write_reg!("MAIR_EL1", v),
                    Reg::Amair => write_reg!("AMAIR_EL1", v),
                    Reg::ContextId => write_reg!("CONTEXTIDR_EL1", v),
                    Reg::Sctlr | Reg::Tcr | Reg::Ttbr1 => {}
                }
            }
        }
        _ => {
            let elr: u64;
            // SAFETY: reads this PE's ELR_EL2.
            unsafe { core::arch::asm!("mrs {}, ELR_EL2", out(reg) elr) };
            crate::record(Kind::UnexpectedTrap, pe(), esr, elr, 0);
        }
    }
    // SAFETY: steps this PE's return address past the trapped instruction.
    unsafe { core::arch::asm!("mrs {t}, ELR_EL2", "add {t}, {t}, #4", "msr ELR_EL2, {t}", t = out(reg) _) };
}

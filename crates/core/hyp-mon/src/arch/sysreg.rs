// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The EL1 registers the pin watches: the ones that decide how the kernel's
//! addresses translate, and the others `HCR_EL2.TVM` traps with them. Pure:
//! the host suite (`tests/host/hv-tests`) pins every number here.

#[path = "../../../../../arch/aarch64/src/ext/hv/sysreg.rs"]
mod iss;

pub use iss::{sysreg_trap, SysregTrap};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Reg {
    Sctlr,
    Ttbr0,
    Ttbr1,
    Tcr,
    Afsr0,
    Afsr1,
    Esr,
    Far,
    Mair,
    Amair,
    ContextId,
}

/// The register a trapped `MSR` / `MRS` names (EL1 registers are Op0 3, Op1 0).
pub const fn reg_of(t: &SysregTrap) -> Option<Reg> {
    if t.op0 != 3 || t.op1 != 0 {
        return None;
    }
    Some(match (t.crn, t.crm, t.op2) {
        (1, 0, 0) => Reg::Sctlr,
        (2, 0, 0) => Reg::Ttbr0,
        (2, 0, 1) => Reg::Ttbr1,
        (2, 0, 2) => Reg::Tcr,
        (5, 1, 0) => Reg::Afsr0,
        (5, 1, 1) => Reg::Afsr1,
        (5, 2, 0) => Reg::Esr,
        (6, 0, 0) => Reg::Far,
        (10, 2, 0) => Reg::Mair,
        (10, 3, 0) => Reg::Amair,
        (13, 0, 1) => Reg::ContextId,
        _ => return None,
    })
}

/// Writes to these are refused once a PE is pinned. `TTBR0_EL1` is the user
/// half and stays free (a context switch writes it); the rest `TVM` traps are
/// carried out unchanged.
pub const fn refused(r: Reg) -> bool {
    matches!(r, Reg::Sctlr | Reg::Tcr | Reg::Ttbr1)
}

/// The register's encoding as `sys_reg(op0, op1, crn, crm, op2)` packs it.
pub const fn encoding(t: &SysregTrap) -> u64 {
    (t.op0 as u64) << 19 | (t.op1 as u64) << 16 | (t.crn as u64) << 12 | (t.crm as u64) << 8 | (t.op2 as u64) << 5
}

/// `HFGWTR_EL2` trap bits (FEAT_FGT) for the refused registers.
pub const HFGWTR_SCTLR_EL1: u64 = 1 << 29;
pub const HFGWTR_TCR_EL1: u64 = 1 << 32;
pub const HFGWTR_TTBR1_EL1: u64 = 1 << 37;
pub const HFGWTR_PIN: u64 = HFGWTR_SCTLR_EL1 | HFGWTR_TCR_EL1 | HFGWTR_TTBR1_EL1;

/// `HCR_EL2.TVM`: writes to the virtual-memory registers trap.
pub const HCR_TVM: u64 = 1 << 26;

/// FEAT_FGT, from `ID_AA64MMFR0_EL1` (bits 59:56).
pub const fn has_fgt(mmfr0: u64) -> bool {
    (mmfr0 >> 56) & 0xf != 0
}

/// `ESR_EL2` of an `MSR TTBR0_EL1, Xt` (EC 0x18, a 32-bit instruction, Op0 3,
/// CRn 2, a write) with the `Rt` field cleared: the one trap the vector's fast
/// path carries out itself.
pub const TTBR0_WRITE_ESR: u64 = 0x18 << 26 | 1 << 25 | 3 << 20 | 2 << 10;
/// `ESR_EL2.ISS.Rt`.
pub const RT_MASK: u64 = 0x1f << 5;

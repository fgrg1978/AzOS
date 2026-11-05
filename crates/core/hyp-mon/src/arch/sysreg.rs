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

/// The fine-grained trap registers a PE starts with: every bit of the five
/// that traps nothing the kernel uses. Their reset value is unknown, and most
/// bits trap when set; the `n*` bits (an `nXXX` register in the architecture's
/// names) trap when clear, and exist only for the feature that adds the
/// register, so they are set exactly where the ID registers say it is there.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Fgt {
    pub hfgrtr: u64,
    pub hfgwtr: u64,
    pub hfgitr: u64,
    pub hdfgrtr: u64,
    pub hdfgwtr: u64,
}

/// `ID_AA64DFR0_EL1`, `ID_AA64PFR1_EL1` and `ID_AA64MMFR3_EL1`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IdRegs {
    pub dfr0: u64,
    pub pfr1: u64,
    pub mmfr3: u64,
}

const fn field(v: u64, lsb: u32) -> u64 {
    (v >> lsb) & 0xf
}

const fn set_if(on: bool, bits: u64) -> u64 {
    if on { bits } else { 0 }
}

pub const fn fgt_open(id: &IdRegs) -> Fgt {
    let spe_v1p2 = field(id.dfr0, 32) >= 3;
    let brbe = field(id.dfr0, 52) != 0;
    let sme = field(id.pfr1, 24) != 0;
    let gcs = field(id.pfr1, 44) != 0;
    let pie = field(id.mmfr3, 8) != 0;
    let poe = field(id.mmfr3, 16) != 0;
    let rw = set_if(sme, 1 << 55 | 1 << 54)  // nTPIDR2_EL0, nSMPRI_EL1
        | set_if(pie, 1 << 58 | 1 << 57)     // nPIR_EL1, nPIRE0_EL1
        | set_if(poe, 1 << 59)               // nPOR_EL0
        | set_if(gcs, 1 << 53 | 1 << 52);    // nGCS_EL1, nGCS_EL0
    Fgt {
        hfgrtr: rw,
        hfgwtr: rw,
        hfgitr: set_if(brbe, 1 << 56 | 1 << 55), // nBRBIALL, nBRBINJ
        hdfgrtr: set_if(spe_v1p2, 1 << 62) | set_if(brbe, 1 << 61 | 1 << 60 | 1 << 59), // nPMSNEVFR_EL1; nBRBDATA, nBRBCTL, nBRBIDR
        hdfgwtr: set_if(spe_v1p2, 1 << 62) | set_if(brbe, 1 << 61 | 1 << 60),
    }
}

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

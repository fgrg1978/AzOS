// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ISS of a trapped `MRS` / `MSR` (`ESR_ELx.EC` 0x18). Shared by source
//! with the resident monitor, so it depends on nothing.

/// A trapped `MRS` / `MSR` (`ESR_EL2.EC` 0x18) decoded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SysregTrap {
    pub op0: u8,
    pub op1: u8,
    pub crn: u8,
    pub crm: u8,
    pub op2: u8,
    pub rt: u8,
    /// `MRS`: the guest reads the register.
    pub read: bool,
}

/// Decode the ISS of a trapped system-register access.
pub const fn sysreg_trap(esr: u64) -> Option<SysregTrap> {
    if (esr >> 26) & 0x3F != 0x18 {
        return None;
    }
    let iss = esr & 0x01FF_FFFF;
    Some(SysregTrap {
        op0: ((iss >> 20) & 3) as u8,
        op2: ((iss >> 17) & 7) as u8,
        op1: ((iss >> 14) & 7) as u8,
        crn: ((iss >> 10) & 0xF) as u8,
        rt: ((iss >> 5) & 0x1F) as u8,
        crm: ((iss >> 1) & 0xF) as u8,
        read: iss & 1 != 0,
    })
}

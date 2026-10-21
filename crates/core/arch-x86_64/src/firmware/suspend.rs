// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! System suspend on x86_64: ACPI S3, where ACPI allows it.
//!
//! Entering S3 is a write of `SLP_TYPa << 10 | SLP_EN` to the FADT's PM1a
//! control block, and `SLP_TYPa` is not in the FADT: it is the first element of
//! the package `\_S3` in the DSDT, an AML object. Reading it takes an AML
//! interpreter (or a byte scan of the DSDT, which finds the wrong answer on a
//! firmware that builds the package in a method). The kernel has neither, so no
//! machine is known to allow S3, and the answer here is "not available" with
//! the reason, never a guess at `SLP_TYP`. The sequence
//! (`azos_drv_power::pm::suspend`) turns that into a refusal with a record,
//! which keeps the code path in place for the day an interpreter exists.
//!
//! The wake side of S3 (`FACS` waking vector, real-mode resume) is not started
//! either; it would be the x86 form of the resume entry the other two ISAs lack.

use super::acpi::Fadt;

/// Why the kernel cannot suspend the system on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemSuspendMissing {
    /// No FADT was read: no ACPI, or a table the parser refused.
    NoFadt,
    /// The FADT names no PM1a control block, so there is no register to write.
    NoPm1Control,
    /// A hardware-reduced platform (FADT flag 20) has no PM1 blocks: sleep is
    /// entered through the sleep-control register of the extended FADT, which
    /// the parser does not read.
    HardwareReduced,
    /// The machine can be asked, and `SLP_TYP` of `\_S3` needs AML.
    NoAml,
}

/// FADT flag HW_REDUCED_ACPI.
const FLAG_HW_REDUCED: u32 = 1 << 20;

/// Whether S3 can be entered, from the FADT the platform read.
pub fn s3_available(fadt: Option<&Fadt>) -> Result<(), SystemSuspendMissing> {
    let Some(f) = fadt else { return Err(SystemSuspendMissing::NoFadt) };
    if f.flags & FLAG_HW_REDUCED != 0 {
        return Err(SystemSuspendMissing::HardwareReduced);
    }
    if f.pm1a_cnt == 0 {
        return Err(SystemSuspendMissing::NoPm1Control);
    }
    // `\_S3` is in the DSDT, and the DSDT is AML.
    Err(SystemSuspendMissing::NoAml)
}

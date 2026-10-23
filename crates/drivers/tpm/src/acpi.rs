// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ACPI `TPM2` table (TCG ACPI Specification), enough to pick the driver.
//!
//! Layout: the 36-byte ACPI header, `PlatformClass` u16, 2 reserved bytes,
//! `ControlAreaAddress` u64, `StartMethod` u32, then start-method parameters
//! this driver does not read. Start method 6 is the memory-mapped TIS/FIFO
//! interface; 7 is the Command Response Buffer started by its `CTRL_START`
//! register, 2 and 8 the CRB started through ACPI as well ([`crate::crb`]).
//!
//! The table carries no window: the TPM device's `_CRS` does, and reading
//! it takes an AML interpreter. So the windows come from the table alone:
//! the PC-client TIS window is fixed at [`TIS_DEFAULT_BASE`]; a CRB's control
//! area is `ControlAreaAddress`, its locality registers the PTP layout puts
//! 0x40 below it ([`crate::crb::head_for`]), and its buffers the addresses
//! the control area holds.

use crate::crb::StartMethod;

/// Physical base of the PC-client TIS window (locality 0).
pub const TIS_DEFAULT_BASE: u64 = 0xFED4_0000;

const SIG: &[u8; 4] = b"TPM2";
const HEADER: usize = 36;
const MIN_LEN: usize = 52;

/// CRB, started through ACPI (the TCG ACPI table's "ACPI start method").
pub const START_METHOD_ACPI: u32 = 2;
pub const START_METHOD_MMIO: u32 = 6;
pub const START_METHOD_CRB: u32 = 7;
pub const START_METHOD_CRB_ACPI: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tpm2Error {
    /// Shorter than the fixed fields, or the length field does not fit.
    Short,
    /// Not a `TPM2` table.
    Signature,
    /// The bytes do not sum to zero.
    Checksum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tpm2Table {
    pub revision: u8,
    pub platform_class: u16,
    pub control_area: u64,
    pub start_method: u32,
}

/// Which driver the table asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    /// TIS/FIFO over MMIO at this base.
    Tis { base: u64 },
    /// Command Response Buffer at this control area, started as `start` says.
    Crb { control_area: u64, start: StartMethod },
    /// Any other start method.
    Unsupported(u32),
}

impl Tpm2Table {
    pub fn parse(t: &[u8]) -> Result<Tpm2Table, Tpm2Error> {
        if t.len() < MIN_LEN {
            return Err(Tpm2Error::Short);
        }
        if &t[0..4] != SIG {
            return Err(Tpm2Error::Signature);
        }
        let len = u32::from_le_bytes([t[4], t[5], t[6], t[7]]) as usize;
        if len < MIN_LEN || len > t.len() {
            return Err(Tpm2Error::Short);
        }
        if t[..len].iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
            return Err(Tpm2Error::Checksum);
        }
        let u64_at = |o: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&t[o..o + 8]);
            u64::from_le_bytes(b)
        };
        Ok(Tpm2Table {
            revision: t[8],
            platform_class: u16::from_le_bytes([t[HEADER], t[HEADER + 1]]),
            control_area: u64_at(HEADER + 4),
            start_method: u32::from_le_bytes([t[48], t[49], t[50], t[51]]),
        })
    }

    pub fn interface(&self) -> Interface {
        match self.start_method {
            START_METHOD_MMIO => Interface::Tis { base: TIS_DEFAULT_BASE },
            START_METHOD_CRB => Interface::Crb { control_area: self.control_area, start: StartMethod::Crb },
            START_METHOD_ACPI | START_METHOD_CRB_ACPI => {
                Interface::Crb { control_area: self.control_area, start: StartMethod::Acpi }
            }
            m => Interface::Unsupported(m),
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TPM 2.0 driver core: the TIS/FIFO protocol, the commands, nothing else.
//!
//! Layers, bottom up:
//!
//! * [`tis::TisRegs`] is the one register-access trait. [`mmio::MmioTis`]
//!   implements it over a memory-mapped window (x86: the fixed TIS window,
//!   see [`acpi`]); [`spi::SpiTis`] implements it over a SPI bus with the
//!   PTP SPI framing and wait states. Everything above is generic over it.
//! * [`tis::Tis`] is the FIFO protocol: locality request/release, burst-count
//!   paced transfer, `expect` checking, the A/B/C timeouts and the per-command
//!   duration classes. One [`tis::Tis::transmit`] is one command.
//! * [`wire`] builds and parses TPM 2.0 structures. Every size read from the
//!   wire is checked against what is left before it is used.
//! * [`tpm::Tpm`] is what the rest of the system calls: `startup`,
//!   `get_random` (a credited entropy source), `pcr_extend`/`pcr_read` (the
//!   measured-boot hook), `nv_*`/`floor_*` (the rollback floor) and `secret_*`
//!   (the keystore's 32-byte root in an NV index of its own).
//!
//! No `unsafe`, no allocation, no MMIO of its own: the caller supplies the
//! register window, the SPI bus and the clock. `tests/host/tpm-tests` runs the
//! whole stack against a scripted TPM.
//!
//! Not here: the CRB interface (ACPI start methods 7 and 8; [`acpi`] reports
//! it, the driver refuses it), interrupts (the driver polls), sessions other
//! than password sessions, and key hierarchies.
#![no_std]
#![forbid(unsafe_code)]

pub mod acpi;
pub mod mmio;
pub mod spi;
pub mod tis;
pub mod tpm;
pub mod wire;

/// The bus below the driver failed (an MMIO window that cannot answer, a SPI
/// transfer that returned an error, a SPI wait state that never ended).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusError;

/// What a bounded wait was waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// `ACCESS.activeLocality` after a locality request.
    Locality,
    /// `STS.commandReady` after asking for it.
    CommandReady,
    /// `STS.burstCount` non-zero.
    Burst,
    /// `STS.stsValid`.
    StsValid,
    /// `STS.dataAvail`: the command is still executing.
    DataAvail,
}

/// Everything the driver reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bus failed.
    Bus,
    /// Nothing answers in the register window (ACCESS reads all ones, or
    /// never becomes valid).
    NoDevice,
    /// The device is a TPM 1.2 (or reports no TPM family at all).
    NotTpm2,
    /// A wait ran out.
    Timeout(Wait),
    /// The locality is above 4.
    BadLocality,
    /// A command that is shorter than a header, larger than the driver's
    /// buffer, or whose size field is not its length.
    BadCommand,
    /// The TPM cleared `expect` before the last command byte, or kept it set
    /// after it.
    ExpectMismatch,
    /// The response header is shorter than 10 bytes, or its size does not fit
    /// the caller's buffer.
    BadResponseSize,
    /// `dataAvail` dropped before the response was complete.
    Truncated,
    /// `dataAvail` is still set after the last response byte.
    TrailingData,
    /// A response field is inconsistent (wrong tag, a size that overruns the
    /// response, an unexpected count).
    Malformed,
    /// The TPM answered with this non-zero response code.
    Tpm(u32),
    /// An argument the driver refuses before sending anything (PCR index
    /// above 23, an NV payload or an auth value over the buffer).
    BadArgument,
    /// An NV index that already exists does not have the attributes, size,
    /// name algorithm or (empty) policy the driver would have defined it
    /// with: someone else made it, so it is not the rollback floor.
    NvMismatch,
}

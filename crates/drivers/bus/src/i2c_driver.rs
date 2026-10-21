// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! I2C as a [`Driver`] impl — third migration (after UART + GPIO).
//!
//! Validates the trait shape against a bus-oriented hardware
//! family (vs char-oriented UART and pin-oriented GPIO). The op
//! payload now needs to address both a bus number and a slave
//! address — proving the uniform `(op, input, output)` API stays
//! ergonomic for multi-axis hardware.
//!
//! The legacy `crate::i2c` API stays in place for kernel-internal
//! callers (IMU init, INA219, etc.); this driver provides the
//! unified API for client tasks via `runtime::REGISTRY`.

use azos_drv_api::{Driver, DriverError, DriverIsolation, DriverManifest};
use crate::i2c;
use core::sync::atomic::{AtomicBool, Ordering};
use azos_abi::cap::CapPerms;

// ──────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────

// Was a duplicate to avoid a `drivers → driver_server` cycle; the constants
// moved to `crates/core/abi` on 2026-09-06, which this crate already depends on.
use azos_abi::drv_kind::DRV_KIND_I2C;

/// Request input header common to every op: `[bus u8, addr u8,
/// reg u8, _pad u8]`. Payload (write data) follows from offset 4.
const I2C_INPUT_HEADER_BYTES: usize = 4;

/// Stable wire-format ops. Bumping
/// `super::api::DRIVER_MANIFEST_VERSION` is required to change any.
/// Write `input[I2C_INPUT_HEADER_BYTES..]` to the device at
/// `[bus, addr]`. The first byte of the trailing payload is the
/// register address (matches DesignWare convention).
pub const I2C_OP_WRITE: u32 = 0;
/// Read from `[bus, addr, reg]` — the input header carries those
/// three bytes. The kernel reads `output.len()` bytes from the
/// device into `output`.
pub const I2C_OP_READ: u32 = 1;
/// Probe device presence. `input[0..2]` = `[bus, addr]`,
/// `output[0]` ← 1 if present, 0 otherwise.
pub const I2C_OP_DETECT: u32 = 2;

/// Width in bytes of the DETECT op output: 1 byte (0 or 1).
const I2C_DETECT_OUTPUT_BYTES: usize = 1;

// ──────────────────────────────────────────────────────────────────────────
// Manifest builder (handles per-platform MMIO presence)
// ──────────────────────────────────────────────────────────────────────────

/// No MMIO range: each controller's window is the bound device's (the
/// hardware bus records it, the introspection tree's `devices/`), not a constant of the manifest.
const fn build_manifest() -> DriverManifest {
    DriverManifest::new(
        DRV_KIND_I2C,
        "i2c0",
        DriverIsolation::InKernel,
        CapPerms::RW,
    )
}

// ──────────────────────────────────────────────────────────────────────────
// Driver state
// ──────────────────────────────────────────────────────────────────────────

/// Stateful wrapper. Hardware state lives in `crate::i2c` (sim) or
/// in MMIO (vf2/k1); this struct only carries the manifest + the
/// cross-CPU init guard.
pub struct I2cDriver {
    initialized: AtomicBool,
    manifest: DriverManifest,
}

impl I2cDriver {
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            manifest: build_manifest(),
        }
    }

    /// Decode the common 4-byte input header into `(bus, addr, reg)`.
    /// `reg` is meaningful for READ; ignored by WRITE/DETECT but
    /// always present so the header layout stays uniform.
    fn decode_header(input: &[u8]) -> Result<(u8, u8, u8), DriverError> {
        if input.len() < I2C_INPUT_HEADER_BYTES {
            return Err(DriverError::BadInput);
        }
        Ok((input[0], input[1], input[2]))
    }
}

impl Default for I2cDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Driver impl
// ──────────────────────────────────────────────────────────────────────────

impl Driver for I2cDriver {
    fn manifest(&self) -> &DriverManifest {
        &self.manifest
    }

    fn init(&self) -> Result<(), DriverError> {
        // The controllers are brought up by the hardware bus when it binds
        // them (`i2c::i2c_attach` on a board; `i2c_init` populates the
        // simulation at boot); registering the driver only opens it to
        // requests.
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    fn handle_request(
        &self,
        op: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, DriverError> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err(DriverError::NotInitialized);
        }
        match op {
            I2C_OP_WRITE => {
                let (bus, addr, _reg) = Self::decode_header(input)?;
                let payload = &input[I2C_INPUT_HEADER_BYTES..];
                if payload.is_empty() {
                    // The legacy API expects at least one byte (the
                    // register), so refuse a header-only write.
                    return Err(DriverError::BadInput);
                }
                match i2c::i2c_write(bus, addr, payload) {
                    0 => Ok(0),
                    _ => Err(DriverError::IoFault),
                }
            }
            I2C_OP_READ => {
                let (bus, addr, reg) = Self::decode_header(input)?;
                if output.is_empty() {
                    return Err(DriverError::BadOutput);
                }
                let n = i2c::i2c_read(bus, addr, reg, output);
                if n < 0 {
                    Err(DriverError::IoFault)
                } else {
                    Ok(n as usize)
                }
            }
            I2C_OP_DETECT => {
                let (bus, addr, _reg) = Self::decode_header(input)?;
                if output.len() < I2C_DETECT_OUTPUT_BYTES {
                    return Err(DriverError::BadOutput);
                }
                output[0] = u8::from(i2c::i2c_detect(bus, addr));
                Ok(I2C_DETECT_OUTPUT_BYTES)
            }
            _ => Err(DriverError::BadOp),
        }
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        // I2C controllers have no power-down sequence in our usage;
        // allow re-init by clearing the framework flag.
        self.initialized.store(false, Ordering::Release);
        Ok(())
    }
}

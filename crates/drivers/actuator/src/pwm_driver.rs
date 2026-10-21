// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PWM as a [`Driver`] impl — fourth migration after UART, GPIO,
//! I2C. Validates the trait against a multi-parameter actuator
//! family (channel + nanosecond period/duty).
//!
//! The legacy `crate::pwm` API stays in place for internal callers
//! (motor PID, ESC); this driver provides the unified API for
//! client tasks via `runtime::REGISTRY`.

use azos_drv_api::{Driver, DriverError, DriverIsolation, DriverManifest};
use crate::pwm;
use core::sync::atomic::{AtomicBool, Ordering};
use azos_abi::cap::CapPerms;

// ──────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────

// Was a duplicate to avoid a `drivers → driver_server` cycle; the constants
// moved to `crates/core/abi` on 2026-09-06, which this crate already depends on.
use azos_abi::drv_kind::DRV_KIND_PWM;

/// Common input layout: `[channel u32 LE, payload u32 LE]`.
/// ENABLE / DISABLE ignore the payload; the rest interpret it as
/// the period/duty nanoseconds (`u32`) or duty percent (`u32`).
const PWM_INPUT_BYTES: usize = 8;

/// Stable wire-format ops.
pub const PWM_OP_ENABLE: u32 = 0;
pub const PWM_OP_DISABLE: u32 = 1;
/// `input[4..8]` = period nanoseconds (`u32 LE`).
pub const PWM_OP_SET_PERIOD: u32 = 2;
/// `input[4..8]` = duty nanoseconds (`u32 LE`).
pub const PWM_OP_SET_DUTY: u32 = 3;
/// `input[4..8]` = duty percent (`u32 LE`, 0..=100).
pub const PWM_OP_SET_DUTY_PCT: u32 = 4;

// ──────────────────────────────────────────────────────────────────────────
// Manifest
// ──────────────────────────────────────────────────────────────────────────

/// No MMIO range: the controller's window is the bound device's (the hardware
/// bus records it, the introspection tree's `devices/`), not a constant of the manifest.
const fn build_manifest() -> DriverManifest {
    DriverManifest::new(
        DRV_KIND_PWM,
        "pwm",
        DriverIsolation::InKernel,
        CapPerms::RW,
    )
}

// ──────────────────────────────────────────────────────────────────────────
// Driver state
// ──────────────────────────────────────────────────────────────────────────

pub struct PwmDriver {
    initialized: AtomicBool,
    manifest: DriverManifest,
}

impl PwmDriver {
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            manifest: build_manifest(),
        }
    }

    /// Decode `[channel u32 LE, payload u32 LE]`.
    fn decode(input: &[u8]) -> Result<(u32, u32), DriverError> {
        if input.len() < PWM_INPUT_BYTES {
            return Err(DriverError::BadInput);
        }
        let ch = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        let pl = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
        Ok((ch, pl))
    }
}

impl Default for PwmDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Driver impl
// ──────────────────────────────────────────────────────────────────────────

impl Driver for PwmDriver {
    fn manifest(&self) -> &DriverManifest {
        &self.manifest
    }

    fn init(&self) -> Result<(), DriverError> {
        // The channels are brought up by the hardware bus when it binds the
        // controller (`pwm::pwm_attach` on a board, nothing to do on the
        // simulation); registering the driver only opens it to requests.
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    fn handle_request(
        &self,
        op: u32,
        input: &[u8],
        _output: &mut [u8],
    ) -> Result<usize, DriverError> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err(DriverError::NotInitialized);
        }
        let (ch, payload) = Self::decode(input)?;
        let rc = match op {
            PWM_OP_ENABLE => pwm::pwm_enable(ch),
            PWM_OP_DISABLE => pwm::pwm_disable(ch),
            PWM_OP_SET_PERIOD => pwm::pwm_set_period(ch, payload),
            PWM_OP_SET_DUTY => pwm::pwm_set_duty(ch, payload),
            PWM_OP_SET_DUTY_PCT => pwm::pwm_set_duty_pct(ch, payload),
            _ => return Err(DriverError::BadOp),
        };
        if rc == 0 {
            Ok(0)
        } else {
            Err(DriverError::IoFault)
        }
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        self.initialized.store(false, Ordering::Release);
        Ok(())
    }
}

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
#[cfg(any(feature = "vf2", feature = "k1"))]
use azos_drv_api::MmioRange;
use crate::pwm;
use core::sync::atomic::{AtomicBool, Ordering};
use azos_abi::cap::CapPerms;

// ──────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────

// Was a duplicate to avoid a `drivers → driver_server` cycle; the constants
// moved to `crates/core/abi` on 2026-09-06, which this crate already depends on.
use azos_abi::drv_kind::DRV_KIND_PWM;

/// MMIO window on real platforms (SiFive PWM block, 8 channels ×
/// 16-byte stride = 128 bytes, page-aligned for completeness).
#[cfg(any(feature = "vf2", feature = "k1"))]
const PWM_MMIO_BYTES: u64 = 0x100;

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

const fn build_manifest() -> DriverManifest {
    let m = DriverManifest::new(
        DRV_KIND_PWM,
        "pwm",
        DriverIsolation::InKernel,
        CapPerms::RW,
    );
    #[cfg(any(feature = "vf2", feature = "k1"))]
    let m = m.with_mmio(MmioRange::new(
        azos_drv_base::platform::hw::PWM_BASE as u64,
        PWM_MMIO_BYTES,
    ));
    m
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
        if self
            .initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            pwm::pwm_init();
        }
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

    /// The channel named, and ONLY when the op reaches just that channel.
    ///
    /// `PWM_OP_ENABLE`, `_DISABLE` and `_SET_PERIOD` touch bits that are
    /// instance-wide on vf2 (`PWMCFG`'s enable bit and scale field), so they
    /// reach every channel and no single index describes them: they return
    /// `None` and are gated by `pwm_domain::pwm_control_allowed`, which
    /// requires the caller to hold every channel reached. Returning the named
    /// channel for those would authorise the narrow claim while the write
    /// lands wide — the exact bug this whole line of work came from.
    ///
    /// The duty ops write the per-channel `PWMCMP` and are genuinely narrow.
    fn request_resource(&self, op: u32, input: &[u8]) -> Option<u32> {
        azos_drv_base::drv_resource::pwm_request_resource(op, input)
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        self.initialized.store(false, Ordering::Release);
        Ok(())
    }
}

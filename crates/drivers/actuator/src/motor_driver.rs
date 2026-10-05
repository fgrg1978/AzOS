// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Motor PID as a [`Driver`] impl — fifth migration after UART,
//! GPIO, I2C, PWM. Validates the trait against a closed-loop
//! controller (vs the open-loop actuators / sensors prior).
//!
//! The legacy `crate::motor_pid` API stays in place; this driver
//! wraps it for client tasks via `runtime::REGISTRY`.

use azos_drv_api::{Driver, DriverError, DriverIsolation, DriverManifest};
use crate::motor_pid;
use core::sync::atomic::{AtomicBool, Ordering};
use azos_abi::cap::CapPerms;

// ──────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────

// Was a duplicate to avoid a `drivers → driver_server` cycle; the constants
// moved to `crates/core/abi` on 2026-09-06, which this crate already depends on.
use azos_abi::drv_kind::DRV_KIND_MOTOR_PID;

// Wire sizes — no magic numbers.
const SET_TARGET_INPUT_BYTES: usize = 4;   // 2× i16 LE
const TICK_INPUT_BYTES:       usize = 24;  // 2× i64 LE + 1× u64 LE
const TICK_OUTPUT_BYTES:      usize = 8;   // 2× i32 LE
const ENABLE_INPUT_BYTES:     usize = 1;   // u8 bool
const ENABLED_OUTPUT_BYTES:   usize = 1;   // u8 bool
const SET_GAINS_INPUT_BYTES:  usize = 12;  // 3× i32 LE

/// Stable wire-format ops.
/// `input[0..2]` = speed_l i16 LE, `input[2..4]` = speed_r i16 LE.
pub const MOTOR_OP_SET_TARGET: u32 = 0;
/// `input[0..8]` = ticks_l i64 LE, `input[8..16]` = ticks_r i64 LE,
/// `input[16..24]` = now u64 LE.
/// `output[0..4]` ← pwm_l i32 LE, `output[4..8]` ← pwm_r i32 LE.
pub const MOTOR_OP_TICK: u32 = 1;
/// `input[0]` = 0 (disable) or 1 (enable).
pub const MOTOR_OP_ENABLE: u32 = 2;
/// `output[0]` ← 0 or 1.
pub const MOTOR_OP_ENABLED: u32 = 3;
/// `input[0..4]` = kp, `input[4..8]` = ki, `input[8..12]` = kd
/// (all i32 LE).
pub const MOTOR_OP_SET_GAINS: u32 = 4;
/// No input. Clears integrator + previous error.
pub const MOTOR_OP_RESET: u32 = 5;

// ──────────────────────────────────────────────────────────────────────────
// Manifest
// ──────────────────────────────────────────────────────────────────────────

const fn build_manifest() -> DriverManifest {
    // The PID controller has no MMIO of its own — it composes PWM
    // + encoder syscalls. So the manifest reports `mmio = None`
    // even on real hardware, which is a useful audit signal: this
    // driver is pure software and does not claim any device pages.
    DriverManifest::new(
        DRV_KIND_MOTOR_PID,
        "motor-pid",
        DriverIsolation::InKernel,
        CapPerms::RW,
    )
}

// ──────────────────────────────────────────────────────────────────────────
// Driver state
// ──────────────────────────────────────────────────────────────────────────

pub struct MotorPidDriver {
    initialized: AtomicBool,
    manifest: DriverManifest,
}

impl MotorPidDriver {
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            manifest: build_manifest(),
        }
    }
}

impl Default for MotorPidDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Driver impl
// ──────────────────────────────────────────────────────────────────────────

impl Driver for MotorPidDriver {
    fn manifest(&self) -> &DriverManifest {
        &self.manifest
    }

    fn init(&self) -> Result<(), DriverError> {
        if self
            .initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            motor_pid::motor_pid_init();
        }
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
            MOTOR_OP_SET_TARGET => {
                if input.len() < SET_TARGET_INPUT_BYTES {
                    return Err(DriverError::BadInput);
                }
                let l = i16::from_le_bytes([input[0], input[1]]);
                let r = i16::from_le_bytes([input[2], input[3]]);
                motor_pid::motor_pid_set_target(l, r);
                Ok(0)
            }
            MOTOR_OP_TICK => {
                if input.len() < TICK_INPUT_BYTES {
                    return Err(DriverError::BadInput);
                }
                if output.len() < TICK_OUTPUT_BYTES {
                    return Err(DriverError::BadOutput);
                }
                let ticks_l = i64::from_le_bytes(
                    input[0..8].try_into().map_err(|_| DriverError::BadInput)?,
                );
                let ticks_r = i64::from_le_bytes(
                    input[8..16].try_into().map_err(|_| DriverError::BadInput)?,
                );
                let now = u64::from_le_bytes(
                    input[16..24].try_into().map_err(|_| DriverError::BadInput)?,
                );
                let (pwm_l, pwm_r) = motor_pid::motor_pid_tick(ticks_l, ticks_r, now);
                output[0..4].copy_from_slice(&pwm_l.to_le_bytes());
                output[4..8].copy_from_slice(&pwm_r.to_le_bytes());
                Ok(TICK_OUTPUT_BYTES)
            }
            MOTOR_OP_ENABLE => {
                if input.len() < ENABLE_INPUT_BYTES {
                    return Err(DriverError::BadInput);
                }
                motor_pid::motor_pid_enable(input[0] != 0);
                Ok(0)
            }
            MOTOR_OP_ENABLED => {
                if output.len() < ENABLED_OUTPUT_BYTES {
                    return Err(DriverError::BadOutput);
                }
                output[0] = u8::from(motor_pid::motor_pid_enabled());
                Ok(ENABLED_OUTPUT_BYTES)
            }
            MOTOR_OP_SET_GAINS => {
                if input.len() < SET_GAINS_INPUT_BYTES {
                    return Err(DriverError::BadInput);
                }
                let kp = i32::from_le_bytes(
                    input[0..4].try_into().map_err(|_| DriverError::BadInput)?,
                );
                let ki = i32::from_le_bytes(
                    input[4..8].try_into().map_err(|_| DriverError::BadInput)?,
                );
                let kd = i32::from_le_bytes(
                    input[8..12].try_into().map_err(|_| DriverError::BadInput)?,
                );
                motor_pid::motor_pid_set_gains(kp, ki, kd);
                Ok(0)
            }
            MOTOR_OP_RESET => {
                motor_pid::motor_pid_reset();
                Ok(0)
            }
            _ => Err(DriverError::BadOp),
        }
    }

    /// The PID driver's ops act on the WHOLE differential pair — its input
    /// carries a left/right target, not a motor id — so no single resource
    /// index describes what they reach.
    ///
    /// `None` therefore falls back to the kind-wide check, and that is
    /// deliberately weaker than it looks: a task holding `Cap<Motor>(0)`
    /// passes it and then drives both wheels. The strong version already
    /// exists next door — `motor_cap.rs`'s `require_pair_write` demands write
    /// on resource 0 AND 1 — and wiring this path to it is a `crates/core/ipc`
    /// change, so it is named here rather than guessed at.
    fn request_resource(&self, _op: u32, _input: &[u8]) -> Option<u32> {
        None
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        motor_pid::motor_pid_enable(false);
        self.initialized.store(false, Ordering::Release);
        Ok(())
    }
}

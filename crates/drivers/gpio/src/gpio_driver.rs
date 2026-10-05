// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! GPIO as a [`Driver`] impl — second migration to the RFC-0002 API
//! (after `uart_driver`).
//!
//! Thin wrapper over the existing free-function GPIO module
//! (`crate::gpio`). Proves the [`Driver`] trait shape scales beyond
//! UART to a different hardware family (pin-oriented, simulated on
//! QEMU, real MMIO on VF2/K1).
//!
//! The legacy `crate::gpio` API stays in place — kernel-internal
//! callers (e.g. `safety` ESTOP latch) continue using it directly.
//! This driver provides the unified API for client tasks via
//! `runtime::REGISTRY`.

use azos_drv_api::{Driver, DriverError, DriverIsolation, DriverManifest};
#[cfg(any(feature = "vf2", feature = "k1"))]
use azos_drv_api::MmioRange;
use crate::gpio::{self, GpioDir};
use core::sync::atomic::{AtomicBool, Ordering};
use azos_abi::cap::CapPerms;

// ──────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────

/// Mirrors `azos_driver_server::DRV_KIND_GPIO`. Kept duplicate to
/// avoid a `drivers → driver_server` cycle; the two must stay equal.
const DRV_KIND_GPIO: u32 = 0x0001;

/// MMIO window claimed by the GPIO driver on real platforms.
/// Sized for a full page of the JH7110 sys_iomux block (256 bytes
/// of registers, page-aligned for completeness).
#[cfg(any(feature = "vf2", feature = "k1"))]
const GPIO_MMIO_BYTES: u64 = 0x100;

/// Width in bytes of the request input blob shared by every op:
/// `[pin u32 LE, payload u8, pad u8 × 3]`. Reads ignore the
/// payload field; writes carry the 0/1 value in payload.
const GPIO_INPUT_BYTES: usize = 8;

/// Number of bytes a READ op writes into the caller's output:
/// a single byte (0 or 1).
const GPIO_READ_OUTPUT_BYTES: usize = 1;

/// Stable wire-format ops. Bumping `DRIVER_MANIFEST_VERSION` is
/// required to change any of these.
/// Set pin direction. `input[0..4]` = pin u32 LE,
/// `input[4]` = direction (0 = input, 1 = output).
pub const GPIO_OP_SET_DIR: u32 = 0;
/// Read pin level. `input[0..4]` = pin u32 LE,
/// `output[0]` ← 0 or 1.
pub const GPIO_OP_READ: u32 = 1;
/// Write pin level. `input[0..4]` = pin u32 LE,
/// `input[4]` = value (low bit used).
pub const GPIO_OP_WRITE: u32 = 2;
/// Toggle pin level. `input[0..4]` = pin u32 LE.
pub const GPIO_OP_TOGGLE: u32 = 3;

// ──────────────────────────────────────────────────────────────────────────
// Manifest builder (handles per-platform MMIO presence)
// ──────────────────────────────────────────────────────────────────────────

const fn build_manifest() -> DriverManifest {
    let m = DriverManifest::new(
        DRV_KIND_GPIO,
        "gpio",
        DriverIsolation::InKernel,
        CapPerms::RW,
    );
    // Only VF2/K1 expose a real GPIO MMIO block; QEMU simulates the
    // pins in software.
    #[cfg(any(feature = "vf2", feature = "k1"))]
    let m = m.with_mmio(MmioRange::new(
        azos_drv_base::platform::hw::GPIO_BASE as u64,
        GPIO_MMIO_BYTES,
    ));
    m
}

// ──────────────────────────────────────────────────────────────────────────
// Driver state
// ──────────────────────────────────────────────────────────────────────────

/// Stateful wrapper. The actual GPIO state lives in the static in
/// `crate::gpio` (sim) or in real MMIO (vf2/k1); this struct only
/// carries the manifest + a cross-CPU init guard.
pub struct GpioDriver {
    initialized: AtomicBool,
    manifest: DriverManifest,
}

impl GpioDriver {
    /// Construct an uninitialised GPIO driver. `const` so a `static
    /// GPIO_DRV: GpioDriver` can be created without a runtime hook.
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            manifest: build_manifest(),
        }
    }

    /// Decode `pin` from the first 4 bytes of `input`.
    fn decode_pin(input: &[u8]) -> Result<u32, DriverError> {
        if input.len() < 4 {
            return Err(DriverError::BadInput);
        }
        Ok(u32::from_le_bytes([input[0], input[1], input[2], input[3]]))
    }

    /// Decode `pin + payload` from at least [`GPIO_INPUT_BYTES`] bytes.
    fn decode_pin_payload(input: &[u8]) -> Result<(u32, u8), DriverError> {
        if input.len() < GPIO_INPUT_BYTES {
            return Err(DriverError::BadInput);
        }
        let pin = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        Ok((pin, input[4]))
    }
}

impl Default for GpioDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Driver impl
// ──────────────────────────────────────────────────────────────────────────

impl Driver for GpioDriver {
    fn manifest(&self) -> &DriverManifest {
        &self.manifest
    }

    fn init(&self) -> Result<(), DriverError> {
        // Idempotent + cross-CPU safe. `compare_exchange` ensures
        // only one caller across CPUs actually runs `gpio_init`.
        if self
            .initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            gpio::gpio_init();
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
            GPIO_OP_SET_DIR => {
                let (pin, dir_raw) = Self::decode_pin_payload(input)?;
                let dir = match dir_raw {
                    0 => GpioDir::Input,
                    1 => GpioDir::Output,
                    _ => return Err(DriverError::BadInput),
                };
                match gpio::gpio_set_direction(pin, dir) {
                    0 => Ok(0),
                    _ => Err(DriverError::IoFault),
                }
            }
            GPIO_OP_READ => {
                let pin = Self::decode_pin(input)?;
                if output.len() < GPIO_READ_OUTPUT_BYTES {
                    return Err(DriverError::BadOutput);
                }
                let v = gpio::gpio_read(pin);
                if v < 0 {
                    return Err(DriverError::IoFault);
                }
                output[0] = v as u8;
                Ok(GPIO_READ_OUTPUT_BYTES)
            }
            GPIO_OP_WRITE => {
                let (pin, val) = Self::decode_pin_payload(input)?;
                match gpio::gpio_write(pin, (val & 1) as u32) {
                    0 => Ok(0),
                    _ => Err(DriverError::IoFault),
                }
            }
            GPIO_OP_TOGGLE => {
                let pin = Self::decode_pin(input)?;
                match gpio::gpio_toggle(pin) {
                    0 => Ok(0),
                    _ => Err(DriverError::IoFault),
                }
            }
            _ => Err(DriverError::BadOp),
        }
    }

    /// Every GPIO op names its pin in `input[0..4]`, and `Cap<Gpio>`'s
    /// resource IS the pin number, so the mapping is the identity.
    ///
    /// This is the driver whose omission was live: `SYS_DRV_INVOKE` checked
    /// only that the caller held SOME `Cap<Gpio>`, so `Cap<Gpio>(5)` wrote
    /// pin 40. A malformed payload returns `None`, which denies rather than
    /// guesses — `handle_request` will reject it a moment later anyway, and
    /// authorising on a pin decoded from bytes we just called malformed would
    /// be the wrong order.
    fn request_resource(&self, _op: u32, input: &[u8]) -> Option<u32> {
        azos_drv_base::drv_resource::gpio_request_resource(input)
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        // Pin state stays as-is; the driver framework guards against
        // double-init via the atomic flag, so allowing a fresh
        // `init()` later is the right behaviour.
        self.initialized.store(false, Ordering::Release);
        Ok(())
    }
}

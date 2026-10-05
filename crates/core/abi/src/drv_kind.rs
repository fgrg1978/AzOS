// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `DRV_KIND_*` — the device-kind identifiers used by the driver registry.
//!
//! **The `DRV_KIND_*` values are ABI, not an internal enumeration**
//! (`DRIVER_MAX_KINDS` is the exception — see its own doc). `SYS_DRIVER_REGISTER`
//! (520), `SYS_DRIVER_UNREGISTER` (521), `SYS_DRIVER_POLL_EVENT`,
//! `SYS_DRIVER_FETCH_REQUEST`, `SYS_DRIVER_REPLY` and `SYS_DRV_INVOKE` all
//! take one of these values in a register from ring 3, so renumbering one is
//! a break in exactly the way renumbering a syscall is.
//!
//! They lived in `crates/drivers/driver_server` until 2026-09-06 and moved here for
//! the reason that crate makes them hard to reach: `driver_server` depends on
//! `azos_sync`, which depends on `azos_arch`, which is RV64-only — so
//! every host test crate that wanted a `DRV_KIND_*` had to either shim the
//! whole registry or restate the number. `crates/core/abi` is dependency-free by
//! design and is already a dependency of every one of those crates.
//!
//! `driver_server` re-exports this module wholesale, so every existing
//! `azos_driver_server::DRV_KIND_*` path still resolves.

/// Upper bound on driver kinds. One registry slot per kind.
///
/// **Not ABI, unlike everything below it** — no syscall carries this value;
/// it is `crates/drivers/driver_server`'s table capacity. It sits here only so the
/// registry's kinds and its size stay in one file, and changing it breaks no
/// ring-3 program.
pub const DRIVER_MAX_KINDS: usize = 32;

/// General-purpose I/O pins.
pub const DRV_KIND_GPIO: u32 = 0x0001;
/// I2C controller.
pub const DRV_KIND_I2C: u32 = 0x0002;
/// SPI controller.
pub const DRV_KIND_SPI: u32 = 0x0003;
/// Serial port.
pub const DRV_KIND_UART: u32 = 0x0004;
/// PWM generator.
pub const DRV_KIND_PWM: u32 = 0x0005;
/// DMA engine.
pub const DRV_KIND_DMA: u32 = 0x0006;
/// CSI camera.
pub const DRV_KIND_CSI_CAM: u32 = 0x0007;
/// LIDAR unit.
pub const DRV_KIND_LIDAR: u32 = 0x0008;
/// Motor PID loop — the actuation path.
pub const DRV_KIND_MOTOR_PID: u32 = 0x0009;
/// Inertial measurement unit.
pub const DRV_KIND_IMU: u32 = 0x000A;
/// GNSS receiver.
pub const DRV_KIND_GPS: u32 = 0x000B;
/// Analogue-to-digital converter.
pub const DRV_KIND_ADC: u32 = 0x000C;
/// Neural accelerator.
pub const DRV_KIND_NPU: u32 = 0x000D;
/// CAN bus. No board in the tree exposes one.
pub const DRV_KIND_CAN: u32 = 0x000E;
/// xHCI USB host controller.
pub const DRV_KIND_USB_XHCI: u32 = 0x000F;
/// Piezo buzzer. Served by a ring-3 driver (`userspace/drivers/buzz_drv`).
pub const DRV_KIND_BUZZER: u32 = 0x0010;
/// INA219 current/voltage monitor. Served by a ring-3 driver
/// (`userspace/drivers/ina_drv`).
pub const DRV_KIND_POWER_MON: u32 = 0x0011;
/// The ring-3 ML inference service (`userspace/services/mlsrv`). Not a device: the
/// behavior loop's MLP runs there, and the kernel reaches it the way it
/// reaches a ring-3 driver. Its ops are [`crate::ml_srv`]. 0x0012: after the
/// ring-3 buzzer and power monitor.
pub const DRV_KIND_ML: u32 = 0x0012;

/// Request ops of the ring-3 buzzer driver (`DRV_KIND_BUZZER`).
///
/// Every reply carries one byte: 1 when the driver's PWM writes were accepted,
/// 0 otherwise. The driver answers when the sound STARTS, never when it ends.
pub mod buzzer_op {
    /// Input: `freq_hz: u16`, `duration_ms: u32` (LE). Frequency or duration 0
    /// stops.
    pub const TONE: u32 = 0;
    /// Input: `freq_hz: u16` (LE). Held until the next request; 0 stops.
    pub const ON: u32 = 1;
    /// Stop whatever is playing.
    pub const OFF: u32 = 2;
    /// 100 ms at 1000 Hz.
    pub const BEEP: u32 = 3;
    /// Three 80 ms beeps at 2000 Hz, 60 ms apart.
    pub const ALERT: u32 = 4;
    /// C4 - E4 - G4 - C5, 120 ms each, 40 ms apart.
    pub const STARTUP: u32 = 5;
}

/// Request ops of the ring-3 power-monitor driver (`DRV_KIND_POWER_MON`).
pub mod power_op {
    /// Output: the last sample, [`POWER_DATA_SIZE`] bytes, or 0 bytes while
    /// the chip is unconfigured.
    pub const READ: u32 = 0;
    /// Output: `sample_count: u32`, `read_failures: u32` (LE), `configured: u8`,
    /// then `charge_ma_us: u64` (LE): the integrated charge behind
    /// `mah_used`, in mA x us, each sample weighted by the time measured since
    /// the previous one ([`STATS_BYTES`] in all; the first 9 bytes are the
    /// wave 9 layout).
    pub const STATS: u32 = 1;
    /// Bytes [`STATS`] writes.
    pub const STATS_BYTES: usize = 17;
    /// `voltage_mv: u16`, `current_ma: u16`, `mah_used: u32`,
    /// `capacity_pct: u8`, `sag: u8`, `failsafe: u8`, `pad: u8` (LE) — the
    /// `SYS_SENSOR_READ(SENSOR_TYPE_POWER)` record.
    pub const POWER_DATA_SIZE: usize = 12;
    /// Output: the [`READ`] record, then `acq_ns: u64` (LE): when the driver's
    /// register reads behind that sample completed, on the vDSO clock in
    /// nanoseconds ([`POWER_TS_BYTES`] in all), or 0 bytes while the chip is
    /// unconfigured. Wave 11 (SENSORTS): what `SYS_SENSOR_READ_TS` reports
    /// for `SENSOR_TYPE_POWER`. A driver older than this answers it with
    /// `STATUS_BAD_OP` and no bytes.
    pub const READ_TS: u32 = 2;
    /// Bytes [`READ_TS`] writes.
    pub const POWER_TS_BYTES: usize = POWER_DATA_SIZE + 8;
}

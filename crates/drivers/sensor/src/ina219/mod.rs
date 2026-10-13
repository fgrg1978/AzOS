// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! INA219 power monitor: the kernel API, in either placement (RFC-0052
//! section 6.1, wave 11 DRVPLACE).
//!
//! One chip-logic source, `crates/drivers/ina219`, and two hosts chosen per
//! board by Kconfig `DRV_INA219_PLACEMENT`:
//!
//! * `ring3` (default; RFC-0040 rule 3): [`proxy`] — every call is a
//!   `UserDriverProxy` request to `userspace/drivers/ina_drv` (`INADRV.ELF`),
//!   started from its topology row.
//! * `kernel` (cargo feature `ina219-kernel`): [`kernel_host`] — a kernel
//!   task samples the chip over `azos_drv_bus::i2c` and publishes the chip state;
//!   every call is a direct read of that state, no request, no wake-up.
//!
//! Both answer through `azos_ina219::serve` from a `azos_ina219::Ina219`,
//! so the same `SYS_SENSOR_READ(SENSOR_TYPE_POWER)` record comes out of
//! either. The API below is identical in both: callers (the sensor syscall,
//! the gate smokes) do not know the placement.
//!
//! Not read by any safety decision (the only consumer is the sensor
//! syscall), which is what allows the ring-3 placement at all; the drivers a
//! safety decision reads have no placement switch (Kconfig.drivers).

use azos_abi::drv_kind::power_op;

/// Bytes of one power record: voltage_mv u16, current_ma u16, mah_used u32,
/// capacity_pct u8, sag u8, failsafe u8, pad u8 (all LE).
pub const POWER_DATA_SIZE: usize = power_op::POWER_DATA_SIZE;

/// This kernel was built with the in-kernel host (`DRV_INA219_PLACEMENT =
/// kernel`). The kernel asserts it against the topology's ring-3 row, so a
/// build that places the driver in the kernel and still declares
/// `INADRV.ELF` does not link.
pub const IN_KERNEL: bool = cfg!(feature = "ina219-kernel");

#[cfg(not(feature = "ina219-kernel"))]
pub mod proxy;
#[cfg(not(feature = "ina219-kernel"))]
pub use proxy::{
    ina219_charge_ma_us, ina219_driver_tid, ina219_read_power, ina219_read_power_stamped,
    ina219_stats,
};

#[cfg(feature = "ina219-kernel")]
pub mod kernel_host;
#[cfg(feature = "ina219-kernel")]
pub use kernel_host::{
    ina219_charge_ma_us, ina219_driver_tid, ina219_read_power, ina219_read_power_stamped,
    ina219_stats,
};

/// The chip-logic source (`AZOS-CHIP-SRC ina219 <hex>`), which the kernel
/// host prints at start (`tools/chip_source_check.py`).
pub const SOURCE_MARKER: &[u8] = &azos_ina219::SOURCE_MARKER;

/// Where the INA219 runs in this build, for the log and the gate rows.
pub const PLACEMENT: &str = if IN_KERNEL { "kernel" } else { "ring-3" };

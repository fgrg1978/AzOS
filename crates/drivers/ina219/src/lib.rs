// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! INA219 power monitor, one source for both placements (RFC-0052 section
//! 6.1, wave 11 DRVPLACE).
//!
//! [`chip`] is the chip logic over a [`Bus`]; [`serve`] answers the
//! `power_op` requests from a chip's state. A host supplies the bus, the
//! clock and the loop: ring 3 (`userspace/drivers/ina_drv`, a
//! `DriverRequest` per request through the kernel's proxy) or the kernel
//! (`crates/drivers/sensor`, feature `ina219-kernel`, a direct call).
//! Kconfig `DRV_INA219_PLACEMENT` picks the host per board.

#![no_std]

pub mod chip;

pub use chip::{Bus, Ina219, INA219_ADDR, INA219_BUS, INA219_POLL_HZ, POWER_DATA_SIZE};

// `SOURCE_HASH` / `SOURCE_MARKER`: the fingerprint of this crate's source
// that each host prints at start (`crates/drivers/chip_source.rs`,
// `tools/chip_source_check.py`).
include!(concat!(env!("OUT_DIR"), "/chip_source.rs"));

use azos_abi::drv_kind::power_op;

/// Answer `power_op` request `op` from `chip`'s published state into `out`.
/// `acq_ns` is the acquisition stamp of that state (the host's clock read
/// right after the first register read behind it). `Some(bytes written)`,
/// `None` for an op this driver does not know.
///
/// `READ` and `READ_TS` write 0 bytes while the chip is unconfigured: "no
/// data", never a fabricated battery. `out` must hold [`power_op::STATS_BYTES`]
/// and [`power_op::POWER_TS_BYTES`]; a shorter buffer gets 0 bytes.
pub fn serve(chip: &Ina219, op: u32, acq_ns: u64, out: &mut [u8]) -> Option<usize> {
    match op {
        power_op::READ => Some(chip.read_power(out)),
        power_op::READ_TS => {
            if out.len() < power_op::POWER_TS_BYTES
                || chip.read_power(&mut out[..POWER_DATA_SIZE]) != POWER_DATA_SIZE
            {
                return Some(0);
            }
            out[POWER_DATA_SIZE..power_op::POWER_TS_BYTES].copy_from_slice(&acq_ns.to_le_bytes());
            Some(power_op::POWER_TS_BYTES)
        }
        power_op::STATS => {
            if out.len() < power_op::STATS_BYTES {
                return Some(0);
            }
            out[0..4].copy_from_slice(&chip.sample_count().to_le_bytes());
            out[4..8].copy_from_slice(&chip.read_failures().to_le_bytes());
            out[8] = chip.is_initialized() as u8;
            out[9..17].copy_from_slice(&chip.charge_ma_us().to_le_bytes());
            Some(power_op::STATS_BYTES)
        }
        _ => None,
    }
}

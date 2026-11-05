// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! INA219 power monitor, one source for both placements.
//!
//! [`chip`] is the chip logic over a [`Bus`]; [`Monitor`] serves the
//! `PowerMon` interface (`azos_devif::powermon`) from a chip's state. A host
//! supplies the bus, the clock and the loop: ring 3
//! (`userspace/drivers/ina_drv`, on `endpoint.powermon`) or the kernel
//! (`crates/drivers/sensor`, a direct call). The topology row's `place` picks
//! the host.

#![no_std]
#![forbid(unsafe_code)]

pub mod chip;

pub use chip::{Bus, Ina219, INA219_ADDR, INA219_BUS, INA219_POLL_HZ, POWER_DATA_SIZE};

// `SOURCE_HASH` / `SOURCE_MARKER`: the fingerprint of this crate's source
// that each host prints at start (`crates/drivers/chip_source.rs`,
// `tools/lint/chip_source_check.py`).
include!(concat!(env!("OUT_DIR"), "/chip_source.rs"));

use azos_devif::powermon::{PowerMon, PowerStats};
use azos_devif::{outcome, Out, Sample};

/// A chip's published state as the `PowerMon` interface serves it. `acq_ns`
/// is the acquisition stamp of that state (the host's clock read right after
/// the first register read behind it).
pub struct Monitor<'a> {
    pub chip: &'a Ina219,
    pub acq_ns: u64,
}

impl PowerMon for Monitor<'_> {
    /// `NOT_READY` while the chip is unconfigured: "no data", never a
    /// fabricated battery.
    fn read(&mut self) -> Out<Sample> {
        let mut rec = [0u8; POWER_DATA_SIZE];
        if self.chip.read_power(&mut rec) != POWER_DATA_SIZE {
            return Out::err(outcome::NOT_READY);
        }
        Out::ok(Sample::new(&rec, 0, self.acq_ns))
    }

    fn stats(&mut self) -> Out<PowerStats> {
        Out::ok(PowerStats {
            samples: self.chip.sample_count(),
            failures: self.chip.read_failures(),
            configured: self.chip.is_initialized(),
            charge_ma_us: self.chip.charge_ma_us(),
        })
    }
}

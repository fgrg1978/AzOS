// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `PowerMon` interface: a battery power monitor (the INA219).
//!
//! The one interface of a driver that has two hosts from one source
//! (`crates/drivers/ina219`): the kernel host is called directly
//! (`PowerMonDirect`), the ring-3 host (`userspace/drivers/ina_drv`) serves the
//! same trait from the endpoint [`ENDPOINT`] its topology row declares and is
//! called through `PowerMonClient`; `PowerMonPlaced` is the value a caller holds
//! when it must not know which. The row's `place` says which runs.
//!
//! This is a task-hosted endpoint, not a kernel-hosted interface: it is not in
//! [`crate::IFACES`]. It is not the `Sensor` interface because a monitor also
//! answers its own counters ([`PowerStats`]), which no sensor type has.
//!
//! The record is the 12 bytes `SENSOR_TYPE_POWER` returns (voltage_mv u16,
//! current_ma u16, mah_used u32, capacity_pct u8, sag u8, failsafe u8, pad u8,
//! little-endian) in a [`Sample`] with the time its register reads completed.

use crate::outcome::Out;
use crate::sensor::Sample;
use azos_idl::{azos_interface, Reader, Wire, Writer};

/// The interface id (ASCII "PMON").
pub const POWERMON_ID: u32 = 0x504D_4F4E;

/// The endpoint a topology row declares for this object.
pub const ENDPOINT: &str = "endpoint.powermon";

/// The name that endpoint has in the kernel's pool (the grant without its
/// `endpoint.` prefix), which is how the kernel finds it to mint a capability.
pub const ENDPOINT_NAME: &str = "powermon";

/// Bytes of one power record.
pub const RECORD_BYTES: usize = 12;

/// What the monitor counts about itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PowerStats {
    /// Samples published.
    pub samples: u32,
    /// Register transfers that failed.
    pub failures: u32,
    /// The chip has accepted its configuration.
    pub configured: bool,
    /// Charge integrated over the time measured between samples, mA x us.
    pub charge_ma_us: u64,
}

impl Wire for PowerStats {
    const WORDS: usize = 4;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.samples.put(w);
        self.failures.put(w);
        self.configured.put(w);
        self.charge_ma_us.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let samples = u32::get(r);
        let failures = u32::get(r);
        let configured = bool::get(r);
        PowerStats { samples, failures, configured, charge_ma_us: u64::get(r) }
    }
}

#[azos_interface(id = 0x504D_4F4E, level = 1)]
pub trait PowerMon {
    /// The last sample. `NOT_READY` while the chip has not accepted its
    /// configuration or no host has sampled: never a fabricated reading.
    #[idempotent]
    fn read(&mut self) -> Out<Sample>;
    /// The monitor's counters.
    #[idempotent]
    fn stats(&mut self) -> Out<PowerStats>;
}

/// The ops of [`PowerMon`] that only read, by name: what a caller that must
/// say whether a call acts (the kernel's call by name under containment,
/// `azos_syscall::kcall::Purpose`) declares for each. Every op not named
/// here, a new one included, acts.
pub const OBSERVING_OPS: &[&str] = &["read", "stats"];

/// Does the request whose header word is `h` only read? Its interface is
/// [`POWERMON_ID`] and its op is one of [`OBSERVING_OPS`]; anything else,
/// an unknown op included, is taken to act.
pub fn request_observes(h: u64) -> bool {
    azos_idl::header_id(h) == POWERMON_ID
        && PowerMonIdl::OPS.iter().any(|o| o.op == azos_idl::header_op(h) && OBSERVING_OPS.contains(&o.name))
}

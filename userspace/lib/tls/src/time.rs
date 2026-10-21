// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The clock a handshake reads.
//!
//! rustls checks a certificate's validity against a [`TimeProvider`]. On
//! `*-unknown-azos` the system clock (`SystemTime::now`) is the real-time clock
//! the vDSO publishes, which reads 1970 plus the uptime until a time source
//! (NTP) has set it. [`DeviceTime`] therefore **has no time** until the clock
//! has been set, and a handshake then fails with "failed to get current time"
//! instead of trusting a wrong one.

use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

/// 2026-01-01 00:00:00 UTC: a clock that reads earlier has not been set.
pub const CLOCK_SET_AFTER_SECS: u64 = 1_767_225_600;

/// The system clock, once it has been set.
#[derive(Debug)]
pub struct DeviceTime;

impl TimeProvider for DeviceTime {
    fn current_time(&self) -> Option<UnixTime> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        (now.as_secs() >= CLOCK_SET_AFTER_SECS).then(|| UnixTime::since_unix_epoch(now))
    }
}

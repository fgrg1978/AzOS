// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The stamped sensor sample of `SYS_SENSOR_READ_TS` (606): a fixed header
//! that carries the time the value was acquired, followed by the payload in
//! `SYS_SENSOR_READ_TYPED`'s (561) byte format for the sensor type.
//!
//! ## The clock
//!
//! `acq_ns` is the monotonic clock ring 3 reads through the vDSO
//! (`azos_libsys::vdso_now_ns`): the free-running counter the kernel calls
//! `timebase::now()`, converted with [`crate::time::ticks_to_ns`] at the
//! frequency the vDSO page publishes. A reader can therefore compare it with
//! its own `vdso_now_ns()` without any conversion.
//!
//! ## Where the stamp is taken
//!
//! At acquisition, not at delivery: the counter is read right after the
//! device transfer that produced the value completes (an I2C burst, an ADC
//! conversion, a GPIO read), or, for a value a producer caches (a GPS fix
//! parsed from the receiver's stream, a LiDAR revolution, odometry integrated
//! by its task, the ring-3 power monitor's last sample), when the producer
//! filled the cache. A value read twice from the same cache carries the same
//! stamp both times. Where a record joins several reads (two rangefinders,
//! three GPIO lines) the stamp is that of the FIRST, so the age a reader
//! computes is never smaller than the age of any field.
//!
//! `acq_ns == 0` means the acquisition time is unknown (a producer that does
//! not report one): such a sample is never fresh.

/// Header layout version written in [`SS_OFF_VERSION`].
pub const SENSOR_SAMPLE_VERSION: u8 = 1;
/// Bytes of the header; the payload starts here. Written in
/// [`SS_OFF_HDR_LEN`] so a later version can grow the header and an older
/// reader still finds the payload.
pub const SENSOR_SAMPLE_HDR_LEN: usize = 16;

/// `u8`: [`SENSOR_SAMPLE_VERSION`].
pub const SS_OFF_VERSION: usize = 0;
/// `u8`: [`SENSOR_SAMPLE_HDR_LEN`].
pub const SS_OFF_HDR_LEN: usize = 1;
/// `u16` LE: `SENSOR_SAMPLE_FLAG_*`.
pub const SS_OFF_FLAGS: usize = 2;
/// `u32` LE: payload bytes after the header (561's return value for the
/// same read).
pub const SS_OFF_PAYLOAD_LEN: usize = 4;
/// `u64` LE: acquisition time, vDSO-clock nanoseconds; 0 = unknown.
pub const SS_OFF_ACQ_NS: usize = 8;

/// The value was not measured by a device: a simulated source stands in for
/// the sensor (QEMU's fixed GPS fix, the simulated rangefinder, the battery
/// voltage reported when no ADC is fitted). The stamp is when the simulation
/// produced it.
pub const SENSOR_SAMPLE_FLAG_SYNTHETIC: u16 = 1 << 0;

/// The header [`SYS_SENSOR_READ_TS`](crate::syscall_nr::SYS_SENSOR_READ_TS)
/// writes in front of the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SensorSampleHdr {
    /// [`SENSOR_SAMPLE_VERSION`] when written by this kernel.
    pub version: u8,
    /// Header bytes; the payload starts here.
    pub hdr_len: u8,
    /// `SENSOR_SAMPLE_FLAG_*`.
    pub flags: u16,
    /// Payload bytes after the header.
    pub payload_len: u32,
    /// Acquisition time, vDSO-clock nanoseconds; 0 = unknown.
    pub acq_ns: u64,
}

impl SensorSampleHdr {
    /// A version-1 header.
    pub const fn new(flags: u16, payload_len: u32, acq_ns: u64) -> Self {
        Self {
            version: SENSOR_SAMPLE_VERSION,
            hdr_len: SENSOR_SAMPLE_HDR_LEN as u8,
            flags,
            payload_len,
            acq_ns,
        }
    }

    /// The wire bytes.
    pub fn to_bytes(&self) -> [u8; SENSOR_SAMPLE_HDR_LEN] {
        let mut b = [0u8; SENSOR_SAMPLE_HDR_LEN];
        b[SS_OFF_VERSION] = self.version;
        b[SS_OFF_HDR_LEN] = self.hdr_len;
        b[SS_OFF_FLAGS..SS_OFF_FLAGS + 2].copy_from_slice(&self.flags.to_le_bytes());
        b[SS_OFF_PAYLOAD_LEN..SS_OFF_PAYLOAD_LEN + 4].copy_from_slice(&self.payload_len.to_le_bytes());
        b[SS_OFF_ACQ_NS..SS_OFF_ACQ_NS + 8].copy_from_slice(&self.acq_ns.to_le_bytes());
        b
    }

    /// Parse a header. `None` when `b` is shorter than the fixed fields or the
    /// header claims a version 0 or a length shorter than version 1's.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < SENSOR_SAMPLE_HDR_LEN {
            return None;
        }
        let h = Self {
            version: b[SS_OFF_VERSION],
            hdr_len: b[SS_OFF_HDR_LEN],
            flags: u16::from_le_bytes([b[SS_OFF_FLAGS], b[SS_OFF_FLAGS + 1]]),
            payload_len: u32::from_le_bytes([
                b[SS_OFF_PAYLOAD_LEN], b[SS_OFF_PAYLOAD_LEN + 1],
                b[SS_OFF_PAYLOAD_LEN + 2], b[SS_OFF_PAYLOAD_LEN + 3],
            ]),
            acq_ns: {
                let mut w = [0u8; 8];
                w.copy_from_slice(&b[SS_OFF_ACQ_NS..SS_OFF_ACQ_NS + 8]);
                u64::from_le_bytes(w)
            },
        };
        if h.version == 0 || (h.hdr_len as usize) < SENSOR_SAMPLE_HDR_LEN {
            return None;
        }
        Some(h)
    }
}

/// Whether a sample acquired at `acq_ns` is still usable at `now_ns`: the
/// staleness rule every consumer of a stamp applies. `0` (unknown) is never
/// fresh; a stamp from the future (a clock that is not the same as the
/// reader's) is not either. Strictly less than `max_age_ns`.
pub const fn sample_is_fresh_ns(acq_ns: u64, now_ns: u64, max_age_ns: u64) -> bool {
    acq_ns != 0 && acq_ns <= now_ns && now_ns - acq_ns < max_age_ns
}

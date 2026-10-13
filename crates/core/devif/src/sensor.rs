// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Sensor` interface: one sensor type.
//!
//! The endpoint's badge is the sensor type (`endpoint = "sensor.0"` the IMU
//! ... `"sensor.9"` the power monitor, [`azos_abi::sensor_sample`]'s list);
//! there is no type argument, so a task cannot ask for a sensor it was not
//! granted. Every op observes and needs `READ`.
//!
//! A reading is the sample header's two fields and up to [`SAMPLE_BYTES`]
//! bytes of record. A type whose record is larger (a LiDAR scan, a camera
//! frame) is not read through this interface: it travels on the stream rings
//! (`stream.lidar`, `stream.camera`) and the ring's `READ_SENSOR` op.
//!
//! The control loops that need a sensor at their own rate bind it to the
//! vDSO page with `bind_vdso` and read it there with no call at all.

use crate::outcome::Out;
use azos_idl::{azos_interface, Reader, Wire, Writer};

/// The interface id (ASCII "SENS").
pub const SENSOR_ID: u32 = 0x5345_4E53;

/// Sensor types the interface serves: 0 (IMU) to 9 (power monitor).
pub const TYPES: u32 = 10;
/// Words of record in a reading.
pub const SAMPLE_WORDS: usize = 3;
/// Most bytes of record a reading carries.
pub const SAMPLE_BYTES: usize = SAMPLE_WORDS * 8;

/// One reading: the record and when it was acquired.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    /// Bytes of record that are meaningful.
    pub len: u32,
    /// `azos_abi::sensor_sample::SENSOR_SAMPLE_FLAG_*`.
    pub flags: u32,
    /// Acquisition time on the vDSO clock, nanoseconds; 0 = unknown.
    pub acq_ns: u64,
    /// The record, little-endian, the rest zero.
    pub w: [u64; SAMPLE_WORDS],
}

impl Sample {
    /// Copy the record into `out`; returns how many bytes were copied.
    pub fn copy_to(&self, out: &mut [u8]) -> usize {
        let n = (self.len as usize).min(SAMPLE_BYTES).min(out.len());
        for (i, o) in out[..n].iter_mut().enumerate() {
            *o = (self.w[i / 8] >> ((i % 8) * 8)) as u8;
        }
        n
    }

    /// A reading of `data` (at most [`SAMPLE_BYTES`] of it).
    pub fn new(data: &[u8], flags: u32, acq_ns: u64) -> Sample {
        let n = data.len().min(SAMPLE_BYTES);
        let mut s = Sample { len: n as u32, flags, acq_ns, w: [0; SAMPLE_WORDS] };
        for (i, b) in data[..n].iter().enumerate() {
            s.w[i / 8] |= (*b as u64) << ((i % 8) * 8);
        }
        s
    }
}

impl Wire for Sample {
    const WORDS: usize = 2 + SAMPLE_WORDS;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.len.put(w);
        self.flags.put(w);
        self.acq_ns.put(w);
        self.w.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let len = u32::get(r);
        let flags = u32::get(r);
        let acq_ns = u64::get(r);
        Sample { len, flags, acq_ns, w: <[u64; SAMPLE_WORDS]>::get(r) }
    }
}

#[azos_interface(id = 0x5345_4E53, level = 1)]
pub trait Sensor {
    /// The sensor's current reading. `NOT_READY` when the driver has nothing
    /// to give yet (the capability was accepted), `UNSUPPORTED` for a type
    /// whose record does not fit [`SAMPLE_BYTES`]. Needs `READ`.
    #[idempotent]
    fn read(&self) -> Out<Sample>;
    /// Publish this sensor on the caller's vDSO page: its readings appear in
    /// the page's sample slot without a call. `true` when the timer interrupt
    /// refreshes the slot (the sensors it can sample: the encoder and the
    /// odometry), `false` when the sensor is bound but has no interrupt-safe
    /// source and is read by `read` only. `NOT_READY` when the caller has not
    /// mapped its page. Needs `READ`.
    fn bind_vdso(&mut self) -> Out<bool>;
}

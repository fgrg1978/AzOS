// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Sensor` interface the kernel hosts: one sensor type, the badge of the
//! endpoint capability a topology row grants (`endpoint = "sensor.0"` the IMU
//! ... `"sensor.9"` the power monitor). It replaces `SYS_SENSOR_READ_TYPED`,
//! `SYS_SENSOR_READ_TS` and `SYS_VDSO_SENSOR_BIND`; the authority is the same
//! (`READ` on the sensor's capability), stated as the op class of the
//! endpoint.
//!
//! There is no type argument to disagree with the badge, so a task cannot ask
//! for a sensor it was not granted. A reading is the record and when it was
//! acquired (`azos_devif::Sample`: the stamp the stamped read used to carry in
//! its header). A type whose record does not fit a reply, the LiDAR scan and the
//! camera frame, answers `UNSUPPORTED`: those travel on the stream rings
//! (`stream.lidar`, `stream.camera`) and the io_ring's `READ_SENSOR` op, which
//! read into a buffer the caller owns.

use azos_abi::cap::CapPerms;
use azos_devif::sensor::{Sample, SAMPLE_BYTES, TYPES};
use azos_devif::{outcome, Out};

use crate::handlers::{sensor_read_into, SENSOR_TYPE_CAMERA, SENSOR_TYPE_LIDAR};
use crate::khost::Caller;

/// The `Sensor` interface served for one caller.
pub struct SensorServer(pub Caller);

impl SensorServer {
    /// The sensor type the badge names.
    fn ty(&self) -> Result<u32, u32> {
        if self.0.badge < TYPES {
            Ok(self.0.badge)
        } else {
            Err(outcome::BAD_ARGUMENT)
        }
    }
}

impl azos_devif::Sensor for SensorServer {
    fn read(&self) -> Out<Sample> {
        if let Err(o) = self.0.gate::<Sample>(CapPerms::READ) {
            return o;
        }
        let ty = match self.ty() {
            Ok(t) => t,
            Err(c) => return Out::err(c),
        };
        if matches!(ty as u64, SENSOR_TYPE_LIDAR | SENSOR_TYPE_CAMERA) {
            return Out::err(outcome::UNSUPPORTED);
        }
        let mut got = None;
        sensor_read_into(ty as u64, SAMPLE_BYTES as u64, |data, meta| {
            got = Some(Sample::new(data, meta.flags as u32, meta.acq_ns));
            data.len() as i64
        });
        match got {
            Some(s) => Out::ok(s),
            // The driver has nothing yet (or the domain is not built in).
            None => Out::err(outcome::NOT_READY),
        }
    }

    fn bind_vdso(&mut self) -> Out<bool> {
        if let Err(o) = self.0.gate::<bool>(CapPerms::READ) {
            return o;
        }
        let ty = match self.ty() {
            Ok(t) => t,
            Err(c) => return Out::err(c),
        };
        match crate::vdso_notify::bind_sensor(self.0.tid, ty) {
            Ok(published) => Out::ok(published),
            Err(_) => Out::err(outcome::NOT_READY),
        }
    }
}

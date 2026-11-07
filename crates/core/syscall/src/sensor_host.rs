// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Sensor` interface the kernel hosts: one sensor instance, the badge of
//! the endpoint capability a topology row grants (`endpoint = "sensor.0"` the
//! IMU ... `"sensor.9"` the power monitor). It replaces `SYS_SENSOR_READ_TYPED`,
//! `SYS_SENSOR_READ_TS` and `SYS_VDSO_SENSOR_BIND`; the authority is the same
//! (`READ` on the sensor's capability), stated as the op class of the
//! endpoint.
//!
//! The instances are the sensor class's (`azos_drv_base::sensors`): the badge
//! names one, so a task cannot ask for a sensor it was not granted. A reading
//! is the sensor's newest published sample or its chip's read, and when it was
//! acquired (`azos_devif::Sample`: the stamp the stamped read used to carry in
//! its header). A sensor whose record does not fit a reply, the LiDAR scan and
//! the camera frame, answers `UNSUPPORTED`: a scan has no ring-3 path yet, and a
//! camera frame is the `Frame` interface's (`crate::frame_host`).

use azos_abi::cap::CapPerms;
use azos_devif::sensor::{Sample, TYPES};
use azos_devif::{outcome, Out};
use azos_drv_base::sensors::{self, ReadError};

use crate::khost::Caller;

/// May an io_ring pass serve a `Sensor` call on the instance `badge` names?
/// Its source says: a stream is a copy of what a producer published; a chip
/// says whether its read may sleep (the power monitor's I2C or ring-3 host).
/// An instance that is not registered is refused by the server without a read.
pub(crate) fn ring_served(badge: u32) -> bool {
    sensors::get(badge).is_none_or(|s| !s.may_sleep())
}

/// The `Sensor` interface served for one caller.
pub struct SensorServer(pub Caller);

impl azos_devif::Sensor for SensorServer {
    fn read(&self) -> Out<Sample> {
        if let Err(o) = self.0.gate::<Sample>(CapPerms::READ) {
            return o;
        }
        let Some(sensor) = sensors::get(self.0.badge) else {
            return Out::err(if (self.0.badge as usize) < sensors::INSTANCES { outcome::NOT_READY } else { outcome::BAD_ARGUMENT });
        };
        match sensor.read() {
            Ok(s) => Out::ok(s),
            Err(ReadError::Unsupported) => Out::err(outcome::UNSUPPORTED),
            Err(ReadError::NotReady | ReadError::Io) => Out::err(outcome::NOT_READY),
        }
    }

    fn bind_vdso(&mut self) -> Out<bool> {
        if let Err(o) = self.0.gate::<bool>(CapPerms::READ) {
            return o;
        }
        if self.0.badge >= TYPES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        // CANARY, never in a real build: the bind skips the image's answer.
        // A number whose producer is not built into this image is vacant: a bind
        // would have the timer interrupt publish a slot nothing feeds.
        if !cfg!(feature = "vdso-bind-canary") && sensors::get(self.0.badge).is_none() {
            return Out::err(outcome::NOT_READY);
        }
        match crate::vdso_notify::bind_sensor(self.0.tid, self.0.badge) {
            Ok(published) => Out::ok(published),
            Err(_) => Out::err(outcome::NOT_READY),
        }
    }
}

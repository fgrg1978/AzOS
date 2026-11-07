// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the `Sensor` interface the kernel hosts (D6 part A) --
// `crates/core/syscall/src/sensor_host.rs`. They restate the typed sensor
// read's tests (the record, the acquisition stamp, the capability check) for
// the endpoint op:
//
// * the reading is the sensor's own record with its acquisition stamp, in
//   vDSO-clock nanoseconds;
// * `READ` is the whole authority: a capability without it reads nothing, and
//   containment (a write-class refusal) does not touch a read;
// * the sensor is the badge: a badge past the class's limit is refused, one
//   no sensor holds is not ready, and the LiDAR and the camera, whose records
//   do not fit a reply, answer `UNSUPPORTED` without reading a device.
//
// **What is real here.** `SensorServer`, the class's registry and the sample
// the reply carries. **What is not.** The encoders are a chip that reads the
// pair `shims/robot` reports, with an acquisition stamp the test sets
// (`shim_set_encoder_acq`) (`harness::sensor_rig`), so the bytes asserted here
// are the chip's own, converted with the frequency the shim's timebase
// carries.

use super::harness::serial;
use crate::khost::Caller;
use crate::sensor_host::SensorServer;
use azos_robot_sensors as board;
use azos_abi::cap::CapPerms;
use azos_devif::{outcome, Sensor};

const TID: u32 = 0x7e51_0001;

fn server(badge: u32, rights: CapPerms) -> SensorServer {
    SensorServer(Caller { tid: TID, badge, rights })
}

fn encoder() -> SensorServer {
    server(board::ENCODER, CapPerms::READ)
}

/// **The reading carries the sensor's acquisition stamp in vDSO-clock
/// nanoseconds, and the record is its bytes for the same read.**
///
/// 2_500_000 ticks at the shim's `TIMER_FREQ` is the ns value
/// `azos_abi::time::ticks_to_ns` gives -- the conversion libsys's
/// `vdso_now_ns` applies to its own counter, which is what makes the stamp
/// comparable with a ring-3 clock read.
///
/// **Canary.** Make the encoder chip pass an acquisition stamp of 0 to its
/// sample: the sample reads `acq_ns == 0`.
#[test]
fn the_sample_carries_the_acquisition_stamp_and_the_sensors_record() {
    let _g = serial();
    azos_robot::shim_set_encoder(1234, -5678);
    azos_robot::shim_set_encoder_acq(2_500_000);

    let out = encoder().read();
    assert!(out.is_ok(), "code {}", out.code);
    let s = out.value;
    assert_eq!(s.len, 16);
    assert_eq!(s.flags, 0, "a counter read is a measurement, not synthetic");
    let want_ns = azos_abi::time::ticks_to_ns(2_500_000, azos_drv_sys::timebase::TIMER_FREQ);
    assert_ne!(want_ns, 0);
    assert_eq!(s.acq_ns, want_ns);
    let mut rec = [0u8; 16];
    assert_eq!(s.copy_to(&mut rec), 16);
    assert_eq!(rec[..8], 1234i64.to_le_bytes());
    assert_eq!(rec[8..], (-5678i64).to_le_bytes());
}

/// **A buffer too short for the record still gets the whole record's length
/// from the reply, and the client copies what fits**: truncation is visible.
#[test]
fn a_short_client_buffer_sees_the_full_length_and_a_prefix() {
    let _g = serial();
    azos_robot::shim_set_encoder(1, 2);
    azos_robot::shim_set_encoder_acq(7);
    let s = encoder().read().value;
    assert_eq!(s.len, 16);
    let mut short = [0xEEu8; 9];
    assert_eq!(s.copy_to(&mut short), 9);
    assert_eq!(short[..8], 1i64.to_le_bytes());
    assert_eq!(short[8], 2, "the ninth byte is the second word's low byte");
}

/// **`READ` is the authority: a capability without it is `DENIED` and reads
/// nothing**, and containment (which refuses the acting class) leaves a read
/// alone.
///
/// **Canary.** Skip the `gate` in `read`: the unheld call reads the encoders.
#[test]
fn a_read_needs_the_read_class_and_survives_containment() {
    let _g = serial();
    azos_robot::shim_set_encoder_acq(7);
    let reads = azos_robot::shim_encoder_reads();
    for rights in [CapPerms::NONE, CapPerms::WRITE] {
        let out = server(board::ENCODER, rights).read();
        assert_eq!(out.code, outcome::DENIED, "rights {rights:?}");
    }
    assert_eq!(azos_robot::shim_encoder_reads(), reads, "a refused call read the encoders");

    azos_ipc::cap::degraded_set(true);
    let out = encoder().read();
    azos_ipc::cap::degraded_set(false);
    assert!(out.is_ok(), "containment refused a read: code {}", out.code);
}

/// **A badge past the class's limit is `BAD_ARGUMENT`, one no sensor holds is
/// `NOT_READY`, a stream nothing has published into is `NOT_READY`, and the
/// LiDAR and the camera answer `UNSUPPORTED`; none of them reads a device.**
///
/// **Canary.** Answer `BAD_ARGUMENT` for every badge no sensor holds: the
/// second assertion fails.
#[test]
fn a_bad_badge_is_refused_and_a_scan_or_a_frame_is_unsupported() {
    let _g = serial();
    let reads = azos_robot::shim_encoder_reads();
    let limit = azos_drv_base::sensors::INSTANCES as u32;
    assert_eq!(server(limit, CapPerms::READ).read().code, outcome::BAD_ARGUMENT);
    assert_eq!(server(u32::MAX, CapPerms::READ).read().code, outcome::BAD_ARGUMENT);
    assert_eq!(server(limit - 1, CapPerms::READ).read().code, outcome::NOT_READY, "no sensor holds it");
    assert_eq!(server(board::LIDAR, CapPerms::READ).read().code, outcome::UNSUPPORTED);
    assert_eq!(server(board::CAMERA, CapPerms::READ).read().code, outcome::UNSUPPORTED);
    assert_eq!(azos_robot::shim_encoder_reads(), reads);
}

/// **A stream answers with its newest sample, and with nothing before the
/// first.** The IMU is a stream a task publishes into.
///
/// **Canary.** Answer the oldest retained sample instead of the newest: the
/// second assertion reads the first sample.
#[test]
fn a_stream_reads_its_newest_sample_and_is_not_ready_before_the_first() {
    let _g = serial();
    let imu = || server(board::IMU, CapPerms::READ).read();
    assert_eq!(imu().code, outcome::NOT_READY, "nothing published yet");
    let mut tx = board::IMU_SENSOR.producer().expect("the test is the producer");
    tx.publish(board::IMU_SENSOR.pack(&[1, 2, 3, 4, 5, 6], 0, 111));
    tx.publish(board::IMU_SENSOR.pack(&[7, 8, 9, 10, 11, 12], 0, 222));
    let s = imu().value;
    assert_eq!((s.len, s.acq_ns), (24, 222));
    let mut rec = [0u8; 24];
    s.copy_to(&mut rec);
    assert_eq!(rec[..4], 7i32.to_le_bytes());
}

/// **An unknown acquisition time stays 0**, the "never fresh" value, rather
/// than being converted into a small nonzero number.
#[test]
fn an_unknown_stamp_is_reported_as_zero() {
    let _g = serial();
    azos_robot::shim_set_encoder_acq(0);
    let s = encoder().read().value;
    assert_eq!(s.acq_ns, 0);
    assert!(!azos_abi::sensor_sample::sample_is_fresh_ns(s.acq_ns, u64::MAX / 2, u64::MAX));
}

/// **Binding to the vDSO page is gated like a read**: no `READ`, `DENIED`; a
/// bad type, `BAD_ARGUMENT`; neither reaches the page.
#[test]
fn a_vdso_bind_is_gated_like_a_read() {
    let _g = serial();
    assert_eq!(server(board::ENCODER, CapPerms::WRITE).bind_vdso().code, outcome::DENIED);
    assert_eq!(server(azos_devif::sensor::TYPES, CapPerms::READ).bind_vdso().code, outcome::BAD_ARGUMENT);
}

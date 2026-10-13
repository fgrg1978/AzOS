// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the `Sensor` interface the kernel hosts (D6 part A) --
// `crates/core/syscall/src/sensor_host.rs`. They restate the typed sensor
// read's tests (the record, the acquisition stamp, the capability check) for
// the endpoint op:
//
// * the reading is the arm's own record with the arm's acquisition stamp,
//   converted to vDSO-clock nanoseconds;
// * `READ` is the whole authority: a capability without it reads nothing, and
//   containment (a write-class refusal) does not touch a read;
// * the sensor type is the badge: a badge past the last type is refused, and
//   the LiDAR and the camera, whose records do not fit a reply, answer
//   `UNSUPPORTED` without reading the device.
//
// **What is real here.** `SensorServer`, the shared `sensor_read_into` arm
// table and the sample the reply carries. **What is not.** The sensor is the
// encoder pair `shims/robot` reports, with an acquisition stamp the test sets
// (`shim_set_encoder_acq`): the encoder arm takes its stamp from
// `encoder_read_stamped`, so the bytes asserted here are the arm's own,
// converted with the frequency the shim's timebase carries.

use super::harness::serial;
use crate::khost::Caller;
use crate::sensor_host::SensorServer;
use azos_abi::cap::CapPerms;
use azos_devif::{outcome, Sensor};

const TID: u32 = 0x7e51_0001;

fn server(badge: u32, rights: CapPerms) -> SensorServer {
    SensorServer(Caller { tid: TID, badge, rights })
}

fn encoder() -> SensorServer {
    server(SENSOR_TYPE_ENCODER as u32, CapPerms::READ)
}

/// **The reading carries the arm's acquisition stamp, converted to vDSO-clock
/// nanoseconds, and the record is the arm's bytes for the same read.**
///
/// 2_500_000 ticks at the shim's `TIMER_FREQ` is the ns value
/// `azos_abi::time::ticks_to_ns` gives -- the conversion libsys's
/// `vdso_now_ns` applies to its own counter, which is what makes the stamp
/// comparable with a ring-3 clock read.
///
/// **Canary.** Make the encoder arm pass `SampleMeta::at_ticks(0, 0)`: the
/// sample reads `acq_ns == 0`. Build the sample with `flags: 0` from a fixed
/// literal instead of `meta.flags`: the synthetic flag of the rangefinder arm
/// is lost (see the next test's sibling in the drivers suite).
#[test]
fn the_sample_carries_the_acquisition_stamp_and_the_arms_record() {
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
        let out = server(SENSOR_TYPE_ENCODER as u32, rights).read();
        assert_eq!(out.code, outcome::DENIED, "rights {rights:?}");
    }
    assert_eq!(azos_robot::shim_encoder_reads(), reads, "a refused call read the encoders");

    azos_ipc::cap::degraded_set(true);
    let out = encoder().read();
    azos_ipc::cap::degraded_set(false);
    assert!(out.is_ok(), "containment refused a read: code {}", out.code);
}

/// **A badge past the last sensor type is `BAD_ARGUMENT`, and the LiDAR and
/// the camera answer `UNSUPPORTED`; none of them reads a device.**
#[test]
fn a_bad_type_is_refused_and_a_scan_or_a_frame_is_unsupported() {
    let _g = serial();
    let reads = azos_robot::shim_encoder_reads();
    assert_eq!(server(azos_devif::sensor::TYPES, CapPerms::READ).read().code, outcome::BAD_ARGUMENT);
    assert_eq!(server(u32::MAX, CapPerms::READ).read().code, outcome::BAD_ARGUMENT);
    assert_eq!(server(SENSOR_TYPE_LIDAR as u32, CapPerms::READ).read().code, outcome::UNSUPPORTED);
    assert_eq!(server(SENSOR_TYPE_CAMERA as u32, CapPerms::READ).read().code, outcome::UNSUPPORTED);
    assert_eq!(azos_robot::shim_encoder_reads(), reads);
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
    assert_eq!(server(SENSOR_TYPE_ENCODER as u32, CapPerms::WRITE).bind_vdso().code, outcome::DENIED);
    assert_eq!(server(azos_devif::sensor::TYPES, CapPerms::READ).bind_vdso().code, outcome::BAD_ARGUMENT);
}

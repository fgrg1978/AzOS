// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Brain-protocol wire-format microbenchmarks.
//!
//! These are the encode/decode primitives on the kernel↔brain TCP hot
//! path.  `parse_packet` is also `#[wcet(50_us)]`-instrumented; the
//! synthetic number here is the contention-free baseline to compare the
//! runtime distribution against.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_behavior::brain_protocol as bp;

/// CRC-8/MAXIM (poly 0x31) over a 64-byte sensor payload.  Pure bit-twiddle
/// loop — 8 shifts per byte; the integrity-check cost on every frame.
pub fn bench_crc8_64B(iters: u64) -> BenchResult {
    let data = [0x42u8; bp::SENSOR_PAYLOAD_SIZE];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(bp::crc8(&data));
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `build_packet` — frame a 64-byte payload (header + payload copy + CRC).
pub fn bench_build_packet_64B(iters: u64) -> BenchResult {
    let payload = [0x42u8; bp::SENSOR_PAYLOAD_SIZE];
    // header(5) + payload + crc(1)
    let mut out = [0u8; bp::SENSOR_PAYLOAD_SIZE + 6];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = bp::build_packet(bp::PKT_SENSOR, &payload, &mut out);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `parse_packet` — validate MAGIC + length + CRC over a pre-built frame.
/// Pre-frame outside the timed loop so we measure parse, not build.
pub fn bench_parse_packet_64B(iters: u64) -> BenchResult {
    let payload = [0x42u8; bp::SENSOR_PAYLOAD_SIZE];
    let mut frame = [0u8; bp::SENSOR_PAYLOAD_SIZE + 6];
    let n = bp::build_packet(bp::PKT_SENSOR, &payload, &mut frame);

    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(bp::parse_packet(&frame[..n]));
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `encode_sensor_packet` — fill the 64-byte wheeled sensor struct.  Pure
/// little-endian scalar writes; the per-frame serialise cost robot-side.
pub fn bench_encode_sensor_packet(iters: u64) -> BenchResult {
    let mut buf = [0u8; bp::SENSOR_PAYLOAD_SIZE];

    let start = read_cycles();
    for _ in 0..iters {
        bp::encode_sensor_packet(
            &mut buf,
            0,            // timestamp_ms
            [0i32; 3],    // accel_mg
            [0i32; 3],    // gyro_mdps
            0,            // battery_mv
            0, 0,         // odom dist / hdg
            0, 0,         // encoder l / r
            0, 0,         // range front / right
            0,            // sensor_flags
        );
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("protocol.crc8_64B",            &best_of(|| bench_crc8_64B(iters)));            n += 1;
    report("protocol.build_packet_64B",    &best_of(|| bench_build_packet_64B(iters)));    n += 1;
    report("protocol.parse_packet_64B",    &best_of(|| bench_parse_packet_64B(iters)));    n += 1;
    report("protocol.encode_sensor_packet", &best_of(|| bench_encode_sensor_packet(iters))); n += 1;
    n
}

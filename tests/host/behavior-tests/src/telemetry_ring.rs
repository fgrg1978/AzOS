// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The actuation telemetry is a ring of the record region (`azos_records`),
//! beside the kernel log's and the decisions', and not on the flight
//! recorder's ring. These tests attach a region of the build's own layout, so
//! they need Kconfig `KLOG` on (the gate's config has it).

use super::flight_recorder::begin;
use super::logger::*;
use azos_records::record::{Envelope, Merge, Read, Region, Step};
use azos_records::{reader, SOURCE_TELEMETRY};
use std::sync::OnceLock;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct Line([u8; 64]);

/// The region, attached once for the process: its base and length.
fn region() -> (usize, usize) {
    static REGION: OnceLock<(usize, usize)> = OnceLock::new();
    *REGION.get_or_init(|| {
        let bytes = azos_records::REGION_BYTES;
        let mem: &'static mut [Line] = Box::leak(vec![Line([0; 64]); bytes.div_ceil(64)].into_boxed_slice());
        let base = mem.as_mut_ptr() as *mut u8;
        // SAFETY: zeroed, 64-aligned, leaked (never freed), used by nothing
        // else, and no producer runs before this returns.
        let h = unsafe { azos_records::attach(base, bytes, 10_000_000) };
        assert!(h.is_some(), "the build keeps no record region (Kconfig KLOG is off)");
        (base as usize, bytes)
    })
}

/// The recorder's lock, a region, and this thread's telemetry going to its
/// ring in the region (the other suites' encoders feed the flight recorder's).
struct Guard {
    _g: super::flight_recorder::RecorderGuard,
}

fn start() -> Guard {
    let g = begin(0x0A0B_0C01);
    region();
    telemetry_on_ring_for_test(false);
    Guard { _g: g }
}

impl Drop for Guard {
    fn drop(&mut self) {
        telemetry_on_ring_for_test(true);
    }
}

fn ring_head() -> u64 {
    reader(SOURCE_TELEMETRY).expect("the region keeps a telemetry ring").head()
}

/// Every record from `cursor` on, as the one reader of the ring sees them.
fn read_from(mut cursor: u64) -> Vec<(Envelope, [u8; 24])> {
    let r = reader(SOURCE_TELEMETRY).unwrap();
    let mut out = Vec::new();
    loop {
        let (mut env, mut p) = (Envelope::default(), [0u8; 24]);
        match r.read(&mut cursor, &mut env, &mut p) {
            Read::Record => out.push((env, p)),
            Read::Empty => return out,
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Every encoder lands its arguments where the format says, behind the
/// envelope: the kind, the payload length, the source and the sequence.
/// **Canary** `telemetry-ring-canary`: the records go to the flight recorder's
/// ring and the telemetry ring reads empty (red).
#[test]
fn each_encoder_lands_its_fields_in_the_telemetry_ring() {
    let _g = start();
    let from = ring_head();
    log_sensor_snapshot(0x1234, -300, 0x0000_ABCD, -12345);
    log_actuator_cmd(3, 1, 50, 0, 0);
    log_mode_change(1, 2);
    log_skill_start(0x0BAD);
    log_skill_end(0x0BAD, 0x33);
    log_waypoint(-1000, 2000, 7, 0x5A);
    log_error(0x7A, 0xBEEF, 0xDEAD_C0DE);
    let got = read_from(from);
    assert_eq!(got.len(), 7, "one record per encoder");
    for (i, (env, _)) in got.iter().enumerate() {
        assert_eq!((env.seq, env.source, env.len), (from + i as u64, SOURCE_TELEMETRY, LOG_PAYLOAD_BYTES as u16));
    }
    let kinds: Vec<u16> = got.iter().map(|(e, _)| e.kind).collect();
    assert_eq!(
        kinds,
        [LOG_EVT_SENSOR_SNAPSHOT, LOG_EVT_ACTUATOR_CMD, LOG_EVT_MODE_CHANGE, LOG_EVT_SKILL_START, LOG_EVT_SKILL_END, LOG_EVT_WAYPOINT, LOG_EVT_ERROR]
            .map(u16::from)
    );
    let p = |i: usize| &got[i].1;
    assert_eq!(u16::from_le_bytes([p(0)[0], p(0)[1]]), 0x1234);
    assert_eq!(i16::from_le_bytes([p(0)[2], p(0)[3]]), -300);
    assert_eq!(u32::from_le_bytes(p(0)[4..8].try_into().unwrap()), 0x0000_ABCD);
    assert_eq!(i32::from_le_bytes(p(0)[8..12].try_into().unwrap()), -12345);
    assert_eq!((p(1)[0], i16::from_le_bytes([p(1)[2], p(1)[3]]), i16::from_le_bytes([p(1)[4], p(1)[5]])), (3, 1, 50));
    assert_eq!((p(2)[0], p(2)[1]), (1, 2));
    assert_eq!(u16::from_le_bytes([p(3)[0], p(3)[1]]), 0x0BAD);
    assert_eq!((u16::from_le_bytes([p(4)[0], p(4)[1]]), p(4)[2]), (0x0BAD, 0x33));
    assert_eq!(i32::from_le_bytes(p(5)[0..4].try_into().unwrap()), -1000);
    assert_eq!(i32::from_le_bytes(p(5)[4..8].try_into().unwrap()), 2000);
    assert_eq!((u16::from_le_bytes([p(5)[8], p(5)[9]]), p(5)[10]), (7, 0x5A));
    assert_eq!((p(6)[0], u16::from_le_bytes([p(6)[1], p(6)[2]]), p(6)[3]), (0x7A, 0xBEEF, 0));
    assert_eq!(u32::from_le_bytes(p(6)[4..8].try_into().unwrap()), 0xDEAD_C0DE);
    assert!(got.windows(2).all(|w| w[0].0.ts <= w[1].0.ts), "stamped in order");
}

/// Telemetry needs no flight recorder: with the logger off (no volume) the
/// ring still takes the record, which `logd` reads.
#[test]
fn telemetry_is_recorded_with_the_flight_recorder_off() {
    let _g = start();
    logger_shutdown();
    let from = ring_head();
    log_error(1, 2, 3);
    assert_eq!(read_from(from).len(), 1);
}

/// **The safety ring is not telemetry's.** A pending latch record sits at the
/// recorder's ring while many times its capacity of telemetry is logged: the
/// ring's length, its drop count and the latch's announcement are what they
/// were, because none of it touched the ring. **Canary** `telemetry-ring-canary`:
/// the telemetry takes the ring, evicts and is counted (red).
#[test]
fn a_telemetry_flood_leaves_the_flight_recorders_ring_alone() {
    let _g = start();
    logger_init().expect("mount succeeds");
    logger_set_rt_probe(rt_yes);
    let r = log_safety_violation_durable(SAFETY_ESTOP, 2, 30);
    assert_eq!(r, Err(LogStorageError::Deferred));
    let (len0, dropped0) = (logger_ring_len(), logger_analytics().events_dropped);
    for i in 0..(3 * LOG_RING_CAPACITY) as i32 {
        log_waypoint(i, -i, i as u16, 0x77);
        log_actuator_cmd(1, 2, 3, 0, 0);
    }
    logger_set_rt_probe(rt_no);
    assert_eq!(logger_ring_len(), len0, "telemetry took slots of the safety ring");
    assert_eq!(logger_analytics().events_dropped, dropped0, "telemetry evicted a record");
    logger_flusher_pass();
    let recs = super::flight_recorder::decode_file(0);
    assert!(recs.iter().any(|r| r.kind == LOG_EVT_SAFETY_VIOLATION && r.payload[0] == SAFETY_ESTOP && r.payload[1] == 2));
    assert!(recs.iter().all(|r| r.kind == LOG_EVT_SAFETY_VIOLATION), "telemetry reached the flight recorder's file");
    logger_shutdown();
}

fn rt_yes() -> bool {
    true
}
fn rt_no() -> bool {
    false
}

/// A full telemetry ring overwrites its oldest record, never blocks the
/// producer, and tells the reader how many it lost.
#[test]
fn a_full_telemetry_ring_overwrites_its_oldest_and_the_reader_is_told() {
    let _g = start();
    let r = reader(SOURCE_TELEMETRY).unwrap();
    let entries = r.entries();
    let from = r.head();
    for i in 0..3 * entries {
        log_mode_change(i as u8, 0);
    }
    let mut cursor = from;
    let (mut env, mut p) = (Envelope::default(), [0u8; 24]);
    let Read::Lost(n) = r.read(&mut cursor, &mut env, &mut p) else { panic!("a reader two laps behind got no loss") };
    assert_eq!(n, 2 * entries, "the records the ring lapped");
    let mut kept = 0;
    while r.read(&mut cursor, &mut env, &mut p) == Read::Record {
        kept += 1;
    }
    assert_eq!(kept, entries);
}

/// **A record with a stale sequence** (written under the sequence before the
/// one it took) is dropped by the one reader and counted, never handed on as
/// the record its slot should hold.
#[test]
fn a_telemetry_record_with_a_stale_sequence_is_dropped_and_counted() {
    let _g = start();
    let (base, bytes) = region();
    // SAFETY: the region `region()` attached, leaked and readable for `bytes`.
    let reg = unsafe { Region::open(base as *const u8, bytes) }.expect("a record region");
    let ring = (0..reg.rings()).find(|&i| reg.ring(i).unwrap().source() == SOURCE_TELEMETRY).unwrap();
    let mut m = Merge::<288>::oldest(reg);
    m.seek(ring, ring_head());
    let w = azos_records::writer(SOURCE_TELEMETRY).unwrap();
    let h = azos_records::Head { ts: 1, clock: azos_records::CLOCK_TIMEBASE, kind: 4, len: 2, cpu: 0, flags: 0 };
    w.publish_stale(&h, |p| p.bytes(0, &[1, 2]));
    log_mode_change(3, 4);
    let (mut env, mut buf) = (Envelope::default(), [0u8; 288]);
    let mut kinds = Vec::new();
    loop {
        match m.next(&mut env, &mut buf) {
            Step::Record { ring: r } if r == ring => kinds.push(env.kind),
            Step::Record { .. } => {}
            Step::Stale { ring: r } => assert_eq!(r, ring),
            Step::Empty => break,
            s => panic!("unexpected {s:?}"),
        }
    }
    assert_eq!(m.stale(ring), 1, "the stale record is counted");
    assert_eq!(kinds, [u16::from(LOG_EVT_MODE_CHANGE)], "and only the good one is handed on");
}

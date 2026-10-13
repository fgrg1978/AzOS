// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel sensor streams (wave 11, SHMRING): `stream.lidar` and
//! `stream.camera`, consumed from the `Cap<Shm>` this task's topology row is
//! seeded with.
//!
//! Owner decision 2026-10-03: holding that capability is the authority to
//! read the stream — no per-frame capability check. Without it (the streams'
//! Kconfig symbols are off by default) the lookup misses, and this prints
//! which path answered instead: for a LiDAR scan the io_ring's `READ_SENSOR`
//! op (the fallback the gate's canary row reads), for a camera frame (which
//! does not fit the ring's data buffer) the `sensor` endpoint, which answers
//! `UNSUPPORTED`: the stream is the only way to read a frame.
//!
//! LiDAR checks, against the QEMU feeder (Kconfig `LIDAR_SIM`, a revolution
//! every 100 ms whose point `i` of revolution `r` has distance
//! `(r mod 64) << 10 | i`):
//! 1. doorbell drain: 20 scans intact (1440 bytes, every point's index, one
//!    revolution per scan), in order (consecutive `seq`, revolution + 1);
//! 2. suppression: the consumer polls (sleeps 450 ms without announcing) and
//!    drains in batches — the producer rings NO doorbell for those scans;
//! 3. the producer never blocks: a 2.5 s stall fills the 16-slot ring, the
//!    producer drops (drop-newest, counted) and keeps its 100 ms cadence; the
//!    gap in `seq` after the drain equals the drops it counted.

use azos_libsys as sys;
use sys::{RingSleep, RingStep, SpscBytes};

use crate::{report, Line};

const SENSOR_LIDAR: u32 = 6;
const SENSOR_CAMERA: u32 = 8;
/// LiDAR record: 360 points of 4 bytes.
const SCAN_BYTES: usize = 1440;
/// The upper bound of a stream mapping (`MAX_MEMOBJ_PAGES` pages).
const MAP_MAX: usize = 64 * sys::PAGE_SIZE;

fn now_ms() -> u64 { sys::vdso_now_ns() / 1_000_000 }

/// The latest scan through the io_ring's `READ_SENSOR` op: the bytes read
/// (the ring's data buffer holds a whole scan), or a negative error.
fn ring_scan(ty: u32) -> isize {
    let mut out = [0u8; 8];
    let cap = sys::ioring_create_typed(&mut out);
    if cap <= 0 {
        return cap;
    }
    let cap = cap as u32;
    let Ok(ring) = sys::ioring::Ring::open(cap, out) else {
        sys::ioring_destroy_typed(cap);
        return -1;
    };
    ring.push(sys::ioring::OP_READ_SENSOR, ty, 0, SCAN_BYTES as u32, 1);
    let sub = sys::ioring_submit_typed(cap);
    let r = if sub == 1 {
        ring.pop().map_or(-3, |(_, result, _)| result as isize)
    } else {
        sub
    };
    sys::ioring_destroy_typed(cap);
    r
}

/// What the `sensor` endpoint of `ty` answers: the record length, or the
/// negated outcome (`-5`, `UNSUPPORTED`, for a scan or a frame, which travel on
/// their stream), `-1000` when the topology grants no such endpoint.
fn sensor_answer(ty: u32, buf: &mut [u8]) -> isize {
    match sys::dev::lookup(sys::dev::key::SENSOR, ty) {
        None => -1000,
        Some(ep) => match sys::dev::sensor_read(ep, buf) {
            Ok(smp) => smp.len as isize,
            Err(c) => -(c as isize),
        },
    }
}

/// Pop one item, sleeping on the doorbell while the ring is empty, for at
/// most until `deadline_ms`. `(info, waits)`; `None` on the deadline.
fn pop_waiting(r: &SpscBytes, out: &mut [u8], deadline_ms: u64, waits: &mut u64) -> Option<sys::SlotInfo> {
    loop {
        match r.try_pop(out) {
            (RingStep::Blocked, _) => {}
            (_, info) => return Some(info),
        }
        if now_ms() >= deadline_ms {
            return None;
        }
        if let RingSleep::Wait { addr, expected } = r.consumer_sleep() {
            *waits += 1;
            let _ = sys::notify_wait(addr, expected, 200_000_000);
            r.consumer_woke();
        }
    }
}

/// Is `scan` one whole synthetic revolution? Its revolution (mod 64).
fn scan_rev(scan: &[u8], len: u32) -> Option<u32> {
    if len as usize != SCAN_BYTES {
        return None;
    }
    let mut rev = None;
    for i in 0..360 {
        let d = u16::from_le_bytes([scan[i * 4 + 2], scan[i * 4 + 3]]) as u32;
        if d & 0x3FF != i as u32 {
            return None;
        }
        match rev {
            None => rev = Some(d >> 10),
            Some(r) if r != d >> 10 => return None,
            _ => {}
        }
    }
    rev
}

fn map(cap: isize, name: &[u8]) -> Option<SpscBytes> {
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        report(name, false, va);
        return None;
    }
    let r = SpscBytes::from_header(va as usize, MAP_MAX);
    report(name, r.is_some(), va.min(1));
    r
}

pub fn run() {
    lidar();
    camera();
}

fn lidar() {
    let cap = sys::cap_lookup(sys::ty::SHM.raw(), azos_abi::cap::SHM_STREAM_LIDAR);
    if cap < 0 {
        let n = ring_scan(SENSOR_LIDAR);
        Line::new()
            .s(b"[CAPTEST] stream lidar: off (no Cap<Shm>, lookup rc=")
            .i(cap)
            .s(b"), the io_ring READ_SENSOR path answered ")
            .i(n)
            .flush();
        return;
    }
    let Some(r) = map(cap, b"stream lidar: map Cap<Shm> and read the ring's geometry") else { return };
    let mut scan = [0u8; SCAN_BYTES];

    // 1. Doorbell drain.
    let (mut waits, mut bad, mut n) = (0u64, 0u64, 0u64);
    let (mut last_seq, mut last_rev) = (None::<u32>, 0u32);
    let w0 = r.wakes();
    let end = now_ms() + 10_000;
    while n < 20 {
        let Some(info) = pop_waiting(&r, &mut scan, end, &mut waits) else { break };
        match scan_rev(&scan, info.len) {
            Some(rev) => {
                if let Some(s) = last_seq {
                    if info.seq != s.wrapping_add(1) || rev != (last_rev + 1) & 0x3F { bad += 1; }
                }
                last_seq = Some(info.seq);
                last_rev = rev;
            }
            None => bad += 1,
        }
        n += 1;
    }
    let bells = r.wakes().wrapping_sub(w0) as u64;
    Line::new()
        .s(b"[CAPTEST] stream lidar: doorbell drain ")
        .i(n as isize)
        .s(b" scans, consumer waits=")
        .i(waits as isize)
        .s(b" producer doorbells=")
        .i(bells as isize)
        .flush();
    report(b"stream lidar: 20 scans intact and in order (seq + 1, revolution + 1, every point)",
           n == 20 && bad == 0, bad as isize);

    // 2. Suppression: poll without announcing a sleep, drain in batches.
    let w1 = r.wakes();
    let mut batches = [0u64; 4];
    let mut pbad = 0u64;
    for b in batches.iter_mut() {
        sys::sleep(450);
        while let (RingStep::Done | RingStep::DoneWake { .. }, info) = r.try_pop(&mut scan) {
            if scan_rev(&scan, info.len).is_none() { pbad += 1; }
            if let Some(s) = last_seq {
                if info.seq != s.wrapping_add(1) { pbad += 1; }
            }
            last_seq = Some(info.seq);
            *b += 1;
        }
    }
    let pbells = r.wakes().wrapping_sub(w1) as u64;
    let mut l = Line::new();
    l.s(b"[CAPTEST] stream lidar: polled drain, batches of ");
    for (i, b) in batches.iter().enumerate() {
        if i > 0 { l.s(b"/"); }
        l.i(*b as isize);
    }
    l.s(b" scans, producer doorbells=").i(pbells as isize).flush();
    report(b"stream lidar: no doorbell while the consumer never said it sleeps",
           pbells == 0, pbells as isize);
    report(b"stream lidar: every batch drained more than one scan, intact and in order",
           batches.iter().all(|&b| b >= 2) && pbad == 0, pbad as isize);

    // 3. The producer never blocks on a stalled consumer.
    let d0 = r.drops();
    sys::sleep(2500);
    let d1 = r.drops();
    let mut acq = [0u64; 16];
    let mut seqs = [0u32; 16];
    let mut got = 0usize;
    while got < 16 {
        match r.try_pop(&mut scan) {
            (RingStep::Blocked, _) => break,
            (_, info) => {
                acq[got] = info.acq_ns;
                seqs[got] = info.seq;
                got += 1;
            }
        }
    }
    let mut w = 0u64;
    let next = pop_waiting(&r, &mut scan, now_ms() + 1_000, &mut w);
    let dropped = d1.wrapping_sub(d0);
    let gap = next.map_or(0, |i| i.seq.wrapping_sub(seqs[got.max(1) - 1]).wrapping_sub(1));
    let max_step_ms = (1..got).map(|i| acq[i].wrapping_sub(acq[i - 1]) / 1_000_000).max().unwrap_or(0);
    Line::new()
        .s(b"[CAPTEST] stream lidar: 2500 ms stall: ring held ")
        .i(got as u64 as isize)
        .s(b" scans, producer dropped ")
        .i(dropped as u64 as isize)
        .s(b" (seq gap ")
        .i(gap as u64 as isize)
        .s(b"), largest step between held scans ")
        .i(max_step_ms as isize)
        .s(b" ms")
        .flush();
    report(b"stream lidar: a stalled consumer costs drops, never a blocked producer (full ring held, drops counted = seq gap, cadence kept)",
           got == r.cap as usize && dropped >= 5 && next.is_some() && gap >= dropped && max_step_ms <= 300,
           dropped as isize);
}

fn camera() {
    let cap = sys::cap_lookup(sys::ty::SHM.raw(), azos_abi::cap::SHM_STREAM_CAMERA);
    if cap < 0 {
        let mut buf = [0u8; 24];
        let n = sensor_answer(SENSOR_CAMERA, &mut buf);
        Line::new()
            .s(b"[CAPTEST] stream camera: off (no Cap<Shm>, lookup rc=")
            .i(cap)
            .s(b"), the sensor endpoint answered ")
            .i(n)
            .flush();
        return;
    }
    let Some(r) = map(cap, b"stream camera: map Cap<Shm> and read the ring's geometry") else { return };
    static mut FRAME: [u8; 19_264] = [0; 19_264];
    // SAFETY: only this function uses FRAME.
    let frame = unsafe { &mut *core::ptr::addr_of_mut!(FRAME) };
    let (mut waits, mut bad, mut n, mut last) = (0u64, 0u64, 0u64, None::<u32>);
    let w0 = r.wakes();
    let end = now_ms() + 10_000;
    while n < 10 {
        let Some(info) = pop_waiting(&r, frame, end, &mut waits) else { break };
        let len = info.len as usize;
        let jpeg = len >= 4 && frame[0] == 0xFF && frame[1] == 0xD8
            && frame[len - 2] == 0xFF && frame[len - 1] == 0xD9;
        if !jpeg || last.is_some_and(|s| info.seq != s.wrapping_add(1)) { bad += 1; }
        last = Some(info.seq);
        n += 1;
    }
    Line::new()
        .s(b"[CAPTEST] stream camera: ")
        .i(n as isize)
        .s(b" frames, consumer waits=")
        .i(waits as isize)
        .s(b" producer doorbells=")
        .i(r.wakes().wrapping_sub(w0) as u64 as isize)
        .flush();
    report(b"stream camera: 10 JPEG frames (SOI..EOI) in order", n == 10 && bad == 0, bad as isize);
}

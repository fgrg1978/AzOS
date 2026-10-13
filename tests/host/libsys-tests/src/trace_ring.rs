// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_spsc::trace`: the kernel tracer's per-CPU record rings (wave 15).
//! Wrap, drops, the overwrite policy's lost-record detection, a hostile
//! tail, the header check, and two concurrent producer/consumer models.

use azos_spsc::trace::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A 64-byte aligned heap region.
struct Region {
    mem: Vec<u64>,
}

impl Region {
    fn new(ncpu: u32, entries: u32, policy: u32) -> Region {
        let bytes = region_bytes(ncpu, entries);
        // u64 words, plus one line of slack to align to 64.
        let mut r = Region { mem: vec![0u64; bytes / 8 + 8] };
        let base = r.base();
        region_init(base, ncpu, entries, policy, 10_000_000, TS_TIMEBASE, 0x7f);
        let _ = &mut r;
        r
    }
    fn base(&self) -> usize {
        (self.mem.as_ptr() as usize + 63) & !63
    }
}

fn geom(r: &Region, ncpu: u32, entries: u32) -> TraceGeometry {
    TraceGeometry::from_header(r.base(), region_bytes(ncpu, entries)).expect("header")
}

fn args(i: u32) -> [u32; 4] {
    [i, !i, i.wrapping_mul(3), 0xA5A5_0000 | (i & 0xffff)]
}

#[test]
fn records_arrive_intact_in_order_across_many_wraps() {
    let r = Region::new(1, 8, POLICY_DROP);
    let g = geom(&r, 1, 8);
    assert_eq!((g.ncpu, g.entries, g.policy, g.ts_hz, g.classes), (1, 8, POLICY_DROP, 10_000_000, 0x7f));
    let mut p = TraceProducer::attach(r.base(), 0, 8);
    let mut c = TraceConsumer::new(r.base(), &g, 0);
    let mut next = 0u32;
    // 1000 records through an 8-slot ring: 125 wraps, batches of 1..=8.
    for round in 0..200u32 {
        let n = 1 + round % 8;
        for _ in 0..n {
            assert!(p.push::<false>(next as u64 * 10, 0x0201, args(next)));
            next += 1;
        }
        for _ in 0..n {
            match c.pop() {
                Pop::Rec(rec) => {
                    assert_eq!(rec.ts, rec.seq as u64 * 10);
                    assert_eq!((rec.event, rec.cpu, rec.args), (0x0201, 0, args(rec.seq)));
                }
                other => panic!("expected a record, got {other:?}"),
            }
        }
        assert_eq!(c.pop(), Pop::Empty);
        c.release();
    }
    assert_eq!((p.drops(), c.drops()), (0, 0));
    assert_eq!(c.tail(), next);
}

#[test]
fn a_full_ring_drops_the_newest_and_counts_it() {
    let r = Region::new(2, 4, POLICY_DROP);
    let g = geom(&r, 2, 4);
    let mut p = TraceProducer::attach(r.base(), 1, 4);
    for i in 0..4 {
        assert!(p.push::<false>(i, 1, args(i as u32)));
    }
    // Full: three refused, counted in the shared word.
    for i in 4..7 {
        assert!(!p.push::<false>(i, 1, args(i as u32)));
    }
    let mut c = TraceConsumer::new(r.base(), &g, 1);
    assert_eq!(c.drops(), 3);
    // The four oldest survive, unchanged.
    for i in 0..4u32 {
        assert!(matches!(c.pop(), Pop::Rec(rec) if rec.seq == i && rec.args == args(i)));
    }
    assert_eq!(c.pop(), Pop::Empty);
    // Until released, the producer still sees a full ring.
    assert!(!p.push::<false>(9, 1, args(9)));
    c.release();
    assert!(p.push::<false>(10, 1, args(10)));
    assert!(matches!(c.pop(), Pop::Rec(rec) if rec.seq == 4 && rec.ts == 10));
    // Ring 0 untouched.
    let c0 = TraceConsumer::new(r.base(), &g, 0);
    assert_eq!(c0.drops(), 0);
}

#[test]
fn overwrite_keeps_the_newest_and_the_reader_counts_what_it_lost() {
    let r = Region::new(1, 4, POLICY_OVERWRITE);
    let g = geom(&r, 1, 4);
    let mut p = TraceProducer::attach(r.base(), 0, 4);
    for i in 0..10u32 {
        assert!(p.push::<true>(i as u64, 2, args(i)));
    }
    // 10 written into 4 slots with no reader: 6 overwritten unread.
    let mut c = TraceConsumer::new(r.base(), &g, 0);
    assert_eq!(c.drops(), 6);
    // The reader learns the lap one slot at a time (slot 0 says index 8 is
    // there, so at most 5..=8 can survive; slot 1 then says 9): what it
    // counts lost adds up to the 6 overwritten, each index once.
    let mut lost = 0;
    let first = loop {
        match c.pop() {
            Pop::Lost(n) => lost += n,
            Pop::Rec(rec) => break rec,
            Pop::Empty => panic!("empty before the survivors"),
        }
    };
    assert_eq!((lost, first.seq, first.args), (6, 6, args(6)));
    for i in 7..10u32 {
        assert!(matches!(c.pop(), Pop::Rec(rec) if rec.seq == i && rec.args == args(i)), "record {i}");
    }
    assert_eq!(c.pop(), Pop::Empty);
}

#[test]
fn an_in_progress_slot_reads_as_empty_or_lapped_never_as_a_record() {
    let r = Region::new(1, 4, POLICY_OVERWRITE);
    let g = geom(&r, 1, 4);
    let base = r.base();
    let slot0_seq = base + HDR_BYTES + RING_HDR_BYTES + 8;
    let mut c = TraceConsumer::new(base, &g, 0);
    // Record 0 being written (marker 0 ^ 1): not readable yet.
    unsafe { core::ptr::write_volatile(slot0_seq as *mut u32, 1) };
    assert_eq!(c.pop(), Pop::Empty);
    // Record 4 (the next lap) being written over the unread record 0: lapped.
    unsafe { core::ptr::write_volatile(slot0_seq as *mut u32, 4 ^ 1) };
    assert_eq!(c.pop(), Pop::Lost(1));
    assert_eq!(c.tail(), 1);
}

#[test]
fn a_garbage_tail_costs_drops_never_an_out_of_ring_write() {
    let r = Region::new(1, 4, POLICY_DROP);
    let base = r.base();
    let tail = base + HDR_BYTES + RING_TAIL_OFF;
    let mut p = TraceProducer::attach(base, 0, 4);
    for i in 0..4 {
        p.push::<false>(i, 1, args(i as u32));
    }
    let before = r.mem.clone();
    for bad in [u32::MAX, 0x8000_0000, 1000, 5] {
        unsafe { core::ptr::write_volatile(tail as *mut u32, bad) };
        assert!(!p.push::<false>(99, 1, args(99)), "tail {bad:#x} read as room");
    }
    // Only the tail word and the drops word changed.
    let drops = base + HDR_BYTES + RING_DROPS_OFF;
    for (i, (a, b)) in before.iter().zip(r.mem.iter()).enumerate() {
        let addr = r.mem.as_ptr() as usize + i * 8;
        if addr == tail & !7 || addr == drops & !7 {
            continue;
        }
        assert_eq!(a, b, "word at {:#x} changed", addr - base);
    }
}

#[test]
fn the_header_check_refuses_a_bad_geometry() {
    let r = Region::new(2, 8, POLICY_DROP);
    let base = r.base();
    let bytes = region_bytes(2, 8);
    assert!(TraceGeometry::from_header(base, bytes).is_some());
    assert!(TraceGeometry::from_header(base, bytes - 1).is_none(), "a short mapping was accepted");
    let entries = base + HDR_ENTRIES;
    unsafe { core::ptr::write_volatile(entries as *mut u32, 6) };
    assert!(TraceGeometry::from_header(base, bytes).is_none(), "6 entries accepted");
    unsafe { core::ptr::write_volatile(entries as *mut u32, 8) };
    unsafe { core::ptr::write_volatile((base + HDR_MAGIC) as *mut u32, 0) };
    assert!(TraceGeometry::from_header(base, bytes).is_none(), "no magic accepted");
}

#[test]
fn the_kernel_peek_reads_its_own_view_only() {
    let r = Region::new(1, 4, POLICY_OVERWRITE);
    let mut p = TraceProducer::attach(r.base(), 0, 4);
    assert!(p.peek(0).is_none());
    for i in 0..6u32 {
        p.push::<true>(i as u64, 3, args(i));
    }
    assert!(p.peek(1).is_none(), "an overwritten index peeked");
    assert!(p.peek(6).is_none(), "an unwritten index peeked");
    for i in 2..6u32 {
        assert_eq!(p.peek(i).map(|r| r.args), Some(args(i)));
    }
}

/// A producer thread and a consumer thread on one ring, drop policy: every
/// record the producer says it wrote arrives exactly once, in order and
/// intact; the rest are exactly the drops counted.
#[test]
fn concurrent_drop_policy_loses_nothing_it_did_not_count() {
    const N: u32 = 400_000;
    let r = Arc::new(Region::new(1, 64, POLICY_DROP));
    let g = geom(&r, 1, 64);
    let base = r.base();
    let done = Arc::new(AtomicBool::new(false));
    let (r2, d2) = (r.clone(), done.clone());
    let prod = std::thread::spawn(move || {
        let _keep = r2;
        let mut p = TraceProducer::attach(base, 0, 64);
        let mut written = 0u32;
        for i in 0..N {
            if p.push::<false>(i as u64, 7, args(i)) {
                written += 1;
            }
        }
        d2.store(true, Ordering::Release);
        (written, p.drops())
    });
    let mut c = TraceConsumer::new(base, &g, 0);
    let mut got = 0u32;
    let mut last_ts: Option<u64> = None;
    loop {
        let fin = done.load(Ordering::Acquire);
        let mut n = 0;
        while let Pop::Rec(rec) = c.pop() {
            // The record's own payload says which push it was.
            let i = rec.ts as u32;
            assert_eq!(rec.args, args(i), "torn record");
            assert_eq!(rec.seq, got, "seq gap");
            if let Some(l) = last_ts {
                assert!(rec.ts > l, "out of order");
            }
            last_ts = Some(rec.ts);
            got += 1;
            n += 1;
            if n == 16 {
                c.release();
                n = 0;
            }
        }
        c.release();
        if fin && c.pop() == Pop::Empty {
            break;
        }
    }
    let (written, drops) = prod.join().unwrap();
    assert_eq!(got, written);
    assert_eq!(written + drops, N);
    assert_eq!(c.drops(), drops);
}

/// Overwrite policy under a concurrent producer: the reader never accepts a
/// torn record, and what it read plus what it counted lost covers every
/// index exactly once.
#[test]
fn concurrent_overwrite_never_hands_out_a_torn_record() {
    const N: u32 = 4_000_000;
    let r = Arc::new(Region::new(1, 2, POLICY_OVERWRITE));
    let g = geom(&r, 1, 2);
    let base = r.base();
    let done = Arc::new(AtomicBool::new(false));
    let (r2, d2) = (r.clone(), done.clone());
    let prod = std::thread::spawn(move || {
        let _keep = r2;
        let mut p = TraceProducer::attach(base, 0, 2);
        for i in 0..N {
            p.push::<true>(i as u64, 9, args(i));
        }
        d2.store(true, Ordering::Release);
    });
    let mut c = TraceConsumer::new(base, &g, 0);
    let (mut got, mut lost) = (0u64, 0u64);
    loop {
        let fin = done.load(Ordering::Acquire);
        loop {
            match c.pop() {
                Pop::Rec(rec) => {
                    assert_eq!(rec.ts as u32, rec.seq, "record from another index");
                    assert_eq!(rec.args, args(rec.seq), "torn record accepted");
                    got += 1;
                }
                Pop::Lost(n) => lost += n as u64,
                Pop::Empty => break,
            }
        }
        if fin {
            break;
        }
    }
    prod.join().unwrap();
    while let p @ (Pop::Rec(_) | Pop::Lost(_)) = c.pop() {
        match p {
            Pop::Rec(_) => got += 1,
            Pop::Lost(n) => lost += n as u64,
            Pop::Empty => unreachable!(),
        }
    }
    assert_eq!(got + lost, N as u64, "read {got} + lost {lost}");
    assert!(got > 0);
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The record substrate (`azos_rings::region::record`): one region, a ring
//! per source, one envelope, one merging reader.

use azos_rings::region::record::{
    format, region_bytes, Envelope, Head, Merge, Read, Region, RingSpec, Step, CLOCK_TIMEBASE, ENV_BYTES,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const KLOG: u8 = 1;
const DECISION: u8 = 2;
const TELEMETRY: u8 = 3;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct Line([u8; 64]);

/// A formatted region of `specs`, and the memory under it.
fn region(specs: &[RingSpec]) -> (Vec<Line>, Region) {
    let bytes = region_bytes(specs);
    let mut mem = vec![Line([0; 64]); bytes.div_ceil(64)];
    let base = mem.as_mut_ptr() as *mut u8;
    // SAFETY: zeroed, 64-aligned, `bytes` long, nobody else uses it.
    let r = unsafe {
        format(base, specs, 1_000_000_000);
        Region::open(base, bytes).unwrap()
    };
    (mem, r)
}

/// The address and length of the memory under a region.
fn mem_base(mem: &[Line]) -> usize {
    mem.as_ptr() as usize
}

fn mem_len(mem: &[Line]) -> usize {
    mem.len() * 64
}

fn three(entries: u32) -> [RingSpec; 3] {
    [
        RingSpec { source: KLOG, slot_bytes: 320, entries },
        RingSpec { source: DECISION, slot_bytes: 64, entries },
        RingSpec { source: TELEMETRY, slot_bytes: 64, entries },
    ]
}

fn put(r: &Region, ring: usize, ts: u64, kind: u16, body: &[u8]) -> u64 {
    // SAFETY: the test owns the region.
    let w = unsafe { r.writer(ring).unwrap() };
    let h = Head { ts, clock: CLOCK_TIMEBASE, kind, len: body.len() as u16, cpu: 0, flags: 0 };
    w.publish(&h, |p| p.bytes(0, body))
}

#[test]
fn records_of_three_sources_come_out_in_time_order_with_one_reader() {
    let (_m, r) = region(&three(16));
    // Written out of time order across the rings, in order within each (the
    // kernel log line printed first is stamped first).
    put(&r, 2, 30, 7, b"telemetry");
    put(&r, 0, 10, 6, b"klog line");
    put(&r, 1, 20, 3, b"decision");
    put(&r, 0, 40, 6, b"klog again");
    put(&r, 1, 50, 3, b"decision again");
    let mut m = Merge::<288>::oldest(r);
    let (mut env, mut buf) = (Envelope::default(), [0u8; 288]);
    let mut got = Vec::new();
    loop {
        match m.next(&mut env, &mut buf) {
            Step::Record { ring } => {
                assert_eq!(env.source, [KLOG, DECISION, TELEMETRY][ring], "the envelope names its ring's source");
                got.push((env.ts, buf[..env.len as usize].to_vec()));
            }
            Step::Empty => break,
            s => panic!("unexpected {s:?}"),
        }
    }
    let want: Vec<(u64, Vec<u8>)> = [
        (10, &b"klog line"[..]),
        (20, b"decision"),
        (30, b"telemetry"),
        (40, b"klog again"),
        (50, b"decision again"),
    ]
    .iter()
    .map(|(t, b)| (*t, b.to_vec()))
    .collect();
    assert_eq!(got, want, "one reader sees every source, oldest first");
}

#[test]
fn a_lapped_reader_is_told_how_many_records_it_lost() {
    let (_m, r) = region(&three(4));
    for i in 0..10u64 {
        put(&r, 1, i, 0, &i.to_le_bytes());
    }
    let mut m = Merge::<32>::oldest(r);
    // The reader started at the oldest, 6: lap it again.
    for i in 10..13u64 {
        put(&r, 1, i, 0, &i.to_le_bytes());
    }
    let (mut env, mut buf) = (Envelope::default(), [0u8; 32]);
    assert_eq!(m.next(&mut env, &mut buf), Step::Lost { ring: 1, n: 3 }, "6, 7 and 8 were overwritten");
    let mut seen = Vec::new();
    while let Step::Record { .. } = m.next(&mut env, &mut buf) {
        seen.push(env.seq);
    }
    assert_eq!(seen, vec![9, 10, 11, 12]);
    assert_eq!(m.lost(1), 3);
}

#[test]
fn a_record_with_a_stale_sequence_is_dropped_and_counted() {
    let (_m, r) = region(&three(8));
    put(&r, 0, 1, 6, b"before");
    // SAFETY: the test owns the region.
    let w = unsafe { r.writer(0).unwrap() };
    w.publish_stale(&Head { ts: 2, len: 5, ..Head::default() }, |p| p.bytes(0, b"stale"));
    put(&r, 0, 3, 6, b"after");
    let mut m = Merge::<288>::oldest(r);
    let (mut env, mut buf) = (Envelope::default(), [0u8; 288]);
    let mut steps = Vec::new();
    loop {
        match m.next(&mut env, &mut buf) {
            Step::Empty => break,
            Step::Record { .. } => steps.push(buf[..env.len as usize].to_vec()),
            Step::Stale { ring } => {
                assert_eq!(ring, 0);
                steps.push(b"<dropped>".to_vec());
            }
            s => panic!("unexpected {s:?}"),
        }
    }
    assert_eq!(steps, vec![b"before".to_vec(), b"<dropped>".to_vec(), b"after".to_vec()], "the stale record is never handed on");
    assert_eq!(m.stale(0), 1);
}

#[test]
fn a_producer_mid_store_holds_the_merge_back() {
    let (mut mem, r) = region(&three(8));
    // A producer of ring 0 has claimed index 0 and not stored it yet: the
    // head moved, the slot's stamp did not.
    head_word(&mut mem, 0).fetch_add(1, Ordering::Relaxed);
    put(&r, 1, 5, 0, b"newer");
    let mut m = Merge::<32>::oldest(r);
    let (mut env, mut buf) = (Envelope::default(), [0u8; 32]);
    assert_eq!(m.next(&mut env, &mut buf), Step::Pending { ring: 0 }, "nothing is handed out ahead of a record mid-store");
    assert_eq!(m.next(&mut env, &mut buf), Step::Pending { ring: 0 }, "and it stays held while the store lasts");
    m.skip(0);
    assert_eq!(m.next(&mut env, &mut buf), Step::Record { ring: 1 });
    assert_eq!(m.next(&mut env, &mut buf), Step::Empty);
}

/// Ring `i`'s head word: the first word at the offset its descriptor names
/// (the table is at byte 64, a descriptor 16 bytes, the offset its first u32).
fn head_word(mem: &mut [Line], i: usize) -> &'static AtomicU64 {
    let base = mem.as_mut_ptr() as *mut u8;
    // SAFETY: inside the test's region; the head is 8-aligned.
    unsafe {
        let off = core::ptr::read(base.add(64 + i * 16) as *const u32) as usize;
        AtomicU64::from_ptr(base.add(off) as *mut u64)
    }
}

#[test]
fn replay_keeps_every_sequence_number() {
    let (_e, early) = region(&three(4));
    for i in 0..6u64 {
        put(&early, 1, 100 + i, 9, &i.to_le_bytes());
    }
    let (_m, big) = region(&three(16));
    // SAFETY: both regions are the test's; nobody writes either meanwhile.
    let skipped = unsafe { big.writer(1).unwrap().replay(&early.ring(1).unwrap()) };
    assert_eq!(skipped, 2, "0 and 1 had been overwritten in the early ring");
    let ring = big.ring(1).unwrap();
    let (mut env, mut buf) = (Envelope::default(), [0u8; 32]);
    let mut c = ring.oldest();
    for i in 2..6u64 {
        assert_eq!(ring.read(&mut c, &mut env, &mut buf), Read::Record);
        assert_eq!((env.seq, env.ts, env.kind), (i, 100 + i, 9), "the same record under the same sequence");
        assert_eq!(&buf[..8], &i.to_le_bytes());
    }
    assert_eq!(put(&big, 1, 200, 9, b""), 6, "the next record continues the sequence");
}

#[test]
fn replay_keeps_a_stale_record_stale() {
    let (_e, early) = region(&three(4));
    put(&early, 0, 1, 6, b"before");
    // SAFETY: the test owns the region.
    unsafe { early.writer(0).unwrap() }.publish_stale(&Head { ts: 2, len: 5, ..Head::default() }, |p| p.bytes(0, b"stale"));
    put(&early, 0, 3, 6, b"after");
    let (_m, big) = region(&three(16));
    // SAFETY: both regions are the test's; nobody writes either meanwhile.
    unsafe { big.writer(0).unwrap().replay(&early.ring(0).unwrap()) };
    let mut m = Merge::<288>::oldest(big);
    let (mut env, mut buf) = (Envelope::default(), [0u8; 288]);
    let mut steps = Vec::new();
    loop {
        match m.next(&mut env, &mut buf) {
            Step::Empty => break,
            s => steps.push(s),
        }
    }
    assert_eq!(steps, vec![Step::Record { ring: 0 }, Step::Stale { ring: 0 }, Step::Record { ring: 0 }], "dropped and counted after the handover, not a gap");
    assert_eq!(m.stale(0), 1);
}

#[test]
fn a_region_of_another_layout_is_refused() {
    let (mut m, r) = region(&three(8));
    let bytes = region_bytes(&three(8));
    let base = m.as_mut_ptr() as *mut u8;
    // SAFETY: inside the test's region.
    unsafe {
        assert!(Region::open(base, bytes - 1).is_none(), "a ring past the mapping");
        assert!(Region::open(base, 100).is_none(), "shorter than the header");
        *base.add(4) = 9;
        assert!(Region::open(base, bytes).is_none(), "another version");
        *base.add(4) = 1;
        // A slot too small for the envelope.
        core::ptr::write(base.add(64 + 4) as *mut u32, ENV_BYTES as u32);
        assert!(Region::open(base, bytes).is_none());
    }
    let _ = r;
}

/// A producer that laps the reader between its copy and its re-check (the
/// test hook stands where the race lands): the re-check sees the stamp moved
/// and reports the lap, the mixed copy is never handed on. **Canary**
/// `canary-no-recheck`: the copy is handed on as record 0.
#[test]
fn a_record_overwritten_during_the_copy_is_not_handed_on() {
    static R: std::sync::OnceLock<Region> = std::sync::OnceLock::new();
    let (mem, r) = region(&three(4));
    let _keep = mem;
    let _ = R.set(r);
    put(&r, 1, 0, 0, b"first");
    let (base, len) = (mem_base(&_keep), mem_len(&_keep));
    azos_rings::region::record::test_hook::set(base, len, || {
        let r = R.get().unwrap();
        for i in 1..=4u64 {
            put(r, 1, i, 0, b"lapper");
        }
    });
    let ring = r.ring(1).unwrap();
    let (mut c, mut env, mut buf) = (0u64, Envelope::default(), [0u8; 32]);
    assert_eq!(ring.read(&mut c, &mut env, &mut buf), Read::Lost(1), "the record under the copy was overwritten");
    assert_eq!(c, 1);
}

/// **The hook is for the region it was set for.** A read of another region
/// (another test of the process, reading all the time) does not take it, and the
/// read of its own region does, once.
///
/// **Canary.** `canary-hook-any-region`: the neighbour's read takes it.
#[test]
fn the_hook_waits_for_its_own_region() {
    static FIRED: AtomicU64 = AtomicU64::new(0);
    let (mem_a, a) = region(&three(4));
    let (mem_b, b) = region(&three(4));
    put(&a, 1, 0, 0, b"a");
    put(&b, 1, 0, 0, b"b");
    azos_rings::region::record::test_hook::set(mem_base(&mem_a), mem_len(&mem_a), || {
        FIRED.fetch_add(1, Ordering::SeqCst);
    });
    let (mut env, mut buf) = (Envelope::default(), [0u8; 32]);
    for _ in 0..3 {
        let mut c = 0u64;
        assert_eq!(b.ring(1).unwrap().read(&mut c, &mut env, &mut buf), Read::Record);
    }
    assert_eq!(FIRED.load(Ordering::SeqCst), 0, "another region's read took the hook");
    let mut c = 0u64;
    assert_eq!(a.ring(1).unwrap().read(&mut c, &mut env, &mut buf), Read::Record);
    assert_eq!(FIRED.load(Ordering::SeqCst), 1);
    let mut c = 0u64;
    assert_eq!(a.ring(1).unwrap().read(&mut c, &mut env, &mut buf), Read::Record);
    assert_eq!(FIRED.load(Ordering::SeqCst), 1, "once");
    drop((mem_a, mem_b));
}

/// Three producers, one reader, no lap of a producer mid-store expected but
/// none ruled out on a loaded host: every torn or stale record the reader
/// sees must be one the ring counted as lapped (the protocol's residual, see
/// record.rs), and every record is read or counted lost, but for the lapped
/// ones the ring counts.
#[test]
fn many_producers_one_reader_every_record_whole() {
    let (mem, r) = region(&three(64));
    let _keep = mem;
    let stop = Arc::new(AtomicBool::new(false));
    const PER: u64 = 20_000;
    // Made before any record exists, so every record is the reader's to see.
    let mut m = Merge::<288>::oldest(r);
    let producers: Vec<_> = (0..3u64)
        .map(|p| {
            let r = r;
            std::thread::spawn(move || {
                for i in 0..PER {
                    let v = p << 32 | i;
                    // Every byte of the payload says the same value: a torn
                    // record would mix two.
                    let mut body = [0u8; 280];
                    for c in body.chunks_mut(8) {
                        c.copy_from_slice(&v.to_le_bytes());
                    }
                    put(&r, 0, v, p as u16, &body);
                }
            })
        })
        .collect();
    let reader = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let (mut env, mut buf) = (Envelope::default(), [0u8; 288]);
            let (mut read, mut torn, mut skipped, mut pending_at) = (0u64, 0u64, 0u64, (0u64, 0u32));
            loop {
                match m.next(&mut env, &mut buf) {
                    Step::Record { .. } => {
                        let v = u64::from_le_bytes(buf[..8].try_into().unwrap());
                        if !buf[..280].chunks(8).all(|c| c == v.to_le_bytes()) || env.ts != v {
                            torn += 1;
                        }
                        read += 1;
                    }
                    Step::Pending { ring } => {
                        let c = m.cursor(ring);
                        pending_at = if pending_at.0 == c { (c, pending_at.1 + 1) } else { (c, 1) };
                        // A producer the host descheduled mid-store, or one a
                        // lapping producer overtook in the same slot: the
                        // sink gives up on it and counts it, as `logd` does.
                        if pending_at.1 > 1_000_000 {
                            m.skip(ring);
                            skipped += 1;
                        }
                        // A descheduled producer needs this CPU: give it up now
                        // and then, a spin that never does can take minutes on a
                        // loaded host.
                        if pending_at.1 % 64 == 0 {
                            std::thread::yield_now();
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                    Step::Lost { .. } | Step::Stale { .. } => {}
                    Step::Empty => {
                        if stop.load(Ordering::Acquire) && m.next(&mut env, &mut buf) == Step::Empty {
                            return (read, m.lost(0) + skipped, m.stale(0), torn);
                        }
                    }
                }
            }
        })
    };
    for p in producers {
        p.join().unwrap();
    }
    stop.store(true, Ordering::Release);
    let (read, lost, stale, torn) = reader.join().unwrap();
    let lapped = r.ring(0).unwrap().lapped();
    assert!(torn + stale <= lapped, "{torn} torn and {stale} stale records, but only {lapped} producers lapped");
    // A record whose producer was lapped mid-store is counted by the ring
    // (`lapped`); the reader may have counted it lost too, or not seen it at
    // all: that is the whole tolerance.
    let total = read + lost;
    assert!(
        total <= 3 * PER && total + lapped >= 3 * PER,
        "every record is read or counted lost (read {read} lost {lost} torn {torn} lapped {lapped})"
    );
    assert!(read > 0);
}

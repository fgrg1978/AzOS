// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_cam_ring::FanoutRing` (wave 15, B2): one producer,
//! two consumers with their own cursors, overwrite-oldest and backpressure.

use azos_cam_ring::{FanoutRing, FrameFormat, FrameInfo, FrameSink, Policy};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const N: usize = 4;
const SZ: usize = 64;
const TX: usize = 0;
const STREAM: usize = 1;
type Ring = FanoutRing<N, SZ, 2>;

/// Frame `seq`'s content: its length and every byte derive from `seq`, so a
/// reader can tell a torn or wrong frame.
fn fill(buf: &mut [u8; SZ], seq: u64) -> usize {
    let len = 8 + (seq as usize % (SZ - 8));
    for (i, b) in buf[..len].iter_mut().enumerate() {
        *b = (seq as u8).wrapping_mul(31).wrapping_add(i as u8);
    }
    len
}

fn check(bytes: &[u8], seq: u64) {
    assert_eq!(bytes.len(), 8 + (seq as usize % (SZ - 8)), "frame {seq}: length");
    for (i, b) in bytes.iter().enumerate() {
        assert_eq!(*b, (seq as u8).wrapping_mul(31).wrapping_add(i as u8), "frame {seq}: byte {i}");
    }
}

fn stamp_of(seq: u64) -> u64 {
    1_000 + seq * 7
}

/// Produce one frame; returns its sequence number, `None` if refused.
fn produce(r: &Ring) -> Option<u64> {
    let next = r.last_seq() + 1;
    let slot = r.claim()?;
    let len = fill(slot, next);
    Some(r.commit(len, stamp_of(next)))
}

#[test]
fn overwrite_oldest_never_refuses_and_the_latest_frame_wins() {
    let r = Ring::new(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    // Nobody reads: 20 frames into 4 slots.
    for want in 1..=20 {
        assert_eq!(produce(&r), Some(want), "the producer must never be refused");
    }
    assert_eq!(r.refused(), 0);
    assert_eq!(r.produced(), 20);
    // 20 frames, 4 slots: 16 overwritten before either consumer took them.
    assert_eq!(r.overwritten(), 16);
    let f = r.acquire_latest(TX).expect("the newest frame");
    assert_eq!(f.seq(), 20);
    assert_eq!(f.stamp(), stamp_of(20), "the acquisition stamp travels with the frame");
    check(f.bytes(), 20);
    assert_eq!(f.skipped(), 19);
}

#[test]
fn two_consumers_keep_their_own_cursors() {
    let r = Ring::new(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    let mut tx_seen = Vec::new();
    for k in 1..=12u64 {
        produce(&r).unwrap();
        // The stream takes every frame as it is committed.
        let f = r.acquire_latest(STREAM).expect("stream: a new frame");
        assert_eq!((f.seq(), f.skipped(), f.stamp()), (k, 0, stamp_of(k)));
        check(f.bytes(), k);
        drop(f);
        assert!(r.acquire_latest(STREAM).is_none(), "stream: nothing new after taking it");
        // The sender takes the newest every third frame.
        if k % 3 == 0 {
            let f = r.acquire_latest(TX).expect("tx: a new frame");
            check(f.bytes(), f.seq());
            tx_seen.push((f.seq(), f.skipped()));
        }
    }
    assert_eq!(tx_seen, vec![(3, 2), (6, 2), (9, 2), (12, 2)]);
    assert!(r.acquire_latest(TX).is_none());
    // One encode per frame for both consumers: 12 committed, 12 + 4 taken.
    assert_eq!(r.produced(), 12);
}

#[test]
fn a_lagging_consumer_skips_to_the_newest_frame() {
    let r = Ring::new(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    for _ in 0..10 {
        produce(&r).unwrap();
    }
    // Each consumer goes straight to frame 10, the nine before it skipped.
    for c in [TX, STREAM] {
        let f = r.acquire_latest(c).unwrap();
        assert_eq!((f.seq(), f.skipped()), (10, 9));
        assert_eq!(f.stamp(), stamp_of(10));
        check(f.bytes(), 10);
        drop(f);
        assert!(r.acquire_latest(c).is_none());
    }
}

#[test]
fn a_pinned_frame_is_never_overwritten() {
    let r = Ring::new(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    produce(&r).unwrap();
    let held = r.acquire_latest(TX).unwrap();
    let held2 = {
        produce(&r).unwrap();
        r.acquire_latest(STREAM).unwrap()
    };
    // Both consumers hold a frame; the producer runs on, 100 frames, never
    // refused and never into a pinned slot.
    for _ in 0..100 {
        assert!(produce(&r).is_some());
    }
    assert_eq!((held.seq(), held2.seq()), (1, 2));
    check(held.bytes(), 1);
    check(held2.bytes(), 2);
    assert_eq!(held.stamp(), stamp_of(1));
}

#[test]
fn backpressure_refuses_until_the_slowest_consumer_takes_its_frames() {
    let r = Ring::new(Policy::Backpressure);
    r.attach(TX);
    r.attach(STREAM);
    // 4 slots, one always the newest: 4 frames fill it, the 5th waits.
    for want in 1..=4 {
        assert_eq!(produce(&r), Some(want));
    }
    // Slot of frame 1 is free (not newest, not pinned) but TX and STREAM
    // have not taken it: refused.
    assert_eq!(produce(&r), None);
    assert_eq!(r.refused(), 1);
    // The stream catches up; TX still holds frame 1 back.
    assert_eq!(r.acquire_latest(STREAM).unwrap().seq(), 4);
    assert_eq!(produce(&r), None);
    // TX takes the newest: everything older is passed over, capture resumes.
    assert_eq!(r.acquire_latest(TX).unwrap().seq(), 4);
    assert_eq!(produce(&r), Some(5));
    assert_eq!(r.overwritten(), 0, "backpressure never overwrites a frame a consumer is owed");
    // A detached consumer holds nothing back.
    r.detach(STREAM);
    for _ in 0..10 {
        assert!(produce(&r).is_some() || r.acquire_latest(TX).is_some());
    }
}

#[test]
fn attach_starts_at_the_newest_frame_and_detach_is_idempotent() {
    let r = Ring::new(Policy::OverwriteOldest);
    produce(&r).unwrap();
    assert!(!r.any_attached());
    r.attach(TX);
    r.attach(TX);
    assert!(r.is_attached(TX) && !r.is_attached(STREAM));
    assert!(r.acquire_latest(TX).is_none(), "frames before attach are not owed");
    produce(&r).unwrap();
    assert_eq!(r.acquire_latest(TX).unwrap().seq(), 2);
    r.detach(TX);
    r.detach(TX);
    assert!(!r.any_attached());
}

/// One producer thread, two consumer threads:
/// every frame a consumer gets is whole (its bytes and stamp match its
/// sequence number) and sequence numbers only grow, whatever the
/// interleaving. The producer is never refused.
#[test]
fn concurrent_readers_never_see_a_torn_frame() {
    const FRAMES: u64 = 200_000;
    let r: Arc<Ring> = Arc::new(Ring::new(Policy::OverwriteOldest));
    r.attach(TX);
    r.attach(STREAM);
    let done = Arc::new(AtomicBool::new(false));
    let taken: Arc<[AtomicU64; 2]> = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
    let reader = |c: usize| {
        let r = Arc::clone(&r);
        let done = Arc::clone(&done);
        let taken = Arc::clone(&taken);
        std::thread::spawn(move || {
            let (mut last, mut got) = (0u64, 0u64);
            while !done.load(Ordering::Acquire) {
                if let Some(f) = r.acquire_latest(c) {
                    assert!(f.seq() > last, "consumer {c}: seq went {last} -> {}", f.seq());
                    assert_eq!(f.seq() - last - 1, f.skipped());
                    check(f.bytes(), f.seq());
                    assert_eq!(f.stamp(), stamp_of(f.seq()));
                    last = f.seq();
                    got += 1;
                    taken[c].store(got, Ordering::Release);
                }
            }
            got
        })
    };
    let a = reader(TX);
    let b = reader(STREAM);
    // At least FRAMES frames, and on until each reader took 1000 (the
    // threads may start late), capped at 100 x FRAMES.
    let mut want = 0;
    while want < FRAMES
        || (want < 100 * FRAMES
            && (taken[0].load(Ordering::Acquire) < 1000 || taken[1].load(Ordering::Acquire) < 1000))
    {
        want += 1;
        assert_eq!(produce(&r), Some(want));
    }
    done.store(true, Ordering::Release);
    let (ga, gb) = (a.join().unwrap(), b.join().unwrap());
    assert_eq!(r.refused(), 0);
    assert!(ga >= 1000 && gb >= 1000, "both consumers took frames ({ga}, {gb})");
}

// ---- The sink hook: a camera driver other than the capture task ----

/// What a class driver does with a ring, through the trait alone: wait for a
/// reader, claim, append payloads, commit.
fn write_through_sink(sink: &dyn FrameSink, payloads: &[&[u8]], stamp: u64, info: FrameInfo) -> bool {
    let Some(slot) = sink.claim() else { return false };
    let mut off = 0;
    for p in payloads {
        slot[off..off + p.len()].copy_from_slice(p);
        off += p.len();
    }
    sink.commit(off, stamp, info);
    true
}

#[test]
fn a_frame_written_through_the_sink_carries_its_format_and_size() {
    let r = Ring::new(Policy::OverwriteOldest);
    r.attach(TX);
    write_through_sink(&r, &[b"\xff\xd8", b"jpeg", b"\xff\xd9"], 11, FrameInfo::JPEG);
    let f = r.acquire_latest(TX).expect("the JPEG");
    assert_eq!(f.bytes(), b"\xff\xd8jpeg\xff\xd9");
    assert_eq!(f.info(), FrameInfo::JPEG);
    assert_eq!(f.stamp(), 11);
    drop(f);
    // A raw frame of another size: the next frame does not inherit the info
    // of the slot's previous frame.
    write_through_sink(&r, &[&[1, 2, 3, 4, 5, 6, 7, 8]], 22, FrameInfo::yuyv(2, 2));
    let f = r.acquire_latest(TX).expect("the raw frame");
    assert_eq!(f.info(), FrameInfo { format: FrameFormat::Yuyv, width: 2, height: 2 });
    assert_eq!(f.bytes().len(), 8);
    drop(f);
    // The capture task's own commit is a JPEG again.
    let slot = r.claim().unwrap();
    slot[..2].copy_from_slice(&[0xff, 0xd8]);
    r.commit(2, 33);
    assert_eq!(r.acquire_latest(TX).unwrap().info(), FrameInfo::JPEG);
}

#[test]
fn the_sink_is_wanted_only_while_a_consumer_is_attached() {
    let r = Ring::new(Policy::OverwriteOldest);
    assert!(!FrameSink::wanted(&r));
    r.attach(TX);
    assert!(FrameSink::wanted(&r));
    r.detach(TX);
    assert!(!FrameSink::wanted(&r));
}

#[test]
fn an_aborted_sink_frame_publishes_nothing() {
    let r = Ring::new(Policy::OverwriteOldest);
    r.attach(TX);
    let sink: &dyn FrameSink = &r;
    assert!(sink.claim().is_some());
    sink.abort();
    assert_eq!(r.produced(), 0);
    assert!(r.acquire_latest(TX).is_none());
    // The window is closed again: the next claim works.
    assert!(write_through_sink(sink, &[b"x"], 1, FrameInfo::JPEG));
    assert_eq!(r.produced(), 1);
}

#[test]
fn a_second_producer_cannot_claim_while_the_first_holds_a_slot() {
    let r = Ring::new(Policy::OverwriteOldest);
    r.attach(TX);
    // The USB driver holds a slot across turns of its task; the capture task
    // finds the ring taken and writes nothing, instead of racing it.
    let held = r.claim().expect("the first producer");
    held[0] = 0xaa;
    assert!(r.claim().is_none(), "a claim inside another's window must be refused");
    assert_eq!(r.refused(), 0, "that is not backpressure");
    r.commit(1, 5);
    // After the commit the other producer gets its turn, in another slot.
    let second = r.claim().expect("the window is closed");
    second[0] = 0xbb;
    r.commit(1, 6);
    assert_eq!(r.acquire_latest(TX).unwrap().bytes(), &[0xbb]);
}

#[test]
fn two_producers_never_write_a_slot_together() {
    // Real threads: each producer writes its own byte over a whole slot
    // between claim and commit; the consumer must never see a mixed frame.
    let r = Arc::new(Ring::new(Policy::OverwriteOldest));
    r.attach(TX);
    let stop = Arc::new(AtomicBool::new(false));
    let wrote = Arc::new(AtomicU64::new(0));
    let mut hs = Vec::new();
    for who in [0xa1u8, 0xb2] {
        let (r, stop, wrote) = (r.clone(), stop.clone(), wrote.clone());
        hs.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Some(slot) = FrameSink::claim(&*r) {
                    slot[..SZ].fill(who);
                    FrameSink::commit(&*r, SZ, 0, FrameInfo::JPEG);
                    wrote.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    let mut seen = 0u64;
    while wrote.load(Ordering::Relaxed) < 20_000 {
        if let Some(f) = r.acquire_latest(TX) {
            let b = f.bytes();
            assert!(b[0] == 0xa1 || b[0] == 0xb2);
            assert!(b.iter().all(|x| *x == b[0]), "a frame mixed two producers");
            seen += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    for h in hs {
        h.join().unwrap();
    }
    assert!(seen > 0);
}

// ---- Raw pixels ----

#[test]
fn the_luma_of_a_yuyv_frame_is_every_other_byte() {
    use azos_cam_ring::yuyv_luma;
    // 4x2 pixels: Y values 10..18 interleaved with chroma 200+.
    let yuyv: Vec<u8> = (0..8u8).flat_map(|i| [10 + i, 200 + i]).collect();
    let mut dst = [0u8; 8];
    assert_eq!(yuyv_luma(&yuyv, 4, 2, &mut dst, 8, 8), Some((4, 2)));
    assert_eq!(dst, [10, 11, 12, 13, 14, 15, 16, 17]);
}

#[test]
fn a_big_yuyv_frame_is_decimated_to_fit() {
    use azos_cam_ring::yuyv_luma;
    // 8x4 pixels into 4x4: every second pixel of every second row (step 2).
    let yuyv: Vec<u8> = (0..32u8).flat_map(|i| [i, 0xee]).collect();
    let mut dst = [0u8; 16];
    assert_eq!(yuyv_luma(&yuyv, 8, 4, &mut dst, 4, 4), Some((4, 2)));
    assert_eq!(&dst[..8], &[0, 2, 4, 6, 16, 18, 20, 22]);
    // Height decides the step as well as width.
    assert_eq!(yuyv_luma(&yuyv, 8, 4, &mut dst, 8, 1), Some((2, 1)));
    assert_eq!(&dst[..2], &[0, 4]);
}

#[test]
fn a_yuyv_frame_that_does_not_add_up_gives_nothing() {
    use azos_cam_ring::yuyv_luma;
    let mut dst = [0u8; 16];
    assert_eq!(yuyv_luma(&[0; 15], 2, 4, &mut dst, 8, 8), None, "a byte short of 2 * w * h");
    assert_eq!(yuyv_luma(&[0; 16], 0, 4, &mut dst, 8, 8), None);
    assert_eq!(yuyv_luma(&[0; 16], 2, 4, &mut dst[..7], 8, 8), None, "dst too small");
    assert_eq!(yuyv_luma(&[0; 16], 2, 4, &mut dst, 0, 8), None);
}

// ---- JPEG size ----

/// SOI, an APP0 and a DQT segment, then SOF0 for `w` x `h`.
fn jpeg_head(w: u16, h: u16) -> Vec<u8> {
    let mut j = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x06, 1, 2, 3, 4, 0xff, 0xdb, 0x00, 0x04, 9, 9];
    j.extend([0xff, 0xc0, 0x00, 0x0b, 8]);
    j.extend(h.to_be_bytes());
    j.extend(w.to_be_bytes());
    j.extend([1, 1, 0x11, 0]);
    j
}

#[test]
fn a_jpeg_says_its_size_in_the_start_of_frame() {
    use azos_cam_ring::jpeg_size;
    assert_eq!(jpeg_size(&jpeg_head(160, 120)), Some((160, 120)));
    assert_eq!(jpeg_size(&jpeg_head(640, 480)), Some((640, 480)));
    // Fill bytes before a marker, and a progressive frame (SOF2).
    let mut j = jpeg_head(320, 240);
    j.splice(2..2, [0xff, 0xff]);
    assert_eq!(jpeg_size(&j), Some((320, 240)));
    let mut j = jpeg_head(320, 240);
    let sof = j.iter().position(|b| *b == 0xc0).unwrap();
    j[sof] = 0xc2;
    assert_eq!(jpeg_size(&j), Some((320, 240)));
}

#[test]
fn bytes_that_are_not_a_jpeg_with_a_frame_header_have_no_size() {
    use azos_cam_ring::jpeg_size;
    let j = jpeg_head(160, 120);
    assert_eq!(jpeg_size(&[]), None);
    assert_eq!(jpeg_size(&[0xff, 0xd8]), None, "SOI alone");
    assert_eq!(jpeg_size(&[0, 1, 2, 3, 4, 5]), None, "no SOI");
    assert_eq!(jpeg_size(&j[..j.len() - 6]), None, "ends inside the SOF");
    // The scan starts before any frame header.
    assert_eq!(jpeg_size(&[0xff, 0xd8, 0xff, 0xda, 0, 2, 0, 0]), None);
    // A segment whose length runs past the end.
    assert_eq!(jpeg_size(&[0xff, 0xd8, 0xff, 0xe0, 0xff, 0xff, 0, 0]), None);
    // A zero size is no size.
    assert_eq!(jpeg_size(&jpeg_head(0, 120)), None);
    // A DHT (c4) is not a frame header.
    assert_eq!(jpeg_size(&[0xff, 0xd8, 0xff, 0xc4, 0, 4, 0, 0, 0xff, 0xd9]), None);
}

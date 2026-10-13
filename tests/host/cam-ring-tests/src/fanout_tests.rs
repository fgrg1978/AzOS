// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_cam_ring::FanoutRing` (wave 15, B2): one producer,
//! two consumers with their own cursors, overwrite-oldest and backpressure.

use azos_cam_ring::{FanoutRing, Policy};
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
        // The stream takes every frame, in order.
        let f = r.acquire_next(STREAM).expect("stream: a new frame");
        assert_eq!((f.seq(), f.skipped(), f.stamp()), (k, 0, stamp_of(k)));
        check(f.bytes(), k);
        drop(f);
        assert!(r.acquire_next(STREAM).is_none(), "stream: nothing new after taking it");
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
    // Latest read: straight to frame 10.
    let f = r.acquire_latest(TX).unwrap();
    assert_eq!((f.seq(), f.skipped()), (10, 9));
    assert_eq!(f.stamp(), stamp_of(10));
    drop(f);
    // In-order read: the oldest frame still in the ring (7..10 in 4 slots),
    // the six overwritten ones counted as skipped.
    let f = r.acquire_next(STREAM).unwrap();
    assert_eq!((f.seq(), f.skipped()), (7, 6));
    check(f.bytes(), 7);
    drop(f);
    for want in 8..=10 {
        let f = r.acquire_next(STREAM).unwrap();
        assert_eq!((f.seq(), f.skipped()), (want, 0));
    }
    assert!(r.acquire_next(STREAM).is_none());
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
    while r.acquire_next(STREAM).is_some() {}
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

/// One producer thread, two consumer threads (one latest, one in order):
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
    let reader = |c: usize, newest: bool| {
        let r = Arc::clone(&r);
        let done = Arc::clone(&done);
        let taken = Arc::clone(&taken);
        std::thread::spawn(move || {
            let (mut last, mut got) = (0u64, 0u64);
            while !done.load(Ordering::Acquire) {
                let f = if newest { r.acquire_latest(c) } else { r.acquire_next(c) };
                if let Some(f) = f {
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
    let a = reader(TX, true);
    let b = reader(STREAM, false);
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

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_cam_ring::FramePool`: one producer, readers with their
//! own cursors, references on lent buffers, both lag policies.

use azos_cam_ring::{FrameFormat, FrameInfo, FramePool, FrameSink, NoRoom, Policy};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const N: usize = 4;
const SZ: usize = 64;
const TX: usize = 0;
const STREAM: usize = 1;
type Ring = FramePool<N, SZ, 2>;

/// A pool with `N` buffers lent from the heap, as the kernel lends memory
/// objects.
fn pool(policy: Policy) -> Ring {
    let p = Ring::new(policy);
    let bufs: Vec<usize> = (0..N).map(|_| Box::leak(vec![0u8; SZ].into_boxed_slice()).as_mut_ptr() as usize).collect();
    assert_eq!(p.install(&bufs), Ok(N));
    p
}

/// Frame `seq`'s content: its length and every byte derive from `seq`, so a
/// reader can tell a torn or wrong frame.
fn fill(buf: &mut [u8], seq: u64) -> usize {
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
fn a_pool_without_buffers_claims_nothing_and_takes_no_reader() {
    let r = Ring::new(Policy::OverwriteOldest);
    assert!(!r.ready());
    assert!(r.claim().is_none());
    assert!(!r.attach(TX));
    assert!(!r.any_attached());
    // Fewer buffers than a reader and the newest and the one being written
    // need: the pool takes none of them.
    let one = Box::leak(vec![0u8; SZ].into_boxed_slice()).as_mut_ptr() as usize;
    assert_eq!(r.install(&[one; N - 1]), Err(NoRoom));
    assert!(!r.ready());
    assert_eq!(r.install(&[one; N]), Ok(N));
    assert!(r.ready() && r.attach(TX));
    assert_eq!(r.install(&[one; N]), Err(NoRoom), "lent once");
}

#[test]
fn overwrite_oldest_never_refuses_and_the_latest_frame_wins() {
    let r = pool(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    // Nobody reads: 20 frames into 4 slots.
    for want in 1..=20 {
        assert_eq!(produce(&r), Some(want), "the producer must never be refused");
    }
    assert_eq!(r.refused(), 0);
    assert_eq!(r.produced(), 20);
    // 20 frames, 4 slots: 16 overwritten before either reader took them.
    assert_eq!(r.overwritten(), 16);
    let f = r.acquire_latest(TX).expect("the newest frame");
    assert_eq!(f.seq(), 20);
    assert_eq!(f.stamp(), stamp_of(20), "the acquisition stamp travels with the frame");
    check(f.bytes(), 20);
    assert_eq!(f.skipped(), 19);
}

#[test]
fn two_readers_keep_their_own_cursors() {
    let r = pool(Policy::OverwriteOldest);
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
    // One encode per frame for both readers: 12 committed, 12 + 4 taken.
    assert_eq!(r.produced(), 12);
}

#[test]
fn a_lagging_reader_skips_to_the_newest_frame() {
    let r = pool(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    for _ in 0..10 {
        produce(&r).unwrap();
    }
    // Each reader goes straight to frame 10, the nine before it skipped.
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
fn a_referenced_frame_is_never_overwritten() {
    let r = pool(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    produce(&r).unwrap();
    let held = r.acquire_latest(TX).unwrap();
    let held2 = {
        produce(&r).unwrap();
        r.acquire_latest(STREAM).unwrap()
    };
    // Both readers hold a frame; the producer runs on, 100 frames, never
    // refused and never into a referenced slot.
    for _ in 0..100 {
        assert!(produce(&r).is_some());
    }
    assert_eq!((held.seq(), held2.seq()), (1, 2));
    check(held.bytes(), 1);
    check(held2.bytes(), 2);
    assert_eq!(held.stamp(), stamp_of(1));
}

#[test]
fn backpressure_refuses_until_the_slowest_owed_reader_takes_its_frames() {
    let r = pool(Policy::Backpressure);
    r.attach_owed(TX);
    r.attach_owed(STREAM);
    // 4 slots, one always the newest: 4 frames fill it, the 5th waits.
    for want in 1..=4 {
        assert_eq!(produce(&r), Some(want));
    }
    // The slot of frame 1 is free (not newest, not referenced) but TX and
    // STREAM have not taken it: refused.
    assert_eq!(produce(&r), None);
    assert_eq!(r.refused(), 1);
    // The stream takes frame 1; TX still holds it back.
    assert_eq!(r.acquire(STREAM).unwrap().seq(), 1);
    assert_eq!(produce(&r), None);
    // TX takes it too: capture resumes, and nothing an owed reader had not
    // taken was overwritten.
    assert_eq!(r.acquire(TX).unwrap().seq(), 1);
    assert_eq!(produce(&r), Some(5));
    assert_eq!(r.overwritten(), 0, "backpressure never overwrites a frame a reader is owed");
    // Every frame comes in order, none skipped.
    for want in 2..=5 {
        for c in [TX, STREAM] {
            let f = r.acquire(c).unwrap();
            assert_eq!((f.seq(), f.skipped()), (want, 0));
            check(f.bytes(), want);
        }
    }
    // A detached reader holds nothing back.
    r.detach(STREAM);
    for _ in 0..10 {
        assert!(produce(&r).is_some() || r.acquire(TX).is_some());
    }
}

#[test]
fn attach_starts_at_the_newest_frame_and_detach_is_idempotent() {
    let r = pool(Policy::OverwriteOldest);
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

/// One producer thread, two reader threads:
/// every frame a reader gets is whole (its bytes and stamp match its
/// sequence number) and sequence numbers only grow, whatever the
/// interleaving. The producer is never refused.
#[test]
fn concurrent_readers_never_see_a_torn_frame() {
    const FRAMES: u64 = 200_000;
    let r: Arc<Ring> = Arc::new(pool(Policy::OverwriteOldest));
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
                    assert!(f.seq() > last, "reader {c}: seq went {last} -> {}", f.seq());
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
    assert!(ga >= 1000 && gb >= 1000, "both readers took frames ({ga}, {gb})");
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
    let r = pool(Policy::OverwriteOldest);
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
fn the_sink_is_wanted_only_while_a_reader_is_attached() {
    let r = pool(Policy::OverwriteOldest);
    assert!(!FrameSink::wanted(&r));
    r.attach(TX);
    assert!(FrameSink::wanted(&r));
    r.detach(TX);
    assert!(!FrameSink::wanted(&r));
}

#[test]
fn an_aborted_sink_frame_publishes_nothing() {
    let r = pool(Policy::OverwriteOldest);
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
    let r = pool(Policy::OverwriteOldest);
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
    // between claim and commit; the reader must never see a mixed frame.
    let r = Arc::new(pool(Policy::OverwriteOldest));
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while wrote.load(Ordering::Relaxed) < 20_000 && std::time::Instant::now() < deadline {
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
    assert!(wrote.load(Ordering::Relaxed) >= 20_000, "the producers were held up");
    assert!(seen > 0);
}


// ---- The guarantees of the class ----

#[test]
fn one_commit_serves_every_reader_and_the_references_end_with_the_reads() {
    let r = pool(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    for k in 1..=1000u64 {
        assert_eq!(produce(&r), Some(k));
        let (a, b) = (r.acquire_latest(TX).unwrap(), r.acquire_latest(STREAM).unwrap());
        assert_eq!(r.references(), 2, "each reader holds one reference on the one buffer");
        assert_eq!((a.seq(), b.seq()), (k, k));
        check(a.bytes(), k);
        check(b.bytes(), k);
        drop((a, b));
        assert_eq!(r.references(), 0, "a reference ends with the read");
    }
    assert_eq!(r.produced(), 1000, "one frame in the pool, however many readers took it");
    assert_eq!(r.refused(), 0);
}

#[test]
fn a_slow_reader_never_blocks_the_producer() {
    let r = pool(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    // The stream reader never reads, the sender holds one frame the whole run.
    produce(&r).unwrap();
    let held = r.acquire_latest(TX).unwrap();
    for k in 2..=500u64 {
        assert_eq!(produce(&r), Some(k), "frame {k}: the producer waited for a reader");
    }
    assert_eq!(r.refused(), 0);
    assert_eq!(held.seq(), 1);
    check(held.bytes(), 1);
    drop(held);
    let f = r.acquire_latest(STREAM).unwrap();
    assert_eq!((f.seq(), f.skipped()), (500, 499), "the lagging reader goes to the newest frame");
}

#[test]
fn backpressure_keeps_the_frame_a_reader_is_owed() {
    let r = pool(Policy::Backpressure);
    r.attach_owed(TX);
    for want in 1..=N as u64 {
        assert_eq!(produce(&r), Some(want));
    }
    // The producer is refused, counted, and the oldest frame is still there
    // for the reader that never took it.
    for _ in 0..5 {
        assert_eq!(produce(&r), None);
    }
    assert_eq!((r.refused(), r.overwritten(), r.produced()), (5, 0, N as u64));
    let f = r.acquire(TX).unwrap();
    assert_eq!((f.seq(), f.skipped()), (1, 0), "the oldest frame, not the newest");
    check(f.bytes(), 1);
}

#[test]
fn a_reader_the_pool_is_not_owed_to_never_holds_the_producer_back() {
    let r = pool(Policy::Backpressure);
    r.attach_owed(TX);
    // The stream reader attaches plainly, takes nothing and does not go away.
    r.attach(STREAM);
    for want in 1..=50u64 {
        assert_eq!(produce(&r), Some(want), "frame {want}: a quiet reader stalled the producer");
        let f = r.acquire(TX).unwrap();
        assert_eq!((f.seq(), f.skipped()), (want, 0));
    }
    assert_eq!(r.refused(), 0);
    let f = r.acquire(STREAM).unwrap();
    assert_eq!((f.seq(), f.skipped()), (50, 49), "the quiet reader goes to the newest frame");
}

#[test]
fn a_detached_reader_holds_nothing_back() {
    let r = pool(Policy::Backpressure);
    r.attach_owed(TX);
    r.attach_owed(STREAM);
    for want in 1..=N as u64 {
        assert_eq!(produce(&r), Some(want));
    }
    assert_eq!(produce(&r), None);
    // Both readers go away (a task that exited): capture resumes.
    r.detach(TX);
    r.detach(STREAM);
    assert!(!r.any_attached());
    assert_eq!(produce(&r), Some(N as u64 + 1), "a reader that is gone is still owed frames");
}

#[test]
fn a_reader_cannot_change_a_frame_another_reader_will_read() {
    let r = pool(Policy::OverwriteOldest);
    r.attach(TX);
    r.attach(STREAM);
    produce(&r).unwrap();
    let a = r.acquire_latest(TX).unwrap();
    let before = a.bytes().to_vec();
    check(&before, 1);
    // The first reader reads it as often as it likes; the second still gets
    // the bytes the producer committed.
    for _ in 0..3 {
        assert_eq!(a.bytes(), &before[..]);
    }
    let b = r.acquire_latest(STREAM).unwrap();
    check(b.bytes(), 1);
    assert_eq!(b.bytes(), &before[..]);
}

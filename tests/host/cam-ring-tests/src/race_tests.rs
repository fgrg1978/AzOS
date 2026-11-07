// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The two re-checks of the reader/producer handshake, each held at the point
//! where it matters (`azos_cam_ring::pool::race`): a reader that took a
//! reference on a buffer the producer has already reused, and a producer that
//! chose a buffer a reader takes a reference on before it is marked filling.

use azos_cam_ring::pool::race;
use azos_cam_ring::{FramePool, Policy};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::Mutex;

const SZ: usize = 16;
type Ring = FramePool<4, SZ, 2>;

/// The hooks are process-wide: one race at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
static POOL: AtomicPtr<Ring> = AtomicPtr::new(core::ptr::null_mut());

fn pool() -> &'static Ring {
    let p: &'static Ring = Box::leak(Box::new(Ring::new(Policy::OverwriteOldest)));
    let bufs: Vec<usize> = (0..4).map(|_| Box::leak(vec![0u8; SZ].into_boxed_slice()).as_mut_ptr() as usize).collect();
    p.install(&bufs).unwrap();
    POOL.store(p as *const Ring as *mut Ring, Ordering::Release);
    p
}

fn the_pool() -> &'static Ring {
    // SAFETY: set by `pool` to a leaked pool.
    unsafe { &*POOL.load(Ordering::Acquire) }
}

/// Is `pool` the one under test? The other tests of this binary reach the
/// same points on pools of their own.
fn mine(pool: usize) -> bool {
    pool == POOL.load(Ordering::Acquire) as usize
}

fn put(p: &Ring, byte: u8) -> u64 {
    let slot = p.claim().expect("a buffer");
    slot[..SZ].fill(byte);
    p.commit(SZ, byte as u64)
}

static REUSED: AtomicBool = AtomicBool::new(false);

/// While a reader holds the id of the newest frame (about to take its
/// reference), the producer writes four more frames, the last into the very buffer the id names.
fn producer_reuses_the_buffer(pool: usize) {
    if mine(pool) && !REUSED.swap(true, Ordering::SeqCst) {
        let p = the_pool();
        for b in 2..=5u8 {
            put(p, b);
        }
    }
}

/// **A reader whose buffer was reused while it held only the id does not
/// return the new bytes under the old number.** It sees the buffer's sequence
/// number differ, gives the reference back and takes the newest frame.
///
/// **Canary.** `canary-reader-skips-recheck`: it returns frame 1 with the bytes
/// of frame 5.
#[test]
fn a_reader_whose_buffer_was_reused_takes_the_newest_frame_instead() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let p = pool();
    p.attach(0);
    put(p, 1);
    REUSED.store(false, Ordering::SeqCst);
    race::set(&race::BEFORE_REF, Some(producer_reuses_the_buffer));
    let f = p.acquire_latest(0).expect("a frame");
    race::set(&race::BEFORE_REF, None);
    assert_eq!(f.seq(), 5, "the buffer of frame 1 holds frame 5 now");
    assert!(f.bytes().iter().all(|b| *b == 5), "frame {} read as {:?}", f.seq(), f.bytes());
    assert_eq!(p.references(), 1);
}

static READER_READY: AtomicBool = AtomicBool::new(false);
static GO: AtomicBool = AtomicBool::new(false);
static READER_HOLDS: AtomicBool = AtomicBool::new(false);

fn wait(flag: &AtomicBool) {
    let t = std::time::Instant::now();
    while !flag.load(Ordering::SeqCst) {
        assert!(t.elapsed().as_secs() < 10, "the other side never came");
        std::thread::yield_now();
    }
}

fn reader_waits_for_the_producer(pool: usize) {
    if !mine(pool) {
        return;
    }
    READER_READY.store(true, Ordering::SeqCst);
    wait(&GO);
}

fn producer_waits_for_the_reader(pool: usize) {
    if !mine(pool) {
        return;
    }
    GO.store(true, Ordering::SeqCst);
    wait(&READER_HOLDS);
}

fn reader_holds(pool: usize) {
    if !mine(pool) {
        return;
    }
    READER_HOLDS.store(true, Ordering::SeqCst);
}

/// **A producer that chose a buffer a reader then takes a reference on does
/// not write into it.** The reader holds the id of frame 1; the producer
/// commits three more frames and chooses frame 1's buffer; the reader takes its
/// reference and finds the frame whole; the producer then marks the buffer
/// filling and sees the reference.
///
/// **Canary.** `canary-producer-skips-recheck`: the producer writes into the
/// buffer the reader holds, and the reader's bytes change.
#[test]
fn a_producer_that_chose_a_buffer_a_reader_then_took_leaves_it_alone() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let p = pool();
    p.attach(0);
    put(p, 1);
    for f in [&READER_READY, &GO, &READER_HOLDS] {
        f.store(false, Ordering::SeqCst);
    }
    race::set(&race::BEFORE_REF, Some(reader_waits_for_the_producer));
    race::set(&race::AFTER_REF, Some(reader_holds));
    let reader = std::thread::spawn(move || {
        let p = the_pool();
        let f = p.acquire_latest(0).expect("a frame");
        // The producer has had its say by the time the reader looks.
        wait(&FINISHED);
        (f.seq(), f.bytes().to_vec())
    });
    wait(&READER_READY);
    for b in 2..=4u8 {
        put(p, b);
    }
    race::set(&race::BEFORE_FILL, Some(producer_waits_for_the_reader));
    if let Some(slot) = p.claim() {
        slot[..SZ].fill(0xEE);
        p.commit(SZ, 9);
    }
    race::set(&race::BEFORE_FILL, None);
    race::set(&race::BEFORE_REF, None);
    race::set(&race::AFTER_REF, None);
    FINISHED.store(true, Ordering::SeqCst);
    let (seq, bytes) = reader.join().unwrap();
    assert_eq!(seq, 1);
    assert!(bytes.iter().all(|b| *b == 1), "frame 1 changed under its reader: {bytes:?}");
}

static FINISHED: AtomicBool = AtomicBool::new(false);

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The guest's RAM as the memory objects that make it, attached one at a time.

use crate::guest::{GuestMem, OutOfRam, SegError, SegRam, MAX_SEGS};

const BASE: u64 = 0x8000_0000;
const CHUNK: usize = 0x1000;

/// `n` chunks of memory, each filled with its own index + 1, attached in
/// order to a window of `window` bytes at `BASE`.
fn ram_of(n: usize, window: u64) -> (SegRam, Vec<Vec<u8>>) {
    let mut chunks: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8 + 1; CHUNK]).collect();
    let mut r = SegRam::new();
    r.set_window(BASE, window);
    for (i, c) in chunks.iter_mut().enumerate() {
        // SAFETY: the chunk is a live Vec that outlives the SegRam in these tests.
        unsafe { r.attach(BASE + (i * CHUNK) as u64, CHUNK as u64, c.as_mut_ptr()) }.unwrap();
    }
    (r, chunks)
}

#[test]
fn the_ram_is_seen_only_when_the_whole_window_is_attached() {
    let window = 3 * CHUNK as u64;
    let mut chunks: Vec<Vec<u8>> = (0..3).map(|_| vec![0u8; CHUNK]).collect();
    let mut r = SegRam::new();
    assert_eq!(r.range(), (0, 0), "no RAM at all");
    r.set_window(BASE, window);
    assert_eq!((r.range(), r.complete()), ((0, 0), false), "a window is not memory");
    for (i, c) in chunks.iter_mut().enumerate() {
        // SAFETY: live Vecs outliving `r`.
        unsafe { r.attach(BASE + (i * CHUNK) as u64, CHUNK as u64, c.as_mut_ptr()) }.unwrap();
        let whole = i == 2;
        assert_eq!(r.complete(), whole, "after {} of 3", i + 1);
        assert_eq!(r.range(), if whole { (BASE, window) } else { (0, 0) }, "after {} of 3", i + 1);
        assert_eq!(r.attached(), ((i + 1) * CHUNK) as u64);
        // Part of the guest's memory missing: nothing is readable, even what is there.
        assert_eq!(r.read(BASE, &mut [0u8; 4]) == Ok(()), whole);
    }
}

#[test]
fn an_access_across_objects_reads_and_writes_each_side() {
    let (mut r, chunks) = ram_of(3, 3 * CHUNK as u64);
    // 8 bytes straddling the first boundary: 4 of chunk 0 (1), 4 of chunk 1 (2).
    let mut b = [0u8; 8];
    r.read(BASE + CHUNK as u64 - 4, &mut b).unwrap();
    assert_eq!(b, [1, 1, 1, 1, 2, 2, 2, 2]);
    // A write over both boundaries lands in all three.
    let data: Vec<u8> = (0..CHUNK as u32 + 8).map(|i| 0x80 + (i % 7) as u8).collect();
    r.write(BASE + CHUNK as u64 - 4, &data).unwrap();
    assert_eq!(&chunks[0][CHUNK - 4..], &data[..4]);
    assert_eq!(&chunks[1][..], &data[4..4 + CHUNK]);
    assert_eq!(&chunks[2][..4], &data[4 + CHUNK..]);
    assert_eq!(chunks[2][4], 3, "and not a byte further");
    let mut back = vec![0u8; data.len()];
    r.read(BASE + CHUNK as u64 - 4, &mut back).unwrap();
    assert_eq!(back, data);
    // The first and the last byte of the window.
    r.read(BASE, &mut b[..1]).unwrap();
    r.read(BASE + 3 * CHUNK as u64 - 1, &mut b[1..2]).unwrap();
    assert_eq!((b[0], b[1]), (1, 3), "the ends of the window are the objects' own");
}

#[test]
fn an_access_not_wholly_inside_the_window_fails_and_touches_nothing() {
    let (mut r, chunks) = ram_of(2, 2 * CHUNK as u64);
    let end = BASE + 2 * CHUNK as u64;
    let mut b = [0xEEu8; 8];
    for gpa in [BASE - 1, BASE - 8, end - 4, end, end + 100, u64::MAX - 3] {
        assert_eq!(r.read(gpa, &mut b), Err(OutOfRam), "read at {gpa:#x}");
        assert_eq!(b, [0xEE; 8], "a refused read wrote into the buffer");
        assert_eq!(r.write(gpa, &[9; 8]), Err(OutOfRam), "write at {gpa:#x}");
    }
    assert!(chunks.iter().all(|c| c.iter().all(|&x| x == c[0])), "a refused write changed memory");
    assert_eq!((chunks[0][0], chunks[1][CHUNK - 1]), (1, 2));
    // Empty accesses are fine inside, refused outside.
    assert_eq!(r.read(BASE, &mut []), Ok(()));
    assert_eq!(r.read(end + 1, &mut []), Err(OutOfRam));
}

#[test]
fn ranges_attach_in_order_from_the_base_and_inside_the_window() {
    let mut c = vec![0u8; CHUNK];
    let mut r = SegRam::new();
    r.set_window(BASE, 2 * CHUNK as u64);
    // SAFETY (all below): `c` lives through the test and these fail before touching it.
    assert_eq!(unsafe { r.attach(BASE + CHUNK as u64, CHUNK as u64, c.as_mut_ptr()) }, Err(SegError::NotNext), "a hole at the start");
    assert_eq!(unsafe { r.attach(BASE - CHUNK as u64, CHUNK as u64, c.as_mut_ptr()) }, Err(SegError::NotNext));
    unsafe { r.attach(BASE, CHUNK as u64, c.as_mut_ptr()) }.unwrap();
    assert_eq!(unsafe { r.attach(BASE, CHUNK as u64, c.as_mut_ptr()) }, Err(SegError::NotNext), "twice");
    assert_eq!(unsafe { r.attach(BASE + CHUNK as u64, 2 * CHUNK as u64, c.as_mut_ptr()) }, Err(SegError::OutOfWindow), "past the end");
    assert_eq!(unsafe { r.attach(BASE + CHUNK as u64, 0, c.as_mut_ptr()) }, Err(SegError::OutOfWindow), "empty");
    assert_eq!(r.attached(), CHUNK as u64, "refusals attach nothing");
}

#[test]
fn a_task_holds_a_bounded_number_of_objects() {
    let window = (MAX_SEGS as u64 + 1) * 16;
    let mut mem = vec![0u8; (MAX_SEGS + 1) * 16];
    let mut r = SegRam::new();
    r.set_window(BASE, window);
    for i in 0..MAX_SEGS {
        // SAFETY: slices of `mem`, live and disjoint.
        unsafe { r.attach(BASE + i as u64 * 16, 16, mem.as_mut_ptr().add(i * 16)) }.unwrap();
    }
    let last = unsafe { r.attach(BASE + MAX_SEGS as u64 * 16, 16, mem.as_mut_ptr().add(MAX_SEGS * 16)) };
    assert_eq!(last, Err(SegError::Full));
    assert!(!r.complete());
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Wave 14 (SPAWNCACHE): `image_cache::read_verified`, the one reader of an
// image by path for spawn and exec, against a medium whose stamp the test
// controls. Every test checks the property the cache must never break: the
// digest answered is the SHA-256 of the bytes in the buffer, which are the
// bytes loaded and the bytes the profile and row are picked by.

use crate::file_ops::{ContentStamp, FileOps};
use crate::image_cache::{self, read_verified};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

/// One file. `epoch` stands for the volume's write epoch; `stamps` off is a
/// backend with no stamps (the ramfs).
struct Medium {
    bytes: Mutex<Vec<u8>>,
    epoch: AtomicU64,
    stamps: AtomicBool,
    /// Rewrite the file (and move the epoch) after the next read copied it
    /// out: a write that lands while the image is read.
    write_during_read: Mutex<Option<Vec<u8>>>,
    hashed_reads: AtomicU32,
    plain_reads: AtomicU32,
}

impl Medium {
    const fn new() -> Self {
        Medium {
            bytes: Mutex::new(Vec::new()),
            epoch: AtomicU64::new(1),
            stamps: AtomicBool::new(true),
            write_during_read: Mutex::new(None),
            hashed_reads: AtomicU32::new(0),
            plain_reads: AtomicU32::new(0),
        }
    }
    fn reset(&self, bytes: &[u8]) {
        *self.bytes.lock().unwrap() = bytes.to_vec();
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.stamps.store(true, Ordering::SeqCst);
        *self.write_during_read.lock().unwrap() = None;
        self.hashed_reads.store(0, Ordering::SeqCst);
        self.plain_reads.store(0, Ordering::SeqCst);
    }
    /// The rewrite of an image in place: same cluster, same size, new bytes.
    fn rewrite(&self, bytes: &[u8]) {
        *self.bytes.lock().unwrap() = bytes.to_vec();
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
    fn copy_out(&self, dst: &mut [u8]) -> usize {
        let n = {
            let b = self.bytes.lock().unwrap();
            if b.len() >= dst.len() { return 0; }
            dst[..b.len()].copy_from_slice(&b);
            b.len()
        };
        if let Some(new) = self.write_during_read.lock().unwrap().take() {
            // The new bytes landed over what was copied, then the epoch moved.
            dst[..new.len()].copy_from_slice(&new);
            self.rewrite(&new);
        }
        n
    }
}

impl FileOps for Medium {
    fn open(&self, _: &[u8], _: u32) -> i64 { -1 }
    fn close(&self, _: i32) -> i64 { -1 }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { -1 }
    fn write(&self, _: i32, _: &[u8]) -> i64 { -1 }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { -1 }
    fn dup(&self, _: i32) -> i64 { -1 }
    fn dup2(&self, _: i32, _: i32) -> i64 { -1 }
    fn mkdir(&self, _: &[u8]) -> i64 { -1 }
    fn unlink(&self, _: &[u8]) -> i64 { -1 }
    fn readdir(&self, _: &[u8], _: u32) -> Option<([u8; 64], u32, bool)> { None }
    fn release_all(&self, _: u32) -> usize { 0 }
    fn read_whole(&self, _: &[u8], dst: &mut [u8]) -> usize {
        self.plain_reads.fetch_add(1, Ordering::SeqCst);
        self.copy_out(dst)
    }
    fn read_whole_with(&self, _: &[u8], dst: &mut [u8], sink: &mut dyn FnMut(&[u8])) -> usize {
        self.hashed_reads.fetch_add(1, Ordering::SeqCst);
        let n = self.copy_out(dst);
        // In runs, as the kernel's does.
        for run in dst[..n].chunks(700) { sink(run); }
        n
    }
    fn content_stamp(&self, _: &[u8]) -> Option<ContentStamp> {
        if !self.stamps.load(Ordering::SeqCst) { return None; }
        let size = self.bytes.lock().unwrap().len() as u64;
        Some(ContentStamp { fs: 1, epoch: self.epoch.load(Ordering::SeqCst), id: 3, size })
    }
}

static M: Medium = Medium::new();
const PATH: &[u8] = b"/fat/TOOLBOX.ELF";

fn image(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed)).collect()
}

fn sha(b: &[u8]) -> [u8; 32] { azos_sched::seccomp::image_digest(b) }

fn start(bytes: &[u8]) -> std::sync::MutexGuard<'static, ()> {
    // The suite's one lock: the digest table is process-wide, and the exec
    // tests use it too.
    let g = super::harness::serial();
    image_cache::clear();
    M.reset(bytes);
    g
}

/// **The first read hashes in the same pass and remembers; the second
/// takes the digest without hashing.** Same bytes, same stamp.
#[test]
fn a_repeat_read_of_unchanged_bytes_hits() {
    let img = image(1, 5000);
    let _g = start(&img);
    let mut buf = vec![0u8; 8192];
    let a = read_verified(&M, PATH, &mut buf).unwrap();
    assert!(!a.hit);
    assert_eq!(a.digest, sha(&img));
    assert_eq!(M.hashed_reads.load(Ordering::SeqCst), 1, "a miss hashes while it reads");
    let b = read_verified(&M, PATH, &mut buf).unwrap();
    assert!(b.hit);
    assert_eq!(b.digest, sha(&buf[..b.total]));
    assert_eq!(M.hashed_reads.load(Ordering::SeqCst), 1, "a hit does not hash");
}

/// **A file rewritten in place (same cluster, same size) is never run
/// under its old digest.** The epoch moved, so the cached digest no longer
/// applies; the new bytes are hashed.
///
/// **Canary.** `digest-cache-stale-canary` (the epoch is ignored): the old
/// digest comes back for the new bytes.
#[test]
fn a_rewritten_file_is_hashed_again() {
    let img = image(2, 5000);
    let _g = start(&img);
    let mut buf = vec![0u8; 8192];
    assert!(!read_verified(&M, PATH, &mut buf).unwrap().hit);
    let new = image(3, 5000);
    M.rewrite(&new);
    let v = read_verified(&M, PATH, &mut buf).unwrap();
    assert!(!v.hit, "the old digest must not serve new bytes");
    assert_eq!(v.digest, sha(&new));
    assert_eq!(&buf[..v.total], &new[..]);
}

/// **A write that lands while a hit reads the image: the bytes read are
/// hashed, never given the cached digest.** Otherwise the profile picked
/// for the old bytes would be applied to bytes nobody verified.
///
/// **Canary.** `digest-recheck-canary` (no stamp check after the read):
/// the cached digest of the old bytes comes back.
#[test]
fn a_write_during_a_hit_is_hashed() {
    let img = image(4, 5000);
    let _g = start(&img);
    let mut buf = vec![0u8; 8192];
    assert!(!read_verified(&M, PATH, &mut buf).unwrap().hit);
    let new = image(5, 5000);
    *M.write_during_read.lock().unwrap() = Some(new.clone());
    let v = read_verified(&M, PATH, &mut buf).unwrap();
    assert_eq!(&buf[..v.total], &new[..]);
    assert!(!v.hit);
    assert_eq!(v.digest, sha(&new), "the digest of what is in the buffer");
}

/// **A write that lands while a miss reads: the digest of what was read is
/// answered, and nothing is remembered under either stamp.**
#[test]
fn a_write_during_a_miss_is_not_remembered() {
    let img = image(6, 5000);
    let _g = start(&img);
    let mut buf = vec![0u8; 8192];
    let new = image(7, 5000);
    *M.write_during_read.lock().unwrap() = Some(new.clone());
    let v = read_verified(&M, PATH, &mut buf).unwrap();
    assert!(!v.hit);
    assert_eq!(v.digest, sha(&buf[..v.total]));
    assert_eq!(image_cache::live_entries(), 0);
    // The next read is a miss again, of the new bytes.
    let w = read_verified(&M, PATH, &mut buf).unwrap();
    assert!(!w.hit);
    assert_eq!(w.digest, sha(&new));
}

/// **A file system with no stamps is never cached.** (The ramfs, tmpfs.)
#[test]
fn no_stamp_no_cache() {
    let img = image(8, 3000);
    let _g = start(&img);
    M.stamps.store(false, Ordering::SeqCst);
    let mut buf = vec![0u8; 8192];
    for _ in 0..3 {
        let v = read_verified(&M, PATH, &mut buf).unwrap();
        assert!(!v.hit);
        assert_eq!(v.digest, sha(&img));
    }
    assert_eq!(image_cache::live_entries(), 0);
}

/// **A file that does not fit is refused, cached or not** (the whole-file
/// rule of `read_whole`).
#[test]
fn a_file_that_does_not_fit_is_refused() {
    let img = image(9, 9000);
    let _g = start(&img);
    let mut buf = vec![0u8; 8192];
    assert_eq!(read_verified(&M, PATH, &mut buf), Err(-1));
}

/// **The table is bounded and replaces the least recently used entry.**
#[test]
fn the_table_replaces_the_least_recently_used() {
    let _g = start(&image(10, 100));
    let st = |id: u64| ContentStamp { fs: 1, epoch: 1_000_000, id, size: 100 };
    for id in 0..image_cache::DIGEST_SLOTS as u64 {
        image_cache::remember(&st(id), &[id as u8; 32]);
    }
    // Touch 0, so 1 is now the oldest.
    assert_eq!(image_cache::digest_for(&st(0)), Some([0u8; 32]));
    image_cache::remember(&st(99), &[99u8; 32]);
    assert_eq!(image_cache::live_entries(), image_cache::DIGEST_SLOTS);
    assert_eq!(image_cache::digest_for(&st(1)), None, "the LRU entry went");
    assert_eq!(image_cache::digest_for(&st(0)), Some([0u8; 32]));
    assert_eq!(image_cache::digest_for(&st(99)), Some([99u8; 32]));
    // A lookup at a later epoch drops every entry of that backend.
    let later = ContentStamp { epoch: 1_000_001, ..st(0) };
    assert_eq!(image_cache::digest_for(&later), None);
    assert_eq!(image_cache::live_entries(), 0);
}

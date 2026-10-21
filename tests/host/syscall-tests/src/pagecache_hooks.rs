// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Storage L11 part B: the file layer's reads and writes through the page cache,
// against the REAL `file_map.rs` (`cache_read`, `cache_write`, `cache_writeback`,
// `cache_forget`: what the kernel's `PageCacheHooks` are made of) and the REAL
// `memobj.rs`, `pager.rs` and `pmm` on the shim arena. A file is a byte vector
// behind the real `PageBacking` seam, which counts what the cache asked of it.
// The kernel glue over them (`kernel/src/boot/pagecache.rs`: the filesystem to
// its backing, the Domain and the clocks) has no host row; it is a boot row.
//
// What each row pins, and the mutation that turns it red (by hand, 2026-10-17;
// discriminates / does not / did not compile):
//
// * `reads_cross_windows_and_a_second_read_is_a_hit`: a range over the edge of
//   a 64-page window is served from two objects, one backing call per page,
//   and nothing past the file's end. Mutation: `windows` not splitting at the
//   window edge -> red; `use_window` creating a new object on every call -> the
//   hit assert red.
// * `writes_stay_dirty_until_written_back_and_count_their_pages`: a write is in
//   the cache, not in the file; it says how many clean pages it dirtied; the
//   write-back sends the valid part of each dirty page and a second one
//   nothing. Mutation: `cache_write` returning the pages touched instead of the
//   pages made dirty -> the second write's count red.
// * `a_writeback_of_one_file_leaves_the_others_dirty`: `Some(key)` is that
//   file, `None` is every file of the backing. Mutation: `entry_of` ignoring
//   the key -> red.
// * `a_longer_file_keeps_its_pages_and_a_shorter_one_loses_them`: the contract
//   of `PageCacheHooks::read` over the registry. Mutation: `use_window` not
//   calling `memobj_paged_set_size_ref` -> the bytes after an append are the
//   zeros of the old end page: red.
// * `forgetting_a_file_never_writes_its_dirty_pages`: a forgotten dirty page is
//   gone, the file keeps its old bytes, and the frames go back. Mutation:
//   `cache_forget` calling `cache_writeback` first -> red.
// * `a_forget_from_the_middle_keeps_the_pages_before_it`.
// * `a_filesystems_files_are_forgotten_without_touching_another`: the backing
//   identifies the filesystem.
// * `the_cache_keeps_to_its_share_of_the_object_table_by_giving_idle_windows_back`:
//   twice `CACHE_OBJECTS` windows, each stored to; every store reaches the file.
//   Mutation: `use_window` not reaping when the cache is full -> `None`, the
//   store is not in the cache and the first assert is red; `close_idle` not
//   writing back (a bare release) -> the lost-store assert red.
// * `a_forget_that_is_refused_leaves_nothing_stale_to_serve_or_write`: a
//   holder is pinned, so the forget of a dirty page is refused. Until it goes
//   through the object is not read (declined to the backend), not written
//   (declined), not written back (an error) and its dirty page never reaches
//   the file; once the pin is gone the next call forgets it and the file's
//   bytes are served. Mutation: `cache_forget` not calling `mark_stale` -> the
//   read still serves the cached page: red; `settle` not calling
//   `settle_stale` -> the stale page is written back: red.
// * `a_failed_writeback_keeps_the_page_dirty_and_is_reported`: the medium says
//   no; the answer is an error, the page is dirty and goes on the next pass.
//
// Included into `mod handlers` (see `lib.rs`).

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_mm::pager::{PageBacking, PageIoError, PageKey, PAGE_KEY_LEN};
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Bytes of a cache window (64 pages).
const WIN: usize = 64 * PAGE_SIZE;

struct TFile {
    data: Mutex<Vec<u8>>,
    reads: Mutex<Vec<(u64, usize)>>,
    writes: Mutex<Vec<(u64, usize)>>,
}

const EMPTY_FILE: TFile =
    TFile { data: Mutex::new(Vec::new()), reads: Mutex::new(Vec::new()), writes: Mutex::new(Vec::new()) };

/// Files 0 and 1 of the first filesystem, file 2 of the second (the key's
/// first byte is the index, so file 2 shares no key with the others and file 3
/// shares file 0's key under the other backing).
static FILES: [TFile; 4] = [EMPTY_FILE; 4];
static FAIL_WRITES: AtomicBool = AtomicBool::new(false);

fn pattern(i: usize) -> u8 {
    (i % 251 + 1) as u8
}

fn fill_file(idx: usize, len: usize) {
    *FILES[idx].data.lock().unwrap() = (0..len).map(pattern).collect();
    FILES[idx].reads.lock().unwrap().clear();
    FILES[idx].writes.lock().unwrap().clear();
}

fn grow(idx: usize, by: usize) {
    let mut d = FILES[idx].data.lock().unwrap();
    let n = d.len();
    d.extend((n..n + by).map(pattern));
}

fn data(idx: usize) -> Vec<u8> {
    FILES[idx].data.lock().unwrap().clone()
}

fn reads(idx: usize) -> usize {
    FILES[idx].reads.lock().unwrap().len()
}

fn writes(idx: usize) -> Vec<(u64, usize)> {
    FILES[idx].writes.lock().unwrap().clone()
}

/// A filesystem's backing. `Backing(n)` serves the files `n..` by the key's
/// first byte; two of them are two filesystems (distinct addresses).
struct Backing(u8);

impl PageBacking for Backing {
    fn read_page(&self, key: &PageKey, off: u64, dst: &mut [u8]) -> Result<usize, PageIoError> {
        let f = &FILES[key.0[0] as usize];
        f.reads.lock().unwrap().push((off, dst.len()));
        let d = f.data.lock().unwrap();
        let off = off as usize;
        let n = dst.len().min(d.len().saturating_sub(off));
        dst[..n].copy_from_slice(&d[off..off + n]);
        Ok(n)
    }

    fn write_page(&self, key: &PageKey, off: u64, src: &[u8]) -> Result<(), PageIoError> {
        if FAIL_WRITES.load(Ordering::SeqCst) {
            return Err(PageIoError::Io);
        }
        let f = &FILES[key.0[0] as usize];
        f.writes.lock().unwrap().push((off, src.len()));
        let mut d = f.data.lock().unwrap();
        let off = off as usize;
        assert!(off + src.len() <= d.len(), "a write-back lengthened the file");
        d[off..off + src.len()].copy_from_slice(src);
        Ok(())
    }
}

static FS_A: Backing = Backing(1);
static FS_B: Backing = Backing(2);

fn key(idx: usize) -> PageKey {
    let mut k = [0u8; PAGE_KEY_LEN];
    k[0] = idx as u8;
    PageKey(k)
}

fn clean() {
    crate::file_map::__reset_for_tests();
    FAIL_WRITES.store(false, Ordering::SeqCst);
}

fn read(b: &'static Backing, idx: usize, size: usize, off: usize, len: usize) -> Option<Vec<u8>> {
    let mut dst = vec![0u8; len];
    crate::file_map::cache_read(b, &key(idx), size as u64, off as u64, &mut dst).map(|n| {
        dst.truncate(n);
        dst
    })
}

#[test]
fn reads_cross_windows_and_a_second_read_is_a_hit() {
    let _g = serial();
    clean();
    let size = 2 * WIN + 3 * PAGE_SIZE + 77;
    fill_file(0, size);

    let off = WIN - 100;
    let got = read(&FS_A, 0, size, off, 300).expect("served");
    assert!(got.iter().enumerate().all(|(i, &b)| b == pattern(off + i)), "the file's bytes");
    assert_eq!(reads(0), 2, "one backing call for each of the two pages");
    assert_eq!(read(&FS_A, 0, size, off, 300), Some(got), "the same bytes");
    assert_eq!(reads(0), 2, "a second read is a hit");

    // The end of the file clamps; at or past it is empty.
    assert_eq!(read(&FS_A, 0, size, size - 10, 100).map(|v| v.len()), Some(10));
    assert_eq!(read(&FS_A, 0, size, size, 100).map(|v| v.len()), Some(0));
    assert_eq!(read(&FS_A, 0, size, size + 5, 100).map(|v| v.len()), Some(0));
    // A range over three windows.
    let all = read(&FS_A, 0, size, 0, size).expect("whole file");
    assert!(all.iter().enumerate().all(|(i, &b)| b == pattern(i)));
    clean();
}

#[test]
fn writes_stay_dirty_until_written_back_and_count_their_pages() {
    let _g = serial();
    clean();
    let size = 2 * WIN + PAGE_SIZE;
    fill_file(0, size);
    let src = vec![0xA5u8; 300];
    let off = WIN - 100;

    // Over the window edge: two clean pages made dirty.
    assert_eq!(crate::file_map::cache_write(&FS_A, &key(0), size as u64, off as u64, &src), Some((300, 2)));
    assert!(writes(0).is_empty(), "in the cache, not in the file");
    assert_ne!(data(0)[off], 0xA5);
    // Again: both dirty already; one more clean page too.
    assert_eq!(crate::file_map::cache_write(&FS_A, &key(0), size as u64, off as u64, &src), Some((300, 0)));
    assert_eq!(
        crate::file_map::cache_write(&FS_A, &key(0), size as u64, (WIN + 5 * PAGE_SIZE) as u64, &src[..10]),
        Some((10, 1))
    );
    // The cache reads its own bytes.
    assert_eq!(read(&FS_A, 0, size, off, 300), Some(src.clone()));

    assert_eq!(crate::file_map::cache_writeback(&FS_A, Some(&key(0))), Ok(()));
    let mut w = writes(0);
    w.sort();
    assert_eq!(w, vec![(((WIN - PAGE_SIZE) as u64), PAGE_SIZE), (WIN as u64, PAGE_SIZE), ((WIN + 5 * PAGE_SIZE) as u64, PAGE_SIZE)]);
    assert!(data(0)[off..off + 300].iter().all(|&b| b == 0xA5), "the file has it now");
    assert_eq!(crate::file_map::cache_writeback(&FS_A, Some(&key(0))), Ok(()));
    assert_eq!(writes(0).len(), 3, "a clean cache writes nothing");
    clean();
}

#[test]
fn a_writeback_of_one_file_leaves_the_others_dirty() {
    let _g = serial();
    clean();
    fill_file(0, 3 * PAGE_SIZE);
    fill_file(1, 3 * PAGE_SIZE);
    let size = 3 * PAGE_SIZE as u64;
    assert!(crate::file_map::cache_write(&FS_A, &key(0), size, 0, &[1; 8]).is_some());
    assert!(crate::file_map::cache_write(&FS_A, &key(1), size, 0, &[2; 8]).is_some());

    assert_eq!(crate::file_map::cache_writeback(&FS_A, Some(&key(0))), Ok(()));
    assert_eq!((writes(0).len(), writes(1).len()), (1, 0), "only the file named");
    assert_eq!(data(1)[0], pattern(0), "the other file still has its old bytes");
    assert_eq!(crate::file_map::cache_writeback(&FS_A, None), Ok(()));
    assert_eq!((writes(0).len(), writes(1).len()), (1, 1), "every file of the filesystem");
    assert_eq!(data(1)[0], 2);
    clean();
}

#[test]
fn a_longer_file_keeps_its_pages_and_a_shorter_one_loses_them() {
    let _g = serial();
    clean();
    let size = 3 * PAGE_SIZE + 100;
    fill_file(0, size);
    assert_eq!(read(&FS_A, 0, size, 0, size).map(|v| v.len()), Some(size));
    assert_eq!(reads(0), 4);

    // An append behind the cache: the file layer says the new length.
    grow(0, 300);
    let longer = size + 300;
    let got = read(&FS_A, 0, longer, 0, longer).expect("served");
    assert!(got.iter().enumerate().all(|(i, &b)| b == pattern(i)), "the appended bytes are the file's, not zeros");
    assert_eq!(reads(0), 5, "the page that held the old end was read again, the others were kept");

    // Cut: another object, every page filled again.
    let shorter = PAGE_SIZE + 50;
    let got = read(&FS_A, 0, shorter, 0, longer).expect("served");
    assert_eq!(got.len(), shorter, "nothing past the new end");
    assert_eq!(reads(0), 7, "the two pages of the new length");
    // A write inside the shorter file, then the file is lengthened: dirt first, at the old length.
    assert!(crate::file_map::cache_write(&FS_A, &key(0), shorter as u64, 3, &[0x77; 4]).is_some());
    grow(0, 10);
    assert!(read(&FS_A, 0, shorter + 10, 0, 8).is_some());
    assert_eq!(data(0)[3], 0x77, "the dirty page reached the file before the file was re-attached");
    clean();
}

#[test]
fn forgetting_a_file_never_writes_its_dirty_pages() {
    let _g = serial();
    clean();
    let size = WIN + 2 * PAGE_SIZE;
    fill_file(0, size);
    let before = azos_mm::shim_pages_in_use();
    assert!(crate::file_map::cache_write(&FS_A, &key(0), size as u64, 5, &[0xEE; 4]).is_some());
    assert!(crate::file_map::cache_write(&FS_A, &key(0), size as u64, (WIN + 5) as u64, &[0xEE; 4]).is_some());

    assert!(crate::file_map::cache_forget(&FS_A, Some(&key(0)), 0));
    assert!(writes(0).is_empty(), "a forgotten dirty page was written");
    assert_eq!(data(0)[5], pattern(5));
    assert_eq!(crate::file_map::cache_writeback(&FS_A, None), Ok(()));
    assert!(writes(0).is_empty());
    assert_eq!(azos_mm::shim_pages_in_use(), before, "the frames went back with the idle objects");
    let got = read(&FS_A, 0, size, 0, 8).expect("served again");
    assert_eq!(got[5], pattern(5), "filled again from the file");
    clean();
}

#[test]
fn a_forget_from_the_middle_keeps_the_pages_before_it() {
    let _g = serial();
    clean();
    let size = 4 * PAGE_SIZE;
    fill_file(0, size);
    for p in 0..4 {
        assert!(crate::file_map::cache_write(&FS_A, &key(0), size as u64, (p * PAGE_SIZE) as u64, &[0xC3]).is_some());
    }
    assert!(crate::file_map::cache_forget(&FS_A, Some(&key(0)), (2 * PAGE_SIZE + 1) as u64));
    assert_eq!(crate::file_map::cache_writeback(&FS_A, None), Ok(()));
    let d = data(0);
    assert_eq!((d[0], d[PAGE_SIZE]), (0xC3, 0xC3), "the pages before the cut are written");
    assert_eq!((d[2 * PAGE_SIZE], d[3 * PAGE_SIZE]), (pattern(2 * PAGE_SIZE), pattern(3 * PAGE_SIZE)), "from the page holding the byte they are gone");
    clean();
}

#[test]
fn a_filesystems_files_are_forgotten_without_touching_another() {
    let _g = serial();
    clean();
    let size = 2 * PAGE_SIZE;
    fill_file(0, size);
    fill_file(3, size);
    // File 0 of filesystem A and file 3 of B: two keys, two backings.
    assert!(crate::file_map::cache_write(&FS_A, &key(0), size as u64, 0, &[1]).is_some());
    let mut kb = key(3);
    kb.0[1] = 1;
    assert!(crate::file_map::cache_write(&FS_B, &kb, size as u64, 0, &[2]).is_some());

    assert!(crate::file_map::cache_forget(&FS_A, None, 0), "an unmount of A");
    assert_eq!(crate::file_map::cache_writeback(&FS_B, None), Ok(()));
    assert_eq!(writes(3).len(), 1, "B's dirty page survived A's forget");
    assert_eq!(data(3)[0], 2);
    assert_eq!(crate::file_map::cache_writeback(&FS_A, None), Ok(()));
    assert!(writes(0).is_empty(), "A's dirty page did not");
    clean();
}

#[test]
fn a_failed_writeback_keeps_the_page_dirty_and_is_reported() {
    let _g = serial();
    clean();
    let size = 2 * PAGE_SIZE;
    fill_file(0, size);
    assert!(crate::file_map::cache_write(&FS_A, &key(0), size as u64, 1, &[0x99]).is_some());
    FAIL_WRITES.store(true, Ordering::SeqCst);
    assert_eq!(crate::file_map::cache_writeback(&FS_A, Some(&key(0))), Err(()));
    assert_eq!(data(0)[1], pattern(1));
    FAIL_WRITES.store(false, Ordering::SeqCst);
    assert_eq!(crate::file_map::cache_writeback(&FS_A, Some(&key(0))), Ok(()), "dirty again, written on the next pass");
    assert_eq!(data(0)[1], 0x99);
    clean();
}

#[test]
fn the_cache_keeps_to_its_share_of_the_object_table_by_giving_idle_windows_back() {
    let _g = serial();
    clean();
    // Twice the windows the file layer may hold: each store is in a window of
    // its own, so the first ones have to be written back and closed for the
    // last ones to have an object.
    let windows = 2 * crate::file_map::CACHE_OBJECTS;
    let size = windows * WIN;
    fill_file(0, size);
    for w in 0..windows {
        let at = (w * WIN + 3) as u64;
        assert_eq!(
            crate::file_map::cache_write(&FS_A, &key(0), size as u64, at, &[0xD0 + w as u8]),
            Some((1, 1)),
            "window {w} had no object"
        );
    }
    assert_eq!(crate::file_map::cache_writeback(&FS_A, None), Ok(()));
    let d = data(0);
    for w in 0..windows {
        assert_eq!(d[w * WIN + 3], 0xD0 + w as u8, "window {w}'s store was lost with its object");
    }
    // The whole file reads back through the same few objects.
    let all = read(&FS_A, 0, size, 0, size).expect("served");
    assert_eq!(all.len(), size);
    assert!(all.iter().enumerate().all(|(i, &b)| b == d[i]));
    clean();
}

#[test]
fn a_forget_that_is_refused_leaves_nothing_stale_to_serve_or_write() {
    use azos_ipc::memobj;
    let _g = serial();
    clean();
    let size = 2 * PAGE_SIZE;
    fill_file(0, size);
    assert!(crate::file_map::cache_write(&FS_A, &key(0), size as u64, 5, &[0xEE; 4]).is_some());
    let obj = crate::file_map::__object_for_tests(&FS_A, &key(0), 0).expect("the window is cached");
    // A mapper that is pinned: the forget cannot unmap the pages safely.
    assert!(memobj::memobj_acquire_ref(77, obj).is_ok());
    assert_eq!(memobj::memobj_pin_ref(77, obj), Ok(true));

    // The forget waits a while (it sleeps between tries) before it gives up.
    // A sleep passes the time it asked for (the host clock only moves when told).
    azos_sched::shim_arm_block_outcome(azos_sched::BlockOutcome::Returned);
    let clock = std::sync::atomic::AtomicU64::new(0);
    azos_sched::shim_set_block_hook(Some(Box::new(move |_| {
        azos_drv_irqchip::clint::set_time(clock.fetch_add(1 << 24, Ordering::SeqCst) + (1 << 24));
    })));
    assert!(!crate::file_map::cache_forget(&FS_A, Some(&key(0)), 0), "refused: the holder is pinned");
    // The file was replaced behind the cache.
    *FILES[0].data.lock().unwrap() = vec![0x77; size];
    assert!(read(&FS_A, 0, size, 0, 8).is_none(), "the stale page is not served");
    assert!(crate::file_map::cache_write(&FS_A, &key(0), size as u64, 0, &[1]).is_none(), "nor stored to");
    assert_eq!(crate::file_map::cache_writeback(&FS_A, Some(&key(0))), Err(()), "nor written back");
    assert_eq!(crate::file_map::cache_writeback(&FS_A, None), Err(()));
    azos_sched::shim_disarm_block_outcome();
    azos_sched::shim_set_block_hook(None);
    azos_drv_irqchip::clint::set_time(0);
    assert!(writes(0).is_empty(), "the stale dirty page reached the file");
    assert_eq!(data(0)[5], 0x77);

    // The pin goes (the holder exits, `memobj_release_all`): the next call carries the forget out.
    memobj::memobj_release_all(77);
    assert_eq!(crate::file_map::cache_writeback(&FS_A, Some(&key(0))), Ok(()));
    assert!(writes(0).is_empty(), "the stale dirty page was dropped, not written");
    let got = read(&FS_A, 0, size, 0, 8).expect("served again");
    assert_eq!(got[5], 0x77, "filled from the file that is there now");
    clean();
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the page cache's backing seam (storage L11, part A): the REAL
//! `crates/core/mm/src/page_backing.rs`, which a `MemKind::Paged` MemObj fills
//! its frames from and writes them back through, over a byte-vector file.
//!
//! What is here is the arithmetic and the contract of the seam: where the file
//! ends inside a page, what the backing is asked for, and what a failure
//! leaves. The object table's half (a cache page IS a MemObj frame, the clean
//! drop, the dirty write-back, the shared mapping) is in `crates/core/ipc/src/memobj.rs`'s
//! tests (`tests/host/ipc-tests`); the file layer's half is
//! `tests/host/fs-tests/src/page_cache.rs`.
//!
//! Canaries (by hand, 2026-10-16; discriminates / does not / did not compile):
//! * `valid_len` not clamping to the end of the file: `valid_len_is_the_part_of_a_page_inside_the_file` red.
//! * `fill_page` asking the backing for the whole page: `a_fill_asks_the_backing_for_the_valid_part_only` red.
//! * `fill_page` not zeroing after a short read: `a_short_read_is_zero_filled` red.
//! * `write_back_page` writing the whole page: `a_write_back_sends_the_valid_part_only` red.
//! * `write_back_page` calling the backing for a page past the end:
//!   `a_page_past_the_end_is_never_written` red.

#[path = "../../../../crates/core/mm/src/page_backing.rs"]
mod page_backing;

use page_backing::{fill_page, valid_len, write_back_page, PageBacking, PageIoError, PageKey, PAGE_KEY_LEN};
use std::cell::RefCell;

/// A file of bytes, and what the cache asked of it.
struct File {
    data: RefCell<Vec<u8>>,
    /// `(offset, length)` of every read and every write.
    reads: RefCell<Vec<(u64, usize)>>,
    writes: RefCell<Vec<(u64, usize)>>,
    /// Answer reads with at most this many bytes.
    short: Option<usize>,
    fail: bool,
}

// SAFETY: each test owns its file and runs on one thread; `Sync` is only the
// trait's bound.
unsafe impl Sync for File {}

impl File {
    fn new(len: usize) -> File {
        File {
            data: RefCell::new((0..len).map(|p| (p % 251 + 1) as u8).collect()),
            reads: RefCell::new(Vec::new()),
            writes: RefCell::new(Vec::new()),
            short: None,
            fail: false,
        }
    }
}

impl PageBacking for File {
    fn read_page(&self, _k: &PageKey, off: u64, dst: &mut [u8]) -> Result<usize, PageIoError> {
        self.reads.borrow_mut().push((off, dst.len()));
        if self.fail {
            return Err(PageIoError::Io);
        }
        let d = self.data.borrow();
        let off = off as usize;
        let n = dst.len().min(d.len().saturating_sub(off)).min(self.short.unwrap_or(usize::MAX));
        dst[..n].copy_from_slice(&d[off..off + n]);
        Ok(n)
    }

    fn write_page(&self, _k: &PageKey, off: u64, src: &[u8]) -> Result<(), PageIoError> {
        self.writes.borrow_mut().push((off, src.len()));
        if self.fail {
            return Err(PageIoError::Io);
        }
        let mut d = self.data.borrow_mut();
        let off = off as usize;
        assert!(off + src.len() <= d.len(), "a write-back lengthened the file");
        d[off..off + src.len()].copy_from_slice(src);
        Ok(())
    }
}

const KEY: PageKey = PageKey([0x5A; PAGE_KEY_LEN]);

/// Every granule the translation code can be built with.
const PAGES: [usize; 3] = [4096, 16384, 65536];

#[test]
fn valid_len_is_the_part_of_a_page_inside_the_file() {
    for p in PAGES {
        let pb = p as u64;
        assert_eq!(valid_len(10 * pb, 0, p), p, "a page inside the file");
        assert_eq!(valid_len(10 * pb, 9 * pb, p), p, "the last whole page");
        assert_eq!(valid_len(10 * pb + 100, 10 * pb, p), 100, "the tail page");
        assert_eq!(valid_len(10 * pb, 10 * pb, p), 0, "the page after the last byte");
        assert_eq!(valid_len(10 * pb, 11 * pb, p), 0, "a page far past it");
        assert_eq!(valid_len(0, 0, p), 0, "an empty file");
        assert_eq!(valid_len(1, 0, p), 1);
        assert_eq!(valid_len(u64::MAX, u64::MAX - pb, p), p, "no overflow at the top of the file range");
        assert_eq!(valid_len(u64::MAX, u64::MAX, p), 0);
    }
}

#[test]
fn a_fill_asks_the_backing_for_the_valid_part_only() {
    for p in PAGES {
        let f = File::new(3 * p + 100);
        let mut page = vec![0xFFu8; p];
        fill_page(&f, &KEY, 3 * p as u64, f.data.borrow().len() as u64, &mut page).unwrap();
        assert_eq!(f.reads.borrow().as_slice(), &[(3 * p as u64, 100)], "{p}: only the file's bytes are asked for");
        assert_eq!(&page[..100], &f.data.borrow()[3 * p..], "{p}");
        assert!(page[100..].iter().all(|&b| b == 0), "{p}: zeros after the file's end, over whatever the frame held");
    }
}

#[test]
fn a_page_past_the_end_is_zero_and_asks_for_nothing() {
    let p = PAGES[0];
    let f = File::new(p);
    let mut page = vec![0xFFu8; p];
    fill_page(&f, &KEY, p as u64, p as u64, &mut page).unwrap();
    assert!(f.reads.borrow().is_empty(), "the backing was asked past the end of the file");
    assert!(page.iter().all(|&b| b == 0));
}

#[test]
fn a_short_read_is_zero_filled() {
    let p = PAGES[0];
    let mut f = File::new(4 * p);
    f.short = Some(10);
    let mut page = vec![0xFFu8; p];
    fill_page(&f, &KEY, p as u64, 4 * p as u64, &mut page).unwrap();
    assert_eq!(&page[..10], &f.data.borrow()[p..p + 10]);
    assert!(page[10..].iter().all(|&b| b == 0), "the backing answered 10 bytes; the rest of the page is zero");
}

#[test]
fn a_failing_backing_fails_the_fill_and_the_write_back() {
    let p = PAGES[0];
    let mut f = File::new(2 * p);
    f.fail = true;
    let mut page = vec![0u8; p];
    assert_eq!(fill_page(&f, &KEY, 0, 2 * p as u64, &mut page), Err(PageIoError::Io));
    assert_eq!(write_back_page(&f, &KEY, 0, 2 * p as u64, &page), Err(PageIoError::Io));
}

#[test]
fn a_write_back_sends_the_valid_part_only() {
    for p in PAGES {
        let f = File::new(2 * p + 100);
        let mut page = vec![0xEEu8; p];
        page[0] = 0x11;
        let len = f.data.borrow().len() as u64;
        write_back_page(&f, &KEY, 2 * p as u64, len, &page).unwrap();
        assert_eq!(f.writes.borrow().as_slice(), &[(2 * p as u64, 100)], "{p}");
        assert_eq!(f.data.borrow().len(), 2 * p + 100, "{p}: the file did not grow");
        assert_eq!(f.data.borrow()[2 * p], 0x11);
        // A whole page inside the file goes whole.
        f.writes.borrow_mut().clear();
        write_back_page(&f, &KEY, 0, len, &page).unwrap();
        assert_eq!(f.writes.borrow().as_slice(), &[(0, p)], "{p}");
    }
}

#[test]
fn a_page_past_the_end_is_never_written() {
    let p = PAGES[0];
    let f = File::new(p);
    write_back_page(&f, &KEY, p as u64, p as u64, &vec![1u8; p]).unwrap();
    write_back_page(&f, &KEY, 5 * p as u64, p as u64, &vec![1u8; p]).unwrap();
    assert!(f.writes.borrow().is_empty(), "a page wholly past the end reached the file");
}

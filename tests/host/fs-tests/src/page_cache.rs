// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the file layer's side of the page cache (storage L11, part A):
//! a `MemKind::Paged` MemObj fills and writes back its pages through the
//! `PageBacking` callback (`crates/core/mm/src/page_backing.rs`), and
//! `azos_fs::FsPageBacking` (`crates/fs/fs/src/pagecache.rs`, the REAL source,
//! pulled with `#[path]` like the other file-layer modules) implements it over
//! a filesystem's positional `read_at` / `write_at`.
//!
//! The rows run the real `FsPageBacking` over the REAL `TmpFs` and `Fat32Fs`.
//! What they prove is the key conversion and the write mapping (a short or
//! refused write is an error), and the seam underneath: the real backends
//! honour the contract the cache relies on at page offsets, at every granule
//! the translation code can have, and the cache's fill and write-back (the
//! real `fill_page` / `write_back_page`) leave a file's length alone. The
//! object table's half is in `crates/core/ipc/src/memobj.rs`'s tests; the arithmetic
//! alone is in `tests/host/mm-tests/src/page_cache.rs`.
//!
//! Canaries (by hand, 2026-10-16; discriminates / does not / did not compile):
//! * `write_back_page` sending the whole page: both `*_does_not_lengthen_the_file` rows red.
//! * `fill_page` not zeroing after the file's end: both `*_fill_*` rows red.
//! * `FsPageBacking::write_page` mapping a refused write to `Ok`: `a_refused_write_is_an_error` red; a short one: `a_short_write_is_an_error` red.
//! * `FsPageBacking::page_key` or the read/write key conversion altering a byte: `the_page_key_is_the_inode_key_bytes` red.
//!
//! Wired into the suite by `mod page_cache;` in `src/lib.rs`.

#![cfg(test)]

use super::pagecache::FsPageBacking;
use super::{fat32, image::*, serial, tmpfs, vfs};
use azos_mm::pager::{fill_page, write_back_page, PageBacking, PageIoError, PageKey, PAGE_KEY_LEN};
use vfs::FileSystem;

use fat32::FAT32_FS as FAT;

/// The cache's granules: 512 stands for "not the 4096 the old code assumed".
const GRANULES: [usize; 2] = [512, 4096];

fn bytes(len: usize) -> Vec<u8> {
    (0..len).map(|p| (p % 251 + 1) as u8).collect()
}

#[test]
fn the_cache_key_is_exactly_the_inode_key() {
    assert_eq!(vfs::INODE_KEY_LEN, PAGE_KEY_LEN, "FsPageBacking copies the key as bytes");
}

/// The key a file is named by in the cache is the filesystem's own bytes, and
/// the backing finds the file by them: a read through `page_key` returns the
/// file's content, not another file's.
#[test]
fn the_page_key_is_the_inode_key_bytes() {
    let _g = serial();
    let (a, b) = (b"pgkeya", b"pgkeyb");
    let ka = tmpfs::TmpFs.key_for(a).unwrap();
    let kb = tmpfs::TmpFs.key_for(b).unwrap();
    tmpfs::TmpFs.write_at(&ka, 0, b"AAAA").unwrap();
    tmpfs::TmpFs.write_at(&kb, 0, b"BBBBBB").unwrap();
    assert_eq!(FsPageBacking::page_key(&ka).0, ka.bytes);
    let back = FsPageBacking::new(&tmpfs::TMPFS_FS);
    let mut dst = [0u8; 8];
    assert_eq!(back.read_page(&FsPageBacking::page_key(&ka), 0, &mut dst), Ok(4));
    assert_eq!(&dst[..4], b"AAAA");
    assert_eq!(back.read_page(&FsPageBacking::page_key(&kb), 0, &mut dst), Ok(6));
    assert_eq!(&dst[..6], b"BBBBBB");
    // A write lands in the file the key names.
    back.write_page(&FsPageBacking::page_key(&kb), 2, b"xy").unwrap();
    assert_eq!(back.read_page(&FsPageBacking::page_key(&kb), 0, &mut dst), Ok(6));
    assert_eq!(&dst[..6], b"BBxyBB");
    let _ = (tmpfs::tmpfs_unlink(a), tmpfs::tmpfs_unlink(b));
}

/// Run the fill and write-back rows against the file `key` names on `fs`,
/// which holds `len = 2 * g + 100` bytes of `bytes(len)`; `size_of` reads the
/// file's length back from the filesystem.
fn rows(fs: &'static dyn FileSystem, key: &vfs::InodeKey, g: usize, size_of: &dyn Fn() -> u64) {
    let b = FsPageBacking::new(fs);
    let pk = PageKey(key.bytes);
    let len = 2 * g + 100;
    let want = bytes(len);
    assert_eq!(size_of(), len as u64);

    // Fill: a whole page, then the straddling page (zeros after the end),
    // over a frame that held something else.
    let mut page = vec![0xFFu8; g];
    fill_page(&b, &pk, g as u64, len as u64, &mut page).unwrap();
    assert_eq!(page, want[g..2 * g], "{g}: a page inside the file is the file's bytes");
    let mut page = vec![0xFFu8; g];
    fill_page(&b, &pk, 2 * g as u64, len as u64, &mut page).unwrap();
    assert_eq!(&page[..100], &want[2 * g..], "{g}: the straddling page");
    assert!(page[100..].iter().all(|&p| p == 0), "{g}: zeros after the file's end");
    let mut page = vec![0xFFu8; g];
    fill_page(&b, &pk, 3 * g as u64, len as u64, &mut page).unwrap();
    assert!(page.iter().all(|&p| p == 0), "{g}: a page past the end is zero");

    // Write-back of the straddling page: junk after the end must not reach
    // the file, and the valid part must.
    let mut page = vec![0xEEu8; g];
    page[..100].iter_mut().enumerate().for_each(|(i, p)| *p = (i % 7) as u8 + 100);
    write_back_page(&b, &pk, 2 * g as u64, len as u64, &page).unwrap();
    assert_eq!(size_of(), len as u64, "{g}: a write-back lengthened the file");
    let mut back = vec![0u8; 2 * g + 200];
    let n = fs.read_at(key, 0, &mut back);
    assert_eq!(n, len, "{g}");
    assert_eq!(&back[..2 * g], &want[..2 * g], "{g}: the earlier pages are untouched");
    assert_eq!(&back[2 * g..len], &page[..100], "{g}: the valid part went to the file");

    // A page wholly past the end is never written.
    write_back_page(&b, &pk, 4 * g as u64, len as u64, &vec![0x11u8; g]).unwrap();
    assert_eq!(size_of(), len as u64, "{g}: a page past the end reached the file");

    // A whole page in the middle goes whole.
    let mut mid = vec![0u8; g];
    fill_page(&b, &pk, g as u64, len as u64, &mut mid).unwrap();
    mid.iter_mut().for_each(|p| *p ^= 0x5A);
    write_back_page(&b, &pk, g as u64, len as u64, &mid).unwrap();
    let mut again = vec![0u8; g];
    fill_page(&b, &pk, g as u64, len as u64, &mut again).unwrap();
    assert_eq!(again, mid, "{g}: what the cache wrote back is what the next fill reads");
}

#[test]
fn a_tmpfs_file_fills_and_writes_back_by_page_and_does_not_lengthen_the_file() {
    let _g = serial();
    for g in GRANULES {
        assert!(3 * g + 100 <= tmpfs::TMPFS_MAX_BYTES, "TMPFS_MAX_KB is too small for the {g} row");
        let name = format!("pgc{g}");
        let key = tmpfs::TmpFs.key_for(name.as_bytes()).expect("a legal tmpfs name");
        assert_eq!(tmpfs::TmpFs.write_at(&key, 0, &bytes(2 * g + 100)), Ok(2 * g + 100));
        rows(&tmpfs::TMPFS_FS, &key, g, &|| tmpfs::tmpfs_size(name.as_bytes()).unwrap() as u64);
        let _ = tmpfs::tmpfs_unlink(name.as_bytes());
    }
}

#[test]
fn a_fat32_file_fills_and_writes_back_by_page_and_does_not_lengthen_the_file() {
    let _g = serial();
    for g in GRANULES {
        super::swap_medium(build(&Geom::default()));
        assert_eq!(fat32::fat32_mount(), Ok(()));
        let name83 = *b"PAGES   BIN";
        assert_eq!(fat32::fat32_write_file(&name83, &bytes(2 * g + 100)), Ok(()));
        let key = FAT.key_for(b"pages.bin").expect("a legal 8.3 name");
        rows(&FAT, &key, g, &|| FAT.stat(&key).expect("the file is there").size);
    }
}

/// A write the filesystem refuses is an error to the cache, which keeps the
/// page dirty: `FsPageBacking` must not call it a success.
#[test]
fn a_refused_write_is_an_error() {
    let _g = serial();
    let name = b"pgcshort";
    let key = tmpfs::TmpFs.key_for(name).unwrap();
    tmpfs::TmpFs.write_at(&key, 0, &bytes(16)).unwrap();
    let b = FsPageBacking::new(&tmpfs::TMPFS_FS);
    // A write the filesystem refuses outright: past the tmpfs ceiling.
    let past = tmpfs::TMPFS_MAX_BYTES as u64;
    assert_eq!(b.write_page(&PageKey(key.bytes), past, &[1u8; 64]), Err(PageIoError::Io));
    let _ = tmpfs::tmpfs_unlink(name);
}

/// A filesystem that takes half of what it is given: `write_page` is "all of
/// it or an error", so a short `write_at` must come back as `Io` (the cache
/// then keeps the page dirty instead of calling half a page written back).
struct HalfWrites;

impl FileSystem for HalfWrites {
    fn fs_type(&self) -> u32 { 0 }
    fn mount(&self) -> Result<(), ()> { Ok(()) }
    fn sync(&self) -> Result<(), ()> { Ok(()) }
    fn key_for(&self, _: &[u8]) -> Option<vfs::InodeKey> { None }
    fn stat(&self, _: &vfs::InodeKey) -> Option<vfs::FileStat> { None }
    fn read_all(&self, _: &vfs::InodeKey, _: &vfs::FileStat, _: &mut [u8]) -> usize { 0 }
    fn write_all(&self, _: &vfs::InodeKey, _: &[u8]) -> Result<(), ()> { Err(()) }
    fn unlink(&self, _: &vfs::InodeKey) -> Result<(), ()> { Err(()) }
    fn read_at(&self, _: &vfs::InodeKey, _: u64, _: &mut [u8]) -> usize { 0 }
    fn write_at(&self, _: &vfs::InodeKey, _: u64, src: &[u8]) -> Result<usize, ()> { Ok(src.len() / 2) }
}

static HALF: HalfWrites = HalfWrites;

#[test]
fn a_short_write_is_an_error() {
    let b = FsPageBacking::new(&HALF);
    let key = PageKey([7u8; PAGE_KEY_LEN]);
    assert_eq!(b.write_page(&key, 0, &[1u8; 64]), Err(PageIoError::Io));
}

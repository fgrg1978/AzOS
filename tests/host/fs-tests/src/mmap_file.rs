// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the file layer's half of a file `mmap` (front mmap-file,
//! storage L11 part B): `azos_fs::page_source` (`crates/fs/src/pagecache.rs`,
//! the REAL source, with `vfs::fd_file_backing`), which turns an open
//! descriptor into the page cache's name for its file.
//!
//! What the rows pin: two opens of one file name ONE cache source (same key,
//! same backing value: the cache registry finds one object for both), two files
//! name two; a descriptor opened for writing is writable for a shared mapping
//! and a read-only one is not; a file that is not a backend's (a ramfs file),
//! a closed descriptor and an out-of-range one have no source; the size is the
//! file's now; and the source drives the real `fill_page` / `write_back_page`
//! over the real backends, a private copy never writing (the cache only writes
//! back what a shared mapping made dirty).
//!
//! Canaries (by hand, 2026-10-17; discriminates / does not / did not compile):
//! * `page_source` building the key from anything but the inode's own bytes:
//!   `two_opens_of_a_file_name_one_source` and the FAT32 row red.
//! * `backing_of` making a new value per call: the same two rows red (backing
//!   identity).
//! * `writable` not following the descriptor's mode: `a_read_only_open_is_not_writable`
//!   and the FAT32 row red.
//! * Do not discriminate: the `streaming` test in `page_source` (every backend
//!   this tree mounts streams, so no host row reaches the refusal); `!b.ro_stream`
//!   (a read-only stream has no write permission anyway); the inode-type and
//!   in-use tests of `fd_file_backing` (a ramfs file, a directory and a closed
//!   descriptor are all refused by `b.fs?` or an empty slot first: the
//!   refusal rows below pin the answer, not the line); the pool's ninth
//!   filesystem (`MAX_MOUNTS` is 4: unreachable).
//!
//! Wired into the suite by `mod mmap_file;` in `src/lib.rs`.

#![cfg(test)]

use super::pagecache::PageSource;
use super::{serial, vfs};
use azos_mm::pager::{fill_page, write_back_page};
use vfs::{O_CREAT, O_RDONLY, O_RDWR};

fn bytes(len: usize) -> Vec<u8> {
    (0..len).map(|p| (p % 251 + 1) as u8).collect()
}

/// A blank FAT32 volume mounted at `/fat` (the one mount this suite always has;
/// a mount of its own would use up a slot the other suites count on).
fn volume() {
    super::vfs_open_close::fresh_volume();
}

/// Create `name` beneath `root` holding `data`, and leave it closed.
fn make(root: &[u8], name: &[u8], data: &[u8]) {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open_at(&mut t, root, name, O_CREAT | O_RDWR);
    assert!(fd >= 0, "create {:?}", String::from_utf8_lossy(name));
    assert_eq!(vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()), data.len() as i32);
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
}

fn page_source_of<const N: usize>(t: &vfs::FdTableN<N>, fd: i32) -> Option<PageSource> {
    super::pagecache::page_source(t, fd)
}

fn same_backing(a: &PageSource, b: &PageSource) -> bool {
    a.backing as *const dyn azos_mm::pager::PageBacking as *const () as usize
        == b.backing as *const dyn azos_mm::pager::PageBacking as *const () as usize
}

#[test]
fn two_opens_of_a_file_name_one_source() {
    let _g = serial();
    volume();
    make(b"/fat", b"ONE.BIN", &bytes(5000));
    make(b"/fat", b"TWO.BIN", &bytes(10));
    let mut t = vfs::ScratchFds::new();
    let a = vfs::vfs_open_at(&mut t, b"/fat", b"ONE.BIN", O_RDWR);
    let b = vfs::vfs_open_at(&mut t, b"/fat", b"ONE.BIN", O_RDONLY);
    let c = vfs::vfs_open_at(&mut t, b"/fat", b"TWO.BIN", O_RDONLY);
    assert!(a >= 0 && b >= 0 && c >= 0);
    let (sa, sb, sc) = (page_source_of(&t, a).unwrap(), page_source_of(&t, b).unwrap(), page_source_of(&t, c).unwrap());
    assert_eq!(sa.key, sb.key, "one file, one name in the cache");
    assert_ne!(sa.key, sc.key, "two files, two names");
    assert!(same_backing(&sa, &sb) && same_backing(&sa, &sc), "one filesystem, one backing value");
    assert_eq!((sa.size, sc.size), (5000, 10), "the size is the file's now");
    for fd in [a, b, c] {
        vfs::vfs_close(&mut t, fd);
    }
}

#[test]
fn a_read_only_open_is_not_writable() {
    let _g = serial();
    volume();
    make(b"/fat", b"PERM.BIN", &bytes(100));
    let mut t = vfs::ScratchFds::new();
    let rw = vfs::vfs_open_at(&mut t, b"/fat", b"PERM.BIN", O_RDWR);
    let ro = vfs::vfs_open_at(&mut t, b"/fat", b"PERM.BIN", O_RDONLY);
    assert!(page_source_of(&t, rw).unwrap().writable);
    assert!(!page_source_of(&t, ro).unwrap().writable, "a shared writable mapping needs a descriptor opened for writing");
    for fd in [rw, ro] {
        vfs::vfs_close(&mut t, fd);
    }
}

#[test]
fn a_fat32_file_has_a_source_and_a_read_only_stream_is_not_writable() {
    let _g = serial();
    volume();
    make(b"/fat", b"MM.BIN", &bytes(3 * 512 + 7));
    let mut t = vfs::ScratchFds::new();
    let rw = vfs::vfs_open_at(&mut t, b"/fat", b"MM.BIN", O_RDWR);
    let ro = vfs::vfs_open_at(&mut t, b"/fat", b"MM.BIN", O_RDONLY);
    assert!(rw >= 0 && ro >= 0);
    let (a, b) = (page_source_of(&t, rw).unwrap(), page_source_of(&t, ro).unwrap());
    assert_eq!(a.key, b.key, "the write open and the read-only stream name one file");
    assert!(same_backing(&a, &b));
    assert_eq!((a.size, b.size), (3 * 512 + 7, 3 * 512 + 7));
    assert!(a.writable && !b.writable);

    // The source is what the cache fills from and writes back to: the real
    // backend through the real seam, at a page offset.
    let want = bytes(3 * 512 + 7);
    let mut page = vec![0u8; 512];
    fill_page(a.backing, &a.key, 512, a.size, &mut page).unwrap();
    assert_eq!(page, want[512..1024]);
    let mut last = vec![0xFFu8; 512];
    fill_page(a.backing, &a.key, 3 * 512, a.size, &mut last).unwrap();
    assert_eq!(&last[..7], &want[3 * 512..]);
    assert!(last[7..].iter().all(|&p| p == 0));
    // A write-back of the straddling page does not lengthen the file.
    let mut edit = last.clone();
    edit[0] ^= 0x5A;
    write_back_page(a.backing, &a.key, 3 * 512, a.size, &edit).unwrap();
    assert_eq!(page_source_of(&t, rw).unwrap().size, 3 * 512 + 7, "a write-back lengthened the file");
    assert_eq!(super::vfs_open_close::on_disk(b"MM.BIN")[3 * 512], want[3 * 512] ^ 0x5A);
    for fd in [rw, ro] {
        vfs::vfs_close(&mut t, fd);
    }
}

#[test]
fn what_is_not_a_backend_file_has_no_source() {
    let _g = serial();
    volume();
    let mut t = vfs::ScratchFds::new();
    // A ramfs file holds its own bytes: nothing for the cache to read. It sits
    // in the root, not under `tmp`: the tmpfs mounted there by other rows is
    // page-cached now (storage L11 part B), so a file beneath it has a source.
    let ram = vfs::vfs_open_at(&mut t, b"/", b"mmap_ram", O_CREAT | O_RDWR);
    assert!(ram >= 0);
    assert!(page_source_of(&t, ram).is_none());
    // A directory, a closed descriptor, and the ends of the table.
    let dir = vfs::vfs_open_at(&mut t, b"/", b"tmp", O_RDONLY);
    if dir >= 0 {
        assert!(page_source_of(&t, dir).is_none(), "a directory has no pages");
        vfs::vfs_close(&mut t, dir);
    }
    assert!(page_source_of(&t, -1).is_none());
    assert!(page_source_of(&t, 1_000_000).is_none());
    let gone = ram;
    vfs::vfs_close(&mut t, ram);
    assert!(page_source_of(&t, gone).is_none(), "a closed descriptor");
}

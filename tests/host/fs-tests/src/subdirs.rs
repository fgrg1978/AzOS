// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! FAT32 files in subdirectories, through the VFS.
//!
//! The VFS names a FAT32 file by a key, and the key used to be the 8.3 name of
//! a root-directory file: `key_for` refused any name with a `/`, so
//! `/fat/PKG/SYS_B/KERN.BIN` (the staged half of a whole-system update),
//! `/fat/PKG/JOURNAL.BIN` (the installer's journal) and the shell's
//! `echo hi > /fat/D1/A.TXT` all failed (`Io(Write)`) while the reader, which
//! walks paths, listed and read the same directories. The key is now the
//! canonical path, and create, write, unlink, rename, truncate and the
//! atomic replace all work below the root.
//!
//! Each row names what breaks it. The ones about the directory a file is in
//! go red if the directory is dropped from a lookup or from the entry cache
//! (a file of the same name in the root answers for it); the ones about the
//! cut are in `subdirs_cut.rs`.

#![cfg(test)]

use super::vfs_open_close::fresh_volume;
use super::{fat32, serial, vfs};
use vfs::{FileSystem as _, FsErr};

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add((i % 251) as u8)).collect()
}

/// What `echo data > path` does: create, truncate, write, close.
fn put(path: &[u8], data: &[u8]) -> bool {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, path, vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
    if fd < 0 {
        return false;
    }
    let wrote = data.is_empty() || vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()) == data.len() as i32;
    vfs::vfs_close(&mut t, fd) == 0 && wrote
}

/// The file's bytes through a read-only open, or `None` when it does not open.
fn get(path: &[u8]) -> Option<Vec<u8>> {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, path, vfs::O_RDONLY);
    if fd < 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 700];
    loop {
        let n = vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), buf.len());
        assert!(n >= 0, "read failed");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    Some(out)
}

fn names(dir: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let (mut cookie, mut ent) = (0u64, vfs::DirEnt::new());
    while let Some(next) = vfs::vfs_readdir(dir, cookie, &mut ent).expect("readdir") {
        out.push(String::from_utf8_lossy(ent.name()).into_owned());
        cookie = next;
    }
    out
}

fn free_clusters() -> u64 {
    fat32::FAT32_FS.statfs().expect("statfs").blocks_free
}

fn mkdir(path: &[u8]) {
    assert_eq!(vfs::vfs_mkdir(path), Ok(()), "mkdir {}", String::from_utf8_lossy(path));
}

/// **The shell's `echo hi > /fat/D1/A.TXT`.** Created in the directory and
/// nowhere else, readable through a new open, sized by `stat`.
#[test]
fn a_file_is_created_written_and_read_in_a_subdirectory() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/D1");
    assert!(put(b"/fat/D1/A.TXT", b"hi\n"), "the redirect into a subdirectory");
    assert_eq!(get(b"/fat/D1/A.TXT").as_deref(), Some(&b"hi\n"[..]));
    let st = vfs::vfs_stat(b"/fat/D1/A.TXT").expect("stat");
    assert_eq!((st.size, st.is_dir), (3, false));
    assert!(vfs::vfs_stat(b"/fat/D1").expect("the directory").is_dir);
    assert!(vfs::vfs_stat(b"/fat/A.TXT").is_none(), "not in the root");
    assert_eq!(get(b"/fat/A.TXT"), None);
    assert_eq!(names(b"/fat/D1"), [".", "..", "A.TXT"]);
    // The name is case-folded as in the root.
    assert_eq!(get(b"/fat/d1/a.txt").as_deref(), Some(&b"hi\n"[..]));
}

/// **`/fat/PKG/SYS_B/KERN.BIN` and `/fat/PKG/JOURNAL.BIN`.** Directories
/// nested, a file of several clusters, and the same name in the root: each is
/// its own file (a lookup that dropped the directory would answer one for the
/// other, as would an entry cache keyed by name alone).
#[test]
fn nested_directories_keep_same_named_files_apart() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/PKG");
    mkdir(b"/fat/PKG/SYS_B");
    let (root, deep, mid) = (pattern(900, 1), pattern(5000, 2), pattern(1300, 3));
    assert!(put(b"/fat/KERN.BIN", &root));
    assert!(put(b"/fat/PKG/SYS_B/KERN.BIN", &deep));
    assert!(put(b"/fat/PKG/KERN.BIN", &mid));
    for _ in 0..2 {
        assert_eq!(get(b"/fat/KERN.BIN"), Some(root.clone()));
        assert_eq!(get(b"/fat/PKG/SYS_B/KERN.BIN"), Some(deep.clone()));
        assert_eq!(get(b"/fat/PKG/KERN.BIN"), Some(mid.clone()));
    }
    assert_eq!(vfs::vfs_stat(b"/fat/PKG/SYS_B/KERN.BIN").map(|s| s.size), Some(5000));
    // Rewriting one leaves the others.
    let again = pattern(2100, 9);
    assert!(put(b"/fat/PKG/SYS_B/KERN.BIN", &again));
    assert_eq!(get(b"/fat/PKG/SYS_B/KERN.BIN"), Some(again));
    assert_eq!(get(b"/fat/KERN.BIN"), Some(root));
    assert_eq!(get(b"/fat/PKG/KERN.BIN"), Some(mid));
}

/// A name below a directory that is not there, or is a file, makes nothing.
#[test]
fn a_missing_or_file_parent_creates_nothing() {
    let _g = serial();
    fresh_volume();
    assert!(!put(b"/fat/NOPE/A.TXT", b"x"), "no such directory");
    assert!(put(b"/fat/F.TXT", b"x"));
    assert!(!put(b"/fat/F.TXT/A.TXT", b"x"), "a file is no directory");
    assert!(vfs::vfs_mkdir(b"/fat/NOPE/D").is_err());
    assert!(vfs::vfs_stat(b"/fat/NOPE").is_none());
    assert_eq!(get(b"/fat/NOPE/A.TXT"), None);
    assert_eq!(vfs::vfs_unlink(b"/fat/NOPE/A.TXT"), Err(FsErr::NotFound));
}

/// Removing a file of a subdirectory frees its clusters and leaves the
/// directory, and the same name elsewhere.
#[test]
fn unlink_in_a_subdirectory_frees_the_chain_and_only_that_file() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/D1");
    let before = free_clusters();
    assert!(put(b"/fat/KEEP.BIN", &pattern(700, 4)));
    let with_keep = free_clusters();
    assert!(put(b"/fat/D1/KEEP.BIN", &pattern(2000, 5)));
    assert!(free_clusters() < with_keep);
    assert_eq!(vfs::vfs_unlink(b"/fat/D1/KEEP.BIN"), Ok(()));
    assert_eq!(free_clusters(), with_keep, "the chain went back");
    assert_eq!(get(b"/fat/D1/KEEP.BIN"), None);
    assert_eq!(get(b"/fat/KEEP.BIN"), Some(pattern(700, 4)), "the root's file stays");
    assert_eq!(names(b"/fat/D1"), [".", ".."]);
    assert_eq!(vfs::vfs_unlink(b"/fat/D1/KEEP.BIN"), Err(FsErr::NotFound));
    assert_eq!(vfs::vfs_unlink(b"/fat/D1"), Err(FsErr::IsDir));
    // And the root's file can go too.
    assert_eq!(vfs::vfs_unlink(b"/fat/KEEP.BIN"), Ok(()));
    assert_eq!(free_clusters(), before);
}

/// `rmdir` of a nested directory: refused while it holds a file, done once
/// empty, and a file is `NotDir`.
#[test]
fn rmdir_of_a_nested_directory() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/A");
    mkdir(b"/fat/A/B");
    assert!(put(b"/fat/A/B/F.TXT", b"f"));
    assert_eq!(vfs::vfs_rmdir(b"/fat/A/B"), Err(FsErr::NotEmpty));
    assert_eq!(vfs::vfs_rmdir(b"/fat/A/B/F.TXT"), Err(FsErr::NotDir));
    assert_eq!(vfs::vfs_unlink(b"/fat/A/B/F.TXT"), Ok(()));
    assert_eq!(vfs::vfs_rmdir(b"/fat/A/B"), Ok(()));
    assert!(vfs::vfs_stat(b"/fat/A/B").is_none());
    assert_eq!(names(b"/fat/A"), [".", ".."]);
    assert_eq!(vfs::vfs_rmdir(b"/fat/A"), Ok(()));
}

/// **Rename across directories**, to a free name and over a file: the content
/// moves whole, the source name is gone, and nothing is left on the old chain.
#[test]
fn rename_across_directories_moves_the_file() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/STAGE");
    mkdir(b"/fat/LIVE");
    let before = free_clusters();
    let (a, b) = (pattern(1800, 6), pattern(700, 7));
    assert!(put(b"/fat/STAGE/IMG.BIN", &a));
    // To a free name in another directory.
    assert_eq!(vfs::vfs_rename(b"/fat/STAGE/IMG.BIN", b"/fat/LIVE/NEW.BIN"), Ok(()));
    assert_eq!(get(b"/fat/STAGE/IMG.BIN"), None);
    assert_eq!(get(b"/fat/LIVE/NEW.BIN"), Some(a.clone()));
    // Over a file of another directory: its old chain is freed.
    assert!(put(b"/fat/STAGE/IMG.BIN", &b));
    assert_eq!(vfs::vfs_rename(b"/fat/STAGE/IMG.BIN", b"/fat/LIVE/NEW.BIN"), Ok(()));
    assert_eq!(get(b"/fat/STAGE/IMG.BIN"), None);
    assert_eq!(get(b"/fat/LIVE/NEW.BIN"), Some(b.clone()));
    // Up into the root, and back down.
    assert_eq!(vfs::vfs_rename(b"/fat/LIVE/NEW.BIN", b"/fat/TOP.BIN"), Ok(()));
    assert_eq!(get(b"/fat/TOP.BIN"), Some(b.clone()));
    assert_eq!(vfs::vfs_rename(b"/fat/TOP.BIN", b"/fat/STAGE/DOWN.BIN"), Ok(()));
    assert_eq!(get(b"/fat/STAGE/DOWN.BIN"), Some(b));
    assert_eq!(names(b"/fat/LIVE"), [".", ".."]);
    assert_eq!(vfs::vfs_unlink(b"/fat/STAGE/DOWN.BIN"), Ok(()));
    assert_eq!(free_clusters(), before, "no chain was leaked or lost");
    // A missing source and a missing target directory.
    assert_eq!(vfs::vfs_rename(b"/fat/STAGE/NOPE.BIN", b"/fat/LIVE/X.BIN"), Err(FsErr::NotFound));
    assert!(put(b"/fat/STAGE/S.BIN", b"s"));
    assert!(vfs::vfs_rename(b"/fat/STAGE/S.BIN", b"/fat/GONE/X.BIN").is_err());
    assert_eq!(get(b"/fat/STAGE/S.BIN"), Some(b"s".to_vec()), "a refused rename moved nothing");
}

/// Within one subdirectory a rename is what it is in the root, and a
/// directory renamed in place takes its files with it; moved to another
/// directory it is refused (its `..` would have to follow).
#[test]
fn rename_within_a_directory_and_of_a_directory() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/D1");
    mkdir(b"/fat/D2");
    assert!(put(b"/fat/D1/A.TXT", b"aaa"));
    assert!(put(b"/fat/D1/B.TXT", b"bbbb"));
    assert_eq!(vfs::vfs_rename(b"/fat/D1/A.TXT", b"/fat/D1/C.TXT"), Ok(()), "to a free name");
    assert_eq!(get(b"/fat/D1/A.TXT"), None);
    assert_eq!(get(b"/fat/D1/C.TXT").as_deref(), Some(&b"aaa"[..]));
    assert_eq!(vfs::vfs_rename(b"/fat/D1/C.TXT", b"/fat/D1/B.TXT"), Ok(()), "over a file");
    assert_eq!(get(b"/fat/D1/B.TXT").as_deref(), Some(&b"aaa"[..]));
    assert_eq!(vfs::vfs_rename(b"/fat/D1", b"/fat/E1"), Ok(()), "a directory in place");
    assert!(vfs::vfs_stat(b"/fat/D1").is_none());
    assert_eq!(get(b"/fat/E1/B.TXT").as_deref(), Some(&b"aaa"[..]));
    assert_eq!(vfs::vfs_rename(b"/fat/E1", b"/fat/D2/E1"), Err(FsErr::Unsupported));
    assert!(vfs::vfs_stat(b"/fat/E1").expect("still there").is_dir);
}

/// The atomic replace (`vfs_replace_file`: a temp file beside the target,
/// fsync, rename over it) works in a subdirectory: `JOURNAL.BIN` of the
/// installer is written this way, and no temp name is left.
#[test]
fn an_atomic_replace_in_a_subdirectory() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/PKG");
    for (i, len) in [10usize, 3000, 40, 0, 1500].into_iter().enumerate() {
        let data = pattern(len, i as u8 + 20);
        assert_eq!(vfs::vfs_replace_file(b"/fat/PKG/JOURNAL.BIN", &data), Ok(()), "replace {i}");
        assert_eq!(get(b"/fat/PKG/JOURNAL.BIN"), Some(data));
    }
    assert_eq!(names(b"/fat/PKG"), [".", "..", "JOURNAL.BIN"]);
    assert_eq!(get(b"/fat/JOURNAL.BIN"), None);
}

/// Truncate, append and an in-place overwrite below the root.
#[test]
fn truncate_append_and_overwrite_in_a_subdirectory() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/LOG");
    let first = pattern(1200, 30);
    assert!(put(b"/fat/LOG/L.TXT", &first));
    // Append.
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, b"/fat/LOG/L.TXT", vfs::O_WRONLY | vfs::O_APPEND);
    assert!(fd >= 0);
    assert_eq!(vfs::vfs_write(&mut t, fd, b"tail".as_ptr(), 4), 4);
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    let mut want = first.clone();
    want.extend_from_slice(b"tail");
    assert_eq!(get(b"/fat/LOG/L.TXT"), Some(want));
    // Truncate to a shorter length, then to zero.
    assert_eq!(vfs::vfs_truncate(b"/fat/LOG/L.TXT", 700), Ok(()));
    assert_eq!(get(b"/fat/LOG/L.TXT"), Some(first[..700].to_vec()));
    assert_eq!(vfs::vfs_truncate(b"/fat/LOG/L.TXT", 0), Ok(()));
    assert_eq!(get(b"/fat/LOG/L.TXT"), Some(Vec::new()));
    // Overwrite with a shorter file (O_TRUNC).
    assert!(put(b"/fat/LOG/L.TXT", b"short"));
    assert_eq!(get(b"/fat/LOG/L.TXT").as_deref(), Some(&b"short"[..]));
}

/// A subdirectory that outgrows its cluster (16 entries at one sector per
/// cluster) extends itself like the root does, and every file stays readable.
#[test]
fn a_subdirectory_grows_past_one_cluster() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/BIG");
    for i in 0..30u8 {
        let path = format!("/fat/BIG/F{i:02}.DAT");
        assert!(put(path.as_bytes(), &[i; 40]), "create {path}");
    }
    for i in 0..30u8 {
        let path = format!("/fat/BIG/F{i:02}.DAT");
        assert_eq!(get(path.as_bytes()), Some(vec![i; 40]), "read {path}");
    }
    assert_eq!(names(b"/fat/BIG").len(), 32);
    for i in (0..30u8).step_by(2) {
        assert_eq!(vfs::vfs_unlink(format!("/fat/BIG/F{i:02}.DAT").as_bytes()), Ok(()));
    }
    assert_eq!(names(b"/fat/BIG").len(), 17);
    assert!(put(b"/fat/BIG/NEW.DAT", b"n"), "a freed slot is reused");
    assert_eq!(get(b"/fat/BIG/F01.DAT"), Some(vec![1; 40]));
}

/// The listing of a subdirectory carries `.` and `..`: the installer's
/// directory walk (`clear_dir`) must skip them, as the kernel-side store does.
#[test]
fn a_subdirectory_listing_has_the_dot_entries() {
    let _g = serial();
    fresh_volume();
    mkdir(b"/fat/PKG");
    mkdir(b"/fat/PKG/SYS_B");
    assert_eq!(names(b"/fat/PKG/SYS_B"), [".", ".."]);
    assert_eq!(names(b"/fat/PKG"), [".", "..", "SYS_B"]);
    // The root has none.
    assert_eq!(names(b"/fat"), ["PKG"]);
}

/// The longest key is 63 bytes: a path that does not fit makes no file (and
/// no panic), one that does is a file.
#[test]
fn a_path_longer_than_a_key_is_refused() {
    let _g = serial();
    fresh_volume();
    let mut dir = String::from("/fat");
    for c in ["ABCDEFGH.IJK", "ABCDEFGH.IJK", "ABCDEFGH.IJK", "ABCDEFGH.IJK"] {
        dir.push('/');
        dir.push_str(c);
        mkdir(dir.as_bytes());
    }
    // 4 directories of 12 + 3 separators = 51; a 12-byte name needs 64.
    let long = format!("{dir}/ABCDEFGH.IJK");
    assert!(!put(long.as_bytes(), b"x"));
    let ok = format!("{dir}/A.B");
    assert!(put(ok.as_bytes(), b"x"));
    assert_eq!(get(ok.as_bytes()).as_deref(), Some(&b"x"[..]));
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Storage L12: every open is relative to a directory and cannot leave it
//! (`vfs::join_beneath`, `vfs::vfs_open_at`).
//!
//! The directory is a `Cap<Dir>` for ring 3 (a tree capability's root path);
//! here it is a path, which is all the VFS ever sees of one. What these tests
//! pin is the VFS half: the join refuses every escape before the filesystem
//! sees a name, an escape creates nothing, and the kernel's own root-relative
//! open is the same call.

use super::{serial, tmpfs, vfs};
use vfs::{FsErr, MAX_PATH, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY};

fn join(root: &[u8], rel: &[u8]) -> Result<Vec<u8>, FsErr> {
    let mut out = [0u8; MAX_PATH];
    vfs::join_beneath(root, rel, &mut out).map(|n| out[..n].to_vec())
}

/// **Relative names join onto the directory and are normalised.** `//` and
/// `.` vanish, and a `..` that stays inside is resolved.
///
/// **Canary.** Make `join_beneath` keep `.` components: `./a` joins as
/// `/fat/./a`.
#[test]
fn a_relative_name_joins_beneath_its_directory() {
    assert_eq!(join(b"/fat", b"CONFIG.INI").unwrap(), b"/fat/CONFIG.INI");
    assert_eq!(join(b"/", b"fat/CONFIG.INI").unwrap(), b"/fat/CONFIG.INI");
    assert_eq!(join(b"/fat", b"./a//b/").unwrap(), b"/fat/a/b");
    assert_eq!(join(b"/fat", b"a/../b").unwrap(), b"/fat/b", "a `..` that stays inside is resolved");
    assert_eq!(join(b"/fat", b"a/b/../../c").unwrap(), b"/fat/c");
    assert_eq!(join(b"/fat/LOGS", b"x").unwrap(), b"/fat/LOGS/x");
    assert_eq!(join(b"//fat//LOGS/", b"x").unwrap(), b"/fat/LOGS/x", "the root is normalised too");
    assert_eq!(join(b"/fat", b"a/..").unwrap(), b"/fat", "the directory itself");
    assert_eq!(join(b"/", b"a/..").unwrap(), b"/", "the root itself");
}

/// **Nothing climbs out.** `..` at the top, after cancelling, or hidden in a
/// longer name's neighbourhood: all refused, as is a sibling that merely
/// shares the directory's name as a prefix.
///
/// **Canary.** Let `..` at depth 0 pop the root: `../fatx/F` joins as
/// `/fatx/F`, and the first assert fails.
#[test]
fn no_dotdot_escapes_the_directory() {
    for rel in [&b".."[..], b"../fatx/F", b"a/../..", b"a/../../fat/F", b"../", b"./..", b"a/b/../../..", b".//.."] {
        assert_eq!(join(b"/fat", rel), Err(FsErr::Invalid), "{:?} escaped /fat", String::from_utf8_lossy(rel));
    }
    // The root has nothing above it either.
    assert_eq!(join(b"/", b".."), Err(FsErr::Invalid));
    // A name that only looks like `..` is a name.
    assert_eq!(join(b"/fat", b"...").unwrap(), b"/fat/...");
    assert_eq!(join(b"/fat", b"..a").unwrap(), b"/fat/..a");
}

/// **No absolute names, no empty names, no NULs, no `..` in the directory.**
///
/// **Canary.** Strip a leading `/` instead of refusing it: `/etc/x` joins as
/// `/fat/etc/x` and the first assert fails.
#[test]
fn an_absolute_or_malformed_name_is_refused() {
    assert_eq!(join(b"/fat", b"/etc/x"), Err(FsErr::Invalid), "absolute");
    assert_eq!(join(b"/fat", b"//x"), Err(FsErr::Invalid), "absolute with a doubled slash");
    assert_eq!(join(b"/fat", b""), Err(FsErr::Invalid), "empty");
    assert_eq!(join(b"/fat", b"a\0b"), Err(FsErr::Invalid), "NUL inside");
    assert_eq!(join(b"fat", b"x"), Err(FsErr::Invalid), "a relative directory");
    assert_eq!(join(b"", b"x"), Err(FsErr::Invalid), "no directory");
    assert_eq!(join(b"/fat/..", b"x"), Err(FsErr::Invalid), "`..` in the directory");
    assert_eq!(join(b"/fat/./x", b"y"), Err(FsErr::Invalid), "`.` in the directory");
}

/// **A join that does not fit is refused, not truncated.** A truncated path
/// would name a different (shorter) file.
#[test]
fn a_join_past_the_path_limit_is_refused() {
    let long = vec![b'a'; MAX_PATH];
    assert_eq!(join(b"/fat", &long), Err(FsErr::NameTooLong));
    let fits = vec![b'a'; MAX_PATH - 6];
    assert_eq!(join(b"/fat", &fits).unwrap().len(), MAX_PATH - 1);
    let just = vec![b'a'; MAX_PATH - 5];
    assert_eq!(join(b"/fat", &just).unwrap().len(), MAX_PATH, "exactly the limit fits");
    let over = vec![b'a'; MAX_PATH - 4];
    assert_eq!(join(b"/fat", &over), Err(FsErr::NameTooLong));
}

/// A streaming backend to open against, mounted at its own point: `/cd` is
/// the mount other suites of this crate assert is absent until they mount it.
fn mount_tmp() {
    super::vfs_open_close::vfs_once();
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        vfs::vfs_mount_fs(b"/cd", &tmpfs::TMPFS_FS).expect("room for /cd");
    });
}

fn clear_tmp() {
    let mut names = Vec::new();
    tmpfs::tmpfs_ls(|n, _| names.push(n.to_vec()));
    for n in names { tmpfs::tmpfs_unlink(&n).unwrap(); }
}

/// **An open relative to a directory opens the file beneath it; the same file
/// is not reachable by climbing out of a sibling directory.** The root `/cd`
/// reaches `live`; the root `/` reaches `cd/live`; neither reaches it from
/// `/fat`.
///
/// **Canary.** Skip `join_beneath` in `vfs_open_at` (open `root` + `/` + `rel`
/// by plain concatenation): `../cd/live` from `/fat` opens, and the escape
/// assert fails.
#[test]
fn an_open_at_a_directory_stays_beneath_it() {
    let _g = serial();
    mount_tmp();
    clear_tmp();
    tmpfs::tmpfs_write(b"live", b"data").unwrap();
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open_at(&mut t, b"/cd", b"live", O_RDONLY);
    assert!(fd >= 0, "a relative open under /cd");
    let mut b = [0u8; 8];
    assert_eq!(vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), 8), 4);
    assert_eq!(&b[..4], b"data");
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);

    let fd = vfs::vfs_open_at(&mut t, b"/", b"cd/live", O_RDONLY);
    assert!(fd >= 0, "the same file from the root");
    vfs::vfs_close(&mut t, fd);

    assert_eq!(vfs::vfs_open_at(&mut t, b"/fat", b"../cd/live", O_RDONLY), -1, "climbing out of /fat");
    assert_eq!(vfs::vfs_open_at(&mut t, b"/cd", b"/cd/live", O_RDONLY), -1, "an absolute name");
    assert_eq!(vfs::vfs_open_at(&mut t, b"/cd", b"../cd/live", O_RDONLY), -1,
        "a `..` out and back in is still an escape");
}

/// **An escape creates nothing.** The refusal comes before the filesystem is
/// asked, so `O_CREAT` through a name that leaves the directory leaves no file
/// behind in the directory it named.
///
/// **Canary.** As above: with the join skipped the create lands in `/cd`.
#[test]
fn an_escaping_create_leaves_no_file() {
    let _g = serial();
    mount_tmp();
    clear_tmp();
    let mut t = vfs::ScratchFds::new();
    assert_eq!(vfs::vfs_open_at(&mut t, b"/fat", b"../cd/made", O_WRONLY | O_CREAT), -1);
    assert_eq!(tmpfs::tmpfs_size(b"made"), None, "the escaping create reached the filesystem");
    let fd = vfs::vfs_open_at(&mut t, b"/cd", b"made", O_WRONLY | O_CREAT);
    assert!(fd >= 0, "a create beneath its directory");
    vfs::vfs_close(&mut t, fd);
    assert_eq!(tmpfs::tmpfs_size(b"made"), Some(0));
}

/// **The kernel's own open is the open at the root.** `vfs_open(path)` and
/// `vfs_open_at("/", path without its slash)` answer alike for files that
/// exist and for files that do not, and an escape from the root is refused on
/// both.
#[test]
fn the_kernel_open_is_the_open_at_the_root() {
    let _g = serial();
    mount_tmp();
    clear_tmp();
    tmpfs::tmpfs_write(b"live", b"x").unwrap();
    let mut t = vfs::ScratchFds::new();
    for path in [&b"/cd/live"[..], b"/cd/nofile", b"/nodir/x"] {
        let a = vfs::vfs_open(&mut t, path, O_RDWR) >= 0;
        let b = vfs::vfs_open_at(&mut t, vfs::ROOT_DIR, &path[1..], O_RDWR) >= 0;
        assert_eq!(a, b, "{:?}", String::from_utf8_lossy(path));
    }
    assert_eq!(vfs::vfs_open(&mut t, b"/../cd/live", O_RDONLY), -1, "even the kernel's root has nothing above it");
    assert_eq!(vfs::vfs_open(&mut t, b"/", O_RDONLY), -1, "no name");
}

/// **No ambient path open is left in the VFS.** The only public opens are
/// `vfs_open_at` and the kernel's root-relative `vfs_open`; the resolved-path
/// opens under them are private, so nothing outside the module can reach the
/// filesystem with a path that skipped the join.
#[test]
fn only_the_joined_opens_are_public() {
    let src = include_str!("../../../../crates/fs/fs/src/vfs.rs");
    let public: Vec<&str> = src
        .lines()
        .filter(|l| l.starts_with("pub fn vfs_open") || l.starts_with("pub fn open_"))
        .map(|l| l.split('<').next().unwrap())
        .collect();
    assert_eq!(public, ["pub fn vfs_open_at", "pub fn vfs_open"], "{public:?}");
    assert!(src.contains("\nfn open_resolved<"), "open_resolved must stay private");
    assert!(src.contains("\nfn vfs_open_inner<"), "vfs_open_inner must stay private");
}

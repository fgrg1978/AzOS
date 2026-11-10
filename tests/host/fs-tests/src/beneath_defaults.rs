// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `*_beneath` defaults of `FileSystem` (`crates/fs/src/vfs.rs`) for a
//! backend that has not said whether it follows links: a caller rooted
//! below the mount is refused, one rooted at the mount or above it is
//! served. A backend whose names are lexical says so (`follows_links`) and
//! the floor is nothing to it (FAT32, tmpfs, devfs, azvol: every other test
//! of this suite).

use super::{serial, vfs};
use vfs::{DirEnt, FileStat, FileSystem, FsErr, InodeKey, StatFs};

const AT: &str = "/lnk";
const DATA: &[u8] = b"abc";

/// A backend with only the base methods: it names `d` (a directory with the
/// one entry `f`) and `d/f`, and keeps every `*_beneath` default.
struct Linky;

fn key(name: &[u8]) -> InodeKey {
    let mut k = InodeKey { bytes: [0; vfs::INODE_KEY_LEN] };
    k.bytes[..name.len()].copy_from_slice(name);
    k
}

fn file(size: u64, is_dir: bool) -> FileStat {
    FileStat { size, is_dir, cookie: 0, mode: 0, uid: 0, gid: 0, nlink: 1, atime: 0, mtime: 0, ctime: 0 }
}

impl FileSystem for Linky {
    fn fs_type(&self) -> u32 { 0x4C4E }
    fn mount(&self) -> Result<(), ()> { Ok(()) }
    fn sync(&self) -> Result<(), ()> { Ok(()) }
    fn key_for(&self, name: &[u8]) -> Option<InodeKey> {
        matches!(name, b"d" | b"d/f").then(|| key(name))
    }
    fn stat(&self, k: &InodeKey) -> Option<FileStat> {
        if *k == key(b"d") { Some(file(0, true)) } else if *k == key(b"d/f") { Some(file(DATA.len() as u64, false)) } else { None }
    }
    fn read_all(&self, k: &InodeKey, _: &FileStat, dst: &mut [u8]) -> usize { self.read_at(k, 0, dst) }
    fn write_all(&self, _: &InodeKey, _: &[u8]) -> Result<(), ()> { Err(()) }
    fn unlink(&self, _: &InodeKey) -> Result<(), ()> { Err(()) }
    fn read_at(&self, k: &InodeKey, offset: u64, dst: &mut [u8]) -> usize {
        if *k != key(b"d/f") { return 0; }
        let from = (offset as usize).min(DATA.len());
        let n = (DATA.len() - from).min(dst.len());
        dst[..n].copy_from_slice(&DATA[from..from + n]);
        n
    }
    fn write_at(&self, _: &InodeKey, _: u64, _: &[u8]) -> Result<usize, ()> { Err(()) }
    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut DirEnt) -> Result<Option<u64>, FsErr> {
        if dir != b"d" { return Err(FsErr::NotFound); }
        if cookie > 0 { return Ok(None); }
        out.name[0] = b'f';
        out.name_len = 1;
        out.is_dir = false;
        out.size = DATA.len() as u64;
        Ok(Some(1))
    }
    fn statfs(&self) -> Result<StatFs, FsErr> {
        Ok(StatFs { fs_type: 0x4C4E, block_size: 512, blocks: 8, blocks_free: 4, files: 2, files_free: 0, name_max: 64 })
    }
}

fn mounted() {
    super::vfs_root_once();
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        static FS: Linky = Linky;
        vfs::vfs_mount_fs(AT.as_bytes(), &FS).expect("the mount table has room");
    });
}

fn open_beneath(root: &[u8], rel: &[u8]) -> bool {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open_at(&mut t, root, rel, vfs::O_RDONLY);
    if fd < 0 {
        return false;
    }
    let mut b = [0u8; 8];
    let n = vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), 8);
    vfs::vfs_close(&mut t, fd);
    assert_eq!(&b[..n.max(0) as usize], DATA, "the open served the file whole");
    true
}

/// **A backend that has not taken the floor serves only a caller rooted at
/// the mount or above it.** Beneath `/lnk/d`, the stat, listing, statfs and
/// open of its own entries are refused (the key is not given, the listing
/// and statfs are `Denied`, the open fails); the same calls rooted at
/// `/lnk` and at `/` are served. The backend is asked nothing about the
/// floor: the defaults decide, from what it has not said.
///
/// **Canary.** `beneath-default-open-canary`: the defaults drop the floor,
/// and every refusal below is an answer.
#[test]
fn a_backend_without_the_floor_serves_only_a_caller_rooted_at_or_above_the_mount() {
    let _g = serial();
    mounted();
    let mut e = DirEnt::new();
    assert!(vfs::vfs_stat_beneath(b"/lnk/d", b"/lnk/d/f").is_err());
    assert_eq!(vfs::vfs_readdir_beneath(b"/lnk/d", b"/lnk/d", 0, &mut e).err(), Some(FsErr::Denied));
    assert_eq!(vfs::vfs_statfs_beneath(b"/lnk/d", b"/lnk/d/f").err(), Some(FsErr::Denied));
    assert!(!open_beneath(b"/lnk/d", b"f"));
    for root in [&b"/lnk"[..], b"/"] {
        assert_eq!(vfs::vfs_stat_beneath(root, b"/lnk/d/f").map(|st| st.size), Ok(DATA.len() as u64), "rooted at {}", String::from_utf8_lossy(root));
        assert_eq!(vfs::vfs_readdir_beneath(root, b"/lnk/d", 0, &mut e), Ok(Some(1)));
        assert_eq!(&e.name[..e.name_len], b"f");
        assert_eq!(vfs::vfs_statfs_beneath(root, b"/lnk/d/f").map(|s| s.blocks), Ok(8));
    }
    assert!(open_beneath(b"/lnk", b"d/f"));
    assert!(open_beneath(b"/", b"lnk/d/f"));
}

/// **An op that changes the tree carries the caller's floor to a backend
/// that follows links.** Beneath `/lnk/d`, the ops that reach the backend by
/// name (mkdir, rmdir, rename) are `Denied` before it is asked, since a name
/// carries no floor; the ops that reach it by key (unlink, truncate) ask for
/// the key beneath the floor, which the defaults do not give. Rooted at the
/// mount, each reaches the backend (its own answer: `Unsupported` from the
/// defaults it keeps, `Io` from its `unlink`).
///
/// **Canary.** `mutate-floor-canary`: every op is rooted at the mount, and
/// the refusals beneath `/lnk/d` become the backend's answers.
#[test]
fn a_change_by_name_through_a_backend_that_follows_links_is_refused_beneath_a_floor() {
    let _g = serial();
    mounted();
    assert_eq!(vfs::vfs_mkdir_beneath(b"/lnk/d", b"/lnk/d/g"), Err(FsErr::Denied));
    assert_eq!(vfs::vfs_rmdir_beneath(b"/lnk/d", b"/lnk/d/g"), Err(FsErr::Denied));
    assert_eq!(vfs::vfs_rename_beneath(b"/lnk/d", b"/lnk/d/f", b"/lnk/d/g"), Err(FsErr::Denied));
    assert_eq!(vfs::vfs_unlink_beneath(b"/lnk/d", b"/lnk/d/f"), Err(FsErr::Invalid));
    assert_eq!(vfs::vfs_truncate_beneath(b"/lnk/d", b"/lnk/d/f", 0), Err(FsErr::Invalid));
    assert_eq!(vfs::vfs_mkdir_beneath(b"/lnk", b"/lnk/d/g"), Err(FsErr::Unsupported));
    assert_eq!(vfs::vfs_rmdir_beneath(b"/lnk", b"/lnk/d/g"), Err(FsErr::Unsupported));
    assert_eq!(vfs::vfs_rename_beneath(b"/lnk", b"/lnk/d/f", b"/lnk/d/g"), Err(FsErr::Unsupported));
    assert_eq!(vfs::vfs_unlink_beneath(b"/lnk", b"/lnk/d/f"), Err(FsErr::Io));
    assert_eq!(vfs::vfs_truncate_beneath(b"/lnk", b"/lnk/d/f", 0), Err(FsErr::Unsupported));
}

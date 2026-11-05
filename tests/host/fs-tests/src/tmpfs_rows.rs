//! The RAM file systems through the VFS router: tmpfs at `/` and at `/tmp`,
//! devfs at `/dev`. Directories, rename, the bounds and what a bound refuses.
//!
//! Canaries (by hand; discriminates / does not / did not compile):
//! * `State::free_slot` answering slot 0 instead of `NoSpace` on a full table
//!   (cargo feature `tmpfs-bound-canary`, a gate row):
//!   `a_full_entry_table_refuses_and_the_other_mount_is_unaffected` red
//!   (the next create succeeds over a live entry).
//! * `State::put` without the byte bound: `a_write_past_the_byte_bound_is_refused`
//!   red.
//! * `backend_for_path` answering the first matching mount instead of the
//!   longest: `root_and_tmp_are_two_file_systems` red (`/tmp/x` lands in `/`).

#![cfg(test)]

use super::{serial, tmpfs, tmpfs_h, vfs};
use vfs::{DirEnt, FsErr, ScratchFds, O_APPEND, O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY};

fn put(path: &[u8], data: &[u8]) -> bool {
    let mut t = ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, path, O_WRONLY | O_CREAT | O_TRUNC);
    if fd < 0 { return false; }
    let n = vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len());
    vfs::vfs_close(&mut t, fd);
    n == data.len() as i32
}

fn get(path: &[u8]) -> Option<Vec<u8>> {
    let mut t = ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, path, O_RDONLY);
    if fd < 0 { return None; }
    let mut out = vec![0u8; 4096];
    let n = vfs::vfs_read(&mut t, fd, out.as_mut_ptr(), out.len());
    vfs::vfs_close(&mut t, fd);
    out.truncate(n.max(0) as usize);
    Some(out)
}

fn names(dir: &[u8]) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let (mut cookie, mut e) = (0, DirEnt::new());
    while let Some(next) = vfs::vfs_readdir(dir, cookie, &mut e).expect("readdir") {
        out.push((String::from_utf8_lossy(e.name()).into_owned(), e.is_dir));
        cookie = next;
    }
    out
}

fn setup() {
    super::vfs_open_close::vfs_once();
    tmpfs_h::clear();
}

/// mkdir, create, read, rename, unlink and rmdir on `base` (`/rows` or
/// `/tmp/rows`), with each refusal's error.
fn tree_on(base: &str) {
    let p = |rest: &str| format!("{base}{rest}").into_bytes();
    assert_eq!(vfs::vfs_mkdir(&p("")), Ok(()));
    assert_eq!(vfs::vfs_mkdir(&p("")), Err(FsErr::Exists));
    assert_eq!(vfs::vfs_mkdir(&p("/d")), Ok(()));
    assert_eq!(vfs::vfs_mkdir(&p("/no/deeper")), Err(FsErr::NotFound), "a missing parent");

    assert!(put(&p("/d/f"), b"hello"));
    assert!(put(&p("/top"), b"top"));
    assert_eq!(get(&p("/d/f")).as_deref(), Some(&b"hello"[..]));
    assert_eq!(vfs::vfs_stat(&p("/d/f")).map(|s| (s.size, s.is_dir)), Some((5, false)));
    assert_eq!(vfs::vfs_stat(&p("/d")).map(|s| (s.size, s.is_dir)), Some((1, true)), "a directory's size is its entries");
    assert_eq!(vfs::vfs_stat(&p("/d//f")).map(|s| s.size), Some(5), "an empty component is skipped");
    assert_eq!(names(&p("")), [("d".to_string(), true), ("top".to_string(), false)]);
    assert_eq!(names(&p("/d")), [("f".to_string(), false)]);

    // A file under a file, and a directory opened as a file.
    assert!(!put(&p("/top/x"), b"x"), "a file is not a directory");
    let mut t = ScratchFds::new();
    assert!(vfs::vfs_open(&mut t, &p("/d"), O_RDONLY) < 0, "a directory is not opened as a file");

    // rename: within a directory, across directories, over a file.
    assert_eq!(vfs::vfs_rename(&p("/d/f"), &p("/d/g")), Ok(()));
    assert_eq!(vfs::vfs_rename(&p("/d/g"), &p("/top")), Ok(()), "a file replaces a file");
    assert_eq!(get(&p("/top")).as_deref(), Some(&b"hello"[..]));
    assert!(vfs::vfs_stat(&p("/d/g")).is_none());
    assert_eq!(vfs::vfs_rename(&p("/none"), &p("/x")), Err(FsErr::NotFound));
    assert_eq!(vfs::vfs_rename(&p("/top"), &p("/d")), Err(FsErr::IsDir), "a file onto a directory");
    assert_eq!(vfs::vfs_mkdir(&p("/d/sub")), Ok(()));
    assert_eq!(vfs::vfs_rename(&p("/d"), &p("/d/sub/in")), Err(FsErr::Invalid), "a directory into itself");
    assert_eq!(vfs::vfs_rename(&p("/d"), &p("/e")), Ok(()), "a directory moves with what it holds");
    assert!(vfs::vfs_stat(&p("/e/sub")).is_some_and(|s| s.is_dir));
    assert!(vfs::vfs_stat(&p("/d")).is_none());

    // unlink and rmdir.
    assert_eq!(vfs::vfs_unlink(&p("/e")), Err(FsErr::IsDir));
    assert_eq!(vfs::vfs_rmdir(&p("/top")), Err(FsErr::NotDir));
    assert_eq!(vfs::vfs_rmdir(&p("/e")), Err(FsErr::NotEmpty));
    assert_eq!(vfs::vfs_unlink(&p("/top")), Ok(()));
    assert_eq!(vfs::vfs_unlink(&p("/top")), Err(FsErr::NotFound));
    assert_eq!(vfs::vfs_rmdir(&p("/e/sub")), Ok(()));
    assert_eq!(vfs::vfs_rmdir(&p("/e")), Ok(()));
    assert_eq!(vfs::vfs_rmdir(&p("")), Ok(()));
    assert!(vfs::vfs_stat(&p("")).is_none());
}

#[test]
fn directories_work_on_root_and_on_tmp() {
    let _g = serial();
    setup();
    tree_on("/rows");
    tree_on("/tmp/rows");
}

#[test]
fn root_and_tmp_are_two_file_systems() {
    let _g = serial();
    setup();
    assert!(put(b"/same", b"root"));
    assert!(put(b"/tmp/same", b"tmp"));
    assert_eq!(get(b"/same").as_deref(), Some(&b"root"[..]));
    assert_eq!(get(b"/tmp/same").as_deref(), Some(&b"tmp"[..]));
    assert_eq!(tmpfs_h::size(b"same"), Some(3), "/tmp/same is the /tmp instance's");
    assert_eq!(vfs::vfs_rename(b"/same", b"/tmp/moved"), Err(FsErr::Invalid), "no rename across mounts");
    assert_eq!(vfs::vfs_unlink(b"/same"), Ok(()));
    assert_eq!(vfs::vfs_unlink(b"/tmp/same"), Ok(()));
    assert_eq!(vfs::vfs_statfs(b"/").unwrap().fs_type, tmpfs::FS_TYPE_TMPFS);
    assert_eq!(vfs::vfs_statfs(b"/tmp/x").unwrap().fs_type, tmpfs::FS_TYPE_TMPFS);
    // A path that merely starts like a mount point is not under it.
    assert!(put(b"/tmpx", b"x"));
    assert_eq!(tmpfs_h::size(b"x"), None);
    assert_eq!(vfs::vfs_unlink(b"/tmpx"), Ok(()));
}

/// The entry table is a bound that refuses: the next create is `NoSpace`, on
/// that mount only, and a removed entry gives its slot back.
#[test]
fn a_full_entry_table_refuses_and_the_other_mount_is_unaffected() {
    let _g = serial();
    setup();
    assert_eq!(vfs::vfs_mkdir(b"/tmp/full"), Ok(()));
    for i in 0..tmpfs::TMPFS_MAX_FILES - 1 {
        assert!(put(format!("/tmp/full/f{i}").as_bytes(), b"."), "file {i} fits");
    }
    assert_eq!(vfs::vfs_statfs(b"/tmp").unwrap().files_free, 0);
    assert!(!put(b"/tmp/full/over", b"."), "the open that would create it is refused");
    assert_eq!(vfs::vfs_mkdir(b"/tmp/full/dir"), Err(FsErr::NoSpace));
    assert_eq!(vfs::vfs_statfs(b"/tmp").unwrap().files_free, 0, "nothing was evicted for it");
    assert_eq!(vfs::vfs_stat(b"/tmp/full/f0").map(|s| s.size), Some(1));

    assert!(put(b"/rootside", b"root still has room"));
    assert_eq!(vfs::vfs_unlink(b"/rootside"), Ok(()));

    assert_eq!(vfs::vfs_unlink(b"/tmp/full/f0"), Ok(()));
    assert!(put(b"/tmp/full/over", b"."), "a freed slot is reusable");
    tmpfs_h::clear();
}

#[test]
fn a_write_past_the_byte_bound_is_refused() {
    let _g = serial();
    setup();
    let max = tmpfs::TMPFS_MAX_BYTES;
    assert!(!put(b"/tmp/big", &vec![1u8; max + 1]), "one file cannot pass the bound");
    assert!(put(b"/tmp/big", &vec![1u8; max]), "the bound itself fits");
    assert_eq!(vfs::vfs_stat(b"/tmp/big").map(|s| s.size), Some(max as u64));

    // The file that is the whole bound cannot grow, and keeps what it has.
    let mut t = ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, b"/tmp/big", O_WRONLY | O_APPEND);
    assert!(fd >= 0);
    assert_eq!(vfs::vfs_write(&mut t, fd, b"!".as_ptr(), 1), -1);
    vfs::vfs_close(&mut t, fd);
    assert_eq!(vfs::vfs_stat(b"/tmp/big").map(|s| s.size), Some(max as u64));

    // Another file's bytes are what a write past the bound evicts, oldest
    // first, and directories stay.
    assert_eq!(vfs::vfs_mkdir(b"/tmp/keep"), Ok(()));
    assert!(put(b"/tmp/second", &vec![2u8; max / 2]));
    assert!(vfs::vfs_stat(b"/tmp/big").is_none(), "the oldest file made room");
    assert!(vfs::vfs_stat(b"/tmp/keep").is_some_and(|s| s.is_dir));
    let sf = vfs::vfs_statfs(b"/tmp").unwrap();
    assert_eq!(sf.blocks - sf.blocks_free, (max / 2) as u64);
    tmpfs_h::clear();
}

#[test]
fn names_and_paths_have_bounds() {
    let _g = serial();
    setup();
    let ok = "n".repeat(tmpfs::TMPFS_NAME_LEN - 1);
    let long = "n".repeat(tmpfs::TMPFS_NAME_LEN);
    assert_eq!(vfs::vfs_mkdir(format!("/tmp/{ok}").as_bytes()), Ok(()));
    assert_eq!(vfs::vfs_mkdir(format!("/tmp/{long}").as_bytes()), Err(FsErr::NameTooLong));
    // The key (the path inside the mount) is the file's name in the VFS.
    assert_eq!(vfs::vfs_mkdir(b"/tmp/dd"), Ok(()));
    let deep = format!("/tmp/dd/{}", "m".repeat(vfs::INODE_KEY_LEN - 3));
    assert!(put(deep.as_bytes(), b"fits"), "a path of exactly INODE_KEY_LEN bytes");
    assert!(!put(format!("{deep}m").as_bytes(), b"over"), "one byte more is refused");
    tmpfs_h::clear();
}

#[test]
fn dev_is_three_console_devices() {
    let _g = serial();
    setup();
    let mut t = ScratchFds::new();
    let out = vfs::vfs_open(&mut t, b"/dev/stdout", O_WRONLY);
    assert!(out >= 0);
    assert_eq!(vfs::vfs_write(&mut t, out, b"x".as_ptr(), 1), 1);
    vfs::vfs_close(&mut t, out);
    let inp = vfs::vfs_open(&mut t, b"/dev/stdin", O_RDONLY);
    assert!(inp >= 0);
    let mut b = [0u8; 4];
    assert_eq!(vfs::vfs_read(&mut t, inp, b.as_mut_ptr(), 4), 0, "no keyboard behind stdin");
    assert_eq!(vfs::vfs_write(&mut t, inp, b"x".as_ptr(), 1), -1, "stdin is not written");
    vfs::vfs_close(&mut t, inp);
    assert!(vfs::vfs_open(&mut t, b"/dev/null", O_WRONLY | O_CREAT) < 0, "devices are not made by creating");
    assert_eq!(vfs::vfs_unlink(b"/dev/stdin"), Err(FsErr::Io));
}

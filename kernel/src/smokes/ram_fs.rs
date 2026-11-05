// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktests `ram_fs_mkdir_unlink_rename` and `ram_fs_bound_refuses`: the RAM file
//! systems through the VFS router, at `/` (tmpfs) and at `/tmp` (a second
//! instance with its own bounds).
//!
//! Host twin: `fs-tests`' `tmpfs_rows` (canary `tmpfs-bound-canary` here: a
//! full entry table hands out slot 0 instead of refusing).

use azos_fs::{FsErr, ScratchFds, O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY};

fn put(path: &[u8], data: &[u8]) -> bool {
    let mut t = ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut t, path, O_WRONLY | O_CREAT | O_TRUNC);
    if fd < 0 { return false; }
    let n = azos_fs::vfs_write(&mut t, fd, data.as_ptr(), data.len());
    azos_fs::vfs_close(&mut t, fd);
    n == data.len() as i32
}

fn holds(path: &[u8], want: &[u8]) -> bool {
    let mut t = ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut t, path, O_RDONLY);
    if fd < 0 { return false; }
    let mut got = [0u8; 16];
    let n = azos_fs::vfs_read(&mut t, fd, got.as_mut_ptr(), got.len());
    azos_fs::vfs_close(&mut t, fd);
    n >= 0 && &got[..n as usize] == want
}

/// `dir` + `rest` in `buf`.
fn path<'a>(buf: &'a mut [u8; 64], dir: &[u8], rest: &[u8]) -> &'a [u8] {
    buf[..dir.len()].copy_from_slice(dir);
    buf[dir.len()..dir.len() + rest.len()].copy_from_slice(rest);
    &buf[..dir.len() + rest.len()]
}

fn tree(dir: &[u8]) -> Result<(), &'static str> {
    let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
    if azos_fs::vfs_mkdir(dir) != Ok(()) { return Err("mkdir of the test directory"); }
    if azos_fs::vfs_mkdir(dir) != Err(FsErr::Exists) { return Err("mkdir twice is not EEXIST"); }
    let sub = path(&mut a, dir, b"/sub");
    if azos_fs::vfs_mkdir(sub) != Ok(()) { return Err("mkdir of a subdirectory"); }
    let f = path(&mut a, dir, b"/sub/f");
    if !put(f, b"hello") || !holds(f, b"hello") { return Err("a file in a subdirectory"); }
    let g = path(&mut b, dir, b"/sub/g");
    if azos_fs::vfs_rename(f, g) != Ok(()) { return Err("rename within a directory"); }
    if azos_fs::vfs_stat(f).is_some() || !holds(g, b"hello") { return Err("rename left the old name or lost the bytes"); }
    let top = path(&mut a, dir, b"/g");
    if azos_fs::vfs_rename(g, top) != Ok(()) || !holds(top, b"hello") { return Err("rename into the parent"); }
    if azos_fs::vfs_rmdir(dir) != Err(FsErr::NotEmpty) { return Err("rmdir of a directory with entries"); }
    if azos_fs::vfs_unlink(dir) != Err(FsErr::IsDir) { return Err("unlink of a directory"); }
    if azos_fs::vfs_unlink(top) != Ok(()) { return Err("unlink of a file"); }
    if azos_fs::vfs_unlink(top) != Err(FsErr::NotFound) { return Err("unlink of a missing file"); }
    if azos_fs::vfs_rmdir(path(&mut a, dir, b"/sub")) != Ok(()) { return Err("rmdir of the subdirectory"); }
    if azos_fs::vfs_rmdir(dir) != Ok(()) { return Err("rmdir of the test directory"); }
    Ok(())
}

azos_ktest::ktest_late! {
    fn ram_fs_mkdir_unlink_rename() {
        tree(b"/ktest-ram")?;
        tree(b"/tmp/ktest-ram")
    }
}

/// A name `f<i>` for `i` below 1000.
fn numbered(buf: &mut [u8; 64], dir: &[u8], i: usize) -> usize {
    let digits = [b'0' + (i / 100 % 10) as u8, b'0' + (i / 10 % 10) as u8, b'0' + (i % 10) as u8];
    let p = path(buf, dir, b"/f");
    let n = p.len();
    buf[n..n + 3].copy_from_slice(&digits);
    n + 3
}

azos_ktest::ktest_late! {
    fn ram_fs_bound_refuses() {
        const DIR: &[u8] = b"/tmp/ktest-full";
        if azos_fs::vfs_mkdir(DIR) != Ok(()) { return Err("mkdir of the test directory"); }
        let room = azos_fs::vfs_statfs(b"/tmp").map_err(|_| "statfs /tmp")?.files_free as usize;
        if room == 0 || room > 999 { return Err("an unexpected number of free entries"); }
        let mut buf = [0u8; 64];
        for i in 0..room {
            let n = numbered(&mut buf, DIR, i);
            if !put(&buf[..n], b".") { return Err("a create below the bound was refused"); }
        }
        let n = numbered(&mut buf, DIR, room);
        if put(&buf[..n], b".") { return Err("a create past the entry bound was not refused"); }
        if azos_fs::vfs_mkdir(b"/tmp/ktest-full/d") != Err(FsErr::NoSpace) {
            return Err("mkdir past the entry bound is not ENOSPC");
        }
        if azos_fs::vfs_stat(b"/tmp/ktest-full/f000").is_none() { return Err("a refusal evicted an entry"); }
        // The other mount is not charged for it.
        if !put(b"/ktest-room", b".") || azos_fs::vfs_unlink(b"/ktest-room") != Ok(()) {
            return Err("the root file system shares /tmp's bound");
        }
        for i in 0..room {
            let n = numbered(&mut buf, DIR, i);
            azos_fs::vfs_unlink(&buf[..n]).map_err(|_| "unlink of a filler")?;
        }
        azos_fs::vfs_rmdir(DIR).map_err(|_| "rmdir of the test directory")
    }
}

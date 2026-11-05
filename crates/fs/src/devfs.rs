// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! devfs — `/dev`: the console's three descriptors as character devices.
//!
//! `stdin` reads end-of-file (there is no keyboard behind it); `stdout` and
//! `stderr` write to the console as one piece, the path `sys_write` takes for
//! fd 1 and 2.

use crate::vfs::{DirEnt, FileStat, FileSystem, FsErr, InodeKey, INODE_KEY_LEN, S_IFCHR};

/// `FS_TYPE_*` tag of devfs.
pub const FS_TYPE_DEVFS: u32 = 3;

const NODES: [&[u8]; 3] = [b"stdin", b"stdout", b"stderr"];

pub struct DevFs;

/// Mounted at `/dev`.
pub static DEV_FS: DevFs = DevFs;

fn node(key: &InodeKey) -> Option<usize> {
    let n = key.bytes.iter().position(|&b| b == 0).unwrap_or(INODE_KEY_LEN);
    NODES.iter().position(|&name| name == &key.bytes[..n])
}

impl FileSystem for DevFs {
    fn fs_type(&self) -> u32 { FS_TYPE_DEVFS }

    fn mount(&self) -> Result<(), ()> { Ok(()) }

    fn sync(&self) -> Result<(), ()> { Ok(()) }

    fn key_for(&self, name: &[u8]) -> Option<InodeKey> {
        NODES.iter().find(|&&n| n == name)?;
        let mut bytes = [0u8; INODE_KEY_LEN];
        bytes[..name.len()].copy_from_slice(name);
        Some(InodeKey { bytes })
    }

    fn stat(&self, key: &InodeKey) -> Option<FileStat> {
        let perm = if node(key)? == 0 { 0o444 } else { 0o222 };
        let mut st = FileStat::file(0, 0);
        st.mode = S_IFCHR | perm;
        Some(st)
    }

    fn read_all(&self, _key: &InodeKey, _st: &FileStat, _dst: &mut [u8]) -> usize { 0 }

    fn write_all(&self, key: &InodeKey, src: &[u8]) -> Result<(), ()> {
        self.write_at(key, 0, src).map(|_| ())
    }

    fn unlink(&self, _key: &InodeKey) -> Result<(), ()> { Err(()) }

    fn read_at(&self, _key: &InodeKey, _offset: u64, _dst: &mut [u8]) -> usize { 0 }

    fn write_at(&self, key: &InodeKey, _offset: u64, src: &[u8]) -> Result<usize, ()> {
        if node(key).ok_or(())? == 0 { return Err(()); }
        if !src.is_empty() {
            azos_drv_sys::uart::console_write_ring3(src);
        }
        Ok(src.len())
    }

    fn streaming(&self) -> bool { true }

    fn device_backed(&self) -> bool { false }

    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut DirEnt) -> Result<Option<u64>, FsErr> {
        if !dir.is_empty() {
            return Err(if NODES.contains(&dir) { FsErr::NotDir } else { FsErr::NotFound });
        }
        let Some(name) = usize::try_from(cookie).ok().and_then(|i| NODES.get(i)) else {
            return Ok(None);
        };
        out.set(name, false, 0);
        Ok(Some(cookie + 1))
    }
}

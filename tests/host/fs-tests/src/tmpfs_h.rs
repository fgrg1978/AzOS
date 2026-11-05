// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `/tmp` instance by flat name, for the rows that set files up or look
//! behind the VFS: the trait calls with a name where a key goes.

use super::{tmpfs::TMPFS_TMP, vfs::FileSystem as _};

fn key(name: &[u8]) -> Option<super::vfs::InodeKey> {
    TMPFS_TMP.key_for(name)
}

/// The key of the file `name`, which is made empty if it is not there.
pub fn make(name: &[u8]) -> super::vfs::InodeKey {
    let k = key(name).expect("a legal tmpfs name");
    TMPFS_TMP.create(&k).expect("room for the file");
    key(name).expect("the file's own key")
}

/// Create or replace the whole file.
pub fn write(name: &[u8], data: &[u8]) -> Result<(), ()> {
    TMPFS_TMP.write_all(&key(name).ok_or(())?, data)
}

pub fn write_at(name: &[u8], offset: u64, data: &[u8]) -> Result<usize, ()> {
    TMPFS_TMP.write_at(&key(name).ok_or(())?, offset, data)
}

/// Read from the start; `Err` when the file is not there.
pub fn read(name: &[u8], buf: &mut [u8]) -> Result<usize, ()> {
    let k = key(name).ok_or(())?;
    TMPFS_TMP.stat(&k).ok_or(())?;
    Ok(TMPFS_TMP.read_at(&k, 0, buf))
}

pub fn size(name: &[u8]) -> Option<usize> {
    TMPFS_TMP.stat(&key(name)?).map(|s| s.size as usize)
}

pub fn unlink(name: &[u8]) -> Result<(), ()> {
    TMPFS_TMP.unlink(&key(name).ok_or(())?)
}

/// Remove everything in the `/tmp` instance, directories too.
pub fn clear() {
    fn walk(dir: &str) {
        let mut entries = Vec::new();
        let mut e = super::vfs::DirEnt::new();
        let mut cookie = 0;
        while let Ok(Some(next)) = TMPFS_TMP.readdir(dir.as_bytes(), cookie, &mut e) {
            entries.push((String::from_utf8_lossy(e.name()).into_owned(), e.is_dir));
            cookie = next;
        }
        for (name, is_dir) in entries {
            let path = if dir.is_empty() { name } else { format!("{dir}/{name}") };
            if is_dir {
                walk(&path);
                TMPFS_TMP.rmdir(path.as_bytes()).unwrap();
            } else {
                TMPFS_TMP.unlink(&key(path.as_bytes()).unwrap()).unwrap();
            }
        }
    }
    walk("");
    let sf = TMPFS_TMP.statfs().unwrap();
    assert_eq!(sf.files_free, sf.files, "{:?}: an open file outlived its test", std::thread::current().name());
}

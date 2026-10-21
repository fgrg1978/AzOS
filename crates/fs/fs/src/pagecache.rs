// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The page cache's backing over a mounted filesystem (storage L11): a
//! `MemKind::Paged` MemObj names its file by the backend's own `InodeKey` and
//! reads and writes back its pages through the backend's positional
//! `read_at`/`write_at`. One value per filesystem, `'static` like the
//! `FileSystem` it wraps; the kernel hands it to `memobj_create_paged`.
//!
//! Its own file so the host suite (`tests/host/fs-tests/src/page_cache.rs`)
//! pulls this very source: `lib.rs` cannot be pulled.

use alloc::boxed::Box;

use azos_mm::pager::{PageBacking, PageIoError, PageKey, PAGE_KEY_LEN};
use azos_sync::SpinLock;

use crate::vfs::{self, FdTableN, FileSystem, InodeKey, INODE_KEY_LEN};

pub struct FsPageBacking(&'static dyn FileSystem);

impl FsPageBacking {
    pub const fn new(fs: &'static dyn FileSystem) -> Self {
        Self(fs)
    }

    /// The page-cache name of a file this filesystem named.
    pub const fn page_key(key: &InodeKey) -> PageKey {
        PageKey(key.bytes)
    }
}

// The key crosses as bytes: the two lengths are one number.
const _: () = assert!(INODE_KEY_LEN == PAGE_KEY_LEN);

impl PageBacking for FsPageBacking {
    fn read_page(&self, key: &PageKey, off: u64, dst: &mut [u8]) -> Result<usize, PageIoError> {
        Ok(self.0.read_at(&InodeKey { bytes: key.0 }, off, dst))
    }

    fn write_page(&self, key: &PageKey, off: u64, src: &[u8]) -> Result<(), PageIoError> {
        match self.0.write_at(&InodeKey { bytes: key.0 }, off, src) {
            Ok(n) if n == src.len() => Ok(()),
            _ => Err(PageIoError::Io),
        }
    }
}

// ── Mapping an open file ─────────────────────────────────────────────────────

/// What `mmap` needs of an open file: the page cache's name for it and the
/// backing its pages come from and go back to.
#[derive(Clone, Copy)]
pub struct PageSource {
    /// The filesystem's backing, one value per filesystem ([`backing_of`]).
    pub backing: &'static dyn PageBacking,
    /// The file, as its backend names it.
    pub key: PageKey,
    /// The file's size now, in bytes.
    pub size: u64,
    /// The descriptor was opened for writing, on a backend that takes the
    /// write-back: a shared writable mapping may be made from it.
    pub writable: bool,
}

/// Filesystems the pool names (one `FsPageBacking` each, made on first use).
const BACKINGS: usize = 8;

static POOL: SpinLock<[Option<(usize, &'static FsPageBacking)>; BACKINGS]> = SpinLock::new([None; BACKINGS]);

/// The one [`FsPageBacking`] of `fs`: the page cache stores a `'static`
/// reference, so a filesystem gets its value on the first map and keeps it
/// (the kernel's filesystems are `'static` too). `None` past [`BACKINGS`]
/// distinct filesystems. The file layer's reads and writes through the cache
/// (the kernel's `PageCacheHooks`) and `mmap` name a file by this value, so they
/// reach one object and one copy of each page.
pub fn backing_of(fs: &'static dyn FileSystem) -> Option<&'static FsPageBacking> {
    let id = fs as *const dyn FileSystem as *const () as usize;
    let mut pool = POOL.lock();
    for slot in pool.iter() {
        if let Some((k, b)) = slot {
            if *k == id {
                return Some(b);
            }
        }
    }
    let slot = pool.iter_mut().find(|s| s.is_none())?;
    let b: &'static FsPageBacking = Box::leak(Box::new(FsPageBacking::new(fs)));
    *slot = Some((id, b));
    Some(b)
}

/// The page-cache source of open descriptor `fd` of `table`, or `None` when
/// the descriptor is not a file the cache can serve: not a file, no
/// filesystem behind it (a ramfs inode holds its own bytes), or a backend that
/// does not stream (its inode is a whole-file proxy, rewritten on close, which
/// a cache beside it would corrupt).
pub fn page_source<const N: usize>(table: &FdTableN<N>, fd: i32) -> Option<PageSource> {
    let (b, opened_for_write) = vfs::fd_file_backing(table, fd)?;
    let fs = b.fs?;
    if !b.streaming {
        return None;
    }
    Some(PageSource {
        backing: backing_of(fs)?,
        key: FsPageBacking::page_key(&b.key),
        size: b.size,
        writable: opened_for_write && !b.ro_stream,
    })
}

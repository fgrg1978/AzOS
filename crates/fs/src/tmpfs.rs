// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! tmpfs — the kernel's RAM file system, mounted at `/` and at `/tmp`.
//!
//! An instance is a fixed table of entries (files and directories) behind a
//! spinlock; file data lives on the kernel heap. `/` and `/tmp` are two
//! instances, so each has its own bounds and a flood in one cannot starve the
//! other.
//!
//! ## Bounds (Kconfig, per instance)
//! | Constant           | Meaning                                         |
//! |--------------------|-------------------------------------------------|
//! | `TMPFS_MAX_FILES`  | Entries, files and directories together         |
//! | `TMPFS_MAX_BYTES`  | Data bytes; a write past it evicts the oldest   |
//! |                    | file, and is refused when nothing is left to    |
//! |                    | evict (a single file cannot exceed it)          |
//! | `TMPFS_NAME_LEN`   | One name, NUL included (63 bytes)               |
//!
//! A full entry table is refused (`NoSpace`), never evicted for.
//!
//! The key a file carries through the VFS is its canonical path inside the
//! mount (`dir/sub/name`), at most `INODE_KEY_LEN` bytes.

extern crate alloc;

use alloc::alloc::{alloc, dealloc, Layout};
use core::ptr;
use azos_sync::SpinLock;
use crate::vfs::{DirEnt, FileStat, FileSystem, FsErr, InodeKey, StatFs, INODE_KEY_LEN};

/// Kconfig `TMPFS_MAX_FILES` (default 64).
pub const TMPFS_MAX_FILES: usize = azos_limits::TMPFS_MAX_FILES;
/// Kconfig `TMPFS_MAX_KB` (default 2048, 2 MiB).
pub const TMPFS_MAX_BYTES: usize = azos_limits::TMPFS_MAX_KB * 1024;
/// Longest name including its NUL.
pub const TMPFS_NAME_LEN: usize = 64;
/// `FS_TYPE_*` tag of tmpfs.
pub const FS_TYPE_TMPFS: u32 = 2;

/// `parent` of an entry directly under the mount point.
const MOUNT_DIR: u16 = u16::MAX;

const _: () = assert!(TMPFS_NAME_LEN <= INODE_KEY_LEN);
const _: () = assert!(TMPFS_MAX_FILES < MOUNT_DIR as usize);

struct Entry {
    /// NUL-padded; not NUL-terminated at exactly `TMPFS_NAME_LEN`.
    name:     [u8; TMPFS_NAME_LEN],
    data:     *mut u8,
    capacity: usize,
    /// Logical size of a file; 0 for a directory.
    size:     usize,
    /// Lower is older; refreshed by every write.
    seq:      u32,
    parent:   u16,
    is_dir:   bool,
    active:   bool,
}

// SAFETY: the data pointer is only touched under the instance's lock.
unsafe impl Send for Entry {}

const EMPTY_ENTRY: Entry = Entry {
    name: [0; TMPFS_NAME_LEN], data: ptr::null_mut(), capacity: 0, size: 0,
    seq: 0, parent: MOUNT_DIR, is_dir: false, active: false,
};

struct State {
    entries:    [Entry; TMPFS_MAX_FILES],
    used_bytes: usize,
    next_seq:   u32,
}

/// The components of a path, empty ones (`a//b`, a trailing `/`) dropped.
fn components(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|&b| b == b'/').filter(|c| !c.is_empty())
}

fn name_is(stored: &[u8; TMPFS_NAME_LEN], name: &[u8]) -> bool {
    name.len() < TMPFS_NAME_LEN && stored[..name.len()] == *name && stored[name.len()] == 0
}

fn name_of(e: &Entry) -> &[u8] {
    let n = e.name.iter().position(|&b| b == 0).unwrap_or(TMPFS_NAME_LEN);
    &e.name[..n]
}

impl State {
    const fn new() -> Self {
        State { entries: [EMPTY_ENTRY; TMPFS_MAX_FILES], used_bytes: 0, next_seq: 1 }
    }

    fn find(&self, parent: u16, name: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.active && e.parent == parent && name_is(&e.name, name))
    }

    /// The directory holding the last component of `path`, and that component.
    fn split<'a>(&self, path: &'a [u8]) -> Result<(u16, &'a [u8]), FsErr> {
        let mut dir = MOUNT_DIR;
        let mut parts = components(path).peekable();
        loop {
            let c = parts.next().ok_or(FsErr::Invalid)?;
            if c.len() >= TMPFS_NAME_LEN { return Err(FsErr::NameTooLong); }
            if parts.peek().is_none() { return Ok((dir, c)); }
            dir = match self.find(dir, c) {
                Some(i) if self.entries[i].is_dir => i as u16,
                Some(_) => return Err(FsErr::NotDir),
                None => return Err(FsErr::NotFound),
            };
        }
    }

    fn lookup(&self, path: &[u8]) -> Result<Option<usize>, FsErr> {
        let (dir, leaf) = self.split(path)?;
        Ok(self.find(dir, leaf))
    }

    fn existing(&self, path: &[u8]) -> Result<usize, FsErr> {
        self.lookup(path)?.ok_or(FsErr::NotFound)
    }

    fn children(&self, dir: usize) -> u64 {
        self.entries.iter().filter(|e| e.active && e.parent == dir as u16).count() as u64
    }

    fn free_slot(&self) -> Result<usize, FsErr> {
        let free = self.entries.iter().position(|e| !e.active);
        if cfg!(feature = "tmpfs-bound-canary") {
            return Ok(free.unwrap_or(0));
        }
        free.ok_or(FsErr::NoSpace)
    }

    fn bump(&mut self) -> u32 {
        let s = self.next_seq;
        self.next_seq = s.wrapping_add(1);
        s
    }

    fn insert(&mut self, parent: u16, name: &[u8], is_dir: bool) -> Result<usize, FsErr> {
        let slot = self.free_slot()?;
        let seq = self.bump();
        let e = &mut self.entries[slot];
        *e = EMPTY_ENTRY;
        e.name[..name.len()].copy_from_slice(name);
        e.parent = parent;
        e.is_dir = is_dir;
        e.seq = seq;
        e.active = true;
        Ok(slot)
    }

    fn free(&mut self, idx: usize) {
        let e = &mut self.entries[idx];
        if !e.data.is_null() {
            // SAFETY: allocated with this capacity and alignment in `put`.
            unsafe { dealloc(e.data, Layout::from_size_align_unchecked(e.capacity, 1)); }
        }
        self.used_bytes -= e.size;
        *e = EMPTY_ENTRY;
    }

    /// Free the oldest file other than `keep`; `false` when there is none.
    /// Directories are never evicted.
    fn evict_oldest(&mut self, keep: Option<usize>) -> bool {
        let victim = (0..TMPFS_MAX_FILES)
            .filter(|&i| self.entries[i].active && !self.entries[i].is_dir && Some(i) != keep)
            .min_by_key(|&i| self.entries[i].seq);
        match victim {
            Some(v) => { self.free(v); true }
            None => false,
        }
    }

    /// Write `data` at `offset` of the file `existing`, or of a new file
    /// `leaf` under `parent`. A gap before `offset` reads back as zeros.
    fn put(
        &mut self,
        parent: u16,
        leaf: &[u8],
        existing: Option<usize>,
        offset: usize,
        data: &[u8],
    ) -> Result<(), FsErr> {
        let end = offset.checked_add(data.len())
            .filter(|&e| e <= TMPFS_MAX_BYTES)
            .ok_or(FsErr::NoSpace)?;
        let old_size = existing.map_or(0, |i| self.entries[i].size);
        let new_size = end.max(old_size);
        while self.used_bytes + (new_size - old_size) > TMPFS_MAX_BYTES {
            if !self.evict_oldest(existing) { return Err(FsErr::NoSpace); }
        }
        let slot = match existing {
            Some(i) => i,
            None => self.free_slot()?,
        };
        let capacity = if existing.is_some() { self.entries[slot].capacity } else { 0 };

        let mut grown = None;
        if new_size > capacity {
            // Growth doubles, so a file appended to a page at a time is not
            // copied whole on every page.
            let want = if existing.is_some() {
                new_size.max(capacity.saturating_mul(2).min(TMPFS_MAX_BYTES))
            } else {
                new_size
            };
            // SAFETY: `want >= new_size > capacity >= 0`, so it is not zero.
            let fresh = unsafe { alloc(Layout::from_size_align_unchecked(want, 1)) };
            if fresh.is_null() { return Err(FsErr::NoSpace); }
            // SAFETY: `fresh` holds `want` bytes; the old data holds `old_size`.
            unsafe {
                ptr::write_bytes(fresh, 0, want);
                if old_size > 0 { ptr::copy_nonoverlapping(self.entries[slot].data, fresh, old_size); }
            }
            grown = Some((fresh, want));
        } else if offset > old_size {
            // SAFETY: `offset <= new_size <= capacity`; the bytes past the old
            // size may be left over from a truncate.
            unsafe { ptr::write_bytes(self.entries[slot].data.add(old_size), 0, offset - old_size); }
        }

        let seq = self.bump();
        if existing.is_none() {
            self.entries[slot] = EMPTY_ENTRY;
            let e = &mut self.entries[slot];
            e.name[..leaf.len()].copy_from_slice(leaf);
            e.parent = parent;
            e.active = true;
        }
        self.used_bytes = self.used_bytes - old_size + new_size;
        let e = &mut self.entries[slot];
        e.seq = seq;
        if let Some((fresh, want)) = grown {
            if !e.data.is_null() {
                // SAFETY: allocated with `e.capacity` by an earlier `put`.
                unsafe { dealloc(e.data, Layout::from_size_align_unchecked(e.capacity, 1)); }
            }
            e.data = fresh;
            e.capacity = want;
        }
        if !data.is_empty() {
            // SAFETY: `end <= new_size <= e.capacity`.
            unsafe { ptr::copy_nonoverlapping(data.as_ptr(), e.data.add(offset), data.len()); }
        }
        e.size = new_size;
        Ok(())
    }
}

/// One RAM file system.
pub struct TmpFs {
    state: SpinLock<State>,
}

impl TmpFs {
    pub const fn new() -> Self {
        TmpFs { state: SpinLock::new(State::new()) }
    }
}

/// Mounted at `/`.
pub static TMPFS_ROOT: TmpFs = TmpFs::new();
/// Mounted at `/tmp`.
pub static TMPFS_TMP: TmpFs = TmpFs::new();

/// The key's bytes up to the first NUL: the canonical path.
fn key_path(key: &InodeKey) -> &[u8] {
    let n = key.bytes.iter().position(|&b| b == 0).unwrap_or(INODE_KEY_LEN);
    &key.bytes[..n]
}

impl FileSystem for TmpFs {
    fn device_backed(&self) -> bool { false }

    fn fs_type(&self) -> u32 { FS_TYPE_TMPFS }

    fn mount(&self) -> Result<(), ()> { Ok(()) }

    fn sync(&self) -> Result<(), ()> { Ok(()) }

    /// The canonical path: components joined by `/`. Refused when empty, when
    /// a component is not a legal name or the whole does not fit the key.
    fn key_for(&self, name: &[u8]) -> Option<InodeKey> {
        let mut bytes = [0u8; INODE_KEY_LEN];
        let mut n = 0;
        for c in components(name) {
            if c.len() >= TMPFS_NAME_LEN || c.contains(&0) { return None; }
            let sep = (n > 0) as usize;
            if n + sep + c.len() > INODE_KEY_LEN { return None; }
            if sep == 1 { bytes[n] = b'/'; n += 1; }
            bytes[n..n + c.len()].copy_from_slice(c);
            n += c.len();
        }
        if n == 0 { None } else { Some(InodeKey { bytes }) }
    }

    fn stat(&self, key: &InodeKey) -> Option<FileStat> {
        let st = self.state.lock();
        let i = st.lookup(key_path(key)).ok()??;
        let e = &st.entries[i];
        Some(if e.is_dir { FileStat::dir(st.children(i)) } else { FileStat::file(e.size as u64, 0) })
    }

    fn read_all(&self, key: &InodeKey, _st: &FileStat, dst: &mut [u8]) -> usize {
        self.read_at(key, 0, dst)
    }

    fn write_all(&self, key: &InodeKey, src: &[u8]) -> Result<(), ()> {
        let mut st = self.state.lock();
        let (dir, leaf) = st.split(key_path(key)).map_err(|_| ())?;
        match st.find(dir, leaf) {
            Some(i) if st.entries[i].is_dir => return Err(()),
            Some(i) => st.free(i),
            None => {}
        }
        let slot = st.insert(dir, leaf, false).map_err(|_| ())?;
        if st.put(dir, leaf, Some(slot), 0, src).is_err() {
            st.free(slot);
            return Err(());
        }
        Ok(())
    }

    fn unlink(&self, key: &InodeKey) -> Result<(), ()> {
        let mut st = self.state.lock();
        match st.lookup(key_path(key)) {
            Ok(Some(i)) if !st.entries[i].is_dir => { st.free(i); Ok(()) }
            _ => Err(()),
        }
    }

    fn read_at(&self, key: &InodeKey, offset: u64, dst: &mut [u8]) -> usize {
        let Ok(offset) = usize::try_from(offset) else { return 0 };
        let st = self.state.lock();
        let Ok(Some(i)) = st.lookup(key_path(key)) else { return 0 };
        let e = &st.entries[i];
        if e.is_dir || offset >= e.size { return 0; }
        let n = dst.len().min(e.size - offset);
        // SAFETY: `offset + n <= e.size <= e.capacity`.
        unsafe { ptr::copy_nonoverlapping(e.data.add(offset), dst.as_mut_ptr(), n); }
        n
    }

    /// Creates the file when it is not there (its directory must exist).
    fn write_at(&self, key: &InodeKey, offset: u64, src: &[u8]) -> Result<usize, ()> {
        let offset = usize::try_from(offset).map_err(|_| ())?;
        if src.is_empty() { return Ok(0); }
        let mut st = self.state.lock();
        let (dir, leaf) = st.split(key_path(key)).map_err(|_| ())?;
        let existing = st.find(dir, leaf);
        if existing.is_some_and(|i| st.entries[i].is_dir) { return Err(()); }
        st.put(dir, leaf, existing, offset, src).map_err(|_| ())?;
        Ok(src.len())
    }

    fn streaming(&self) -> bool { true }

    /// Its files are the page cache's too (storage L11): a file-backed `mmap`
    /// of a tmpfs file needs the cache's frames, and `read`/`write` through the
    /// same pages are what keeps a mapping and the file one.
    fn page_cached(&self) -> bool { true }

    fn create(&self, key: &InodeKey) -> Result<(), FsErr> {
        let mut st = self.state.lock();
        let (dir, leaf) = st.split(key_path(key))?;
        if st.find(dir, leaf).is_some() { return Ok(()); }
        st.insert(dir, leaf, false).map(|_| ())
    }

    fn truncate(&self, key: &InodeKey, len: u64) -> Result<(), FsErr> {
        let len = usize::try_from(len).map_err(|_| FsErr::NoSpace)?;
        if len > TMPFS_MAX_BYTES { return Err(FsErr::NoSpace); }
        let mut st = self.state.lock();
        let i = st.existing(key_path(key))?;
        if st.entries[i].is_dir { return Err(FsErr::IsDir); }
        let size = st.entries[i].size;
        if len > size {
            return st.put(MOUNT_DIR, &[], Some(i), len - 1, &[0]);
        }
        st.used_bytes -= size - len;
        let e = &mut st.entries[i];
        e.size = len;
        if len == 0 && !e.data.is_null() {
            // SAFETY: allocated with `e.capacity` in `put`.
            unsafe { dealloc(e.data, Layout::from_size_align_unchecked(e.capacity, 1)); }
            e.data = ptr::null_mut();
            e.capacity = 0;
        }
        Ok(())
    }

    fn mkdir(&self, name: &[u8]) -> Result<(), FsErr> {
        let mut st = self.state.lock();
        let (dir, leaf) = st.split(name)?;
        if st.find(dir, leaf).is_some() { return Err(FsErr::Exists); }
        st.insert(dir, leaf, true).map(|_| ())
    }

    fn rmdir(&self, name: &[u8]) -> Result<(), FsErr> {
        let mut st = self.state.lock();
        let i = st.existing(name)?;
        if !st.entries[i].is_dir { return Err(FsErr::NotDir); }
        if st.children(i) != 0 { return Err(FsErr::NotEmpty); }
        st.free(i);
        Ok(())
    }

    /// A file replaces a file; a directory is never a replacement target and
    /// cannot move into itself.
    fn rename(&self, from: &[u8], to: &[u8]) -> Result<(), FsErr> {
        let mut st = self.state.lock();
        let src = st.existing(from)?;
        let (dir, leaf) = st.split(to)?;
        let dest = st.find(dir, leaf);
        if dest == Some(src) { return Ok(()); }
        let src_dir = st.entries[src].is_dir;
        if src_dir {
            let mut up = dir;
            while up != MOUNT_DIR {
                if up as usize == src { return Err(FsErr::Invalid); }
                up = st.entries[up as usize].parent;
            }
        }
        if let Some(d) = dest {
            if st.entries[d].is_dir && !src_dir { return Err(FsErr::IsDir); }
            if src_dir || st.entries[d].is_dir { return Err(FsErr::Exists); }
            st.free(d);
        }
        let e = &mut st.entries[src];
        e.name = [0; TMPFS_NAME_LEN];
        e.name[..leaf.len()].copy_from_slice(leaf);
        e.parent = dir;
        Ok(())
    }

    fn statfs(&self) -> Result<StatFs, FsErr> {
        let st = self.state.lock();
        let active = st.entries.iter().filter(|e| e.active).count();
        Ok(StatFs {
            fs_type: FS_TYPE_TMPFS, block_size: 1,
            blocks: TMPFS_MAX_BYTES as u64,
            blocks_free: TMPFS_MAX_BYTES.saturating_sub(st.used_bytes) as u64,
            files: TMPFS_MAX_FILES as u64,
            files_free: (TMPFS_MAX_FILES - active) as u64,
            name_max: (TMPFS_NAME_LEN - 1) as u32,
        })
    }

    /// The cookie is the slot to resume at.
    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut DirEnt) -> Result<Option<u64>, FsErr> {
        let st = self.state.lock();
        let d = if components(dir).next().is_none() {
            MOUNT_DIR
        } else {
            let i = st.existing(dir)?;
            if !st.entries[i].is_dir { return Err(FsErr::NotDir); }
            i as u16
        };
        let start = usize::try_from(cookie).unwrap_or(usize::MAX);
        for i in start..TMPFS_MAX_FILES {
            let e = &st.entries[i];
            if !e.active || e.parent != d { continue; }
            let size = if e.is_dir { st.children(i) } else { e.size as u64 };
            if !out.set(name_of(e), e.is_dir, size) { return Err(FsErr::NameTooLong); }
            return Ok(Some(i as u64 + 1));
        }
        Ok(None)
    }
}

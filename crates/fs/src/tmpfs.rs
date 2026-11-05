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
//! | `TMPFS_MAX_BYTES`  | Data bytes; a write past it is refused, and     |
//! |                    | on `/tmp` first evicts the oldest file          |
//! | `TMPFS_NAME_LEN`   | One name, NUL included (63 bytes)               |
//!
//! `/tmp` is scratch space and evicts (FIFO, files only, never one with
//! nothing older left); `/` never does: a full `/` refuses the write. A full
//! entry table is refused (`NoSpace`) on both, never evicted for.
//!
//! ## Keys
//! A file is named to the VFS by its entry, not by its path: the key holds
//! the entry's slot and id, so it follows the file through a rename and
//! names nothing once the file is gone (a write through it never recreates
//! it). A file that is not there yet is named by its directory's slot and id
//! plus the leaf name, which is what `create` needs. Neither form depends on
//! the length of the path, which only the caller's buffers bound.
//!
//! A file unlinked or renamed over while open stays alive, unnamed, until its
//! last close (`opened` / `released`).

extern crate alloc;

use alloc::alloc::{alloc, dealloc, Layout};
use core::ptr;
use azos_sync::SpinLock;
use crate::vfs::{DirEnt, FileStat, FileSystem, FsErr, InodeKey, StatFs, INODE_KEY_LEN, MAX_PATH};

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
/// `parent` of an unlinked file that is still open.
const ORPHAN: u16 = u16::MAX - 1;

/// Bytes of a key before the leaf name: slot (`u16`) and id (`u32`).
const KEY_HEAD: usize = 6;

const _: () = assert!(KEY_HEAD + TMPFS_NAME_LEN - 1 <= INODE_KEY_LEN);
const _: () = assert!(TMPFS_MAX_FILES < ORPHAN as usize);

struct Entry {
    /// NUL-padded; not NUL-terminated at exactly `TMPFS_NAME_LEN`.
    name:     [u8; TMPFS_NAME_LEN],
    data:     *mut u8,
    capacity: usize,
    /// Logical size of a file; 0 for a directory.
    size:     usize,
    /// Lower is older; refreshed by every write.
    seq:      u32,
    /// Never repeats on an instance (wraps past 2^32 entries made): a key
    /// holding the id of a freed entry names nothing.
    id:       u32,
    /// Open files on it (`opened` / `released`).
    refs:     u16,
    parent:   u16,
    is_dir:   bool,
    active:   bool,
}

// SAFETY: the data pointer is only touched under the instance's lock.
unsafe impl Send for Entry {}

const EMPTY_ENTRY: Entry = Entry {
    name: [0; TMPFS_NAME_LEN], data: ptr::null_mut(), capacity: 0, size: 0,
    seq: 0, id: 0, refs: 0, parent: MOUNT_DIR, is_dir: false, active: false,
};

struct State {
    entries:    [Entry; TMPFS_MAX_FILES],
    used_bytes: usize,
    next_seq:   u32,
    next_id:    u32,
    /// A write past the byte bound evicts the oldest file first.
    evicts:     bool,
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
    const fn new(evicts: bool) -> Self {
        State { entries: [EMPTY_ENTRY; TMPFS_MAX_FILES], used_bytes: 0, next_seq: 1, next_id: 1, evicts }
    }

    fn find(&self, parent: u16, name: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.active && e.parent == parent && name_is(&e.name, name))
    }

    /// The directory holding the last component of `path`, and that component.
    /// A path longer than the VFS's own (`MAX_PATH`) names nothing.
    fn split<'a>(&self, path: &'a [u8]) -> Result<(u16, &'a [u8]), FsErr> {
        let len = components(path).map(|c| c.len() + 1).sum::<usize>().saturating_sub(1);
        if len >= MAX_PATH { return Err(FsErr::NameTooLong); }
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

    fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = id.checked_add(1).unwrap_or(1);
        id
    }

    fn insert(&mut self, parent: u16, name: &[u8], is_dir: bool) -> Result<usize, FsErr> {
        let slot = self.free_slot()?;
        let (seq, id) = (self.bump(), self.new_id());
        let e = &mut self.entries[slot];
        *e = EMPTY_ENTRY;
        e.name[..name.len()].copy_from_slice(name);
        e.parent = parent;
        e.is_dir = is_dir;
        e.seq = seq;
        e.id = id;
        e.active = true;
        Ok(slot)
    }

    /// The key naming entry `slot` itself.
    fn key_of(&self, slot: usize) -> InodeKey {
        let mut bytes = [0u8; INODE_KEY_LEN];
        bytes[..2].copy_from_slice(&(slot as u16).to_le_bytes());
        bytes[2..KEY_HEAD].copy_from_slice(&self.entries[slot].id.to_le_bytes());
        InodeKey { bytes }
    }

    /// The key naming `leaf` in directory `dir`, whether or not it is there.
    /// `dir` may be [`ORPHAN`]: a directory that is not there, so the key
    /// names nothing.
    fn key_in(&self, dir: u16, leaf: &[u8]) -> InodeKey {
        let mut bytes = [0u8; INODE_KEY_LEN];
        bytes[..2].copy_from_slice(&dir.to_le_bytes());
        if dir < ORPHAN {
            bytes[2..KEY_HEAD].copy_from_slice(&self.entries[dir as usize].id.to_le_bytes());
        }
        bytes[KEY_HEAD..KEY_HEAD + leaf.len()].copy_from_slice(leaf);
        InodeKey { bytes }
    }

    /// The directory and leaf a key names, or the entry itself when it has no
    /// leaf. `None` when the directory or the entry is gone.
    fn target<'k>(&self, key: &'k InodeKey) -> Option<(u16, &'k [u8])> {
        let slot = u16::from_le_bytes([key.bytes[0], key.bytes[1]]);
        let id = u32::from_le_bytes([key.bytes[2], key.bytes[3], key.bytes[4], key.bytes[5]]);
        let n = key.bytes[KEY_HEAD..].iter().position(|&b| b == 0).unwrap_or(INODE_KEY_LEN - KEY_HEAD);
        let leaf = &key.bytes[KEY_HEAD..KEY_HEAD + n];
        if slot != MOUNT_DIR {
            let e = self.entries.get(slot as usize)?;
            if !e.active || e.id != id || (!leaf.is_empty() && !e.is_dir) { return None; }
        }
        Some((slot, leaf))
    }

    /// The entry a key names now.
    fn resolve(&self, key: &InodeKey) -> Option<usize> {
        let (slot, leaf) = self.target(key)?;
        if leaf.is_empty() {
            return (slot != MOUNT_DIR).then_some(slot as usize);
        }
        self.find(slot, leaf)
    }

    /// Set file `idx`'s size to `len`, which is at most its size. The
    /// allocation is kept (freed when it empties) and counts by size.
    fn cut(&mut self, idx: usize, len: usize) {
        let e = &mut self.entries[idx];
        self.used_bytes -= e.size - len;
        e.size = len;
        if len == 0 && !e.data.is_null() {
            // SAFETY: allocated with `e.capacity` in `put`.
            unsafe { dealloc(e.data, Layout::from_size_align_unchecked(e.capacity, 1)); }
            e.data = ptr::null_mut();
            e.capacity = 0;
        }
    }

    /// Take entry `idx` off its name. Open files keep it alive, unnamed, until
    /// the last one closes ([`TmpFs::released`]).
    fn remove(&mut self, idx: usize) {
        let e = &mut self.entries[idx];
        if e.refs > 0 {
            e.parent = ORPHAN;
            e.name = [0; TMPFS_NAME_LEN];
        } else {
            self.free(idx);
        }
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

    /// Free the oldest named file other than `keep`; `false` when there is
    /// none. Directories are never evicted.
    fn evict_oldest(&mut self, keep: Option<usize>) -> bool {
        let victim = (0..TMPFS_MAX_FILES)
            .filter(|&i| {
                let e = &self.entries[i];
                e.active && !e.is_dir && e.parent != ORPHAN && Some(i) != keep
            })
            .min_by_key(|&i| self.entries[i].seq);
        match victim {
            Some(v) => { self.free(v); true }
            None => false,
        }
    }

    /// Write `data` at `offset` of file `slot`, growing it. A gap before
    /// `offset` reads back as zeros.
    fn put(&mut self, slot: usize, offset: usize, data: &[u8]) -> Result<(), FsErr> {
        let end = offset.checked_add(data.len())
            .filter(|&e| e <= TMPFS_MAX_BYTES)
            .ok_or(FsErr::NoSpace)?;
        let existing = Some(slot);
        let old_size = self.entries[slot].size;
        let new_size = end.max(old_size);
        while self.used_bytes + (new_size - old_size) > TMPFS_MAX_BYTES {
            if !self.evicts || !self.evict_oldest(existing) { return Err(FsErr::NoSpace); }
        }
        let capacity = self.entries[slot].capacity;

        let mut grown = None;
        if new_size > capacity {
            // SAFETY: `new_size > capacity >= 0`, so it is not zero.
            let fresh = unsafe { alloc(Layout::from_size_align_unchecked(new_size, 1)) };
            if fresh.is_null() { return Err(FsErr::NoSpace); }
            // SAFETY: `fresh` holds `new_size` bytes; the old data holds `old_size`.
            unsafe {
                ptr::write_bytes(fresh, 0, new_size);
                if old_size > 0 { ptr::copy_nonoverlapping(self.entries[slot].data, fresh, old_size); }
            }
            grown = Some((fresh, new_size));
        } else if offset > old_size {
            // SAFETY: `offset <= new_size <= capacity`; the bytes past the old
            // size may be left over from a truncate.
            unsafe { ptr::write_bytes(self.entries[slot].data.add(old_size), 0, offset - old_size); }
        }

        let seq = self.bump();
        self.used_bytes = self.used_bytes - old_size + new_size;
        let e = &mut self.entries[slot];
        e.seq = seq;
        if let Some((fresh, cap)) = grown {
            if !e.data.is_null() {
                // SAFETY: allocated with `e.capacity` by an earlier `put`.
                unsafe { dealloc(e.data, Layout::from_size_align_unchecked(e.capacity, 1)); }
            }
            e.data = fresh;
            e.capacity = cap;
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
    /// `evicts`: a write past the byte bound frees the oldest file to fit
    /// (scratch space) instead of being refused.
    pub const fn new(evicts: bool) -> Self {
        TmpFs { state: SpinLock::new(State::new(evicts)) }
    }
}

/// Mounted at `/`: refuses what does not fit.
pub static TMPFS_ROOT: TmpFs = TmpFs::new(false);
/// Mounted at `/tmp`: scratch space, evicts the oldest file to fit a write.
pub static TMPFS_TMP: TmpFs = TmpFs::new(true);

impl FileSystem for TmpFs {
    fn device_backed(&self) -> bool { false }

    fn fs_type(&self) -> u32 { FS_TYPE_TMPFS }

    fn mount(&self) -> Result<(), ()> { Ok(()) }

    fn sync(&self) -> Result<(), ()> { Ok(()) }

    /// The entry's own key when `name` is there; else the key of the leaf in
    /// its directory, which names nothing yet (and nothing at all when the
    /// directory is not there either). `None` when `name` is not a legal path.
    fn key_for(&self, name: &[u8]) -> Option<InodeKey> {
        if components(name).any(|c| c.contains(&0)) { return None; }
        let st = self.state.lock();
        let (dir, leaf) = match st.split(name) {
            Ok(v) => v,
            Err(FsErr::NotFound | FsErr::NotDir) => {
                let leaf = components(name).last()?;
                return (leaf.len() < TMPFS_NAME_LEN).then(|| st.key_in(ORPHAN, leaf));
            }
            Err(_) => return None,
        };
        Some(match st.find(dir, leaf) {
            Some(i) => st.key_of(i),
            None => st.key_in(dir, leaf),
        })
    }

    fn stat(&self, key: &InodeKey) -> Option<FileStat> {
        let st = self.state.lock();
        let i = st.resolve(key)?;
        let e = &st.entries[i];
        Some(if e.is_dir { FileStat::dir(st.children(i)) } else { FileStat::file(e.size as u64, 0) })
    }

    fn read_all(&self, key: &InodeKey, _st: &FileStat, dst: &mut [u8]) -> usize {
        self.read_at(key, 0, dst)
    }

    /// Replace the whole file, creating it when the key names a leaf that is
    /// not there yet.
    fn write_all(&self, key: &InodeKey, src: &[u8]) -> Result<(), ()> {
        let mut st = self.state.lock();
        let slot = match st.resolve(key) {
            Some(i) if st.entries[i].is_dir => return Err(()),
            Some(i) => i,
            None => {
                let (dir, leaf) = st.target(key).ok_or(())?;
                if leaf.is_empty() || dir == ORPHAN { return Err(()); }
                let mut name = [0u8; TMPFS_NAME_LEN];
                name[..leaf.len()].copy_from_slice(leaf);
                st.insert(dir, &name[..leaf.len()], false).map_err(|_| ())?
            }
        };
        st.cut(slot, 0);
        st.put(slot, 0, src).map_err(|_| ())
    }

    fn unlink(&self, key: &InodeKey) -> Result<(), ()> {
        let mut st = self.state.lock();
        match st.resolve(key) {
            Some(i) if !st.entries[i].is_dir => { st.remove(i); Ok(()) }
            _ => Err(()),
        }
    }

    fn read_at(&self, key: &InodeKey, offset: u64, dst: &mut [u8]) -> usize {
        let Ok(offset) = usize::try_from(offset) else { return 0 };
        let st = self.state.lock();
        let Some(i) = st.resolve(key) else { return 0 };
        let e = &st.entries[i];
        if e.is_dir || offset >= e.size { return 0; }
        let n = dst.len().min(e.size - offset);
        // SAFETY: `offset + n <= e.size <= e.capacity`.
        unsafe { ptr::copy_nonoverlapping(e.data.add(offset), dst.as_mut_ptr(), n); }
        n
    }

    /// Writes the file the key names; a file that is gone (unlinked and not
    /// open, evicted) is not made again.
    fn write_at(&self, key: &InodeKey, offset: u64, src: &[u8]) -> Result<usize, ()> {
        let offset = usize::try_from(offset).map_err(|_| ())?;
        if src.is_empty() { return Ok(0); }
        let mut st = self.state.lock();
        let i = st.resolve(key).ok_or(())?;
        if st.entries[i].is_dir { return Err(()); }
        st.put(i, offset, src).map_err(|_| ())?;
        Ok(src.len())
    }

    fn streaming(&self) -> bool { true }

    fn keys_follow_file(&self) -> bool { true }

    /// Its files are the page cache's too (storage L11): a file-backed `mmap`
    /// of a tmpfs file needs the cache's frames, and `read`/`write` through the
    /// same pages are what keeps a mapping and the file one.
    fn page_cached(&self) -> bool { true }

    fn opened(&self, key: &InodeKey) {
        let mut st = self.state.lock();
        if let Some(i) = st.resolve(key) {
            st.entries[i].refs = st.entries[i].refs.saturating_add(1);
        }
    }

    fn released(&self, key: &InodeKey) {
        let mut st = self.state.lock();
        let Some(i) = st.resolve(key) else { return };
        let e = &mut st.entries[i];
        e.refs = e.refs.saturating_sub(1);
        if e.refs == 0 && e.parent == ORPHAN {
            st.free(i);
        }
    }

    fn create(&self, key: &InodeKey) -> Result<(), FsErr> {
        let mut st = self.state.lock();
        if st.resolve(key).is_some() { return Ok(()); }
        let (dir, leaf) = st.target(key).ok_or(FsErr::NotFound)?;
        if leaf.is_empty() || dir == ORPHAN { return Err(FsErr::NotFound); }
        let mut name = [0u8; TMPFS_NAME_LEN];
        name[..leaf.len()].copy_from_slice(leaf);
        st.insert(dir, &name[..leaf.len()], false).map(|_| ())
    }

    fn truncate(&self, key: &InodeKey, len: u64) -> Result<(), FsErr> {
        let len = usize::try_from(len).map_err(|_| FsErr::NoSpace)?;
        if len > TMPFS_MAX_BYTES { return Err(FsErr::NoSpace); }
        let mut st = self.state.lock();
        let i = st.resolve(key).ok_or(FsErr::NotFound)?;
        if st.entries[i].is_dir { return Err(FsErr::IsDir); }
        if len > st.entries[i].size {
            return st.put(i, len - 1, &[0]);
        }
        st.cut(i, len);
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

    /// A file replaces a file; a directory is never the target of a rename
    /// and cannot move into itself.
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
            st.remove(d);
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

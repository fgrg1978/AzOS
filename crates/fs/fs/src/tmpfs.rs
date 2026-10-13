// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TmpFS — bounded in-RAM temporary filesystem (F20).
//!
//! Provides a lightweight `/tmp` with a hard capacity cap and FIFO eviction.
//! Entries are allocated from the kernel heap; the entry table itself is a
//! fixed-size static array protected by a spinlock.
//!
//! ## Design goals
//! - **Bounded**: `TMPFS_MAX_BYTES` cap prevents unbounded RAM growth.
//! - **Fast for a small, bounded table**: no inode tree walk — `names_equal`
//!   is a linear scan of up to `TMPFS_MAX_FILES` (64) entries, `O(n)`, NOT a
//!   hash lookup (there is no hash anywhere in this file). "Fast" describes
//!   avoiding a directory tree walk, not the lookup's own complexity class.
//! - **Eviction**: when full, the oldest (lowest `seq`) entry is removed to
//!   make room for the new one.  Callers that need durability use FAT32.
//! - **VFS-agnostic API**: kernel subsystems (logger, sensor recorder, etc.)
//!   use the direct `tmpfs_*` API; syscall wrappers adapt via the VFS.
//!
//! ## Limits
//! | Constant           | Value     | Meaning                          |
//! |--------------------|-----------|----------------------------------|
//! | `TMPFS_MAX_FILES`  | 64        | Max simultaneous entries         |
//! | `TMPFS_MAX_BYTES`  | 2 MiB     | Total cap on data bytes          |
//! | `TMPFS_NAME_LEN`   | 64        | Max filename length (bytes)      |

extern crate alloc;

use alloc::alloc::{alloc, dealloc, Layout};
use core::ptr;
use azos_sync::SpinLock;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of files that can exist in tmpfs simultaneously.
/// Kconfig `TMPFS_MAX_FILES` (default 64).
pub const TMPFS_MAX_FILES: usize = azos_limits::TMPFS_MAX_FILES;
/// Total data capacity (bytes).  Writes that would exceed this limit trigger
/// FIFO eviction of the oldest entry. Kconfig `TMPFS_MAX_KB` (default 2048,
/// 2 MiB).
pub const TMPFS_MAX_BYTES: usize = azos_limits::TMPFS_MAX_KB * 1024;
/// Maximum filename length including NUL terminator.
pub const TMPFS_NAME_LEN:  usize = 64;

// ── Entry ─────────────────────────────────────────────────────────────────────

/// One tmpfs file entry.
struct TmpEntry {
    /// Filename (NUL-padded, not NUL-terminated if exactly `TMPFS_NAME_LEN`).
    name:     [u8; TMPFS_NAME_LEN],
    /// Heap-allocated data buffer.
    data:     *mut u8,
    /// Allocated capacity in bytes.
    capacity: usize,
    /// Logical size (written bytes).
    size:     usize,
    /// Monotonic sequence number — lower = older.
    seq:      u32,
    /// Slot in use.
    active:   bool,
}

// SAFETY: TmpEntry contains a raw pointer but it is only accessed under the
// SpinLock, which prevents concurrent access.
unsafe impl Send for TmpEntry {}

const EMPTY_ENTRY: TmpEntry = TmpEntry {
    name: [0; TMPFS_NAME_LEN],
    data: ptr::null_mut(),
    capacity: 0,
    size: 0,
    seq: 0,
    active: false,
};

// ── Global table ──────────────────────────────────────────────────────────────

struct TmpfsState {
    entries:    [TmpEntry; TMPFS_MAX_FILES],
    used_bytes: usize,
    next_seq:   u32,
}

impl TmpfsState {
    const fn new() -> Self {
        TmpfsState {
            entries:    [EMPTY_ENTRY; TMPFS_MAX_FILES],
            used_bytes: 0,
            next_seq:   1,
        }
    }
}

static TMPFS: SpinLock<TmpfsState> = SpinLock::new(TmpfsState::new());

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by tmpfs operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmpfsError {
    /// No free slot and eviction failed (all entries pinned or all removed
    /// but still not enough space for the new entry alone).
    OutOfSpace,
    /// Filename exceeds `TMPFS_NAME_LEN` bytes.
    NameTooLong,
    /// File not found.
    NotFound,
    /// Internal heap allocation failed.
    AllocFailed,
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn name_fits(name: &[u8]) -> bool {
    name.len() < TMPFS_NAME_LEN
}

fn names_equal(a: &[u8; TMPFS_NAME_LEN], b: &[u8]) -> bool {
    let len = b.len().min(TMPFS_NAME_LEN);
    &a[..len] == b && (len >= TMPFS_NAME_LEN || a[len] == 0)
}

/// Find the index of the oldest (lowest seq) active entry.
fn oldest_index(state: &TmpfsState) -> Option<usize> {
    let mut min_seq = u32::MAX;
    let mut idx = None;
    for (i, e) in state.entries.iter().enumerate() {
        if e.active && e.seq < min_seq {
            min_seq = e.seq;
            idx = Some(i);
        }
    }
    idx
}

/// Free a single entry's heap buffer and mark it inactive.
unsafe fn free_entry(state: &mut TmpfsState, idx: usize) {
    let e = &mut state.entries[idx];
    if !e.data.is_null() {
        dealloc(e.data, Layout::from_size_align_unchecked(e.capacity, 1));
    }
    state.used_bytes -= e.size;
    state.entries[idx] = EMPTY_ENTRY;
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Write (create or overwrite) a file in tmpfs.
///
/// If the capacity cap would be exceeded, the oldest entry is evicted
/// repeatedly until there is room.  Returns `Err(OutOfSpace)` only if the
/// new data alone exceeds `TMPFS_MAX_BYTES`.
pub fn tmpfs_write(name: &[u8], data: &[u8]) -> Result<(), TmpfsError> {
    if !name_fits(name) { return Err(TmpfsError::NameTooLong); }
    if data.len() > TMPFS_MAX_BYTES { return Err(TmpfsError::OutOfSpace); }

    let mut state = TMPFS.lock();

    // Remove existing entry with the same name (overwrite).
    for i in 0..TMPFS_MAX_FILES {
        if state.entries[i].active && names_equal(&state.entries[i].name, name) {
            unsafe { free_entry(&mut state, i); }
            break;
        }
    }

    // Evict oldest until we have enough headroom.
    while state.used_bytes + data.len() > TMPFS_MAX_BYTES {
        if let Some(old) = oldest_index(&state) {
            unsafe { free_entry(&mut state, old); }
        } else {
            break;
        }
    }

    // Find a free slot.
    let slot = state.entries.iter().position(|e| !e.active)
        .ok_or(TmpfsError::OutOfSpace)?;

    // Allocate heap buffer.
    let buf = if data.is_empty() {
        ptr::null_mut()
    } else {
        let layout = unsafe { Layout::from_size_align_unchecked(data.len(), 1) };
        let p = unsafe { alloc(layout) };
        if p.is_null() { return Err(TmpfsError::AllocFailed); }
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()); }
        p
    };

    let seq = state.next_seq;
    state.next_seq = state.next_seq.wrapping_add(1);
    state.used_bytes += data.len();

    let e = &mut state.entries[slot];
    e.name[..name.len()].copy_from_slice(name);
    e.data     = buf;
    e.capacity = data.len();
    e.size     = data.len();
    e.seq      = seq;
    e.active   = true;

    Ok(())
}

/// Read a file from tmpfs into `buf`.
///
/// Returns the number of bytes actually copied (may be less than the file
/// size if `buf` is shorter).  Returns `Err(NotFound)` if the file does not
/// exist.
pub fn tmpfs_read(name: &[u8], buf: &mut [u8]) -> Result<usize, TmpfsError> {
    if !name_fits(name) { return Err(TmpfsError::NameTooLong); }
    let state = TMPFS.lock();
    for e in state.entries.iter() {
        if e.active && names_equal(&e.name, name) {
            let n = buf.len().min(e.size);
            unsafe { ptr::copy_nonoverlapping(e.data, buf.as_mut_ptr(), n); }
            return Ok(n);
        }
    }
    Err(TmpfsError::NotFound)
}

/// Read a file from tmpfs starting `offset` bytes in, into `buf`.
///
/// Returns the number of bytes actually copied (0 at or past EOF).
/// `Err(NotFound)` if the file does not exist. Streaming in name only — the
/// data is already RAM-resident, so this is `tmpfs_read` with an offset,
/// not a different code path — but it gives `TmpFs::read_at` the same
/// signature FAT32's real streaming implementation has, so a caller
/// migrated onto `FileSystem::read_at` sees one seam, not one streaming
/// backend and one that still expects a whole-file buffer.
pub fn tmpfs_read_at(name: &[u8], offset: usize, buf: &mut [u8]) -> Result<usize, TmpfsError> {
    if !name_fits(name) { return Err(TmpfsError::NameTooLong); }
    let state = TMPFS.lock();
    for e in state.entries.iter() {
        if e.active && names_equal(&e.name, name) {
            if offset >= e.size { return Ok(0); }
            let n = buf.len().min(e.size - offset);
            unsafe { ptr::copy_nonoverlapping(e.data.add(offset), buf.as_mut_ptr(), n); }
            return Ok(n);
        }
    }
    Err(TmpfsError::NotFound)
}

/// Write `data` at `offset` bytes into a tmpfs file, growing it (and
/// reallocating) if `offset + data.len()` exceeds the current size.
/// Creates the file if it does not exist. Any gap between the old size and
/// `offset` is zero-filled, matching FAT32's `write_at` (`zero_fill_range`)
/// so a caller cannot tell the two backends apart by what a hole reads back
/// as. Returns bytes written.
pub fn tmpfs_write_at(name: &[u8], offset: usize, data: &[u8]) -> Result<usize, TmpfsError> {
    if !name_fits(name) { return Err(TmpfsError::NameTooLong); }
    if data.is_empty() { return Ok(0); }
    let write_end = offset.checked_add(data.len()).ok_or(TmpfsError::OutOfSpace)?;
    if write_end > TMPFS_MAX_BYTES { return Err(TmpfsError::OutOfSpace); }

    let mut state = TMPFS.lock();

    let existing = (0..TMPFS_MAX_FILES)
        .find(|&i| state.entries[i].active && names_equal(&state.entries[i].name, name));
    let old_size = existing.map(|i| state.entries[i].size).unwrap_or(0);
    // A write entirely inside the current file must not shrink it — only
    // `offset + data.len()` past the existing size grows anything.
    let new_size = write_end.max(old_size);

    if new_size > old_size {
        // Evict oldest entries (other than this one) until the size delta
        // fits, exactly as `tmpfs_write` does for a whole new file.
        let delta = new_size - old_size;
        while state.used_bytes + delta > TMPFS_MAX_BYTES {
            let victim = (0..TMPFS_MAX_FILES)
                .filter(|&i| state.entries[i].active && Some(i) != existing)
                .min_by_key(|&i| state.entries[i].seq);
            match victim {
                Some(v) => unsafe { free_entry(&mut state, v); },
                None    => break,
            }
        }
        if state.used_bytes + delta > TMPFS_MAX_BYTES {
            return Err(TmpfsError::OutOfSpace);
        }
    }

    let layout = unsafe { Layout::from_size_align_unchecked(new_size.max(1), 1) };
    let new_buf = unsafe { alloc(layout) };
    if new_buf.is_null() { return Err(TmpfsError::AllocFailed); }
    unsafe {
        // Zero the whole thing first so a hole (old_size..offset, on growth
        // past the old EOF) reads back as zero rather than the allocator's
        // leftovers.
        ptr::write_bytes(new_buf, 0, new_size);
        if let Some(i) = existing {
            let old = &state.entries[i];
            if !old.data.is_null() && old.size > 0 {
                ptr::copy_nonoverlapping(old.data, new_buf, old.size);
            }
        }
        ptr::copy_nonoverlapping(data.as_ptr(), new_buf.add(offset), data.len());
    }

    let slot = match existing {
        Some(i) => {
            unsafe {
                let old = &state.entries[i];
                if !old.data.is_null() {
                    dealloc(old.data, Layout::from_size_align_unchecked(old.capacity, 1));
                }
            }
            i
        }
        None => {
            let s = state.entries.iter().position(|e| !e.active)
                .ok_or(TmpfsError::OutOfSpace)?;
            state.entries[s].name = [0; TMPFS_NAME_LEN];
            state.entries[s].name[..name.len()].copy_from_slice(name);
            s
        }
    };

    let seq = state.next_seq;
    state.next_seq = state.next_seq.wrapping_add(1);
    state.used_bytes = state.used_bytes - old_size + new_size;

    let e = &mut state.entries[slot];
    e.data     = new_buf;
    e.capacity = new_size;
    e.size     = new_size;
    e.seq      = seq;
    e.active   = true;

    Ok(data.len())
}

/// Get the size of a tmpfs file without reading its data.
pub fn tmpfs_size(name: &[u8]) -> Option<usize> {
    if !name_fits(name) { return None; }
    let state = TMPFS.lock();
    for e in state.entries.iter() {
        if e.active && names_equal(&e.name, name) {
            return Some(e.size);
        }
    }
    None
}

/// Remove a file from tmpfs.
///
/// Returns `Ok(())` if deleted, `Err(NotFound)` if it did not exist.
pub fn tmpfs_unlink(name: &[u8]) -> Result<(), TmpfsError> {
    if !name_fits(name) { return Err(TmpfsError::NameTooLong); }
    let mut state = TMPFS.lock();
    for i in 0..TMPFS_MAX_FILES {
        if state.entries[i].active && names_equal(&state.entries[i].name, name) {
            unsafe { free_entry(&mut state, i); }
            return Ok(());
        }
    }
    Err(TmpfsError::NotFound)
}

/// List all active entries.  Calls `cb(name_bytes, size)` for each file.
/// The `name_bytes` slice is the raw name without trailing NUL bytes.
pub fn tmpfs_ls(mut cb: impl FnMut(&[u8], usize)) {
    let state = TMPFS.lock();
    for e in state.entries.iter() {
        if !e.active { continue; }
        let name_len = e.name.iter().position(|&b| b == 0).unwrap_or(TMPFS_NAME_LEN);
        cb(&e.name[..name_len], e.size);
    }
}

/// Return `(files_active, used_bytes, max_bytes)`.
/// Set `name`'s size to `len`: shrink in place, or grow with zeros (through
/// `tmpfs_write_at`, which zero-fills). RFC-0048 P2, behind
/// `FileSystem::truncate`.
pub fn tmpfs_truncate(name: &[u8], len: usize) -> Result<(), TmpfsError> {
    if !name_fits(name) { return Err(TmpfsError::NameTooLong); }
    {
        let mut state = TMPFS.lock();
        let i = (0..TMPFS_MAX_FILES)
            .find(|&i| state.entries[i].active && names_equal(&state.entries[i].name, name))
            .ok_or(TmpfsError::NotFound)?;
        let size = state.entries[i].size;
        if len <= size {
            // `used_bytes` counts sizes (see `free_entry`); the allocation
            // keeps its capacity and is freed by it.
            state.entries[i].size = len;
            state.used_bytes -= size - len;
            return Ok(());
        }
    }
    // Grow: one zero byte at the new last offset; the gap is zero-filled.
    tmpfs_write_at(name, len - 1, &[0]).map(|_| ())
}

/// Rename `from` to `to`, replacing an existing `to`. RFC-0048 P2, behind
/// `FileSystem::rename`.
pub fn tmpfs_rename(from: &[u8], to: &[u8]) -> Result<(), TmpfsError> {
    if !name_fits(from) || !name_fits(to) || to.is_empty() { return Err(TmpfsError::NameTooLong); }
    let mut state = TMPFS.lock();
    let src = (0..TMPFS_MAX_FILES)
        .find(|&i| state.entries[i].active && names_equal(&state.entries[i].name, from))
        .ok_or(TmpfsError::NotFound)?;
    if let Some(dst) = (0..TMPFS_MAX_FILES)
        .find(|&i| i != src && state.entries[i].active && names_equal(&state.entries[i].name, to))
    {
        unsafe { free_entry(&mut state, dst); }
    }
    let e = &mut state.entries[src];
    e.name = [0; TMPFS_NAME_LEN];
    e.name[..to.len()].copy_from_slice(to);
    Ok(())
}

pub fn tmpfs_stats() -> (usize, usize, usize) {
    let state = TMPFS.lock();
    let active = state.entries.iter().filter(|e| e.active).count();
    (active, state.used_bytes, TMPFS_MAX_BYTES)
}

// ── The VFS backend ───────────────────────────────────────────────────────────

/// tmpfs as a value the VFS can be handed.
///
/// **Not mounted by `vfs::init()`.** Implementing the interface and changing
/// what `/tmp` resolves to are two different changes; this is the first one.
/// Mounting it is `vfs_mount_fs(b"/tmp", &TMPFS_FS)`, one line, once someone
/// decides `open("/tmp/x")` should stop returning -1.
pub struct TmpFs;

/// The tmpfs backend, as a value.
pub static TMPFS_FS: TmpFs = TmpFs;

/// `FS_TYPE_*` tag for tmpfs. There was no tag for it, because there was no
/// way to mount it.
pub const FS_TYPE_TMPFS: u32 = 2;

/// The generic key holds every name tmpfs stores (see `key_for`).
const _: () = assert!(TMPFS_NAME_LEN <= crate::vfs::INODE_KEY_LEN);

impl crate::vfs::FileSystem for TmpFs {
    /// RAM-resident: no device wait (owner rule F1 does not apply).
    fn device_backed(&self) -> bool { false }

    #[inline]
    fn fs_type(&self) -> u32 { FS_TYPE_TMPFS }

    /// Nothing to bring online: the entry table is a static, and the first
    /// write initialises whatever it needs.
    #[inline]
    fn mount(&self) -> Result<(), ()> { Ok(()) }

    /// Nothing to flush: `tmpfs_write` copies into the heap synchronously and
    /// tmpfs is RAM, so there is no medium to be behind.
    #[inline]
    fn sync(&self) -> Result<(), ()> { Ok(()) }

    /// **Every tmpfs name fits the generic key.** `INODE_KEY_LEN` is
    /// `TMPFS_NAME_LEN` (64; the `const _` above this impl checks it), so a name is
    /// refused here only when it is empty, longer than tmpfs itself stores,
    /// or has a `/` in it. (Until wave 10 the key was 11 bytes and every
    /// longer tmpfs name returned `None`.)
    #[inline]
    fn key_for(&self, name: &[u8]) -> Option<crate::vfs::InodeKey> {
        if name.is_empty() || name.len() > crate::vfs::INODE_KEY_LEN { return None; }
        if name.contains(&b'/') { return None; }
        let mut bytes = [0u8; crate::vfs::INODE_KEY_LEN];
        bytes[..name.len()].copy_from_slice(name);
        Some(crate::vfs::InodeKey { bytes })
    }

    #[inline]
    fn stat(&self, key: &crate::vfs::InodeKey) -> Option<crate::vfs::FileStat> {
        let name = key_name(key);
        let size = tmpfs_size(name)?;
        Some(crate::vfs::FileStat::file(size as u64, 0))
    }

    /// tmpfs has no locator, so the cookie is unused and the lookup is by
    /// name — a second `O(n)` scan of 64 slots, which is what `tmpfs_read`
    /// costs anyway.
    #[inline]
    fn read_all(
        &self,
        key: &crate::vfs::InodeKey,
        _st: &crate::vfs::FileStat,
        dst: &mut [u8],
    ) -> usize {
        tmpfs_read(key_name(key), dst).unwrap_or(0)
    }

    #[inline]
    fn write_all(&self, key: &crate::vfs::InodeKey, src: &[u8]) -> Result<(), ()> {
        tmpfs_write(key_name(key), src).map_err(|_| ())
    }

    #[inline]
    fn unlink(&self, key: &crate::vfs::InodeKey) -> Result<(), ()> {
        tmpfs_unlink(key_name(key)).map_err(|_| ())
    }

    #[inline]
    fn read_at(&self, key: &crate::vfs::InodeKey, offset: u64, dst: &mut [u8]) -> usize {
        let offset = match usize::try_from(offset) { Ok(o) => o, Err(_) => return 0 };
        tmpfs_read_at(key_name(key), offset, dst).unwrap_or(0)
    }

    #[inline]
    fn write_at(&self, key: &crate::vfs::InodeKey, offset: u64, src: &[u8]) -> Result<usize, ()> {
        let offset = usize::try_from(offset).map_err(|_| ())?;
        tmpfs_write_at(key_name(key), offset, src).map_err(|_| ())
    }

    // ── RFC-0048 P2 ──────────────────────────────────────────────────────

    /// tmpfs is RAM: reading and writing in place is what it does anyway,
    /// so it is the tree's streaming backend.
    #[inline]
    fn streaming(&self) -> bool { true }

    fn create(&self, key: &crate::vfs::InodeKey) -> Result<(), crate::vfs::FsErr> {
        let name = key_name(key);
        if tmpfs_size(name).is_some() { return Ok(()); }
        tmpfs_write(name, &[]).map_err(tmpfs_err)
    }

    fn truncate(&self, key: &crate::vfs::InodeKey, len: u64) -> Result<(), crate::vfs::FsErr> {
        let len = usize::try_from(len).map_err(|_| crate::vfs::FsErr::NoSpace)?;
        if len > TMPFS_MAX_BYTES { return Err(crate::vfs::FsErr::NoSpace); }
        tmpfs_truncate(key_name(key), len).map_err(tmpfs_err)
    }

    fn rename(&self, from: &[u8], to: &[u8]) -> Result<(), crate::vfs::FsErr> {
        if from.contains(&b'/') || to.contains(&b'/') { return Err(crate::vfs::FsErr::NotFound); }
        tmpfs_rename(from, to).map_err(tmpfs_err)
    }

    fn statfs(&self) -> Result<crate::vfs::StatFs, crate::vfs::FsErr> {
        let (active, used, max) = tmpfs_stats();
        Ok(crate::vfs::StatFs {
            fs_type: FS_TYPE_TMPFS, block_size: 1,
            blocks: max as u64, blocks_free: max.saturating_sub(used) as u64,
            files: TMPFS_MAX_FILES as u64,
            files_free: TMPFS_MAX_FILES.saturating_sub(active) as u64,
            name_max: (TMPFS_NAME_LEN - 1) as u32,
        })
    }

    /// Flat: only the root, `""`. The cookie is the slot index to resume at.
    fn readdir(
        &self,
        dir: &[u8],
        cookie: u64,
        out: &mut crate::vfs::DirEnt,
    ) -> Result<Option<u64>, crate::vfs::FsErr> {
        if !dir.is_empty() { return Err(crate::vfs::FsErr::NotFound); }
        let state = TMPFS.lock();
        let start = usize::try_from(cookie).unwrap_or(usize::MAX);
        for i in start..TMPFS_MAX_FILES {
            let e = &state.entries[i];
            if !e.active { continue; }
            let n = e.name.iter().position(|&b| b == 0).unwrap_or(TMPFS_NAME_LEN);
            out.set(&e.name[..n], false, e.size as u64);
            return Ok(Some(i as u64 + 1));
        }
        Ok(None)
    }
}

fn tmpfs_err(e: TmpfsError) -> crate::vfs::FsErr {
    match e {
        TmpfsError::OutOfSpace | TmpfsError::AllocFailed => crate::vfs::FsErr::NoSpace,
        TmpfsError::NameTooLong => crate::vfs::FsErr::NameTooLong,
        TmpfsError::NotFound => crate::vfs::FsErr::NotFound,
    }
}

/// The key's bytes trimmed at the first NUL — tmpfs names are plain bytes, so
/// the key is the name, NUL-padded.
#[inline]
fn key_name(key: &crate::vfs::InodeKey) -> &[u8] {
    let n = key.bytes.iter().position(|&b| b == 0).unwrap_or(crate::vfs::INODE_KEY_LEN);
    &key.bytes[..n]
}

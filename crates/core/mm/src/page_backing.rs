// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a file-backed MemObj (`MemKind::Paged`) reads its pages from and writes
//! them back to: the callback the unified page cache calls (storage L11).
//!
//! The cache is the MemObj: a cached page is one of the object's frames, there
//! is no second copy. This file is the other half of that, the part that
//! knows nothing of frames and tables: how a page's bytes come from, and go
//! back to, a file. It names `core` only, so the object table (`azos_ipc`),
//! the file layer (`azos_fs`) and the host suites all link the one source.
//!
//! **Byte offsets, not page numbers.** The cache's page is the translation
//! granule of the build (4, 16 or 64 KiB), and the file layer must not repeat
//! that constant (a fixed 4096 in an offset split already cost this tree a
//! bug). The cache passes the byte offset of the page and a slice whose length
//! is the page, or less at the end of the file.
//!
//! **Where the file ends.** A page that straddles the end of the file is
//! filled with the file's bytes and zeros after them, and written back as the
//! file's bytes only ([`valid_len`]): a write-back never grows the file, and a
//! mapping past the end can never lengthen it. The size is the cache's to
//! know (the object records it); the backing is never asked beyond it.

/// Bytes of the backend's own name for a file: what the cache stores and hands
/// back on every call. The file layer's `InodeKey` is exactly this long (the
/// file layer asserts it), so naming a file costs no table and no handle.
pub const PAGE_KEY_LEN: usize = 64;

/// A file, as its backend names it. Opaque to the cache.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageKey(pub [u8; PAGE_KEY_LEN]);

/// A backing call failed. The cache keeps no detail: a failed fill maps
/// nothing, a failed write-back leaves the page dirty.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PageIoError {
    Io,
}

/// A file's page store. Called with no lock held (a call may wait for the
/// medium), from task context.
pub trait PageBacking: Sync {
    /// Read the file's bytes at byte offset `off` into `dst`; how many were
    /// read. Fewer than `dst.len()` means the file ended there.
    fn read_page(&self, key: &PageKey, off: u64, dst: &mut [u8]) -> Result<usize, PageIoError>;

    /// Write `src` at byte offset `off`. All of it or an error.
    fn write_page(&self, key: &PageKey, off: u64, src: &[u8]) -> Result<(), PageIoError>;
}

/// The bytes of the page at byte offset `off` that lie inside a file of
/// `file_size` bytes: the whole page, the part up to the end of the file, or 0
/// past it.
pub const fn valid_len(file_size: u64, off: u64, page_bytes: usize) -> usize {
    let left = file_size.saturating_sub(off);
    if left < page_bytes as u64 {
        left as usize
    } else {
        page_bytes
    }
}

/// Fill `dst` (one page, which the caller owns) with the page at byte offset
/// `off` of the file: the file's bytes inside `file_size`, zeros after them
/// (and wherever the backing read short). The backing is asked for the valid
/// part only.
pub fn fill_page(
    b: &dyn PageBacking,
    key: &PageKey,
    off: u64,
    file_size: u64,
    dst: &mut [u8],
) -> Result<(), PageIoError> {
    let n = valid_len(file_size, off, dst.len());
    let got = if n == 0 { 0 } else { b.read_page(key, off, &mut dst[..n])?.min(n) };
    dst[got..].fill(0);
    Ok(())
}

/// Write the page `src` back to the file at byte offset `off`: its valid part
/// only, and nothing at all for a page wholly past the end.
pub fn write_back_page(
    b: &dyn PageBacking,
    key: &PageKey,
    off: u64,
    file_size: u64,
    src: &[u8],
) -> Result<(), PageIoError> {
    let n = valid_len(file_size, off, src.len());
    if n == 0 {
        return Ok(());
    }
    b.write_page(key, off, &src[..n])
}

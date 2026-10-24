// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The page cache under the file layer (storage L11, part B), installed.
//!
//! `azos_fs` routes the file data of a filesystem that takes the cache
//! (`FileSystem::page_cached`: FAT32 and tmpfs) through [`PageCacheHooks`]
//! when the kernel has installed them, and reads and writes the backend with
//! none. This installs them once, before the first volume is mounted, so no
//! file's data is ever read or written both ways.
//!
//! The cache is the one `mmap` maps: a `MemKind::Paged` object per 64-page
//! window of a file, kept by `azos_syscall::file_map`'s registry (the hooks
//! are `file_map::cache_*` in terms of the filesystem's `FsPageBacking`, one
//! value per filesystem, which is how a `write` and a `MAP_SHARED` store meet
//! in one frame). What is the kernel's here:
//!
//! * `now_ms` and `wake`: the `fs-wb` task's clock and waker. Over its
//!   watermark the cache wakes the same task that writes the FAT32 block
//!   cache back, and its pass (`fat32_writeback_tick`) starts with the pages;
//! * `domain`: the Domain of the task that is calling, whose writers are
//!   throttled by their own dirty pages (`azos_fs::vfs`'s `DIRTY` rows);
//! * `domain_budget`: the dirty pages a Domain may hold before its writers
//!   write back, the `FS_WRITEBACK_WATERMARK_PCT` share of its frame budget
//!   (`azos_sched::domain::used_limit`); a Domain with no frame budget (the
//!   kernel's own tasks, `fs-wb` among them) has that share of the cache;
//! * `capacity_pages`: what the dirty share is a share of: the pages of the
//!   object table's full complement of windows, at most half the frames the
//!   machine has, so the cache cannot be asked to hold more than it could.
//!
//! The cache's memory is system memory and charged to no Domain; it goes back
//! to the allocator under pressure (`tasks::reclaim` writes back and drops
//! clean pages) and, with `FS_WRITEBACK` off, a write is made durable before it
//! returns (the file layer's rule, not this file's).

use azos_fs::{FileSystem, FsErr, FsPageBacking, InodeKey, PageCacheHooks};
use azos_syscall::file_map;

use crate::kprintln;

/// The filesystem's page backing and the page-cache name of the file: `None`
/// past the distinct filesystems the pool can name (the caller then reads the
/// backend).
fn name(fs: &'static dyn FileSystem, key: &InodeKey) -> Option<(&'static FsPageBacking, azos_mm::pager::PageKey)> {
    Some((azos_fs::backing_of(fs)?, FsPageBacking::page_key(key)))
}

fn read(fs: &'static dyn FileSystem, key: &InodeKey, size: u64, off: u64, dst: &mut [u8]) -> Option<usize> {
    let (b, k) = name(fs, key)?;
    file_map::cache_read(b, &k, size, off, dst)
}

fn write(fs: &'static dyn FileSystem, key: &InodeKey, size: u64, off: u64, src: &[u8]) -> Option<(usize, usize)> {
    let (b, k) = name(fs, key)?;
    file_map::cache_write(b, &k, size, off, src)
}

fn writeback(fs: &'static dyn FileSystem, key: &InodeKey) -> Result<(), FsErr> {
    let Some((b, k)) = name(fs, key) else { return Ok(()) };
    file_map::cache_writeback(b, Some(&k)).map_err(|()| FsErr::Io)
}

fn flush_fs(fs: &'static dyn FileSystem) -> Result<(), FsErr> {
    let Some(b) = azos_fs::backing_of(fs) else { return Ok(()) };
    file_map::cache_writeback(b, None).map_err(|()| FsErr::Io)
}

fn forget(fs: &'static dyn FileSystem, key: Option<&InodeKey>, from: u64) {
    let Some(b) = azos_fs::backing_of(fs) else { return };
    let k = key.map(FsPageBacking::page_key);
    if !file_map::cache_forget(b, k.as_ref(), from) {
        // A page that kept being written back, or a mapper that is pinned. The
        // cache has marked the object stale: it is not served, mapped or
        // written back until a later call has forgotten it, so the file's
        // reads go to the backend and its writes and write-backs fail with
        // `Io` meanwhile; nothing old reaches whatever has the name now.
        azos_drv_sys::kerr!("[FS] page cache: pages of a changed file are held; the file is unserved until they go");
    }
}

fn capacity_pages() -> usize {
    file_map::CACHE_PAGES.min(azos_mm::pmm::total_pages() / 2)
}

fn domain() -> u32 {
    azos_ipc::cap_store::domain_key_of(azos_sched::current_proc_tid())
}

fn domain_budget(domain: u32) -> usize {
    let (_, limit) = azos_sched::domain::used_limit(domain);
    budget_pages(limit as usize, capacity_pages())
}

/// The dirty pages one Domain may hold: the watermark's share of its frame
/// budget `limit`, or of the cache's `capacity` when it has none (`limit == 0`:
/// the kernel's own tasks, `fs-wb` among them, and a key that names no Domain).
fn budget_pages(limit: usize, capacity: usize) -> usize {
    let pages = if limit == 0 { capacity } else { limit };
    pages * azos_limits::FS_WRITEBACK_WATERMARK_PCT as usize / 100
}

static HOOKS: PageCacheHooks = PageCacheHooks {
    read,
    write,
    writeback,
    flush_fs,
    drop: forget,
    capacity_pages,
    domain,
    domain_budget,
    now_ms: super::fs_wb_now_ms,
    wake: super::fs_wb_wake,
};

/// Install the page cache under the file layer. Boot, once, after the object
/// table and the allocator exist and before any filesystem that takes it is
/// mounted. Every ISA.
pub(crate) fn install_page_cache() {
    azos_fs::vfs_page_cache_hooks(Some(&HOOKS));
    // The boot canary (`tools/gate/ci_check.sh`, the "disk: partition cap refused from ring 3" row): the line below
    // is printed only when the file layer says the table is in place, and
    // carries the budget of the kernel's own Domain, which runs the
    // `limit == 0` arm of `domain_budget` that `fs-wb` takes every pass.
    if !azos_fs::page_cache_installed() {
        azos_drv_sys::kerr!("[FS] page cache NOT installed: the file layer refused the hooks");
        return;
    }
    kprintln!(
        "[FS] page cache installed: {} windows of {} pages, {} pages at most, dirty watermark {}%, kernel budget {} pages, write-back {}",
        azos_ipc::memobj::MAX_MEMOBJS,
        azos_ipc::memobj::MAX_MEMOBJ_PAGES,
        capacity_pages(),
        azos_limits::FS_WRITEBACK_WATERMARK_PCT,
        domain_budget(azos_sched::domain::NONE),
        if azos_limits::FS_WRITEBACK { "by age" } else { "through" },
    );
}

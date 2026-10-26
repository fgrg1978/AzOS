// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for storage L11 part B: FAT32 and tmpfs file data through the
//! unified page cache (`crates/fs/src/vfs.rs`, "The page cache seam").
//!
//! The rows run the REAL `vfs.rs`, `fat32.rs`, `tmpfs.rs` and the REAL
//! `FsPageBacking` + `fill_page`/`write_back_page` arithmetic; what stands in
//! for the kernel is the object table: [`Cache`] below implements
//! `PageCacheHooks` over boxed page buffers with the semantics of
//! `azos_ipc::memobj`'s Paged objects (fill once from the file, clamp to the
//! size the file has, dirty on write or through a writable mapping, write back
//! through the backing, drop forgets). The object table's own rows are
//! `crates/core/ipc/src/memobj.rs`'s tests; this file proves the file layer's
//! half: what is routed through the cache, when it reaches the backend, and
//! that nothing reads or discards the file's bytes behind it.
//!
//! Every row takes `serial()` and installs the cache for its own length only
//! ([`Installed`]), so the rest of the suite (written before the cache) keeps
//! running against none.
//!
//! Canaries (by hand, 2026-10-17; discriminates / does not / did not compile):
//! * `cache_read` not asking the cache (`None` always): `a_second_read_is_served_from_the_cache`
//!   and `a_mapping_and_read_see_the_same_page` red.
//! * `cache_write` writing the backend (`None` always): `a_write_inside_the_file_stays_in_the_cache_until_fsync` red.
//! * `fd_fsync_finish` / `vfs_fsync` without `page_cache_flush_file`: the same row red.
//! * `cache_write`'s extension without the `page_cache_flush_file`: `an_extending_write_keeps_the_dirty_pages_before_it` red.
//! * `fat32_sync_checked` without `page_cache_flush_fs`: `sync_and_unmount_write_the_pages_back` red.
//! * `fat32_unmount` without the leading `page_cache_flush_fs`: the same row red.
//! * `fat32_writeback_tick` without `page_cache_writeback_due`: the age, ratio and budget rows red.
//! * `page_cache_writeback_due` ignoring the age (`aged` true): `the_flusher_waits_for_the_age` red.
//! * `page_cache_throttle` without the budget test: `a_domain_over_its_budget_writes_back_its_own_files` red.
//! * `vfs_unlink` / `vfs_truncate` / `vfs_rename` / `vfs_replace_file` / `vfs_content_stamp` / the O_TRUNC open without their cache call (FAT32's own `cache_forget` and rename flush removed with them): the matching `coherence_*` row red; `vfs_unlink` alone on tmpfs: `a_tmpfs_file_goes_through_the_cache` red.
//! * `vfs_fsync` without `page_cache_flush_file`: the tmpfs row red (FAT32's fsync is a volume sync, which writes the pages itself); `fd_fsync_finish` the same through the split fsync.
//! * `read_sector_with` retaining (`retain` ignored): `the_block_cache_does_not_keep_what_the_page_cache_filled` red.
//! * `Fat32Fs::page_cached` / `TmpFs::page_cached` false: that backend's rows red.
//! * (review fixes, 2026-10-17) `page_cache_writeback_due` ending the pass at the first failed file: `a_failing_file_does_not_starve_the_others` red.
//! * `page_cache_throttle` dropping the failure (no `WB_FAILED`) or breaking at it: `a_throttle_that_cannot_write_a_file_back_goes_on_and_reports_it` red.
//! * `dirty_note` matching the file only (the first dirtier's Domain): `pages_are_charged_to_the_domain_that_dirtied_them` red.
//! * `cache_read` without the `handle_names` test: `a_read_only_stream_does_not_read_a_replaced_name_through_the_cache` red.
//! * the double's `attach` clearing the pages on growth: `appends_write_through_and_do_not_refill_the_file` red.
//! * `WB_FAILED` one flag for every filesystem: `a_write_back_failure_is_reported_by_its_own_filesystem` red.
//! * `fat32_unlink_root` without its `cache_forget`s: `coherence_unlink_path_mkdir_and_rmdir` red.
//! * `fat32_read` without its settle, `fat32_write` without its settle or its forget, `fat32_open(TRUNCATE)` without its forget: `coherence_the_direct_handle_api` red (four canaries).
//! * Does NOT discriminate: the `page_cache_drop` after the `replace-in-place-canary` branch of `vfs_replace_file`
//!   (the drop before it already empties the cache and the branch is raw; only a reader that refills the cache
//!   in the middle of the replace could see the difference, and the host has no second thread there). Kept for that race.
//!
//! Wired into the suite by `mod l11b;` in `src/lib.rs` (the integrator's line; not on the front's branch).

#![cfg(test)]

use super::{fat32, image::*, pagecache::FsPageBacking, serial, tmpfs, vfs, vfs_open_close, vfs_p2};
use azos_mm::pager::{fill_page, write_back_page, PageKey};
use fs_test_drivers::{disk_durable_image, disk_stats, disk_take_log, disk_write_fail_after, disk_write_fail_clear,
                      disk_writeback, LogEntry};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use vfs::{FileSystem, FsErr, InodeKey, PageCacheHooks, O_APPEND, O_RDONLY, O_RDWR, O_TRUNC};

use fat32::FAT32_FS as FAT;

// ── The cache: what the kernel's object table is, on the host ───────────────

struct CFile {
    fs: &'static dyn FileSystem,
    key: InodeKey,
    /// The size the pages were filled and are clamped at.
    size: u64,
    pages: BTreeMap<u64, Box<[u8]>>,
    dirty: BTreeSet<u64>,
}

struct Store {
    files: Vec<CFile>,
    page: usize,
    cap: usize,
    /// `(domain, budget)`; a domain with no row has none.
    budgets: Vec<(u32, usize)>,
    /// Pages filled from the backing since the install.
    fills: usize,
    /// Pages written back since the install.
    written: usize,
    /// Calls of `read`/`write` the cache answered.
    served: usize,
    /// Answer `None` to `read` and `write`: the cache cannot serve.
    decline: bool,
    /// Files whose `writeback` fails (the medium refuses them).
    fail: Vec<InodeKey>,
    /// Calls of `writeback` since the install.
    writebacks: usize,
}

static STORE: Mutex<Store> = Mutex::new(Store {
    files: Vec::new(), page: 1024, cap: 64, budgets: Vec::new(), fills: 0, written: 0, served: 0, decline: false,
    fail: Vec::new(), writebacks: 0,
});
static DOMAIN: AtomicU32 = AtomicU32::new(0);
static NOW: AtomicU64 = AtomicU64::new(1);
static WAKES: AtomicUsize = AtomicUsize::new(0);

/// The store, whether or not a failed row poisoned it.
fn store() -> std::sync::MutexGuard<'static, Store> {
    STORE.lock().unwrap_or_else(|e| e.into_inner())
}

fn same(f: &CFile, fs: &dyn FileSystem, key: &InodeKey) -> bool {
    f.key == *key
        && core::ptr::addr_eq(f.fs as *const dyn FileSystem, fs as *const dyn FileSystem)
        && f.fs.fs_type() == fs.fs_type()
}

impl Store {
    /// The file's slot, attached at `size`. What was dirty is written back at
    /// the old size first. A SHORTER file is another object: the pages go. A
    /// LONGER one keeps its pages except the one that held the old end, which
    /// has zeros after it that are bytes now (the contract of
    /// `PageCacheHooks::read`).
    fn attach(&mut self, fs: &'static dyn FileSystem, key: &InodeKey, size: u64) -> usize {
        if let Some(i) = self.files.iter().position(|f| same(f, fs, key)) {
            if self.files[i].size != size {
                self.writeback(i).expect("write-back at the old size");
                let old = self.files[i].size;
                if size > old {
                    let end_page = old / self.page as u64;
                    self.files[i].pages.remove(&end_page);
                } else {
                    self.files[i].pages.clear();
                }
                self.files[i].size = size;
            }
            return i;
        }
        self.files.push(CFile { fs, key: *key, size, pages: BTreeMap::new(), dirty: BTreeSet::new() });
        self.files.len() - 1
    }

    fn ensure(&mut self, i: usize, idx: u64) {
        if self.files[i].pages.contains_key(&idx) {
            return;
        }
        let page = self.page;
        let f = &self.files[i];
        let mut buf = vec![0xFFu8; page].into_boxed_slice();
        fill_page(&FsPageBacking::new(f.fs), &PageKey(f.key.bytes), idx * page as u64, f.size, &mut buf).expect("fill");
        self.files[i].pages.insert(idx, buf);
        self.fills += 1;
    }

    fn writeback(&mut self, i: usize) -> Result<(), FsErr> {
        let page = self.page;
        let idxs: Vec<u64> = self.files[i].dirty.iter().copied().collect();
        for idx in idxs {
            let f = &self.files[i];
            let b = FsPageBacking::new(f.fs);
            write_back_page(&b, &PageKey(f.key.bytes), idx * page as u64, f.size, &f.pages[&idx]).map_err(|_| FsErr::Io)?;
            self.files[i].dirty.remove(&idx);
            self.written += 1;
        }
        Ok(())
    }

    fn dirty_pages(&self) -> usize {
        self.files.iter().map(|f| f.dirty.len()).sum()
    }
}

fn h_read(fs: &'static dyn FileSystem, key: &InodeKey, size: u64, off: u64, dst: &mut [u8]) -> Option<usize> {
    let mut s = store();
    if s.decline {
        return None;
    }
    let i = s.attach(fs, key, size);
    let page = s.page as u64;
    let end = (off + dst.len() as u64).min(size);
    let mut done = 0usize;
    let mut pos = off;
    while pos < end {
        let idx = pos / page;
        s.ensure(i, idx);
        let at = (pos % page) as usize;
        let n = ((page as usize - at) as u64).min(end - pos) as usize;
        dst[done..done + n].copy_from_slice(&s.files[i].pages[&idx][at..at + n]);
        done += n;
        pos += n as u64;
    }
    s.served += 1;
    Some(done)
}

fn h_write(fs: &'static dyn FileSystem, key: &InodeKey, size: u64, off: u64, src: &[u8]) -> Option<(usize, usize)> {
    let mut s = store();
    if s.decline {
        return None;
    }
    assert!(off + src.len() as u64 <= size, "the file layer sent an extension to the cache");
    let i = s.attach(fs, key, size);
    let page = s.page as u64;
    let mut done = 0usize;
    let mut pos = off;
    let mut newly = 0usize;
    while done < src.len() {
        let idx = pos / page;
        s.ensure(i, idx);
        let at = (pos % page) as usize;
        let n = (page as usize - at).min(src.len() - done);
        s.files[i].pages.get_mut(&idx).unwrap()[at..at + n].copy_from_slice(&src[done..done + n]);
        if s.files[i].dirty.insert(idx) {
            newly += 1;
        }
        done += n;
        pos += n as u64;
    }
    s.served += 1;
    Some((done, newly))
}

fn h_writeback(fs: &'static dyn FileSystem, key: &InodeKey) -> Result<(), FsErr> {
    let mut s = store();
    s.writebacks += 1;
    if s.fail.contains(key) {
        return Err(FsErr::Io);
    }
    match s.files.iter().position(|f| same(f, fs, key)) {
        Some(i) => s.writeback(i),
        None => Ok(()),
    }
}

fn h_flush_fs(fs: &'static dyn FileSystem) -> Result<(), FsErr> {
    let mut s = store();
    for i in 0..s.files.len() {
        if core::ptr::addr_eq(s.files[i].fs as *const dyn FileSystem, fs as *const dyn FileSystem) {
            if s.fail.contains(&s.files[i].key) {
                return Err(FsErr::Io);
            }
            s.writeback(i)?;
        }
    }
    Ok(())
}

fn h_drop(fs: &'static dyn FileSystem, key: Option<&InodeKey>, from: u64) {
    let mut s = store();
    let page = s.page as u64;
    for f in s.files.iter_mut() {
        if !core::ptr::addr_eq(f.fs as *const dyn FileSystem, fs as *const dyn FileSystem)
            || key.is_some_and(|k| f.key != *k)
        {
            continue;
        }
        // Every page that holds a byte at or after `from`.
        let first = from / page;
        f.pages.retain(|&idx, _| idx < first);
        f.dirty.retain(|&idx| idx < first);
    }
}

fn h_capacity() -> usize {
    store().cap
}

fn h_domain() -> u32 {
    DOMAIN.load(Ordering::SeqCst)
}

fn h_budget(domain: u32) -> usize {
    store().budgets.iter().find(|b| b.0 == domain).map_or(usize::MAX, |b| b.1)
}

static HOOKS: PageCacheHooks = PageCacheHooks {
    read: h_read, write: h_write, writeback: h_writeback, flush_fs: h_flush_fs, drop: h_drop,
    capacity_pages: h_capacity, domain: h_domain, domain_budget: h_budget, now_ms: clock, wake,
};

fn clock() -> u64 {
    NOW.load(Ordering::SeqCst)
}

fn wake() {
    WAKES.fetch_add(1, Ordering::SeqCst);
}

/// The cache installed for the length of a row; removed (and emptied) on drop.
struct Installed;

fn install(page: usize, cap: usize) -> Installed {
    *store() = Store {
        files: Vec::new(), page, cap, budgets: Vec::new(), fills: 0, written: 0, served: 0, decline: false,
        fail: Vec::new(), writebacks: 0,
    };
    DOMAIN.store(0, Ordering::SeqCst);
    NOW.store(1000, Ordering::SeqCst);
    WAKES.store(0, Ordering::SeqCst);
    vfs::vfs_page_cache_hooks(Some(&HOOKS));
    Installed
}

impl Drop for Installed {
    fn drop(&mut self) {
        vfs::vfs_page_cache_hooks(None);
        *store() = Store {
            files: Vec::new(), page: 1024, cap: 64, budgets: Vec::new(), fills: 0, written: 0, served: 0, decline: false,
            fail: Vec::new(), writebacks: 0,
        };
    }
}

/// "A writable mapping": the page's own buffer, brought into the cache if it
/// is not there. Writes through the pointer are the cache's page, and a page
/// mapped writable counts as dirty, as `memobj` takes it.
fn map_page(fs: &'static dyn FileSystem, key: &InodeKey, size: u64, idx: u64, write: bool) -> *mut u8 {
    let mut s = store();
    let i = s.attach(fs, key, size);
    s.ensure(i, idx);
    if write {
        s.files[i].dirty.insert(idx);
    }
    s.files[i].pages.get_mut(&idx).unwrap().as_mut_ptr()
}

fn fills() -> usize {
    store().fills
}

fn dirty_pages() -> usize {
    store().dirty_pages()
}

fn written() -> usize {
    store().written
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const GRANULES: [usize; 3] = [512, 1024, 4096];

fn pat(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|p| seed.wrapping_add((p % 251) as u8).max(1)).collect()
}

fn name83(n: &[u8; 11]) -> [u8; 11] {
    *n
}

/// A fresh volume with `/fat/<name>` holding `data`, written the old way
/// (the direct API: no cache involved in making the fixture).
fn volume_with(files: &[(&[u8; 11], &[u8])]) {
    vfs_open_close::fresh_volume();
    for (n, d) in files {
        assert_eq!(fat32::fat32_write_file(&name83(n), d), Ok(()));
    }
    assert_eq!(fat32::fat32_sync(), Ok(()));
}

fn path(n: &str) -> Vec<u8> {
    let mut p = b"/fat/".to_vec();
    p.extend_from_slice(n.as_bytes());
    p
}

fn key(n: &[u8]) -> InodeKey {
    FAT.key_for(n).expect("an 8.3 name")
}

/// What the file holds ON THE VOLUME (the backend, never the cache).
fn on_volume(n: &[u8]) -> Vec<u8> {
    vfs_open_close::on_disk(n)
}

/// `len` bytes at `off` through the VFS (a fresh descriptor each time).
fn vfs_read_at(p: &[u8], off: i64, len: usize) -> Vec<u8> {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, p, O_RDONLY);
    assert!(fd >= 0, "open {:?}", String::from_utf8_lossy(p));
    assert_eq!(vfs::vfs_lseek(&mut t, fd, off, vfs::SEEK_SET), off);
    let mut b = vec![0u8; len];
    let n = vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), len);
    assert!(n >= 0);
    b.truncate(n as usize);
    vfs::vfs_close(&mut t, fd);
    b
}

fn vfs_write_at(t: &mut vfs::ScratchFds, fd: i32, off: i64, d: &[u8]) -> i32 {
    assert_eq!(vfs::vfs_lseek(t, fd, off, vfs::SEEK_SET), off);
    vfs::vfs_write(t, fd, d.as_ptr(), d.len())
}

// ── Rows ────────────────────────────────────────────────────────────────────

/// **Reads through the cache are the bytes of reads without it**, for every
/// shape: whole file, from an offset, inside a sector, across sectors and
/// pages, straddling the end, past the end, empty; at every page granule.
#[test]
fn reads_are_byte_identical_with_and_without_the_cache() {
    let _g = serial();
    let want = pat(9000, 3);
    let shapes: [(i64, usize); 10] = [
        (0, 9000), (0, 1), (5, 700), (511, 3), (512, 512), (1000, 2000), (4090, 100), (8990, 500), (9000, 10), (9100, 4),
    ];
    for g in GRANULES {
        volume_with(&[(b"SAME    BIN", &want)]);
        let p = path("SAME.BIN");
        let plain: Vec<Vec<u8>> = shapes.iter().map(|&(o, l)| vfs_read_at(&p, o, l)).collect();
        let _c = install(g, 64);
        for (k, &(o, l)) in shapes.iter().enumerate() {
            let got = vfs_read_at(&p, o, l);
            assert_eq!(got, plain[k], "{g}: ({o}, {l}) differs from the uncached read");
            let lo = (o as usize).min(want.len());
            assert_eq!(got, want[lo..(lo + l).min(want.len())], "{g}: ({o}, {l}) differs from the file");
        }
        // And the same through a read-write descriptor (the generic streaming open).
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
        assert!(fd >= 0);
        let mut b = vec![0u8; 9000];
        assert_eq!(vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), 9000), 9000);
        assert_eq!(b, want, "{g}: an O_RDWR read");
        vfs::vfs_close(&mut t, fd);
    }
}

/// **The first read fills pages, the second is served from them** with no
/// device read at all; the fills are one per page touched.
///
/// **Canary.** `cache_read` answering `None`: no page is ever filled.
#[test]
fn a_second_read_is_served_from_the_cache() {
    let _g = serial();
    volume_with(&[(b"HIT     BIN", &pat(3000, 9))]);
    let _c = install(1024, 64);
    let p = path("HIT.BIN");
    let first = vfs_read_at(&p, 0, 3000);
    assert_eq!(first, pat(3000, 9));
    assert_eq!(fills(), 3, "3000 bytes are 3 pages of 1024");
    let (reads, _) = disk_stats();
    let again = vfs_read_at(&p, 0, 3000);
    assert_eq!(again, first);
    assert_eq!(fills(), 3, "a hit fills nothing");
    assert_eq!(disk_stats().0, reads, "a hit reads the device not at all");
}

/// **File data the page cache filled is not kept again by the block cache.**
/// A raw `read_at` (the cache's fill) of a cold file reaches the device every
/// time with a cache installed, and is served from the block cache the second
/// time without one: the metadata cache stays metadata.
///
/// **Canary.** `read_sector_with` installing the line whatever `retain`: the
/// second raw read stops reaching the device.
#[test]
fn the_block_cache_does_not_keep_what_the_page_cache_filled() {
    let _g = serial();
    volume_with(&[(b"RAW     BIN", &pat(2048, 4))]);
    let k = key(b"raw.bin");
    let mut b = vec![0u8; 2048];
    // Drop whatever the fixture's own writes left in the block cache.
    for s in 0..Geom::default().total_sectors as u32 { fat32::fat32_cache_invalidate(s); }
    {
        let _c = install(1024, 64);
        assert_eq!(FAT.read_at(&k, 0, &mut b), 2048);
        let (r1, _) = disk_stats();
        assert_eq!(FAT.read_at(&k, 0, &mut b), 2048);
        assert!(disk_stats().0 > r1, "with a page cache the block cache retains no file data");
        assert_eq!(b, pat(2048, 4));
    }
    for s in 0..Geom::default().total_sectors as u32 { fat32::fat32_cache_invalidate(s); }
    assert_eq!(FAT.read_at(&k, 0, &mut b), 2048);
    let (r2, _) = disk_stats();
    assert_eq!(FAT.read_at(&k, 0, &mut b), 2048);
    assert_eq!(disk_stats().0, r2, "without one it keeps the data, as before");
}

/// **A write inside the file dirties a page and stays in the cache until
/// `fsync`**: the volume still has the old bytes, a read sees the new ones, and
/// after the `fsync` the new bytes are on the volume and durable.
///
/// **Canaries.** `cache_write` answering `None`: the volume has the bytes at
/// once. `fd_fsync_finish`/`vfs_fsync` without `page_cache_flush_file`: the
/// volume never gets them.
#[test]
fn a_write_inside_the_file_stays_in_the_cache_until_fsync() {
    let _g = serial();
    let old = pat(3000, 1);
    volume_with(&[(b"WR      BIN", &old)]);
    disk_writeback();
    let _c = install(1024, 64);
    let p = path("WR.BIN");
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
    assert!(fd >= 0);
    let new = pat(100, 200);
    assert_eq!(vfs_write_at(&mut t, fd, 1500, &new), 100);
    assert_eq!(dirty_pages(), 1);
    let mut want = old.clone();
    want[1500..1600].copy_from_slice(&new);
    assert_eq!(on_volume(b"wr.bin"), old, "the write is in the cache, not on the volume");
    assert_eq!(vfs_read_at(&p, 0, 3000), want, "a read sees it");
    assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()));
    assert_eq!(dirty_pages(), 0);
    assert_eq!(on_volume(b"wr.bin"), want, "fsync wrote the page back");
    // The split fsync an RT-safe table uses (`fd_fsync_begin`/`finish`).
    assert_eq!(vfs_write_at(&mut t, fd, 2000, b"split"), 5);
    want[2000..2005].copy_from_slice(b"split");
    assert_eq!(on_volume(b"wr.bin")[2000..2005], old[2000..2005], "still only in the cache");
    let work = vfs::fd_fsync_begin(&t, fd).expect("lend");
    assert_eq!(vfs::fd_fsync_finish(work), Ok(()));
    assert_eq!(on_volume(b"wr.bin"), want, "the split fsync wrote it back too");
    // Durable: the image a power cut leaves has it.
    fat32::fat32_unmount(fat32::Volume::assume_mounted()).unwrap();
    let img = disk_durable_image();
    fs_test_drivers::disk_load(img);
    assert_eq!(fat32::fat32_mount(), Ok(()));
    assert_eq!(on_volume(b"wr.bin"), want, "durable after fsync");
    vfs::vfs_close(&mut t, fd);
}

/// **A mapping and `read()` see one page.** A byte written through the page's
/// buffer (a writable mapping) is what `read()` returns, with nothing written
/// to the volume; a byte written with `write()` is in the buffer the mapping
/// sees; the mapped write is dirty, so `fsync` carries it to the volume.
///
/// **Canary.** `cache_read` answering `None`: `read()` returns the volume's
/// bytes, the mapped write is not seen.
#[test]
fn a_mapping_and_read_see_the_same_page() {
    let _g = serial();
    let old = pat(2500, 5);
    volume_with(&[(b"MAP     BIN", &old)]);
    let _c = install(1024, 64);
    let p = path("MAP.BIN");
    let fs: &'static dyn FileSystem = &vfs::FAT32_FS;
    let k = key(b"map.bin");
    let page = map_page(fs, &k, 2500, 1, true);
    // SAFETY: the cache's page buffer, a live Box in `STORE`, single-threaded.
    let view = unsafe { core::slice::from_raw_parts_mut(page, 1024) };
    assert_eq!(&view[..64], &old[1024..1088], "the mapping sees the file's bytes");
    view[3] = 0xAB;
    view[1000] = 0xCD;
    let got = vfs_read_at(&p, 1024, 1024);
    assert_eq!(got[3], 0xAB, "read() sees the mapped write");
    assert_eq!(got[1000], 0xCD);
    assert_eq!(on_volume(b"map.bin"), old, "nothing reached the volume");
    // And the other way.
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
    assert_eq!(vfs_write_at(&mut t, fd, 1024 + 10, b"xyz"), 3);
    assert_eq!(&view[10..13], b"xyz", "write() is in the mapped page");
    assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()));
    let on = on_volume(b"map.bin");
    assert_eq!((on[1024 + 3], on[1024 + 10], on[1024 + 1000]), (0xAB, b'x', 0xCD), "fsync carried the mapped write");
    vfs::vfs_close(&mut t, fd);
}

/// **A write that reaches past the end takes the backend's ordered path** and
/// the page that held the old end is not served stale: the bytes after the old
/// end, which the cache filled as zeros, are the appended bytes now (the cache
/// re-attaches the file at the length it is told).
///
/// **Canary.** The double's `attach` keeping its pages at a new length: the
/// straddling page still reads zeros where the append went (a cache that did
/// not re-attach would fail this row the same way).
#[test]
fn an_extending_write_takes_the_ordered_path_and_the_old_end_page_is_not_served_stale() {
    let _g = serial();
    let old = pat(1500, 7);
    volume_with(&[(b"APP     BIN", &old)]);
    let _c = install(1024, 64);
    let p = path("APP.BIN");
    // Warm the page that holds the old end.
    assert_eq!(vfs_read_at(&p, 0, 1500), old);
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR | O_APPEND);
    assert!(fd >= 0);
    let add = pat(900, 31);
    assert_eq!(vfs::vfs_write(&mut t, fd, add.as_ptr(), add.len()), 900);
    let mut want = old.clone();
    want.extend_from_slice(&add);
    assert_eq!(on_volume(b"app.bin"), want, "the append is on the volume (the ordered path), not in the cache");
    assert_eq!(dirty_pages(), 0, "an extension dirties nothing");
    assert_eq!(vfs_read_at(&p, 0, 2400), want, "the old-end page was forgotten, not served stale");
    // A second one, through the same descriptor.
    assert_eq!(vfs::vfs_write(&mut t, fd, add.as_ptr(), add.len()), 900);
    want.extend_from_slice(&add);
    assert_eq!(vfs_read_at(&p, 0, 3300), want);
    vfs::vfs_close(&mut t, fd);
}

/// **An extension writes the file's dirty pages first.** A page dirtied inside
/// the file, then an append: the volume has both, and the dirty page is not
/// written back later over the extended file.
///
/// **Canary.** `cache_write`'s extension without `page_cache_flush_file`: the
/// dirtied bytes are lost with the dropped page.
#[test]
fn an_extending_write_keeps_the_dirty_pages_before_it() {
    let _g = serial();
    let old = pat(2000, 11);
    volume_with(&[(b"DIRTYAPP   ", &old)]);
    let _c = install(1024, 64);
    let p = path("DIRTYAPP");
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
    assert_eq!(vfs_write_at(&mut t, fd, 1900, b"HEAD"), 4);
    assert_eq!(dirty_pages(), 1);
    assert_eq!(vfs_write_at(&mut t, fd, 2000, b"TAIL"), 4, "at the end: an extension");
    let mut want = old.clone();
    want[1900..1904].copy_from_slice(b"HEAD");
    want.extend_from_slice(b"TAIL");
    assert_eq!(on_volume(b"dirtyapp"), want);
    assert_eq!(vfs_read_at(&p, 0, 2004), want);
    assert_eq!(dirty_pages(), 0);
    vfs::vfs_close(&mut t, fd);
}

/// **The FAT32 power-loss order holds with the cache in front**: a dirty
/// overwrite and an extension, then `fsync`; every state a cut leaves (every
/// prefix of epochs and every subset of the writes of one) mounts, has no
/// journal record left, a chain that is sound and covers the size, and a file
/// that is the old one or the extended one: never the entry over bytes that
/// did not reach the medium.
#[test]
fn the_fat32_power_loss_order_holds_with_the_cache() {
    let _g = serial();
    const OLD: usize = 1400;
    const ADD: usize = 700;
    let old = pat(OLD, 21);
    let add = pat(ADD, 99);
    volume_with(&[(b"CUT     BIN", &old)]);
    disk_writeback();
    let pristine = disk_durable_image();
    let _ = disk_take_log();
    {
        let _c = install(1024, 64);
        let p = path("CUT.BIN");
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
        assert_eq!(vfs_write_at(&mut t, fd, 100, &pat(50, 150)), 50);
        assert_eq!(vfs_write_at(&mut t, fd, OLD as i64, &add), ADD as i32);
        assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()));
        vfs::vfs_close(&mut t, fd);
        for _ in 0..4 {
            if fat32::fat32_writeback_dirty().0 == 0 { break; }
            assert_eq!(fat32::fat32_writeback_now(), Ok(()));
        }
    }
    let log = disk_take_log();
    let mut epochs: Vec<Vec<(u64, Vec<u8>)>> = vec![Vec::new()];
    for e in &log {
        match e {
            LogEntry::Write(s, d) => epochs.last_mut().unwrap().push((*s, d.clone())),
            LogEntry::Flush | LogEntry::Fua => epochs.push(Vec::new()),
        }
    }
    let mut new_file = old.clone();
    new_file[100..150].copy_from_slice(&pat(50, 150));
    new_file.extend_from_slice(&add);
    let mut states = 0usize;
    let mut base = pristine.clone();
    for (k, ep) in epochs.iter().enumerate() {
        assert!(ep.len() <= 16, "epoch {k} has {} writes", ep.len());
        for mask in 0u32..(1u32 << ep.len()) {
            let mut img = base.clone();
            for (i, (s, d)) in ep.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    img[*s as usize * SECTOR..][..SECTOR].copy_from_slice(d);
                }
            }
            super::swap_medium(img);
            for s in 0..Geom::default().total_sectors as u32 { fat32::fat32_cache_invalidate(s); }
            assert_eq!(fat32::fat32_mount(), Ok(()), "epoch {k} subset {mask:#b} must mount");
            let got = on_volume(b"cut.bin");
            assert!(got.len() == OLD || got.len() == OLD + ADD, "epoch {k} {mask:#b}: size {}", got.len());
            // Bytes past the old end are the appended ones or nothing: never
            // another file's.
            assert_eq!(got[OLD.min(got.len())..], new_file[OLD.min(got.len())..got.len()],
                "epoch {k} subset {mask:#b}: bytes past the old end are not the appended ones");
            // The overwritten range is old or new, byte by byte.
            for i in 0..OLD {
                assert!(got[i] == old[i] || got[i] == new_file[i], "epoch {k} {mask:#b}: byte {i}");
            }
            assert!(fat32::fat32_check_root_chain(b"CUT     BIN").is_ok(), "epoch {k} {mask:#b}: chain");
            assert!(fat32::fat32_journal_idle(), "epoch {k} {mask:#b}: journal");
            states += 1;
        }
        for (s, d) in ep {
            base[*s as usize * SECTOR..][..SECTOR].copy_from_slice(d);
        }
    }
    assert!(states > epochs.len(), "no subset beyond the prefix cuts was checked");
    // The last prefix is the whole operation: the extended file.
    super::swap_medium(base);
    assert_eq!(fat32::fat32_mount(), Ok(()));
    assert_eq!(on_volume(b"cut.bin"), new_file);
}

/// **`sync` and unmount write the cached pages back**, and the unmount does it
/// before the clean flag: a volume remounted after an unmount is clean and has
/// the data.
///
/// **Canaries.** `fat32_sync_checked` without `page_cache_flush_fs`: the
/// durable image after `fat32_sync` lacks the data. `fat32_unmount` without
/// the leading `page_cache_flush_fs`: the clean volume lacks it.
#[test]
fn sync_and_unmount_write_the_pages_back() {
    let _g = serial();
    let old = pat(2048, 13);
    volume_with(&[(b"SYNC    BIN", &old)]);
    disk_writeback();
    let _c = install(1024, 64);
    let p = path("SYNC.BIN");
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
    assert_eq!(vfs_write_at(&mut t, fd, 5, b"synced"), 6);
    let mut want = old.clone();
    want[5..11].copy_from_slice(b"synced");
    assert_eq!(on_volume(b"sync.bin"), old);
    assert_eq!(fat32::fat32_sync(), Ok(()));
    assert_eq!(dirty_pages(), 0);
    super::swap_medium(disk_durable_image());
    assert_eq!(fat32::fat32_mount(), Ok(()));
    assert_eq!(on_volume(b"sync.bin"), want, "durable after the volume sync");
    vfs::vfs_close(&mut t, fd);

    // Unmount with a dirty page.
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
    assert_eq!(vfs_write_at(&mut t, fd, 2000, b"unmounted"), 9);
    want[2000..2009].copy_from_slice(b"unmounted");
    fat32::fat32_unmount(fat32::Volume::assume_mounted()).unwrap();
    assert_eq!(dirty_pages(), 0, "the unmount wrote the page back");
    assert!(store().files.iter().all(|f| f.pages.is_empty()), "and forgot the pages: the medium may change");
    fs_test_drivers::disk_load(disk_durable_image());
    assert_eq!(fat32::fat32_mount(), Ok(()));
    assert!(!fat32::fat32_mount_report().unclean, "the volume was marked clean");
    assert_eq!(on_volume(b"sync.bin"), want, "and it has the data");
    vfs::vfs_close(&mut t, fd);
}

/// **The flusher waits for the age.** A dirty page is not written before
/// `FS_WRITEBACK_MAX_AGE_MS` has passed since it was dirtied, and is at it; the
/// tick that wrote it flushes the block cache too (the volume has it).
///
/// **Canaries.** `fat32_writeback_tick` without `page_cache_writeback_due`:
/// never written. `page_cache_writeback_due` ignoring the age: written at once.
#[test]
fn the_flusher_waits_for_the_age() {
    let _g = serial();
    let old = pat(3000, 17);
    volume_with(&[(b"AGE     BIN", &old)]);
    let _c = install(1024, 64);
    let age = azos_limits::FS_WRITEBACK_MAX_AGE_MS as u64;
    let p = path("AGE.BIN");
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
    NOW.store(5000, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, fd, 10, b"aged"), 4);
    assert_eq!(dirty_pages(), 1);
    assert!(!fat32::fat32_writeback_tick(5000 + age - 1), "not old enough");
    assert_eq!(dirty_pages(), 1);
    assert_eq!(on_volume(b"age.bin"), old);
    assert!(fat32::fat32_writeback_tick(5000 + age), "old enough");
    assert_eq!(dirty_pages(), 0);
    let mut want = old.clone();
    want[10..14].copy_from_slice(b"aged");
    assert_eq!(on_volume(b"age.bin"), want);
    assert_eq!(fat32::fat32_writeback_dirty().0, 0, "the same tick flushed the block cache");
    vfs::vfs_close(&mut t, fd);
}

/// **Over the dirty share the oldest files go first**, without waiting for the
/// age; under it nothing is written. The writer that crosses the share wakes
/// the flusher.
///
/// **Canary.** `over_watermark` always false: the second tick writes nothing.
#[test]
fn over_the_watermark_the_oldest_file_is_written_back() {
    let _g = serial();
    volume_with(&[(b"RA      BIN", &pat(2048, 1)), (b"RB      BIN", &pat(2048, 2))]);
    // 8 pages of cache, 25% watermark: 2 dirty pages cross it.
    let _c = install(1024, 8);
    let mut t = vfs::ScratchFds::new();
    let a = vfs::vfs_open(&mut t, &path("RA.BIN"), O_RDWR);
    let b = vfs::vfs_open(&mut t, &path("RB.BIN"), O_RDWR);
    NOW.store(2000, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, a, 0, b"a"), 1);
    assert_eq!(WAKES.load(Ordering::SeqCst), 0, "one page of eight is under the share");
    assert!(!fat32::fat32_writeback_tick(2001), "under the share and young: nothing");
    NOW.store(2010, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, b, 0, b"b"), 1);
    assert!(WAKES.load(Ordering::SeqCst) >= 1, "two pages of eight cross the share: the flusher is woken");
    assert!(fat32::fat32_writeback_tick(2011), "over the share: the oldest goes");
    assert_eq!(dirty_pages(), 1, "until the share is under: the younger file stays");
    assert_eq!(on_volume(b"ra.bin")[0], b'a');
    assert_ne!(on_volume(b"rb.bin")[0], b'b', "B is young and the cache is under the share");
    assert!(fat32::fat32_writeback_tick(2010 + azos_limits::FS_WRITEBACK_MAX_AGE_MS as u64), "B's age");
    assert_eq!(dirty_pages(), 0);
    assert_eq!(on_volume(b"rb.bin")[0], b'b');
    vfs::vfs_close(&mut t, a);
    vfs::vfs_close(&mut t, b);
}

/// **A Domain over its budget writes back its own files before its write
/// returns**, oldest first; another Domain's dirty file is left alone.
///
/// **Canary.** `page_cache_throttle` without the budget test: nothing is
/// written back by the writer.
#[test]
fn a_domain_over_its_budget_writes_back_its_own_files() {
    let _g = serial();
    volume_with(&[
        (b"DA      BIN", &pat(4096, 1)), (b"DB      BIN", &pat(4096, 2)), (b"DC      BIN", &pat(4096, 3)),
    ]);
    let _c = install(1024, 1024);
    store().budgets.push((7, 2));
    let mut t = vfs::ScratchFds::new();
    let a = vfs::vfs_open(&mut t, &path("DA.BIN"), O_RDWR);
    let b = vfs::vfs_open(&mut t, &path("DB.BIN"), O_RDWR);
    let c = vfs::vfs_open(&mut t, &path("DC.BIN"), O_RDWR);
    // Domain 9 has no budget; its file stays dirty whatever happens.
    DOMAIN.store(9, Ordering::SeqCst);
    NOW.store(3000, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, c, 0, b"nine"), 4);
    // Domain 7: two pages in file A (at its budget), then one in B (over).
    DOMAIN.store(7, Ordering::SeqCst);
    NOW.store(3001, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, a, 0, b"seven"), 5);
    assert_eq!(vfs_write_at(&mut t, a, 2048, b"seven"), 5);
    assert_eq!(dirty_pages(), 3);
    assert_eq!(written(), 0, "at the budget: no write-back");
    NOW.store(3002, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, b, 0, b"over"), 4);
    assert_eq!(written(), 2, "A's two pages went back to bring Domain 7 under its budget");
    assert_eq!(on_volume(b"da.bin")[..5], *b"seven");
    assert_eq!(on_volume(b"dc.bin")[..4], pat(4096, 3)[..4], "Domain 9's file is still only in the cache");
    assert_eq!(dirty_pages(), 2, "B's page and C's");
    for fd in [a, b, c] { vfs::vfs_close(&mut t, fd); }
}

/// A volume with `/fat/<n>` of 3000 bytes (`seed`), a cache installed, and
/// byte 10 of the file written through the cache: a dirty page, nothing else
/// settled. The fixture of the `coherence_*` rows: one operation each, so no
/// other call can make the page durable first.
fn dirty_fixture(n83: &[u8; 11], seed: u8) -> (Installed, vfs::ScratchFds, i32, Vec<u8>) {
    volume_with(&[(n83, &pat(3000, seed))]);
    let c = install(1024, 64);
    let mut t = vfs::ScratchFds::new();
    let name: String = String::from_utf8_lossy(&n83[..8]).trim_end().to_string()
        + "." + String::from_utf8_lossy(&n83[8..]).trim_end();
    let fd = vfs::vfs_open(&mut t, &path(&name), O_RDWR);
    assert!(fd >= 0);
    assert_eq!(vfs_write_at(&mut t, fd, 10, b"D"), 1);
    assert_eq!(dirty_pages(), 1);
    let mut want = pat(3000, seed);
    want[10] = b'D';
    (c, t, fd, want)
}

/// **A truncate keeps the dirty bytes of the head it keeps.**
///
/// **Canary.** `vfs_truncate` without its flush.
#[test]
fn coherence_truncate() {
    let _g = serial();
    let (_c, mut t, fd, mut want) = dirty_fixture(b"TRU     BIN", 1);
    assert_eq!(vfs::vfs_truncate(&path("TRU.BIN"), 1500), Ok(()));
    want.truncate(1500);
    assert_eq!(on_volume(b"tru.bin"), want);
    assert_eq!(vfs_read_at(&path("TRU.BIN"), 0, 3000), want, "and the cache does not serve the cut tail");
    vfs::vfs_close(&mut t, fd);
}

/// **An unlinked file stays gone**: the dirty page is not written back into a
/// file that is not there (`write_at` creates), on FAT32 and on tmpfs.
///
/// **Canary.** `vfs_unlink` without its drops AND `fat32_unlink_root` without
/// `cache_forget` (FAT32 has the second layer); tmpfs, which has only the
/// first, goes red in `a_tmpfs_file_goes_through_the_cache`.
#[test]
fn coherence_unlink() {
    let _g = serial();
    let (_c, mut t, fd, _) = dirty_fixture(b"UNL     BIN", 2);
    assert_eq!(vfs::vfs_unlink(&path("UNL.BIN")), Ok(()));
    fat32::fat32_writeback_tick(NOW.load(Ordering::SeqCst) + 100_000);
    assert_eq!(fat32::fat32_sync(), Ok(()));
    assert!(FAT.stat(&key(b"unl.bin")).is_none(), "a write-back must not create the file again");
    vfs::vfs_close(&mut t, fd);
}

/// **A rename carries the dirty bytes with the file.**
///
/// **Canary.** `vfs_rename` and `fat32_rename` without their flush of the source.
#[test]
fn coherence_rename() {
    let _g = serial();
    let (_c, mut t, fd, want) = dirty_fixture(b"REN     BIN", 3);
    assert_eq!(vfs::vfs_rename(&path("REN.BIN"), &path("NEW.BIN")), Ok(()));
    assert_eq!(on_volume(b"new.bin"), want);
    assert_eq!(vfs_read_at(&path("NEW.BIN"), 0, 3000), want);
    assert!(FAT.stat(&key(b"ren.bin")).is_none());
    vfs::vfs_close(&mut t, fd);
}

/// **A replace discards the old pages**: the new file is served, and nothing is
/// written back over it.
///
/// **Canary.** `vfs_replace_file` without its drops AND `fat32_rename` without
/// `cache_forget(new_name83)`.
#[test]
fn coherence_replace() {
    let _g = serial();
    let (_c, mut t, fd, _) = dirty_fixture(b"REP     BIN", 4);
    // Warm the cache with the old file, then replace it by one of the SAME
    // length: only the drop tells the cache the pages are not the file's.
    assert_eq!(vfs_read_at(&path("REP.BIN"), 0, 3000).len(), 3000);
    let new = pat(3000, 77);
    assert_eq!(vfs::vfs_replace_file(&path("REP.BIN"), &new), Ok(()));
    assert_eq!(vfs_read_at(&path("REP.BIN"), 0, 3000), new, "the new file, not the old pages");
    assert_eq!(fat32::fat32_sync(), Ok(()));
    assert_eq!(on_volume(b"rep.bin"), new, "nothing is written back over the new file");
    vfs::vfs_close(&mut t, fd);
}

/// **A content stamp names bytes that are on the backend**: the dirty page is
/// written before the stamp is given.
///
/// **Canary.** `vfs_content_stamp` without its flush.
#[test]
fn coherence_content_stamp() {
    let _g = serial();
    let (_c, mut t, fd, want) = dirty_fixture(b"STA     BIN", 5);
    assert!(vfs::vfs_content_stamp(&path("STA.BIN")).is_some());
    assert_eq!(on_volume(b"sta.bin"), want, "the stamp flushed the file first");
    vfs::vfs_close(&mut t, fd);
}

/// **An `O_TRUNC` open does not bring the old dirty bytes back.**
///
/// **Canary.** The `O_TRUNC` open without its drop.
#[test]
fn coherence_open_truncate() {
    let _g = serial();
    let (_c, mut t, fd, _) = dirty_fixture(b"OTR     BIN", 6);
    vfs::vfs_close(&mut t, fd);
    let o = vfs::vfs_open(&mut t, &path("OTR.BIN"), O_RDWR | O_TRUNC);
    assert!(o >= 0);
    assert_eq!(vfs::vfs_write(&mut t, o, b"fresh".as_ptr(), 5), 5);
    assert_eq!(fat32::fat32_sync(), Ok(()));
    assert_eq!(on_volume(b"otr.bin"), b"fresh");
    vfs::vfs_close(&mut t, o);
}

/// **A whole-file change made through the direct API is not hidden by the
/// cache**: a file cached and dirty, then replaced by `fat32_write_file`,
/// read back through the VFS, is the new file, and the old dirty page is not
/// written over it.
///
/// **Canary.** `write_file_journaled` without `cache_forget`: the read returns
/// the old page.
#[test]
fn coherence_the_direct_api_replaces_a_cached_file() {
    let _g = serial();
    volume_with(&[(b"DIR     BIN", &pat(2000, 1))]);
    let _c = install(1024, 64);
    let p = path("DIR.BIN");
    assert_eq!(vfs_read_at(&p, 0, 2000), pat(2000, 1));
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
    assert_eq!(vfs_write_at(&mut t, fd, 5, b"old-dirty"), 9);
    assert_eq!(fat32::fat32_write_file(b"DIR     BIN", &pat(2000, 50)), Ok(()));
    assert_eq!(vfs_read_at(&p, 0, 2000), pat(2000, 50), "the new file, not the old page");
    assert_eq!(fat32::fat32_sync(), Ok(()));
    assert_eq!(on_volume(b"dir.bin"), pat(2000, 50), "and the old dirty page is not written over it");
    vfs::vfs_close(&mut t, fd);
}

/// **A cache that cannot serve a file leaves the backend path as it was**: reads
/// and writes come out the same, and what the cache holds dirty is on the
/// volume before the backend is read.
#[test]
fn a_declining_cache_falls_back_to_the_backend() {
    let _g = serial();
    let old = pat(3000, 8);
    volume_with(&[(b"DEC     BIN", &old)]);
    let _c = install(1024, 64);
    let p = path("DEC.BIN");
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
    assert_eq!(vfs_write_at(&mut t, fd, 100, b"cached"), 6);
    store().decline = true;
    let mut want = old.clone();
    want[100..106].copy_from_slice(b"cached");
    assert_eq!(vfs_read_at(&p, 0, 3000), want, "the backend was settled before it was read");
    assert_eq!(vfs_write_at(&mut t, fd, 200, b"raw"), 3);
    want[200..203].copy_from_slice(b"raw");
    assert_eq!(on_volume(b"dec.bin"), want, "a declined write went to the backend");
    store().decline = false;
    assert_eq!(vfs_read_at(&p, 0, 3000), want, "and the cache does not serve a page older than it");
    vfs::vfs_close(&mut t, fd);
}

/// **A failed write-back keeps the page dirty and is reported**; the retry
/// succeeds and the bytes arrive. (Write-through, where `write_at` meets the
/// device: with the block cache in write-back mode a page is handed to it
/// whole and a device failure surfaces at the flush, below.)
#[test]
fn a_failed_write_back_keeps_the_page_dirty() {
    let _g = serial();
    let old = pat(2048, 19);
    volume_with(&[(b"FAIL    BIN", &old)]);
    let _c = install(1024, 64);
    let p = path("FAIL.BIN");
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR);
    let mut want = old.clone();
    want[7..12].copy_from_slice(b"retry");
    {
        let _w = super::write_through();
        assert_eq!(vfs_write_at(&mut t, fd, 7, b"retry"), 5);
        disk_write_fail_after(0);
        let r = vfs::vfs_fsync(&mut t, fd);
        disk_write_fail_clear();
        assert!(r.is_err(), "the failed write-back is the fsync's verdict");
        assert_eq!(dirty_pages(), 1, "the page is still dirty");
        assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()));
        assert_eq!(dirty_pages(), 0);
        assert_eq!(on_volume(b"fail.bin"), want);
    }
    // Write-back: the page reaches the block cache, the flush fails, and the
    // verdict is the fsync's; a retry flushes.
    assert_eq!(vfs_write_at(&mut t, fd, 100, b"again"), 5);
    want[100..105].copy_from_slice(b"again");
    fs_test_drivers::disk_flush_mode(fs_test_drivers::FlushMode::Io);
    let r = vfs::vfs_fsync(&mut t, fd);
    fs_test_drivers::disk_flush_mode(fs_test_drivers::FlushMode::Ok);
    assert!(r.is_err(), "a flush that failed is the fsync's verdict");
    assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()));
    assert_eq!(on_volume(b"fail.bin"), want);
    vfs::vfs_close(&mut t, fd);
}

/// **tmpfs files go through the cache too**: a write inside the file is in the
/// cache and not in tmpfs until the flusher or an `fsync`, a read sees it, a
/// mapping shares the page, and an append takes tmpfs's own path.
///
/// **Canary.** `TmpFs::page_cached` false: the write is in tmpfs at once.
#[test]
fn a_tmpfs_file_goes_through_the_cache() {
    let _g = serial();
    vfs_p2::tmp_once();
    vfs_p2::clear_tmpfs();
    let base = pat(3000, 23);
    tmpfs::tmpfs_write(b"cached", &base).unwrap();
    let _c = install(1024, 64);
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, b"/tmp/cached", O_RDWR);
    assert!(fd >= 0);
    assert_eq!(vfs_write_at(&mut t, fd, 1100, b"in the cache"), 12);
    let mut raw = vec![0u8; 3000];
    assert_eq!(tmpfs::tmpfs_read(b"cached", &mut raw), Ok(3000));
    assert_eq!(raw, base, "tmpfs still has the old bytes");
    let mut want = base.clone();
    want[1100..1112].copy_from_slice(b"in the cache");
    assert_eq!(vfs_read_at(b"/tmp/cached", 0, 3000), want);
    // The mapping and read() share the page.
    let fs: &'static dyn FileSystem = &tmpfs::TMPFS_FS;
    let k = tmpfs::TmpFs.key_for(b"cached").unwrap();
    let page = map_page(fs, &k, 3000, 1, true);
    // SAFETY: the cache's page buffer, single-threaded.
    let view = unsafe { core::slice::from_raw_parts_mut(page, 1024) };
    assert_eq!(&view[76..88], b"in the cache");
    view[500] = 0xEE;
    assert_eq!(vfs_read_at(b"/tmp/cached", 1524, 1)[0], 0xEE);
    assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()));
    assert_eq!(tmpfs::tmpfs_read(b"cached", &mut raw), Ok(3000));
    want[1524] = 0xEE;
    assert_eq!(raw, want, "fsync wrote the pages into tmpfs");
    // The split fsync reaches tmpfs's pages too.
    assert_eq!(vfs_write_at(&mut t, fd, 2900, b"split"), 5);
    want[2900..2905].copy_from_slice(b"split");
    let work = vfs::fd_fsync_begin(&t, fd).expect("lend");
    assert_eq!(vfs::fd_fsync_finish(work), Ok(()));
    assert_eq!(tmpfs::tmpfs_read(b"cached", &mut raw), Ok(3000));
    assert_eq!(raw, want, "the split fsync wrote them too");
    // unlink: gone for good, whatever the flusher does after.
    assert_eq!(vfs_write_at(&mut t, fd, 5, b"late"), 4);
    assert_eq!(vfs::vfs_unlink(b"/tmp/cached"), Ok(()));
    fat32::fat32_writeback_tick(NOW.load(Ordering::SeqCst) + 100_000);
    assert_eq!(tmpfs::tmpfs_size(b"cached"), None, "a write-back must not create the file again");
    tmpfs::tmpfs_write(b"cached", &want).unwrap();
    // An append is tmpfs's own.
    let end = vfs::vfs_lseek(&mut t, fd, 0, vfs::SEEK_END);
    assert_eq!(end, 3000);
    assert_eq!(vfs::vfs_write(&mut t, fd, b"++".as_ptr(), 2), 2);
    assert_eq!(tmpfs::tmpfs_size(b"cached"), Some(3002));
    assert_eq!(vfs_read_at(b"/tmp/cached", 2998, 10), [&want[2998..], b"++".as_slice()].concat());
    vfs::vfs_close(&mut t, fd);
    vfs_p2::clear_tmpfs();
}

/// **With the cache removed every path is the backend's again**: a write is on
/// the volume at once, and what the cache held dirty was written before.
#[test]
fn removing_the_cache_restores_the_backend_paths() {
    let _g = serial();
    let old = pat(2000, 29);
    volume_with(&[(b"OFF     BIN", &old)]);
    {
        let _c = install(1024, 64);
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, &path("OFF.BIN"), O_RDWR);
        assert_eq!(vfs_write_at(&mut t, fd, 0, b"cached"), 6);
        assert_eq!(dirty_pages(), 1);
        vfs::vfs_close(&mut t, fd);
        assert_eq!(fat32::fat32_sync(), Ok(()));
    }
    let mut want = old.clone();
    want[..6].copy_from_slice(b"cached");
    assert_eq!(on_volume(b"off.bin"), want);
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &path("OFF.BIN"), O_RDWR);
    assert_eq!(vfs_write_at(&mut t, fd, 0, b"direct"), 6);
    assert_eq!(&on_volume(b"off.bin")[..6], b"direct", "no cache: the write is on the volume at once");
    vfs::vfs_close(&mut t, fd);
}

// ── The reviewer's rows (2026-10-17): failing files, handles, appends, direct API ──

/// **A file whose write-back fails does not starve the files behind it.** Two
/// files are old enough; the older one's write-back fails every time. The
/// flusher leaves it tracked and writes the other one in the same pass; the
/// failure is the next fsync's verdict, once.
///
/// **Canary.** `page_cache_writeback_due` ending the pass at the first failure
/// (the `?` it had): B is never written.
#[test]
fn a_failing_file_does_not_starve_the_others() {
    let _g = serial();
    let (a0, b0) = (pat(2048, 1), pat(2048, 2));
    volume_with(&[(b"STA2    BIN", &a0), (b"STB2    BIN", &b0)]);
    let _c = install(1024, 64);
    let mut t = vfs::ScratchFds::new();
    let a = vfs::vfs_open(&mut t, &path("STA2.BIN"), O_RDWR);
    let b = vfs::vfs_open(&mut t, &path("STB2.BIN"), O_RDWR);
    NOW.store(4000, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, a, 0, b"a"), 1);
    NOW.store(4010, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, b, 0, b"b"), 1);
    store().fail.push(key(b"sta2.bin"));
    let late = 4010 + azos_limits::FS_WRITEBACK_MAX_AGE_MS as u64;
    assert!(fat32::fat32_writeback_tick(late), "B was written");
    assert_eq!(on_volume(b"stb2.bin")[0], b'b', "the failing file did not end the pass");
    assert_eq!(on_volume(b"sta2.bin"), a0, "A is not on the volume");
    assert_eq!(dirty_pages(), 1, "and A is still dirty, tracked for the next pass");
    assert!(vfs::vfs_fsync(&mut t, b).is_err(), "the failure no one waited for is the next fsync's verdict");
    store().fail.clear();
    assert!(fat32::fat32_writeback_tick(late + 1), "the next pass tries A again");
    assert_eq!(on_volume(b"sta2.bin")[0], b'a');
    assert_eq!(dirty_pages(), 0);
    assert_eq!(vfs::vfs_fsync(&mut t, b), Ok(()), "the verdict was given once");
    vfs::vfs_close(&mut t, a);
    vfs::vfs_close(&mut t, b);
}

/// **A writer's throttle skips a file it cannot write back and reports it.**
/// Domain 7 is over its budget and its oldest file fails: the next one is
/// written, the write succeeded (it was buffered), and the failure is the next
/// fsync's verdict.
///
/// **Canary.** `page_cache_throttle` breaking at the first failure, or
/// dropping it (no `WB_FAILED`): B stays dirty / the fsync says `Ok`.
#[test]
fn a_throttle_that_cannot_write_a_file_back_goes_on_and_reports_it() {
    let _g = serial();
    volume_with(&[(b"TA      BIN", &pat(2048, 1)), (b"TB      BIN", &pat(2048, 2))]);
    let _c = install(1024, 64);
    store().budgets.push((7, 1));
    store().fail.push(key(b"ta.bin"));
    DOMAIN.store(7, Ordering::SeqCst);
    let mut t = vfs::ScratchFds::new();
    let a = vfs::vfs_open(&mut t, &path("TA.BIN"), O_RDWR);
    let b = vfs::vfs_open(&mut t, &path("TB.BIN"), O_RDWR);
    NOW.store(5000, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, a, 0, b"a"), 1);
    NOW.store(5001, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, b, 0, b"b"), 1, "over the budget, the write still succeeds");
    assert_eq!(on_volume(b"tb.bin")[0], b'b', "A failed, so B went back to bring the Domain under its budget");
    assert_eq!(dirty_pages(), 1, "A is still dirty");
    store().fail.clear();
    assert!(vfs::vfs_fsync(&mut t, b).is_err(), "the medium is back, and the failure is still reported");
    assert_eq!(vfs::vfs_fsync(&mut t, b), Ok(()), "once");
    assert_eq!(vfs::vfs_fsync(&mut t, a), Ok(()));
    assert_eq!(on_volume(b"ta.bin")[0], b'a');
    vfs::vfs_close(&mut t, a);
    vfs::vfs_close(&mut t, b);
}

/// **Two Domains writing one file are each charged their own pages.** Domain 7
/// dirties a page, then Domain 8 two more of the same file: Domain 8 is over its
/// budget of one page at the second, and the file (all three pages, a
/// write-back is per file) goes back; Domain 7, at its budget, is not the one
/// who paid.
///
/// **Canary.** `dirty_note` matching the file only (one entry, the first
/// dirtier's Domain 7): Domain 8 is charged nothing and `written()` stays 0.
#[test]
fn pages_are_charged_to_the_domain_that_dirtied_them() {
    let _g = serial();
    volume_with(&[(b"SHR     BIN", &pat(4096, 5))]);
    let _c = install(1024, 64);
    store().budgets.push((7, 1));
    store().budgets.push((8, 1));
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &path("SHR.BIN"), O_RDWR);
    DOMAIN.store(7, Ordering::SeqCst);
    NOW.store(6000, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, fd, 0, b"seven"), 5);
    DOMAIN.store(8, Ordering::SeqCst);
    NOW.store(6001, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, fd, 1024, b"eight"), 5);
    assert_eq!(written(), 0, "7 holds one page and 8 one: both at their budgets");
    assert_eq!(vfs_write_at(&mut t, fd, 2048, b"eight"), 5);
    assert_eq!(written(), 3, "8 holds two against a budget of one: the file goes back, whole");
    assert_eq!(dirty_pages(), 0);
    let v = on_volume(b"shr.bin");
    assert_eq!(&v[..5], b"seven");
    assert_eq!(&v[2048..2053], b"eight");
    vfs::vfs_close(&mut t, fd);
}

/// **A read-only stream follows the name it opened when the name is replaced.**
/// The stream's handle names the file it opened; once a replace put another
/// file under the name, the read does not ask the cache (whose pages are the
/// name's file now) and takes the stream's own path, which looks the name up
/// again: the new file's bytes, as before the cache.
///
/// **Canary.** `cache_read` without the `handle_names` test: the cache serves
/// the read (`served` rises).
#[test]
fn a_read_only_stream_does_not_read_a_replaced_name_through_the_cache() {
    let _g = serial();
    let old = pat(3000, 3);
    volume_with(&[(b"STR     BIN", &old)]);
    let _c = install(1024, 64);
    let p = path("STR.BIN");
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDONLY);
    assert!(fd >= 0);
    let mut buf = vec![0u8; 100];
    assert_eq!(vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), 100), 100);
    assert_eq!(buf, old[..100], "before the replace the stream is served by the cache");
    let served = store().served;
    assert_eq!(served, 1);
    let new = pat(3000, 90);
    assert_eq!(vfs::vfs_replace_file(&p, &new), Ok(()));
    assert_eq!(vfs::vfs_lseek(&mut t, fd, 0, vfs::SEEK_SET), 0);
    assert_eq!(vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), 100), 100);
    assert_eq!(buf, new[..100], "the name's file now");
    assert_eq!(store().served, served, "and the cache was not asked");
    vfs::vfs_close(&mut t, fd);
}

/// **Appends are written through and do not make the cache refill the file.**
/// Twenty appends, each followed by a read of the whole file: the bytes are
/// right every time, no page is ever dirty (nothing to charge or age), and the
/// cache refills the one page that held the old end per append, not the file.
///
/// **Canary.** The double's `attach` clearing every page on growth (the
/// contract of `PageCacheHooks::read` without its keep): `fills()` is about
/// three times the bound.
#[test]
fn appends_write_through_and_do_not_refill_the_file() {
    let _g = serial();
    let first = pat(2000, 6);
    volume_with(&[(b"APN     BIN", &first)]);
    let _c = install(1024, 64);
    let p = path("APN.BIN");
    let mut want = first.clone();
    assert_eq!(vfs_read_at(&p, 0, 2000), want);
    let base = fills();
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, &p, O_RDWR | O_APPEND);
    for i in 0..20u8 {
        let add = pat(50, 100 + i);
        assert_eq!(vfs::vfs_write(&mut t, fd, add.as_ptr(), add.len()), 50);
        want.extend_from_slice(&add);
        assert_eq!(vfs_read_at(&p, 0, want.len()), want);
        assert_eq!(dirty_pages(), 0, "an append dirties nothing");
    }
    assert_eq!(written(), 0, "and nothing was written back by the cache");
    assert_eq!(store().writebacks, 20, "each append asked the cache to settle the file first: a call on a clean file");
    assert_eq!(on_volume(b"apn.bin"), want);
    // 20 old-end pages; the file crossed into a third page once.
    assert!(fills() - base <= 22, "{} refills for 20 appends", fills() - base);
    vfs::vfs_close(&mut t, fd);
}

/// **`fat32_unlink_path` leaves no dirty page to create the file again**, and
/// `fat32_mkdir` / `rmdir` over a cached file's name change nothing it holds.
///
/// **Canary.** `fat32_unlink_root` without its `cache_forget` (and
/// `vfs_unlink` not involved: this is the direct API): the tick creates the
/// file again.
#[test]
fn coherence_unlink_path_mkdir_and_rmdir() {
    let _g = serial();
    let (_c, mut t, fd, want) = dirty_fixture(b"UNM     BIN", 8);
    assert!(fat32::fat32_mkdir(fat32::Volume::assume_mounted(), b"/UNM.BIN").is_err(), "a file holds the name");
    assert_eq!(vfs::vfs_rmdir(&path("UNM.BIN")), Err(FsErr::NotDir));
    assert_eq!(dirty_pages(), 1, "neither touched the cached file");
    assert_eq!(fat32::fat32_sync(), Ok(()));
    assert_eq!(on_volume(b"unm.bin"), want);
    vfs::vfs_close(&mut t, fd);
    let (_c2, mut t2, fd2, _) = dirty_fixture(b"UNP     BIN", 9);
    assert_eq!(fat32::fat32_unlink_path(b"UNP.BIN"), Ok(()));
    fat32::fat32_writeback_tick(NOW.load(Ordering::SeqCst) + 100_000);
    assert_eq!(fat32::fat32_sync(), Ok(()));
    assert!(FAT.stat(&key(b"unp.bin")).is_none(), "a write-back must not create the file again");
    vfs::vfs_close(&mut t2, fd2);
}

/// **A direct handle on a cached file sees the VFS's bytes and is seen by the
/// VFS**: a read through `fat32_read` returns the bytes a page dirtied AFTER
/// the open holds, a `fat32_write` is not overwritten later by the old page and
/// is what the next VFS read returns, and an open with `TRUNCATE` does not let
/// the old dirty bytes come back.
///
/// **Canaries.** `fat32_read` without `settle_cache`: the first assert is red;
/// `fat32_write` without its forget (or its settle): the VFS read (or the
/// volume) is red; `fat32_open` without the `TRUNCATE` forget: the last assert
/// is red.
#[test]
fn coherence_the_direct_handle_api() {
    use fat32::open_flags as of;
    let _g = serial();
    let (_c, mut t, fd, mut want) = dirty_fixture(b"DHA     BIN", 10);
    let vol = fat32::Volume::assume_mounted();
    let h = fat32::fat32_open(vol, b"/DHA.BIN", of::READ).expect("open");
    assert_eq!(vfs_write_at(&mut t, fd, 30, b"F"), 1, "dirtied after the direct open");
    want[30] = b'F';
    let mut got = vec![0u8; 3000];
    assert_eq!(fat32::fat32_read(h, &mut got), Ok(3000));
    assert_eq!(got, want, "both dirty bytes are in what the direct reader sees");
    assert_eq!(fat32::fat32_close(h), Ok(()));
    assert_eq!(vfs_write_at(&mut t, fd, 40, b"G"), 1, "dirty again, before the direct write");
    want[40] = b'G';
    let w = fat32::fat32_open(vol, b"/DHA.BIN", of::WRITE).expect("open");
    assert_eq!(fat32::fat32_seek(w, fat32::SeekFrom::Start(20)), Ok(20));
    assert_eq!(fat32::fat32_write(w, b"XYZ"), Ok(3));
    assert_eq!(fat32::fat32_close(w), Ok(()));
    want[20..23].copy_from_slice(b"XYZ");
    assert_eq!(vfs_read_at(&path("DHA.BIN"), 0, 3000), want, "the VFS reads the direct write");
    assert_eq!(fat32::fat32_sync(), Ok(()));
    assert_eq!(on_volume(b"dha.bin"), want, "and nothing older is written over it");
    // Dirty again, then a TRUNCATE open and nothing else: the file is empty
    // and stays empty through the next sync.
    assert_eq!(vfs_write_at(&mut t, fd, 10, b"E"), 1);
    let o = fat32::fat32_open(vol, b"/DHA.BIN", of::WRITE | of::TRUNCATE).expect("open");
    assert_eq!(fat32::fat32_close(o), Ok(()));
    assert_eq!(fat32::fat32_sync(), Ok(()));
    assert_eq!(on_volume(b"dha.bin"), b"", "the old dirty page did not come back");
    vfs::vfs_close(&mut t, fd);
}

/// **A write-back failure is reported by an fsync of its own filesystem.** A
/// FAT32 file fails its write-back in the flusher; an fsync of a tmpfs file
/// (also paged) is `Ok` and does not take the verdict; the next FAT32 fsync
/// does.
///
/// **Canary.** `WB_FAILED` one flag for every filesystem (or
/// `page_cache_fsync` taking it without the `cached` gate): the tmpfs fsync
/// answers `Io`, the FAT32 one `Ok`.
#[test]
fn a_write_back_failure_is_reported_by_its_own_filesystem() {
    let _g = serial();
    volume_with(&[(b"OWN     BIN", &pat(2048, 4))]);
    vfs_p2::tmp_once();
    vfs_p2::clear_tmpfs();
    tmpfs::tmpfs_write(b"other", &pat(2048, 5)).unwrap();
    let _c = install(1024, 64);
    let mut t = vfs::ScratchFds::new();
    let a = vfs::vfs_open(&mut t, &path("OWN.BIN"), O_RDWR);
    let o = vfs::vfs_open(&mut t, b"/tmp/other", O_RDWR);
    NOW.store(7000, Ordering::SeqCst);
    assert_eq!(vfs_write_at(&mut t, a, 0, b"a"), 1);
    store().fail.push(key(b"own.bin"));
    fat32::fat32_writeback_tick(7000 + azos_limits::FS_WRITEBACK_MAX_AGE_MS as u64);
    store().fail.clear();
    assert_eq!(vfs::vfs_fsync(&mut t, o), Ok(()), "tmpfs does not take FAT32's failure");
    assert!(vfs::vfs_fsync(&mut t, a).is_err(), "FAT32 reports its own");
    assert_eq!(vfs::vfs_fsync(&mut t, a), Ok(()));
    vfs::vfs_close(&mut t, a);
    vfs::vfs_close(&mut t, o);
}

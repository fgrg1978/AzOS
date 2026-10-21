// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the install of the page cache (storage L11, part B): what the
//! file layer does once the kernel has put its `PageCacheHooks` in place, as
//! `kernel/src/boot/pagecache.rs` does at boot, and what it does not.
//!
//! The hooks' own behaviour over the object table has its rows in
//! `tests/host/syscall-tests/src/pagecache_hooks.rs` (the real `file_map.rs`
//! over the real `memobj.rs`) and `crates/core/ipc/src/memobj.rs` (the growth
//! contract); the file layer's use of them is `l11b.rs`'s. This file is the
//! seam between the two: the install itself and the one rule that follows from
//! it in the FAT32 driver.
//!
//! * `installing_and_removing_the_hooks_is_what_page_cache_installed_says`:
//!   none installed is false, installed is true, removed is false again.
//!   Canary: `page_cache_installed` answering `true` always (or the install
//!   not storing the table) -> red.
//! * `the_handle_api_retains_nothing_when_a_page_cache_is_installed`: the
//!   direct `fat32_read` (OTA and driver images, configuration: file data that
//!   is not the page cache's) leaves the data sectors out of the block cache
//!   once a cache is installed, so the block cache holds metadata and the
//!   writes it stages, not file data twice; with none it retains them, as
//!   before. Canary: `fat32_read` passing `retain: true` -> the installed half
//!   red.
//!
//! Wired into the suite by `mod pagecache_hooks;` in `src/lib.rs`.

#![cfg(test)]

use super::{fat32, image::Geom, serial, vfs, vfs_open_close};
use fs_test_drivers::disk_stats;
use vfs::{FsErr, InodeKey, PageCacheHooks};

/// A table whose cache serves nothing: the install is what is under test.
static NONE: PageCacheHooks = PageCacheHooks {
    read: |_, _, _, _, _| None,
    write: |_, _, _, _, _| None,
    writeback: |_, _| -> Result<(), FsErr> { Ok(()) },
    flush_fs: |_| Ok(()),
    drop: |_, _: Option<&InodeKey>, _| {},
    capacity_pages: || 1,
    domain: || 0,
    domain_budget: |_| usize::MAX,
    now_ms: || 1,
    wake: || {},
};

#[test]
fn installing_and_removing_the_hooks_is_what_page_cache_installed_says() {
    let _g = serial();
    vfs::vfs_page_cache_hooks(None);
    assert!(!vfs::page_cache_installed(), "no kernel, no cache");
    vfs::vfs_page_cache_hooks(Some(&NONE));
    assert!(vfs::page_cache_installed());
    vfs::vfs_page_cache_hooks(None);
    assert!(!vfs::page_cache_installed(), "removed again");
}

/// Read `len` bytes of `/name` through the direct handle API.
fn handle_read(name: &[u8], len: usize) -> Vec<u8> {
    let h = fat32::fat32_open(fat32::Volume::assume_mounted(), name, fat32::open_flags::READ).expect("open");
    let mut buf = vec![0u8; len];
    assert_eq!(fat32::fat32_read(h, &mut buf), Ok(len));
    assert_eq!(fat32::fat32_close(h), Ok(()));
    buf
}

#[test]
fn the_handle_api_retains_nothing_when_a_page_cache_is_installed() {
    let _g = serial();
    let data: Vec<u8> = (0..4096usize).map(|p| (p % 251 + 1) as u8).collect();
    vfs_open_close::fresh_volume();
    assert_eq!(fat32::fat32_write_file(b"HND     BIN", &data), Ok(()));
    assert_eq!(fat32::fat32_sync(), Ok(()));
    let total = Geom::default().total_sectors as u32;

    for installed in [true, false] {
        for s in 0..total { fat32::fat32_cache_invalidate(s); }
        vfs::vfs_page_cache_hooks(installed.then_some(&NONE));
        assert_eq!(handle_read(b"/HND.BIN", data.len()), data);
        let (r1, _) = disk_stats();
        assert_eq!(handle_read(b"/HND.BIN", data.len()), data);
        let again = disk_stats().0 - r1;
        vfs::vfs_page_cache_hooks(None);
        if installed {
            assert!(again > 0, "with a page cache the block cache retains no file data read through the handle API");
        } else {
            assert_eq!(again, 0, "without one it keeps the data, as before");
        }
    }
}

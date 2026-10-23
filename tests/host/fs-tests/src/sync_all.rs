// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for `vfs::vfs_sync_all` / `vfs::sync_volumes`: what the orderly
//! power-off and the `Power` interface's `sync` make durable (owner decision
//! 2026-10-23, Q1: both the ring-3 power service and the kernel's orderly path
//! sync every filesystem before the power goes).
//!
//! * The real FAT32 volume, write-back on, behind a disk with a volatile cache:
//!   a file written and closed is lost at a power cut, and survives it once
//!   `vfs_sync_all` ran.
//! * Stand-in backends: every distinct volume is asked once, a ticketed flush
//!   is waited for until it answers or the time is up (and the volumes after
//!   it are still synced), a failure is counted and does not stop the rest.
//!
//! Canaries (by hand, 2026-10-23; discriminates / does not / did not compile):
//! * `vfs_sync_all` returning `SyncAll::default()` without syncing:
//!   `a_closed_file_survives_a_power_cut_after_sync_all` red.
//! * `sync_volumes` not waiting for a ticket (`None` taken as done):
//!   `a_ticketed_flush_is_waited_for` and
//!   `a_flush_that_never_answers_times_out_and_the_rest_are_synced` red.
//! * `sync_volumes` waiting for a ticket without asking `expired`: not run
//!   (the timeout row would never return).
//! * `sync_volumes` stopping at the first failure:
//!   `every_volume_is_asked_whatever_an_earlier_one_answered` red.

#![cfg(test)]

use super::{fat32, image::*, serial, swap_medium, vfs};
use fs_test_drivers::{disk_durable_image, disk_writeback};
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use vfs::{FileStat, FileSystem, FsErr, InodeKey};

/// A backend whose `sync` and ticketed flush answer what the test says.
struct Fake {
    /// `sync` answers this (inline backends).
    sync_ok: bool,
    /// `Some(n)`: a ticketed flush that completes after `n` looks; `None`
    /// with `ticket`: never completes.
    done_after: Option<u32>,
    ticket: bool,
    syncs: AtomicU32,
    looks: AtomicU32,
}

impl Fake {
    const fn inline(ok: bool) -> Fake {
        Fake { sync_ok: ok, done_after: None, ticket: false, syncs: AtomicU32::new(0), looks: AtomicU32::new(0) }
    }
    const fn ticketed(done_after: Option<u32>) -> Fake {
        Fake { sync_ok: true, done_after, ticket: true, syncs: AtomicU32::new(0), looks: AtomicU32::new(0) }
    }
}

impl FileSystem for Fake {
    fn fs_type(&self) -> u32 { 0x5359 }
    fn mount(&self) -> Result<(), ()> { Ok(()) }
    fn sync(&self) -> Result<(), ()> {
        self.syncs.fetch_add(1, SeqCst);
        if self.sync_ok { Ok(()) } else { Err(()) }
    }
    fn key_for(&self, _: &[u8]) -> Option<InodeKey> { None }
    fn stat(&self, _: &InodeKey) -> Option<FileStat> { None }
    fn read_all(&self, _: &InodeKey, _: &FileStat, _: &mut [u8]) -> usize { 0 }
    fn write_all(&self, _: &InodeKey, _: &[u8]) -> Result<(), ()> { Err(()) }
    fn unlink(&self, _: &InodeKey) -> Result<(), ()> { Err(()) }
    fn read_at(&self, _: &InodeKey, _: u64, _: &mut [u8]) -> usize { 0 }
    fn write_at(&self, _: &InodeKey, _: u64, _: &[u8]) -> Result<usize, ()> { Err(()) }
    fn flush_request(&self) -> Option<u64> { self.ticket.then_some(7) }
    fn flush_done(&self, t: u64) -> Option<Result<(), FsErr>> {
        assert_eq!(t, 7, "the ticket asked for is the one waited on");
        let n = self.looks.fetch_add(1, SeqCst) + 1;
        match self.done_after {
            Some(after) if n > after => Some(Ok(())),
            _ => None,
        }
    }
}

fn never() -> bool { false }
fn nothing() {}

#[test]
fn a_closed_file_survives_a_power_cut_after_sync_all() {
    let _g = serial();
    let g = Geom::default();
    let mut img = build(&g);
    set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
    swap_medium(img);
    assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
    crate::vfs_open_close::vfs_once();
    disk_writeback();
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, b"/fat/DURABLE.TXT", vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
    assert!(fd >= 0, "the create must succeed");
    assert_eq!(vfs::vfs_write(&mut t, fd, b"durable-ok\n".as_ptr(), 11), 11);
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);

    // The control: a close queues, so a cut now loses the file.
    let lost = disk_durable_image();
    let r = vfs::vfs_sync_all(&never, &nothing);
    assert_eq!(r.failed, 0, "{r:?}");
    assert!(r.volumes >= 1, "the FAT32 mount is a volume: {r:?}");

    let synced = disk_durable_image();
    swap_medium(lost);
    assert_eq!(fat32::fat32_mount(), Ok(()));
    assert!(fat32::FAT32_FS.key_for(b"DURABLE.TXT").and_then(|k| fat32::FAT32_FS.stat(&k)).is_none(),
        "without the sync the cut must lose the file, or this row proves nothing");
    swap_medium(synced);
    assert_eq!(fat32::fat32_mount(), Ok(()));
    assert_eq!(crate::vfs_open_close::on_disk(b"DURABLE.TXT"), b"durable-ok\n");
}

#[test]
fn a_ticketed_flush_is_waited_for() {
    static F: Fake = Fake::ticketed(Some(3));
    let pauses = AtomicU32::new(0);
    let r = vfs::sync_volumes(&[&F], &never, &|| { pauses.fetch_add(1, SeqCst); });
    assert_eq!(r, vfs::SyncAll { volumes: 1, failed: 0, timed_out: 0 });
    assert_eq!(pauses.load(SeqCst), 3, "a pause between each look until it answered");
    assert_eq!(F.syncs.load(SeqCst), 0, "a ticketed backend is not also synced inline");
}

#[test]
fn a_flush_that_never_answers_times_out_and_the_rest_are_synced() {
    static STUCK: Fake = Fake::ticketed(None);
    static AFTER: Fake = Fake::inline(true);
    let looks = AtomicU32::new(0);
    let expired = || looks.fetch_add(1, SeqCst) >= 5;
    let r = vfs::sync_volumes(&[&STUCK, &AFTER], &expired, &nothing);
    assert_eq!(r, vfs::SyncAll { volumes: 2, failed: 0, timed_out: 1 });
    assert_eq!(AFTER.syncs.load(SeqCst), 1, "the volume after the stuck one is still synced");
}

#[test]
fn every_volume_is_asked_whatever_an_earlier_one_answered() {
    static BAD: Fake = Fake::inline(false);
    static GOOD: Fake = Fake::inline(true);
    let r = vfs::sync_volumes(&[&BAD, &GOOD], &never, &nothing);
    assert_eq!(r, vfs::SyncAll { volumes: 2, failed: 1, timed_out: 0 });
    assert_eq!((BAD.syncs.load(SeqCst), GOOD.syncs.load(SeqCst)), (1, 1));
}

/// A ticket whose backend cannot say it completed is not durable: the
/// trait's default `flush_done` is `Unsupported`, never `Ok`.
#[test]
fn a_ticket_nobody_answers_for_is_a_failure() {
    struct NoDone;
    impl FileSystem for NoDone {
        fn fs_type(&self) -> u32 { 0 }
        fn mount(&self) -> Result<(), ()> { Ok(()) }
        fn sync(&self) -> Result<(), ()> { Ok(()) }
        fn key_for(&self, _: &[u8]) -> Option<InodeKey> { None }
        fn stat(&self, _: &InodeKey) -> Option<FileStat> { None }
        fn read_all(&self, _: &InodeKey, _: &FileStat, _: &mut [u8]) -> usize { 0 }
        fn write_all(&self, _: &InodeKey, _: &[u8]) -> Result<(), ()> { Err(()) }
        fn unlink(&self, _: &InodeKey) -> Result<(), ()> { Err(()) }
        fn read_at(&self, _: &InodeKey, _: u64, _: &mut [u8]) -> usize { 0 }
        fn write_at(&self, _: &InodeKey, _: u64, _: &[u8]) -> Result<usize, ()> { Err(()) }
        fn flush_request(&self) -> Option<u64> { Some(1) }
    }
    static N: NoDone = NoDone;
    assert_eq!(vfs::sync_volumes(&[&N], &never, &nothing).failed, 1);
}

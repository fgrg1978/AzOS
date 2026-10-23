// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The removable volume (Kconfig `USB_STORAGE_VOLUME`): the FAT32 filesystem
//! of a USB stick, mounted as a second volume beside `/fat`, never in its
//! place.
//!
//! # One file, two volumes
//!
//! `fat32.rs` keeps its volume in statics (the volume lock, the sector cache,
//! the open-file table, the journal state). This module compiles that same
//! file a second time, as [`fat32`], so the stick's volume has statics of its
//! own and shares nothing with `/fat` but the source. What differs is the
//! sibling `fat32_dev` the file reads, here:
//!
//! - the device: the [`Disk`] the kernel attaches (the stick's request queue),
//!   and the stick's own partition table ([`azos_drv_block::partition::parse`]
//!   at attach; the boot disk's published table is not the stick's);
//! - write-through (no `FS_WRITEBACK`): a stick is pulled out without asking,
//!   and a write that returned is then on it, not in a cache waiting for the
//!   `fs-wb` task (which serves `/fat` alone, so this volume hands out no flush
//!   tickets either: an `fsync` syncs inline);
//! - a sector cache of its own size, Kconfig `USB_VOLUME_CACHE_KB`;
//! - no discard and no native FUA (the class driver has neither);
//! - its own identity ([`crate::vfs::FS_TYPE_FAT32_REMOVABLE`],
//!   [`crate::vfs::STAMP_FS_FAT32_REMOVABLE`]): the page cache, the write-back
//!   failure bit and the spawn cache never take one volume's file for the
//!   other's.
//!
//! # Life of a stick
//!
//! [`mount`] when the disk becomes ready (the kernel's `usb` glue, from a
//! task of its own: the stick's I/O is served by the `usb` task, which must
//! not wait for it). [`unplugged`] when it goes: from then on every device
//! call fails at once, the mount is retired (`vfs_unmount`: the path names
//! nothing, open descriptors on it fail their reads and writes) and the volume
//! state is reset for the next stick; a command the disk held when it left
//! already failed in the class driver. [`eject`] is the orderly way out (the
//! power-off): the page cache and the volume written back, the volume marked
//! clean, the stick's cache flushed (SYNCHRONIZE CACHE), then the same
//! retirement.
//!
//! # Authority
//!
//! None here. Ring 3 reaches the mount the way it reaches `/fat`: beneath a
//! `Cap<Dir>` tree the topology grants on the mount's path, read through the
//! root tree, written only through a write tree on the mount.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use azos_drv_api::block::FlushError;
use azos_drv_block::partition::{self as table, PartError, Table};
use azos_sync::SpinLock;

/// A USB disk as this volume reads and writes it: 512-byte sectors.
pub trait Disk: Sync {
    /// The medium's size in sectors (0 while there is no medium).
    fn sectors(&self) -> u64;
    fn read(&self, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()>;
    /// `preflush`: every write that completed before this one is durable
    /// before it starts.
    fn write(&self, sector: u64, count: u32, buf: &[u8], preflush: bool) -> Result<(), ()>;
    /// Every completed write durable (SYNCHRONIZE CACHE).
    fn flush(&self) -> Result<(), FlushError>;
}

/// The disk the volume is on: set by [`mount`], kept (it is the kernel's,
/// `'static`) until the next one. [`GONE`] says whether it may be used.
static DISK: SpinLock<Option<&'static dyn Disk>> = SpinLock::new(None);
/// The disk was unplugged: every device call fails without reaching it.
static GONE: AtomicBool = AtomicBool::new(true);
/// The stick's partition table, as [`mount`] read it.
static TABLE: SpinLock<Option<Table>> = SpinLock::new(None);
/// Where the volume is mounted, while [`STATE`] is [`MOUNTED`].
static AT: SpinLock<Option<MountPath>> = SpinLock::new(None);
/// Who has the volume: [`mount`] and [`retire`] each claim it for the whole
/// of their I/O (no lock is held across a device wait).
static STATE: AtomicU8 = AtomicU8::new(IDLE);
const IDLE: u8 = 0;
const MOUNTING: u8 = 1;
const MOUNTED: u8 = 2;
const RETIRING: u8 = 3;

#[derive(Clone, Copy)]
struct MountPath {
    bytes: [u8; 64],
    len: usize,
}

impl MountPath {
    fn of(at: &[u8]) -> Option<MountPath> {
        let mut bytes = [0u8; 64];
        bytes.get_mut(..at.len())?.copy_from_slice(at);
        Some(MountPath { bytes, len: at.len() })
    }
    fn get(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The disk, unless it is gone.
fn disk() -> Option<&'static dyn Disk> {
    if GONE.load(Ordering::Acquire) {
        return None;
    }
    *DISK.lock()
}

/// What `fat32.rs` sits on and the knobs this volume sets (see the module
/// doc).
pub(crate) mod fat32_dev {
    pub(crate) const WRITEBACK: bool = false;
    /// Kconfig `USB_VOLUME_CACHE_KB`.
    pub(crate) const BLOCK_CACHE_KB: usize = azos_limits::USB_VOLUME_CACHE_KB;
    pub(crate) const FS_TYPE: u32 = crate::vfs::FS_TYPE_FAT32_REMOVABLE;
    pub(crate) const STAMP_FS: u32 = crate::vfs::STAMP_FS_FAT32_REMOVABLE;
    pub(crate) const TICKETED: bool = false;

    /// The stick, with the surface of `azos_drv_block::blkdev` that
    /// `fat32.rs` uses.
    pub(crate) mod blkdev {
        use super::super::disk;
        use azos_drv_api::block::FlushError;

        pub(crate) fn capacity_sectors() -> u64 {
            disk().map_or(0, |d| d.sectors())
        }
        pub(crate) fn read_quiet(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
            disk().ok_or(())?.read(sector, count, buf)
        }
        pub(crate) fn write_quiet(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
            disk().ok_or(())?.write(sector, count, buf, false)
        }
        /// No native FUA ([`fua_commit`] is false), so `fua` is never asked.
        pub(crate) fn write_run(sector: u64, count: u32, buf: &[u8], preflush: bool, fua: bool) -> Result<(), ()> {
            if fua {
                return Err(());
            }
            disk().ok_or(())?.write(sector, count, buf, preflush)
        }
        pub(crate) fn flush() -> Result<(), FlushError> {
            disk().ok_or(FlushError::Io)?.flush()
        }
        pub(crate) fn fua_commit() -> bool {
            false
        }
        pub(crate) const DISCARD: bool = false;
        pub(crate) use azos_drv_block::blkdev::DiscardError;
        pub(crate) fn discard(_runs: &[(u64, u32)]) -> Result<(), DiscardError> {
            Err(DiscardError::Unsupported)
        }
        /// Nobody else reads or writes the stick behind the volume's back:
        /// there is nothing to observe.
        pub(crate) fn set_write_observer(_f: fn(u64, u32)) {}
        pub(crate) fn set_read_observer(_f: fn(u64, u32), _held: fn(u64, u32) -> bool) {}
    }

    /// The stick's partition table, with the surface of
    /// `azos_drv_block::partition` that `fat32.rs` uses.
    pub(crate) mod partition {
        use super::super::TABLE;

        pub(crate) fn count() -> u32 {
            TABLE.lock().map_or(0, |t| t.count as u32)
        }
        pub(crate) fn partition(index: u32) -> Option<(u64, u64)> {
            TABLE.lock().and_then(|t| t.get(index as usize)).map(|p| (p.start, p.sectors))
        }
    }
}

/// The stick's FAT32 volume: `fat32.rs`, compiled again over `fat32_dev`.
#[path = "fat32.rs"]
pub mod fat32;

/// Why [`mount`] did not mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A volume is mounted already.
    Busy,
    /// The mount path does not fit.
    Path,
    /// The partition table is present but refused.
    Table(PartError),
    /// No partition and no bare medium holds a FAT32 volume.
    NoFat32,
    /// The VFS refused the mount point.
    Vfs,
}

/// What was mounted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mounted {
    /// The volume's first sector on the stick (0: a bare medium).
    pub base: u64,
    /// Partitions the table holds.
    pub partitions: u32,
}

/// Mount the FAT32 volume of `disk` at `at`: the first partition of its table
/// that holds one, else the bare medium.
/// A stick unplugged while it was being mounted is retired by the mount
/// itself, once mounted ([`unplugged`] found nothing to retire yet): the
/// answer is then the one the I/O gave, or [`Why::NoFat32`].
pub fn mount(disk: &'static dyn Disk, at: &[u8]) -> Result<Mounted, Why> {
    let path = MountPath::of(at).ok_or(Why::Path)?;
    if STATE.compare_exchange(IDLE, MOUNTING, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return Err(Why::Busy);
    }
    *DISK.lock() = Some(disk);
    GONE.store(false, Ordering::Release);
    let r = attach(disk, at);
    match r {
        Ok(_) => {
            *AT.lock() = Some(path);
            STATE.store(MOUNTED, Ordering::Release);
            if GONE.load(Ordering::Acquire) {
                let _ = retire(false);
            }
        }
        Err(_) => {
            GONE.store(true, Ordering::Release);
            *TABLE.lock() = None;
            STATE.store(IDLE, Ordering::Release);
        }
    }
    r
}

fn attach(disk: &'static dyn Disk, at: &[u8]) -> Result<Mounted, Why> {
    let t = table::parse(disk.sectors(), &mut |lba, buf: &mut [u8; table::SECTOR]| disk.read(lba, 1, buf))
        .map_err(Why::Table)?;
    *TABLE.lock() = Some(t);
    fat32::fat32_mount().map_err(|()| Why::NoFat32)?;
    if crate::vfs::vfs_mount_fs(at, &fat32::FAT32_FS).is_err() {
        let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());
        return Err(Why::Vfs);
    }
    Ok(Mounted { base: fat32::fat32_volume_base(), partitions: t.count as u32 })
}

/// Is a volume mounted?
pub fn mounted() -> bool {
    STATE.load(Ordering::Acquire) == MOUNTED
}

/// The stick went away: fail every device call from now on, retire the
/// mount, reset the volume for the next stick. Nothing waits for the device.
/// A no-op when nothing is mounted.
pub fn unplugged() {
    GONE.store(true, Ordering::Release);
    let _ = retire(false);
}

/// The orderly way out (the power-off): write the volume back and mark it
/// clean, flush the stick's cache, retire the mount. `Ok(None)` when nothing
/// was mounted; otherwise whether the stick confirmed it is durable.
pub fn eject() -> Option<Result<(), ()>> {
    let r = retire(true)?;
    // The unmount flushed already; once more for what it wrote last (the
    // clean flag), and so a stick that answered the flush wrongly is told.
    let flushed = match fat32_dev::blkdev::flush() {
        Ok(()) | Err(FlushError::Unsupported) => true,
        Err(FlushError::Io) => false,
    };
    Some(if r && flushed { Ok(()) } else { Err(()) })
}

/// Retire the mount (`writeback`: the page cache's dirty pages go to the
/// volume first), unmount the volume. `None` when nothing is mounted; else
/// whether everything reached the stick.
fn retire(writeback: bool) -> Option<bool> {
    STATE.compare_exchange(MOUNTED, RETIRING, Ordering::AcqRel, Ordering::Acquire).ok()?;
    let at = AT.lock().take()?;
    let paged = crate::vfs::vfs_unmount(at.get(), writeback).is_ok();
    let unmounted = fat32::fat32_unmount(fat32::Volume::assume_mounted()).is_ok();
    *TABLE.lock() = None;
    STATE.store(IDLE, Ordering::Release);
    Some(paged && unmounted)
}

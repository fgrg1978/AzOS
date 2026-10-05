// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Who is told that the boot medium was written (wave 14, FATCACHE).
//!
//! The FAT32 driver keeps a block cache of the medium (`azos_fs`'s
//! `bcache.rs`, sized by Kconfig `FS_BLOCK_CACHE_KB`). Its own writes keep
//! that cache coherent (write-through), but other code writes the same
//! medium: the USB mass-storage gadget, the reserved-tail records, ring-3
//! `SYS_DISK_WRITE` through a partition `Cap<Disk>`. Every one of those
//! goes through [`blkdev::write`](crate::blkdev::write), which calls
//! [`notify`] after the device answered, so a new writer is coherent by
//! construction; a writer that reaches the device another way calls
//! [`notify`] itself (`SYS_DISK_WRITE`, which drives `virtio::blk` directly).
//!
//! One observer, a plain `fn`, registered by the cache owner. This crate
//! cannot name `azos_fs` (the dependency runs the other way), hence the
//! pointer. The observer is called with no lock of this crate held; it may
//! take the cache's own lock, so the cache owner must never write through
//! `blkdev::write` while holding that lock — it uses
//! [`blkdev::write_quiet`](crate::blkdev::write_quiet), and
//! `tests/host/fs-tests` holds the list of its callers to one file.
//!
//! Lives in its own file, with no dependency, so the host suites pull this
//! exact code by `#[path]`.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The observer as a `fn(u64, u32)` address; 0 = none.
static OBSERVER: AtomicUsize = AtomicUsize::new(0);

/// Install `f` as the observer of every medium write (replacing any other).
pub fn set(f: fn(u64, u32)) {
    OBSERVER.store(f as usize, Ordering::Release);
}

/// Remove the observer.
pub fn clear() {
    OBSERVER.store(0, Ordering::Release);
}

/// Sectors `[sector, sector + count)` of the medium were just written (or a
/// write of them was attempted and may have landed in part). Call AFTER the
/// device answered: an observer that drops cached copies before the write
/// lands lets a reader refill them with the old bytes.
#[inline]
pub fn notify(sector: u64, count: u32) {
    let f = OBSERVER.load(Ordering::Acquire);
    if f != 0 {
        // SAFETY: the only non-zero value ever stored is a `fn(u64, u32)`
        // cast to `usize` by `set`; fn pointers are never null and the cast
        // round-trips on every target this crate builds for.
        let f: fn(u64, u32) = unsafe { core::mem::transmute::<usize, fn(u64, u32)>(f) };
        f(sector, count);
    }
}

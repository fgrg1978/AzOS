// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Who is told that the boot medium was written (wave 14, FATCACHE).
//!
//! The FAT32 driver keeps a block cache of the medium (`azos_fs`'s
//! `bcache.rs`, sized by Kconfig `FS_BLOCK_CACHE_KB`). Its own writes keep
//! that cache coherent (write-through), but other code writes the same
//! medium: the USB mass-storage gadget, the reserved-tail records, ring-3
//! block entries through a partition's `block` endpoint. Every one of those
//! goes through [`blkdev::write`](crate::blkdev::write), which calls
//! [`notify`] after the device answered, so a new writer is coherent by
//! construction; a writer that reaches the device another way calls
//! [`notify`] itself (the block entry, which drives `blkdev::write_raw`).
//!
//! One observer, a plain `fn`, registered by the cache owner. This crate
//! cannot name `azos_fs` (the dependency runs the other way), hence the
//! pointer. The observer is called with no lock of this crate held; it may
//! take the cache's own lock, so the cache owner must never write through
//! `blkdev::write` while holding that lock — it uses
//! [`blkdev::write_quiet`](crate::blkdev::write_quiet), and
//! `tests/host/fs-tests` holds the list of its callers to one file.
//!
//! A third pointer is not an observer of the cache but the writes' ledger:
//! [`account`] is called once per write the device **completed**, with the
//! Domain it was made for and its bytes, and the kernel's sink adds them to
//! that Domain's counter (`azos_sched::domain::add_written`), where the
//! introspection tree and the energy accounting read them. It is called from
//! the request layer's completion (and the SD/eMMC backend's write), under the
//! layer's hart lock, so the sink may only do atomics.
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

/// Remove every observer (the write one, the read one and its probe) and the
/// write ledger's sink.
pub fn clear() {
    OBSERVER.store(0, Ordering::Release);
    ACCOUNT.store(0, Ordering::Release);
    READ_OBSERVER.store(0, Ordering::Release);
    DIRTY_PROBE.store(0, Ordering::Release);
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

/// The read observer (wave 15, WRITEBACK) as a `fn(u64, u32)` address; 0 = none.
static READ_OBSERVER: AtomicUsize = AtomicUsize::new(0);

/// The dirty probe as a `fn(u64, u32) -> bool` address; 0 = none.
static DIRTY_PROBE: AtomicUsize = AtomicUsize::new(0);

/// Install `f` as the observer called before every medium read that is not
/// the cache owner's own (FAT32 under Kconfig `FS_WRITEBACK`: it writes back
/// the dirty sectors in the range first), and `held` as its probe: does the
/// observer have something to write back for the range? `held` takes the
/// cache's leaf lock and nothing else; it never waits for the device.
pub fn set_read(f: fn(u64, u32), held: fn(u64, u32) -> bool) {
    READ_OBSERVER.store(f as usize, Ordering::Release);
    DIRTY_PROBE.store(held as usize, Ordering::Release);
}

/// Would [`before_read`] of `[sector, sector + count)` wait for the device (the
/// cache owner holds a write of those sectors that has not reached it)? A
/// caller that must not wait (an io_ring submit) asks first and leaves the
/// read to a pass that may. `false` with no observer installed.
#[inline]
pub fn read_would_wait(sector: u64, count: u32) -> bool {
    let f = DIRTY_PROBE.load(Ordering::Acquire);
    if f == 0 {
        return false;
    }
    // SAFETY: the only non-zero value ever stored is a `fn(u64, u32) -> bool`
    // cast to `usize` by `set_read`.
    let f: fn(u64, u32) -> bool = unsafe { core::mem::transmute::<usize, fn(u64, u32) -> bool>(f) };
    f(sector, count)
}

/// Sectors `[sector, sector + count)` are about to be read by someone other
/// than the cache owner. Call BEFORE the read, with no lock held: the
/// observer may wait on the device.
#[inline]
pub fn before_read(sector: u64, count: u32) {
    let f = READ_OBSERVER.load(Ordering::Acquire);
    if f != 0 {
        // SAFETY: the only non-zero value ever stored is a `fn(u64, u32)`
        // cast to `usize` by `set_read`.
        let f: fn(u64, u32) = unsafe { core::mem::transmute::<usize, fn(u64, u32)>(f) };
        f(sector, count);
    }
}

/// The write ledger's sink as a `fn(u32, u64)` address; 0 = none.
static ACCOUNT: AtomicUsize = AtomicUsize::new(0);

/// Install `f` as the sink of [`account`]: `f(owner, bytes)`. It runs under a
/// spinlock of the request layer, so it may take no lock and never wait.
pub fn set_account(f: fn(u32, u64)) {
    ACCOUNT.store(f as usize, Ordering::Release);
}

/// `bytes` were written to the medium for the Domain `owner`
/// (`azos_devif::block::OWNER_KERNEL` for the kernel's own) and the device
/// reported them done. Call once per completed write request, never for a
/// failed one (it may have landed in part; the ledger counts what is known),
/// and never for a flush or a discard.
#[inline]
pub fn account(owner: u32, bytes: u64) {
    let f = ACCOUNT.load(Ordering::Acquire);
    if f != 0 {
        // SAFETY: the only non-zero value ever stored is a `fn(u32, u64)`
        // cast to `usize` by `set_account`.
        let f: fn(u32, u64) = unsafe { core::mem::transmute::<usize, fn(u32, u64)>(f) };
        f(owner, bytes);
    }
}

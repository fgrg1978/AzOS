// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `file-census` (vsbench diagnostic, off in every build that ships): where a
//! backend file's open / read / close goes, summed over operations and
//! printed as a per-open average every [`EVERY`] backend opens. Read under
//! `-icount shift=0`, where a nanosecond of guest time is one guest
//! instruction (riscv64's 10 MHz timer counts in steps of 100, so a phase is
//! only meaningful averaged). The model is `spawn.rs`'s `spawn-census`.
//!
//! Phases (each an interval, summed): `open` (all of `vfs_open` on a backend
//! path), inside it `stat` (key + directory lookup), `alloc` (proxy inode and
//! its buffer), `fill` (`read_all` into the proxy); `read` and `close` (all
//! of `vfs_read`/`vfs_close` on a backend inode); for a read-only stream
//! also `path` (`path_lookup`'s miss), `key` (mount match + backend key),
//! `inode` (inode slot) and `fd` (descriptor). Counters (per open): FAT32
//! sector-cache hits and misses and device read requests.
//!
//! Without the feature every function here is an empty inline function.

pub const OPEN: usize = 0;
pub const STAT: usize = 1;
pub const ALLOC: usize = 2;
pub const FILL: usize = 3;
pub const READ: usize = 4;
pub const CLOSE: usize = 5;
pub const PATH: usize = 6;
pub const KEY: usize = 7;
pub const INODE: usize = 8;
pub const FD: usize = 9;
pub const DEV_READS: usize = 10;
pub const SLOTS: usize = 11;
pub const TIMED: usize = 10;
pub const EVERY: u64 = 100;

#[cfg(feature = "file-census")]
mod imp {
    use core::sync::atomic::{AtomicU64, Ordering};
    pub static ACC: [AtomicU64; super::SLOTS] = [const { AtomicU64::new(0) }; super::SLOTS];
    pub static N: AtomicU64 = AtomicU64::new(0);
    static CACHE0: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    const NAMES: [&str; super::TIMED] =
        ["open", "stat", "alloc", "fill", "read", "close", "path", "key", "inode", "fd"];

    #[inline(always)]
    pub fn now() -> u64 { azos_drv_sys::timebase::now() }
    #[inline(always)]
    pub fn add(i: usize, t0: u64, t1: u64) { ACC[i].fetch_add(t1.wrapping_sub(t0), Ordering::Relaxed); }
    #[inline(always)]
    pub fn count(i: usize) { ACC[i].fetch_add(1, Ordering::Relaxed); }

    /// One backend open finished: every [`EVERY`](super::EVERY), print the
    /// averages since the last line and start again.
    pub fn open_done() {
        let n = N.fetch_add(1, Ordering::Relaxed) + 1;
        if n % super::EVERY != 0 { return; }
        let f = azos_drv_sys::timebase::TIMER_FREQ;
        let mut line = [0u64; super::TIMED];
        for (k, l) in line.iter_mut().enumerate() {
            *l = ACC[k].swap(0, Ordering::Relaxed).saturating_mul(1_000_000_000 / f) / super::EVERY;
        }
        let dev = ACC[super::DEV_READS].swap(0, Ordering::Relaxed);
        let st = crate::fat32::fat32_cache_counters();
        let (h, m) = (st.hits as u64, st.misses as u64);
        let dh = h.wrapping_sub(CACHE0[0].swap(h, Ordering::Relaxed));
        let dm = m.wrapping_sub(CACHE0[1].swap(m, Ordering::Relaxed));
        let e = super::EVERY;
        azos_drv_sys::kprintln!(
            "[FILE-CENSUS] opens={} avg_ns {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} per_open hits={}.{:02} misses={}.{:02} dev_reads={}.{:02}",
            n, NAMES[0], line[0], NAMES[1], line[1], NAMES[2], line[2], NAMES[3], line[3],
            NAMES[4], line[4], NAMES[5], line[5], NAMES[6], line[6], NAMES[7], line[7],
            NAMES[8], line[8], NAMES[9], line[9],
            dh / e, (dh % e) * 100 / e, dm / e, (dm % e) * 100 / e, dev / e, (dev % e) * 100 / e,
        );
    }
}
#[cfg(feature = "file-census")]
pub use imp::{add, count, now, open_done};

#[cfg(not(feature = "file-census"))]
#[inline(always)]
pub fn now() -> u64 { 0 }
#[cfg(not(feature = "file-census"))]
#[inline(always)]
pub fn add(_: usize, _: u64, _: u64) {}
#[cfg(not(feature = "file-census"))]
#[inline(always)]
pub fn count(_: usize) {}
#[cfg(not(feature = "file-census"))]
#[inline(always)]
pub fn open_done() {}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Filesystem subsystem microbenchmarks (tmpfs path).
//!
//! tmpfs is the RAM-backed FS used for sysfs-style data exchange.
//! Pure data-structure work, no disk I/O — clean signal under TCG.
//! FAT32 benches require disk.img setup and are deferred.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_fs::tmpfs;

const BENCH_FILE: &[u8] = b"_bench_scratch";

/// Write 64 bytes to a tmpfs file in a loop.  Hits the create-or-update
/// path; second+ iteration is an update.
pub fn bench_tmpfs_write_64B(iters: u64) -> BenchResult {
    let data = [0x42u8; 64];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = tmpfs::tmpfs_write(BENCH_FILE, &data);
    }
    let end = read_cycles();

    let _ = tmpfs::tmpfs_unlink(BENCH_FILE);
    BenchResult::from_total(start, end, iters)
}

/// Read 64 bytes from a tmpfs file.  Pre-write outside the timed loop.
pub fn bench_tmpfs_read_64B(iters: u64) -> BenchResult {
    let data = [0x99u8; 64];
    let _ = tmpfs::tmpfs_write(BENCH_FILE, &data);
    let mut buf = [0u8; 64];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = tmpfs::tmpfs_read(BENCH_FILE, &mut buf);
    }
    let end = read_cycles();

    let _ = tmpfs::tmpfs_unlink(BENCH_FILE);
    BenchResult::from_total(start, end, iters)
}

/// `tmpfs_size` on existing file — lookup-only fast path.
pub fn bench_tmpfs_size(iters: u64) -> BenchResult {
    let _ = tmpfs::tmpfs_write(BENCH_FILE, &[0u8; 8]);

    let start = read_cycles();
    for _ in 0..iters {
        let _ = tmpfs::tmpfs_size(BENCH_FILE);
    }
    let end = read_cycles();

    let _ = tmpfs::tmpfs_unlink(BENCH_FILE);
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("fs.tmpfs_write_64B", &best_of(|| bench_tmpfs_write_64B(iters))); n += 1;
    report("fs.tmpfs_read_64B",  &best_of(|| bench_tmpfs_read_64B(iters)));  n += 1;
    report("fs.tmpfs_size",      &best_of(|| bench_tmpfs_size(iters)));      n += 1;
    n
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Filesystem subsystem microbenchmarks (the VFS over tmpfs at `/tmp`).
//!
//! RAM-backed, no disk I/O — clean signal under TCG.
//! FAT32 benches require disk.img setup and are deferred.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_fs::{ScratchFds, O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY};

const BENCH_FILE: &[u8] = b"/tmp/_bench_scratch";

fn write_file(t: &mut ScratchFds, data: &[u8]) {
    let fd = azos_fs::vfs_open(t, BENCH_FILE, O_WRONLY | O_CREAT | O_TRUNC);
    if fd >= 0 {
        let _ = azos_fs::vfs_write(t, fd, data.as_ptr(), data.len());
        let _ = azos_fs::vfs_close(t, fd);
    }
}

/// Open, write 64 bytes and close a `/tmp` file in a loop.  Hits the
/// create-or-truncate path; second+ iteration is an update.
pub fn bench_tmpfs_write_64B(iters: u64) -> BenchResult {
    let data = [0x42u8; 64];
    let mut t = ScratchFds::new();

    let start = read_cycles();
    for _ in 0..iters {
        write_file(&mut t, &data);
    }
    let end = read_cycles();

    let _ = azos_fs::vfs_unlink(BENCH_FILE);
    BenchResult::from_total(start, end, iters)
}

/// Open, read 64 bytes and close a `/tmp` file.  Pre-write outside the timed
/// loop.
pub fn bench_tmpfs_read_64B(iters: u64) -> BenchResult {
    let mut t = ScratchFds::new();
    write_file(&mut t, &[0x99u8; 64]);
    let mut buf = [0u8; 64];

    let start = read_cycles();
    for _ in 0..iters {
        let fd = azos_fs::vfs_open(&mut t, BENCH_FILE, O_RDONLY);
        if fd >= 0 {
            let _ = azos_fs::vfs_read(&mut t, fd, buf.as_mut_ptr(), buf.len());
            let _ = azos_fs::vfs_close(&mut t, fd);
        }
    }
    let end = read_cycles();

    let _ = azos_fs::vfs_unlink(BENCH_FILE);
    BenchResult::from_total(start, end, iters)
}

/// `vfs_stat` on an existing file — lookup-only fast path.
pub fn bench_tmpfs_size(iters: u64) -> BenchResult {
    write_file(&mut ScratchFds::new(), &[0u8; 8]);

    let start = read_cycles();
    for _ in 0..iters {
        let _ = azos_fs::vfs_stat(BENCH_FILE);
    }
    let end = read_cycles();

    let _ = azos_fs::vfs_unlink(BENCH_FILE);
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("fs.tmpfs_write_64B", &best_of(|| bench_tmpfs_write_64B(iters))); n += 1;
    report("fs.tmpfs_read_64B",  &best_of(|| bench_tmpfs_read_64B(iters)));  n += 1;
    report("fs.tmpfs_size",      &best_of(|| bench_tmpfs_size(iters)));      n += 1;
    n
}

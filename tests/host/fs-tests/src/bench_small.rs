// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A small-file lane on `/fat` (the boot volume), for before/after
//! comparisons of `fat32.rs`: create, write and close 100 files of 700 bytes,
//! then read each back, through the VFS over the shim disk. Prints the
//! wall-clock per operation (host time, best of five rounds) and the device
//! requests of a round, which are exact and must not change across a
//! refactor that is not meant to change the I/O.
//!
//! `#[ignore]`: a measurement, not a check. Run it alone:
//! `cargo test --release bench_small -- --ignored --nocapture`.

use super::{fat32, image::*, serial, swap_medium, vfs, vfs_open_close::vfs_once};
use std::time::Instant;

const FILES: usize = 100;
const LEN: usize = 700;

fn volume() {
    let g = Geom { spc: 8, rsvd: 32, num_fats: 2, fat_sz32: 64, root_clus: 2, total_sectors: 65536 };
    let mut img = build(&g);
    set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
    swap_medium(img);
    assert_eq!(fat32::fat32_mount(), Ok(()));
    vfs_once();
}

#[test]
#[ignore]
fn bench_small_file_lane() {
    let _g = serial();
    let data = vec![0x5au8; LEN];
    let (mut best_w, mut best_r) = (f64::MAX, f64::MAX);
    let mut reqs = (0, 0, 0, 0);
    for _ in 0..5 {
        volume();
        let mut t = vfs::ScratchFds::new();
        let (r0, w0) = fs_test_drivers::disk_stats();
        let start = Instant::now();
        for i in 0..FILES {
            let p = format!("/fat/B{i:03}.TXT");
            let fd = vfs::vfs_open(&mut t, p.as_bytes(), vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
            assert!(fd >= 0);
            assert_eq!(vfs::vfs_write(&mut t, fd, data.as_ptr(), LEN), LEN as i32);
            assert_eq!(vfs::vfs_close(&mut t, fd), 0);
        }
        assert_eq!(fat32::fat32_sync(), Ok(()));
        let w = start.elapsed().as_secs_f64() * 1e6 / FILES as f64;
        let (r1, w1) = fs_test_drivers::disk_stats();
        let start = Instant::now();
        let mut buf = vec![0u8; LEN + 16];
        for i in 0..FILES {
            let p = format!("/fat/B{i:03}.TXT");
            let fd = vfs::vfs_open(&mut t, p.as_bytes(), vfs::O_RDONLY);
            assert!(fd >= 0);
            assert_eq!(vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), buf.len()), LEN as i32);
            vfs::vfs_close(&mut t, fd);
        }
        let r = start.elapsed().as_secs_f64() * 1e6 / FILES as f64;
        let (r2, w2) = fs_test_drivers::disk_stats();
        reqs = (r1 - r0, w1 - w0, r2 - r1, w2 - w1);
        best_w = best_w.min(w);
        best_r = best_r.min(r);
    }
    println!(
        "bench_small: write+close {best_w:.2} us/file, read {best_r:.2} us/file; device requests: write phase {} reads {} writes, read phase {} reads {} writes",
        reqs.0, reqs.1, reqs.2, reqs.3
    );
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A write that starts past the end of a FAT32 file zero-fills the hole in the
//! writer's call, so the hole is bounded and a fill that stops part-way gives
//! its clusters back.
//!
//! Canary: `--features fat-hole-unbounded-canary` (no bound, no give-back):
//! both tests fail.

#![cfg(test)]

use super::image::*;
use super::{fat32, serial};

/// Data clusters of the default fixture volume (`fat_sz32 = 8`, 256 sectors).
const DATA_CLUSTERS: u32 = 208;

fn mount_volume() -> Geom {
    let g = Geom::default();
    let mut img = build(&g);
    set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
    super::swap_medium(img);
    assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
    g
}

/// FAT entries of the data region that read free, from the medium.
fn free_clusters() -> u32 {
    let rsvd = Geom::default().rsvd as u64;
    let entry = |c: u32| {
        let sec = fs_test_drivers::disk_peek(rsvd + c as u64 / 128).expect("FAT sector");
        let o = (c % 128) as usize * 4;
        u32::from_le_bytes(sec[o..o + 4].try_into().unwrap()) & 0x0FFF_FFFF
    };
    (2..2 + DATA_CLUSTERS).filter(|c| entry(*c) == 0).count() as u32
}

fn one_byte_file() -> fat32::Fat32File {
    let flags = fat32::open_flags::WRITE | fat32::open_flags::CREATE;
    let f = fat32::fat32_open(fat32::Volume::assume_mounted(), b"/H.BIN", flags).expect("create");
    assert_eq!(fat32::fat32_write(f, b"x"), Ok(1));
    f
}

/// **One write cannot ask for the volume.** A file with one byte, a seek to
/// 2 GiB and a one-byte write: the hole is past the bound, so the write is
/// refused before any cluster is taken or any sector written.
#[test]
fn a_hole_past_the_bound_is_refused_before_anything_is_written() {
    let _g = serial();
    let _wt = crate::write_through();
    mount_volume();
    let f = one_byte_file();
    let (free, (_, writes)) = (free_clusters(), fs_test_drivers::disk_stats());
    assert_eq!(fat32::fat32_seek(f, fat32::SeekFrom::Start(1 << 31)), Ok(1 << 31));
    assert_eq!(fat32::fat32_write(f, b"y"), Err(fat32::FsError::NoSpace));
    assert_eq!(free_clusters(), free, "the refused write took clusters");
    assert_eq!(fs_test_drivers::disk_stats().1, writes, "the refused write reached the device");
}

/// **A hole that stops part-way leaves nothing linked.** A 200 KiB hole is
/// within the bound but the 104 KiB volume cannot hold it: the fill fails
/// when the volume is full, and every cluster it linked is free again.
#[test]
fn a_hole_that_runs_out_of_space_gives_its_clusters_back() {
    let _g = serial();
    let _wt = crate::write_through();
    mount_volume();
    let f = one_byte_file();
    let free = free_clusters();
    assert_eq!(fat32::fat32_seek(f, fat32::SeekFrom::Start(200 * 1024)), Ok(200 * 1024));
    assert_eq!(fat32::fat32_write(f, b"y"), Err(fat32::FsError::NoSpace));
    assert_eq!(free_clusters(), free, "the failed fill kept the clusters it linked");
    assert_eq!(fat32::fat32_close(f), Ok(()));
    assert_eq!(fat32::fat32_lookup_root(b"H       BIN").map(|e| e.1), Ok(1), "the file is still one byte");
}

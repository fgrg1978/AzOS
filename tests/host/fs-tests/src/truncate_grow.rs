// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Fat32Fs::truncate` to a length other than zero never takes a heap buffer
//! of that length: a grow writes zeros in bounded chunks, a shrink cuts the
//! chain in place, and a grow that fails is cut back.
//!
//! Canary: `--features fat-truncate-heap-canary` (a grow holds a buffer of the
//! grown length): `a_grow_takes_no_buffer_of_the_length` fails.

#![cfg(test)]

use super::alloc_peak;
use super::image::*;
use super::vfs::{FileSystem as _, FsErr};
use super::{fat32, serial};

/// 4096 sectors of one-sector clusters: a megabyte of data fits.
fn mount_big_volume() {
    let g = Geom { fat_sz32: 32, total_sectors: 4096, ..Geom::default() };
    let mut img = build(&g);
    set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
    super::swap_medium(img);
    assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
}

fn key(name: &[u8]) -> super::vfs::InodeKey {
    fat32::FAT32_FS.key_for(name).expect("a legal 8.3 name")
}

fn size_of(k: &super::vfs::InodeKey) -> u64 {
    fat32::FAT32_FS.stat(k).expect("the file exists").size
}

fn free_clusters() -> u64 {
    fat32::FAT32_FS.statfs().expect("statfs").blocks_free
}

/// **A grow holds no buffer of its length.** One megabyte, from an empty
/// file: the largest allocation of the call stays well below it, the file has
/// the length, and what the new bytes read is zero.
#[test]
fn a_grow_takes_no_buffer_of_the_length() {
    let _g = serial();
    mount_big_volume();
    let k = key(b"G.BIN");
    assert_eq!(fat32::FAT32_FS.create(&k), Ok(()));
    alloc_peak::reset();
    assert_eq!(fat32::FAT32_FS.truncate(&k, 1 << 20), Ok(()));
    let peak = alloc_peak::largest();
    // The shim disk's write log grows by doubling (128 KiB here); a buffer of
    // the length would be 1 MiB.
    assert!(peak < 512 * 1024, "the grow allocated {peak} bytes in one piece");
    assert_eq!(size_of(&k), 1 << 20);
    let mut tail = vec![0xAAu8; 1024];
    assert_eq!(fat32::FAT32_FS.read_at(&k, (1 << 20) - 1024, &mut tail), 1024);
    assert!(tail.iter().all(|&b| b == 0), "the grown bytes read as zeros");
}

/// **A shrink keeps the head in place and frees the tail.**
#[test]
fn a_shrink_keeps_the_head_and_frees_the_tail() {
    let _g = serial();
    mount_big_volume();
    let k = key(b"S.BIN");
    let data: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(fat32::FAT32_FS.write_at(&k, 0, &data), Ok(data.len()));
    let free = free_clusters();
    alloc_peak::reset();
    assert_eq!(fat32::FAT32_FS.truncate(&k, 700), Ok(()));
    assert!(alloc_peak::largest() < 4000, "the shrink copied the file");
    assert_eq!(size_of(&k), 700);
    let mut head = vec![0u8; 700];
    assert_eq!(fat32::FAT32_FS.read_at(&k, 0, &mut head), 700);
    assert_eq!(head, data[..700]);
    assert!(free_clusters() > free, "the cut-off clusters were not given back");
}

/// **A grow that cannot finish is cut back.** More than the volume holds:
/// refused, the file keeps its length and bytes, and no cluster stays taken.
#[test]
fn a_grow_that_runs_out_of_space_leaves_the_file_as_it_was() {
    let _g = serial();
    mount_big_volume();
    let k = key(b"F.BIN");
    assert_eq!(fat32::FAT32_FS.write_at(&k, 0, b"keep me"), Ok(7));
    let free = free_clusters();
    let r = fat32::FAT32_FS.truncate(&k, 3 << 20);
    assert!(matches!(r, Err(FsErr::Io | FsErr::NoSpace)), "{r:?}");
    assert_eq!(size_of(&k), 7);
    let mut head = [0u8; 7];
    assert_eq!(fat32::FAT32_FS.read_at(&k, 0, &mut head), 7);
    assert_eq!(&head, b"keep me");
    assert_eq!(free_clusters(), free, "the failed grow kept clusters");
}

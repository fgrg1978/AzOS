// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the swap file's filesystem side (Kconfig
//! `MM_SWAP_BACKEND_FILE`): `FileSystem::{swap_resize, swap_runs}` of FAT32
//! (the real `fat32.rs`, over the shim disk). The azvol side (the real engine
//! over an in-memory device) and the VFS pin that keeps every other path off
//! the file are in `azvol_mount.rs`, which owns the fixtures for them.
//!
//! Not here: the swap layer's side (`tests/host/mm-tests/src/swap_file.rs`) and
//! the kernel's request splitting (`kernel/src/boot/swap.rs`).
//!
//! Canaries (discriminate / do not / did not compile):
//! * `Fat32Fs::swap_resize` growing through a path that leaves the clusters as
//!   they were (no zero fill): `a_fat32_swap_file_grows_in_zeroed_clusters_and_its_runs_cover_it` red (the
//!   volume's free space is poisoned with 0xAA).
//! * `fat32_trim_file` not writing the new end-of-chain, or freeing the tail before the
//!   size: `a_fat32_shrink_keeps_the_head_frees_the_tail_and_leaves_a_sound_volume` red (free count and chain check).
//! * `swap_runs` not joining adjacent clusters, or joining across a gap:
//!   `a_fragmented_fat32_swap_file_reports_every_run_and_refuses_more_than_it_may` red.
//! * (azvol: `azvol_mount.rs`, `a_failed_azvol_resize_leaves_no_transaction_open` and
//!   `the_pinned_swap_file_answers_busy_to_every_path_that_would_move_it`.)
//! * Does not discriminate: the `Invalid` for a `len` past the size (the swap layer never asks).

#![cfg(test)]

use super::{fat32, image::*, serial, vfs};
use vfs::{FileSystem as _, FsErr, InodeKey, SectorRun};

const LEN_40: u64 = 40 * SECTOR as u64;

/// A volume whose free space holds 0xAA: a cluster the filesystem hands a file
/// without writing it shows up as 0xAA.
fn poisoned_volume() {
    let g = Geom::default();
    let mut img = build(&g);
    set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
    let first_free = (cluster_sector(&g, 2) + 1) * SECTOR;
    img[first_free..].fill(0xAA);
    super::swap_medium(img);
    assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
}

fn key(name: &[u8]) -> InodeKey {
    fat32::FAT32_FS.key_for(name).expect("an 8.3 name")
}

fn runs_of(k: &InodeKey, len: u64) -> Result<Vec<SectorRun>, FsErr> {
    let mut out = [SectorRun::default(); 32];
    let n = fat32::FAT32_FS.swap_runs(k, len, &mut out)?;
    Ok(out[..n].to_vec())
}

fn free_clusters() -> u64 {
    fat32::FAT32_FS.statfs().unwrap().blocks_free
}

fn read_all(k: &InodeKey) -> Vec<u8> {
    let st = fat32::FAT32_FS.stat(k).unwrap();
    let mut b = vec![0xFFu8; st.size as usize];
    assert_eq!(fat32::FAT32_FS.read_at(k, 0, &mut b), b.len());
    b
}

fn raw(lba: u64, n: u32) -> Vec<u8> {
    let mut b = vec![0u8; n as usize * SECTOR];
    fs_test_drivers::blkdev::read_quiet(lba, n, &mut b).unwrap();
    b
}

fn raw_fill(runs: &[SectorRun], byte: u8) {
    for r in runs {
        fs_test_drivers::blkdev::write_quiet(r.lba, r.sectors, &vec![byte; r.sectors as usize * SECTOR]).unwrap();
    }
}

// ── FAT32 ────────────────────────────────────────────────────────────────────

#[test]
fn a_fat32_swap_file_grows_in_zeroed_clusters_and_its_runs_cover_it() {
    let _g = serial();
    poisoned_volume();
    let fs = &fat32::FAT32_FS;
    let k = key(b"SWAPT.AZS");
    fs.create(&k).unwrap();
    assert_eq!(fs.swap_runs(&k, 0, &mut []), Ok(0), "an empty file has no runs");
    assert_eq!(fs.swap_resize(&k, LEN_40), Ok(()));
    assert_eq!(fs.stat(&k).unwrap().size, LEN_40);
    assert!(read_all(&k).iter().all(|&b| b == 0), "the grown part is zeros, not what the free space held");
    let runs = runs_of(&k, LEN_40).unwrap();
    assert_eq!(runs.iter().map(|r| r.sectors as u64).sum::<u64>(), 40);
    let g = Geom::default();
    for r in &runs {
        assert!(r.lba > cluster_sector(&g, 2) as u64, "{r:?}: the root directory's cluster is not the file's");
        assert!(r.lba + r.sectors as u64 <= g.total_sectors as u64, "{r:?} is on the volume");
    }
    // A fresh volume hands out the clusters in order: one run.
    assert_eq!(runs.len(), 1, "{runs:?}");
    // Asking for more than the file holds, or for a directory, is refused.
    assert_eq!(fs.swap_runs(&k, LEN_40 + 1, &mut [SectorRun::default(); 4]), Err(FsErr::Invalid));
    // The same length again is a no-op that keeps the blocks.
    assert_eq!(fs.swap_resize(&k, LEN_40), Ok(()));
    assert_eq!(runs_of(&k, LEN_40).unwrap(), runs);
}

#[test]
fn a_fragmented_fat32_swap_file_reports_every_run_and_refuses_more_than_it_may() {
    let _g = serial();
    poisoned_volume();
    let fs = &fat32::FAT32_FS;
    let (k, other) = (key(b"SWAPT.AZS"), key(b"OTHER.BIN"));
    fs.create(&k).unwrap();
    fs.create(&other).unwrap();
    // The swap file and another file take turns at the free clusters.
    let mut blob = Vec::new();
    for i in 0..6u64 {
        assert_eq!(fs.swap_resize(&k, (i + 1) * 8 * SECTOR as u64), Ok(()));
        let chunk = vec![i as u8 + 1; SECTOR];
        assert_eq!(fs.write_at(&other, i * SECTOR as u64, &chunk), Ok(SECTOR));
        blob.extend_from_slice(&chunk);
    }
    let runs = runs_of(&k, 48 * SECTOR as u64).unwrap();
    assert_eq!(runs.len(), 6, "one run per turn: {runs:?}");
    assert_eq!(runs.iter().map(|r| r.sectors).collect::<Vec<_>>(), vec![8; 6]);
    // They are the file's order, and none overlaps the other file's clusters.
    let mut other_at = Vec::new();
    for w in runs.windows(2) {
        assert_eq!(w[1].lba, w[0].lba + 9, "a cluster of the other file lies between two runs");
        other_at.push(w[0].lba + 8);
    }
    for (i, lba) in other_at.iter().enumerate() {
        assert_eq!(raw(*lba, 1), vec![i as u8 + 1; SECTOR], "the other file's cluster at {lba}");
    }
    // Fewer slots than runs: refused, not cut short.
    assert_eq!(fs.swap_runs(&k, 48 * SECTOR as u64, &mut [SectorRun::default(); 5]), Err(FsErr::NoSpace));
    // A shorter prefix needs fewer.
    assert_eq!(runs_of(&k, 17 * SECTOR as u64).unwrap().len(), 3);
    assert_eq!(read_all(&other), blob);
}

#[test]
fn a_fat32_shrink_keeps_the_head_frees_the_tail_and_leaves_a_sound_volume() {
    let _g = serial();
    poisoned_volume();
    let fs = &fat32::FAT32_FS;
    let (k, other) = (key(b"SWAPT.AZS"), key(b"OTHER.BIN"));
    fs.create(&k).unwrap();
    assert_eq!(fs.swap_resize(&k, LEN_40), Ok(()));
    fs.create(&other).unwrap();
    let blob = vec![0x5Au8; 3 * SECTOR];
    assert_eq!(fs.write_at(&other, 0, &blob), Ok(blob.len()));
    let full = runs_of(&k, LEN_40).unwrap();
    // What the swap layer would have written: marks in the head and the tail.
    raw_fill(&full, 0xCD);
    let free_before = free_clusters();

    // Down to 16 sectors and a bit: 17 clusters stay.
    let cut = 16 * SECTOR as u64 + 100;
    assert_eq!(fs.swap_resize(&k, cut), Ok(()));
    assert_eq!(fs.stat(&k).unwrap().size, cut);
    assert_eq!(free_clusters(), free_before + 23, "the 23 clusters past the 17th are free (held or not)");
    let head = runs_of(&k, cut).unwrap();
    let mut want = Vec::new();
    let mut left = 17u64;
    for r in &full {
        if left == 0 {
            break;
        }
        let take = left.min(r.sectors as u64);
        want.push(SectorRun { lba: r.lba, sectors: take as u32 });
        left -= take;
    }
    assert_eq!(head, want, "the head keeps its blocks");
    for r in &head {
        assert_eq!(raw(r.lba, r.sectors), vec![0xCD; r.sectors as usize * SECTOR], "the head's bytes were not touched");
    }
    assert_eq!(read_all(&other), blob, "the other file is whole");

    // Make it durable, remount, and check the chain the way the mount does.
    assert!(fat32::fat32_sync_checked().is_ok());
    super::swap_medium(fs_test_drivers::disk_image());
    assert_eq!(fat32::fat32_mount(), Ok(()));
    let r = fat32::fat32_mount_report();
    assert_eq!((r.cross_linked, r.broken_chains), (0, 0), "{r:?}");
    let name83: [u8; 11] = *b"SWAPT   AZS";
    assert!(matches!(fat32::fat32_check_root_chain(&name83), Ok(Some(_))), "the chain is sound");
    assert_eq!(fs.stat(&k).unwrap().size, cut);
    assert_eq!(runs_of(&k, cut).unwrap(), head);

    // Growing again hands out zeros, not what the tail held before.
    assert_eq!(fs.swap_resize(&k, LEN_40), Ok(()));
    let now = read_all(&k);
    assert!(now[cut as usize..].iter().all(|&b| b == 0), "the regrown tail is zeros");
    assert_eq!(read_all(&other), blob);

    // And to nothing.
    assert_eq!(fs.swap_resize(&k, 0), Ok(()));
    assert_eq!(fs.stat(&k).unwrap().size, 0);
    assert_eq!(fs.swap_runs(&k, 0, &mut []), Ok(0));
}

#[test]
fn a_fat32_swap_file_that_cannot_grow_is_refused_and_can_still_shrink() {
    let _g = serial();
    poisoned_volume();
    let fs = &fat32::FAT32_FS;
    let k = key(b"SWAPT.AZS");
    fs.create(&k).unwrap();
    assert_eq!(fs.swap_resize(&k, 8 * SECTOR as u64), Ok(()));
    // FAT32 files end below 4 GiB.
    assert_eq!(fs.swap_resize(&k, 1 << 32), Err(FsErr::NoSpace));
    // More than the volume has.
    assert!(fs.swap_resize(&k, 400 * SECTOR as u64).is_err());
    let after = fs.stat(&k).unwrap().size;
    assert!(after >= 8 * SECTOR as u64, "the head is still there");
    // The failed grow left a file the swap layer can cut back to what it had.
    assert_eq!(fs.swap_resize(&k, 8 * SECTOR as u64), Ok(()));
    assert_eq!(runs_of(&k, 8 * SECTOR as u64).unwrap().iter().map(|r| r.sectors).sum::<u32>(), 8);
    // A name that is not a file.
    assert_eq!(fs.swap_resize(&key(b"NOSUCH.AZS"), 512), Err(FsErr::NotFound));
}

#[test]
fn a_filesystem_that_cannot_map_its_files_says_so() {
    let k = super::tmpfs::TMPFS_FS.key_for(b"x").unwrap();
    assert_eq!(super::tmpfs::TMPFS_FS.swap_runs(&k, 0, &mut []), Err(FsErr::Unsupported));
    assert_eq!(super::tmpfs::TMPFS_FS.swap_resize(&k, 0), Err(FsErr::Unsupported));
}
